#include "ttoolbox.h"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <map>
#include <set>
#include <algorithm>
#include <string>
#include <ranges>
#include <vector>
#include <utility>

#include "gpa-sync.h"
#include "recovery.h"

template<typename T>
static double get_median(std::vector<T> vals) {
    if (vals.empty())
        return 0.0;

    std::ranges::sort(vals);
    if (vals.size() % 1 > 0)
        return static_cast<double>(vals[vals.size() / 2]);
    return (static_cast<double>(vals[vals.size() / 2]) + static_cast<double>(vals[vals.size() / 2 - 1])) / 2.0;
}

static void filter_accesses_without_tokens(std::vector<page_accesses> &page_accesses) {
    for (auto i = 0u; i < page_accesses.size();) {
        if (page_accesses[i].accessed_cls.empty()) {
            page_accesses.erase(page_accesses.begin() + i);
            continue;
        }
        i++;
    }
}

static void filter_handle_single_fault_frames(std::vector<page_accesses> &page_accesses) {
    std::vector<unsigned long> frames;

    for (unsigned int i = 0; i < page_accesses.size(); i++) {
        if (page_accesses[i].gpa == sync_gpa)
            frames.push_back(i);
    }


    for (const auto frame_base: frames) {
        std::map<unsigned int, unsigned int> bucket_ids;
        unsigned long frame_len = 0;
        for (unsigned int i = frame_base + 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++)
            frame_len++;
        if (frame_len != 1 || frame_base + 1 >= page_accesses.size())
            continue;

        for (auto cl : page_accesses[frame_base + 1].measured_cls) {
            if (gpa_to_token[cl].token_id >> 63)
                continue;
            auto score = page_accesses[frame_base + 1].accessed_cls[cl];
            page_accesses[frame_base + 1].accessed_cls[cl] = std::max(score, static_cast<unsigned char>(1));
        }

        bool single_access = page_accesses[frame_base + 1].measured_cls.size() == 1;
        for (const auto [cl, score]: page_accesses[frame_base + 1].accessed_cls) {
            const auto new_score = single_access ? std::min(score + 30u, 190u) : 70;
            page_accesses[frame_base + 1].set_cl_confidence_score(cl, new_score);
        }
    }
}

static void filter_handle_two_fault_frames(std::vector<page_accesses> &page_accesses) {
    std::vector<unsigned long> frames;

    for (unsigned int i = 0; i < page_accesses.size(); i++) {
        if (page_accesses[i].gpa == sync_gpa)
            frames.push_back(i);
    }

    for (const auto frame_base: frames) {
        std::map<unsigned int, unsigned int> bucket_ids;
        unsigned long frame_len = 0;
        for (unsigned int i = frame_base + 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++)
            frame_len++;
        if (frame_len != 2 || frame_base + 2 >= page_accesses.size())
            continue;

        for (const auto [cl, score]: page_accesses[frame_base + 1].accessed_cls) {
            const auto new_score = std::min(score + 40u, 190u);
            page_accesses[frame_base + 1].set_cl_confidence_score(cl, new_score);
        }

        for (const auto cl: page_accesses[frame_base + 2].accessed_cls | std::views::keys)
            page_accesses[frame_base + 2].set_cl_confidence_score(cl, 50);
    }
}

// Special case with bucket rule - If a sync frame has exactly 2 entries, all our assumptions break
// Instead, the correct token is guaranteed to be in the first fault
// Named after the "Ġcommande" token that routinely pops up in the output if we don't handle this
static void handle_commande_case(std::vector<page_accesses> &page_accesses, unsigned int commande_fault, unsigned int max_bkid) {
    for (const auto cl: page_accesses[commande_fault ].accessed_cls | std::views::keys) {
        if (gpa_to_token[cl].bucket_id == max_bkid)
            page_accesses[commande_fault].set_cl_confidence_score(cl, 200);
        else
            page_accesses[commande_fault].set_cl_confidence_score(cl, 0);
    }

    for (const auto cl: page_accesses[commande_fault + 1].accessed_cls | std::views::keys) {
        if (gpa_to_token[cl].bucket_id == max_bkid)
            page_accesses[commande_fault + 1].set_cl_confidence_score(cl, 50);
        else
            page_accesses[commande_fault + 1].set_cl_confidence_score(cl, 0);
    }
}

// If we see a token with bucket_position > 0, assert that in the previous page fault, we must have seen the previous token in the bucket
// If this is not the case, remove the token
static void filter_require_prev_in_chain(std::vector<page_accesses> &page_accesses) {
    std::vector<unsigned long> frames;

    for (unsigned int i = 0; i < page_accesses.size(); i++) {
        if (page_accesses[i].gpa == sync_gpa)
            frames.push_back(i);
    }

    for (const auto frame_base: frames) {
        std::map<unsigned int, unsigned int> bucket_ids;
        unsigned long frame_len = 0;
        for (unsigned int i = frame_base + 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++)
            frame_len++;

        for (unsigned int i = frame_base + 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++) {
            for (const auto cl: page_accesses[i].accessed_cls | std::views::keys) {
                auto id = gpa_to_token[cl].bucket_id;
                if (id >= 0xffffff)
                    continue;
                bucket_ids[id]++;
            }
        }
        if (bucket_ids.empty())
            continue;

        auto max_bkid_c = std::max_element(bucket_ids.begin(), bucket_ids.end(), [](const auto &a, const auto &b) {return a.second < b.second;});
        if (max_bkid_c->second < 2)
            continue;
        auto max_bkid = max_bkid_c->first;

        /*if (frame_len == 2) {
            handle_commande_case(page_accesses, frame_base + 1, max_bkid);
            continue;
        }*/

        auto max_page = frame_base;
        unsigned long max_cl = 0;
        unsigned int max_pos = 0;
        for (unsigned int i = frame_base + 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++) {
            page_accesses[i].bucket_access = true;
            for (const auto cl: page_accesses[i].accessed_cls | std::views::keys)
                if (gpa_to_token[cl].bucket_id == max_bkid && gpa_to_token[cl].bucket_pos >= max_pos) {
                    max_pos = gpa_to_token[cl].bucket_pos;
                    max_cl = cl;
                    max_page = i;
                }
        }

        for (unsigned int i = frame_base + 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++) {
            for (const auto cl: page_accesses[i].accessed_cls | std::views::keys) {
                if (i == max_page && cl == max_cl)
                    page_accesses[i].set_cl_confidence_score(cl, 200);
                else
                    page_accesses[i].set_cl_confidence_score(cl, 0);
            }
        }

    }

    for (auto& fault: page_accesses) {
        for (const auto cl: fault.accessed_cls | std::views::keys)
            if (gpa_to_token[cl].bucket_pos > 0)
                fault.set_cl_confidence_score(cl, 0);
    }
}

// We can only have one token per page for which the access is 100% confirmed
static void filter_only_one_confirmed(std::vector<page_accesses> &page_accesses) {
    unsigned int sync_window_len = 0;

    std::set<unsigned int> confirmed_accesses;
    unsigned int i = 0;
    for (i = 0; i < page_accesses.size(); i++) {
        auto &fault = page_accesses[i];
        if (fault.gpa == sync_gpa) {
            sync_window_len = 0;
            continue;
        }
        sync_window_len++;

        bool confirmed = false;
        for (const auto score: fault.accessed_cls | std::views::values) {
            if (score >= 200) {
                confirmed = true;
                break;
            }
        }
        if (!confirmed)
            continue;

        unsigned int j;
        for (j = i - sync_window_len + 1; j < page_accesses.size() && page_accesses[j].gpa != sync_gpa; j++)
            confirmed_accesses.insert(j);
        i = j - 1;
    }

    for (const auto v: confirmed_accesses) {
        for (const auto cl: page_accesses[v].accessed_cls | std::views::keys)
            page_accesses[v].set_cl_confidence_score(cl, 0);
    }
}

// When we measure a cache line access, we heuristically also consider the adjacent cache lines accessed
// However, in the case of a conflict where both measured and adjacent cache lines have the same confidence score, we penalize inferred accesses
// Exception: When an inferred cache line sits in-between two measured cache lines (<measured> - <inferred> - <measured>), it is usually a prompt token - we prioritize these accesses instead
static void filter_prioritize_orig(std::vector<page_accesses> &page_accesses) {
    for (auto& fault : page_accesses) {
        for (const auto cl: fault.accessed_cls | std::views::keys) {
            if (fault.measured_cls.contains(cl))
                continue;
            fault.set_cl_confidence_score(cl, 0);
        }
    }
}

// We can never leak a dummy token
static void filter_eliminate_dummy_token(std::vector<page_accesses> &page_accesses) {
    for (auto& fault : page_accesses) {
        for (const auto cl: fault.accessed_cls | std::views::keys) {
            if (gpa_to_token[cl].token_id >> 63)
                fault.set_cl_confidence_score(cl, 0);
        }
    }
}

// Boost tokens a neighbor of which was also measured
static void filter_boost_double_measurement(std::vector<page_accesses> &page_accesses) {
    for (auto& fault : page_accesses) {
        for (const auto cl: fault.accessed_cls | std::views::keys) {
            if (fault.measured_cls.contains(cl + 0x40) || fault.accessed_cls.contains(cl - 0x40)) {
                auto score = fault.get_cl_confidence_score(cl);
                fault.set_cl_confidence_score(cl, std::min(score + 5u, 200u));
            }
        }
    }
}

// Lift the best token of a frame above the threshold
static void filter_pick_best_in_frame(std::vector<page_accesses> &page_accesses) {
    std::vector<unsigned long> frames;

    for (unsigned int i = 0; i < page_accesses.size(); i++) {
        if (page_accesses[i].gpa == sync_gpa)
            frames.push_back(i);
    }

    for (const auto frame_base: frames) {
        auto max_fault = frame_base + 1;
        unsigned char max_score = 0;
        unsigned long max_gpa = 0;
        for (unsigned long i = max_fault; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++) {
            const auto [gpa, score, str] = get_best_token(page_accesses[i]);
            if (score > max_score) {
                max_score = score;
                max_fault = i;
                max_gpa = gpa;
            }
        }
        if (!max_score || max_score > 130)
            continue;

        page_accesses[max_fault].set_cl_confidence_score(max_gpa, 131);
    }
}

void apply_filter_chain_llama(std::vector<page_accesses> &page_accesses) {
    filter_accesses_without_tokens(page_accesses);
    filter_eliminate_dummy_token(page_accesses);
    filter_require_prev_in_chain(page_accesses);
    filter_handle_two_fault_frames(page_accesses);
    filter_handle_single_fault_frames(page_accesses);
    filter_only_one_confirmed(page_accesses);
    filter_prioritize_orig(page_accesses);
    filter_boost_double_measurement(page_accesses);
    filter_accesses_without_tokens(page_accesses);
    filter_pick_best_in_frame(page_accesses);
}
