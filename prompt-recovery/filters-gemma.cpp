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
#include <iterator>
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


        for (const auto [cl, score]: page_accesses[frame_base + 1].accessed_cls) {
            const auto new_score = std::min(score + 30u, 190u);
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
        if (frame_len < 2 || frame_len > 3 || frame_base + frame_len >= page_accesses.size())
            continue;

        for (const auto [cl, score]: page_accesses[frame_base + 1].accessed_cls) {
            const auto new_score = std::min(score + 40u, 190u);
            page_accesses[frame_base + 1].set_cl_confidence_score(cl, new_score);
        }

        for (const auto cl: page_accesses[frame_base + 2].accessed_cls | std::views::keys)
            page_accesses[frame_base + 2].set_cl_confidence_score(cl, 50);

        if (frame_len <= 2)
            continue;

        for (const auto cl: page_accesses[frame_base + 3].accessed_cls | std::views::keys)
            page_accesses[frame_base + 3].set_cl_confidence_score(cl, 50);

    }
}

// Special case with bucket rule - If a sync frame has exactly 2 entries, all our assumptions break
// Instead, the correct token is guaranteed to be in the first fault
// Named after the "Ġcommande" token that routinely pops up in the output if we don't handle this
static void handle_commande_case(std::vector<page_accesses> &page_accesses, unsigned int commande_fault, unsigned int max_bkid) {
    bool check = false;

    for (const auto cl: page_accesses[commande_fault + 1].accessed_cls | std::views::keys) {
        if (gpa_to_token[cl].bucket_id == max_bkid && page_accesses[commande_fault + 1].measured_cls.contains(cl)) {
            page_accesses[commande_fault + 1].set_cl_confidence_score(cl, 150);
            check = true;
        } else
            page_accesses[commande_fault + 1].set_cl_confidence_score(cl, 0);
    }

    for (const auto cl: page_accesses[commande_fault ].accessed_cls | std::views::keys) {
        if (gpa_to_token[cl].bucket_id == max_bkid && page_accesses[commande_fault].measured_cls.contains(cl) && !check) {
            page_accesses[commande_fault].set_cl_confidence_score(cl, 150);
        } else
            page_accesses[commande_fault].set_cl_confidence_score(cl, 0);
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
            for (const auto cl: page_accesses[i].accessed_cls | std::views::keys)
                bucket_ids[gpa_to_token[cl].bucket_id]++;
        }
        if (bucket_ids.empty())
            continue;

        auto max_bkid_c = std::max_element(bucket_ids.begin(), bucket_ids.end(), [](const auto &a, const auto &b) {return a.second < b.second;});
        if (max_bkid_c->second < 2)
            continue;
        auto max_bkid = max_bkid_c->first;

        if (frame_len == 2) {
            handle_commande_case(page_accesses, frame_base + 1, max_bkid);
            continue;
        }

        for (unsigned int i = frame_base + 1; i < frame_base + frame_len - 1 && page_accesses[i].gpa != sync_gpa; i++)
            for (const auto cl: page_accesses[i].accessed_cls | std::views::keys)
                page_accesses[i].set_cl_confidence_score(cl, 0);

        auto max_page = frame_base;
        unsigned long max_cl = 0;
        unsigned int max_pos = 0;
        for (unsigned int i = frame_base + frame_len - 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++) {
            page_accesses[i].bucket_access = true;
            for (const auto cl: page_accesses[i].accessed_cls | std::views::keys)
                if (gpa_to_token[cl].bucket_id == max_bkid && gpa_to_token[cl].bucket_pos >= max_pos) {
                    max_pos = gpa_to_token[cl].bucket_pos;
                    max_cl = cl;
                    max_page = i;
                }
        }

        for (unsigned int i = frame_base + frame_len - 1; i < page_accesses.size() && page_accesses[i].gpa != sync_gpa; i++) {
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

// On the next page access after a confirmed token, there is no token
static void filter_gap(std::vector<page_accesses> &page_accesses) {
    for (auto it = page_accesses.begin() + 1; it + 1 != page_accesses.end(); ++it) {
        bool confirmed = false;
        for (const auto score: it->accessed_cls | std::views::values) {
            if (score >= 200) {
                confirmed = true;
                break;
            }
        }

        if (!confirmed)
            continue;

        for (const auto cl: (it + 1)->accessed_cls | std::views::keys)
            (it + 1)->set_cl_confidence_score(cl, 15);
        for (const auto cl: (it - 1)->accessed_cls | std::views::keys)
            (it - 1)->set_cl_confidence_score(cl, 15);
    }
}

// We often observe double-accesses of tokens with a page in-between (<token A> -> <something else> -> <token A again>)
// Keep only the second, but give it a high confidence score
static void filter_double_tap(std::vector<page_accesses> &page_accesses) {
    bool last_had_double_tap = false;
    for (auto it = page_accesses.begin() + 1; it + 3 != page_accesses.end(); ++it) {
        if (it->gpa != (it + 2)->gpa) {
            last_had_double_tap = false;
            continue;
        }

        std::set<unsigned long> double_tap_cls;
        for (auto cl: it->accessed_cls | std::views::keys) {
            for (auto cl_r: (it + 2)->accessed_cls | std::views::keys) {
                if (std::abs(static_cast<long>(cl_r) - static_cast<long>(cl)) <= 1 && (it + 2)->get_cl_confidence_score(cl_r) > 10) {
                    double_tap_cls.insert(cl);
                }
            }
        }

        if (last_had_double_tap) {
            for (const auto cl: (it + 1)->accessed_cls | std::views::keys)
                (it + 1)->accessed_cls[cl] = std::min(static_cast<unsigned char>(30),
                                                      (it + 1)->get_cl_confidence_score(cl));
        } else {
            for (const auto cl: (it - 1)->accessed_cls | std::views::keys)
                (it - 1)->set_cl_confidence_score(cl, (it - 1)->get_cl_confidence_score(cl) + 20);
        }

        for (const auto cl: it->accessed_cls | std::views::keys)
            it->accessed_cls[cl] = std::min(static_cast<unsigned char>(14), it->get_cl_confidence_score(cl));

        if (double_tap_cls.empty()) {
            if (last_had_double_tap) {
                for (const auto cl: (it + 2)->accessed_cls | std::views::keys)
                    (it + 2)->set_cl_confidence_score(cl, 150);
                for (const auto cl: (it + 3)->accessed_cls | std::views::keys)
                    (it + 3)->set_cl_confidence_score(cl, 40);
            }
            last_had_double_tap = false;
            continue;
        }

        for (const auto cl: (it + 2)->accessed_cls | std::views::keys)
            (it + 2)->set_cl_confidence_score(cl, double_tap_cls.contains(cl)
                                                      ? 160
                                                      : std::min(static_cast<unsigned char>(13),
                                                                 (it + 2)->get_cl_confidence_score(cl)));

        last_had_double_tap = true;
    }
}

// Remove all tokens where the next token of the same bucket was observed in the next page fault
static void filter_no_next_in_chain(std::vector<page_accesses> &page_accesses) {
    for (auto it = page_accesses.begin(); it + 1 != page_accesses.end(); ++it) {
        bool match = false;
        for (const auto cl: it->accessed_cls | std::views::keys) {
            auto bucket_id = gpa_to_token[cl].bucket_id;
            // auto bucket_pos = gpa_to_token[cl].bucket_pos;

            for (const auto cl_r: (it + 1)->accessed_cls | std::views::keys) {
                auto r_bucket_id = gpa_to_token[cl_r].bucket_id;
                // auto r_bucket_pos = gpa_to_token[cl_r].bucket_pos;
                if (bucket_id == r_bucket_id) {
                    match = true;
                    break;
                }
            }

            if (!match)
                continue;

            for (const auto cl_r: (it + 1)->accessed_cls | std::views::keys) {
                auto r_bucket_id = gpa_to_token[cl_r].bucket_id;
                // auto r_bucket_pos = gpa_to_token[cl_r].bucket_pos;
                if (bucket_id != r_bucket_id)
                    (it + 1)->set_cl_confidence_score(cl_r, 0);
            }

            break;
        }

        if (!match)
            continue;

        for (const auto cl: it->accessed_cls | std::views::keys)
            it->accessed_cls[cl] = 0;
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
            auto score = fault.get_cl_confidence_score(cl);
            /*if (fault.measured_cls.contains(cl + 0x40) && fault.measured_cls.contains(cl - 0x40))
                score = std::min(score + 5, 199);
            else if (fault.measured_cls.contains(cl + 0x40) && (gpa_to_token[cl].gpa & 0x3f) >= 0x28)
                ;
            else*/
                score = score > 5 ? score - 5 : 1;
            fault.set_cl_confidence_score(cl, score);
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

static void filter_blacklist_tokens(std::vector<page_accesses> &page_accesses) {
    constexpr std::array blacklist_tokens = {
        1634u,
        143130u,
    };
    auto lookup = blacklist_tokens | std::views::transform([](const auto id) {return id_to_token[id].gpa & ~0x3ful;});
    const std::set blacklist_gpas (lookup.begin(), lookup.end());

    for (auto& fault : page_accesses) {
        for (const auto cl: fault.accessed_cls | std::views::keys) {
            if (blacklist_gpas.contains(cl))
                fault.set_cl_confidence_score(cl, 0);
        }
    }
}

// Slightly deprioritize accesses with an adjacent high score
static void filter_deprioritize_bloom(std::vector<page_accesses> &page_accesses) {
    unsigned char max_last = 0, max_cur = 0, max_next = 0;
    for (auto it = page_accesses.begin() + 2; it != page_accesses.end(); ++it) {
        max_last = max_cur;
        max_cur = max_next;
        max_next = 0;
        for (const auto score: it->accessed_cls | std::views::values)
            max_next = std::max(score, max_next);

        if (max_next < 150 && max_last < 150)
            continue;

        auto offset = std::max(max_next, max_last) - 150;
        for (const auto cl: (it - 1)->accessed_cls | std::views::keys) {
            auto score = (it - 1)->get_cl_confidence_score(cl);
            if (score > offset)
                (it - 1)->set_cl_confidence_score(cl, score - offset);
        }
    }
}

constexpr double LOWER_QUANTILE = 0.02;   // 2%
constexpr double UPPER_QUANTILE = 0.98;   // 98%
constexpr std::size_t NUM_BUCKETS = 100;  // number of histogram buckets

struct HistogramBucket {
    double range_start;
    double range_end;
    size_t count;
};

template <typename T>
static double quantile(const std::vector<T>& data, double q) {
    if (data.empty())
        return 0;
    if (q < 0.0 || q > 1.0)
        return 0;

    auto n = data.size();
    auto pos = q * static_cast<double>(n - 1);
    auto idx = static_cast<size_t>(pos);
    double frac = pos - static_cast<double>(idx);

    if (idx + 1 < n)
        return data[idx] + frac * (data[idx + 1] - data[idx]);
    else
        return data[idx];
}

template <typename T>
static std::vector<HistogramBucket> get_histogram(std::vector<T> values, const T vmin, const T vmax) {
    if (values.size() < 2)
        return {};

    std::sort(values.begin(), values.end());

    auto fview = values | std::views::filter([vmin, vmax](const auto v){return v >= vmin && v <= vmax;});
    std::vector filtered(fview.begin(), fview.end());
    printf("Filtered %lu\n", filtered.size());
    if (filtered.empty())
        return {};

    // Build histogram
    double bucket_width = (vmax - vmin) / static_cast<double>(NUM_BUCKETS);
    printf("Min: %lx, Max: %lx, Width %lx\n", vmin, vmax, static_cast<unsigned long>(bucket_width));

    std::vector<HistogramBucket> buckets(NUM_BUCKETS);
    for (size_t i = 0; i < NUM_BUCKETS; ++i) {
        buckets[i].range_start = vmin + static_cast<double>(i) * bucket_width;
        buckets[i].range_end = vmin + static_cast<double>(i + 1) * bucket_width;
        buckets[i].count = 0;
    }

    for (auto v : filtered) {
        auto idx = static_cast<size_t>((v - vmin) / bucket_width);
        if (idx >= NUM_BUCKETS)
            idx = NUM_BUCKETS - 1; // Edge case: max value
        buckets[idx].count++;
    }

    // Sort buckets by count in descending order
    std::sort(buckets.begin(), buckets.end(),
              [](const HistogramBucket& a, const HistogramBucket& b) {
                  return a.count > b.count;
              });

    return buckets;
}

// Boost tokens a neighbor of which was also measured
static void filter_boost_double_measurement(std::vector<page_accesses> &page_accesses) {
    for (auto& fault : page_accesses) {
        for (const auto cl: fault.measured_cls) {
            if (fault.measured_cls.contains(cl + 0x40) || fault.measured_cls.contains(cl - 0x40)) {
                auto score = fault.get_cl_confidence_score(cl);
                fault.set_cl_confidence_score(cl, std::min(score + 5u, 200u));
            }
        }
    }
}


void apply_filter_chain_gemma(std::vector<page_accesses> &page_accesses) {
    filter_accesses_without_tokens(page_accesses);
    filter_eliminate_dummy_token(page_accesses);
    filter_require_prev_in_chain(page_accesses);
    filter_handle_two_fault_frames(page_accesses);
    filter_handle_single_fault_frames(page_accesses);
    filter_only_one_confirmed(page_accesses);
    filter_blacklist_tokens(page_accesses);
    filter_prioritize_orig(page_accesses);
    filter_boost_double_measurement(page_accesses);
    filter_accesses_without_tokens(page_accesses);
}
