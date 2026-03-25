#ifndef RECOVERY_H
#define RECOVERY_H

#include <set>
#include <vector>
#include <map>

#include "tdxutils.h"
#include "gpa-sync.h"
#include "sequence-analysis.h"

#define SERVER_IP "127.0.0.1"
#define PORT 12123
#define MODEL_LLAMA 1
#define MODEL_GEMMA 2

struct model_specific_configuration {
    unsigned int model;
    unsigned int trail_length;
    const char* start_header_printable;
    const char* end_header_printable;
    const char* start_header;
    const char* end_header;
};

struct page_accesses {
    unsigned long gpa{};
    unsigned long timestamp{};
    unsigned long frame_tsc_diff{};
    std::map<unsigned long, unsigned char> accessed_cls;
    std::set<unsigned long> measured_cls;
    bool bucket_access{};

    void set_cl_confidence_score(unsigned long cl, unsigned char score) {
        auto entry = accessed_cls.find(cl);

        if (entry == accessed_cls.end())
            return;

        if ((entry->second && entry->second < 200))
            accessed_cls[cl] = score;
    }

    unsigned char get_cl_confidence_score(unsigned long cl) const {
        const auto &entry = accessed_cls.find(cl);

        if (entry != accessed_cls.end())
            return entry->second;

        return 0;
    }

    bool operator==(const page_accesses &o) const {
        return o.gpa == gpa;
    }

    page_accesses() = default;

    explicit page_accesses(unsigned long gpa) : gpa(gpa), accessed_cls(std::map<unsigned long, unsigned char>()) {
    }

    page_accesses(unsigned long gpa,
                  const std::map<unsigned long, unsigned char> &accessed_cls) : gpa(gpa), accessed_cls(accessed_cls) {
    }

    page_accesses(unsigned long gpa, const std::set<unsigned long> &cls, const std::set<unsigned long> &measured,
                  const unsigned long timestamp, const unsigned long frame_tsc_diff) : gpa(gpa), timestamp(timestamp), frame_tsc_diff(frame_tsc_diff), measured_cls(measured),
                                                   bucket_access(false) {
        for (auto cl: cls)
            accessed_cls[cl] = 100;
    }
};

extern unsigned long tdr_pa;
extern unsigned long sync_gpa;
extern const model_specific_configuration* target_model;
extern std::vector<unsigned long> target_gpas;
extern std::map<unsigned long, gpa_sync_entry> id_to_token;
extern std::map<unsigned long, gpa_sync_entry> gpa_to_token;

int connect_to_victim();
void send_buffer(int client_fd, const unsigned char *buf, unsigned long len);
gpa_sync *get_token_addresses(int victim_fd);
void init_tokens(const gpa_sync *token_sync, bool verbose);

void extract_prompt(const std::vector<tdx_access_monitor_hit> &accesses, bool verbose, std::vector<page_accesses>& out_accesses);
int monitor_all_tokens(int util_fd, int victim_fd, const char *prompt, std::vector<tdx_access_monitor_hit> &accesses);
std::tuple<unsigned long, unsigned char, const char *> get_best_token(const page_accesses &access);

AlignmentResult<page_accesses> align_repeating_tokenizations(const std::vector<page_accesses> &page_accesses, bool verbose);
std::vector<page_accesses> pessimistic_merge(AlignmentResult<page_accesses> &aligned);
std::vector<page_accesses> optimistic_merge(AlignmentResult<page_accesses> &aligned);

std::vector<unsigned long> get_correct_sequence(const unsigned long* correct_token_array, unsigned long num_tokens);
std::vector<unsigned long> get_correct_sequence(const std::vector<unsigned long>& tokens);
std::vector<page_accesses> isolate_prompt(const std::vector<page_accesses> &page_accesses, bool verbose);

std::string decode_accesses(const std::vector<page_accesses> &page_accesses);
void print_decoded_accesses(const std::vector<page_accesses> &page_accesses);

unsigned int split_target_pages(int util_fd, const std::vector<unsigned long> &gpas);
bool verify_target_page_level(int util_fd, const std::vector<unsigned long> &gpas);

void init_correct_tokens(const int32_t* tokens, unsigned long num_tokens);

void apply_filter_chain_llama(std::vector<page_accesses> &page_accesses);
void apply_filter_chain_gemma(std::vector<page_accesses> &page_accesses);

#endif