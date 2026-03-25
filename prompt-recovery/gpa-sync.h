#ifndef GPA_SYNC_H
#define GPA_SYNC_H

#ifndef __cplusplus
extern "C" {
#endif

struct gpa_sync_entry {
    char token_string[256]; // Not necessarily 0-terminated!
    unsigned long token_id;
    unsigned long gpa;
    unsigned int bucket_id;
    unsigned int bucket_pos;
} __attribute__((packed));

struct gpa_sync {
    unsigned long num_tokens;
    unsigned long tokenizer_code_gpa;
    unsigned long sampling_code_gpa;
    struct gpa_sync_entry tokens[1];
} __attribute__((packed));

#ifndef __cplusplus
}
#endif
#endif