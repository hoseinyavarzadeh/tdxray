#ifndef LIBTOKENIZE_H
#define LIBTOKENIZE_H

#ifdef __cplusplus
extern "C" {
#endif

struct token_info {
    char token_string[256]; // Not necessarily 0-terminated!
    unsigned long token_id;
};

int libtokenize_init(const char* file_path);
void libtokenize_exit(void);
void libtokenize_free_string(const char* str);
void libtokenize_free_tokens(int32_t* tokens);
unsigned long libtokenize_get_tokens(const char* prompt_ptr, int32_t** tokens_out);
const char* libtokenize_tokens_to_string(const int32_t* tokens, unsigned long num_tokens);

#ifdef __cplusplus
}

struct lookup_access {
    unsigned int hash {};
    unsigned int token_id {};
    unsigned int lookup_id {};
    std::string substring;

    lookup_access (const unsigned int hash, const unsigned int token_id, const unsigned int lookup_id, std::string substring) :
        hash(hash), token_id(token_id), lookup_id(lookup_id), substring(std::move(substring)) {}
};


#include <vector>
#include <utility>
std::vector<std::pair<std::string, unsigned long>>& get_accessed_tokens();
std::vector<lookup_access> get_all_accesses();

#endif

#endif