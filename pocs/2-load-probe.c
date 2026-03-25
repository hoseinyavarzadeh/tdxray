#include "ttoolbox.h"
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include "rt_histogram.h"
#include "modkmap.h"
#include "tdxutils.h"

#define X_AXIS_TARGET   4000
#define X_AXIS_MAX      4000
#define SAMPLE_INTERVAL 10
#define AVG_LEN 1000

// %0 <- target address
// %1 <- 1

#define MEASUREMENT_SEQUENCE "mov (%0), %1"

static unsigned int __attribute__((aligned(0x1000))) avg_buf[AVG_LEN];

static unsigned long avg_d(const unsigned int *buf, unsigned long len) {
    unsigned long sum = 0, _len = len;
    while (_len--)
        sum += buf[_len];
    return sum / len;
}

static inline __attribute__((always_inline)) unsigned long access_time(void *p) {
    unsigned long ret;
    tt_maccess((unsigned char*) p + 0x800); // Make sure the translation is in TLB
    tt_mfence();
    ret = tt_rdtsc();
    asm volatile (MEASUREMENT_SEQUENCE :: "r"(p), "r"(1));
    tt_mfence();
    return tt_rdtsc() - ret;
}

static unsigned long gpa_to_hpa(int util_fd, unsigned long gpa, unsigned long tdr_pa) {
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

int main(int argc, char *argv[]) {
    unsigned long target_paddr;
    unsigned char *target_page;
    unsigned long tdr_pa, hpa;
    unsigned int i;
    int modkmap_fd, tdxutils_fd;

    if (argc <= 1) {
        printf("Usage: %s <GPA>\n", argv[0]);
        return 0;
    }

    modkmap_fd = open("/dev/modkmap", O_RDONLY);
    if (modkmap_fd < 0) {
        perror("open /dev/modkmap");
        exit(EXIT_FAILURE);
    }

    tdxutils_fd = open("/dev/tdxutils", O_RDONLY);
    if (tdxutils_fd < 0) {
        perror("open /dev/tdxutils_fd");
        exit(EXIT_FAILURE);
    }

    tdr_pa = get_tdr_pa(tdxutils_fd);

    histogram_init(X_AXIS_TARGET, 10, X_AXIS_MAX);
    strncpy(histo_xlabel, "Cycles", sizeof(histo_xlabel) - 1);
    strncpy(histo_ylabel, "# Samples", sizeof(histo_xlabel) - 1);
    snprintf(histogram_title, sizeof(histogram_title), "Probing Access Time for Instruction '%s'", MEASUREMENT_SEQUENCE);


    target_paddr = strtoul(argv[1], NULL, 16);
    hpa = gpa_to_hpa(tdxutils_fd, target_paddr, tdr_pa);
    if (!~hpa) {
        printf("Could not resolve GPA 0x%lx", target_paddr);
        exit(EXIT_FAILURE);
    }
    target_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, modkmap_fd, (off_t) (hpa & ~0xffful));
    if (target_page == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    target_page += target_paddr & 0xffful;

    snprintf(histogram_title_right, sizeof(histogram_title_right), "Target HPA: 0x%lx", hpa);

    for (i = 0; /*infinite*/; i++) {
        avg_buf[i % AVG_LEN] = (unsigned int) access_time(target_page);
        usleep(SAMPLE_INTERVAL);

        if (i % (50000 / SAMPLE_INTERVAL) == 0) {
            histogram_update(avg_buf, countof(avg_buf));
            snprintf(histogram_title_left, sizeof(histogram_title_left), "Average: %lu", avg_d(avg_buf, countof(avg_buf)));
        }
    }
}
