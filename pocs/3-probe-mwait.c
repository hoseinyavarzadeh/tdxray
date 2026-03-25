#include "ttoolbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/poll.h>
#include "tdxutils.h"

#define CRESET "\033[39m"
#define CGRN "\033[92m"
#define CCYN "\033[96m"

// Counts the number of lines that are silently dropped by L2 cache. These lines are typically in Shared or Exclusive state. A non-threaded event.
static const struct pmc_info emerald_rapids_L2_LINES_OUT_SILENT = {
    .evt = {
        .event_sel = 0x26,
        .umask = 0x1,
    },
    .offcore_rsp = 0
};

#define ACCESS_TYPE TDX_ACCESS_TYPE_LOAD
#define target_pmc emerald_rapids_L2_LINES_OUT_SILENT

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

static void mwait_monitor(int mwait_fd, unsigned long hpa, unsigned char core_id) {
    int status;
    unsigned long tsc = 0;
    struct pollfd pfd = {.fd = mwait_fd, .events = POLLIN};
    struct tdx_mwait_target target = {.hpa = hpa, .pmc = target_pmc, .core = core_id, .access_type = ACCESS_TYPE};
    struct tdx_mwait_access access = {0, };
    struct timespec ts = {0, };
    double now = 0, last = 0;

    target.pmc.evt.os = 1;
    target.pmc.evt.en = 1;

    status = ioctl(mwait_fd, IOCTL_MWAIT_MONITOR_SINGLE, &target);
    if (status < 0) {
        perror("IOCTL_MWAIT_MONITOR_SINGLE");
        exit(EXIT_FAILURE);
    }

    do {
        status = poll(&pfd, 1, 500);
        if (status <= 0)
            continue;

        while (read(mwait_fd, &access, sizeof(access)) > 0) {}


        clock_gettime(CLOCK_REALTIME, &ts);
        now = (double) ts.tv_sec + (double)ts.tv_nsec / 1000000000;
        if (now - last > 0.1) {
            printf("\rMWAIT TSC Delta: " CRED "0x%016lx " CRESET " - PMC Delta: " CGRN "0x%016lx" CRESET " - Access TSC Delta: " CCYN "0x%016lx" CRESET, access.tsc - tsc, access.pmc_delta, access.tsc_delta);
            last = now;
            fflush(stdout);
        }

        tsc = access.tsc;
    } while(status >= 0);
}

int main(int argc, char* argv[]) {
    unsigned long gpa, hpa, core_id;
    char* endptr = 0;
    int util_fd, mwait_fd;
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <GPA> <core ID>\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    gpa = strtoul(argv[1], &endptr, 0);
    if (*endptr != '\0'){
        fprintf(stderr, "Could not parse GPA '%s'. Please give me valid integer in hex.\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    core_id = strtoul(argv[2], &endptr, 0);
    if (*endptr != '\0') {
        fprintf(stderr, "Could not parse core ID '%s'. Please give me valid integer in hex or decimal.\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    util_fd = open("/dev/" TDXUTILS_DEVICE_NAME, O_RDWR);
    if (util_fd < 0) {
        fprintf(stderr, "Could not open the /dev/" TDXUTILS_DEVICE_NAME " device file. Make sure that the kernel module is loaded\n");
        exit(EXIT_FAILURE);
    }
    mwait_fd = open("/dev/" TDX_MWAIT_DEVICE_NAME, O_RDWR);
    if (mwait_fd < 0) {
        fprintf(stderr, "Could not open the /dev/" TDX_MWAIT_DEVICE_NAME " device file. Make sure that the kernel module is loaded and mwait is supported by your CPU\n");
        exit(EXIT_FAILURE);
    }

    hpa = gpa_to_hpa(util_fd, gpa, get_tdr_pa(util_fd));
    close(util_fd);

    printf("HPA %lx\n", hpa);
    mwait_monitor(mwait_fd, hpa, (unsigned char) core_id);

    close(mwait_fd);
    return 0;
}
