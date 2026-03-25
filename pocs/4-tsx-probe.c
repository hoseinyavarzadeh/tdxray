#include "ttoolbox.h"
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include "modkmap.h"
#include "tdxutils.h"

static const char loading[] = "-\\|/";

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
    unsigned int i, c = 0;
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

    printf("Note: Ensure that TSX is enabled on your test platform. If in doubt, run 'sudo wrmsr -a 0x122 0'\n");

    for (i = 0; /*infinite*/; i++) {
        volatile unsigned long aborted = 0;

        asm volatile (
            "xbegin 1f\n"
            "mov (%%rsi), %%rdi\n"
            "xend\n"
            "jmp 2f\n"
            "1:\n"
            "inc %%rcx\n"
            "2:\n"
            : "+c" (aborted)
            : "S" (target_page)
            : "rax", "rdi", "memory"
        );

        printf("\r[%c] %s            ", loading[c++ % strlen(loading)], aborted ? CRED "Transaction Aborted" CRESET : CCYN "Transaction Committed" CRESET);
        fflush(stdout);
        usleep(100000);
    }
}
