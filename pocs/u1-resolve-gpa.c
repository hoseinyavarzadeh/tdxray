#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "../tdxutils/tdxutils.h"

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

int main(int argc, char* argv[]) {
    unsigned long gpa, hpa;
    char* endptr = 0;
    int util_fd;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <GPA>\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    gpa = strtoul(argv[1], &endptr, 0);
    if (*endptr != '\0'){
        fprintf(stderr, "Could not parse GPA '%s'. Please give me valid integer in hex.\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    util_fd = open("/dev/" TDXUTILS_DEVICE_NAME, O_RDWR);
    if (util_fd < 0) {
        fprintf(stderr, "Could not open the /dev/" TDXUTILS_DEVICE_NAME " device file. Make sure that the kernel module is loaded\n");
        exit(EXIT_FAILURE);
    }

    hpa = gpa_to_hpa(util_fd, gpa, get_tdr_pa(util_fd));
    if (!~hpa) {
        printf("Could not translate GPA\n");}
    else
        printf("0x%lx\n", hpa);

    close(util_fd);
    return 0;
}
