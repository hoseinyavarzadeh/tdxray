#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include "../tdxutils/tdxutils.h"

#define CRESET "\033[39m"
#define CGRN "\033[92m"
#define CCYN "\033[96m"
#define CRED "\033[91m"

// Helper function to check page level
static unsigned char get_page_level(int util_fd, unsigned long gpa, unsigned long tdr_pa) {
    union tdx_sept_entry entry;
    unsigned long rc;

    // Align to 2MB boundary for checking
    gpa = gpa & ~((1ul << 21) - 1);
    
    rc = seamcall_tdh_mem_sept_rd(util_fd, 1, gpa, tdr_pa, (void*) &entry, NULL);
    if (rc != TDX_SUCCESS) {
        fprintf(stderr, "Error - Could not resolve GPA 0x%lx! Make sure it is valid.\n", gpa);
        return 0;  // Return 0 (4KB) as default
    }

    return entry.leaf ? 1 : 0;  // 1 = 2MB page, 0 = 4KB page
}

// Function to split huge pages
static int split_huge_pages(int util_fd, unsigned long start_gpa, unsigned long end_gpa, unsigned long tdr_pa) {
    struct tdx_split_huge_pages_req req = {
        .tdr_pa = tdr_pa,
        .start_gpa = start_gpa,
        .end_gpa = end_gpa,
        .target_level = 0  // PG_LEVEL_4K
    };
    
    printf("Splitting huge pages from " CCYN "0x%lx" CRESET " to " CCYN "0x%lx" CRESET "\n", 
           start_gpa, end_gpa);
    
    if (ioctl(util_fd, IOCTL_TDX_SPLIT_HUGE_PAGES, &req) < 0) {
        perror("ioctl IOCTL_TDX_SPLIT_HUGE_PAGES");
        return -1;
    }
    
    printf(CGRN "Successfully split huge pages in range 0x%lx - 0x%lx\n" CRESET, 
           start_gpa, end_gpa);
    return 0;
}

// Function to verify the split worked
static void verify_split(int util_fd, unsigned long gpa, unsigned long tdr_pa) {
    printf("\nVerifying split at GPA " CCYN "0x%lx" CRESET ":\n", gpa);
    
    // Check a few addresses around the GPA
    for (int i = -1; i <= 1; i++) {
        unsigned long test_gpa = gpa + (i * 0x200000);  // +/- 2MB
        unsigned char level = get_page_level(util_fd, test_gpa, tdr_pa);
        printf("  GPA 0x%lx: " CCYN "%s" CRESET " page\n", 
               test_gpa, level == 0 ? "4KB" : "2MB");
    }
}

int main(int argc, char* argv[]) {
    unsigned long gpa, tdr_pa;
    char* endptr = 0;
    int util_fd;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <GPA>\n", argv[0]);
        fprintf(stderr, "This program splits a 2MB page containing the given GPA into 4KB pages\n");
        fprintf(stderr, "Example: %s 0x10000000\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    gpa = strtoul(argv[1], &endptr, 0);
    if (*endptr != '\0'){
        fprintf(stderr, "Could not parse GPA '%s'. Please give valid integer in hex.\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    util_fd = open("/dev/" TDXUTILS_DEVICE_NAME, O_RDWR);
    if (util_fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    tdr_pa = get_tdr_pa(util_fd);
    printf("TDR PA: " CCYN "0x%lx" CRESET "\n", tdr_pa);

    // Align GPA to 2MB boundary for splitting
    unsigned long start_gpa = gpa & ~((1UL << 21) - 1);  // 2MB aligned start
    unsigned long end_gpa = start_gpa + (1UL << 21);     // 2MB range
    
    printf("Target GPA: " CCYN "0x%lx" CRESET "\n", gpa);
    printf("Split range: " CCYN "0x%lx" CRESET " - " CCYN "0x%lx" CRESET " (2MB)\n", 
           start_gpa, end_gpa);

    // Check current page level
    printf("\nBefore split:\n");
    verify_split(util_fd, gpa, tdr_pa);

    // Split the huge page
    if (split_huge_pages(util_fd, start_gpa, end_gpa, tdr_pa) == 0) {
        // Verify the split
        printf("\nAfter split:\n");
        verify_split(util_fd, gpa, tdr_pa);
    }

    close(util_fd);
    return 0;
}