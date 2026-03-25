#ifndef _MODKMAP__H_
#define _MODKMAP__H_

#ifndef MODKMAP_KERNEL
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdint.h>
#endif

#define PTE_PRESENT     (1 << 0)
#define PTE_RW          (1 << 1)
#define PTE_US          (1 << 2)

#define PMD_LARGE_PAGE  (1 << 7)

#define PAGE_NOT_PRESENT    0
#define PAGE_2MB            1
#define PAGE_4KB            2

#define PAT_UNCACHABLE          0
#define PAT_WRITE_COMBINING     1
#define PAT_WRITE_THROUGH       4
#define PAT_WRITE_PROTECTED     5
#define PAT_WRITE_BACK          6
#define PAT_UNCACHED            7

typedef uint64_t e_p5d_t;
typedef uint64_t e_p4d_t;
typedef uint64_t e_pud_t;
typedef uint64_t e_pmd_t;
typedef uint64_t e_pte_t;

typedef struct {
    e_p5d_t p5d;
    e_p4d_t p4d;
    e_pud_t pud;
    e_pmd_t pmd;
    e_pte_t pte;

    unsigned long vaddr;
    unsigned int page_type;
} __attribute__((packed)) page_walk_t;

typedef struct modkmap_control_regs {
    unsigned long cr0;
    unsigned long cr2;
    unsigned long cr3;
    unsigned long cr4;
    unsigned long cr8;

    unsigned long dr0;
    unsigned long dr1;
    unsigned long dr2;
    unsigned long dr3;
    unsigned long dr6;
    unsigned long dr7;
} __attribute__((packed)) modkmap_control_regs;

struct vma_list_entry {
    unsigned long start;
    unsigned long end;
    unsigned long prot;
} __attribute__((packed));

#define MAX_VMA_LIST_ENTRIES 0x80

struct vma_list {
    unsigned int max_entries;
    unsigned int num_entries;
    struct vma_list_entry entries[1];
} __attribute__((packed));

struct x64_pat
{
    union
    {
        uint64_t raw;
        unsigned char entries[8];
    };
};

struct io_request {
    unsigned int value;
    unsigned short address;
    unsigned char size; // Bytes, can be 1, 2, and 4
};

#define MODKMAP_INTERFACE_TYPE          0xc5
#define IOCTL_RD_DIRECT_MAP             _IOWR(MODKMAP_INTERFACE_TYPE, 1, unsigned long)
#define IOCTL_RD_TEST_PAGE_ADDR         _IOWR(MODKMAP_INTERFACE_TYPE, 2, unsigned long)
#define IOCTL_RD_CONTROL_REGS           _IOWR(MODKMAP_INTERFACE_TYPE, 4, modkmap_control_regs)
#define IOCTL_RD_MAX_PADDR              _IOWR(MODKMAP_INTERFACE_TYPE, 5, unsigned long)
#define IOCTL_RD_PAGE_TABLES            _IOWR(MODKMAP_INTERFACE_TYPE, 6, page_walk_t)
#define IOCTL_PADDR_PROBE_ACCESS_TIME   _IOWR(MODKMAP_INTERFACE_TYPE, 7, unsigned long)
#define IOCTL_KMACCESS                  _IOWR(MODKMAP_INTERFACE_TYPE, 8, unsigned long)
#define IOCTL_GET_VMA_LIST              _IOWR(MODKMAP_INTERFACE_TYPE, 9, struct vma_list)
#define IOCTL_WR_PAGE_TABLES            _IOWR(MODKMAP_INTERFACE_TYPE, 78, page_walk_t)
#define IOCTL_RD_PAT                    _IOWR(MODKMAP_INTERFACE_TYPE, 79, struct x64_pat)
#define IOCTL_WR_PAT                    _IOWR(MODKMAP_INTERFACE_TYPE, 80, struct x64_pat)
#define IOCTL_WBINVD                    _IO(  MODKMAP_INTERFACE_TYPE, 81)
#define IOCTL_RD_IO                     _IOWR(MODKMAP_INTERFACE_TYPE, 82, struct io_request)
#define IOCTL_WR_IO                     _IOWR(MODKMAP_INTERFACE_TYPE, 83, struct io_request)

#ifndef MODKMAP_KERNEL

// mmap with memory type
static void* mmap_mt(void* addr, size_t length, int prot, int flags, int fd, off_t offset, int modkmap_fd, unsigned char memory_type) {
    void* ret = mmap(addr, length, prot, flags | MAP_POPULATE, fd, offset);
    page_walk_t vm = {0, };
    struct x64_pat pat = {.raw = 0};
    ssize_t status;
    unsigned long pos;
    unsigned char pat_i;

    if (ret == MAP_FAILED)
        return ret;

    status = ioctl(modkmap_fd, IOCTL_RD_PAT, &pat.raw);
    if (status < 0)
        goto fail;

    for (pat_i = 0; pat_i < 8; pat_i++)
        if (pat.entries[pat_i] == memory_type)
            break;
    if (pat_i >= 8)
        goto fail;

    for (pos = 0; pos < length; pos += 0x1000) {
        vm.vaddr = (unsigned long) ret + pos;

        status = ioctl(modkmap_fd, IOCTL_RD_PAGE_TABLES, &vm);
        if (status < 0)
            continue;

        if (vm.page_type != PAGE_4KB)
            continue;

        vm.pte &= ~0b10011000;
        vm.pte |= ((pat_i & 3) << 3) | ((pat_i & 4) << 4);

        ioctl(modkmap_fd, IOCTL_WR_PAGE_TABLES, &vm);
    }

    return ret;
fail:
    munmap(ret, length);
    return MAP_FAILED;
}
#endif

#endif
