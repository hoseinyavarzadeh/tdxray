#define MODKMAP_KERNEL 1
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/ioport.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/msr.h>
#include "modkmap.h"
#include "device_register.h"

#ifndef DEBUG
#define dprintk(...)
#else
#define dprintk(...) printk(__VA_ARGS__)
#endif

#define DEVICE_NAME     "modkmap"

static struct mutex instance_lock;
static struct device_info devinfo = {0,};
static volatile unsigned char *dummy_page = NULL;
static unsigned long pte_addr_mask = 0, lp_addr_mask = 0;

#ifndef PAGE_MASK
#define PAGE_MASK     (~(PAGE_SIZE - 1))
#endif

#define LARGE_PAGE_SHIFT    21
#define LARGE_PAGE_SIZE     (1 << LARGE_PAGE_SHIFT)
#define LARGE_PAGE_MASK     (~(LARGE_PAGE_SIZE - 1))

#define P5D_INDEX(x)  (((uint64_t)(x) >> 48) & 0x1ff)
#define P4D_INDEX(x)  (((uint64_t)(x) >> 39) & 0x1ff)
#define PUD_INDEX(x)  (((uint64_t)(x) >> 30) & 0x1ff)
#define PMD_INDEX(x)  (((uint64_t)(x) >> 21) & 0x1ff)
#define PTE_INDEX(x)  (((uint64_t)(x) >> 12) & 0x1ff)

#define MAX_ALLOCATION_UNIT (1ul << 30)

static inline unsigned long __attribute__((always_inline)) tt_rdtsc(void) {
    unsigned long a, d;
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (d << 32) | a;
}

static inline void __attribute__((always_inline)) tt_maccess(const void *p) {
    asm volatile("mov (%0), %%rax" :: "r"(p) : "rax");
}

static inline void __attribute__((always_inline)) tt_mfence(void) {
    asm volatile("mfence");
}

static inline unsigned long __attribute__((always_inline)) tt_access_time(const void *p) {
    unsigned long s;
    tt_mfence();
    s = tt_rdtsc();
    tt_maccess(p);
    tt_mfence();
    return tt_rdtsc() - s;
}

static void init_page_table_utils(void) {
    uintptr_t maxphys;

    asm ("cpuid" : "=a"(maxphys) : "a"(0x80000008), "c" (0) : "rbx", "rdx");
    maxphys &= (1 << 8) - 1;

    pte_addr_mask = ((1ull << maxphys) - 1) & PAGE_MASK; // Mask for 4kB pages
    lp_addr_mask = ((1ull << maxphys) - 1) & LARGE_PAGE_MASK; // Mask for 2MB pages
}

static int do_page_walk(page_walk_t *out) {
    const e_p5d_t *p5d;
    const e_p4d_t *p4d;
    const e_pud_t *pud;
    const e_pmd_t *pmd;
    const e_pte_t *pte;
    unsigned long cur_paddr;
    unsigned long cr3;

    asm volatile ("mov %%cr3, %0" : "=r"(cr3));

    out->p5d = ~0ul;
    out->p4d = 0;
    out->pud = 0;
    out->pmd = 0;
    out->pte = 0;
    out->page_type = PAGE_NOT_PRESENT;

    // P4D
    cur_paddr = cr3 & pte_addr_mask;
    if (unlikely(pgtable_l5_enabled())) {
        // P5D if necessary
        cur_paddr += P5D_INDEX(out->vaddr) * sizeof(*p5d);
        if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
            return -EINVAL;
        p5d = phys_to_virt(cur_paddr);
        cur_paddr = *p5d & pte_addr_mask;
        out->p5d = *p5d;
        if (!(*p5d & PTE_PRESENT))
            return -EINVAL;
    }
    cur_paddr += P4D_INDEX(out->vaddr) * sizeof(*p4d);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    p4d = phys_to_virt(cur_paddr);
    cur_paddr = *p4d & pte_addr_mask;
    out->p4d = *p4d;
    if (!(out->p4d & PTE_PRESENT))
        return -EINVAL;

    // PUD
    cur_paddr += PUD_INDEX(out->vaddr) * sizeof(*pud);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    pud = phys_to_virt(cur_paddr);
    cur_paddr = *pud & pte_addr_mask;
    out->pud = *pud;
    if (!(out->pud & PTE_PRESENT))
        return -EINVAL;

    // PMD
    cur_paddr += PMD_INDEX(out->vaddr) * sizeof(*pmd);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    pmd = phys_to_virt(cur_paddr);
    cur_paddr = *pmd & pte_addr_mask;
    out->pmd = *pmd;
    if (!(out->pmd & PTE_PRESENT))
        return -EINVAL;
    if (out->pmd & PMD_LARGE_PAGE) {
        out->page_type = PAGE_2MB;
        return 0;
    }

    // PTE
    cur_paddr += PTE_INDEX(out->vaddr) * sizeof(*pte);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    pte = phys_to_virt(cur_paddr);
    out->pte = *pte;
    if (out->pte & PTE_PRESENT)
        out->page_type = PAGE_4KB;

    return 0;
}

static long pt_walk(void __user*arg) {
    page_walk_t out;
    long rc;

    if (copy_from_user(&out, arg, sizeof(out)) != 0)
        return -EFAULT;

    rc = do_page_walk(&out);
    if (copy_to_user(arg, &out, sizeof(out)) != 0)
        return -EFAULT;

    return rc;
}

static long write_page_tables(void* __user arg)
{
    page_walk_t vm = {0,};
    e_p5d_t *p5d;
    e_p4d_t *p4d;
    e_pud_t *pud;
    e_pmd_t *pmd;
    e_pte_t *pte;
    unsigned long cr3, cur_paddr;

    if (copy_from_user(&vm, arg, sizeof(vm)) != 0)
        return -EFAULT;

    asm volatile ("mov %%cr3, %0" : "=r"(cr3));

    // P4D
    cur_paddr = cr3 & pte_addr_mask;
    if (unlikely(pgtable_l5_enabled())) {
        // P5D if necessary
        cur_paddr += P5D_INDEX(vm.vaddr) * sizeof(*p5d);
        if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
            return -EINVAL;
        p5d = phys_to_virt(cur_paddr);
        *p5d = vm.p5d;
        cur_paddr = *p5d & pte_addr_mask;

        if (!(*p5d & PTE_PRESENT))
            return 0;
    }
    cur_paddr += P4D_INDEX(vm.vaddr) * sizeof(*p4d);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    p4d = phys_to_virt(cur_paddr);
    *p4d = vm.p4d;
    cur_paddr = *p4d & pte_addr_mask;
    if (!(*p4d & PTE_PRESENT))
        return 0;

    // PUD
    cur_paddr += PUD_INDEX(vm.vaddr) * sizeof(*pud);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    pud = phys_to_virt(cur_paddr);
    *pud = vm.pud;
    cur_paddr = *pud & pte_addr_mask;
    if (!(*pud & PTE_PRESENT))
        return 0;

    // PMD
    cur_paddr += PMD_INDEX(vm.vaddr) * sizeof(*pmd);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    pmd = phys_to_virt(cur_paddr);
    *pmd = vm.pmd;
    cur_paddr = *pmd & pte_addr_mask;
    if (!(vm.pmd & PTE_PRESENT) || (vm.pmd & PMD_LARGE_PAGE))
        return 0;

    // PTE
    cur_paddr += PTE_INDEX(vm.vaddr) * sizeof(*pte);
    if (!pfn_valid(cur_paddr >> PAGE_SHIFT))
        return -EINVAL;
    pte = phys_to_virt(cur_paddr);
    *pte = vm.pte;

    asm volatile ("invlpg (%0)\nmfence\n" :: "r"(vm.vaddr));

    return 0;
}

static unsigned long paddr_get_access_time(unsigned long paddr) {
    void *vaddr;
    unsigned long ret;

    if (!pfn_valid(paddr >> PAGE_SHIFT))
        return ~0ul;

    vaddr = phys_to_virt(paddr);
    tt_maccess((unsigned char *) ((unsigned long) vaddr & ~0xffful) + 0xfc0ul);
    ret = tt_access_time(vaddr);

    asm volatile ("clflush (%0)\nmfence\n" :: "r"(vaddr));

    return ret;
}

static ssize_t modkmap_read(struct file *file, char __user *data, size_t size, loff_t *off) {
    void *buf, *vaddr;
    size_t remaining, copied, to_copy;
    int ret = 0;
    unsigned long pfn;
    struct inode *inode;

    buf = vmalloc(PAGE_SIZE);
    if (!buf)
        return -ENOMEM;

    inode = file_inode(file);
    inode_lock(inode);

    dprintk(KERN_INFO "modkmap: read %lu bytes from paddr %lx\n", size, (unsigned long) *off);

    remaining = size;
    while (remaining > 0) {
        if (*off & (PAGE_SIZE - 1))
            to_copy = min(remaining, PAGE_SIZE - ((unsigned long)*off & (PAGE_SIZE - 1)));
        else
            to_copy = min(remaining, PAGE_SIZE);
        pfn = *off >> PAGE_SHIFT;

        // Check if pfn is valid
        if (pfn_valid(pfn)) {
            vaddr = phys_to_virt(*off);
            if (!vaddr) {
                ret = -EFAULT;
                break;
            }
            memcpy(buf, (unsigned char *) vaddr, to_copy);
        } else
            memset(buf, 0xff, to_copy);

        copied = copy_to_user(data, buf, to_copy);
        if (copied) {
            ret = -EFAULT;
            break;
        }

        *off += to_copy;
        data += to_copy;
        remaining -= to_copy;
    }

    inode_unlock(inode);
    vfree(buf);
    return ret ? ret : (size - remaining);
}

static ssize_t modkmap_write(struct file *f, const char __user *data, size_t size, loff_t *off) {
    return -EBADF;
}

static int modkmap_open(struct inode *inode, struct file *file) {
    dprintk(KERN_INFO "[modkmap] Process %d opened a handle\n", current->pid);
    return 0;
}

static int modkmap_release(struct inode *inode, struct file *file) {
    dprintk(KERN_INFO "[modkmap] Process %d released its handle\n", current->pid);
    return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 16, 0)
typedef int vm_fault_t;

static inline vm_fault_t vmf_insert_pfn(struct vm_area_struct *vma, unsigned long addr, unsigned long pfn) {
    int err = vm_insert_pfn(vma, addr, pfn);

    if (err == -ENOMEM)
        return VM_FAULT_OOM;
    if (err < 0 && err != -EBUSY)
        return VM_FAULT_SIGBUS;

    return VM_FAULT_NOPAGE;
}
#endif

/* Helper function to set VM flags based on kernel version */
static inline void set_vm_flags(struct vm_area_struct *vma, unsigned long flags) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_set(vma, flags);
#else
    vma->vm_flags |= flags;
#endif
}

/* Helper function to clear VM flags based on kernel version */
static inline void clear_vm_flags(struct vm_area_struct *vma, unsigned long flags) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_clear(vma, flags);
#else
    vma->vm_flags &= ~flags;
#endif
}

/* Helper to switch to PFNMAP mode temporarily */
static inline void switch_to_pfnmap(struct vm_area_struct *vma) {
    clear_vm_flags(vma, VM_MIXEDMAP);
    set_vm_flags(vma, VM_PFNMAP);
}

/* Helper to switch back to MIXEDMAP mode */
static inline void switch_to_mixedmap(struct vm_area_struct *vma) {
    clear_vm_flags(vma, VM_PFNMAP);
    set_vm_flags(vma, VM_MIXEDMAP);
}

/* Insert a single page with fallback to PFNMAP */
static int insert_page_with_fallback(struct vm_area_struct *vma,
                                     unsigned long vaddr,
                                     unsigned long cur_pfn) {
    int rc;
    vm_fault_t rcf;
    struct page *page = pfn_to_page(cur_pfn);

    if (pfn_valid(cur_pfn)) {
        switch_to_mixedmap(vma);
        rc = vm_insert_page(vma, vaddr, page);
        if (rc >= 0)
            return 0;
    }

    /* Invalid PFN - use PFNMAP */
    switch_to_pfnmap(vma);
    rcf = vmf_insert_pfn(vma, vaddr, cur_pfn);
    switch_to_mixedmap(vma);

    if (rcf != VM_FAULT_NOPAGE)
        return -ENOMEM;

    return 0;
}

static int map_single_regular_page(struct vm_area_struct *vma,
                             unsigned long *vaddr,
                             unsigned long *cur_pfn,
                             unsigned long *remaining) {
    int rc = insert_page_with_fallback(vma, *vaddr, *cur_pfn);
    if (rc < 0)
        return rc;

    *vaddr += PAGE_SIZE;
    *cur_pfn += 1;
    *remaining -= PAGE_SIZE;

    return 0;
}

static int modkmap_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long size = (vma->vm_end - vma->vm_start);
    unsigned long cur_pfn = vma->vm_pgoff;
    unsigned long vaddr = vma->vm_start;
    unsigned long remaining = size;
    int rc;

    /* Head: advance until both vaddr and PFN are 2MB-aligned */
    while (remaining >= PAGE_SIZE && ((vaddr | (cur_pfn << PAGE_SHIFT)) & (PMD_SIZE - 1))) {
        rc = map_single_regular_page(vma, &vaddr, &cur_pfn, &remaining);
        if (rc)
            return rc;
    }

    /* Middle: map as many chunks as possible */
    while (remaining >= PMD_SIZE) {
        unsigned long unit_size = min(remaining & ~((unsigned long) PMD_SIZE - 1), MAX_ALLOCATION_UNIT);
        rc = remap_pfn_range(vma, vaddr, cur_pfn, unit_size, vma->vm_page_prot);

        if (!rc) {
            vaddr += unit_size;
            cur_pfn += (unit_size >> PAGE_SHIFT);
            remaining -= unit_size;
            continue;
        }

        // Fallback - insert pages individually
        do {
            rc = map_single_regular_page(vma, &vaddr, &cur_pfn, &remaining);
            if (rc < 0)
                goto exit;
        } while (remaining & (PMD_SIZE - 1));
    }

    /* Tail: map any remaining pages one-by-one */
    while (remaining >= PAGE_SIZE) {
        rc = map_single_regular_page(vma, &vaddr, &cur_pfn, &remaining);
        if (rc < 0)
            goto exit;
    }

    set_vm_flags(vma, VM_SHARED | VM_MAYWRITE);
    rc = 0;

    dprintk(KERN_INFO "mmap 0x%lx (offset 0x%lx -> 0x%lx) - rc %d\n",
            size, vma->vm_pgoff, cur_pfn, rc);
exit:
    return rc;
}

static long read_control_regs(void * __user out) {
    modkmap_control_regs regs;
    unsigned long a, b, c, d;

    asm volatile (
        "mov %%cr0, %0\n"
        "mov %%cr2, %1\n"
        "mov %%cr3, %2\n"
        "mov %%cr4, %3\n"
        "mov %%cr8, %4\n"
        :
        "=r" (regs.cr0),
        "=r" (regs.cr2),
        "=r" (regs.cr3),
        "=r" (regs.cr4),
        "=r" (regs.cr8)
    );

    asm volatile ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));

    if ((d >> 2) & 1) {
        asm volatile (
            "mov %%dr0, %0\n"
            "mov %%dr1, %1\n"
            "mov %%dr2, %2\n"
            "mov %%dr3, %3\n"
            "mov %%dr6, %4\n"
            "mov %%dr7, %5\n"
            :
            "=r" (regs.dr0),
            "=r" (regs.dr1),
            "=r" (regs.dr2),
            "=r" (regs.dr3),
            "=r" (regs.dr6),
            "=r" (regs.dr7)
        );
    }

    if (copy_to_user(out, &regs, sizeof(regs)) != 0)
        return -EFAULT;

    return 0;
}

static unsigned long find_max_physical_address_recursive(const struct resource *res, unsigned long max_addr) {
    const struct resource *child;

    if (strcmp(res->name, "System RAM") == 0)
        max_addr = res->end;

    for (child = res->child; child; child = child->sibling)
        max_addr = find_max_physical_address_recursive(child, max_addr);

    return max_addr;
}

static unsigned long find_max_physical_address(void) {
    return find_max_physical_address_recursive(&iomem_resource, 0);
}

static long get_vma_list(void __user*arg) {
    struct vma_list header = {0,};
    struct vma_list *vmas;
    struct vma_list_entry *entries;
    struct vm_area_struct *vma;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    VMA_ITERATOR(vmi, current->mm, 0);
#endif
    unsigned long status;
    unsigned int i = 0;

    if (copy_from_user(&header, arg, offsetof(struct vma_list, entries)) != 0)
        return -EFAULT;

    if (header.max_entries > MAX_VMA_LIST_ENTRIES || header.max_entries == 0)
        return -EINVAL;

    vmas = kmalloc(offsetof(struct vma_list, entries) + header.max_entries * sizeof(header.entries[0]), GFP_KERNEL);
    if (!vmas)
        return -ENOMEM;

    *vmas = header;
    entries = vmas->entries;

    mmap_read_lock(current->mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    for_each_vma(vmi, vma) {
#else
        for (vma = current->mm->mmap; vma != NULL; vma = vma->vm_next) {
#endif
        entries[i].start = vma->vm_start;
        entries[i].end = vma->vm_end;
        entries[i].prot = vma->vm_page_prot.pgprot;
        i++;

        if (i >= header.max_entries)
            break;
    }
    mmap_read_unlock(current->mm);
    vmas->num_entries = i;

    status = copy_to_user(
        arg, vmas, offsetof(struct vma_list, entries) + vmas->num_entries * sizeof(header.entries[0]));
    kfree(vmas);

    if (status != 0)
        return -EFAULT;

    return 0;
}

static void kmaccess_safe(unsigned long addr) {
    page_walk_t vm = {0,};
    vm.vaddr = addr;

    if (do_page_walk(&vm) < 0)
        return;

    if (vm.page_type == PAGE_NOT_PRESENT)
        return;
    if ((vm.p4d & PTE_US) && (vm.pud & PTE_US) && (vm.pmd & PTE_US) && (
            vm.page_type == PAGE_4KB ? (vm.pte & PTE_US) : 1))
        return;

    asm volatile("mov (%0), %0\nmfence" :: "r"(addr));
}

static void set_pat_on_cpu(void* _val)
{
    unsigned long pat_lo = (unsigned long)_val;
    unsigned long pat_hi = pat_lo >> 32;
    pat_lo &= (1ul << 32) - 1;
    wrmsr_safe(MSR_IA32_CR_PAT, pat_lo, pat_hi);
}

static long set_pat(void* __user arg)
{
    unsigned long pat = 0;
    if (copy_from_user(&pat, arg, sizeof(pat)) != 0)
        return -EFAULT;

    on_each_cpu(set_pat_on_cpu, (void*)pat, 1);

    return 0;
}

static long get_pat(void* __user arg)
{
    unsigned long pat_hi = 0, pat_lo = 0;
    rdmsr_safe(MSR_IA32_CR_PAT, &pat_lo, &pat_hi);

    pat_lo |= pat_hi << 32;

    if (copy_to_user(arg, &pat_lo, sizeof(pat_lo)) != 0)
        return -EFAULT;

    return 0;
}

static long rd_io(void* __user arg) {
    struct io_request io = {0, };

    if (copy_from_user(&io, arg, sizeof(io)) != 0)
        return -EFAULT;

    io.value = 0;

    switch (io.size) {
        case 1:
            asm volatile ("in %%dx, %%al\n" : "=a"(io.value) : "d"(io.address) : "memory");
            break;
        case 2:
            asm volatile ("in %%dx, %%ax\n" : "=a"(io.value) : "d"(io.address) : "memory");
            break;
        case 4:
            asm volatile ("in %%dx, %%eax\n" : "=a"(io.value) : "d"(io.address) : "memory");
            break;
        default:
            return -EINVAL;
    }

    if (copy_to_user(arg, &io, sizeof(io)) != 0)
        return -EFAULT;

    return 0;
}

static long wr_io(void* __user arg) {
    struct io_request io = {0, };

    if (copy_from_user(&io, arg, sizeof(io)) != 0)
        return -EFAULT;

    switch (io.size) {
        case 1:
            asm volatile ("out %%al, %%dx\n" :: "a"(io.value), "d"(io.address) : "memory");
            break;
        case 2:
            asm volatile ("out %%ax, %%dx\n" :: "a"(io.value), "d"(io.address) : "memory");
            break;
        case 4:
            asm volatile ("out %%eax, %%dx\n" :: "a"(io.value), "d"(io.address) : "memory");
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static long modkmap_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    long rc = -ENOTTY;
    void *ret_addr;

    mutex_lock(&instance_lock);

    switch (cmd) {
        case IOCTL_RD_DIRECT_MAP:
            ret_addr = phys_to_virt(0);
            rc = copy_to_user((void * __user) arg, &ret_addr, sizeof(ret_addr)) == 0 ? 0 : -EFAULT;
            break;
        case IOCTL_RD_TEST_PAGE_ADDR:
            ret_addr = (void *) dummy_page;
            rc = copy_to_user((void * __user) arg, &ret_addr, sizeof(ret_addr)) == 0 ? 0 : -EFAULT;
            break;
        case IOCTL_RD_CONTROL_REGS:
            rc = read_control_regs((void * __user) arg);
            break;
        case IOCTL_RD_MAX_PADDR:
            ret_addr = (void *) find_max_physical_address();
            rc = copy_to_user((void * __user) arg, &ret_addr, sizeof(ret_addr)) == 0 ? 0 : -EFAULT;
            break;
        case IOCTL_RD_PAGE_TABLES:
            rc = pt_walk((void * __user) arg);
            break;
        case IOCTL_PADDR_PROBE_ACCESS_TIME:
            if (copy_from_user(&ret_addr, (void * __user) arg, sizeof(ret_addr)) != 0) {
                rc = -EFAULT;
                break;
            }
            ret_addr = (void *) paddr_get_access_time((unsigned long) ret_addr);
            rc = copy_to_user((void * __user) arg, &ret_addr, sizeof(ret_addr)) == 0 ? 0 : -EFAULT;
            break;
        case IOCTL_KMACCESS:
            kmaccess_safe(arg);
            rc = 0;
            break;
        case IOCTL_GET_VMA_LIST:
            rc = get_vma_list((void __user*) arg);
            break;
        case IOCTL_WR_PAGE_TABLES:
            rc = write_page_tables((void __user*) arg);
            break;
        case IOCTL_RD_PAT:
            rc = get_pat((void __user*) arg);
            break;
        case IOCTL_WR_PAT:
            rc = set_pat((void __user*) arg);
            break;
        case IOCTL_WBINVD:
            asm volatile("wbinvd");
            rc = 0;
            break;
        case IOCTL_RD_IO:
            rc = rd_io((void __user*) arg);
            break;
        case IOCTL_WR_IO:
            rc = wr_io((void __user*) arg);
            break;
        default:
            printk(KERN_INFO "modkmap: Undefined IOCTL\n");
            break;
    }

    mutex_unlock(&instance_lock);

    return rc;
}

static loff_t modkmap_llseek(struct file *file, loff_t offset, int whence) {
    struct inode *inode = file_inode(file);

    if (whence != SEEK_SET)
        return -EINVAL;

    inode_lock(inode);

    if (offset != file->f_pos)
        file->f_pos = offset;

    inode_unlock(inode);
    return offset;
}

const struct file_operations fops = {
    .open = modkmap_open,
    .release = modkmap_release,
    .read = modkmap_read,
    .write = modkmap_write,
    .mmap = modkmap_mmap,
    .unlocked_ioctl = modkmap_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    .compat_ioctl = compat_ptr_ioctl,
#endif
    .llseek = modkmap_llseek,
};

static int __init modkmap_init(void) {
    int rc = -EFAULT;

    mutex_init(&instance_lock);
    mutex_lock(&instance_lock);

    init_page_table_utils();

    if (create_chardev(&devinfo, &fops, DEVICE_NAME, 0666) < 0)
        goto out;

    dummy_page = (void *) __get_free_pages(GFP_KERNEL, 1);
    memset((void *) dummy_page, 0xba, PAGE_SIZE);

    rc = 0;
out:
    mutex_unlock(&instance_lock);
    return rc;
}

static void __exit modkmap_exit(void) {
    remove_chardev(&devinfo);
    mutex_destroy(&instance_lock);
    free_pages((unsigned long) dummy_page, 1);
}

module_init(modkmap_init);
module_exit(modkmap_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Kernel memory mapping module");
