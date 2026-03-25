#define TDXUTILS_KERNEL 1
#include <linux/module.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/version.h>
#include <linux/kvm_host.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <asm/vmx.h>
#include <asm/tdx.h>
#include "tdxutils.h"
#include "device_register.h"
#include "address_tree.h"

#ifndef EXIT_REASON_TDCALL
#define EXIT_REASON_TDCALL 77
#endif

union vmx_exit_reason {
	struct {
		u32	basic			: 16;
		u32	reserved16		: 1;
		u32	reserved17		: 1;
		u32	reserved18		: 1;
		u32	reserved19		: 1;
		u32	reserved20		: 1;
		u32	reserved21		: 1;
		u32	reserved22		: 1;
		u32	reserved23		: 1;
		u32	reserved24		: 1;
		u32	reserved25		: 1;
		u32	bus_lock_detected	: 1;
		u32	enclave_mode		: 1;
		u32	smi_pending_mtf		: 1;
		u32	smi_from_vmx_root	: 1;
		u32	reserved30		: 1;
		u32	failed_vmentry		: 1;
	};
	u32 full;
};

struct tdr_pa_entry {
    struct list_head lhead;
    unsigned long tdr_pa;
    struct kvm* vm;
};

struct address_list {
    struct list_head lhead;
    unsigned long addr;
    unsigned long tdr_pa;
    unsigned char level;
};

struct seamcall_ret_args {
    unsigned long opcode;
    struct tdx_module_args args_in;
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
void (*tdx_track_)(struct kvm *kvm) = NULL;
u64 (*seamcall_saved_ret)(u64 fn, struct tdx_module_args *args) = NULL;
static struct kprobe tdx_exit_kprobe = {0, };
static struct kprobe tdx_gmem_max_level_kprobe = {0, };
static struct kretprobe seamcall_ret_kprobe = {0, };
static kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;
static struct device_info devinfo = {0, };
static void (*tdx_get_exit_info_)(struct kvm_vcpu *vcpu, u32 *reason, u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code);
static unsigned long lookup_hack_ip_dest = 0;
static LIST_HEAD(tdr_pas);
static LIST_HEAD(accessed_addresses);
static LIST_HEAD(monitor_trail);
static unsigned int monitor_trail_length = 0;
static struct tdx_monitor_range monitor_range = {0, };
static volatile unsigned char* comm_page = NULL;
static DECLARE_WAIT_QUEUE_HEAD(poll_waitqueue);
static int event_flag = 0;
static int reduce_page_size = 0;
static struct rb_root blocked_pages = RB_ROOT;
static spinlock_t interface_lock = __SPIN_LOCK_UNLOCKED(interface_lock);
static spinlock_t seamcall_lock = __SPIN_LOCK_UNLOCKED(seamcall_lock);
static volatile struct seamcall_ret_args seamcall_arg_backup =  {0, };

static void (*kvm_tdp_mmu_try_split_huge_pages_)(struct kvm *kvm,
                                                const struct kvm_memory_slot *slot,
                                                gfn_t start, gfn_t end,
                                                int target_level, bool shared);

static struct kprobe kvm_tdp_mmu_try_split_huge_pages_kprobe = {0, };

static struct tdx_interchanging_block inchg_block = {0, };
static struct tdx_gpa_range_list* tdcall_trap = NULL;

static int return_trampoline(void) {
    return 1;
}

struct kvm* get_kvm_from_tdr(unsigned long tdr_pa) {
    struct tdr_pa_entry* cur = (struct tdr_pa_entry*) tdr_pas.next;

    while (&cur->lhead != &tdr_pas) {
        if (tdr_pa == cur->tdr_pa)
            return cur->vm;
        cur = (struct tdr_pa_entry*) cur->lhead.next;
    }

    return NULL;
}

static unsigned long unblock_gpa(unsigned long level, unsigned long gpa, unsigned long tdr_pa) {
    struct kvm* vm = NULL;
    struct tdx_module_args tdx_args = {0, };
    unsigned long ret;

    tdx_args.rcx = level | level_align(gpa, level);
    tdx_args.rdx = tdr_pa;
    // printk(KERN_INFO "TDH_MEM_RANGE_UNBLOCK(rcx 0x%llx, rdx 0x%llx)\n", tdx_args.rcx, tdx_args.rdx);
    ret = seamcall_saved_ret(TDH_MEM_RANGE_UNBLOCK, &tdx_args);

    if ((ret & TDX_ERROR_CODE_MASK) == TDX_EPT_ENTRY_STATE_INCORRECT) {
        vm = get_kvm_from_tdr(tdr_pa);
        if (vm) {
            memset(&tdx_args, 0, sizeof(tdx_args));
            tdx_args.rcx = level | level_align(gpa, level);
            tdx_args.rdx = tdr_pa;
            seamcall_saved_ret(TDH_MEM_RANGE_BLOCK, &tdx_args);
            tdx_track_(vm);
            memset(&tdx_args, 0, sizeof(tdx_args));
            tdx_args.rcx = level | level_align(gpa, level);
            tdx_args.rdx = tdr_pa;
            ret = seamcall_saved_ret(TDH_MEM_RANGE_UNBLOCK, &tdx_args);
        }
    }

    else if ((ret & TDX_ERROR_CODE_MASK) == TDX_TLB_TRACKING_NOT_DONE) {
        vm = get_kvm_from_tdr(tdr_pa);
        if (vm) {
            tdx_track_(vm);
            memset(&tdx_args, 0, sizeof(tdx_args));
            tdx_args.rcx = level | level_align(gpa, level);
            tdx_args.rdx = tdr_pa;
            ret = seamcall_saved_ret(TDH_MEM_RANGE_UNBLOCK, &tdx_args);
        }
    }

    if (ret != TDX_SUCCESS)
        printk(KERN_WARNING "TDH_MEM_RANGE_UNBLOCK(rcx 0x%lx, rdx 0x%lx) -> rax 0x%lx, rcx 0x%llx, rdx 0x%llx\n", level | level_align(gpa, level), tdr_pa, ret, tdx_args.rcx, tdx_args.rdx);

    if (vm)
        tdx_track_(vm);

    return ret;
}

static unsigned long block_gpa(unsigned long level, unsigned long gpa, unsigned long tdr_pa) {
    struct kvm* vm = NULL;
    struct tdx_module_args tdx_args = {0, };
    unsigned long ret;

    tdx_args.rcx = level | level_align(gpa, level);
    tdx_args.rdx = tdr_pa;

    ret = seamcall_saved_ret(TDH_MEM_RANGE_BLOCK, &tdx_args);

    // Page is probably already blocked - unblock, then re-block
    if ((ret & TDX_ERROR_CODE_MASK) == TDX_EPT_ENTRY_STATE_INCORRECT) {
        memset(&tdx_args, 0, sizeof(tdx_args));
        tdx_args.rcx = level | level_align(gpa, level);
        tdx_args.rdx = tdr_pa;
        seamcall_saved_ret(TDH_MEM_RANGE_UNBLOCK, &tdx_args);
        memset(&tdx_args, 0, sizeof(tdx_args));
        tdx_args.rcx = level | level_align(gpa, level);
        tdx_args.rdx = tdr_pa;
        ret = seamcall_saved_ret(TDH_MEM_RANGE_BLOCK, &tdx_args);
    }

    else if ((ret & TDX_ERROR_CODE_MASK) == TDX_TLB_TRACKING_NOT_DONE) {
        vm = get_kvm_from_tdr(tdr_pa);
        if (vm) {
            tdx_track_(vm);
            memset(&tdx_args, 0, sizeof(tdx_args));
            tdx_args.rcx = level | level_align(gpa, level);
            tdx_args.rdx = tdr_pa;
            ret = seamcall_saved_ret(TDH_MEM_RANGE_BLOCK, &tdx_args);
        }
    }

    else if ((ret & TDX_ERROR_CODE_MASK) == TDX_GPA_RANGE_ALREADY_BLOCKED)
        ret = TDX_SUCCESS;

    if (ret != TDX_SUCCESS)
        printk(KERN_INFO "TDH_MEM_RANGE_BLOCK(rcx 0x%lx, rdx 0x%lx) -> rax 0x%lx, rcx 0x%llx, rdx 0x%llx\n", level | level_align(gpa, level), tdr_pa, ret, tdx_args.rcx, tdx_args.rdx);

    if (vm)
        tdx_track_(vm);

    return ret;
}

long block_range(struct tdx_gpa_range* range, void (*unblock_callback)(unsigned long addr, unsigned long tdr_pa, unsigned char level)) {
    unsigned long pos, status = 0;

    if (range->start >= range->end || range->level > TDX_LEVEL_2M)
        return -EINVAL;
    if ((range->start | range->end) & (level_pg_size(range->level) - 1))
        return -EINVAL;

    for (pos = range->start; pos < range->end; pos += level_pg_size(range->level)) {
        // Skip address if it is already blocked
        if (search_addr(&blocked_pages, pos))
            continue;

        // Block page
        status = block_gpa(range->level, pos, range->tdr_pa);
        if (status != TDX_SUCCESS)
            break;

        // Mark page blocked
        insert_addr(&blocked_pages, pos, range->tdr_pa, range->level, unblock_callback);
    }

    range->start = pos;

    return status;
}

long unblock_range(struct tdx_gpa_range* range, void (*_)(unsigned long, unsigned long, unsigned char)) {
    struct address_tree_node* node = NULL;
    unsigned long pos, status = 0;

    if (range->start >= range->end || range->level > TDX_LEVEL_2M)
        return -EINVAL;
    if ((range->start | range->end) & (level_pg_size(range->level) - 1))
        return -EINVAL;

    for (pos = range->start; pos < range->end; pos += level_pg_size(range->level)) {
        // Skip address if it is not blocked
        node = search_addr(&blocked_pages, pos);
        if (!node)
            continue;

        if (node->unblock_callback)
            node->unblock_callback(node->level, node->tdr_pa, node->level);

        status = unblock_gpa(node->level, node->addr, node->tdr_pa);
        if (status != TDX_SUCCESS)
            break;

        rb_erase(&node->node, &blocked_pages);
        kfree(node);
    }

    range->start = pos;

    return status;
}

static int __kprobes __get_kallsyms_lookup_name_pre(struct kprobe *p, struct pt_regs *regs) {
    lookup_hack_ip_dest = --(regs->ip);
    return 0;
}

static int __kprobes __dummy_pre(struct kprobe *p, struct pt_regs *regs) {
    return 0;
}

static struct address_tree_node* get_blocked_gpa_node(unsigned long fault_gpa, unsigned long tdr_pa, unsigned char level) {
    if (inchg_block.tdr_pa == tdr_pa) {
        if (level_align(fault_gpa, inchg_block.level_a) == level_align(inchg_block.gpa_a, inchg_block.level_a))
            return (void*) ~0ul;
    }

    return search_addr(&blocked_pages, level_align(fault_gpa, level));
}

static int unblock_node(unsigned long fault_gpa, unsigned long tdr_pa, struct address_tree_node* node) {
    if (!node)
        return -EINVAL;

    if (node->tdr_pa != tdr_pa)
        return -EINVAL;

    if (node->unblock_callback)
        node->unblock_callback(node->addr, node->tdr_pa, node->level);

    // Unblock page
    if (unblock_gpa(node->level, fault_gpa, tdr_pa) != TDX_SUCCESS)
        return -EFAULT;

    // Mark page unblocked
    rb_erase(&node->node, &blocked_pages);
    kfree(node);

    return 0;
}

static void exchange_blocked_pages (void) {
    unsigned long t_pa;
    struct kvm* vm = get_kvm_from_tdr(inchg_block.tdr_pa);
    ktime_t start;
    s64 elapsed_ns = 0;

    *(volatile unsigned long*)comm_page = inchg_block.gpa_a;
    start = ktime_get();

    // We wait for the user to acknowledge that the page was accessed - 100 usecs timeout
    while (*(volatile unsigned long*)comm_page && elapsed_ns < 100000) {
        cond_resched();
        elapsed_ns = ktime_to_ns(ktime_sub(ktime_get(), start));
    }

    // printk(KERN_INFO "Hit block @ %lx\n", inchg_block.gpa_a);

    unblock_gpa(inchg_block.level_a, inchg_block.gpa_a, inchg_block.tdr_pa);
    block_gpa(inchg_block.level_b, inchg_block.gpa_b, inchg_block.tdr_pa);

    if (vm)
        tdx_track_(vm);

    t_pa = inchg_block.gpa_a;
    inchg_block.gpa_a = inchg_block.gpa_b;
    inchg_block.gpa_b = t_pa;

    t_pa = inchg_block.level_a;
    inchg_block.level_a = inchg_block.level_b;
    inchg_block.level_b = (unsigned char) t_pa;
}

static int update_monitor_trail(unsigned long gpa, unsigned char level, struct address_tree_node* node) {
    struct kvm* vm;
    struct address_list* entry;

    unblock_node(gpa, monitor_range.tdr_pa, node);

    if (monitor_trail_length < monitor_range.trail_length) {
        monitor_trail_length++;
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            return -ENOMEM;
    } else {
        vm = get_kvm_from_tdr(monitor_range.tdr_pa);

        // Pop last trail entry and block it again
        entry = (void*) monitor_trail.prev;
        list_del(&entry->lhead);
        block_gpa(entry->level, entry->addr, entry->tdr_pa);
        if (vm)
            tdx_track_(vm);
    }

    // Push currently accessed page to beginning of trail
    entry->addr = gpa;
    entry->tdr_pa = monitor_range.tdr_pa;
    entry->level = level;

    list_add(&entry->lhead, &monitor_trail);
    return 0;
}

static unsigned long resolve_gpa(unsigned long gpa, unsigned long tdr_pa, unsigned long* level) {
    struct tdx_module_args tdx_args = {
        .rcx = 1 | (gpa & ~0xffful),
        .rdx = tdr_pa,
    };
    union tdx_sept_entry entry;
    unsigned long ret;

    ret = seamcall_saved_ret(TDH_MEM_SEPT_RD, &tdx_args);
    if (ret != TDX_SUCCESS) {
        printk(KERN_WARNING "TDH_MEM_SEPT_RD(rcx 0x%lx, rdx 0x%lx) -> rax 0x%lx, rcx 0x%llx, rdx 0x%llx\n", 1 | (gpa & ~0xffful), tdr_pa, ret, tdx_args.rcx, tdx_args.rdx);
        return ~0ul;
    }
    entry.raw = tdx_args.rcx;

    if (entry.leaf) {
        *level = tdx_args.rdx;
        return entry.raw;
    }

    memset(&tdx_args, 0, sizeof(tdx_args));
    tdx_args = (struct tdx_module_args ) {
        .rcx = (gpa & ~0xffful),
        .rdx = tdr_pa,
    };
    ret = seamcall_saved_ret(TDH_MEM_SEPT_RD, &tdx_args);
    if (ret != TDX_SUCCESS) {
        printk(KERN_WARNING "TDH_MEM_SEPT_RD(rcx 0x%lx, rdx 0x%lx) -> rax 0x%lx, rcx 0x%llx, rdx 0x%llx\n", (gpa & ~0xffful), tdr_pa, ret, tdx_args.rcx, tdx_args.rdx);
        return ~0ul;
    }
    *level = tdx_args.rdx;
    return tdx_args.rcx;
}


// Sometimes, unblocking a page can apparently fail silently, causing some pages to remain blocked even though we unblocked them
// A VM trying to access such a page will get stuck, as it repeatedly causes a page fault
// This function is a failsafe mechanism for this scenario - we fix it by simply unblocking the page again
static void problem_page_correction(unsigned long fault_gpa, unsigned long tdr_pa, struct kvm* kvm) {
    unsigned long sept_entry;
    unsigned long sept_level = 0xff;

    sept_entry = resolve_gpa(fault_gpa, tdr_pa, &sept_level);
    // printk(KERN_INFO "Correcting SEPT Entry 0x%lx @ Level 0x%lx (-> mapping type = %lx)\n", sept_entry, sept_level, sept_level >> 8 & 0xf);

    if (!~sept_entry) {
        // Resolving the address and mapping state failed - we are completely lost
        // Try to unblock on both possible mapping levels as a last effort, one of them may work
        unblock_gpa(TDX_LEVEL_4K, level_align(fault_gpa, TDX_LEVEL_4K), tdr_pa);
        unblock_gpa(TDX_LEVEL_2M, level_align(fault_gpa, TDX_LEVEL_2M), tdr_pa);
        tdx_track_(kvm);
        return;
    }

    if (sept_level >> 8 != 1)
        return;

    unblock_gpa(sept_level & 0xf, level_align(fault_gpa, sept_level & 0xf), tdr_pa);
    tdx_track_(kvm);
}

static unsigned long tdh_mem_sept_rd(unsigned long tdr_pa, unsigned long gpa, unsigned char level, unsigned long* entry) {
    struct tdx_module_args tdx_args = {0, };
    unsigned long ret;

    tdx_args.rcx = (unsigned long) level | level_align(gpa, level);
    tdx_args.rdx = tdr_pa;

    ret = seamcall_saved_ret(TDH_MEM_SEPT_RD, &tdx_args);
    *entry = tdx_args.rcx;
    return ret;
}

// If the TDX VM triggers a page fault doe to a blocked page, unblock it, and notify the user
// This function is invoked with every EPT violation
static int hook_tdx_handle_ept_violation(struct kvm_vcpu *vcpu) {
    struct address_list* address_entry = NULL;
    struct address_tree_node* node;
    static unsigned long last_fault_gpa = 0, fault_gpa_ctr = 0;
    unsigned long fault_gpa = vcpu->arch.regs[VCPU_REGS_R8];
    unsigned long tdr_pa = *(unsigned long*) ((unsigned char*)vcpu->kvm + sizeof(*(vcpu->kvm)));
    unsigned long status;
    union tdx_sept_entry sept_entry = {.raw = 0};
    unsigned char level = ~0;

    if ((~(tdr_pa >> 32) & ((1ul << 32) - 1)) == 0)
        tdr_pa = *(unsigned long*)((unsigned char*) vcpu->kvm + sizeof(*(vcpu->kvm)) + sizeof(void*));

    status = tdh_mem_sept_rd(tdr_pa, fault_gpa, TDX_LEVEL_2M, &sept_entry.raw);
    if ((status & TDX_ERROR_CODE_MASK) != TDX_SUCCESS) {
        // printk(KERN_INFO "EPT Violation! GPA 0x%lx, TDR_PA 0x%lx, failed to resolve level\n", fault_gpa, tdr_pa);
        return 0;
    }

    level = sept_entry.leaf ? TDX_LEVEL_2M : TDX_LEVEL_4K;

    // printk(KERN_INFO "EPT Violation! GPA 0x%lx, level %u, TDR_PA 0x%lx\n", fault_gpa, level, tdr_pa);

    // Only handle GPAs that we blocked ourselves
    node = get_blocked_gpa_node(fault_gpa, tdr_pa, level);
    if (!node) {
        // printk(KERN_INFO "EPT Violation on foreign page 0x%lx\n", fault_gpa);
        if (last_fault_gpa != fault_gpa) {
            last_fault_gpa = fault_gpa;
            fault_gpa_ctr = 0;
        }
        if (fault_gpa_ctr++ >= 10) {
            fault_gpa_ctr = 0;
            problem_page_correction(fault_gpa, tdr_pa, vcpu->kvm);
        }

        return 0;
    }

    if (inchg_block.tdr_pa == tdr_pa && level_align(fault_gpa, inchg_block.level_a) == level_align(inchg_block.gpa_a, inchg_block.level_a)) {
        // This is the interchange block address
        // Unblock A, block B, and exchange A <-> B
        exchange_blocked_pages();
    } else if (monitor_range.tdr_pa == tdr_pa && fault_gpa >= monitor_range.start && fault_gpa < monitor_range.end) {
        // This GPA is part of the monitor range - update trail
        update_monitor_trail(fault_gpa, level, node);
    } else {
        // Unblock other pages
        unblock_node(fault_gpa, tdr_pa, node);
    }

    // Notify poll interface
    address_entry = kmalloc(sizeof(*address_entry), GFP_KERNEL);
    if (address_entry) {
        address_entry->addr = fault_gpa;
        list_add_tail(&address_entry->lhead, &accessed_addresses);
    }

    event_flag = 1;
    wake_up_interruptible(&poll_waitqueue);

    return 1;
}

static void handle_tdcall (struct kvm* vm) {
    unsigned long i;
    struct tdx_gpa_range* entry;

    if (!tdcall_trap)
        return;

    entry = &tdcall_trap->entries[0];

    for (i = 0; i < tdcall_trap->num_entries; i++) {
        block_range(entry, NULL);
        entry++;
    }
    tdx_track_(vm);

    kfree(tdcall_trap);
    tdcall_trap = NULL;
}

static void record_tdr_pa(struct kvm* vm, unsigned long tdr_pa) {
    struct tdr_pa_entry* cur = (struct tdr_pa_entry*) &tdr_pas, *new;

    // Abort if we already know this VM
    while (cur->lhead.next != &tdr_pas) {
        cur = (struct tdr_pa_entry*) cur->lhead.next;
        if (cur->tdr_pa == tdr_pa)
            return;
    }

    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new)
        return;
    new->tdr_pa = tdr_pa;
    new->vm = vm;

    list_add_tail(&new->lhead, &tdr_pas);
}

static int __kprobes hook_tdx_seamcall_ret_pre(struct kretprobe_instance *ri, struct pt_regs *regs) {
    unsigned long opcode = (unsigned long) regs->di;
    struct tdx_module_args* args = (void*) regs->si;

    spin_lock(&seamcall_lock);

    seamcall_arg_backup.opcode = opcode;

    if (!args)
        return 0;
    memcpy((void*)&seamcall_arg_backup.args_in, args, sizeof(seamcall_arg_backup.args_in));

    return 0;
}

static int __kprobes hook_tdx_seamcall_ret_post(struct kretprobe_instance *ri, struct pt_regs *regs) {
    const unsigned char TDX_STATE_BLOCKED = 0x1;
    const unsigned char TDX_STATE_MAPPED = 0x4;
    unsigned long opcode = seamcall_arg_backup.opcode, ret = regs->ax;
    struct tdx_module_args args_pre, *args_post = (void*) regs->si;

    memcpy(&args_pre, (void*)&seamcall_arg_backup.args_in, sizeof(args_pre));
    memset((void*)&seamcall_arg_backup, 0, sizeof(seamcall_arg_backup));

    spin_unlock(&seamcall_lock);

    if (opcode != TDH_MEM_PAGE_AUG)
        return 0;

    if ((ret & TDX_ERROR_CODE_MASK) != TDX_EPT_ENTRY_STATE_INCORRECT)
        return 0;

    if (((args_post->rdx >> 8) & 0xf) != TDX_STATE_MAPPED && ((args_post->rdx >> 8) & 0xf) != TDX_STATE_BLOCKED)
        return 0;

    if (((args_post->rdx >> 8) & 0xf) == TDX_STATE_MAPPED && (args_post->rcx & 0x7) != 0x7)
        return 0;

    if (((args_post->rdx >> 8) & 0xf) == TDX_STATE_BLOCKED && (args_post->rcx & 0x7) != 0x0)
        return 0;

    printk(KERN_WARNING "Masking TDX Error on TDH_MEM_PAGE_AUG(rcx: 0x%lx, rdx: 0x%lx) -> rax: 0x%lx, rcx 0x%lx, rdx: 0x%lx, r8: 0x%lx\n",
        (unsigned long) args_pre.rcx,
        (unsigned long) args_pre.rdx,
        ret,
        (unsigned long) args_post->rcx,
        (unsigned long) args_post->rdx,
        (unsigned long) args_post->r8);

    regs->ax = 0;
    args_post->rcx = 0;
    args_post->rdx = 0;

    return 0;
}

// Records a list of TDX VMs that are currently running, identified by their TDR.
// Also, if the TDX exit was caused by an EPT violation on a blocked page, we may have to unblock the page again
// This function is invoked with every VM exit
static int __kprobes hook_tdx_handle_exit_pre(struct kprobe* p, struct pt_regs* regs) {
    struct kvm_vcpu * vcpu = (struct kvm_vcpu *) regs->di;
    struct kvm* vm = vcpu->kvm;
    unsigned long tdr_pa = *(unsigned long*)((unsigned char*) vm + sizeof(*vm));
    u64 info1 = 0, info2 = 0;
    u32 intr_info = 0, error_code = 0;
    union vmx_exit_reason exit_reason = {.full = 0};
    fastpath_t fastpath = (fastpath_t) regs->si;
    int rc = 0;

    // Prevent race conditions on our internal data structures
    spin_lock(&interface_lock);

    // TDR_PA offset in struct kvm_tdx changes in 1028-intel. This is a crappy hotfix to get the TDR_PA anyway
    if ((~(tdr_pa >> 32) & ((1ul << 32) - 1)) == 0)
        tdr_pa = *(unsigned long*)((unsigned char*) vm + sizeof(*vm) + sizeof(void*));

    record_tdr_pa(vm, tdr_pa);

    if (fastpath != EXIT_FASTPATH_NONE)
        goto exit;

    tdx_get_exit_info_(vcpu, &exit_reason.full, &info1, &info2, &intr_info, &error_code);

    if (exit_reason.failed_vmentry)
        goto exit;

    if (exit_reason.basic == EXIT_REASON_TDCALL) {
        handle_tdcall(vm);
        goto exit;
    }

    if (exit_reason.basic != EXIT_REASON_EPT_VIOLATION)
        goto exit;

    if (hook_tdx_handle_ept_violation(vcpu)) {
        // Short-circuit the function - Instead of executing it, we return immediately
        regs->ip = (unsigned long long) return_trampoline;
        regs->sp += sizeof(void *);
        rc = 1;
    }

exit:
    spin_unlock(&interface_lock);
    return rc;
}

static int get_kallsyms_lookup_name(kallsyms_lookup_name_t* out) {
    static struct kprobe kp1, kp2;

    lookup_hack_ip_dest = 0;

    kp1.symbol_name = "kallsyms_lookup_name";
    kp1.pre_handler = __get_kallsyms_lookup_name_pre;

    kp2.symbol_name = "kallsyms_lookup_name";
    kp2.pre_handler = __dummy_pre;

    register_kprobe(&kp1);
    register_kprobe(&kp2);

    unregister_kprobe(&kp1);
    unregister_kprobe(&kp2);

    *out = (kallsyms_lookup_name_t) lookup_hack_ip_dest;

    return lookup_hack_ip_dest == 0 ? -1 : 0;
}

static unsigned char get_gpa_level(unsigned long tdr_pa, unsigned long gpa) {
    union tdx_sept_entry entry;
    unsigned long status;

    status = tdh_mem_sept_rd(tdr_pa, gpa, TDX_LEVEL_2M, &entry.raw);
    if ((status & 0xffff) != 0)
        return 0xff;

    if (entry.leaf)
        return TDX_LEVEL_2M;

    return TDX_LEVEL_4K;

}

static ssize_t tdxutils_read(struct file *file, char __user *data, size_t size, loff_t *off) {
    ssize_t bytes_read = 0;
    struct list_head* cur, *last;
    struct address_list* entry;
    unsigned char* staging_buffer;
    ssize_t rc = -EFAULT;

    if (size == 0)
        return 0;
    if (size % sizeof(entry->addr) > 0)
        return -EINVAL;

    spin_lock(&interface_lock);
    cur = accessed_addresses.next;

    size = min(size, 0x800);
    staging_buffer = kmalloc(size, GFP_KERNEL);
    if (!staging_buffer) {
        rc = -ENOMEM;
        goto exit;
    }
    
    while (cur != &accessed_addresses) {
        if (bytes_read + sizeof(entry->addr) > size)
            break;

        entry = (struct address_list*) cur;
        memcpy(staging_buffer + bytes_read, &entry->addr, sizeof(entry->addr));
        bytes_read += sizeof(entry->addr);

        last = cur;
        cur = cur->next;
        list_del(last);
    }

    //if (list_empty(&accessed_addresses))
    //    event_flag = 0;

    if (copy_to_user(data, staging_buffer, bytes_read) != 0) {
        rc = -EFAULT;
        goto exit;
    }

    rc = bytes_read;

exit:
    spin_unlock(&interface_lock);
    if (staging_buffer)
        kfree(staging_buffer);
    return rc;
}

static ssize_t tdxutils_write(struct file *f, const char __user *data, size_t size, loff_t *off) {
    return -EBADF;
}

static long tdxutils_seamcall(void* __user arg) {
    struct tdx_tdh_regs arg_regs = {0, };
    struct tdx_module_args tdx_args = {0, };

    if (copy_from_user(&arg_regs, arg, sizeof(arg_regs)) != 0)
        return -EFAULT;
    
    tdx_args = (struct tdx_module_args) {
        .rcx = arg_regs.rcx,
        .rdx = arg_regs.rdx,
        .r8 = arg_regs.r8,
        .r9 = arg_regs.r9,
        .r10 = arg_regs.r10,
        .r11 = arg_regs.r11,
        .r12 = arg_regs.r12,
        .r13 = arg_regs.r13,
        .r14 = arg_regs.r14,
    };

    arg_regs.rax = seamcall_saved_ret(arg_regs.rax, &tdx_args);

    arg_regs.rcx = tdx_args.rcx;
    arg_regs.rdx = tdx_args.rdx;
    arg_regs.r8 = tdx_args.r8;
    arg_regs.r9 = tdx_args.r9;
    arg_regs.r10 = tdx_args.r10;
    arg_regs.r11 = tdx_args.r11;
    arg_regs.r12 = tdx_args.r12;
    arg_regs.r13 = tdx_args.r13;
    arg_regs.r14 = tdx_args.r14;

    if (copy_to_user(arg, &arg_regs, sizeof(arg_regs)) != 0)
        return -EFAULT;

    return 0;
}

static long tdxutils_get_tdr_pa(void* __user arg) {
    unsigned long index;
    struct tdr_pa_entry* cur = (struct tdr_pa_entry*) tdr_pas.next;

    if (copy_from_user(&index, arg, sizeof(index)) != 0)
        return -EFAULT;

    while (&cur->lhead != &tdr_pas) {
        if (index--) {
            cur = (struct tdr_pa_entry*) cur->lhead.next;
            continue;
        }
        
        if (copy_to_user(arg, &cur->tdr_pa, sizeof(cur->tdr_pa)) != 0)
            return -EFAULT;
        return 0;
    }

    return -ENOENT;
}

static long tdxutils_block_gpa_range(void* __user arg) {
    struct tdx_gpa_range range = {0 ,};
    struct kvm* vm;
    long status;

    // Check input
    if (copy_from_user(&range, arg, sizeof(range)) != 0)
        return -EFAULT;

    vm = get_kvm_from_tdr(range.tdr_pa);
    if (!vm)
        return -EINVAL;

    status = block_range(&range, NULL);
    tdx_track_(vm);

    if (copy_to_user(arg, &range, sizeof(range)) != 0)
        return -EFAULT;

    return status;
}

static long tdxutils_unblock_gpa_range(void* __user arg) {
    struct tdx_gpa_range range = {0 ,};
    long status;

    // Check input
    if (copy_from_user(&range, arg, sizeof(range)) != 0)
        return -EFAULT;

    // Unblock the GPA range
    status = unblock_range(&range, NULL);

    if (copy_to_user(arg, &range, sizeof(range)) != 0)
        return -EFAULT;

    return status;
}

static long tdxutils_clear_interchanging_block(void) {
    if (inchg_block.tdr_pa)
        unblock_gpa(inchg_block.level_a, inchg_block.gpa_a, inchg_block.tdr_pa);

    memset(&inchg_block, 0, sizeof(inchg_block));
    return 0;
}

static long tdxutils_setup_interchanging_block(void* __user arg) {
    unsigned long ret;
    struct kvm* vm;

    tdxutils_clear_interchanging_block();

    if (copy_from_user(&inchg_block, arg, sizeof(inchg_block)) != 0)
        return -EFAULT;

    vm = get_kvm_from_tdr(inchg_block.tdr_pa);
    if (!vm)
        return -EINVAL;

    // printk(KERN_INFO "Blocking initial GPA_A @ %lx with level %x\n", inchg_block.gpa_a, inchg_block.level_a);
    ret = block_gpa(inchg_block.level_a, inchg_block.gpa_a, inchg_block.tdr_pa);
    if (ret != TDX_SUCCESS)
        printk(KERN_ERR "Failed to block initial GPA_A @ %lx with level %x\n", inchg_block.gpa_a, inchg_block.level_a);

    tdx_track_(vm);

    return 0;
}

static long tdxutils_clear_monitor_range(void) {
    struct rb_node *node;
    struct list_head* entry = monitor_trail.next, *last;
    struct address_tree_node *data;

    if (!monitor_range.tdr_pa)
        return 0;

    // Unblock all blocked pages that belong to the monitor range
    for (node = rb_first(&blocked_pages); node; ) {
        data = container_of(node, struct address_tree_node, node);
        node = rb_next(node);
        if (data->tdr_pa != monitor_range.tdr_pa || data->addr < monitor_range.start || data->addr >= monitor_range.end)
            continue;
        unblock_gpa(data->level, data->addr, data->tdr_pa);
        rb_erase(&data->node, &blocked_pages);
        kfree(data);
    }

    while (entry != &monitor_trail) {
        last = entry;
        entry = entry->next;
        list_del(last);
        kfree(last);
    }

    memset(&monitor_range, 0, sizeof(monitor_range));
    monitor_trail_length = 0;

    return 0;
}

static long tdxutils_setup_monitor_range(void* __user arg) {
    struct kvm* vm;
    unsigned long pos, status;
    unsigned char level;

    tdxutils_clear_monitor_range();

    if (copy_from_user(&monitor_range, arg, sizeof(monitor_range)) != 0)
        return -EFAULT;
    if (monitor_range.start >= monitor_range.end || monitor_range.trail_length == 0 || !monitor_range.tdr_pa)
        goto fail;
    vm = get_kvm_from_tdr(monitor_range.tdr_pa);
    if (!vm)
        goto fail;

    pos = monitor_range.start;

    while (pos < monitor_range.end) {
        // Skip address if it is already blocked
        if (search_addr(&blocked_pages, pos))
            continue;
        // Skip range in blacklist if given
        if (pos >= monitor_range.blacklist_start && pos < monitor_range.blacklist_end)
            continue;

        level = get_gpa_level(monitor_range.tdr_pa, pos);

        if (level > TDX_LEVEL_2M) {
            pos += level_pg_size(TDX_LEVEL_4K);
            continue;
        }

        // Block page
        status = block_gpa(level, pos, monitor_range.tdr_pa);
        if (status != TDX_SUCCESS)
            goto fail;

        // Mark page blocked
        insert_addr(&blocked_pages, pos, monitor_range.tdr_pa, level, NULL);

        pos += level_pg_size(level);
    }
    tdx_track_(vm);

    return 0;
fail:
    tdxutils_clear_monitor_range();
    return -EFAULT;
}

static long op_range_list(void* __user arg, long (*op)(struct tdx_gpa_range*, void (*)(unsigned long, unsigned long, unsigned char))) {
    const unsigned long entry_offset = offsetof(struct tdx_gpa_range_list, entries);
    struct tdx_gpa_range_list range_list = {0, };
    struct kvm* vm;
    long status = 0;
    unsigned int i;

    if (copy_from_user(&range_list.num_entries, arg, sizeof(range_list.num_entries)) != 0)
        return -EFAULT;
    if (!range_list.num_entries || range_list.num_entries > GPA_RANGE_LIST_MAX)
        return -EINVAL;

    for (i = 0; i < range_list.num_entries; i++) {
        if (copy_from_user(range_list.entries, arg + entry_offset + i*sizeof(range_list.entries[0]), sizeof(range_list.entries[0])) != 0)
            return -EFAULT;

        status = op(&range_list.entries[0], NULL);

        if (copy_to_user(arg + entry_offset + i*sizeof(range_list.entries[0]), range_list.entries, sizeof(range_list.entries[0])) != 0)
            return -EFAULT;

        if (status != TDX_SUCCESS)
            break;
    }

    if (op == block_range) {
        vm = get_kvm_from_tdr(range_list.entries[0].tdr_pa);
        if (vm)
            tdx_track_(vm);
    }

    return status == TDX_SUCCESS ? 0 : status;
}

static long tdxutils_block_gpa_range_list(void* __user arg) {
    return op_range_list(arg, block_range);
}

static long tdxutils_unblock_gpa_range_list(void* __user arg) {
    return op_range_list(arg, unblock_range);
}

static long tdxutils_install_tdcall_block_trap(void* __user arg) {
    unsigned long trap_size;
    struct tdx_gpa_range_list range_list = {0, };

    if (copy_from_user(&range_list.num_entries, arg, sizeof(range_list.num_entries)) != 0)
        return -EFAULT;
    if (!range_list.num_entries || range_list.num_entries > GPA_RANGE_LIST_MAX)
        return -EINVAL;

    if (tdcall_trap)
        kfree(tdcall_trap);

    trap_size = sizeof(range_list.num_entries) + range_list.num_entries * sizeof(range_list.entries[0]);
    tdcall_trap = kmalloc(trap_size, GFP_KERNEL);
    if (!tdcall_trap)
        return -ENOMEM;

    if (copy_from_user(tdcall_trap, arg, trap_size) == 0)
        return 0; // <- This is the expected return point

    // Clean up in case we failed to copy the range list
    if (tdcall_trap)
        kfree(tdcall_trap);
    tdcall_trap = NULL;

    return -EFAULT;
}

// Function to split huge pages in a given range
static long tdxutils_split_huge_pages_range(struct kvm *kvm, gfn_t start_gfn,
                                           gfn_t end_gfn, int target_level) {
    struct kvm_memory_slot *slot;
    bool shared = false;  // Use write lock for safety

    if (!kvm || !kvm_tdp_mmu_try_split_huge_pages_) {
        printk(KERN_ERR "Invalid parameters for split_huge_pages\n");
        return -EINVAL;
    }

    // Get the memory slot containing the GFN range
    slot = gfn_to_memslot(kvm, start_gfn);
    if (!slot) {
        printk(KERN_ERR "No memory slot found for GFN 0x%lx\n", (unsigned long) start_gfn);
        return -EINVAL;
    }

    // Ensure we don't go beyond the slot boundaries
    if (end_gfn > slot->base_gfn + slot->npages) {
        end_gfn = slot->base_gfn + slot->npages;
        printk(KERN_INFO "Adjusted end_gfn to slot boundary: 0x%lx\n", (unsigned long) end_gfn);
    }

    // printk(KERN_INFO "Splitting huge pages: GFN range [0x%lx, 0x%lx) to level %d\n",
    //       (unsigned long) start_gfn, (unsigned long) end_gfn, target_level);

    // Acquire write lock for safety
    write_lock(&kvm->mmu_lock);

    // Call the function via function pointer
    kvm_tdp_mmu_try_split_huge_pages_(kvm, slot, start_gfn, end_gfn,
                                      target_level, shared);

    write_unlock(&kvm->mmu_lock);

    // printk(KERN_INFO "Successfully split huge pages in range [0x%lx, 0x%lx)\n",
    //       (unsigned long) start_gfn, (unsigned long) end_gfn);

    return 0;
}

// Function to handle the IOCTL for splitting huge pages
static long tdxutils_split_huge_pages_ioctl(void* __user arg) {
    struct tdx_split_huge_pages_req req;
    struct kvm* vm;
    gfn_t start_gfn, end_gfn;

    if (copy_from_user(&req, arg, sizeof(req)) != 0)
        return -EFAULT;

    // Validate inputs
    if (req.target_level > 2) {
        printk(KERN_ERR "Invalid target level: %d\n", req.target_level);
        return -EINVAL;
    }

    if (req.start_gpa >= req.end_gpa) {
        printk(KERN_ERR "Invalid GPA range: 0x%lx - 0x%lx\n",
               req.start_gpa, req.end_gpa);
        return -EINVAL;
    }

    // Convert GPA to GFN
    start_gfn = req.start_gpa >> PAGE_SHIFT;
    end_gfn = req.end_gpa >> PAGE_SHIFT;

    // Find the VM by TDR PA
    vm = get_kvm_from_tdr(req.tdr_pa);
    if (!vm) {
        printk(KERN_ERR "VM not found for TDR PA: 0x%lx\n", req.tdr_pa);
        return -EINVAL;
    }

    // Call the split function
    return tdxutils_split_huge_pages_range(vm, start_gfn, end_gfn, req.target_level);
}

static long tdxutils_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    long rc = -ENOTTY;
    spin_lock(&interface_lock);

    switch(cmd) {
        case IOCTL_TDX_SEAMCALL:
            rc = tdxutils_seamcall((void* __user) arg);
            break;
        case IOCTL_TDX_GET_TDR_PA:
            rc = tdxutils_get_tdr_pa((void* __user) arg);
            break;
        case IOCTL_TDX_BLOCK_GPA_RANGE:
            rc = tdxutils_block_gpa_range((void* __user) arg);
            break;
        case IOCTL_TDX_UNBLOCK_GPA_RANGE:
            rc = tdxutils_unblock_gpa_range((void* __user) arg);
            break;
        case IOCTL_TDX_SETUP_INTERCHANGING_BLOCK:
            rc = tdxutils_setup_interchanging_block((void* __user) arg);
            break;
        case IOCTL_TDX_CLEAR_INTERCHANGING_BLOCK:
            rc = tdxutils_clear_interchanging_block();
            break;
        case IOCTL_TDX_SETUP_MONITOR_RANGE:
            rc = tdxutils_setup_monitor_range((void* __user) arg);
            break;
        case IOCTL_TDX_CLEAR_MONITOR_RANGE:
            rc = tdxutils_clear_monitor_range();
            break;
        case IOCTL_TDX_BLOCK_GPA_RANGE_LIST:
            rc = tdxutils_block_gpa_range_list((void* __user) arg);
            break;
        case IOCTL_TDX_UNBLOCK_GPA_RANGE_LIST:
            rc = tdxutils_unblock_gpa_range_list((void* __user) arg);
            break;
        case IOCTL_TDX_INSTALL_TDCALL_BLOCK_TRAP:
            rc = tdxutils_install_tdcall_block_trap((void* __user) arg);
            break;
        case IOCTL_TDX_SPLIT_HUGE_PAGES:
            rc = tdxutils_split_huge_pages_ioctl((void* __user) arg);
            break;
        case IOCTL_TDX_ACCESS_MONITOR_START:
            rc = tdx_access_monitor_start((void* __user) arg);
            break;
        case IOCTL_TDX_ACCESS_MONITOR_STOP:
            rc = tdx_access_monitor_stop();
            break;
        case IOCTL_TDX_ACCESS_MONITOR_QUERY:
            rc = tdx_access_monitor_query((void* __user) arg);
        default:;
    }

    spin_unlock(&interface_lock);
    return rc;
}

static int tdxutils_open(struct inode *inode, struct file *file) {
    return 0;
}

static int tdxutils_release(struct inode *inode, struct file *file) {
    struct rb_node *node;
    struct address_tree_node *data;

    spin_lock(&interface_lock);

    tdx_access_monitor_stop();

    // Unblock pages that are still blocked
    for (node = rb_first(&blocked_pages); node; ) {
        data = container_of(node, struct address_tree_node, node);
        node = rb_next(node);
        if (data->pid == current->pid) {
            unblock_gpa(data->level, data->addr, data->tdr_pa);
            if (data->unblock_callback)
                data->unblock_callback(data->addr, data->tdr_pa, data->level);

            rb_erase(&data->node, &blocked_pages);
            kfree(data);
        }
    }

    tdxutils_clear_interchanging_block();

    spin_unlock(&interface_lock);

    return 0;
}

static int tdxutils_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long size = (vma->vm_end - vma->vm_start);
    struct page* page;
    int rc;

    if (size != PAGE_SIZE)
        return -EINVAL;
    
    page = virt_to_page(comm_page);
    if (!pfn_valid(page_to_pfn(page)))
        return -EFAULT;
    
    rc = vm_insert_page(vma, vma->vm_start, page);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_set(vma, VM_SHARED | VM_MAYWRITE);
#else
    vma->vm_flags |= VM_SHARED | VM_MAYWRITE;
#endif

    return rc;
}

static unsigned int tdxutils_poll(struct file *file, poll_table *wait) {
    poll_wait(file, &poll_waitqueue, wait);

    if (event_flag) {
        event_flag = 0;
        return POLLIN | POLLRDNORM;
    }

    return 0;
}

// Hook function for tdx_gmem_max_level - modifies max_level from 2MB to 4KB
static int __kprobes hook_tdx_gmem_max_level_pre(struct kprobe* p, struct pt_regs* regs) {
    // struct kvm *kvm = (struct kvm *) regs->di;
    // kvm_pfn_t pfn = (kvm_pfn_t) regs->si;
    // gfn_t gfn = (gfn_t) regs->dx;
    bool is_private = (bool) regs->cx;
    u8 *max_level = (u8 *) regs->r8;
    
    // Only modify if it's private memory
    if (!is_private)
        return 0;
    
    // Log the original call
    // printk(KERN_INFO "tdx_gmem_max_level: kvm=%p, pfn=0x%lx, gfn=0x%lx, is_private=%d, original_max_level=%u\n",
    //        kvm, pfn, gfn, is_private, *max_level);
    
    // Force max_level to 4KB before function executes (options are 4KB or 2MB)
    *max_level = PG_LEVEL_4K;

    // printk(KERN_INFO "tdx_gmem_max_level: Set input max_level to %u\n", *max_level);
    
    return 0;
}

// Hook for kvm_tdp_mmu_try_split_huge_pages
static int __kprobes hook_kvm_tdp_mmu_try_split_huge_pages_pre(struct kprobe* p, struct pt_regs* regs) {
    struct kvm *kvm = (struct kvm *) regs->di;
    const struct kvm_memory_slot *slot = (const struct kvm_memory_slot *) regs->si;
    gfn_t start = (gfn_t) regs->dx;
    gfn_t end = (gfn_t) regs->cx;
    int target_level = (int) regs->r8;
    bool shared = (bool) regs->r9;

    printk(KERN_INFO "kvm_tdp_mmu_try_split_huge_pages: kvm=%p, slot=%p, start=0x%lx, end=0x%lx, target_level=%d, shared=%d\n",
           kvm, slot, (unsigned long) start, (unsigned long) end, target_level, shared);

    return 0;  // Continue with function execution
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,

    .open = tdxutils_open,
    .release = tdxutils_release,
    .read = tdxutils_read,
    .write = tdxutils_write,
    .mmap = tdxutils_mmap,
    .poll = tdxutils_poll,
    .unlocked_ioctl = tdxutils_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    .compat_ioctl = compat_ptr_ioctl,
#endif
    // .llseek = tdxutils_llseek,
};

static int __init tdxutils_init(void) {
    int status;
    (void) remove_addr;

    comm_page = (void *) __get_free_pages(GFP_KERNEL, 1);
    if (!comm_page)
        return -ENOMEM;

    // Get pointer to '__seamcall_saved_ret'
    if (get_kallsyms_lookup_name(&kallsyms_lookup_name_) < 0) {
        printk(KERN_ERR "Cannot get kallsyms_lookup_name\n");
        goto fail;
    }

    seamcall_saved_ret = (void*) kallsyms_lookup_name_("__seamcall_saved_ret");
    if (!seamcall_saved_ret) {
        printk(KERN_ERR "Cannot get __seamcall_saved_ret\n");
        goto fail;
    }

    tdx_track_ = (void*) kallsyms_lookup_name_("tdx_track");
    if (!tdx_track_) {
        printk(KERN_ERR "Cannot get 'tdx_track'\n");
        goto fail;
    }

    tdx_get_exit_info_ = (void*) kallsyms_lookup_name_("tdx_get_exit_info");
    if (!tdx_get_exit_info_) {
        printk(KERN_ERR "Cannot get 'tdx_get_exit_info'\n");
        goto fail;
    }

    kvm_tdp_mmu_try_split_huge_pages_ = (void*) kallsyms_lookup_name_("kvm_tdp_mmu_try_split_huge_pages");
    if (!kvm_tdp_mmu_try_split_huge_pages_) {
        printk(KERN_ERR "Cannot get 'kvm_tdp_mmu_try_split_huge_pages'\n");
        goto fail;
    }

    kvm_tdp_mmu_try_split_huge_pages_kprobe.symbol_name = "kvm_tdp_mmu_try_split_huge_pages";
    kvm_tdp_mmu_try_split_huge_pages_kprobe.pre_handler = hook_kvm_tdp_mmu_try_split_huge_pages_pre;
    if (register_kprobe(&kvm_tdp_mmu_try_split_huge_pages_kprobe) < 0) {
        pr_err("Failed to register kprobe for 'kvm_tdp_mmu_try_split_huge_pages'\n");
        goto fail;
    }

    // Hook 'tdx_handle_exit'
    tdx_exit_kprobe.symbol_name = "tdx_handle_exit";
    tdx_exit_kprobe.pre_handler = hook_tdx_handle_exit_pre;
    if (register_kprobe(&tdx_exit_kprobe) < 0) {
        pr_err("Failed to register kprobe for 'tdx_handle_exit'\n");
        goto fail;
    }

    // Hook 'seamcall_ret'
    seamcall_ret_kprobe.kp.symbol_name = "__seamcall_ret";
    seamcall_ret_kprobe.entry_handler = hook_tdx_seamcall_ret_pre;
    seamcall_ret_kprobe.handler =  hook_tdx_seamcall_ret_post;
    if (register_kretprobe(&seamcall_ret_kprobe) < 0) {
        pr_err("Failed to register kprobe for 'seamcall_ret'\n");
        goto fail;
    }

    // Hook 'tdx_gmem_max_level' if module is loaded with reduce_page_size=1
    if (reduce_page_size) {
        printk(KERN_INFO "tdxutils: Permanently reducing maximum SEPT level to 4kB. Reboot the machine to go back to 2MB\n");
        tdx_gmem_max_level_kprobe.symbol_name = "tdx_gmem_max_level";
        tdx_gmem_max_level_kprobe.pre_handler = hook_tdx_gmem_max_level_pre;
        if (register_kprobe(&tdx_gmem_max_level_kprobe) < 0) {
            pr_err("Failed to register kprobe for 'tdx_gmem_max_level'\n");
            tdx_gmem_max_level_kprobe.symbol_name = NULL;
        }
    }

    // Initialize device interface
    if (create_chardev(&devinfo, &fops, TDXUTILS_DEVICE_NAME, 0666) < 0)
        goto fail;


    status = tdxutils_mwait_init();
    if (status < 0)
        goto fail;

    status = tdxutils_access_monitor_init();
    if (status < 0) {
        tdxutils_mwait_cleanup();
        goto fail;
    }

    return 0;

fail:
    if (kvm_tdp_mmu_try_split_huge_pages_kprobe.symbol_name)
        unregister_kprobe(&kvm_tdp_mmu_try_split_huge_pages_kprobe);
    if (seamcall_ret_kprobe.kp.symbol_name)
        unregister_kretprobe(&seamcall_ret_kprobe);
    if (reduce_page_size && tdx_gmem_max_level_kprobe.symbol_name)
        unregister_kprobe(&tdx_gmem_max_level_kprobe);
    if (tdx_exit_kprobe.symbol_name)
        unregister_kprobe(&tdx_exit_kprobe);
    if (comm_page)
        free_pages((unsigned long) comm_page, 1);

    return -EFAULT;
}

static void __exit tdxutils_exit(void) {
    struct rb_node *node;
    struct address_tree_node *data;
    struct list_head *cur, *last;

    unregister_kprobe(&tdx_exit_kprobe);

    spin_lock(&interface_lock);
    shutdown_in_progress = 1;

    tdxutils_access_monitor_exit();
    tdxutils_mwait_cleanup();
    remove_chardev(&devinfo);

    spin_lock(&seamcall_lock);
    if (seamcall_ret_kprobe.kp.symbol_name)
        unregister_kretprobe(&seamcall_ret_kprobe);
    spin_unlock(&seamcall_lock);

    if (reduce_page_size && tdx_gmem_max_level_kprobe.symbol_name)
        unregister_kprobe(&tdx_gmem_max_level_kprobe);
    unregister_kprobe(&kvm_tdp_mmu_try_split_huge_pages_kprobe);
    free_pages((unsigned long) comm_page, 1);

    spin_unlock(&interface_lock);

    // Unblock pages that are still blocked
    for (node = rb_first(&blocked_pages); node; ) {
        data = container_of(node, struct address_tree_node, node);
        unblock_gpa(data->level, data->addr, data->tdr_pa);
        if (data->unblock_callback)
            data->unblock_callback(data->addr, data->tdr_pa, data->level);
        node = rb_next(node);
    }
    destroy_address_tree(&blocked_pages);

    // Free tdcall trap if still set up
    if (tdcall_trap) {
        kfree(tdcall_trap);
        tdcall_trap = NULL;
    }

    // Free TDR_PA list
    cur = tdr_pas.next;
    while (cur != &tdr_pas) {
        last = cur;
        cur = cur->next;
        kfree(last);
    }

    // Free list of accessed addresses
    cur = accessed_addresses.next;
    while (cur != &accessed_addresses) {
        last = cur;
        cur = cur->next;
        kfree(last);
    }

    shutdown_in_progress = 0;
}

module_init(tdxutils_init);
module_exit(tdxutils_exit);
module_param(reduce_page_size, int, 0444);
MODULE_PARM_DESC(reduce_page_size, "If set to 1, loading the module with this parameter ensures SEPT mappings are no larger than 4kB");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TDX Utilities");
