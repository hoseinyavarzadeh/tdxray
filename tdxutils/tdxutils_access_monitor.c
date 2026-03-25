#define TDXUTILS_KERNEL 1
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kvm_host.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <asm/vmx.h>
#include <asm/tdx.h>
#include "tdxutils.h"

#ifndef dprintk
// #define dprintk(...) printk(__VA_ARGS__)
#define dprintk(...)
#endif

// 1 to record tsc deltas with access types other than TSX, 0 to skip and reduce memory accesses
#define RECORD_TSC_DELTAS 1

// Hard limit to prevent the kernel module from exhausting memory
#define MAX_HIT_ENTRIES 0x100000

#define IA32_TSX_CTRL 0x122

struct page_access_entry {
    struct list_head lhead;
    struct tdx_access_monitor_target_page target;
};

struct hit_entry {
    struct list_head lhead;
    struct tdx_access_monitor_hit hit;
};

unsigned char shutdown_in_progress = 0;

static struct tdx_access_monitor_targets* monitor_targets = NULL;
static unsigned char is_sync_page_blocked = 0;
static unsigned char is_termination_page_blocked = 0;

static unsigned long num_target_pages_unblocked = 0;

static unsigned long hit_entry_count = 0;
static LIST_HEAD(hit_entries);
static LIST_HEAD(last_access_targets);
static unsigned char hit_register[level_pg_size(1) / (0x8 * 0x40)] = {0, };
#if RECORD_TSC_DELTAS
static unsigned short tsc_deltas[level_pg_size(1) / 0x40] = {0, };
#endif
static unsigned short pmc_deltas[level_pg_size(1) / 0x40] = {0, };

static void access_monitor_target_unblock_callback(unsigned long addr, unsigned long tdr_pa, unsigned char level);
static long uninstall_monitor_targets(void);

static int cmp_target(const void *a, const void *b) {
    const struct tdx_access_monitor_target_page* aa = (void*) a, *bb = (void*) b;
    return (aa->gpa > bb->gpa) - (aa->gpa < bb->gpa);
}

static void emerald_rapids_enable_tsx(void) {
    asm volatile ("wrmsr" :: "d"(0ul), "a"(0ul), "c"((unsigned long) IA32_TSX_CTRL));
}

static inline unsigned char __attribute__((always_inline)) is_cached_tsx(void* paddr) {
    volatile unsigned char result = 0;

    asm volatile (
        "xor %%rax, %%rax\n"
        "jnz .Labort_dest\n" // This is to stop objtool from complaining
        "mfence\n"

        "xbegin .Labort_dest\n"
        "mov (%%rsi), %%r8\n"
        "xend\n"

        "jmp .Lend\n"
        ".Labort_dest:\n"
        "inc %%rax\n"
        ".Lend:\n"
        "nop\n"

        : "=a"(result)
        : "S" (paddr)
        : "r8"
    );

    return result ? 1 : 0;
}

static int block_single_page(unsigned long gpa, unsigned long tdr_pa, unsigned long level, void(*unblock_callback)(unsigned long, unsigned long, unsigned char)) {
    struct tdx_gpa_range range = {
        .tdr_pa = tdr_pa,
        .start = gpa,
        .end = gpa + level_pg_size(level),
        .level = level,
    };
    long rc = block_range(&range, unblock_callback);

    if (rc != 0)
        printk(KERN_WARNING "tdxutils access monitor: Could not block GPA 0x%lx\n", gpa);

    return rc == 0 ? 0 : -1;
}

static int unblock_single_page(unsigned long gpa, unsigned long tdr_pa, unsigned long level) {
    struct tdx_gpa_range range = {
        .tdr_pa = tdr_pa,
        .start = gpa,
        .end = gpa + level_pg_size(level),
        .level = level,
    };
    long rc = unblock_range(&range, NULL);

    if (rc != 0)
        printk(KERN_WARNING "tdxutils access monitor: Could not unblock GPA 0x%lx\n", gpa);

    return rc == 0 ? 0 : -1;
}

static void add_hit_entry(const struct tdx_access_monitor_target_page* target, unsigned long id, unsigned char access_type, unsigned long page_offset, unsigned long tsc_delta, unsigned long pmc_delta) {
    struct hit_entry* entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    *entry = (struct hit_entry) {
        .lhead = {0},
        .hit = {
            .access_type = access_type,
            .block_id = id,
            .gpa = target->gpa + page_offset,
            .level = target->level,
            .tsc_delta = tsc_delta,
            .pmc_delta = pmc_delta,
            .hpa = target->hpa + page_offset,
        },
    };

    list_add(&entry->lhead, &hit_entries);
    hit_entry_count++;
}

// Inline so that we don't have to set up a new stack frame
static inline void __attribute__((always_inline)) probe_hpa(const unsigned char access_type, const unsigned long upper, const unsigned long lower, const unsigned long hpa, const unsigned long mix_i, const union ia32_perfevtsel pmc) {
    register unsigned long time;
    struct pmc_instance instance;
    union { unsigned long delta; int status;} pmc_aux;

    if (access_type == TDX_ACCESS_TYPE_TSX) {
        asm volatile("mfence");
        hit_register[mix_i / 8] |= is_cached_tsx((unsigned char*) hpa + mix_i*0x40) ? (1 << (mix_i % 8)) : 0;
        return;
    }

    if (pmc.raw) {
        asm volatile("mfence");
        instance = (struct pmc_instance) {
            .cfg = pmc,
            .offcore_rsp = monitor_targets->pmc.offcore_rsp,
            .backup_cfg = {{0,},},
            .backup_enabled = 0,
            .backup_offcore_rsp = 0,
            .backup_val = 0,
        };
        pmc_aux.delta = 0;
        tdxutils_start_counter(&instance);
    }

    time = tdxutils_rdtsc();
    do_memory_access((unsigned char*) hpa + mix_i*0x40, access_type);
    time = tdxutils_rdtsc() - time;

    if (pmc.raw) {
        tdxutils_stop_counter(&instance, &pmc_aux.delta);
        pmc_deltas[mix_i] = (unsigned short) pmc_aux.delta;
    }

    hit_register[mix_i / 8] |= (time >= lower && time < upper) ? (1 << (mix_i % 8)) : 0; // Record hits in bitmask to save memory
#if RECORD_TSC_DELTAS
    tsc_deltas[mix_i] = (unsigned short) time;
#endif
}

static void record_cache_line_accesses(void* const host_phys, const struct tdx_access_monitor_target_page* target) {
    const unsigned long lower = monitor_targets->hit_tsc_threshold_lower, upper = monitor_targets->hit_tsc_threshold_upper, id = tdxutils_rdtsc();
    const unsigned char access_type = (unsigned char) monitor_targets->access_type, level = target->level;
    const union ia32_perfevtsel pmc_cfg = monitor_targets->pmc.evt;
    unsigned int i, mix_i;
    unsigned char check;

    if (access_type == TDX_ACCESS_TYPE_NONE) {
        asm volatile ("mfence"); // Barrier to keep cache state intact in case we mis-speculate into this block
        add_hit_entry(target, tdxutils_rdtsc(), TDX_ACCESS_TYPE_NONE, 0, ~0ul, 0);
        return;
    }

    if (access_type == TDX_ACCESS_TYPE_TSX)
        emerald_rapids_enable_tsx();

    // Do memory accesses as fast as possible using as little memory as possible to keep the cache state intact
    for (i = 0; i < level_pg_size(level) / 0x40; i++) {
        mix_i =  (7717 * i + 7) % (level_pg_size(level) / 0x40);
        probe_hpa(access_type, upper, lower, (unsigned long) host_phys, mix_i, pmc_cfg);
    }

    dprintk(KERN_INFO "Saved timings for 0x%lx\n", target->gpa);

    // After gathering timings, add records in a separate loop
    for (i = 0, check = 0; i < level_pg_size(level) / 0x40; i++) {
        mix_i =  (7717 * i + 7) % (level_pg_size(level) / 0x40);

        if ((hit_register[mix_i / 8] >> (mix_i % 8) & 1) == 0)
            continue;
        if (hit_entry_count >= MAX_HIT_ENTRIES)
            break;

        check = 1;
        add_hit_entry(target, id, access_type, mix_i * 0x40,
#if RECORD_TSC_DELTAS
        tsc_deltas[mix_i],
#else
        ~0ul,
#endif
        pmc_deltas[mix_i]
        );
    }

    if (!check)
        add_hit_entry(target, id, TDX_ACCESS_TYPE_NONE, 1, ~0ul, 0);

    memset(hit_register, 0, sizeof(hit_register));
#if RECORD_TSC_DELTAS
    memset(tsc_deltas, 0, sizeof(tsc_deltas));
#endif
    memset(pmc_deltas, 0, sizeof(pmc_deltas));
}

static void block_unblocked_target_pages(struct kvm* kvm, unsigned long tdr_pa) {
    struct page_access_entry *cur, *last;
    struct tdx_gpa_range range;
    unsigned long i;

    // Block target pages again
    cur = (void*) last_access_targets.next;
    while (&cur->lhead != &last_access_targets) {
        range = (struct tdx_gpa_range) {
            .tdr_pa = tdr_pa,
            .start = cur->target.gpa,
            .end = cur->target.gpa + level_pg_size(cur->target.level),
            .level = cur->target.level,
        };
        block_range(&range, access_monitor_target_unblock_callback);

        if (monitor_targets->access_type != TDX_ACCESS_TYPE_NONE) {
            // Flush victim cache lines for consistency
            for (i = 0; i < level_pg_size(0); i += 0x40)
                asm volatile ("clflush (%0)" :: "r"(phys_to_virt(cur->target.hpa) + i));
            asm volatile ("mfence");
        }

        last = cur;
        cur = (void*) cur->lhead.next;
        list_del(&last->lhead);
        kfree(last);
        if (num_target_pages_unblocked)
            num_target_pages_unblocked--;
    }
    tdx_track_(kvm);
}

static void measure_last_unblocked_page(unsigned long tdr_pa) {
    struct page_access_entry* cur = (void*) last_access_targets.prev;
    struct kvm* kvm;
    unsigned int i;
    struct tdx_gpa_range range;

    if ((void*) cur == &last_access_targets)
        return;

    record_cache_line_accesses(phys_to_virt(cur->target.hpa), &cur->target);

    kvm = get_kvm_from_tdr(tdr_pa);

    range = (struct tdx_gpa_range) {
        .tdr_pa = tdr_pa,
        .start = cur->target.gpa,
        .end = cur->target.gpa + level_pg_size(cur->target.level),
        .level = cur->target.level,
    };
    block_range(&range, access_monitor_target_unblock_callback);

    if (monitor_targets->access_type != TDX_ACCESS_TYPE_NONE) {
        // Flush victim cache lines for consistency
        for (i = 0; i < level_pg_size(0); i += 0x40)
            asm volatile ("clflush (%0)" :: "r"(phys_to_virt(cur->target.hpa) + i));
        asm volatile ("mfence");
    }

    list_del(&cur->lhead);
    kfree(cur);
    if (num_target_pages_unblocked)
        num_target_pages_unblocked--;

    if (kvm)
        tdx_track_(kvm);
}

static void measure_unblocked_pages(unsigned long tdr_pa) {
    struct kvm* kvm;
    struct page_access_entry* cur = (void*) last_access_targets.next;

    dprintk(KERN_INFO "Measure + re-block\n");

    // Record cache activity
    while (&cur->lhead != &last_access_targets) {
        record_cache_line_accesses(phys_to_virt(cur->target.hpa), &cur->target);
        cur = (void*) cur->lhead.next;
    }

    if (shutdown_in_progress)
        return;

    kvm = get_kvm_from_tdr(tdr_pa);
    if (kvm)
        block_unblocked_target_pages(kvm, tdr_pa);
}

static void access_monitor_sync_unblock_callback(unsigned long addr, unsigned long tdr_pa, unsigned char level) {
    struct tdx_access_monitor_target_page sync_dummy_target;
    (void) addr;
    (void) level;

    dprintk(KERN_INFO "Callback Sync %lx\n", addr);

    if (!monitor_targets)
        return;

    is_sync_page_blocked = 0;
    measure_unblocked_pages(tdr_pa);

    if (hit_entry_count >= MAX_HIT_ENTRIES)
        return;

    sync_dummy_target = (struct tdx_access_monitor_target_page) {
        .gpa = monitor_targets->sync_gpa,
        .hpa = monitor_targets->sync_hpa,
        .level = monitor_targets->sync_level,
    };
    add_hit_entry(&sync_dummy_target, tdxutils_rdtsc(), TDX_ACCESS_TYPE_NONE, 0, ~0ul, 0);
}

static void access_monitor_target_unblock_callback(unsigned long addr, unsigned long tdr_pa, unsigned char level) {
    struct tdx_access_monitor_target_page bkey = {.gpa = addr, .hpa = 0, .level = level};
    const struct tdx_access_monitor_target_page *bval;
    struct page_access_entry* entry;
    struct kvm* kvm;
    unsigned char* host_phys;
    unsigned int i = 0;

    if (!monitor_targets)
        return;

    dprintk(KERN_INFO "Callback Target %lx\n", addr);

    // Find the HPA corresponding to this GPA
    bval = bsearch(&bkey, monitor_targets->targets, monitor_targets->num_targets, sizeof(monitor_targets->targets[0]), cmp_target);
    if (!bval) {
        dprintk(KERN_INFO "Could not find GPA 0x%lx among %lu targets (t[0] = 0x%lx)\n", addr, monitor_targets->num_targets, monitor_targets->targets[0].gpa);
        return;
    }

    if (is_sync_page_blocked && num_target_pages_unblocked >= max((unsigned long) monitor_targets->trail_length, 1ul)) {
        if (monitor_targets->trail_length <= 3)
            // For small trail lengths, we simply measure+reblock everything
            measure_unblocked_pages(tdr_pa);
        else
            // For larger trail lengths, we only re-block the last page
            measure_last_unblocked_page(tdr_pa);
    } else if (!shutdown_in_progress) {
        // Block sync page
        kvm = get_kvm_from_tdr(tdr_pa);

        if (kvm) {
            block_single_page(monitor_targets->sync_gpa, monitor_targets->tdr_pa, monitor_targets->sync_level, access_monitor_sync_unblock_callback);
            tdx_track_(kvm);
            is_sync_page_blocked = 1;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (entry) {
        entry->target = *bval;
        list_add(&entry->lhead, &last_access_targets);
        num_target_pages_unblocked++;
    }

    if (monitor_targets->access_type == TDX_ACCESS_TYPE_NONE)
        return;

    host_phys = phys_to_virt(bval->hpa);

    // Flush victim cache lines for consistency
    for (i = 0; i < level_pg_size(level); i += 0x40)
        asm volatile ("clflush (%0)" :: "r"(host_phys + i));
    asm volatile ("mfence");
}

static void access_monitor_termination_unblock_callback(unsigned long addr, unsigned long tdr_pa, unsigned char level) {
    (void) addr;
    (void) tdr_pa;
    (void) level;

    printk(KERN_INFO "Callback Termination %lx\n", addr);

    is_termination_page_blocked = 0;
    uninstall_monitor_targets();
}

static unsigned long block_gpa_raw(unsigned long level, unsigned long gpa, unsigned long tdr_pa) {
    struct tdx_module_args tdx_args = {0, };
    unsigned long ret;

    tdx_args.rcx = level | level_align(gpa, level);
    tdx_args.rdx = tdr_pa;

    ret = seamcall_saved_ret(TDH_MEM_RANGE_BLOCK, &tdx_args);

    if (ret != 0)
        printk(KERN_WARNING "TDH_MEM_RANGE_BLOCK(rcx 0x%lx, rdx 0x%lx) -> rax 0x%lx, rcx 0x%llx, rdx 0x%llx\n", level | level_align(gpa, level), tdr_pa, ret, tdx_args.rcx, tdx_args.rdx);

    return ret;
}

static void unblock_target_pages(struct tdx_access_monitor_targets* targets, struct tdx_access_monitor_target_page* target_pages, struct kvm* kvm) {
    unsigned long outstanding_ctr, i;
    int status;

    outstanding_ctr = targets->num_targets;
    for (i = 0; i < targets->num_targets; i++) {
        if (!~target_pages[i].gpa)
            continue;

        status = unblock_single_page(target_pages[i].gpa, targets->tdr_pa, target_pages[i].level);
        if (status == 0) {
            target_pages[i].gpa = ~0ul;
            outstanding_ctr--;
        }
    }

    for (i = 0; i < targets->num_targets && outstanding_ctr; i++) {
        if (!~target_pages[i].gpa)
            continue;
        block_gpa_raw(target_pages[i].level, target_pages[i].gpa, targets->tdr_pa);
    }
    if (kvm)
        tdx_track_(kvm);
    for (i = 0; i < targets->num_targets && outstanding_ctr; i++) {
        if (!~target_pages[i].gpa)
            continue;
        unblock_single_page(target_pages[i].gpa, targets->tdr_pa, target_pages[i].level);
    }

    num_target_pages_unblocked = 0;
}


static long uninstall_monitor_targets(void) {
    struct kvm* kvm;
    struct tdx_access_monitor_targets* targets;
    struct tdx_access_monitor_target_page* target_pages;
    struct list_head *cur, *last;
    unsigned long arg_size;

    if (!monitor_targets)
        return 0;

    targets = monitor_targets;
    target_pages = targets->targets;

    // Record cache activity
    cur = last_access_targets.next;
    while (cur != &last_access_targets) {
        record_cache_line_accesses(phys_to_virt(((struct page_access_entry*)cur)->target.hpa), &((struct page_access_entry*)cur)->target);
        cur = cur->next;
    }

    monitor_targets = NULL;
    kvm = get_kvm_from_tdr(targets->tdr_pa);

    printk(KERN_INFO "tdxutils: teardown\n");
    if (!shutdown_in_progress)
        unblock_target_pages(targets, target_pages, kvm);

    if (is_sync_page_blocked && !shutdown_in_progress)
        unblock_single_page(targets->sync_gpa, targets->tdr_pa, targets->sync_level);
    is_sync_page_blocked = 0;


    if (is_termination_page_blocked && !shutdown_in_progress)
        unblock_single_page(targets->termination_gpa, targets->tdr_pa, targets->termination_level);
    is_termination_page_blocked = 0;

    arg_size = offsetof(struct tdx_access_monitor_targets, targets) + sizeof(targets->targets[0]) * targets->num_targets;
    free_pages((unsigned long) targets, get_order(arg_size));

    // Free last access targets
    cur = last_access_targets.next;
    while (cur != &last_access_targets) {
        last = cur;
        cur = cur->next;
        list_del(last);
        kfree(last);
    }
    num_target_pages_unblocked = 0;

    return 0;
}

static long install_monitor_targets(struct tdx_access_monitor_targets* targets, struct kvm* kvm) {
    const struct tdx_access_monitor_target_page* target_pages = targets->targets;
    unsigned long i, arg_size;
    long rc;

    monitor_targets = targets;
    num_target_pages_unblocked = 0;

    dprintk(KERN_INFO "Start Monitor: Sync @ 0x%lx, targets[0] @ 0x%lx\n", (unsigned long) monitor_targets->sync_gpa, monitor_targets->targets[0].gpa);

    // Block target pages
    for (i = 0; i < monitor_targets->num_targets; i++)
        block_single_page(target_pages[i].gpa, monitor_targets->tdr_pa, target_pages[i].level, access_monitor_target_unblock_callback);

    // Block sync page
    rc = block_single_page(monitor_targets->sync_gpa, monitor_targets->tdr_pa, monitor_targets->sync_level,
        access_monitor_sync_unblock_callback);
    if (rc != 0)
        goto fail;
    is_sync_page_blocked = 1;

    // Block termination page
    rc = block_single_page(monitor_targets->termination_gpa, monitor_targets->tdr_pa, monitor_targets->termination_level,
        access_monitor_termination_unblock_callback);
    if (rc != 0)
        goto fail;
    is_termination_page_blocked = 1;

    tdx_track_(kvm);

    return 0;
fail:
    while (i--)
        unblock_single_page(target_pages[i].gpa, targets->tdr_pa, target_pages[i].level);
    if (is_sync_page_blocked) {
        unblock_single_page(monitor_targets->sync_gpa, monitor_targets->tdr_pa, monitor_targets->sync_level);
        is_sync_page_blocked = 0;
    }

    arg_size = offsetof(struct tdx_access_monitor_targets, targets) + sizeof(monitor_targets->targets[0]) * monitor_targets->num_targets;
    free_pages((unsigned long) monitor_targets, get_order(arg_size));
    monitor_targets = NULL;
    return rc;
}

long tdx_access_monitor_start(void* __user arg) {
    struct tdx_access_monitor_targets header = {0, }, *target = NULL;
    struct kvm* kvm;
    unsigned long arg_size;

    if (monitor_targets)
        return -EBUSY;

    if (copy_from_user(&header, arg, sizeof(header)) != 0)
        return -EFAULT;

    if (!header.num_targets || header.num_targets > TDX_ACCESS_MONITOR_TARGETS_MAX)
        return -EINVAL;

    kvm = get_kvm_from_tdr(header.tdr_pa);
    if (!kvm)
        return -EINVAL;

    arg_size = offsetof(struct tdx_access_monitor_targets, targets) + sizeof(target->targets[0]) * header.num_targets;
    target = (void*) __get_free_pages(GFP_KERNEL, get_order(arg_size));
    if (!target)
        return -ENOMEM;

    if (copy_from_user(target, arg, arg_size) != 0) {
        free_pages((unsigned long) target, arg_size);
        return -EFAULT;
    }

    sort(target->targets, target->num_targets, sizeof(target->targets[0]), cmp_target, NULL);

    return install_monitor_targets(target, kvm);
}

long tdx_access_monitor_stop(void) {
    uninstall_monitor_targets();
    return 0;
}

long tdx_access_monitor_query(void* __user arg) {
    struct tdx_access_monitor_query query = {0, };
    struct hit_entry *cur, *last;
    unsigned int i;

    if (copy_from_user(&query, arg, sizeof(query)) != 0)
        return -EFAULT;

    if (!query.dest_len || !query.dest)
        return -EINVAL;

    dprintk(KERN_INFO "Querying - %lu available\n", hit_entry_count);

    cur = (void*) hit_entries.next;
    i = 0;
    while (cur != (void*)&hit_entries) {
        if (copy_to_user((unsigned char*) query.dest + i*sizeof(cur->hit), &cur->hit, sizeof(cur->hit)) != 0)
            return -EFAULT;

        last = cur;
        cur = (void*) cur->lhead.next;
        list_del(&last->lhead);
        kfree(last);
        i++;
        hit_entry_count--;

        if (i >= query.dest_len)
            break;
    }

    query.num_items = i;
    if (copy_to_user(arg, &query, sizeof(query)) != 0)
        return -EFAULT;

    return 0;
}

void tdxutils_access_monitor_exit(void) {
    struct list_head *cur, *last;

    tdx_access_monitor_stop();

    cur = hit_entries.next;
    while (cur != &hit_entries) {
        last = cur;
        cur = cur->next;
        list_del(last);
        kfree(last);
    }
    hit_entry_count = 0;
}

int tdxutils_access_monitor_init(void) {
    return 0;
}
