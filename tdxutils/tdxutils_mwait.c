#define TDXUTILS_KERNEL 1
#include <linux/module.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <asm/vmx.h>
#include <asm/tdx.h>
#include "device_register.h"
#include "tdxutils.h"

#define MAX_LIST_LEN 10000

#define RESCHED_CYCLES 40000000

struct tdx_mwait_access_entry {
    struct list_head lhead;
    struct tdx_mwait_access access;
};

struct mwait_kthread_arg {
    void* address;
    unsigned int index;
    struct tdx_mwait_target target;
};

static unsigned long __attribute__((aligned(32))) access_counts[64] = {0, };
static unsigned char __attribute__((aligned(32))) redundancy_counters[MAX_MWAIT_TARGETS] = {0, };
static struct task_struct *mwait_task = NULL;
static struct device_info mwait_devinfo = {0, };
static DECLARE_WAIT_QUEUE_HEAD(mwait_waitqueue);
static volatile unsigned char mwait_event = 0;
static struct mutex mwait_interface_lock = {0, };
static struct mutex accessed_pages_lock = {0, };
static const struct tdx_mwait_multi_target* multi_targets = NULL;
static struct task_struct **mwait_multi_tasks = NULL;
static LIST_HEAD(mwait_accessed_addresses);
static long address_list_len = 0;

static volatile unsigned char mwait_running = 0;
static volatile unsigned char monitor_timeout_flag = 0;

static unsigned char is_mwait_supported(void) {
    unsigned long c;

    asm volatile ("cpuid" : "=c"(c) : "a"(1), "c"(0) : "rbx", "rdx");

    return (c >> 3) & 1;
}

static inline __attribute__((always_inline)) void mwait(void* address) {
    asm volatile (
        "clflush (%%rax)\n"
        "mfence\n"
        "monitor\n"

        "mfence\n"
        "mwait\n"
        :
        : "a" (address), "c"(0ul), "d"(0ul)
        : "r8"
    );
}

static inline __attribute__((always_inline)) unsigned long local_zero_xchg(unsigned long* p) {
    unsigned long ret;
    asm volatile ("xor %%rax, %%rax\nxchg %%rax, (%%rdi)\n" : "=a"(ret) : "D"(p));
    return ret;
}

static inline __attribute__((always_inline)) unsigned char local_zero_xchgb(unsigned char* p) {
    unsigned char ret;
    asm volatile ("xor %%rax, %%rax\nxchg %%al, (%%rdi)\n" : "=a"(ret) : "D"(p));
    return ret;
}

static unsigned long get_access_pmc_delta(unsigned char access_type, void* address, struct pmc_instance* pmc, unsigned long* tsc_delta) {
        unsigned long pmc_delta = 0, start;

        tdxutils_start_counter(pmc);
        asm volatile ("mfence");
        start = tdxutils_rdtsc();
        
        do_memory_access(address, access_type);

        *tsc_delta = tdxutils_rdtsc() - start;
        tdxutils_stop_counter(pmc, &pmc_delta);
        asm volatile ("clflush (%0)\nmfence" :: "r"(address));

        return pmc_delta;
}

static int kthread_access_loop(void* arg_ptr) {
    unsigned int i;
    const struct tdx_mwait_target* tarr = multi_targets->targets;

    (void) arg_ptr;

    for (i = 0; !kthread_should_stop(); i = (i + 1) % multi_targets->num_targets) {
        do_memory_access((void*) tarr[i].hpa, TDX_ACCESS_TYPE_LOAD);
        if (!i)
            cond_resched();
    }

    return 0;
}

static int kthread_mwait_single(void* arg_ptr) {
    struct mwait_kthread_arg arg;
    struct pmc_instance pmc;
    struct tdx_mwait_access_entry* entry;
    unsigned long delta = 0, tsc, tsc_delta = 0;

    allow_signal(SIGKILL);

    mwait_running = 1;

    memcpy(&arg, arg_ptr, sizeof(arg));
    kfree(arg_ptr);

    while (!kthread_should_stop()) {
        pmc = (struct pmc_instance) {.cfg = arg.target.pmc.evt, .offcore_rsp = arg.target.pmc.offcore_rsp,};
        monitor_timeout_flag = 0;
        set_current_state(TASK_INTERRUPTIBLE);
        mwait(arg.address);

        // This must happen fast
        tsc = tdxutils_rdtsc();
        delta = get_access_pmc_delta(arg.target.access_type, arg.address, &pmc, &tsc_delta);

        set_current_state(TASK_RUNNING);

        // Notify the user
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            continue;
        entry->access.address = (unsigned long) arg.target.hpa;
        entry->access.tsc = tsc;
        entry->access.pmc_delta = delta;
        entry->access.tsc_delta = tsc_delta;
        entry->access.access_type = arg.target.access_type;

        mutex_lock(&accessed_pages_lock);
        if (address_list_len < MAX_LIST_LEN) {
            list_add_tail(&entry->lhead, &mwait_accessed_addresses);
            address_list_len++;
        }
        mutex_unlock(&accessed_pages_lock);

        // Notify poll interface
        mwait_event = 1;
        wake_up_interruptible(&mwait_waitqueue);
    }

    mwait_running = 0;

    return 0;
}

static int kthread_mwait_count(void* arg_ptr) {
    struct mwait_kthread_arg arg;
    unsigned char cl_index;

    allow_signal(SIGKILL);

    memcpy(&arg, arg_ptr, sizeof(arg));
    kfree(arg_ptr);
    cl_index = (unsigned char) (((unsigned long) arg.address >> 6) & 0x3f);

    set_current_state(TASK_INTERRUPTIBLE);

    while (!kthread_should_stop()) {
        mwait(arg.address);
        atomic64_inc((void*) &access_counts[cl_index]);
    }

    return 0;
}

static int kthread_mwait_count_redundant(void* arg_ptr) {
    struct mwait_kthread_arg arg;
    unsigned char cl_index, redundancy_val;

    allow_signal(SIGKILL);

    memcpy(&arg, arg_ptr, sizeof(arg));
    kfree(arg_ptr);
    cl_index = (unsigned char) (((unsigned long) arg.address >> 6) & 0x3f);

    set_current_state(TASK_INTERRUPTIBLE);

    while (!kthread_should_stop()) {
        mwait(arg.address);
        asm volatile ("lock incb (%0)\nmfence" :: "r"(&redundancy_counters[arg.index]));
        asm volatile (".rept 0x100\nnop\n.endr");
        redundancy_val = local_zero_xchgb(&redundancy_counters[arg.index]);
        if (redundancy_val >= 2)
            atomic64_inc((void*) &access_counts[cl_index]);
    }

    return 0;
}

static long mwait_monitor_single(void* __user arg) {
    struct tdx_mwait_target target = {0, };
    struct mwait_kthread_arg* kthread_arg;
    struct page* page;
    void* target_address;

    if (mwait_task)
        kthread_stop(mwait_task);
    
    mwait_task = NULL;

    if (copy_from_user(&target, arg, sizeof(target)) != 0)
        return -EFAULT;
    
    if (!pfn_valid(target.hpa >> PAGE_SHIFT))
        return -EINVAL;

    page = pfn_to_page(target.hpa >> PAGE_SHIFT);
    if (!page)
        return -EINVAL;
    target_address = (void*) ((unsigned long) page_address(page) | (target.hpa & 0xfff));
    if (!target_address)
        return -EINVAL;

    kthread_arg = kmalloc(sizeof(*kthread_arg), GFP_KERNEL);
    if (!kthread_arg)
        return -ENOMEM;

    kthread_arg->address = target_address;
    kthread_arg->target = target;

    mwait_task = kthread_create(kthread_mwait_single, kthread_arg, "mwait_single");
    kthread_bind(mwait_task, target.core);
    wake_up_process(mwait_task);

    return 0;
}

static unsigned char validate_multi_targets(const struct tdx_mwait_multi_target* targets) {
    const unsigned int nproc = num_present_cpus();
    const struct tdx_mwait_target* tarr = targets->targets;
    unsigned int i;

    for (i = 0; i < targets->num_targets; i++) {
        if (!pfn_valid(tarr[i].hpa >> PAGE_SHIFT))
            return 0;
        if (tarr[i].core >= nproc)
            return 0;
    }

    return 1;
}

static struct mwait_kthread_arg* alloc_arg(void* target_address, unsigned int index, const struct tdx_mwait_target* target) {
    struct mwait_kthread_arg* kthread_arg = kmalloc(sizeof(*kthread_arg), GFP_KERNEL);
    if (!kthread_arg)
        return NULL;

    kthread_arg->address = (void*) ((unsigned long) target_address & ~0x3ful);
    kthread_arg->index = index;
    kthread_arg->target = *target;

    return kthread_arg;
}

static void* get_correct_kthread(void) {
    if (!multi_targets->count_only)
        return kthread_mwait_single;
    if (!multi_targets->use_redundancy_core)
        return kthread_mwait_count;
    return kthread_mwait_count_redundant;
}

static long bring_multi_targets_online(void) {
    struct mwait_kthread_arg* kthread_arg;
    const struct tdx_mwait_target* tarr = multi_targets->targets;
    void* target_address;
    struct page* page;
    unsigned int i;

    mwait_multi_tasks = kmalloc(sizeof(*mwait_multi_tasks) * multi_targets->num_targets * (multi_targets->use_redundancy_core ? 2 : 1), GFP_KERNEL);
    if (!mwait_multi_tasks)
        return -ENOMEM;

    memset(access_counts, 0, sizeof(access_counts));

    for (i = 0; i < multi_targets->num_targets; i++) {
        page = pfn_to_page(tarr[i].hpa >> PAGE_SHIFT);
        target_address = page_address(page) + (tarr[i].hpa & 0xffful);

        kthread_arg = alloc_arg(target_address, i, &tarr[i]);
        if (!kthread_arg)
            return -ENOMEM;

        mwait_multi_tasks[i] = kthread_create(get_correct_kthread(), kthread_arg, "mwait_multi");
        kthread_bind(mwait_multi_tasks[i], tarr[i].core);

        if (multi_targets->use_redundancy_core) {
            kthread_arg = alloc_arg(target_address, i, &tarr[i]);
            if (!kthread_arg)
                return -ENOMEM;
            mwait_multi_tasks[i + multi_targets->num_targets] = kthread_create(get_correct_kthread(), kthread_arg, "mwait_multi_redundant");
            kthread_bind(mwait_multi_tasks[i + multi_targets->num_targets], tarr[i].redundancy_core);
            wake_up_process(mwait_multi_tasks[i + multi_targets->num_targets]);
        }

        wake_up_process(mwait_multi_tasks[i]);
    }

    return 0;
}

static void take_multi_targets_offline(void) {
    struct task_struct* sweeper;
    unsigned int i;

    if (!mwait_multi_tasks)
        return;

    sweeper = kthread_create(kthread_access_loop, NULL, "access_loop");
    wake_up_process(sweeper);

    for (i = 0; i < multi_targets->num_targets; i++) {
        kthread_stop(mwait_multi_tasks[i]);
        if (multi_targets->use_redundancy_core)
            kthread_stop(mwait_multi_tasks[i + multi_targets->num_targets]);
    }

    kthread_stop(sweeper);

    kfree(mwait_multi_tasks);
    kfree((void*) multi_targets);
    multi_targets = NULL;
    mwait_multi_tasks = NULL;
    memset(access_counts, 0, sizeof(access_counts));
}

static long mwait_monitor_multi(void* __user arg) {
    struct tdx_mwait_multi_target header;
    struct tdx_mwait_multi_target* targets = NULL;
    unsigned long targets_size;
    long rc = -EINVAL;

    if (multi_targets)
        return -EEXIST;

    if (mwait_task)
        kthread_stop(mwait_task);

    mwait_task = NULL;

    if (copy_from_user(&header, arg, offsetof(struct tdx_mwait_multi_target, targets)) != 0)
        return -EFAULT;

    if (header.num_targets > MAX_MWAIT_TARGETS)
        return -EINVAL;

    targets_size = offsetof(struct tdx_mwait_multi_target, targets) + sizeof(targets->targets[0]) * header.num_targets;

    targets = kmalloc(targets_size, GFP_KERNEL);
    if (!targets)
        return -ENOMEM;

    if (copy_from_user(targets, arg, targets_size) != 0)
        return -EFAULT;

    if (!validate_multi_targets(targets))
        goto fail;

    multi_targets = targets;

    rc = bring_multi_targets_online();
    if (rc >= 0)
        return rc;

fail:
    if (targets)
        kfree(targets);
    multi_targets = NULL;
    return rc;
}

static long mwait_read_access_counts(void* __user arg) {
    unsigned int i;
    unsigned long local_access_counts[64] = {0, };

    for (i = 0; i < sizeof(access_counts) / sizeof(*access_counts); i++)
        local_access_counts[i] = local_zero_xchg(&access_counts[i]);

    if (copy_to_user(arg, local_access_counts, sizeof(access_counts)) != 0)
        return -EFAULT;

    return 0;
}

static long stop_monitor(void) {
    if (mwait_task)
        kthread_stop(mwait_task);
    mwait_task = NULL;

    take_multi_targets_offline();

    return 0;
}

static int tdx_mwait_open(struct inode *inode, struct file *file) {
    return 0;
}

static int tdx_mwait_release(struct inode *inode, struct file *file) {
    int rc;
    
    mutex_lock(&mwait_interface_lock);
    rc = (int) stop_monitor();
    mutex_unlock(&mwait_interface_lock);

    return rc;
}

static ssize_t tdx_mwait_read(struct file *file, char __user *data, size_t size, loff_t *off) {
    ssize_t bytes_read = 0;
    struct list_head* cur, *last;
    struct tdx_mwait_access_entry* entry;
    unsigned char* staging_buffer;
    ssize_t rc = -EFAULT;

    if (size == 0)
        return 0;
    if (size % sizeof(entry->access) > 0)
        return -EINVAL;

    mutex_lock(&mwait_interface_lock);

    size = min(size, 0x800);
    staging_buffer = kmalloc(size, GFP_KERNEL);
    if (!staging_buffer) {
        rc = -ENOMEM;
        goto exit;
    }
    
    mutex_lock(&accessed_pages_lock);
    cur = mwait_accessed_addresses.next;
    while (cur != &mwait_accessed_addresses) {
        if (bytes_read + sizeof(entry->access) > size)
            break;

        entry = (struct tdx_mwait_access_entry*) cur;
        memcpy(staging_buffer + bytes_read, &entry->access, sizeof(entry->access));
        bytes_read += sizeof(entry->access);

        last = cur;
        cur = cur->next;
        list_del(last);
        address_list_len--;
    }
    mutex_unlock(&accessed_pages_lock);

    if (copy_to_user(data, staging_buffer, bytes_read) != 0) {
        rc = -EFAULT;
        goto exit;
    }

    rc = bytes_read;
exit:
    mutex_unlock(&mwait_interface_lock);
    if (staging_buffer)
        kfree(staging_buffer);
    return rc;
}

static ssize_t tdx_mwait_write(struct file *f, const char __user *data, size_t size, loff_t *off) {
    return -EBADF;
}

static long tdx_mwait_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    long rc = -ENOTTY;

    mutex_lock(&mwait_interface_lock);

    switch(cmd) {
        case IOCTL_MWAIT_MONITOR_SINGLE:
            rc = mwait_monitor_single((void* __user) arg);
            break;
        case IOCTL_MWAIT_STOP_MONITOR:
            rc = stop_monitor();
            break;
        case IOCTL_MWAIT_MONITOR_MULTI:
            rc = mwait_monitor_multi((void* __user) arg);
            break;
        case IOCTL_MWAIT_GET_ACCESS_COUNTS:
            rc = mwait_read_access_counts((void* __user) arg);
            break;
        default:;
    }

    mutex_unlock(&mwait_interface_lock);

    return rc;
}

static unsigned int tdx_mwait_poll(struct file *file, poll_table *wait) {
    poll_wait(file, &mwait_waitqueue, wait);

    if (mwait_event) {
        mwait_event = 0;
        return POLLIN | POLLRDNORM;
    }

    return 0;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,

    .open = tdx_mwait_open,
    .release = tdx_mwait_release,
    .read = tdx_mwait_read,
    .write = tdx_mwait_write,
    .poll = tdx_mwait_poll,
    .unlocked_ioctl = tdx_mwait_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    .compat_ioctl = compat_ptr_ioctl,
#endif
    // .llseek = tdx_mwait_llseek,
};

void tdxutils_mwait_cleanup(void) {
    struct list_head *cur, *last;

    if (!is_mwait_supported())
        return;

    remove_chardev(&mwait_devinfo);

    if (mwait_task)
        kthread_stop(mwait_task);
    mwait_task = NULL;

    // Free list of accessed addresses
    mutex_lock(&accessed_pages_lock);
    cur = mwait_accessed_addresses.next;
    while (cur != &mwait_accessed_addresses) {
        last = cur;
        cur = cur->next;
        kfree(last);
    }
    address_list_len = 0;
    mutex_unlock(&accessed_pages_lock);

    mutex_destroy(&accessed_pages_lock);
    mutex_destroy(&mwait_interface_lock);
}

int tdxutils_mwait_init(void) {
    if (!is_mwait_supported()) {
        printk(KERN_WARNING "tdxutils: MWAIT is not supported on this processor.\n");
        return 0;
    }

    mutex_init(&mwait_interface_lock);
    mutex_init(&accessed_pages_lock);

    if (create_chardev(&mwait_devinfo, &fops, TDX_MWAIT_DEVICE_NAME, 0666) < 0) {
        return -EFAULT;
    }

    return 0;
}
