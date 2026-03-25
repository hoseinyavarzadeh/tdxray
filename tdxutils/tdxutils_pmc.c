#define TDXUTILS_KERNEL 1
#include <asm/msr.h>
#include "tdxutils.h"

#define IA32_PERF_GLOBAL_CTRL 0x38f
#define IA32_PMC0 0xc1
#define IA32_PERFEVTSEL0 0x186

#ifndef MSR_OFFCORE_RSP_0
#define MSR_OFFCORE_RSP_0 0x1a6
#endif

#define TEST_PMC_ID 0
#define IA32_PMC_TEST (IA32_PMC0 + TEST_PMC_ID)
#define IA32_PERFEVTSEL_TEST (IA32_PERFEVTSEL0 + TEST_PMC_ID)

static unsigned char is_counter_active(unsigned char id) {
    unsigned long ctrl = 0;

    rdmsrl(IA32_PERF_GLOBAL_CTRL, ctrl);

    return (ctrl >> id) & 1;
}

static void set_counter_active(unsigned char id, unsigned char enabled) {
    unsigned long ctrl = 0;

    rdmsrl(IA32_PERF_GLOBAL_CTRL, ctrl);
    ctrl = (ctrl & ~(1ul << id)) | ((enabled & 1) << id);
    asm volatile ("mfence");
    wrmsrl(IA32_PERF_GLOBAL_CTRL, ctrl);
}

int tdxutils_start_counter(struct pmc_instance* instance) {
    // Disable and create backup of counter
    instance->backup_enabled = is_counter_active(TEST_PMC_ID);
    rdmsrl(IA32_PERFEVTSEL_TEST, instance->backup_cfg.raw);
    set_counter_active(TEST_PMC_ID, 0);
    rdmsrl(IA32_PMC_TEST, instance->backup_val);
    rdmsrl(MSR_OFFCORE_RSP_0, instance->backup_offcore_rsp);

    // Enable configured counter
    wrmsrl(IA32_PMC_TEST, 0);
    wrmsrl(IA32_PERFEVTSEL_TEST, instance->cfg.raw);
    wrmsrl(MSR_OFFCORE_RSP_0, instance->offcore_rsp);
    set_counter_active(TEST_PMC_ID, 1);

    return 0;
}

int tdxutils_stop_counter(struct pmc_instance* instance, unsigned long* delta) {
    // Read counter value
    rdmsrl(IA32_PMC_TEST, *delta);
    set_counter_active(TEST_PMC_ID, 0);

    // Restore old counter settings
    wrmsrl(IA32_PMC_TEST, instance->backup_val);
    wrmsrl(IA32_PERFEVTSEL_TEST, instance->backup_cfg.raw);
    wrmsrl(MSR_OFFCORE_RSP_0, instance->backup_offcore_rsp);
    set_counter_active(TEST_PMC_ID, instance->backup_enabled);

    return 0;
}

