#ifndef CONFIG_H
#define CONFIG_H

#ifdef VICTIM

#define NUMBER_OF_ENCRYPTIONS_VISUAL 1000   // How many encryptions to perform

#elifdef ATTACKER

#define NUM_ATTACK_RUNS 10                  // How many times to repeat the attack
#define DO_LOAD_PROBE   0                   // Use Load+Probe
#define DO_TSX_PROBE    1                   // Use TSX-Probe
#define USE_PMC         0                   // If using Load+Probe, use the PMC variant with the PMC defined below

#define LOAD_PROBE_LOWER_THRESHOLD 480
#define LOAD_PROBE_UPPER_THRESHOLD 3000

// Set to L2_LINES_OUT_SILENT, but can be changed to arbitrary PMC events
// See https://perfmon-events.intel.com/ for details on how to choose other counters
const static struct pmc_info test_pmc = {
    {
        .event_sel = 0x26,
        .umask = 0x1,

        .en = 1,
        .os = 1,
        .usr = 1,
    },
    0
};

#if !(DO_LOAD_PROBE ^ DO_TSX_PROBE)
#error "Invalid configuration - please choose either DO_LOAD_PROBE or DO_TSX_PROBE"
#endif
#if DO_LOAD_PROBE
static const unsigned char access_type = TDX_ACCESS_TYPE_LOAD;
#elif DO_TSX_PROBE
static const unsigned char access_type = TDX_ACCESS_TYPE_TSX;
#endif

#endif

#endif