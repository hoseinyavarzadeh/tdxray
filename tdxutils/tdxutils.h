#ifndef TDXUTILS_H__
#define TDXUTILS_H__

#ifndef TDXUTILS_KERNEL
#include <string.h>
#include <sys/ioctl.h>
#endif

#ifdef __cplusplus
#define _static_assert(x, m) static_assert(x, m)
#define tdxutils_cast(t, m) reinterpret_cast<t>(m)
extern "C" {
#else
#define _static_assert(x, m) _Static_assert(x, m)
#define tdxutils_cast(t, m) (t)(m)
#endif

#define PG_LEVEL_4K 1
#define PG_LEVEL_2M 2

#define TDX_LEVEL_4K 0
#define TDX_LEVEL_2M 1
#define TDX_LEVEL_1G 2

#ifdef __cplusplus
static constexpr unsigned long level_pg_size(unsigned char level) {
	return 1ul << (12 + 9 * level);
}
static constexpr unsigned long level_align(unsigned long x, unsigned char level) {
	return x & ~(level_pg_size(level) - 1);
}
#else
#define level_pg_size(x) (1ul << (12 + 9*(x)))
#define level_align(x, level) ((x) & ~(level_pg_size(level) - 1))
#endif

// Intel TDX SEAMCALL Leaf Numbers (TDH interface)
// Specification: Intel TDX Module ABI Spec v1.5 (348551-006, Apr 2025)
#define TDH_VP_ENTER 0 // Enter TDX non-root operation
#define TDH_MNG_ADDCX 1 // Add a control structure page to a TD Interface Function Name Description
#define TDH_MEM_PAGE_ADD 2 // Add a 4KB private page to a TD during TD build time
#define TDH_MEM_SEPT_ADD 3 // Add and map a 4KB Secure EPT page to a TD
#define TDH_VP_ADDCX 4 // Add a control structure page to a TD VCPU
#define TDH_MEM_PAGE_RELOCATE 5 // Relocate a 4KB mapped page from its HPA to another
#define TDH_MEM_PAGE_AUG 6 // Dynamically add a 4KB private page to an initialized TD
#define TDH_MEM_RANGE_BLOCK 7 // Block a TD private GPA range
#define TDH_MNG_KEY_CONFIG 8 // Configure the TD private key on a single package
#define TDH_MNG_CREATE 9 // Create a guest TD and its TDR root page
#define TDH_VP_CREATE 10 // Create a guest TD VCPU and its TDVPR root page
#define TDH_MNG_RD 11 // Read TD metadata
#define TDH_MEM_RD 12 // Read from private memory of a debuggable guest TD
#define TDH_MNG_WR 13 // Write TD metadata
#define TDH_MEM_WR 14 // Write to private memory of a debuggable guest TD
#define TDH_MEM_PAGE_DEMOTE 15 // Split a 2MB or a 1GB private TD page mapping into 512 4KB or 2MB page mappings respectively
#define TDH_MR_EXTEND 16 // Extend the guest TD measurement register during TD build
#define TDH_MR_FINALIZE 17 // Finalize the guest TD measurement register
#define TDH_VP_FLUSH 18 // Flush the address translation caches and cached TD VMCS associated with a TD VCPU
#define TDH_MNG_VPFLUSHDONE 19 // Check all of a guest TD’s VCPUs have been flushed by TDH.VP.FLUSH
#define TDH_MNG_KEY_FREEID 20 // Mark the guest TD’s HKID as free
#define TDH_MNG_INIT 21 // Initialize per-TD control structures
#define TDH_VP_INIT 22 // Initialize the per-VCPU control structures
#define TDH_MEM_PAGE_PROMOTE 23 // Merge 512 consecutive 4KB or 2MB private TD page mappings into one 2MB or 1GB page mapping respectively
#define TDH_PHYMEM_PAGE_RDMD 24 // Read the metadata of a page in a TDMR
#define TDH_MEM_SEPT_RD 25 // Read a Secure EPT entry
#define TDH_VP_RD 26 // Read VCPU metadata
#define TDH_PHYMEM_PAGE_RECLAIM 28 // Reclaim a physical memory page owned by a TD (i.e., TD private page, Secure EPT page or a control structure page)
#define TDH_MEM_PAGE_REMOVE 29 // Remove a private page from a guest TD
#define TDH_MEM_SEPT_REMOVE 30 // Remove a Secure EPT page from a TD
#define TDH_SYS_KEY_CONFIG 31 // Configure the Intel TDX global private key on the current package
#define TDH_SYS_INFO 32 // Get Intel TDX module information
#define TDH_SYS_INIT 33 // Globally initialize the Intel TDX module
#define TDH_SYS_RD 34 // Read a TDX Module global-scope metadata field
#define TDH_SYS_LP_INIT 35 // Initialize the Intel TDX module per logical processor
#define TDH_SYS_TDMR_INIT 36 // Partially initialize a Trust Domain Memory Region (TDMR)
#define TDH_SYS_RDALL 37 // Read all host-readable TDX Module global-scope metadata fields
#define TDH_MEM_TRACK 38 // Increment the TD’s TLB tracking counter
#define TDH_MEM_RANGE_UNBLOCK 39 // Remove the blocking of a TD private GPA range
#define TDH_PHYMEM_CACHE_WB 40 // Write back the contents of the cache on a WBINVD domain
#define TDH_PHYMEM_PAGE_WBINVD 41 // Write back and invalidate all cache lines associated with the specified memory page and HKID
#define TDH_SYS_RDM 42 // Read multiple TDX Module global-scope metadata fields
#define TDH_VP_WR 43 // Write VCPU metadata
#define TDH_SYS_CONFIG 45 // Globally configure the Intel TDX module
#define TDH_MNG_RDM 46 // Read multiple TD-scope metadata fields
#define TDH_MNG_WRM 47 // Write multiple TD-scope metadata fields
#define TDH_SERVTD_BIND 48 // Bind a service TD to a target TD
#define TDH_SERVTD_PREBIND 49 // Pre-bind a service TD to a target TD
#define TDH_VP_RDM 50 // Read multiple VCPU-scope metadata fields
#define TDH_VP_WRM 51 // Write multiple VCPU-scope metadata fields
#define TDH_SYS_SHUTDOWN 52 // Shutdown the Intel TDX module and prepare handoff data
#define TDH_SYS_UPDATE 53 // Populate Intel TDX module state from handoff data
#define TDH_SYS_S4_END 54 // End S4 resume session
#define TDH_PHYMEM_PAMT_ADD 58 // Add a pair of PAMT pages
#define TDH_PHYMEM_PAMT_REMOVE 59 // Remove a pair of PAMT pages
#define TDH_EXT_INIT 60 // Initialize the TDX module extensions
#define TDH_EXT_MEM_ADD 61 // Add up to 512 4KB memory pages to the TDX module’s memory pool
#define TDH_EXPORT_ABORT 64 // Abort an export session
#define TDH_EXPORT_BLOCKW 65 // Block a TD private page for writing
#define TDH_EXPORT_RESTORE 66 // Restore a list of TD private 4KB pages’ Secure EPT entry states after an export abort
#define TDH_EXPORT_MEM 68 // Export a list of TD private pages contents and/or cancellation requests
#define TDH_EXPORT_PAUSE 70 // Pause the exported TD
#define TDH_EXPORT_TRACK 71 // End the current in-order export phase epoch and either start a new epoch or start the out-of-order export phase
#define TDH_EXPORT_STATE_IMMUTABLE 72 // Start an export session and export the TD's immutable state
#define TDH_EXPORT_STATE_TD 73 // Export the TD's mutable state
#define TDH_EXPORT_STATE_VP 74 // Export a VCPU mutable state
#define TDH_EXPORT_UNBLOCKW 75 // Unblock a page that has been blocked for writing
#define TDH_IMPORT_ABORT 80 // Abort an import session
#define TDH_IMPORT_END 81 // End an import session
#define TDH_IMPORT_COMMIT 82 // Commit the import session and allow the imported TD to run
#define TDH_IMPORT_MEM 83 // Import a list of TD private pages contents and/or cancellation requests based on a migration bundle in shared memory
#define TDH_IMPORT_TRACK 84 // End the current in-order import phase epoch and either start a new epoch or start the out-of-order import phase
#define TDH_IMPORT_STATE_IMMUTABLE 85 // Start an import session and import the TD's immutable state
#define TDH_IMPORT_STATE_TD 86 // Import the TD's mutable state
#define TDH_IMPORT_STATE_VP 87 // Import a VCPU mutable state
#define TDH_MIG_STREAM_CREATE 96 // Create a migration stream
#define TDH_MEM_SHARED_SEPT_WR 163 // Map/un-map shared EPT root table entries used to support trusted DMA access to TD shared GPA space.


// Error codes
#ifndef TDX_SUCCESS
#define TDX_SUCCESS                                  0x0000000000000000ULL
#endif
#define TDX_NON_RECOVERABLE_VCPU                     0x4000000100000000ULL
#define TDX_NON_RECOVERABLE_TD                       0x6000000200000000ULL
#define TDX_INTERRUPTED_RESUMABLE                    0x8000000300000000ULL
#define TDX_INTERRUPTED_RESTARTABLE                  0x8000000400000000ULL
#define TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE        0x6000000500000000ULL
#define TDX_INVALID_RESUMPTION                       0xC000000600000000ULL
#define TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE       0xE000000700000000ULL
#define TDX_CROSS_TD_FAULT                           0x8000000800000000ULL
#define TDX_CROSS_TD_TRAP                            0x9000000900000000ULL
#define TDX_NON_RECOVERABLE_TD_CORRUPTED_MD          0x6000000A00000000ULL
#define TDX_OPERAND_INVALID                          0xC000010000000000ULL
#define TDX_OPERAND_ADDR_RANGE_ERROR                 0xC000010100000000ULL
#define TDX_OPERAND_BUSY                             0x8000020000000000ULL
#define TDX_PREVIOUS_TLB_EPOCH_BUSY                  0x8000020100000000ULL
#define TDX_SYS_BUSY                                 0x8000020200000000ULL
#define TDX_RND_NO_ENTROPY                           0x8000020300000000ULL
#define TDX_OPERAND_BUSY_HOST_PRIORITY               0x8000020400000000ULL
#define TDX_HOST_PRIORITY_BUSY_TIMEOUT               0x9000020500000000ULL
#define TDX_PAGE_METADATA_INCORRECT                  0xC000030000000000ULL
#define TDX_PAGE_ALREADY_FREE                        0x0000030100000000ULL
#define TDX_PAGE_NOT_OWNED_BY_TD                     0xC000030200000000ULL
#define TDX_PAGE_NOT_FREE                            0xC000030300000000ULL
#define TDX_TD_ASSOCIATED_PAGES_EXIST                0xC000040000000000ULL
#define TDX_SYS_INIT_NOT_PENDING                     0xC000050000000000ULL
#define TDX_SYS_LP_INIT_NOT_DONE                     0xC000050200000000ULL
#define TDX_SYS_LP_INIT_DONE                         0xC000050300000000ULL
#define TDX_SYS_NOT_READY                            0xC000050500000000ULL
#define TDX_SYS_SHUTDOWN                             0xC000050600000000ULL
#define TDX_SYS_KEY_CONFIG_NOT_PENDING               0xC000050700000000ULL
#define TDX_SYS_STATE_INCORRECT                      0xC000050800000000ULL
#define TDX_SYS_INVALID_HANDOFF                      0xC000050900000000ULL
#define TDX_SYS_INCOMPATIBLE_SIGSTRUCT               0xC000050A00000000ULL
#define TDX_SYS_LP_INIT_NOT_PENDING                  0xC000050B00000000ULL
#define TDX_SYS_CONFIG_NOT_PENDING                   0xC000050C00000000ULL
#define TDX_INCOMPATIBLE_SEAM_CAPABILITIES           0xC000050D00000000ULL
#define TDX_TD_FATAL                                 0xE000060400000000ULL
#define TDX_TD_NON_DEBUG                             0xC000060500000000ULL
#define TDX_TDCS_NOT_ALLOCATED                       0xC000060600000000ULL
#define TDX_LIFECYCLE_STATE_INCORRECT                0xC000060700000000ULL
#define TDX_OP_STATE_INCORRECT                       0xC000060800000000ULL
#define TDX_NO_VCPUS                                 0xC000060900000000ULL
#define TDX_TDCX_NUM_INCORRECT                       0xC000061000000000ULL
#define TDX_X2APIC_ID_NOT_UNIQUE                     0xC000062100000000ULL
#define TDX_VCPU_STATE_INCORRECT                     0xC000070000000000ULL
#define TDX_VCPU_ASSOCIATED                          0x8000070100000000ULL
#define TDX_VCPU_NOT_ASSOCIATED                      0x8000070200000000ULL
#define TDX_NO_VALID_VE_INFO                         0xC000070400000000ULL
#define TDX_MAX_VCPUS_EXCEEDED                       0xC000070500000000ULL
#define TDX_TSC_ROLLBACK                             0xC000070600000000ULL
#define TDX_INTERRUPTIBILITY_BLOCKED                 0xC000070700000000ULL
#define TDX_TD_VMCS_FIELD_NOT_INITIALIZED            0xC000073000000000ULL
#define TD_VMCS_FIELD_ERROR                          0xC000073100000000ULL
#define TDX_KEY_GENERATION_FAILED                    0x8000080000000000ULL
#define TDX_TD_KEYS_NOT_CONFIGURED                   0x8000081000000000ULL
#define TDX_KEY_STATE_INCORRECT                      0xC000081100000000ULL
#define TDX_KEY_CONFIGURED                           0x0000081500000000ULL
#define TDX_WBCACHE_NOT_COMPLETE                     0x8000081700000000ULL
#define TDX_HKID_NOT_FREE                            0xC000082000000000ULL
#define TDX_NO_HKID_READY_TO_WBCACHE                 0x0000082100000000ULL
#define TDX_WBCACHE_RESUME_ERROR                     0xC000082300000000ULL
#define TDX_FLUSHVP_NOT_DONE                         0x8000082400000000ULL
#define TDX_NUM_ACTIVATED_HKIDS_NOT_SUPPORTED        0xC000082500000000ULL
#define TDX_INCORRECT_CPUID_VALUE                    0xC000090000000000ULL
#define TDX_LIMIT_CPUID_MAXVAL_SET                   0xC000090100000000ULL
#define TDX_INCONSISTENT_CPUID_FIELD                 0xC000090200000000ULL
#define TDX_CPUID_MAX_SUBLEAVES_UNRECOGNIZED         0xC000090300000000ULL
#define TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED        0xC000090400000000ULL
#define TDX_INVALID_WBINVD_SCOPE                     0xC000090500000000ULL
#define TDX_INVALID_PKG_ID                           0xC000090600000000ULL
#define TDX_ENABLE_MONITOR_FSM_NOT_SET               0xC000090700000000ULL
#define TDX_CPUID_LEAF_NOT_SUPPORTED                 0xC000090800000000ULL
#define TDX_SMRR_NOT_LOCKED                          0xC000091000000000ULL
#define TDX_INVALID_SMRR_CONFIGURATION               0xC000091100000000ULL
#define TDX_SMRR_OVERLAPS_CMR                        0xC000091200000000ULL
#define TDX_SMRR_LOCK_NOT_SUPPORTED                  0xC000091300000000ULL
#define TDX_SMRR_NOT_SUPPORTED                       0xC000091400000000ULL
#define TDX_INCONSISTENT_MSR                         0xC000092000000000ULL
#define TDX_INCORRECT_MSR_VALUE                      0xC000092100000000ULL
#define TDX_SEAMREPORT_NOT_AVAILABLE                 0xC000093000000000ULL
#define TDX_SEAMDB_GETREF_NOT_AVAILABLE              0xC000093100000000ULL
#define TDX_SEAMDB_REPORT_NOT_AVAILABLE              0xC000093200000000ULL
#define TDX_SEAMVERIFYREPORT_NOT_AVAILABLE           0xC000093300000000ULL
#define TDX_INVALID_TDMR                             0xC0000A0000000000ULL
#define TDX_NON_ORDERED_TDMR                         0xC0000A0100000000ULL
#define TDX_TDMR_OUTSIDE_CMRS                        0xC0000A0200000000ULL
#define TDX_TDMR_ALREADY_INITIALIZED                 0x00000A0300000000ULL
#define TDX_INVALID_PAMT                             0xC0000A1000000000ULL
#define TDX_PAMT_OUTSIDE_CMRS                        0xC0000A1100000000ULL
#define TDX_PAMT_OVERLAP                             0xC0000A1200000000ULL
#define TDX_INVALID_RESERVED_IN_TDMR                 0xC0000A2000000000ULL
#define TDX_NON_ORDERED_RESERVED_IN_TDMR             0xC0000A2100000000ULL
#define TDX_CMR_LIST_INVALID                         0xC0000A2200000000ULL
#define TDX_EPT_WALK_FAILED                          0xC0000B0000000000ULL
#define TDX_EPT_ENTRY_FREE                           0xC0000B0100000000ULL
#define TDX_EPT_ENTRY_NOT_FREE                       0xC0000B0200000000ULL
#define TDX_EPT_ENTRY_NOT_PRESENT                    0xC0000B0300000000ULL
#define TDX_EPT_ENTRY_NOT_LEAF                       0xC0000B0400000000ULL
#define TDX_EPT_ENTRY_LEAF                           0xC0000B0500000000ULL
#define TDX_GPA_RANGE_NOT_BLOCKED                    0xC0000B0600000000ULL
#define TDX_GPA_RANGE_ALREADY_BLOCKED                0x00000B0700000000ULL
#define TDX_TLB_TRACKING_NOT_DONE                    0xC0000B0800000000ULL
#define TDX_EPT_INVALID_PROMOTE_CONDITIONS           0xC0000B0900000000ULL
#define TDX_PAGE_ALREADY_ACCEPTED                    0x00000B0A00000000ULL
#define TDX_PAGE_SIZE_MISMATCH                       0xC0000B0B00000000ULL
#define TDX_GPA_RANGE_BLOCKED                        0xC0000B0C00000000ULL
#define TDX_EPT_ENTRY_STATE_INCORRECT                0xC0000B0D00000000ULL
#define TDX_EPT_PAGE_NOT_FREE                        0xC0000B0E00000000ULL
#define TDX_L2_SEPT_WALK_FAILED                      0xC0000B0F00000000ULL
#define TDX_L2_SEPT_ENTRY_NOT_FREE                   0xC0000B1000000000ULL
#define TDX_PAGE_ATTR_INVALID                        0xC0000B1100000000ULL
#define TDX_L2_SEPT_PAGE_NOT_PROVIDED                0xC0000B1200000000ULL
#define TDX_METADATA_FIELD_ID_INCORRECT              0xC0000C0000000000ULL
#define TDX_METADATA_FIELD_NOT_WRITABLE              0xC0000C0100000000ULL
#define TDX_METADATA_FIELD_NOT_READABLE              0xC0000C0200000000ULL
#define TDX_METADATA_FIELD_VALUE_NOT_VALID           0xC0000C0300000000ULL
#define TDX_METADATA_LIST_OVERFLOW                   0xC0000C0400000000ULL
#define TDX_INVALID_METADATA_LIST_HEADER             0xC0000C0500000000ULL
#define TDX_REQUIRED_METADATA_FIELD_MISSING          0xC0000C0600000000ULL
#define TDX_METADATA_ELEMENT_SIZE_INCORRECT          0xC0000C0700000000ULL
#define TDX_METADATA_LAST_ELEMENT_INCORRECT          0xC0000C0800000000ULL
#define TDX_METADATA_FIELD_CURRENTLY_NOT_WRITABLE    0xC0000C0900000000ULL
#define TDX_METADATA_WR_MASK_NOT_VALID               0xC0000C0A00000000ULL
#define TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT       0x00000C0B00000000ULL
#define TDX_METADATA_FIELD_SKIP                      0x00000C0C00000000ULL
#define TDX_SERVTD_ALREADY_BOUND_FOR_TYPE            0xC0000D0000000000ULL
#define TDX_SERVTD_TYPE_MISMATCH                     0xC0000D0100000000ULL
#define TDX_SERVTD_ATTR_MISMATCH                     0xC0000D0200000000ULL
#define TDX_SERVTD_INFO_HASH_MISMATCH                0xC0000D0300000000ULL
#define TDX_SERVTD_UUID_MISMATCH                     0xC0000D0400000000ULL
#define TDX_SERVTD_NOT_BOUND                         0xC0000D0500000000ULL
#define TDX_SERVTD_BOUND                             0xC0000D0600000000ULL
#define TDX_TARGET_UUID_MISMATCH                     0xC0000D0700000000ULL
#define TDX_TARGET_UUID_UPDATED                      0xC0000D0800000000ULL
#define TDX_INVALID_MBMD                             0xC0000E0000000000ULL
#define TDX_INCORRECT_MBMD_MAC                       0xC0000E0100000000ULL
#define TDX_NOT_WRITE_BLOCKED                        0xC0000E0200000000ULL
#define TDX_ALREADY_WRITE_BLOCKED                    0x00000E0300000000ULL
#define TDX_NOT_EXPORTED                             0xC0000E0400000000ULL
#define TDX_MIGRATION_STREAM_STATE_INCORRECT         0xC0000E0500000000ULL
#define TDX_MAX_MIGS_NUM_EXCEEDED                    0xC0000E0600000000ULL
#define TDX_EXPORTED_DIRTY_PAGES_REMAIN              0xC0000E0700000000ULL
#define TDX_MIGRATION_DECRYPTION_KEY_NOT_SET         0xC0000E0800000000ULL
#define TDX_TD_NOT_MIGRATABLE                        0xC0000E0900000000ULL
#define TDX_PREVIOUS_EXPORT_CLEANUP_INCOMPLETE       0xC0000E0A00000000ULL
#define TDX_NUM_MIGS_HIGHER_THAN_CREATED             0xC0000E0B00000000ULL
#define TDX_IMPORT_MISMATCH                          0xC0000E0C00000000ULL
#define TDX_MIGRATION_EPOCH_OVERFLOW                 0xC0000E0D00000000ULL
#define TDX_MAX_EXPORTS_EXCEEDED                     0xC0000E0E00000000ULL
#define TDX_INVALID_PAGE_MAC                         0xC0000E0F00000000ULL
#define TDX_MIGRATED_IN_CURRENT_EPOCH                0xC0000E1000000000ULL
#define TDX_DISALLOWED_IMPORT_OVER_REMOVED           0xC0000E1100000000ULL
#define TDX_SOME_VCPUS_NOT_MIGRATED                  0xC0000E1200000000ULL
#define TDX_ALL_VCPUS_IMPORTED                       0xC0000E1300000000ULL
#define TDX_MIN_MIGS_NOT_CREATED                     0xC0000E1400000000ULL
#define TDX_VCPU_ALREADY_EXPORTED                    0xC0000E1500000000ULL
#define TDX_INVALID_MIGRATION_DECRYPTION_KEY         0xC0000E1600000000ULL
#define TDX_INVALID_CPUSVN                           0xC000100000000000ULL
#define TDX_INVALID_REPORTMACSTRUCT                  0xC000100100000000ULL
#define TDX_L2_EXIT_HOST_ROUTED_ASYNC                0x0000110000000000ULL
#define TDX_L2_EXIT_HOST_ROUTED_TDVMCALL             0x0000110100000000ULL
#define TDX_L2_EXIT_PENDING_INTERRUPT                0x0000110200000000ULL
#define TDX_PENDING_INTERRUPT                        0x0000112000000000ULL
#define TDX_TD_EXIT_BEFORE_L2_ENTRY                  0x0000114000000000ULL
#define TDX_TD_EXIT_ON_L2_VM_EXIT                    0x0000114100000000ULL
#define TDX_TD_EXIT_ON_L2_TO_L1                      0x0000114200000000ULL
#define TDX_GLA_NOT_CANONICAL                        0xC000116000000000ULL
#define UNINITIALIZE_ERROR                           0xFFFFFFFFFFFFFFFFULL

#define TDX_ERROR_CODE_MASK							 0xffffffff00000000ul

#define TDX_ACCESS_TYPE_LOAD				0x00
#define TDX_ACCESS_TYPE_CLFLUSH			    0x01
#define TDX_ACCESS_TYPE_CLFLUSHOPT			0x02
#define TDX_ACCESS_TYPE_PREFETCHT0		 	0x03
#define TDX_ACCESS_TYPE_PREFETCHT1		 	0x04
#define TDX_ACCESS_TYPE_PREFETCHT2		 	0x05
#define TDX_ACCESS_TYPE_PREFETCHNTA		 	0x06
#define TDX_ACCESS_TYPE_PREFETCHW		 	0x07
#define TDX_ACCESS_TYPE_SPLIT_LOAD		 	0x08
#define TDX_ACCESS_TYPE_SPLIT_CLFLUSH		0x09

#define TDX_ACCESS_TYPE_MAX		 			 0x09
#define TDX_ACCESS_TYPE_NONE		 	     0xff

// Special access type for TSX - only valid for the access monitor
#define TDX_ACCESS_TYPE_TSX					 0x81

#define GPA_RANGE_LIST_MAX					0x100

union ia32_perfevtsel {
	struct {
		unsigned long event_sel: 8;
		unsigned long umask: 8;
		unsigned long usr: 1;
		unsigned long os: 1;
		unsigned long edge: 1;
		unsigned long pc: 1;
		unsigned long int_: 1;
		unsigned long any_thread: 1;
		unsigned long en: 1;
		unsigned long inv: 1;
		unsigned long cmask: 8;
		unsigned long reserved1: 32;
	};
	unsigned long raw;
};
_static_assert(sizeof(union ia32_perfevtsel) == sizeof(unsigned long), "");

struct pmc_info {
	union ia32_perfevtsel evt;
	unsigned long offcore_rsp;
};

struct tdx_tdh_regs {
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r13;
    unsigned long r12;
    unsigned long r14;
} __attribute__((packed));

struct tdx_gpa_range {
	unsigned long tdr_pa;
	unsigned long start;
	unsigned long end;
	unsigned char level;
} __attribute__((packed));

struct tdx_gpa_range_list {
	unsigned long num_entries;
	struct tdx_gpa_range entries[1];
} __attribute__((packed));

struct tdx_interchanging_block {
	unsigned long tdr_pa;
	unsigned long gpa_a;
    unsigned long gpa_b;
	unsigned char level_a;
	unsigned char level_b;
} __attribute__((packed));

struct tdx_monitor_range {
	unsigned long tdr_pa;
	unsigned long start;
	unsigned long end;
	unsigned long trail_length;

	unsigned long blacklist_start;
	unsigned long blacklist_end;
} __attribute__((packed));

struct tdx_access_monitor_target_page {
	struct {
		unsigned long
			hpa : 56,
			level : 8;
	};
	unsigned long gpa;
} __attribute__ ((packed));

struct tdx_access_monitor_targets {
	struct {
		unsigned long
			sync_gpa : 56,
			sync_level : 8;
	};
	unsigned long sync_hpa;
	struct {
		unsigned long
			termination_gpa: 56,
			termination_level : 8;
	};
	struct {
		unsigned long
			access_type : 32,
			trail_length: 32;
	};
	unsigned long hit_tsc_threshold_upper;
	unsigned long hit_tsc_threshold_lower;
	unsigned long tdr_pa;
	unsigned long num_targets;
	struct pmc_info pmc;
	struct tdx_access_monitor_target_page targets[1];
} __attribute__((packed));
_static_assert(sizeof(struct tdx_access_monitor_targets) % sizeof(unsigned long) == 0, "");

#define TDX_ACCESS_MONITOR_TARGETS_MAX	((														\
	((1 << 10) * 0x1000) - __builtin_offsetof(struct tdx_access_monitor_targets, targets)) /	\
	(sizeof(((struct tdx_access_monitor_targets*)0)->targets[0])								\
))

struct tdx_access_monitor_hit {
	struct {
		unsigned long
		gpa: 56,
		level: 8;
	};
	struct {
		unsigned long
		access_type : 8,
		pmc_delta	: 56;
	};
	unsigned long hpa;
	unsigned long block_id;
	unsigned long tsc_delta;
} __attribute__((packed));

struct tdx_access_monitor_query {
	unsigned long dest_len;	// IN: Number of items that the destination buffer can take
	struct tdx_access_monitor_hit* dest; // IN: Destination address
	unsigned long num_items;	// OUT: Number of items written into dest by the kernel
} __attribute__((packed));
_static_assert(sizeof(struct tdx_access_monitor_query) % sizeof(unsigned long) == 0, "");

struct tdx_mwait_target {
	unsigned long hpa;
	struct pmc_info pmc;
	unsigned char core;
	unsigned char redundancy_core;
	unsigned char access_type;
} __attribute__((packed));


#define MAX_MWAIT_TARGETS 64
struct tdx_mwait_multi_target {
	unsigned int
		num_targets : 30,
		use_redundancy_core : 1,
		count_only : 1;
	struct tdx_mwait_target targets[1];
} __attribute__((packed));

struct tdx_mwait_access {
	unsigned long address;
	unsigned long tsc;
	unsigned long pmc_delta;
	unsigned long tsc_delta;
	unsigned char access_type;
} __attribute__((packed));

// Split huge pages request structure
struct tdx_split_huge_pages_req {
	unsigned long tdr_pa;        // To identify the VM
	unsigned long start_gpa;     // Start guest physical address
	unsigned long end_gpa;       // End guest physical address
	unsigned char target_level;  // Target page level (0=4KB, 1=2MB)
} __attribute__((packed));

union tdx_sept_entry {
	struct {
		unsigned long r		:  1;
		unsigned long w		:  1;
		unsigned long x		:  1;
		unsigned long mt		:  3;
		unsigned long ipat	:  1;
		unsigned long leaf	:  1;
		unsigned long a		:  1;
		unsigned long d		:  1;
		unsigned long xu		:  1;
		unsigned long ignored0	:  1;
		unsigned long pfn		: 40;
		unsigned long reserved	:  5;
		unsigned long vgp		:  1;
		unsigned long pwa		:  1;
		unsigned long ignored1	:  1;
		unsigned long sss		:  1;
		unsigned long spp		:  1;
		unsigned long ignored2	:  1;
		unsigned long sve		:  1;
	};
	unsigned long raw;
} __attribute__((packed, aligned(sizeof(unsigned long))));
_static_assert(sizeof(union tdx_sept_entry) == 8, "Check your compiler");

typedef union sept_entry_arch_info_u
{
    struct
    {
        unsigned long level        : 3;   // Bits 2:0
        unsigned long reserved_0   : 5;   // Bit 7:3
        unsigned long state        : 8;   // Bits 15:8
        unsigned long vm           : 2;   // Bits 17:16
        unsigned long reserved_1   : 46;  // Bits 63:18
    };
    unsigned long raw;
} sept_entry_arch_info_t;
_static_assert(sizeof(sept_entry_arch_info_t) == 8, "sept_entry_arch_info_t");

#ifdef __cplusplus
}
#endif

// For 'tdxutils' interface
#define TDXUTILS_DEVICE_NAME    				"tdxutils"

#define TDXUTILS_INTERFACE_TYPE                 0xc7
#define IOCTL_TDX_SEAMCALL                      _IOWR(TDXUTILS_INTERFACE_TYPE, 1, struct tdx_tdh_regs)
#define IOCTL_TDX_GET_TDR_PA                    _IOWR(TDXUTILS_INTERFACE_TYPE, 2, unsigned long)
#define IOCTL_TDX_BLOCK_GPA_RANGE               _IOWR(TDXUTILS_INTERFACE_TYPE, 3, struct tdx_gpa_range)
#define IOCTL_TDX_UNBLOCK_GPA_RANGE             _IOWR(TDXUTILS_INTERFACE_TYPE, 4, struct tdx_gpa_range)
#define IOCTL_TDX_SETUP_INTERCHANGING_BLOCK     _IOWR(TDXUTILS_INTERFACE_TYPE, 5, struct tdx_interchanging_block)
#define IOCTL_TDX_CLEAR_INTERCHANGING_BLOCK     _IO(TDXUTILS_INTERFACE_TYPE,   6)
#define IOCTL_TDX_SETUP_MONITOR_RANGE			_IOWR(TDXUTILS_INTERFACE_TYPE, 7, struct tdx_monitor_range)
#define IOCTL_TDX_CLEAR_MONITOR_RANGE			_IO(TDXUTILS_INTERFACE_TYPE,   8)
#define IOCTL_TDX_BLOCK_GPA_RANGE_LIST          _IOWR(TDXUTILS_INTERFACE_TYPE, 9, struct tdx_gpa_range_list)
#define IOCTL_TDX_UNBLOCK_GPA_RANGE_LIST        _IOWR(TDXUTILS_INTERFACE_TYPE, 10, struct tdx_gpa_range_list)
#define IOCTL_TDX_INSTALL_TDCALL_BLOCK_TRAP     _IOWR(TDXUTILS_INTERFACE_TYPE, 11, struct tdx_gpa_range_list)
#define IOCTL_TDX_SPLIT_HUGE_PAGES  			_IOWR(TDXUTILS_INTERFACE_TYPE, 12, struct tdx_split_huge_pages_req)
#define IOCTL_TDX_ACCESS_MONITOR_START			_IOWR(TDXUTILS_INTERFACE_TYPE, 13, struct tdx_access_monitor_targets)
#define IOCTL_TDX_ACCESS_MONITOR_STOP			_IO(TDXUTILS_INTERFACE_TYPE, 14)
#define IOCTL_TDX_ACCESS_MONITOR_QUERY  		_IOWR(TDXUTILS_INTERFACE_TYPE, 15, struct tdx_access_monitor_query)

// For 'tdx_mwait' interface
#define TDX_MWAIT_DEVICE_NAME					"tdx_mwait"
#define TDX_MWAIT_INTERFACE_TYPE                0xc8
#define IOCTL_MWAIT_MONITOR_SINGLE              _IOWR(TDX_MWAIT_INTERFACE_TYPE, 1, struct tdx_mwait_target)
#define IOCTL_MWAIT_STOP_MONITOR                _IO(TDX_MWAIT_INTERFACE_TYPE,   2)
#define IOCTL_MWAIT_MONITOR_SINGLE_BLOCKED      _IOWR(TDX_MWAIT_INTERFACE_TYPE, 3, struct tdx_mwait_target)
#define IOCTL_MWAIT_MONITOR_MULTI				_IOWR(TDX_MWAIT_INTERFACE_TYPE, 4, struct tdx_mwait_multi_target)
#define IOCTL_MWAIT_GET_ACCESS_COUNTS			_IOWR(TDX_MWAIT_INTERFACE_TYPE, 5, unsigned long[64])

#define MWAIT_TIMEOUT 100 // usecs

#define __strf_(x) #x
#define tdxutils_stringify(x) __strf_(x)

#ifdef TDXUTILS_KERNEL
struct pmc_instance {
	union ia32_perfevtsel cfg;
	unsigned long offcore_rsp;

	// Backup
	union ia32_perfevtsel backup_cfg;
	unsigned long backup_val;
	unsigned long backup_offcore_rsp;
	unsigned char backup_enabled : 1;
};

extern unsigned char shutdown_in_progress;

int tdxutils_start_counter(struct pmc_instance* instance);
int tdxutils_stop_counter(struct pmc_instance* instance, unsigned long* delta);

void tdxutils_mwait_cleanup(void);
int tdxutils_mwait_init(void);

struct kvm;
struct tdx_module_args;
extern void (*tdx_track_)(struct kvm *kvm);
extern u64 (*seamcall_saved_ret)(u64 fn, struct tdx_module_args *args);
struct kvm* get_kvm_from_tdr(unsigned long tdr_pa);
long block_range(struct tdx_gpa_range* range, void (*unblock_callback)(unsigned long addr, unsigned long tdr_pa, unsigned char level));
long unblock_range(struct tdx_gpa_range* range, void (*_)(unsigned long, unsigned long, unsigned char));

void tdxutils_access_monitor_exit(void);
int tdxutils_access_monitor_init(void);

long tdx_access_monitor_start(void* __user arg);
long tdx_access_monitor_stop(void);
long tdx_access_monitor_query(void* __user arg);

#else
static unsigned long get_tdr_pa(int util_fd) {
    long status, pa = -1;
    unsigned long i, arg;

    for(i = 0;; i++) {
        arg = i;
        status = ioctl(util_fd, IOCTL_TDX_GET_TDR_PA, &arg);
        if (status < 0)
            break;
        pa = arg;
    }

    if (pa < 0 || !i) {
        fprintf(stderr, "It seems like no TDX VM is currently running!\n");
        exit(EXIT_FAILURE);
    }

    if (i > 1)
        fprintf(stderr, "[Warning] Multiple TDX VMs are currently running. I will use the VM with TDR at 0x%lx\n", pa);

    return (unsigned long) pa;
}

static unsigned long seamcall_tdh_mem_sept_rd(int fd, unsigned char level, unsigned long gpa, unsigned long tdr_pa, unsigned long* sept_entry, unsigned long* sept_level) {
	struct tdx_tdh_regs regs;
	int status;

	memset(&regs, 0, sizeof(regs));

	regs.rax = TDH_MEM_SEPT_RD;
	regs.rcx = level | (gpa & ~0xffful);
	regs.rdx = tdr_pa;

	status = ioctl(fd, IOCTL_TDX_SEAMCALL, &regs);
	if (status < 0) {
		perror("[" __FILE__ ":" tdxutils_stringify(__LINE__) "] ioctl");
		return ~0ul;
	}
	
	if (sept_entry)
		*sept_entry = regs.rcx;
	
	if (sept_level)
		*sept_level = regs.rdx;
	
	return regs.rax;
}
#endif

static inline __attribute__((always_inline)) unsigned long tdxutils_rdtsc(void) {
	unsigned long hi, lo;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));

	return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) void do_memory_access(void* address, unsigned char access_type) {
	switch(access_type) {
		case TDX_ACCESS_TYPE_LOAD:
			asm volatile ("mov (%%rax), %%rax" :: "a"(address));
			break;
		case TDX_ACCESS_TYPE_CLFLUSH:
			asm volatile ("clflush (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_CLFLUSHOPT:
			asm volatile ("clflushopt (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_PREFETCHT0:
			asm volatile ("prefetcht0 (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_PREFETCHT1:
			asm volatile ("prefetcht1 (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_PREFETCHT2:
			asm volatile ("prefetcht2 (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_PREFETCHNTA:
			asm volatile ("prefetchnta (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_PREFETCHW:
			asm volatile ("prefetchw (%0)" :: "r"(address));
			break;
		case TDX_ACCESS_TYPE_SPLIT_LOAD:
			asm volatile ("mov (%%rax), %%rax" :: "a"(tdxutils_cast(unsigned char*, address) + 0x39));
			break;
		case TDX_ACCESS_TYPE_SPLIT_CLFLUSH:
			asm volatile ("clflush (%0)" :: "r"(tdxutils_cast(unsigned char*, address) + 0x39));
			break;
		default:;
	}
	asm volatile ("mfence");
}

#undef _static_assert
#undef tdxutils_cast
#endif