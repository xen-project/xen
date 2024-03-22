/*
 * Explicitly intended for multiple inclusion.
 */

#include <xen/lib/x86/cpuid-autogen.h>

/* Number of capability words covered by the featureset words. */
#define FSCAPINTS FEATURESET_NR_ENTRIES

/* Synthetic words follow the featureset words. */
#define X86_NR_SYNTH 1
#define X86_SYNTH(x) (FSCAPINTS * 32 + (x))

/* Synthetic features */
XEN_CPUFEATURE(CONSTANT_TSC,      X86_SYNTH( 0)) /* TSC ticks at a constant rate */
XEN_CPUFEATURE(NONSTOP_TSC,       X86_SYNTH( 1)) /* TSC does not stop in C states */
XEN_CPUFEATURE(ARAT,              X86_SYNTH( 2)) /* Always running APIC timer */
XEN_CPUFEATURE(ARCH_PERFMON,      X86_SYNTH( 3)) /* Intel Architectural PerfMon */
XEN_CPUFEATURE(TSC_RELIABLE,      X86_SYNTH( 4)) /* TSC is known to be reliable */
XEN_CPUFEATURE(XTOPOLOGY,         X86_SYNTH( 5)) /* cpu topology enum extensions */
XEN_CPUFEATURE(CPUID_FAULTING,    X86_SYNTH( 6)) /* cpuid faulting */
XEN_CPUFEATURE(CLFLUSH_MONITOR,   X86_SYNTH( 7)) /* clflush reqd with monitor */
XEN_CPUFEATURE(APERFMPERF,        X86_SYNTH( 8)) /* APERFMPERF */
XEN_CPUFEATURE(MFENCE_RDTSC,      X86_SYNTH( 9)) /* MFENCE synchronizes RDTSC */
XEN_CPUFEATURE(XEN_SMEP,          X86_SYNTH(10)) /* SMEP gets used by Xen itself */
XEN_CPUFEATURE(XEN_SMAP,          X86_SYNTH(11)) /* SMAP gets used by Xen itself */
XEN_CPUFEATURE(SC_NO_LOCK_HARDEN, X86_SYNTH(12)) /* (Disable) Lock critical region hardening */
XEN_CPUFEATURE(IND_THUNK_LFENCE,  X86_SYNTH(13)) /* Use IND_THUNK_LFENCE */
XEN_CPUFEATURE(IND_THUNK_JMP,     X86_SYNTH(14)) /* Use IND_THUNK_JMP */
XEN_CPUFEATURE(SC_NO_BRANCH_HARDEN, X86_SYNTH(15)) /* (Disable) Conditional branch hardening */
XEN_CPUFEATURE(SC_MSR_PV,         X86_SYNTH(16)) /* MSR_SPEC_CTRL used by Xen for PV */
XEN_CPUFEATURE(SC_MSR_HVM,        X86_SYNTH(17)) /* MSR_SPEC_CTRL used by Xen for HVM */
XEN_CPUFEATURE(SC_RSB_PV,         X86_SYNTH(18)) /* RSB overwrite needed for PV */
XEN_CPUFEATURE(SC_RSB_HVM,        X86_SYNTH(19)) /* RSB overwrite needed for HVM */
XEN_CPUFEATURE(XEN_SELFSNOOP,     X86_SYNTH(20)) /* SELFSNOOP gets used by Xen itself */
XEN_CPUFEATURE(SC_MSR_IDLE,       X86_SYNTH(21)) /* Clear MSR_SPEC_CTRL on idle */
XEN_CPUFEATURE(XEN_LBR,           X86_SYNTH(22)) /* Xen uses MSR_DEBUGCTL.LBR */
XEN_CPUFEATURE(SC_DIV,            X86_SYNTH(23)) /* DIV scrub needed */
XEN_CPUFEATURE(SC_RSB_IDLE,       X86_SYNTH(24)) /* RSB overwrite needed for idle. */
XEN_CPUFEATURE(SC_VERW_IDLE,      X86_SYNTH(25)) /* VERW used by Xen for idle */
XEN_CPUFEATURE(XEN_SHSTK,         X86_SYNTH(26)) /* Xen uses CET Shadow Stacks */
XEN_CPUFEATURE(XEN_IBT,           X86_SYNTH(27)) /* Xen uses CET Indirect Branch Tracking */
XEN_CPUFEATURE(IBPB_ENTRY_PV,     X86_SYNTH(28)) /* MSR_PRED_CMD used by Xen for PV */
XEN_CPUFEATURE(IBPB_ENTRY_HVM,    X86_SYNTH(29)) /* MSR_PRED_CMD used by Xen for HVM */

/* Bug words follow the synthetic words. */
#define X86_NR_BUG 1
#define X86_BUG(x) ((FSCAPINTS + X86_NR_SYNTH) * 32 + (x))

#define X86_BUG_FPU_PTRS          X86_BUG( 0) /* (F)X{SAVE,RSTOR} doesn't save/restore FOP/FIP/FDP. */
#define X86_BUG_NULL_SEG          X86_BUG( 1) /* NULL-ing a selector preserves the base and limit. */
#define X86_BUG_CLFLUSH_MFENCE    X86_BUG( 2) /* MFENCE needed to serialise CLFLUSH */
#define X86_BUG_IBPB_NO_RET       X86_BUG( 3) /* IBPB doesn't flush the RSB/RAS */

#define X86_SPEC_NO_LFENCE_ENTRY_PV X86_BUG(16) /* (No) safety LFENCE for SPEC_CTRL_ENTRY_PV. */
#define X86_SPEC_NO_LFENCE_ENTRY_INTR X86_BUG(17) /* (No) safety LFENCE for SPEC_CTRL_ENTRY_INTR. */
#define X86_SPEC_NO_LFENCE_ENTRY_VMX X86_BUG(18) /* (No) safety LFENCE for SPEC_CTRL_ENTRY_VMX. */

#define X86_SPEC_BHB_TSX          X86_BUG(19) /* Use clear_bhb_tsx for BHI mitigation. */
#define X86_SPEC_BHB_LOOPS        X86_BUG(20) /* Use clear_bhb_loops for BHI mitigation.*/
#define X86_SPEC_BHB_LOOPS_LONG   X86_BUG(21) /* Upgrade clear_bhb_loops to the "long" sequence. */

/* Total number of capability words, inc synth and bug words. */
#define NCAPINTS (FSCAPINTS + X86_NR_SYNTH + X86_NR_BUG) /* N 32-bit words worth of info */
