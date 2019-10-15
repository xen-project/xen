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
XEN_CPUFEATURE(LFENCE_DISPATCH,   X86_SYNTH(12)) /* lfence set as Dispatch Serialising */
XEN_CPUFEATURE(IND_THUNK_LFENCE,  X86_SYNTH(13)) /* Use IND_THUNK_LFENCE */
XEN_CPUFEATURE(IND_THUNK_JMP,     X86_SYNTH(14)) /* Use IND_THUNK_JMP */
XEN_CPUFEATURE(SC_BRANCH_HARDEN,  X86_SYNTH(15)) /* Conditional Branch Hardening */
XEN_CPUFEATURE(SC_MSR_PV,         X86_SYNTH(16)) /* MSR_SPEC_CTRL used by Xen for PV */
XEN_CPUFEATURE(SC_MSR_HVM,        X86_SYNTH(17)) /* MSR_SPEC_CTRL used by Xen for HVM */
XEN_CPUFEATURE(SC_RSB_PV,         X86_SYNTH(18)) /* RSB overwrite needed for PV */
XEN_CPUFEATURE(SC_RSB_HVM,        X86_SYNTH(19)) /* RSB overwrite needed for HVM */
XEN_CPUFEATURE(XEN_SELFSNOOP,     X86_SYNTH(20)) /* SELFSNOOP gets used by Xen itself */
XEN_CPUFEATURE(SC_MSR_IDLE,       X86_SYNTH(21)) /* (SC_MSR_PV || SC_MSR_HVM) && default_xen_spec_ctrl */
XEN_CPUFEATURE(XEN_LBR,           X86_SYNTH(22)) /* Xen uses MSR_DEBUGCTL.LBR */
XEN_CPUFEATURE(SC_VERW_PV,        X86_SYNTH(23)) /* VERW used by Xen for PV */
XEN_CPUFEATURE(SC_VERW_HVM,       X86_SYNTH(24)) /* VERW used by Xen for HVM */
XEN_CPUFEATURE(SC_VERW_IDLE,      X86_SYNTH(25)) /* VERW used by Xen for idle */

/* Bug words follow the synthetic words. */
#define X86_NR_BUG 1
#define X86_BUG(x) ((FSCAPINTS + X86_NR_SYNTH) * 32 + (x))

#define X86_BUG_FPU_PTRS          X86_BUG( 0) /* (F)X{SAVE,RSTOR} doesn't save/restore FOP/FIP/FDP. */

/* Total number of capability words, inc synth and bug words. */
#define NCAPINTS (FSCAPINTS + X86_NR_SYNTH + X86_NR_BUG) /* N 32-bit words worth of info */
