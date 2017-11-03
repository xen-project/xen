/*
 * Explicitly intended for multiple inclusion.
 */

#include <asm/cpuid-autogen.h>

#define FSCAPINTS FEATURESET_NR_ENTRIES

#define NCAPINTS (FSCAPINTS + 1) /* N 32-bit words worth of info */

/* Other features, Xen-defined mapping. */
/* This range is used for feature bits which conflict or are synthesized */
XEN_CPUFEATURE(CONSTANT_TSC,    (FSCAPINTS+0)*32+ 0) /* TSC ticks at a constant rate */
XEN_CPUFEATURE(NONSTOP_TSC,     (FSCAPINTS+0)*32+ 1) /* TSC does not stop in C states */
XEN_CPUFEATURE(ARAT,            (FSCAPINTS+0)*32+ 2) /* Always running APIC timer */
XEN_CPUFEATURE(ARCH_PERFMON,    (FSCAPINTS+0)*32+ 3) /* Intel Architectural PerfMon */
XEN_CPUFEATURE(TSC_RELIABLE,    (FSCAPINTS+0)*32+ 4) /* TSC is known to be reliable */
XEN_CPUFEATURE(XTOPOLOGY,       (FSCAPINTS+0)*32+ 5) /* cpu topology enum extensions */
XEN_CPUFEATURE(CPUID_FAULTING,  (FSCAPINTS+0)*32+ 6) /* cpuid faulting */
XEN_CPUFEATURE(CLFLUSH_MONITOR, (FSCAPINTS+0)*32+ 7) /* clflush reqd with monitor */
XEN_CPUFEATURE(APERFMPERF,      (FSCAPINTS+0)*32+ 8) /* APERFMPERF */
XEN_CPUFEATURE(MFENCE_RDTSC,    (FSCAPINTS+0)*32+ 9) /* MFENCE synchronizes RDTSC */
XEN_CPUFEATURE(XEN_SMEP,        (FSCAPINTS+0)*32+10) /* SMEP gets used by Xen itself */
XEN_CPUFEATURE(XEN_SMAP,        (FSCAPINTS+0)*32+11) /* SMAP gets used by Xen itself */
XEN_CPUFEATURE(LFENCE_DISPATCH, (FSCAPINTS+0)*32+12) /* lfence set as Dispatch Serialising */
XEN_CPUFEATURE(IND_THUNK_LFENCE,(FSCAPINTS+0)*32+13) /* Use IND_THUNK_LFENCE */
XEN_CPUFEATURE(IND_THUNK_JMP,   (FSCAPINTS+0)*32+14) /* Use IND_THUNK_JMP */
XEN_CPUFEATURE(XEN_IBPB,        (FSCAPINTS+0)*32+15) /* IBRSB || IBPB */
XEN_CPUFEATURE(XEN_IBRS_SET,    (FSCAPINTS+0)*32+16) /* IBRSB && IRBS set in Xen */
XEN_CPUFEATURE(XEN_IBRS_CLEAR,  (FSCAPINTS+0)*32+17) /* IBRSB && IBRS clear in Xen */
XEN_CPUFEATURE(RSB_NATIVE,      (FSCAPINTS+0)*32+18) /* RSB overwrite needed for native */
XEN_CPUFEATURE(RSB_VMEXIT,      (FSCAPINTS+0)*32+20) /* RSB overwrite needed for vmexit */
