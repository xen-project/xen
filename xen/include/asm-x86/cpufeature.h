/*
 * cpufeature.h
 *
 * Defines x86 CPU feature bits
 */
#if defined(XEN_CPUFEATURE)

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
XEN_CPUFEATURE(XEN_SMEP,        (FSCAPINTS+0)*32+ 10) /* SMEP gets used by Xen itself */
XEN_CPUFEATURE(XEN_SMAP,        (FSCAPINTS+0)*32+ 11) /* SMAP gets used by Xen itself */
XEN_CPUFEATURE(MSR_PLATFORM_INFO, (FSCAPINTS+0)*32+12) /* PLATFORM_INFO MSR present */
XEN_CPUFEATURE(MSR_MISC_FEATURES, (FSCAPINTS+0)*32+13) /* MISC_FEATURES_ENABLES MSR present */

#define NCAPINTS (FSCAPINTS + 1) /* N 32-bit words worth of info */

#elif !defined(__ASM_I386_CPUFEATURE_H)
#ifndef X86_FEATURES_ONLY
#define __ASM_I386_CPUFEATURE_H
#endif

#include <xen/const.h>
#include <asm/cpuid.h>

#define cpufeat_word(idx)	((idx) / 32)
#define cpufeat_bit(idx)	((idx) % 32)
#define cpufeat_mask(idx)	(_AC(1, U) << cpufeat_bit(idx))

/* An alias of a feature we know is always going to be present. */
#define X86_FEATURE_ALWAYS      X86_FEATURE_LM

#if !defined(__ASSEMBLY__) && !defined(X86_FEATURES_ONLY)
#include <xen/bitops.h>

#define cpu_has(c, bit)		test_bit(bit, (c)->x86_capability)
#define boot_cpu_has(bit)	test_bit(bit, boot_cpu_data.x86_capability)

#define CPUID_MWAIT_LEAF                5
#define CPUID5_ECX_EXTENSIONS_SUPPORTED 0x1
#define CPUID5_ECX_INTERRUPT_BREAK      0x2

#define CPUID_PM_LEAF                    6
#define CPUID6_ECX_APERFMPERF_CAPABILITY 0x1

#define cpu_has_fpu		1
#define cpu_has_de		1
#define cpu_has_pse		1
#define cpu_has_pge		1
#define cpu_has_pat		1
#define cpu_has_apic		boot_cpu_has(X86_FEATURE_APIC)
#define cpu_has_sep		boot_cpu_has(X86_FEATURE_SEP)
#define cpu_has_mtrr		1
#define cpu_has_mmx		1
#define cpu_has_sse		boot_cpu_has(X86_FEATURE_SSE)
#define cpu_has_sse2		boot_cpu_has(X86_FEATURE_SSE2)
#define cpu_has_sse3		boot_cpu_has(X86_FEATURE_SSE3)
#define cpu_has_sse4_2		boot_cpu_has(X86_FEATURE_SSE4_2)
#define cpu_has_htt		boot_cpu_has(X86_FEATURE_HTT)
#define cpu_has_nx		boot_cpu_has(X86_FEATURE_NX)
#define cpu_has_clflush		boot_cpu_has(X86_FEATURE_CLFLUSH)
#define cpu_has_page1gb		boot_cpu_has(X86_FEATURE_PAGE1GB)
#define cpu_has_fsgsbase	boot_cpu_has(X86_FEATURE_FSGSBASE)
#define cpu_has_aperfmperf	boot_cpu_has(X86_FEATURE_APERFMPERF)
#define cpu_has_smep            boot_cpu_has(X86_FEATURE_SMEP)
#define cpu_has_smap            boot_cpu_has(X86_FEATURE_SMAP)
#define cpu_has_fpu_sel         (!boot_cpu_has(X86_FEATURE_NO_FPU_SEL))
#define cpu_has_ffxsr           ((boot_cpu_data.x86_vendor == X86_VENDOR_AMD) \
                                 && boot_cpu_has(X86_FEATURE_FFXSR))
#define cpu_has_x2apic          boot_cpu_has(X86_FEATURE_X2APIC)
#define cpu_has_pcid            boot_cpu_has(X86_FEATURE_PCID)
#define cpu_has_xsave           boot_cpu_has(X86_FEATURE_XSAVE)
#define cpu_has_avx             boot_cpu_has(X86_FEATURE_AVX)
#define cpu_has_lwp             boot_cpu_has(X86_FEATURE_LWP)
#define cpu_has_mpx             boot_cpu_has(X86_FEATURE_MPX)
#define cpu_has_arch_perfmon    boot_cpu_has(X86_FEATURE_ARCH_PERFMON)
#define cpu_has_rdtscp          boot_cpu_has(X86_FEATURE_RDTSCP)
#define cpu_has_svm		boot_cpu_has(X86_FEATURE_SVM)
#define cpu_has_vmx		boot_cpu_has(X86_FEATURE_VMX)
#define cpu_has_cpuid_faulting	boot_cpu_has(X86_FEATURE_CPUID_FAULTING)
#define cpu_has_cx16            boot_cpu_has(X86_FEATURE_CX16)
#define cpu_has_xsaveopt	boot_cpu_has(X86_FEATURE_XSAVEOPT)
#define cpu_has_xsavec		boot_cpu_has(X86_FEATURE_XSAVEC)
#define cpu_has_xgetbv1		boot_cpu_has(X86_FEATURE_XGETBV1)
#define cpu_has_xsaves		boot_cpu_has(X86_FEATURE_XSAVES)
#define cpu_has_monitor		boot_cpu_has(X86_FEATURE_MONITOR)
#define cpu_has_eist		boot_cpu_has(X86_FEATURE_EIST)
#define cpu_has_hypervisor	boot_cpu_has(X86_FEATURE_HYPERVISOR)
#define cpu_has_cmp_legacy	boot_cpu_has(X86_FEATURE_CMP_LEGACY)

enum _cache_type {
    CACHE_TYPE_NULL = 0,
    CACHE_TYPE_DATA = 1,
    CACHE_TYPE_INST = 2,
    CACHE_TYPE_UNIFIED = 3
};

union _cpuid4_leaf_eax {
    struct {
        enum _cache_type type:5;
        unsigned int level:3;
        unsigned int is_self_initializing:1;
        unsigned int is_fully_associative:1;
        unsigned int reserved:4;
        unsigned int num_threads_sharing:12;
        unsigned int num_cores_on_die:6;
    } split;
    u32 full;
};

union _cpuid4_leaf_ebx {
    struct {
        unsigned int coherency_line_size:12;
        unsigned int physical_line_partition:10;
        unsigned int ways_of_associativity:10;
    } split;
    u32 full;
};

union _cpuid4_leaf_ecx {
    struct {
        unsigned int number_of_sets:32;
    } split;
    u32 full;
};

struct cpuid4_info {
    union _cpuid4_leaf_eax eax;
    union _cpuid4_leaf_ebx ebx;
    union _cpuid4_leaf_ecx ecx;
    unsigned long size;
};

int cpuid4_cache_lookup(int index, struct cpuid4_info *this_leaf);
#endif

#undef X86_FEATURES_ONLY

#endif /* __ASM_I386_CPUFEATURE_H */

/* 
 * Local Variables:
 * mode:c
 * comment-column:42
 * End:
 */
