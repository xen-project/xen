/*
 * cpufeature.h
 *
 * Defines x86 CPU feature bits
 */

#ifndef __ASM_I386_CPUFEATURE_H
#define __ASM_I386_CPUFEATURE_H

#ifndef __ASSEMBLY__
#include <xen/bitops.h>
#endif

#define NCAPINTS	8	/* N 32-bit words worth of info */

/* Intel-defined CPU features, CPUID level 0x00000001 (edx), word 0 */
#define X86_FEATURE_FPU		(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_VME		(0*32+ 1) /* Virtual Mode Extensions */
#define X86_FEATURE_DE		(0*32+ 2) /* Debugging Extensions */
#define X86_FEATURE_PSE 	(0*32+ 3) /* Page Size Extensions */
#define X86_FEATURE_TSC		(0*32+ 4) /* Time Stamp Counter */
#define X86_FEATURE_MSR		(0*32+ 5) /* Model-Specific Registers, RDMSR, WRMSR */
#define X86_FEATURE_PAE		(0*32+ 6) /* Physical Address Extensions */
#define X86_FEATURE_MCE		(0*32+ 7) /* Machine Check Architecture */
#define X86_FEATURE_CX8		(0*32+ 8) /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC	(0*32+ 9) /* Onboard APIC */
#define X86_FEATURE_SEP		(0*32+11) /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR	(0*32+12) /* Memory Type Range Registers */
#define X86_FEATURE_PGE		(0*32+13) /* Page Global Enable */
#define X86_FEATURE_MCA		(0*32+14) /* Machine Check Architecture */
#define X86_FEATURE_CMOV	(0*32+15) /* CMOV instruction (FCMOVCC and FCOMI too if FPU present) */
#define X86_FEATURE_PAT		(0*32+16) /* Page Attribute Table */
#define X86_FEATURE_PSE36	(0*32+17) /* 36-bit PSEs */
#define X86_FEATURE_PN		(0*32+18) /* Processor serial number */
#define X86_FEATURE_CLFLSH	(0*32+19) /* Supports the CLFLUSH instruction */
#define X86_FEATURE_DS		(0*32+21) /* Debug Store */
#define X86_FEATURE_ACPI	(0*32+22) /* ACPI via MSR */
#define X86_FEATURE_MMX		(0*32+23) /* Multimedia Extensions */
#define X86_FEATURE_FXSR	(0*32+24) /* FXSAVE and FXRSTOR instructions (fast save and restore */
				          /* of FPU context), and CR4.OSFXSR available */
#define X86_FEATURE_XMM		(0*32+25) /* Streaming SIMD Extensions */
#define X86_FEATURE_XMM2	(0*32+26) /* Streaming SIMD Extensions-2 */
#define X86_FEATURE_SELFSNOOP	(0*32+27) /* CPU self snoop */
#define X86_FEATURE_HT		(0*32+28) /* Hyper-Threading */
#define X86_FEATURE_ACC		(0*32+29) /* Automatic clock control */
#define X86_FEATURE_IA64	(0*32+30) /* IA-64 processor */
#define X86_FEATURE_PBE		(0*32+31) /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL	(1*32+11) /* SYSCALL/SYSRET */
#define X86_FEATURE_MP		(1*32+19) /* MP Capable. */
#define X86_FEATURE_NX		(1*32+20) /* Execute Disable */
#define X86_FEATURE_MMXEXT	(1*32+22) /* AMD MMX extensions */
#define X86_FEATURE_FFXSR       (1*32+25) /* FFXSR instruction optimizations */
#define X86_FEATURE_PAGE1GB	(1*32+26) /* 1Gb large page support */
#define X86_FEATURE_RDTSCP	(1*32+27) /* RDTSCP */
#define X86_FEATURE_LM		(1*32+29) /* Long Mode (x86-64) */
#define X86_FEATURE_3DNOWEXT	(1*32+30) /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW	(1*32+31) /* 3DNow! */

/* *** Available for re-use ***, word 2 */

/* Other features, Linux-defined mapping, word 3 */
/* This range is used for feature bits which conflict or are synthesized */
#define X86_FEATURE_CONSTANT_TSC (3*32+ 8) /* TSC ticks at a constant rate */
#define X86_FEATURE_NONSTOP_TSC	(3*32+ 9) /* TSC does not stop in C states */
#define X86_FEATURE_ARAT	(3*32+ 10) /* Always running APIC timer */
#define X86_FEATURE_ARCH_PERFMON (3*32+11) /* Intel Architectural PerfMon */
#define X86_FEATURE_TSC_RELIABLE (3*32+12) /* TSC is known to be reliable */
#define X86_FEATURE_XTOPOLOGY    (3*32+13) /* cpu topology enum extensions */
#define X86_FEATURE_CPUID_FAULTING (3*32+14) /* cpuid faulting */
#define X86_FEATURE_CLFLUSH_MONITOR (3*32+15) /* clflush reqd with monitor */

/* Intel-defined CPU features, CPUID level 0x00000001 (ecx), word 4 */
#define X86_FEATURE_XMM3	(4*32+ 0) /* Streaming SIMD Extensions-3 */
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* Carry-less mulitplication */
#define X86_FEATURE_DTES64	(4*32+ 2) /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT	(4*32+ 3) /* Monitor/Mwait support */
#define X86_FEATURE_DSCPL	(4*32+ 4) /* CPL Qualified Debug Store */
#define X86_FEATURE_VMXE	(4*32+ 5) /* Virtual Machine Extensions */
#define X86_FEATURE_SMXE	(4*32+ 6) /* Safer Mode Extensions */
#define X86_FEATURE_EST		(4*32+ 7) /* Enhanced SpeedStep */
#define X86_FEATURE_TM2		(4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental Streaming SIMD Extensions-3 */
#define X86_FEATURE_CID		(4*32+10) /* Context ID */
#define X86_FEATURE_FMA		(4*32+12) /* Fused Multiply Add */
#define X86_FEATURE_CX16        (4*32+13) /* CMPXCHG16B */
#define X86_FEATURE_XTPR	(4*32+14) /* Send Task Priority Messages */
#define X86_FEATURE_PDCM	(4*32+15) /* Perf/Debug Capability MSR */
#define X86_FEATURE_PCID	(4*32+17) /* Process Context ID */
#define X86_FEATURE_DCA		(4*32+18) /* Direct Cache Access */
#define X86_FEATURE_SSE4_1	(4*32+19) /* Streaming SIMD Extensions 4.1 */
#define X86_FEATURE_SSE4_2	(4*32+20) /* Streaming SIMD Extensions 4.2 */
#define X86_FEATURE_X2APIC	(4*32+21) /* Extended xAPIC */
#define X86_FEATURE_MOVBE	(4*32+22) /* movbe instruction */
#define X86_FEATURE_POPCNT	(4*32+23) /* POPCNT instruction */
#define X86_FEATURE_TSC_DEADLINE (4*32+24) /* "tdt" TSC Deadline Timer */
#define X86_FEATURE_AES		(4*32+25) /* AES instructions */
#define X86_FEATURE_XSAVE	(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_OSXSAVE	(4*32+27) /* OSXSAVE */
#define X86_FEATURE_AVX 	(4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_F16C 	(4*32+29) /* Half-precision convert instruction */
#define X86_FEATURE_RDRAND 	(4*32+30) /* Digital Random Number Generator */
#define X86_FEATURE_HYPERVISOR	(4*32+31) /* Running under some hypervisor */

/* VIA/Cyrix/Centaur-defined CPU features, CPUID level 0xC0000001, word 5 */
#define X86_FEATURE_XSTORE	(5*32+ 2) /* on-CPU RNG present (xstore insn) */
#define X86_FEATURE_XSTORE_EN	(5*32+ 3) /* on-CPU RNG enabled */
#define X86_FEATURE_XCRYPT	(5*32+ 6) /* on-CPU crypto (xcrypt insn) */
#define X86_FEATURE_XCRYPT_EN	(5*32+ 7) /* on-CPU crypto enabled */
#define X86_FEATURE_ACE2	(5*32+ 8) /* Advanced Cryptography Engine v2 */
#define X86_FEATURE_ACE2_EN	(5*32+ 9) /* ACE v2 enabled */
#define X86_FEATURE_PHE		(5*32+ 10) /* PadLock Hash Engine */
#define X86_FEATURE_PHE_EN	(5*32+ 11) /* PHE enabled */
#define X86_FEATURE_PMM		(5*32+ 12) /* PadLock Montgomery Multiplier */
#define X86_FEATURE_PMM_EN	(5*32+ 13) /* PMM enabled */

/* More extended AMD flags: CPUID level 0x80000001, ecx, word 6 */
#define X86_FEATURE_LAHF_LM     (6*32+ 0) /* LAHF/SAHF in long mode */
#define X86_FEATURE_CMP_LEGACY  (6*32+ 1) /* If yes HyperThreading not valid */
#define X86_FEATURE_SVM         (6*32+ 2) /* Secure virtual machine */
#define X86_FEATURE_EXTAPIC     (6*32+ 3) /* Extended APIC space */
#define X86_FEATURE_CR8_LEGACY  (6*32+ 4) /* CR8 in 32-bit mode */
#define X86_FEATURE_ABM         (6*32+ 5) /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A       (6*32+ 6) /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#define X86_FEATURE_OSVW        (6*32+ 9) /* OS Visible Workaround */
#define X86_FEATURE_IBS         (6*32+10) /* Instruction Based Sampling */
#define X86_FEATURE_XOP         (6*32+11) /* extended AVX instructions */
#define X86_FEATURE_SKINIT      (6*32+12) /* SKINIT/STGI instructions */
#define X86_FEATURE_WDT         (6*32+13) /* Watchdog timer */
#define X86_FEATURE_LWP         (6*32+15) /* Light Weight Profiling */
#define X86_FEATURE_FMA4        (6*32+16) /* 4 operands MAC instructions */
#define X86_FEATURE_NODEID_MSR  (6*32+19) /* NodeId MSR */
#define X86_FEATURE_TBM         (6*32+21) /* trailing bit manipulations */
#define X86_FEATURE_TOPOEXT     (6*32+22) /* topology extensions CPUID leafs */
#define X86_FEATURE_DBEXT       (6*32+26) /* data breakpoint extension */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (ebx), word 7 */
#define X86_FEATURE_FSGSBASE	(7*32+ 0) /* {RD,WR}{FS,GS}BASE instructions */
#define X86_FEATURE_BMI1	(7*32+ 3) /* 1st bit manipulation extensions */
#define X86_FEATURE_HLE 	(7*32+ 4) /* Hardware Lock Elision */
#define X86_FEATURE_AVX2	(7*32+ 5) /* AVX2 instructions */
#define X86_FEATURE_SMEP	(7*32+ 7) /* Supervisor Mode Execution Protection */
#define X86_FEATURE_BMI2	(7*32+ 8) /* 2nd bit manipulation extensions */
#define X86_FEATURE_ERMS	(7*32+ 9) /* Enhanced REP MOVSB/STOSB */
#define X86_FEATURE_INVPCID	(7*32+10) /* Invalidate Process Context ID */
#define X86_FEATURE_RTM 	(7*32+11) /* Restricted Transactional Memory */
#define X86_FEATURE_CMT 	(7*32+12) /* Cache Monitoring Technology */
#define X86_FEATURE_NO_FPU_SEL 	(7*32+13) /* FPU CS/DS stored as zero */
#define X86_FEATURE_MPX		(7*32+14) /* Memory Protection Extensions */
#define X86_FEATURE_RDSEED	(7*32+18) /* RDSEED instruction */
#define X86_FEATURE_ADX		(7*32+19) /* ADCX, ADOX instructions */
#define X86_FEATURE_SMAP	(7*32+20) /* Supervisor Mode Access Prevention */

#ifndef __ASSEMBLY__
#define cpu_has(c, bit)		test_bit(bit, (c)->x86_capability)
#define boot_cpu_has(bit)	test_bit(bit, boot_cpu_data.x86_capability)
#define cpufeat_mask(idx)       (1u << ((idx) & 31))

#define CPUID_MWAIT_LEAF                5
#define CPUID5_ECX_EXTENSIONS_SUPPORTED 0x1
#define CPUID5_ECX_INTERRUPT_BREAK      0x2

#define cpu_has_vme		0
#define cpu_has_de		1
#define cpu_has_pse		1
#define cpu_has_tsc		1
#define cpu_has_pge		1
#define cpu_has_pat		1
#define cpu_has_apic		boot_cpu_has(X86_FEATURE_APIC)
#define cpu_has_sep		boot_cpu_has(X86_FEATURE_SEP)
#define cpu_has_mtrr		1
#define cpu_has_mmx		1
#define cpu_has_fxsr		1
#define cpu_has_xmm		1
#define cpu_has_xmm2		1
#define cpu_has_xmm3		boot_cpu_has(X86_FEATURE_XMM3)
#define cpu_has_ht		boot_cpu_has(X86_FEATURE_HT)
#define cpu_has_syscall		1
#define cpu_has_mp		1
#define cpu_has_nx		boot_cpu_has(X86_FEATURE_NX)
#define cpu_has_k6_mtrr		0
#define cpu_has_cyrix_arr	0
#define cpu_has_centaur_mcr	0
#define cpu_has_clflush		boot_cpu_has(X86_FEATURE_CLFLSH)
#define cpu_has_page1gb		boot_cpu_has(X86_FEATURE_PAGE1GB)
#define cpu_has_efer		1
#define cpu_has_fsgsbase	boot_cpu_has(X86_FEATURE_FSGSBASE)

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

#define cpu_has_vmx		boot_cpu_has(X86_FEATURE_VMXE)

#define cpu_has_cpuid_faulting	boot_cpu_has(X86_FEATURE_CPUID_FAULTING)

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

#endif /* __ASM_I386_CPUFEATURE_H */

/* 
 * Local Variables:
 * mode:c
 * comment-column:42
 * End:
 */
