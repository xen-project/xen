/*
 * cpufeature.h
 *
 * Defines x86 CPU feature bits
 */
#ifndef __ASM_I386_CPUFEATURE_H
#define __ASM_I386_CPUFEATURE_H

#include <xen/cache.h>
#include <xen/const.h>
#include <asm/cpuid.h>

#define cpufeat_word(idx)	((idx) / 32)
#define cpufeat_bit(idx)	((idx) % 32)
#define cpufeat_mask(idx)	(_AC(1, U) << cpufeat_bit(idx))

/* An alias of a feature we know is always going to be present. */
#define X86_FEATURE_ALWAYS      X86_FEATURE_LM

#ifndef __ASSEMBLY__

struct cpuinfo_x86 {
    unsigned char x86;                 /* CPU family */
    unsigned char x86_vendor;          /* CPU vendor */
    unsigned char x86_model;
    unsigned char x86_mask;
    unsigned int cpuid_level;          /* Maximum supported CPUID level */
    unsigned int extended_cpuid_level; /* Maximum supported CPUID extended level */
    unsigned int x86_capability[NCAPINTS];
    char x86_vendor_id[16];
    char x86_model_id[64];
    unsigned int x86_cache_size;       /* in KB - valid only when supported */
    unsigned int x86_cache_alignment;  /* In bytes */
    unsigned int x86_max_cores;        /* cpuid returned max cores value */
    unsigned int booted_cores;         /* number of cores as seen by OS */
    unsigned int x86_num_siblings;     /* cpuid logical cpus per chip value */
    unsigned int apicid;
    unsigned int phys_proc_id;         /* package ID of each logical CPU */
    unsigned int cpu_core_id;          /* core ID of each logical CPU */
    unsigned int compute_unit_id;      /* AMD compute unit ID of each logical CPU */
    unsigned short x86_clflush_size;
} __cacheline_aligned;

extern struct cpuinfo_x86 boot_cpu_data;

static inline bool cpu_has(const struct cpuinfo_x86 *info, unsigned int feat)
{
    return info->x86_capability[cpufeat_word(feat)] & cpufeat_mask(feat);
}

static inline bool boot_cpu_has(unsigned int feat)
{
    return cpu_has(&boot_cpu_data, feat);
}

#define CPUID_PM_LEAF                                6
#define CPUID6_EAX_HWP                               BIT(7, U)
#define CPUID6_EAX_HWP_NOTIFICATION                  BIT(8, U)
#define CPUID6_EAX_HWP_ACTIVITY_WINDOW               BIT(9, U)
#define CPUID6_EAX_HWP_ENERGY_PERFORMANCE_PREFERENCE BIT(10, U)
#define CPUID6_EAX_HWP_PACKAGE_LEVEL_REQUEST         BIT(11, U)
#define CPUID6_EAX_HDC                               BIT(13, U)
#define CPUID6_EAX_HWP_PECI                          BIT(16, U)
#define CPUID6_EAX_HW_FEEDBACK                       BIT(19, U)
#define CPUID6_ECX_APERFMPERF_CAPABILITY             BIT(0, U)

/* CPUID level 0x00000001.edx */
#define cpu_has_fpu             1
#define cpu_has_de              1
#define cpu_has_pse             1
#define cpu_has_apic            boot_cpu_has(X86_FEATURE_APIC)
#define cpu_has_sep             boot_cpu_has(X86_FEATURE_SEP)
#define cpu_has_mtrr            1
#define cpu_has_pge             1
#define cpu_has_pse36           boot_cpu_has(X86_FEATURE_PSE36)
#define cpu_has_clflush         boot_cpu_has(X86_FEATURE_CLFLUSH)
#define cpu_has_mmx             1
#define cpu_has_htt             boot_cpu_has(X86_FEATURE_HTT)

/* CPUID level 0x00000001.ecx */
#define cpu_has_sse3            boot_cpu_has(X86_FEATURE_SSE3)
#define cpu_has_pclmulqdq       boot_cpu_has(X86_FEATURE_PCLMULQDQ)
#define cpu_has_monitor         boot_cpu_has(X86_FEATURE_MONITOR)
#define cpu_has_vmx             boot_cpu_has(X86_FEATURE_VMX)
#define cpu_has_eist            boot_cpu_has(X86_FEATURE_EIST)
#define cpu_has_ssse3           boot_cpu_has(X86_FEATURE_SSSE3)
#define cpu_has_fma             boot_cpu_has(X86_FEATURE_FMA)
#define cpu_has_cx16            boot_cpu_has(X86_FEATURE_CX16)
#define cpu_has_pdcm            boot_cpu_has(X86_FEATURE_PDCM)
#define cpu_has_pcid            boot_cpu_has(X86_FEATURE_PCID)
#define cpu_has_sse4_1          boot_cpu_has(X86_FEATURE_SSE4_1)
#define cpu_has_sse4_2          boot_cpu_has(X86_FEATURE_SSE4_2)
#define cpu_has_x2apic          boot_cpu_has(X86_FEATURE_X2APIC)
#define cpu_has_popcnt          boot_cpu_has(X86_FEATURE_POPCNT)
#define cpu_has_aesni           boot_cpu_has(X86_FEATURE_AESNI)
#define cpu_has_xsave           boot_cpu_has(X86_FEATURE_XSAVE)
#define cpu_has_avx             boot_cpu_has(X86_FEATURE_AVX)
#define cpu_has_f16c            boot_cpu_has(X86_FEATURE_F16C)
#define cpu_has_rdrand          boot_cpu_has(X86_FEATURE_RDRAND)
#define cpu_has_hypervisor      boot_cpu_has(X86_FEATURE_HYPERVISOR)

/* CPUID level 0x80000001.edx */
#define cpu_has_nx              (IS_ENABLED(CONFIG_REQUIRE_NX) || \
                                 boot_cpu_has(X86_FEATURE_NX))
#define cpu_has_page1gb         boot_cpu_has(X86_FEATURE_PAGE1GB)
#define cpu_has_rdtscp          boot_cpu_has(X86_FEATURE_RDTSCP)
#define cpu_has_3dnow_ext       boot_cpu_has(X86_FEATURE_3DNOWEXT)
#define cpu_has_3dnow           boot_cpu_has(X86_FEATURE_3DNOW)

/* CPUID level 0x80000001.ecx */
#define cpu_has_cmp_legacy      boot_cpu_has(X86_FEATURE_CMP_LEGACY)
#define cpu_has_svm             boot_cpu_has(X86_FEATURE_SVM)
#define cpu_has_sse4a           boot_cpu_has(X86_FEATURE_SSE4A)
#define cpu_has_xop             boot_cpu_has(X86_FEATURE_XOP)
#define cpu_has_skinit          boot_cpu_has(X86_FEATURE_SKINIT)
#define cpu_has_fma4            boot_cpu_has(X86_FEATURE_FMA4)
#define cpu_has_tbm             boot_cpu_has(X86_FEATURE_TBM)

/* CPUID level 0x0000000D:1.eax */
#define cpu_has_xsaveopt        boot_cpu_has(X86_FEATURE_XSAVEOPT)
#define cpu_has_xsavec          boot_cpu_has(X86_FEATURE_XSAVEC)
#define cpu_has_xgetbv1         boot_cpu_has(X86_FEATURE_XGETBV1)
#define cpu_has_xsaves          boot_cpu_has(X86_FEATURE_XSAVES)

/* CPUID level 0x00000007:0.ebx */
#define cpu_has_bmi1            boot_cpu_has(X86_FEATURE_BMI1)
#define cpu_has_hle             boot_cpu_has(X86_FEATURE_HLE)
#define cpu_has_avx2            boot_cpu_has(X86_FEATURE_AVX2)
#define cpu_has_smep            boot_cpu_has(X86_FEATURE_SMEP)
#define cpu_has_bmi2            boot_cpu_has(X86_FEATURE_BMI2)
#define cpu_has_invpcid         boot_cpu_has(X86_FEATURE_INVPCID)
#define cpu_has_rtm             boot_cpu_has(X86_FEATURE_RTM)
#define cpu_has_pqe             boot_cpu_has(X86_FEATURE_PQE)
#define cpu_has_fpu_sel         (!boot_cpu_has(X86_FEATURE_NO_FPU_SEL))
#define cpu_has_mpx             boot_cpu_has(X86_FEATURE_MPX)
#define cpu_has_avx512f         boot_cpu_has(X86_FEATURE_AVX512F)
#define cpu_has_avx512dq        boot_cpu_has(X86_FEATURE_AVX512DQ)
#define cpu_has_rdseed          boot_cpu_has(X86_FEATURE_RDSEED)
#define cpu_has_smap            boot_cpu_has(X86_FEATURE_SMAP)
#define cpu_has_avx512_ifma     boot_cpu_has(X86_FEATURE_AVX512_IFMA)
#define cpu_has_clflushopt      boot_cpu_has(X86_FEATURE_CLFLUSHOPT)
#define cpu_has_clwb            boot_cpu_has(X86_FEATURE_CLWB)
#define cpu_has_avx512cd        boot_cpu_has(X86_FEATURE_AVX512CD)
#define cpu_has_proc_trace      boot_cpu_has(X86_FEATURE_PROC_TRACE)
#define cpu_has_sha             boot_cpu_has(X86_FEATURE_SHA)
#define cpu_has_avx512bw        boot_cpu_has(X86_FEATURE_AVX512BW)
#define cpu_has_avx512vl        boot_cpu_has(X86_FEATURE_AVX512VL)

/* CPUID level 0x00000007:0.ecx */
#define cpu_has_avx512_vbmi     boot_cpu_has(X86_FEATURE_AVX512_VBMI)
#define cpu_has_pku             boot_cpu_has(X86_FEATURE_PKU)
#define cpu_has_avx512_vbmi2    boot_cpu_has(X86_FEATURE_AVX512_VBMI2)
#define cpu_has_gfni            boot_cpu_has(X86_FEATURE_GFNI)
#define cpu_has_vaes            boot_cpu_has(X86_FEATURE_VAES)
#define cpu_has_vpclmulqdq      boot_cpu_has(X86_FEATURE_VPCLMULQDQ)
#define cpu_has_avx512_vnni     boot_cpu_has(X86_FEATURE_AVX512_VNNI)
#define cpu_has_avx512_bitalg   boot_cpu_has(X86_FEATURE_AVX512_BITALG)
#define cpu_has_avx512_vpopcntdq boot_cpu_has(X86_FEATURE_AVX512_VPOPCNTDQ)
#define cpu_has_rdpid           boot_cpu_has(X86_FEATURE_RDPID)
#define cpu_has_movdiri         boot_cpu_has(X86_FEATURE_MOVDIRI)
#define cpu_has_movdir64b       boot_cpu_has(X86_FEATURE_MOVDIR64B)
#define cpu_has_enqcmd          boot_cpu_has(X86_FEATURE_ENQCMD)
#define cpu_has_pks             boot_cpu_has(X86_FEATURE_PKS)

/* CPUID level 0x80000007.edx */
#define cpu_has_hw_pstate       boot_cpu_has(X86_FEATURE_HW_PSTATE)
#define cpu_has_itsc            boot_cpu_has(X86_FEATURE_ITSC)

/* CPUID level 0x80000008.ebx */
#define cpu_has_amd_ssbd        boot_cpu_has(X86_FEATURE_AMD_SSBD)
#define cpu_has_virt_ssbd       boot_cpu_has(X86_FEATURE_VIRT_SSBD)
#define cpu_has_ssb_no          boot_cpu_has(X86_FEATURE_SSB_NO)
#define cpu_has_auto_ibrs       boot_cpu_has(X86_FEATURE_AUTO_IBRS)

/* CPUID level 0x00000007:0.edx */
#define cpu_has_avx512_vp2intersect boot_cpu_has(X86_FEATURE_AVX512_VP2INTERSECT)
#define cpu_has_srbds_ctrl      boot_cpu_has(X86_FEATURE_SRBDS_CTRL)
#define cpu_has_md_clear        boot_cpu_has(X86_FEATURE_MD_CLEAR)
#define cpu_has_rtm_always_abort boot_cpu_has(X86_FEATURE_RTM_ALWAYS_ABORT)
#define cpu_has_tsx_force_abort boot_cpu_has(X86_FEATURE_TSX_FORCE_ABORT)
#define cpu_has_serialize       boot_cpu_has(X86_FEATURE_SERIALIZE)
#define cpu_has_hybrid          boot_cpu_has(X86_FEATURE_HYBRID)
#define cpu_has_avx512_fp16     boot_cpu_has(X86_FEATURE_AVX512_FP16)
#define cpu_has_arch_caps       boot_cpu_has(X86_FEATURE_ARCH_CAPS)

/* CPUID level 0x00000007:1.eax */
#define cpu_has_sha512          boot_cpu_has(X86_FEATURE_SHA512)
#define cpu_has_sm3             boot_cpu_has(X86_FEATURE_SM3)
#define cpu_has_sm4             boot_cpu_has(X86_FEATURE_SM4)
#define cpu_has_avx_vnni        boot_cpu_has(X86_FEATURE_AVX_VNNI)
#define cpu_has_avx512_bf16     boot_cpu_has(X86_FEATURE_AVX512_BF16)
#define cpu_has_cmpccxadd       boot_cpu_has(X86_FEATURE_CMPCCXADD)
#define cpu_has_avx_ifma        boot_cpu_has(X86_FEATURE_AVX_IFMA)

/* CPUID level 0x80000021.eax */
#define cpu_has_lfence_dispatch boot_cpu_has(X86_FEATURE_LFENCE_DISPATCH)
#define cpu_has_nscb            boot_cpu_has(X86_FEATURE_NSCB)

/* CPUID level 0x00000007:1.edx */
#define cpu_has_avx_vnni_int8   boot_cpu_has(X86_FEATURE_AVX_VNNI_INT8)
#define cpu_has_avx_ne_convert  boot_cpu_has(X86_FEATURE_AVX_NE_CONVERT)
#define cpu_has_avx_vnni_int16  boot_cpu_has(X86_FEATURE_AVX_VNNI_INT16)

/* MSR_ARCH_CAPS */
#define cpu_has_rdcl_no         boot_cpu_has(X86_FEATURE_RDCL_NO)
#define cpu_has_eibrs           boot_cpu_has(X86_FEATURE_EIBRS)
#define cpu_has_rsba            boot_cpu_has(X86_FEATURE_RSBA)
#define cpu_has_skip_l1dfl      boot_cpu_has(X86_FEATURE_SKIP_L1DFL)
#define cpu_has_mds_no          boot_cpu_has(X86_FEATURE_MDS_NO)
#define cpu_has_if_pschange_mc_no boot_cpu_has(X86_FEATURE_IF_PSCHANGE_MC_NO)
#define cpu_has_tsx_ctrl        boot_cpu_has(X86_FEATURE_TSX_CTRL)
#define cpu_has_taa_no          boot_cpu_has(X86_FEATURE_TAA_NO)
#define cpu_has_mcu_ctrl        boot_cpu_has(X86_FEATURE_MCU_CTRL)
#define cpu_has_doitm           boot_cpu_has(X86_FEATURE_DOITM)
#define cpu_has_fb_clear        boot_cpu_has(X86_FEATURE_FB_CLEAR)
#define cpu_has_rrsba           boot_cpu_has(X86_FEATURE_RRSBA)
#define cpu_has_gds_ctrl        boot_cpu_has(X86_FEATURE_GDS_CTRL)
#define cpu_has_gds_no          boot_cpu_has(X86_FEATURE_GDS_NO)
#define cpu_has_rfds_no         boot_cpu_has(X86_FEATURE_RFDS_NO)
#define cpu_has_rfds_clear      boot_cpu_has(X86_FEATURE_RFDS_CLEAR)

/* Synthesized. */
#define cpu_has_arch_perfmon    boot_cpu_has(X86_FEATURE_ARCH_PERFMON)
#define cpu_has_cpuid_faulting  boot_cpu_has(X86_FEATURE_CPUID_FAULTING)
#define cpu_has_aperfmperf      boot_cpu_has(X86_FEATURE_APERFMPERF)
#define cpu_has_xen_lbr         boot_cpu_has(X86_FEATURE_XEN_LBR)
#define cpu_has_xen_shstk       (IS_ENABLED(CONFIG_XEN_SHSTK) && \
                                 boot_cpu_has(X86_FEATURE_XEN_SHSTK))
#define cpu_has_xen_ibt         (IS_ENABLED(CONFIG_XEN_IBT) && \
                                 boot_cpu_has(X86_FEATURE_XEN_IBT))

#define cpu_has_msr_tsc_aux     (cpu_has_rdtscp || cpu_has_rdpid)

/* Bugs. */
#define cpu_bug_fpu_ptrs        boot_cpu_has(X86_BUG_FPU_PTRS)
#define cpu_bug_null_seg        boot_cpu_has(X86_BUG_NULL_SEG)

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
#endif /* !__ASSEMBLY__ */

#endif /* __ASM_I386_CPUFEATURE_H */

/* 
 * Local Variables:
 * mode:c
 * comment-column:42
 * End:
 */
