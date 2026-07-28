/*
 * cpufeature.h
 *
 * Defines x86 CPU feature bits
 */
#ifndef __ASM_I386_CPUFEATURE_H
#define __ASM_I386_CPUFEATURE_H

#include <xen/cache.h>
#include <xen/const.h>
#include <xen/macros.h>

#ifndef __ASSEMBLER__
#include <asm/cpu-policy.h>
#include <asm/cpuid.h>
#include <xen/lib/x86/cpu-policy.h>
#else
#include <asm/cpufeatureset.h>
#endif

#define cpufeat_word(idx)	((idx) / 32)
#define cpufeat_bit(idx)	((idx) % 32)
#define cpufeat_mask(idx)	(_AC(1, U) << cpufeat_bit(idx))

/* An alias of a feature we know is always going to be present. */
#define X86_FEATURE_ALWAYS      X86_FEATURE_LM

/*
 * Layout tied to cpuinfo_x86.vfm
 */
#define VFM_MODEL_MASK  0x000000ff
#define VFM_FAMILY_MASK 0x0000ff00
#define VFM_VENDOR_MASK 0x00ff0000

#define VFM_MAKE(v, f, m) (MASK_INSR(v, VFM_VENDOR_MASK) | \
                           MASK_INSR(f, VFM_FAMILY_MASK) | \
                           MASK_INSR(m, VFM_MODEL_MASK))

#define VFM_MODEL(vfm)  MASK_EXTR(vfm, VFM_MODEL_MASK)
#define VFM_FAMILY(vfm) MASK_EXTR(vfm, VFM_FAMILY_MASK)
#define VFM_VENDOR(vfm) MASK_EXTR(vfm, VFM_VENDOR_MASK)

#ifndef __ASSEMBLER__

struct cpuinfo_x86 {
    /* TODO: Phase out the x86 prefixed names. */
    union {
        struct {
            union {
                uint8_t x86_model;
                uint8_t model;
            };
            union {
                uint8_t x86;
                uint8_t family;
            };
            union {
                uint8_t x86_vendor;
                uint8_t vendor;
            };
            uint8_t _rsvd;             /* Use of this needs coordinating with VFM_MAKE() */
        };
        uint32_t vfm;                  /* Vendor Family Model */
    };
    union {
        uint8_t x86_mask;
        uint8_t stepping;
    };

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

#define CPU_DATA_INIT(what...)                     \
        what.cpuid_level = 1,                      \
        what.extended_cpuid_level = 0,             \
        what.x86_cache_size = -1,                  \
        what.x86_max_cores = 1,                    \
        what.x86_num_siblings = 1,                 \
        what.apicid = BAD_APICID,                  \
        what.phys_proc_id = XEN_INVALID_SOCKET_ID, \
        what.cpu_core_id = XEN_INVALID_CORE_ID,    \
        what.compute_unit_id = INVALID_CUID

/*
 * @keep_basic set to true retains data firmly assumed to be symmetric
 * across all CPUs.  Only CPU_DATA_INIT() will be invoked in that case
 * on the passed structure.
 */
void reset_cpuinfo(struct cpuinfo_x86 *c, bool keep_basic);

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

/* CPUID level 0x00000001.edx */
#define cpu_has_fpu             1
#define cpu_has_de              1
#define cpu_has_pse             1
#define cpu_has_apic            boot_cpu_has(X86_FEATURE_APIC)
#define cpu_has_sep             boot_cpu_has(X86_FEATURE_SEP)
#define cpu_has_mtrr            boot_cpu_has(X86_FEATURE_MTRR)
#define cpu_has_pge             1
#define cpu_has_pse36           boot_cpu_has(X86_FEATURE_PSE36)
#define cpu_has_clflush         boot_cpu_has(X86_FEATURE_CLFLUSH)
#define cpu_has_htt             boot_cpu_has(X86_FEATURE_HTT)

/* CPUID level 0x00000001.ecx */
#define cpu_has_monitor         boot_cpu_has(X86_FEATURE_MONITOR)
#define cpu_has_vmx             boot_cpu_has(X86_FEATURE_VMX)
#define cpu_has_eist            boot_cpu_has(X86_FEATURE_EIST)
#define cpu_has_cx16            boot_cpu_has(X86_FEATURE_CX16)
#define cpu_has_pdcm            boot_cpu_has(X86_FEATURE_PDCM)
#define cpu_has_pcid            boot_cpu_has(X86_FEATURE_PCID)
#define cpu_has_x2apic          boot_cpu_has(X86_FEATURE_X2APIC)
#define cpu_has_xsave           boot_cpu_has(X86_FEATURE_XSAVE)
#define cpu_has_avx             boot_cpu_has(X86_FEATURE_AVX)
#define cpu_has_rdrand          boot_cpu_has(X86_FEATURE_RDRAND)
#define cpu_has_hypervisor      boot_cpu_has(X86_FEATURE_HYPERVISOR)

/* CPUID level 0x80000001.edx */
#define cpu_has_nx              (IS_ENABLED(CONFIG_REQUIRE_NX) || \
                                 boot_cpu_has(X86_FEATURE_NX))
#define cpu_has_page1gb         boot_cpu_has(X86_FEATURE_PAGE1GB)
#define cpu_has_rdtscp          boot_cpu_has(X86_FEATURE_RDTSCP)

/* CPUID level 0x80000001.ecx */
#define cpu_has_cmp_legacy      boot_cpu_has(X86_FEATURE_CMP_LEGACY)
#define cpu_has_svm             boot_cpu_has(X86_FEATURE_SVM)
#define cpu_has_skinit          boot_cpu_has(X86_FEATURE_SKINIT)

/* CPUID level 0x00000006.eax */
#define cpu_has_turbo_boost     host_cpu_policy.basic.turbo_boost
#define cpu_has_arat            host_cpu_policy.basic.arat
#define cpu_has_hwp             host_cpu_policy.basic.hwp
#define cpu_has_hwp_interrupt   host_cpu_policy.basic.hwp_interrupt
#define cpu_has_hwp_activity_window host_cpu_policy.basic.hwp_activity_window
#define cpu_has_hwp_epp         host_cpu_policy.basic.hwp_epp
#define cpu_has_hwp_request_pkg host_cpu_policy.basic.hwp_request_pkg
#define cpu_has_hdc             host_cpu_policy.basic.hdc
#define cpu_has_hwp_peci_override host_cpu_policy.basic.hwp_peci_override
#define cpu_has_hw_feedback     host_cpu_policy.basic.hw_feedback

/* CPUID level 0x00000006.ecx */
#define cpu_has_hw_feedback_cap host_cpu_policy.basic.hw_feedback_cap

/* CPUID level 0x0000000D:1.eax */
#define cpu_has_xsaveopt        boot_cpu_has(X86_FEATURE_XSAVEOPT)
#define cpu_has_xsavec          boot_cpu_has(X86_FEATURE_XSAVEC)
#define cpu_has_xgetbv1         boot_cpu_has(X86_FEATURE_XGETBV1)
#define cpu_has_xsaves          boot_cpu_has(X86_FEATURE_XSAVES)

/* CPUID level 0x00000007:0.ebx */
#define cpu_has_hle             boot_cpu_has(X86_FEATURE_HLE)
#define cpu_has_smep            boot_cpu_has(X86_FEATURE_SMEP)
#define cpu_has_invpcid         boot_cpu_has(X86_FEATURE_INVPCID)
#define cpu_has_rtm             boot_cpu_has(X86_FEATURE_RTM)
#define cpu_has_pqe             boot_cpu_has(X86_FEATURE_PQE)
#define cpu_has_fpu_sel         (!boot_cpu_has(X86_FEATURE_NO_FPU_SEL))
#define cpu_has_mpx             boot_cpu_has(X86_FEATURE_MPX)
#define cpu_has_avx512f         boot_cpu_has(X86_FEATURE_AVX512F)
#define cpu_has_smap            boot_cpu_has(X86_FEATURE_SMAP)
#define cpu_has_clflushopt      boot_cpu_has(X86_FEATURE_CLFLUSHOPT)
#define cpu_has_clwb            boot_cpu_has(X86_FEATURE_CLWB)
#define cpu_has_proc_trace      boot_cpu_has(X86_FEATURE_PROC_TRACE)
#define cpu_has_avx512bw        boot_cpu_has(X86_FEATURE_AVX512BW)

/* CPUID level 0x00000007:0.ecx */
#define cpu_has_pku             boot_cpu_has(X86_FEATURE_PKU)
#define cpu_has_rdpid           boot_cpu_has(X86_FEATURE_RDPID)
#define cpu_has_pks             boot_cpu_has(X86_FEATURE_PKS)

/* CPUID level 0x80000007.edx */
#define cpu_has_hw_pstate       boot_cpu_has(X86_FEATURE_HW_PSTATE)
#define cpu_has_itsc            boot_cpu_has(X86_FEATURE_ITSC)

/* CPUID level 0x80000008.ebx */
#define cpu_has_amd_ssbd        boot_cpu_has(X86_FEATURE_AMD_SSBD)
#define cpu_has_virt_ssbd       boot_cpu_has(X86_FEATURE_VIRT_SSBD)
#define cpu_has_ssb_no          boot_cpu_has(X86_FEATURE_SSB_NO)
#define cpu_has_cppc            boot_cpu_has(X86_FEATURE_CPPC)
#define cpu_has_auto_ibrs       boot_cpu_has(X86_FEATURE_AUTO_IBRS)

/* CPUID level 0x00000007:0.edx */
#define cpu_has_srbds_ctrl      boot_cpu_has(X86_FEATURE_SRBDS_CTRL)
#define cpu_has_md_clear        boot_cpu_has(X86_FEATURE_MD_CLEAR)
#define cpu_has_rtm_always_abort boot_cpu_has(X86_FEATURE_RTM_ALWAYS_ABORT)
#define cpu_has_tsx_force_abort boot_cpu_has(X86_FEATURE_TSX_FORCE_ABORT)
#define cpu_has_hybrid          boot_cpu_has(X86_FEATURE_HYBRID)
#define cpu_has_arch_caps       boot_cpu_has(X86_FEATURE_ARCH_CAPS)

/* CPUID level 0x00000007:1.eax */
#define cpu_has_fred            boot_cpu_has(X86_FEATURE_FRED)
#define cpu_has_lkgs            boot_cpu_has(X86_FEATURE_LKGS)
#define cpu_has_nmi_src         boot_cpu_has(X86_FEATURE_NMI_SRC)

/* CPUID level 0x80000021.eax */
#define cpu_has_lfence_dispatch boot_cpu_has(X86_FEATURE_LFENCE_DISPATCH)
#define cpu_has_verw_clear      boot_cpu_has(X86_FEATURE_VERW_CLEAR)
#define cpu_has_nscb            boot_cpu_has(X86_FEATURE_NSCB)

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
#define cpu_has_pb_opt_ctrl     boot_cpu_has(X86_FEATURE_PB_OPT_CTRL)
#define cpu_has_its_no          boot_cpu_has(X86_FEATURE_ITS_NO)

/* CPUID level 0x80000021.ecx */
#define cpu_has_tsa_sq_no       boot_cpu_has(X86_FEATURE_TSA_SQ_NO)
#define cpu_has_tsa_l1_no       boot_cpu_has(X86_FEATURE_TSA_L1_NO)

/* Synthesized. */
#define cpu_has_arch_perfmon    boot_cpu_has(X86_FEATURE_ARCH_PERFMON)
#define cpu_has_cpuid_faulting  boot_cpu_has(X86_FEATURE_CPUID_FAULTING)
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
#endif /* !__ASSEMBLER__ */

#endif /* __ASM_I386_CPUFEATURE_H */

/* 
 * Local Variables:
 * mode:c
 * comment-column:42
 * End:
 */
