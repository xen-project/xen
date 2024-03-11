#ifndef __ASM_ARM_ARM64_SYSREGS_H
#define __ASM_ARM_ARM64_SYSREGS_H

#include <xen/stringify.h>

/*
 * GIC System register assembly aliases picked from kernel
 */
#define ICC_PMR_EL1               S3_0_C4_C6_0
#define ICC_DIR_EL1               S3_0_C12_C11_1
#define ICC_SGI1R_EL1             S3_0_C12_C11_5
#define ICC_EOIR1_EL1             S3_0_C12_C12_1
#define ICC_IAR1_EL1              S3_0_C12_C12_0
#define ICC_BPR1_EL1              S3_0_C12_C12_3
#define ICC_CTLR_EL1              S3_0_C12_C12_4
#define ICC_SRE_EL1               S3_0_C12_C12_5
#define ICC_IGRPEN1_EL1           S3_0_C12_C12_7

#define ICH_VSEIR_EL2             S3_4_C12_C9_4
#define ICC_SRE_EL2               S3_4_C12_C9_5
#define ICH_HCR_EL2               S3_4_C12_C11_0
#define ICH_VTR_EL2               S3_4_C12_C11_1
#define ICH_MISR_EL2              S3_4_C12_C11_2
#define ICH_EISR_EL2              S3_4_C12_C11_3
#define ICH_ELSR_EL2              S3_4_C12_C11_5
#define ICH_VMCR_EL2              S3_4_C12_C11_7
#define ZCR_EL2                   S3_4_C1_C2_0

#define __LR0_EL2(x)              S3_4_C12_C12_ ## x
#define __LR8_EL2(x)              S3_4_C12_C13_ ## x

#define ICH_LR0_EL2               __LR0_EL2(0)
#define ICH_LR1_EL2               __LR0_EL2(1)
#define ICH_LR2_EL2               __LR0_EL2(2)
#define ICH_LR3_EL2               __LR0_EL2(3)
#define ICH_LR4_EL2               __LR0_EL2(4)
#define ICH_LR5_EL2               __LR0_EL2(5)
#define ICH_LR6_EL2               __LR0_EL2(6)
#define ICH_LR7_EL2               __LR0_EL2(7)
#define ICH_LR8_EL2               __LR8_EL2(0)
#define ICH_LR9_EL2               __LR8_EL2(1)
#define ICH_LR10_EL2              __LR8_EL2(2)
#define ICH_LR11_EL2              __LR8_EL2(3)
#define ICH_LR12_EL2              __LR8_EL2(4)
#define ICH_LR13_EL2              __LR8_EL2(5)
#define ICH_LR14_EL2              __LR8_EL2(6)
#define ICH_LR15_EL2              __LR8_EL2(7)

#define __AP0Rx_EL2(x)            S3_4_C12_C8_ ## x
#define ICH_AP0R0_EL2             __AP0Rx_EL2(0)
#define ICH_AP0R1_EL2             __AP0Rx_EL2(1)
#define ICH_AP0R2_EL2             __AP0Rx_EL2(2)
#define ICH_AP0R3_EL2             __AP0Rx_EL2(3)

#define __AP1Rx_EL2(x)            S3_4_C12_C9_ ## x
#define ICH_AP1R0_EL2             __AP1Rx_EL2(0)
#define ICH_AP1R1_EL2             __AP1Rx_EL2(1)
#define ICH_AP1R2_EL2             __AP1Rx_EL2(2)
#define ICH_AP1R3_EL2             __AP1Rx_EL2(3)

/*
 * Define ID coprocessor registers if they are not
 * already defined by the compiler.
 *
 * Values picked from linux kernel
 */
#ifndef ID_AA64MMFR2_EL1
#define ID_AA64MMFR2_EL1            S3_0_C0_C7_2
#endif
#ifndef ID_PFR2_EL1
#define ID_PFR2_EL1                 S3_0_C0_C3_4
#endif
#ifndef ID_MMFR4_EL1
#define ID_MMFR4_EL1                S3_0_C0_C2_6
#endif
#ifndef ID_MMFR5_EL1
#define ID_MMFR5_EL1                S3_0_C0_C3_6
#endif
#ifndef ID_ISAR6_EL1
#define ID_ISAR6_EL1                S3_0_C0_C2_7
#endif
#ifndef ID_AA64ZFR0_EL1
#define ID_AA64ZFR0_EL1             S3_0_C0_C4_4
#endif
#ifndef ID_DFR1_EL1
#define ID_DFR1_EL1                 S3_0_C0_C3_5
#endif
#ifndef ID_AA64ISAR2_EL1
#define ID_AA64ISAR2_EL1            S3_0_C0_C6_2
#endif
#ifndef ZCR_EL1
#define ZCR_EL1                     S3_0_C1_C2_0
#endif

/* ID registers (imported from arm64/include/asm/sysreg.h in Linux) */

/* id_aa64isar0 */
#define ID_AA64ISAR0_RNDR_SHIFT      60
#define ID_AA64ISAR0_TLB_SHIFT       56
#define ID_AA64ISAR0_TS_SHIFT        52
#define ID_AA64ISAR0_FHM_SHIFT       48
#define ID_AA64ISAR0_DP_SHIFT        44
#define ID_AA64ISAR0_SM4_SHIFT       40
#define ID_AA64ISAR0_SM3_SHIFT       36
#define ID_AA64ISAR0_SHA3_SHIFT      32
#define ID_AA64ISAR0_RDM_SHIFT       28
#define ID_AA64ISAR0_ATOMICS_SHIFT   20
#define ID_AA64ISAR0_CRC32_SHIFT     16
#define ID_AA64ISAR0_SHA2_SHIFT      12
#define ID_AA64ISAR0_SHA1_SHIFT      8
#define ID_AA64ISAR0_AES_SHIFT       4

#define ID_AA64ISAR0_TLB_RANGE_NI    0x0
#define ID_AA64ISAR0_TLB_RANGE       0x2

/* id_aa64isar1 */
#define ID_AA64ISAR1_I8MM_SHIFT      52
#define ID_AA64ISAR1_DGH_SHIFT       48
#define ID_AA64ISAR1_BF16_SHIFT      44
#define ID_AA64ISAR1_SPECRES_SHIFT   40
#define ID_AA64ISAR1_SB_SHIFT        36
#define ID_AA64ISAR1_FRINTTS_SHIFT   32
#define ID_AA64ISAR1_GPI_SHIFT       28
#define ID_AA64ISAR1_GPA_SHIFT       24
#define ID_AA64ISAR1_LRCPC_SHIFT     20
#define ID_AA64ISAR1_FCMA_SHIFT      16
#define ID_AA64ISAR1_JSCVT_SHIFT     12
#define ID_AA64ISAR1_API_SHIFT       8
#define ID_AA64ISAR1_APA_SHIFT       4
#define ID_AA64ISAR1_DPB_SHIFT       0

#define ID_AA64ISAR1_APA_NI                     0x0
#define ID_AA64ISAR1_APA_ARCHITECTED            0x1
#define ID_AA64ISAR1_APA_ARCH_EPAC              0x2
#define ID_AA64ISAR1_APA_ARCH_EPAC2             0x3
#define ID_AA64ISAR1_APA_ARCH_EPAC2_FPAC        0x4
#define ID_AA64ISAR1_APA_ARCH_EPAC2_FPAC_CMB    0x5
#define ID_AA64ISAR1_API_NI                     0x0
#define ID_AA64ISAR1_API_IMP_DEF                0x1
#define ID_AA64ISAR1_API_IMP_DEF_EPAC           0x2
#define ID_AA64ISAR1_API_IMP_DEF_EPAC2          0x3
#define ID_AA64ISAR1_API_IMP_DEF_EPAC2_FPAC     0x4
#define ID_AA64ISAR1_API_IMP_DEF_EPAC2_FPAC_CMB 0x5
#define ID_AA64ISAR1_GPA_NI                     0x0
#define ID_AA64ISAR1_GPA_ARCHITECTED            0x1
#define ID_AA64ISAR1_GPI_NI                     0x0
#define ID_AA64ISAR1_GPI_IMP_DEF                0x1

/* id_aa64isar2 */
#define ID_AA64ISAR2_CLEARBHB_SHIFT 28
#define ID_AA64ISAR2_APA3_SHIFT     12
#define ID_AA64ISAR2_GPA3_SHIFT     8
#define ID_AA64ISAR2_RPRES_SHIFT    4
#define ID_AA64ISAR2_WFXT_SHIFT     0

#define ID_AA64ISAR2_RPRES_8BIT     0x0
#define ID_AA64ISAR2_RPRES_12BIT    0x1
/*
 * Value 0x1 has been removed from the architecture, and is
 * reserved, but has not yet been removed from the ARM ARM
 * as of ARM DDI 0487G.b.
 */
#define ID_AA64ISAR2_WFXT_NI        0x0
#define ID_AA64ISAR2_WFXT_SUPPORTED 0x2

#define ID_AA64ISAR2_APA3_NI                  0x0
#define ID_AA64ISAR2_APA3_ARCHITECTED         0x1
#define ID_AA64ISAR2_APA3_ARCH_EPAC           0x2
#define ID_AA64ISAR2_APA3_ARCH_EPAC2          0x3
#define ID_AA64ISAR2_APA3_ARCH_EPAC2_FPAC     0x4
#define ID_AA64ISAR2_APA3_ARCH_EPAC2_FPAC_CMB 0x5

#define ID_AA64ISAR2_GPA3_NI             0x0
#define ID_AA64ISAR2_GPA3_ARCHITECTED    0x1

/* id_aa64pfr0 */
#define ID_AA64PFR0_CSV3_SHIFT       60
#define ID_AA64PFR0_CSV2_SHIFT       56
#define ID_AA64PFR0_DIT_SHIFT        48
#define ID_AA64PFR0_AMU_SHIFT        44
#define ID_AA64PFR0_MPAM_SHIFT       40
#define ID_AA64PFR0_SEL2_SHIFT       36
#define ID_AA64PFR0_SVE_SHIFT        32
#define ID_AA64PFR0_RAS_SHIFT        28
#define ID_AA64PFR0_GIC_SHIFT        24
#define ID_AA64PFR0_ASIMD_SHIFT      20
#define ID_AA64PFR0_FP_SHIFT         16
#define ID_AA64PFR0_EL3_SHIFT        12
#define ID_AA64PFR0_EL2_SHIFT        8
#define ID_AA64PFR0_EL1_SHIFT        4
#define ID_AA64PFR0_EL0_SHIFT        0

#define ID_AA64PFR0_AMU              0x1
#define ID_AA64PFR0_SVE              0x1
#define ID_AA64PFR0_RAS_V1           0x1
#define ID_AA64PFR0_RAS_V1P1         0x2
#define ID_AA64PFR0_FP_NI            0xf
#define ID_AA64PFR0_FP_SUPPORTED     0x0
#define ID_AA64PFR0_ASIMD_NI         0xf
#define ID_AA64PFR0_ASIMD_SUPPORTED  0x0
#define ID_AA64PFR0_ELx_64BIT_ONLY   0x1
#define ID_AA64PFR0_ELx_32BIT_64BIT  0x2

/* id_aa64pfr1 */
#define ID_AA64PFR1_MPAMFRAC_SHIFT   16
#define ID_AA64PFR1_RASFRAC_SHIFT    12
#define ID_AA64PFR1_MTE_SHIFT        8
#define ID_AA64PFR1_SSBS_SHIFT       4
#define ID_AA64PFR1_BT_SHIFT         0

#define ID_AA64PFR1_SSBS_PSTATE_NI    0
#define ID_AA64PFR1_SSBS_PSTATE_ONLY  1
#define ID_AA64PFR1_SSBS_PSTATE_INSNS 2
#define ID_AA64PFR1_BT_BTI            0x1

#define ID_AA64PFR1_MTE_NI           0x0
#define ID_AA64PFR1_MTE_EL0          0x1
#define ID_AA64PFR1_MTE              0x2
#define ID_AA64PFR1_MTE_ASYMM        0x3

/* id_aa64zfr0 */
#define ID_AA64ZFR0_F64MM_SHIFT      56
#define ID_AA64ZFR0_F32MM_SHIFT      52
#define ID_AA64ZFR0_I8MM_SHIFT       44
#define ID_AA64ZFR0_SM4_SHIFT        40
#define ID_AA64ZFR0_SHA3_SHIFT       32
#define ID_AA64ZFR0_BF16_SHIFT       20
#define ID_AA64ZFR0_BITPERM_SHIFT    16
#define ID_AA64ZFR0_AES_SHIFT        4
#define ID_AA64ZFR0_SVEVER_SHIFT     0

#define ID_AA64ZFR0_F64MM            0x1
#define ID_AA64ZFR0_F32MM            0x1
#define ID_AA64ZFR0_I8MM             0x1
#define ID_AA64ZFR0_BF16             0x1
#define ID_AA64ZFR0_SM4              0x1
#define ID_AA64ZFR0_SHA3             0x1
#define ID_AA64ZFR0_BITPERM          0x1
#define ID_AA64ZFR0_AES              0x1
#define ID_AA64ZFR0_AES_PMULL        0x2
#define ID_AA64ZFR0_SVEVER_SVE2      0x1

/* id_aa64mmfr0 */
#define ID_AA64MMFR0_ECV_SHIFT       60
#define ID_AA64MMFR0_FGT_SHIFT       56
#define ID_AA64MMFR0_EXS_SHIFT       44
#define ID_AA64MMFR0_TGRAN4_2_SHIFT  40
#define ID_AA64MMFR0_TGRAN64_2_SHIFT 36
#define ID_AA64MMFR0_TGRAN16_2_SHIFT 32
#define ID_AA64MMFR0_TGRAN4_SHIFT    28
#define ID_AA64MMFR0_TGRAN64_SHIFT   24
#define ID_AA64MMFR0_TGRAN16_SHIFT   20
#define ID_AA64MMFR0_BIGENDEL0_SHIFT 16
#define ID_AA64MMFR0_SNSMEM_SHIFT    12
#define ID_AA64MMFR0_BIGENDEL_SHIFT  8
#define ID_AA64MMFR0_ASID_SHIFT      4
#define ID_AA64MMFR0_PARANGE_SHIFT   0

#define ID_AA64MMFR0_ASID_8          0x0
#define ID_AA64MMFR0_ASID_16         0x2

#define ID_AA64MMFR0_TGRAN4_NI             0xf
#define ID_AA64MMFR0_TGRAN4_SUPPORTED_MIN  0x0
#define ID_AA64MMFR0_TGRAN4_SUPPORTED_MAX  0x7
#define ID_AA64MMFR0_TGRAN64_NI            0xf
#define ID_AA64MMFR0_TGRAN64_SUPPORTED_MIN 0x0
#define ID_AA64MMFR0_TGRAN64_SUPPORTED_MAX 0x7
#define ID_AA64MMFR0_TGRAN16_NI            0x0
#define ID_AA64MMFR0_TGRAN16_SUPPORTED_MIN 0x1
#define ID_AA64MMFR0_TGRAN16_SUPPORTED_MAX 0xf

#define ID_AA64MMFR0_PARANGE_32        0x0
#define ID_AA64MMFR0_PARANGE_36        0x1
#define ID_AA64MMFR0_PARANGE_40        0x2
#define ID_AA64MMFR0_PARANGE_42        0x3
#define ID_AA64MMFR0_PARANGE_44        0x4
#define ID_AA64MMFR0_PARANGE_48        0x5
#define ID_AA64MMFR0_PARANGE_52        0x6

#define ARM64_MIN_PARANGE_BITS     32

#define ID_AA64MMFR0_TGRAN_2_SUPPORTED_DEFAULT 0x0
#define ID_AA64MMFR0_TGRAN_2_SUPPORTED_NONE    0x1
#define ID_AA64MMFR0_TGRAN_2_SUPPORTED_MIN     0x2
#define ID_AA64MMFR0_TGRAN_2_SUPPORTED_MAX     0x7

/* id_aa64mmfr1 */
#define ID_AA64MMFR1_ECBHB_SHIFT     60
#define ID_AA64MMFR1_AFP_SHIFT       44
#define ID_AA64MMFR1_ETS_SHIFT       36
#define ID_AA64MMFR1_TWED_SHIFT      32
#define ID_AA64MMFR1_XNX_SHIFT       28
#define ID_AA64MMFR1_SPECSEI_SHIFT   24
#define ID_AA64MMFR1_PAN_SHIFT       20
#define ID_AA64MMFR1_LOR_SHIFT       16
#define ID_AA64MMFR1_HPD_SHIFT       12
#define ID_AA64MMFR1_VHE_SHIFT       8
#define ID_AA64MMFR1_VMIDBITS_SHIFT  4
#define ID_AA64MMFR1_HADBS_SHIFT     0

#define ID_AA64MMFR1_VMIDBITS_8      0
#define ID_AA64MMFR1_VMIDBITS_16     2

/* id_aa64mmfr2 */
#define ID_AA64MMFR2_E0PD_SHIFT      60
#define ID_AA64MMFR2_EVT_SHIFT       56
#define ID_AA64MMFR2_BBM_SHIFT       52
#define ID_AA64MMFR2_TTL_SHIFT       48
#define ID_AA64MMFR2_FWB_SHIFT       40
#define ID_AA64MMFR2_IDS_SHIFT       36
#define ID_AA64MMFR2_AT_SHIFT        32
#define ID_AA64MMFR2_ST_SHIFT        28
#define ID_AA64MMFR2_NV_SHIFT        24
#define ID_AA64MMFR2_CCIDX_SHIFT     20
#define ID_AA64MMFR2_LVA_SHIFT       16
#define ID_AA64MMFR2_IESB_SHIFT      12
#define ID_AA64MMFR2_LSM_SHIFT       8
#define ID_AA64MMFR2_UAO_SHIFT       4
#define ID_AA64MMFR2_CNP_SHIFT       0

/* id_aa64dfr0 */
#define ID_AA64DFR0_MTPMU_SHIFT      48
#define ID_AA64DFR0_TRBE_SHIFT       44
#define ID_AA64DFR0_TRACE_FILT_SHIFT 40
#define ID_AA64DFR0_DOUBLELOCK_SHIFT 36
#define ID_AA64DFR0_PMSVER_SHIFT     32
#define ID_AA64DFR0_CTX_CMPS_SHIFT   28
#define ID_AA64DFR0_WRPS_SHIFT       20
#define ID_AA64DFR0_BRPS_SHIFT       12
#define ID_AA64DFR0_PMUVER_SHIFT     8
#define ID_AA64DFR0_TRACEVER_SHIFT   4
#define ID_AA64DFR0_DEBUGVER_SHIFT   0

#define ID_AA64DFR0_PMUVER_8_0       0x1
#define ID_AA64DFR0_PMUVER_8_1       0x4
#define ID_AA64DFR0_PMUVER_8_4       0x5
#define ID_AA64DFR0_PMUVER_8_5       0x6
#define ID_AA64DFR0_PMUVER_8_7       0x7
#define ID_AA64DFR0_PMUVER_IMP_DEF   0xf

#define ID_AA64DFR0_PMSVER_8_2      0x1
#define ID_AA64DFR0_PMSVER_8_3      0x2

#define ID_DFR0_PERFMON_SHIFT        24

#define ID_DFR0_PERFMON_8_0         0x3
#define ID_DFR0_PERFMON_8_1         0x4
#define ID_DFR0_PERFMON_8_4         0x5
#define ID_DFR0_PERFMON_8_5         0x6

#define ID_ISAR4_SWP_FRAC_SHIFT        28
#define ID_ISAR4_PSR_M_SHIFT           24
#define ID_ISAR4_SYNCH_PRIM_FRAC_SHIFT 20
#define ID_ISAR4_BARRIER_SHIFT         16
#define ID_ISAR4_SMC_SHIFT             12
#define ID_ISAR4_WRITEBACK_SHIFT       8
#define ID_ISAR4_WITHSHIFTS_SHIFT      4
#define ID_ISAR4_UNPRIV_SHIFT          0

#define ID_DFR1_MTPMU_SHIFT          0

#define ID_ISAR0_DIVIDE_SHIFT        24
#define ID_ISAR0_DEBUG_SHIFT         20
#define ID_ISAR0_COPROC_SHIFT        16
#define ID_ISAR0_CMPBRANCH_SHIFT     12
#define ID_ISAR0_BITFIELD_SHIFT      8
#define ID_ISAR0_BITCOUNT_SHIFT      4
#define ID_ISAR0_SWAP_SHIFT          0

#define ID_ISAR5_RDM_SHIFT           24
#define ID_ISAR5_CRC32_SHIFT         16
#define ID_ISAR5_SHA2_SHIFT          12
#define ID_ISAR5_SHA1_SHIFT          8
#define ID_ISAR5_AES_SHIFT           4
#define ID_ISAR5_SEVL_SHIFT          0

#define ID_ISAR6_I8MM_SHIFT          24
#define ID_ISAR6_BF16_SHIFT          20
#define ID_ISAR6_SPECRES_SHIFT       16
#define ID_ISAR6_SB_SHIFT            12
#define ID_ISAR6_FHM_SHIFT           8
#define ID_ISAR6_DP_SHIFT            4
#define ID_ISAR6_JSCVT_SHIFT         0

#define ID_MMFR0_INNERSHR_SHIFT      28
#define ID_MMFR0_FCSE_SHIFT          24
#define ID_MMFR0_AUXREG_SHIFT        20
#define ID_MMFR0_TCM_SHIFT           16
#define ID_MMFR0_SHARELVL_SHIFT      12
#define ID_MMFR0_OUTERSHR_SHIFT      8
#define ID_MMFR0_PMSA_SHIFT          4
#define ID_MMFR0_VMSA_SHIFT          0

#define ID_MMFR4_EVT_SHIFT           28
#define ID_MMFR4_CCIDX_SHIFT         24
#define ID_MMFR4_LSM_SHIFT           20
#define ID_MMFR4_HPDS_SHIFT          16
#define ID_MMFR4_CNP_SHIFT           12
#define ID_MMFR4_XNX_SHIFT           8
#define ID_MMFR4_AC2_SHIFT           4
#define ID_MMFR4_SPECSEI_SHIFT       0

#define ID_MMFR5_ETS_SHIFT           0

#define ID_PFR0_DIT_SHIFT            24
#define ID_PFR0_CSV2_SHIFT           16
#define ID_PFR0_STATE3_SHIFT         12
#define ID_PFR0_STATE2_SHIFT         8
#define ID_PFR0_STATE1_SHIFT         4
#define ID_PFR0_STATE0_SHIFT         0

#define ID_DFR0_PERFMON_SHIFT        24
#define ID_DFR0_MPROFDBG_SHIFT       20
#define ID_DFR0_MMAPTRC_SHIFT        16
#define ID_DFR0_COPTRC_SHIFT         12
#define ID_DFR0_MMAPDBG_SHIFT        8
#define ID_DFR0_COPSDBG_SHIFT        4
#define ID_DFR0_COPDBG_SHIFT         0

#define ID_PFR2_SSBS_SHIFT           4
#define ID_PFR2_CSV3_SHIFT           0

#define MVFR0_FPROUND_SHIFT          28
#define MVFR0_FPSHVEC_SHIFT          24
#define MVFR0_FPSQRT_SHIFT           20
#define MVFR0_FPDIVIDE_SHIFT         16
#define MVFR0_FPTRAP_SHIFT           12
#define MVFR0_FPDP_SHIFT             8
#define MVFR0_FPSP_SHIFT             4
#define MVFR0_SIMD_SHIFT             0

#define MVFR1_SIMDFMAC_SHIFT         28
#define MVFR1_FPHP_SHIFT             24
#define MVFR1_SIMDHP_SHIFT           20
#define MVFR1_SIMDSP_SHIFT           16
#define MVFR1_SIMDINT_SHIFT          12
#define MVFR1_SIMDLS_SHIFT           8
#define MVFR1_FPDNAN_SHIFT           4
#define MVFR1_FPFTZ_SHIFT            0

#define ID_PFR1_GIC_SHIFT            28
#define ID_PFR1_VIRT_FRAC_SHIFT      24
#define ID_PFR1_SEC_FRAC_SHIFT       20
#define ID_PFR1_GENTIMER_SHIFT       16
#define ID_PFR1_VIRTUALIZATION_SHIFT 12
#define ID_PFR1_MPROGMOD_SHIFT       8
#define ID_PFR1_SECURITY_SHIFT       4
#define ID_PFR1_PROGMOD_SHIFT        0

#define MVFR2_FPMISC_SHIFT           4
#define MVFR2_SIMDMISC_SHIFT         0

#define DCZID_DZP_SHIFT              4
#define DCZID_BS_SHIFT               0

/*
 * The ZCR_ELx_LEN_* definitions intentionally include bits [8:4] which
 * are reserved by the SVE architecture for future expansion of the LEN
 * field, with compatible semantics.
 */
#define ZCR_ELx_LEN_SHIFT            0
#define ZCR_ELx_LEN_SIZE             9
#define ZCR_ELx_LEN_MASK             0x1ff

/* Access to system registers */

#define WRITE_SYSREG64(v, name) do {                    \
    uint64_t _r = (v);                                  \
    asm volatile("msr "__stringify(name)", %0" : : "r" (_r));       \
} while (0)
#define READ_SYSREG64(name) ({                          \
    uint64_t _r;                                        \
    asm volatile("mrs  %0, "__stringify(name) : "=r" (_r));         \
    _r; })

#define READ_SYSREG(name)     READ_SYSREG64(name)
#define WRITE_SYSREG(v, name) WRITE_SYSREG64(v, name)

/* Wrappers for accessing interrupt controller list registers. */
#define ICH_LR_REG(index)          ICH_LR ## index ## _EL2
#define WRITE_SYSREG_LR(v, index)  WRITE_SYSREG(v, ICH_LR_REG(index))
#define READ_SYSREG_LR(index)      READ_SYSREG(ICH_LR_REG(index))

#endif /* _ASM_ARM_ARM64_SYSREGS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
