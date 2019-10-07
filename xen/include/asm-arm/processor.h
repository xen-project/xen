#ifndef __ASM_ARM_PROCESSOR_H
#define __ASM_ARM_PROCESSOR_H

#ifndef __ASSEMBLY__
#include <xen/types.h>
#endif
#include <public/arch-arm.h>

/* CTR Cache Type Register */
#define CTR_L1Ip_MASK       0x3
#define CTR_L1Ip_SHIFT      14
#define CTR_L1Ip_AIVIVT     0x1

/* MIDR Main ID Register */
#define MIDR_REVISION_MASK      0xf
#define MIDR_RESIVION(midr)     ((midr) & MIDR_REVISION_MASK)
#define MIDR_PARTNUM_SHIFT      4
#define MIDR_PARTNUM_MASK       (0xfff << MIDR_PARTNUM_SHIFT)
#define MIDR_PARTNUM(midr) \
    (((midr) & MIDR_PARTNUM_MASK) >> MIDR_PARTNUM_SHIFT)
#define MIDR_ARCHITECTURE_SHIFT 16
#define MIDR_ARCHITECTURE_MASK  (0xf << MIDR_ARCHITECTURE_SHIFT)
#define MIDR_ARCHITECTURE(midr) \
    (((midr) & MIDR_ARCHITECTURE_MASK) >> MIDR_ARCHITECTURE_SHIFT)
#define MIDR_VARIANT_SHIFT      20
#define MIDR_VARIANT_MASK       (0xf << MIDR_VARIANT_SHIFT)
#define MIDR_VARIANT(midr) \
    (((midr) & MIDR_VARIANT_MASK) >> MIDR_VARIANT_SHIFT)
#define MIDR_IMPLEMENTOR_SHIFT  24
#define MIDR_IMPLEMENTOR_MASK   (0xff << MIDR_IMPLEMENTOR_SHIFT)
#define MIDR_IMPLEMENTOR(midr) \
    (((midr) & MIDR_IMPLEMENTOR_MASK) >> MIDR_IMPLEMENTOR_SHIFT)

#define MIDR_CPU_MODEL(imp, partnum)            \
    (((imp)     << MIDR_IMPLEMENTOR_SHIFT) |    \
     (0xf       << MIDR_ARCHITECTURE_SHIFT) |   \
     ((partnum) << MIDR_PARTNUM_SHIFT))

#define MIDR_CPU_MODEL_MASK \
     (MIDR_IMPLEMENTOR_MASK | MIDR_PARTNUM_MASK | MIDR_ARCHITECTURE_MASK)

#define MIDR_IS_CPU_MODEL_RANGE(midr, model, rv_min, rv_max)            \
({                                                                      \
        u32 _model = (midr) & MIDR_CPU_MODEL_MASK;                      \
        u32 _rv = (midr) & (MIDR_REVISION_MASK | MIDR_VARIANT_MASK);    \
                                                                        \
        _model == (model) && _rv >= (rv_min) && _rv <= (rv_max);        \
})

#define ARM_CPU_IMP_ARM             0x41

#define ARM_CPU_PART_CORTEX_A12     0xC0D
#define ARM_CPU_PART_CORTEX_A17     0xC0E
#define ARM_CPU_PART_CORTEX_A15     0xC0F
#define ARM_CPU_PART_CORTEX_A53     0xD03
#define ARM_CPU_PART_CORTEX_A57     0xD07
#define ARM_CPU_PART_CORTEX_A72     0xD08
#define ARM_CPU_PART_CORTEX_A73     0xD09
#define ARM_CPU_PART_CORTEX_A75     0xD0A
#define ARM_CPU_PART_CORTEX_A76     0xD0B

#define MIDR_CORTEX_A12 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A12)
#define MIDR_CORTEX_A17 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A17)
#define MIDR_CORTEX_A15 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A15)
#define MIDR_CORTEX_A53 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A53)
#define MIDR_CORTEX_A57 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A57)
#define MIDR_CORTEX_A72 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A72)
#define MIDR_CORTEX_A73 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A73)
#define MIDR_CORTEX_A75 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A75)
#define MIDR_CORTEX_A76 MIDR_CPU_MODEL(ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A76)

/* MPIDR Multiprocessor Affinity Register */
#define _MPIDR_UP           (30)
#define MPIDR_UP            (_AC(1,U) << _MPIDR_UP)
#define _MPIDR_SMP          (31)
#define MPIDR_SMP           (_AC(1,U) << _MPIDR_SMP)
#define MPIDR_AFF0_SHIFT    (0)
#define MPIDR_AFF0_MASK     (_AC(0xff,U) << MPIDR_AFF0_SHIFT)
#ifdef CONFIG_ARM_64
#define MPIDR_HWID_MASK     _AC(0xff00ffffff,UL)
#else
#define MPIDR_HWID_MASK     _AC(0xffffff,U)
#endif
#define MPIDR_INVALID       (~MPIDR_HWID_MASK)
#define MPIDR_LEVEL_BITS    (8)


/*
 * Macros to extract affinity level. picked from kernel
 */

#define MPIDR_LEVEL_BITS_SHIFT  3
#define MPIDR_LEVEL_MASK        ((1 << MPIDR_LEVEL_BITS) - 1)

#define MPIDR_LEVEL_SHIFT(level) \
         (((1 << level) >> 1) << MPIDR_LEVEL_BITS_SHIFT)

#define MPIDR_AFFINITY_LEVEL(mpidr, level) \
         ((mpidr >> MPIDR_LEVEL_SHIFT(level)) & MPIDR_LEVEL_MASK)

#define AFFINITY_MASK(level)    ~((_AC(0x1,UL) << MPIDR_LEVEL_SHIFT(level)) - 1)

/* TTBCR Translation Table Base Control Register */
#define TTBCR_EAE    _AC(0x80000000,U)
#define TTBCR_N_MASK _AC(0x07,U)
#define TTBCR_N_16KB _AC(0x00,U)
#define TTBCR_N_8KB  _AC(0x01,U)
#define TTBCR_N_4KB  _AC(0x02,U)
#define TTBCR_N_2KB  _AC(0x03,U)
#define TTBCR_N_1KB  _AC(0x04,U)

/*
 * TTBCR_PD(0|1) can be applied only if LPAE is disabled, i.e., TTBCR.EAE==0
 * (ARM DDI 0487B.a G6-5203 and ARM DDI 0406C.b B4-1722).
 */
#define TTBCR_PD0       (_AC(1,U)<<4)
#define TTBCR_PD1       (_AC(1,U)<<5)

/* SCTLR System Control Register. */

/* Bits specific to SCTLR_EL1 for Arm32 */

#define SCTLR_A32_EL1_V     BIT(13, UL)

/* Common bits for SCTLR_ELx for Arm32 */

#define SCTLR_A32_ELx_TE    BIT(30, UL)
#define SCTLR_A32_ELx_FI    BIT(21, UL)

/* Common bits for SCTLR_ELx for Arm64 */
#define SCTLR_A64_ELx_SA    BIT(3, UL)

/* Common bits for SCTLR_ELx on all architectures */
#define SCTLR_Axx_ELx_EE    BIT(25, UL)
#define SCTLR_Axx_ELx_WXN   BIT(19, UL)
#define SCTLR_Axx_ELx_I     BIT(12, UL)
#define SCTLR_Axx_ELx_C     BIT(2, UL)
#define SCTLR_Axx_ELx_A     BIT(1, UL)
#define SCTLR_Axx_ELx_M     BIT(0, UL)

#ifdef CONFIG_ARM_32

#define HSCTLR_RES1     (BIT( 3, UL) | BIT( 4, UL) | BIT( 5, UL) |\
                         BIT( 6, UL) | BIT(11, UL) | BIT(16, UL) |\
                         BIT(18, UL) | BIT(22, UL) | BIT(23, UL) |\
                         BIT(28, UL) | BIT(29, UL))

#define HSCTLR_RES0     (BIT(7, UL)  | BIT(8, UL)  | BIT(9, UL)  | BIT(10, UL) |\
                         BIT(13, UL) | BIT(14, UL) | BIT(15, UL) | BIT(17, UL) |\
                         BIT(20, UL) | BIT(24, UL) | BIT(26, UL) | BIT(27, UL) |\
                         BIT(31, UL))

/* Initial value for HSCTLR */
#define HSCTLR_SET      (HSCTLR_RES1    | SCTLR_Axx_ELx_A   | SCTLR_Axx_ELx_I)

/* Only used a pre-processing time... */
#define HSCTLR_CLEAR    (HSCTLR_RES0        | SCTLR_Axx_ELx_M   |\
                         SCTLR_Axx_ELx_C    | SCTLR_Axx_ELx_WXN |\
                         SCTLR_A32_ELx_FI   | SCTLR_Axx_ELx_EE  |\
                         SCTLR_A32_ELx_TE)

#if (HSCTLR_SET ^ HSCTLR_CLEAR) != 0xffffffffU
#error "Inconsistent HSCTLR set/clear bits"
#endif

#else

#define SCTLR_EL2_RES1  (BIT( 4, UL) | BIT( 5, UL) | BIT(11, UL) |\
                         BIT(16, UL) | BIT(18, UL) | BIT(22, UL) |\
                         BIT(23, UL) | BIT(28, UL) | BIT(29, UL))

#define SCTLR_EL2_RES0  (BIT( 6, UL) | BIT( 7, UL) | BIT( 8, UL) |\
                         BIT( 9, UL) | BIT(10, UL) | BIT(13, UL) |\
                         BIT(14, UL) | BIT(15, UL) | BIT(17, UL) |\
                         BIT(20, UL) | BIT(21, UL) | BIT(24, UL) |\
                         BIT(26, UL) | BIT(27, UL) | BIT(30, UL) |\
                         BIT(31, UL) | (0xffffffffULL << 32))

/* Initial value for SCTLR_EL2 */
#define SCTLR_EL2_SET   (SCTLR_EL2_RES1     | SCTLR_A64_ELx_SA  |\
                         SCTLR_Axx_ELx_I)

/* Only used a pre-processing time... */
#define SCTLR_EL2_CLEAR (SCTLR_EL2_RES0     | SCTLR_Axx_ELx_M   |\
                         SCTLR_Axx_ELx_A    | SCTLR_Axx_ELx_C   |\
                         SCTLR_Axx_ELx_WXN  | SCTLR_Axx_ELx_EE)

#if (SCTLR_EL2_SET ^ SCTLR_EL2_CLEAR) != 0xffffffffffffffffUL
#error "Inconsistent SCTLR_EL2 set/clear bits"
#endif

#endif

/* HCR Hyp Configuration Register */
#define HCR_RW          (_AC(1,UL)<<31) /* Register Width, ARM64 only */
#define HCR_TGE         (_AC(1,UL)<<27) /* Trap General Exceptions */
#define HCR_TVM         (_AC(1,UL)<<26) /* Trap Virtual Memory Controls */
#define HCR_TTLB        (_AC(1,UL)<<25) /* Trap TLB Maintenance Operations */
#define HCR_TPU         (_AC(1,UL)<<24) /* Trap Cache Maintenance Operations to PoU */
#define HCR_TPC         (_AC(1,UL)<<23) /* Trap Cache Maintenance Operations to PoC */
#define HCR_TSW         (_AC(1,UL)<<22) /* Trap Set/Way Cache Maintenance Operations */
#define HCR_TAC         (_AC(1,UL)<<21) /* Trap ACTLR Accesses */
#define HCR_TIDCP       (_AC(1,UL)<<20) /* Trap lockdown */
#define HCR_TSC         (_AC(1,UL)<<19) /* Trap SMC instruction */
#define HCR_TID3        (_AC(1,UL)<<18) /* Trap ID Register Group 3 */
#define HCR_TID2        (_AC(1,UL)<<17) /* Trap ID Register Group 2 */
#define HCR_TID1        (_AC(1,UL)<<16) /* Trap ID Register Group 1 */
#define HCR_TID0        (_AC(1,UL)<<15) /* Trap ID Register Group 0 */
#define HCR_TWE         (_AC(1,UL)<<14) /* Trap WFE instruction */
#define HCR_TWI         (_AC(1,UL)<<13) /* Trap WFI instruction */
#define HCR_DC          (_AC(1,UL)<<12) /* Default cacheable */
#define HCR_BSU_MASK    (_AC(3,UL)<<10) /* Barrier Shareability Upgrade */
#define HCR_BSU_NONE     (_AC(0,UL)<<10)
#define HCR_BSU_INNER    (_AC(1,UL)<<10)
#define HCR_BSU_OUTER    (_AC(2,UL)<<10)
#define HCR_BSU_FULL     (_AC(3,UL)<<10)
#define HCR_FB          (_AC(1,UL)<<9) /* Force Broadcast of Cache/BP/TLB operations */
#define HCR_VA          (_AC(1,UL)<<8) /* Virtual Asynchronous Abort */
#define HCR_VI          (_AC(1,UL)<<7) /* Virtual IRQ */
#define HCR_VF          (_AC(1,UL)<<6) /* Virtual FIQ */
#define HCR_AMO         (_AC(1,UL)<<5) /* Override CPSR.A */
#define HCR_IMO         (_AC(1,UL)<<4) /* Override CPSR.I */
#define HCR_FMO         (_AC(1,UL)<<3) /* Override CPSR.F */
#define HCR_PTW         (_AC(1,UL)<<2) /* Protected Walk */
#define HCR_SWIO        (_AC(1,UL)<<1) /* Set/Way Invalidation Override */
#define HCR_VM          (_AC(1,UL)<<0) /* Virtual MMU Enable */

/* TCR: Stage 1 Translation Control */

#define TCR_T0SZ_SHIFT  (0)
#define TCR_T1SZ_SHIFT  (16)
#define TCR_T0SZ(x)     ((x)<<TCR_T0SZ_SHIFT)

/*
 * According to ARM DDI 0487B.a, TCR_EL1.{T0SZ,T1SZ} (AArch64, page D7-2480)
 * comprises 6 bits and TTBCR.{T0SZ,T1SZ} (AArch32, page G6-5204) comprises 3
 * bits following another 3 bits for RES0. Thus, the mask for both registers
 * should be 0x3f.
 */
#define TCR_SZ_MASK     (_AC(0x3f,UL))

#define TCR_EPD0        (_AC(0x1,UL)<<7)
#define TCR_EPD1        (_AC(0x1,UL)<<23)

#define TCR_IRGN0_NC    (_AC(0x0,UL)<<8)
#define TCR_IRGN0_WBWA  (_AC(0x1,UL)<<8)
#define TCR_IRGN0_WT    (_AC(0x2,UL)<<8)
#define TCR_IRGN0_WB    (_AC(0x3,UL)<<8)

#define TCR_ORGN0_NC    (_AC(0x0,UL)<<10)
#define TCR_ORGN0_WBWA  (_AC(0x1,UL)<<10)
#define TCR_ORGN0_WT    (_AC(0x2,UL)<<10)
#define TCR_ORGN0_WB    (_AC(0x3,UL)<<10)

#define TCR_SH0_NS      (_AC(0x0,UL)<<12)
#define TCR_SH0_OS      (_AC(0x2,UL)<<12)
#define TCR_SH0_IS      (_AC(0x3,UL)<<12)

/* Note that the fields TCR_EL1.{TG0,TG1} are not available on AArch32. */
#define TCR_TG0_SHIFT   (14)
#define TCR_TG0_MASK    (_AC(0x3,UL)<<TCR_TG0_SHIFT)
#define TCR_TG0_4K      (_AC(0x0,UL)<<TCR_TG0_SHIFT)
#define TCR_TG0_64K     (_AC(0x1,UL)<<TCR_TG0_SHIFT)
#define TCR_TG0_16K     (_AC(0x2,UL)<<TCR_TG0_SHIFT)

/* Note that the field TCR_EL2.TG1 exists only if HCR_EL2.E2H==1. */
#define TCR_EL1_TG1_SHIFT   (30)
#define TCR_EL1_TG1_MASK    (_AC(0x3,UL)<<TCR_EL1_TG1_SHIFT)
#define TCR_EL1_TG1_16K     (_AC(0x1,UL)<<TCR_EL1_TG1_SHIFT)
#define TCR_EL1_TG1_4K      (_AC(0x2,UL)<<TCR_EL1_TG1_SHIFT)
#define TCR_EL1_TG1_64K     (_AC(0x3,UL)<<TCR_EL1_TG1_SHIFT)

/*
 * Note that the field TCR_EL1.IPS is not available on AArch32. Also, the field
 * TCR_EL2.IPS exists only if HCR_EL2.E2H==1.
 */
#define TCR_EL1_IPS_SHIFT   (32)
#define TCR_EL1_IPS_MASK    (_AC(0x7,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_32_BIT  (_AC(0x0,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_36_BIT  (_AC(0x1,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_40_BIT  (_AC(0x2,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_42_BIT  (_AC(0x3,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_44_BIT  (_AC(0x4,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_48_BIT  (_AC(0x5,ULL)<<TCR_EL1_IPS_SHIFT)
#define TCR_EL1_IPS_52_BIT  (_AC(0x6,ULL)<<TCR_EL1_IPS_SHIFT)

/*
 * The following values correspond to the bit masks represented by
 * TCR_EL1_IPS_XX_BIT defines.
 */
#define TCR_EL1_IPS_32_BIT_VAL  (32)
#define TCR_EL1_IPS_36_BIT_VAL  (36)
#define TCR_EL1_IPS_40_BIT_VAL  (40)
#define TCR_EL1_IPS_42_BIT_VAL  (42)
#define TCR_EL1_IPS_44_BIT_VAL  (44)
#define TCR_EL1_IPS_48_BIT_VAL  (48)
#define TCR_EL1_IPS_52_BIT_VAL  (52)
#define TCR_EL1_IPS_MIN_VAL     (25)

/* Note that the fields TCR_EL2.TBI(0|1) exist only if HCR_EL2.E2H==1. */
#define TCR_EL1_TBI0    (_AC(0x1,ULL)<<37)
#define TCR_EL1_TBI1    (_AC(0x1,ULL)<<38)

#ifdef CONFIG_ARM_64

#define TCR_PS(x)       ((x)<<16)
#define TCR_TBI         (_AC(0x1,UL)<<20)

#define TCR_RES1        (_AC(1,UL)<<31|_AC(1,UL)<<23)

#else

#define TCR_RES1        (_AC(1,UL)<<31)

#endif

/* VTCR: Stage 2 Translation Control */

#define VTCR_T0SZ(x)    ((x)<<0)

#define VTCR_SL0(x)     ((x)<<6)

#define VTCR_IRGN0_NC   (_AC(0x0,UL)<<8)
#define VTCR_IRGN0_WBWA (_AC(0x1,UL)<<8)
#define VTCR_IRGN0_WT   (_AC(0x2,UL)<<8)
#define VTCR_IRGN0_WB   (_AC(0x3,UL)<<8)

#define VTCR_ORGN0_NC   (_AC(0x0,UL)<<10)
#define VTCR_ORGN0_WBWA (_AC(0x1,UL)<<10)
#define VTCR_ORGN0_WT   (_AC(0x2,UL)<<10)
#define VTCR_ORGN0_WB   (_AC(0x3,UL)<<10)

#define VTCR_SH0_NS     (_AC(0x0,UL)<<12)
#define VTCR_SH0_OS     (_AC(0x2,UL)<<12)
#define VTCR_SH0_IS     (_AC(0x3,UL)<<12)

#ifdef CONFIG_ARM_64

#define VTCR_TG0_4K     (_AC(0x0,UL)<<14)
#define VTCR_TG0_64K    (_AC(0x1,UL)<<14)
#define VTCR_TG0_16K    (_AC(0x2,UL)<<14)

#define VTCR_PS(x)      ((x)<<16)

#define VTCR_VS    	    (_AC(0x1,UL)<<19)

#endif

#define VTCR_RES1       (_AC(1,UL)<<31)

/* HCPTR Hyp. Coprocessor Trap Register */
#define HCPTR_TTA       ((_AC(1,U)<<20))        /* Trap trace registers */
#define HCPTR_CP(x)     ((_AC(1,U)<<(x)))       /* Trap Coprocessor x */
#define HCPTR_CP_MASK   ((_AC(1,U)<<14)-1)

/* HSTR Hyp. System Trap Register */
#define HSTR_T(x)       ((_AC(1,U)<<(x)))       /* Trap Cp15 c<x> */

/* HDCR Hyp. Debug Configuration Register */
#define HDCR_TDRA       (_AC(1,U)<<11)          /* Trap Debug ROM access */
#define HDCR_TDOSA      (_AC(1,U)<<10)          /* Trap Debug-OS-related register access */
#define HDCR_TDA        (_AC(1,U)<<9)           /* Trap Debug Access */
#define HDCR_TDE        (_AC(1,U)<<8)           /* Route Soft Debug exceptions from EL1/EL1 to EL2 */
#define HDCR_TPM        (_AC(1,U)<<6)           /* Trap Performance Monitors accesses */
#define HDCR_TPMCR      (_AC(1,U)<<5)           /* Trap PMCR accesses */

#define HSR_EC_SHIFT                26

#define HSR_EC_UNKNOWN              0x00
#define HSR_EC_WFI_WFE              0x01
#define HSR_EC_CP15_32              0x03
#define HSR_EC_CP15_64              0x04
#define HSR_EC_CP14_32              0x05        /* Trapped MCR or MRC access to CP14 */
#define HSR_EC_CP14_DBG             0x06        /* Trapped LDC/STC access to CP14 (only for debug registers) */
#define HSR_EC_CP                   0x07        /* HCPTR-trapped access to CP0-CP13 */
#define HSR_EC_CP10                 0x08
#define HSR_EC_JAZELLE              0x09
#define HSR_EC_BXJ                  0x0a
#define HSR_EC_CP14_64              0x0c
#define HSR_EC_SVC32                0x11
#define HSR_EC_HVC32                0x12
#define HSR_EC_SMC32                0x13
#ifdef CONFIG_ARM_64
#define HSR_EC_SVC64                0x15
#define HSR_EC_HVC64                0x16
#define HSR_EC_SMC64                0x17
#define HSR_EC_SYSREG               0x18
#endif
#define HSR_EC_INSTR_ABORT_LOWER_EL 0x20
#define HSR_EC_INSTR_ABORT_CURR_EL  0x21
#define HSR_EC_DATA_ABORT_LOWER_EL  0x24
#define HSR_EC_DATA_ABORT_CURR_EL   0x25
#ifdef CONFIG_ARM_64
#define HSR_EC_BRK                  0x3c
#endif

/* FSR format, common */
#define FSR_LPAE                (_AC(1,UL)<<9)
/* FSR short format */
#define FSRS_FS_DEBUG           (_AC(0,UL)<<10|_AC(0x2,UL)<<0)
/* FSR long format */
#define FSRL_STATUS_DEBUG       (_AC(0x22,UL)<<0)

#ifdef CONFIG_ARM_64
#define MM64_VMID_8_BITS_SUPPORT    0x0
#define MM64_VMID_16_BITS_SUPPORT   0x2
#endif

#ifndef __ASSEMBLY__

extern register_t __cpu_logical_map[];
#define cpu_logical_map(cpu) __cpu_logical_map[cpu]

#endif

/* Physical Address Register */
#define PAR_F           (_AC(1,U)<<0)

/* .... If F == 1 */
#define PAR_FSC_SHIFT   (1)
#define PAR_FSC_MASK    (_AC(0x3f,U)<<PAR_FSC_SHIFT)
#define PAR_STAGE21     (_AC(1,U)<<8)     /* Stage 2 Fault During Stage 1 Walk */
#define PAR_STAGE2      (_AC(1,U)<<9)     /* Stage 2 Fault */

/* If F == 0 */
#define PAR_MAIR_SHIFT  56                       /* Memory Attributes */
#define PAR_MAIR_MASK   (0xffLL<<PAR_MAIR_SHIFT)
#define PAR_NS          (_AC(1,U)<<9)                   /* Non-Secure */
#define PAR_SH_SHIFT    7                        /* Shareability */
#define PAR_SH_MASK     (_AC(3,U)<<PAR_SH_SHIFT)

/* Fault Status Register */
/*
 * 543210 BIT
 * 00XXLL -- XX Fault Level LL
 * ..01LL -- Translation Fault LL
 * ..10LL -- Access Fault LL
 * ..11LL -- Permission Fault LL
 * 01xxxx -- Abort/Parity
 * 10xxxx -- Other
 * 11xxxx -- Implementation Defined
 */
#define FSC_TYPE_MASK (_AC(0x3,U)<<4)
#define FSC_TYPE_FAULT (_AC(0x00,U)<<4)
#define FSC_TYPE_ABT   (_AC(0x01,U)<<4)
#define FSC_TYPE_OTH   (_AC(0x02,U)<<4)
#define FSC_TYPE_IMPL  (_AC(0x03,U)<<4)

#define FSC_FLT_TRANS  (0x04)
#define FSC_FLT_ACCESS (0x08)
#define FSC_FLT_PERM   (0x0c)
#define FSC_SEA        (0x10) /* Synchronous External Abort */
#define FSC_SPE        (0x18) /* Memory Access Synchronous Parity Error */
#define FSC_APE        (0x11) /* Memory Access Asynchronous Parity Error */
#define FSC_SEATT      (0x14) /* Sync. Ext. Abort Translation Table */
#define FSC_SPETT      (0x1c) /* Sync. Parity. Error Translation Table */
#define FSC_AF         (0x21) /* Alignment Fault */
#define FSC_DE         (0x22) /* Debug Event */
#define FSC_LKD        (0x34) /* Lockdown Abort */
#define FSC_CPR        (0x3a) /* Coprocossor Abort */

#define FSC_LL_MASK    (_AC(0x03,U)<<0)

/* HPFAR_EL2: Hypervisor IPA Fault Address Register */
#ifdef CONFIG_ARM_64
#define HPFAR_MASK	GENMASK(39, 4)
#else
#define HPFAR_MASK	GENMASK(31, 4)
#endif

/* Time counter hypervisor control register */
#define CNTHCTL_EL2_EL1PCTEN (1u<<0) /* Kernel/user access to physical counter */
#define CNTHCTL_EL2_EL1PCEN  (1u<<1) /* Kernel/user access to CNTP timer regs */

/* Time counter kernel control register */
#define CNTKCTL_EL1_EL0PCTEN (1u<<0) /* Expose phys counters to EL0 */
#define CNTKCTL_EL1_EL0VCTEN (1u<<1) /* Expose virt counters to EL0 */
#define CNTKCTL_EL1_EL0VTEN  (1u<<8) /* Expose virt timer registers to EL0 */
#define CNTKCTL_EL1_EL0PTEN  (1u<<9) /* Expose phys timer registers to EL0 */

/* Timer control registers */
#define CNTx_CTL_ENABLE   (1u<<0)  /* Enable timer */
#define CNTx_CTL_MASK     (1u<<1)  /* Mask IRQ */
#define CNTx_CTL_PENDING  (1u<<2)  /* IRQ pending */

/* Exception Vector offsets */
/* ... ARM32 */
#define VECTOR32_RST  0
#define VECTOR32_UND  4
#define VECTOR32_SVC  8
#define VECTOR32_PABT 12
#define VECTOR32_DABT 16
/* ... ARM64 */
#define VECTOR64_CURRENT_SP0_BASE  0x000
#define VECTOR64_CURRENT_SPx_BASE  0x200
#define VECTOR64_LOWER64_BASE      0x400
#define VECTOR64_LOWER32_BASE      0x600

#define VECTOR64_SYNC_OFFSET       0x000
#define VECTOR64_IRQ_OFFSET        0x080
#define VECTOR64_FIQ_OFFSET        0x100
#define VECTOR64_ERROR_OFFSET      0x180


#if defined(CONFIG_ARM_32)
# include <asm/arm32/processor.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/processor.h>
#else
# error "unknown ARM variant"
#endif

#ifndef __ASSEMBLY__
void panic_PAR(uint64_t par);

void show_execution_state(const struct cpu_user_regs *regs);
void show_registers(const struct cpu_user_regs *regs);
//#define dump_execution_state() run_in_exception_handler(show_execution_state)
#define dump_execution_state() WARN()

#define cpu_relax() barrier() /* Could yield? */

/* All a bit UP for the moment */
#define cpu_to_core(_cpu)   (0)
#define cpu_to_socket(_cpu) (0)

struct vcpu;
void vcpu_regs_hyp_to_user(const struct vcpu *vcpu,
                           struct vcpu_guest_core_regs *regs);
void vcpu_regs_user_to_hyp(struct vcpu *vcpu,
                           const struct vcpu_guest_core_regs *regs);

void do_trap_hyp_serror(struct cpu_user_regs *regs);

void do_trap_guest_serror(struct cpu_user_regs *regs);

register_t get_default_hcr_flags(void);

/*
 * Synchronize SError unless the feature is selected.
 * This is relying on the SErrors are currently unmasked.
 */
#define SYNCHRONIZE_SERROR(feat)                                  \
    do {                                                          \
        ASSERT(local_abort_is_enabled());                         \
        asm volatile(ALTERNATIVE("dsb sy; isb",                   \
                                 "nop; nop", feat)                \
                                 : : : "memory");                 \
    } while (0)

/*
 * Clear/Set flags in HCR_EL2 for a given vCPU. It only supports the current
 * vCPU for now.
 */
#define vcpu_hcr_clear_flags(v, flags)              \
    do {                                            \
        ASSERT((v) == current);                     \
        (v)->arch.hcr_el2 &= ~(flags);              \
        WRITE_SYSREG((v)->arch.hcr_el2, HCR_EL2);   \
    } while (0)

#define vcpu_hcr_set_flags(v, flags)                \
    do {                                            \
        ASSERT((v) == current);                     \
        (v)->arch.hcr_el2 |= (flags);               \
        WRITE_SYSREG((v)->arch.hcr_el2, HCR_EL2);   \
    } while (0)

#endif /* __ASSEMBLY__ */
#endif /* __ASM_ARM_PROCESSOR_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
