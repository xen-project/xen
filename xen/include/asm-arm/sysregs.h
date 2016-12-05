#ifndef __ASM_ARM_SYSREGS_H
#define __ASM_ARM_SYSREGS_H

#ifdef CONFIG_ARM_64

#include <xen/stringify.h>

/* AArch 64 System Register Encodings */
#define __HSR_SYSREG_c0  0
#define __HSR_SYSREG_c1  1
#define __HSR_SYSREG_c2  2
#define __HSR_SYSREG_c3  3
#define __HSR_SYSREG_c4  4
#define __HSR_SYSREG_c5  5
#define __HSR_SYSREG_c6  6
#define __HSR_SYSREG_c7  7
#define __HSR_SYSREG_c8  8
#define __HSR_SYSREG_c9  9
#define __HSR_SYSREG_c10 10
#define __HSR_SYSREG_c11 11
#define __HSR_SYSREG_c12 12
#define __HSR_SYSREG_c13 13
#define __HSR_SYSREG_c14 14
#define __HSR_SYSREG_c15 15

#define __HSR_SYSREG_0   0
#define __HSR_SYSREG_1   1
#define __HSR_SYSREG_2   2
#define __HSR_SYSREG_3   3
#define __HSR_SYSREG_4   4
#define __HSR_SYSREG_5   5
#define __HSR_SYSREG_6   6
#define __HSR_SYSREG_7   7

/* These are used to decode traps with HSR.EC==HSR_EC_SYSREG */
#define HSR_SYSREG(op0,op1,crn,crm,op2) \
    ((__HSR_SYSREG_##op0) << HSR_SYSREG_OP0_SHIFT) | \
    ((__HSR_SYSREG_##op1) << HSR_SYSREG_OP1_SHIFT) | \
    ((__HSR_SYSREG_##crn) << HSR_SYSREG_CRN_SHIFT) | \
    ((__HSR_SYSREG_##crm) << HSR_SYSREG_CRM_SHIFT) | \
    ((__HSR_SYSREG_##op2) << HSR_SYSREG_OP2_SHIFT)

#define HSR_SYSREG_DCISW          HSR_SYSREG(1,0,c7,c6,2)
#define HSR_SYSREG_DCCSW          HSR_SYSREG(1,0,c7,c10,2)
#define HSR_SYSREG_DCCISW         HSR_SYSREG(1,0,c7,c14,2)

#define HSR_SYSREG_MDSCR_EL1      HSR_SYSREG(2,0,c0,c2,2)
#define HSR_SYSREG_MDRAR_EL1      HSR_SYSREG(2,0,c1,c0,0)
#define HSR_SYSREG_OSLAR_EL1      HSR_SYSREG(2,0,c1,c0,4)
#define HSR_SYSREG_OSLSR_EL1      HSR_SYSREG(2,0,c1,c1,4)
#define HSR_SYSREG_OSDLR_EL1      HSR_SYSREG(2,0,c1,c3,4)
#define HSR_SYSREG_DBGPRCR_EL1    HSR_SYSREG(2,0,c1,c4,4)
#define HSR_SYSREG_MDCCSR_EL0     HSR_SYSREG(2,3,c0,c1,0)

#define HSR_SYSREG_DBGBVRn_EL1(n) HSR_SYSREG(2,0,c0,c##n,4)
#define HSR_SYSREG_DBGBCRn_EL1(n) HSR_SYSREG(2,0,c0,c##n,5)
#define HSR_SYSREG_DBGWVRn_EL1(n) HSR_SYSREG(2,0,c0,c##n,6)
#define HSR_SYSREG_DBGWCRn_EL1(n) HSR_SYSREG(2,0,c0,c##n,7)

#define HSR_SYSREG_DBG_CASES(REG) case HSR_SYSREG_##REG##n_EL1(0):  \
                                  case HSR_SYSREG_##REG##n_EL1(1):  \
                                  case HSR_SYSREG_##REG##n_EL1(2):  \
                                  case HSR_SYSREG_##REG##n_EL1(3):  \
                                  case HSR_SYSREG_##REG##n_EL1(4):  \
                                  case HSR_SYSREG_##REG##n_EL1(5):  \
                                  case HSR_SYSREG_##REG##n_EL1(6):  \
                                  case HSR_SYSREG_##REG##n_EL1(7):  \
                                  case HSR_SYSREG_##REG##n_EL1(8):  \
                                  case HSR_SYSREG_##REG##n_EL1(9):  \
                                  case HSR_SYSREG_##REG##n_EL1(10): \
                                  case HSR_SYSREG_##REG##n_EL1(11): \
                                  case HSR_SYSREG_##REG##n_EL1(12): \
                                  case HSR_SYSREG_##REG##n_EL1(13): \
                                  case HSR_SYSREG_##REG##n_EL1(14): \
                                  case HSR_SYSREG_##REG##n_EL1(15)

#define HSR_SYSREG_SCTLR_EL1      HSR_SYSREG(3,0,c1, c0,0)
#define HSR_SYSREG_ACTLR_EL1      HSR_SYSREG(3,0,c1, c0,1)
#define HSR_SYSREG_TTBR0_EL1      HSR_SYSREG(3,0,c2, c0,0)
#define HSR_SYSREG_TTBR1_EL1      HSR_SYSREG(3,0,c2, c0,1)
#define HSR_SYSREG_TCR_EL1        HSR_SYSREG(3,0,c2, c0,2)
#define HSR_SYSREG_AFSR0_EL1      HSR_SYSREG(3,0,c5, c1,0)
#define HSR_SYSREG_AFSR1_EL1      HSR_SYSREG(3,0,c5, c1,1)
#define HSR_SYSREG_ESR_EL1        HSR_SYSREG(3,0,c5, c2,0)
#define HSR_SYSREG_FAR_EL1        HSR_SYSREG(3,0,c6, c0,0)
#define HSR_SYSREG_PMINTENSET_EL1 HSR_SYSREG(3,0,c9,c14,1)
#define HSR_SYSREG_PMINTENCLR_EL1 HSR_SYSREG(3,0,c9,c14,2)
#define HSR_SYSREG_MAIR_EL1       HSR_SYSREG(3,0,c10,c2,0)
#define HSR_SYSREG_AMAIR_EL1      HSR_SYSREG(3,0,c10,c3,0)
#define HSR_SYSREG_ICC_SGI1R_EL1  HSR_SYSREG(3,0,c12,c11,5)
#define HSR_SYSREG_ICC_ASGI1R_EL1 HSR_SYSREG(3,1,c12,c11,6)
#define HSR_SYSREG_ICC_SGI0R_EL1  HSR_SYSREG(3,2,c12,c11,7)
#define HSR_SYSREG_ICC_SRE_EL1    HSR_SYSREG(3,0,c12,c12,5)
#define HSR_SYSREG_CONTEXTIDR_EL1 HSR_SYSREG(3,0,c13,c0,1)

#define HSR_SYSREG_PMCR_EL0       HSR_SYSREG(3,3,c9,c12,0)
#define HSR_SYSREG_PMCNTENSET_EL0 HSR_SYSREG(3,3,c9,c12,1)
#define HSR_SYSREG_PMCNTENCLR_EL0 HSR_SYSREG(3,3,c9,c12,2)
#define HSR_SYSREG_PMOVSCLR_EL0   HSR_SYSREG(3,3,c9,c12,3)
#define HSR_SYSREG_PMSWINC_EL0    HSR_SYSREG(3,3,c9,c12,4)
#define HSR_SYSREG_PMSELR_EL0     HSR_SYSREG(3,3,c9,c12,5)
#define HSR_SYSREG_PMCEID0_EL0    HSR_SYSREG(3,3,c9,c12,6)
#define HSR_SYSREG_PMCEID1_EL0    HSR_SYSREG(3,3,c9,c12,7)

#define HSR_SYSREG_PMCCNTR_EL0    HSR_SYSREG(3,3,c9,c13,0)
#define HSR_SYSREG_PMXEVTYPER_EL0 HSR_SYSREG(3,3,c9,c13,1)
#define HSR_SYSREG_PMXEVCNTR_EL0  HSR_SYSREG(3,3,c9,c13,2)

#define HSR_SYSREG_PMUSERENR_EL0  HSR_SYSREG(3,3,c9,c14,0)
#define HSR_SYSREG_PMOVSSET_EL0   HSR_SYSREG(3,3,c9,c14,3)

#define HSR_SYSREG_CNTPCT_EL0     HSR_SYSREG(3,3,c14,c0,0)
#define HSR_SYSREG_CNTP_TVAL_EL0  HSR_SYSREG(3,3,c14,c2,0)
#define HSR_SYSREG_CNTP_CTL_EL0   HSR_SYSREG(3,3,c14,c2,1)
#define HSR_SYSREG_CNTP_CVAL_EL0  HSR_SYSREG(3,3,c14,c2,2)

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

#endif

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
