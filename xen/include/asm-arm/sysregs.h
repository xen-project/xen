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

#define HSR_SYSREG_SCTLR_EL1      HSR_SYSREG(3,0,c1, c0,0)
#define HSR_SYSREG_TTBR0_EL1      HSR_SYSREG(3,0,c2, c0,0)
#define HSR_SYSREG_TTBR1_EL1      HSR_SYSREG(3,0,c2, c0,1)
#define HSR_SYSREG_TCR_EL1        HSR_SYSREG(3,0,c2, c0,2)
#define HSR_SYSREG_AFSR0_EL1      HSR_SYSREG(3,0,c5, c1,0)
#define HSR_SYSREG_AFSR1_EL1      HSR_SYSREG(3,0,c5, c1,1)
#define HSR_SYSREG_ESR_EL1        HSR_SYSREG(3,0,c5, c2,0)
#define HSR_SYSREG_FAR_EL1        HSR_SYSREG(3,0,c6, c0,0)
#define HSR_SYSREG_MAIR_EL1       HSR_SYSREG(3,0,c10,c2,0)
#define HSR_SYSREG_AMAIR_EL1      HSR_SYSREG(3,0,c10,c3,0)
#define HSR_SYSREG_CONTEXTIDR_EL1 HSR_SYSREG(3,0,c13,c0,1)

#define HSR_SYSREG_CNTPCT_EL0     HSR_SYSREG(3,3,c14,c0,0)
#define HSR_SYSREG_CNTP_CTL_EL0   HSR_SYSREG(3,3,c14,c2,1)
#define HSR_SYSREG_CNTP_TVAL_EL0  HSR_SYSREG(3,3,c14,c2,0)


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
