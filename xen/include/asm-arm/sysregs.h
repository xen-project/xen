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

#define CNTP_CTL_EL0  HSR_SYSREG(3,3,c14,c2,1)
#define CNTP_TVAL_EL0 HSR_SYSREG(3,3,c14,c2,0)
#endif

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
