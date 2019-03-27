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

/* Access to system registers */

#define READ_SYSREG32(name) ((uint32_t)READ_SYSREG64(name))

#define WRITE_SYSREG32(v, name) WRITE_SYSREG64((uint64_t)v, name)

#define WRITE_SYSREG64(v, name) do {                    \
    uint64_t _r = v;                                    \
    asm volatile("msr "__stringify(name)", %0" : : "r" (_r));       \
} while (0)
#define READ_SYSREG64(name) ({                          \
    uint64_t _r;                                        \
    asm volatile("mrs  %0, "__stringify(name) : "=r" (_r));         \
    _r; })

#define READ_SYSREG(name)     READ_SYSREG64(name)
#define WRITE_SYSREG(v, name) WRITE_SYSREG64(v, name)

#endif /* _ASM_ARM_ARM64_SYSREGS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
