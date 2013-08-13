#ifndef __ASM_ARM_PLATFORMS_MIDWAY_H
#define __ASM_ASM_PLATFORMS_MIDWAY_H

/* addresses of SREG registers for resetting the SoC */
#define MW_SREG_PWR_REQ             0xfff3cf00
#define MW_SREG_A15_PWR_CTRL        0xfff3c200

#define MW_PWR_SUSPEND              0
#define MW_PWR_SOFT_RESET           1
#define MW_PWR_HARD_RESET           2
#define MW_PWR_SHUTDOWN             3

#endif /* __ASM_ARM_PLATFORMS_MIDWAY_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
