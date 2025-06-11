/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ARM_ARM32_MPU_H
#define ARM_ARM32_MPU_H

#ifndef __ASSEMBLY__

/*
 * Unlike arm64, there are no reserved 0 bits beyond base and limit bitfield in
 * prbar and prlar registers respectively.
 */
#define MPU_REGION_RES0       0x0

/* Hypervisor Protection Region Base Address Register */
typedef union {
    struct {
        unsigned int xn:1;       /* Execute-Never */
        unsigned int ap_0:1;     /* Access Permission AP[0] */
        unsigned int ro:1;       /* Access Permission AP[1] */
        unsigned int sh:2;       /* Shareability */
        unsigned int res0:1;
        unsigned int base:26;    /* Base Address */
    } reg;
    uint32_t bits;
} prbar_t;

/* Hypervisor Protection Region Limit Address Register */
typedef union {
    struct {
        unsigned int en:1;     /* Region enable */
        unsigned int ai:3;     /* Memory Attribute Index */
        unsigned int res0:2;
        unsigned int limit:26; /* Limit Address */
    } reg;
    uint32_t bits;
} prlar_t;

/* MPU Protection Region */
typedef struct {
    prbar_t prbar;
    prlar_t prlar;
} pr_t;

#endif /* __ASSEMBLY__ */

#endif /* ARM_ARM32_MPU_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
