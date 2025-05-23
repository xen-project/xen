/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ARM_ARM64_MPU_H
#define ARM_ARM64_MPU_H

#ifndef __ASSEMBLY__

#define MPU_REGION_RES0        (0xFFFFULL << 48)

/* Protection Region Base Address Register */
typedef union {
    struct __packed {
        unsigned long xn_0:1;     /* Execute-Never XN[0] */
        unsigned long xn:1;       /* Execute-Never XN[1] */
        unsigned long ap_0:1;     /* Access Permission AP[0] */
        unsigned long ro:1;       /* Access Permission AP[1] */
        unsigned long sh:2;       /* Shareability */
        unsigned long base:42;    /* Base Address */
        unsigned long res0:16;    /* RES0 */
    } reg;
    uint64_t bits;
} prbar_t;

/* Protection Region Limit Address Register */
typedef union {
    struct __packed {
        unsigned long en:1;     /* Region enable */
        unsigned long ai:3;     /* Memory Attribute Index */
        unsigned long ns:1;     /* Not-Secure */
        unsigned long res0:1;   /* RES0 */
        unsigned long limit:42; /* Limit Address */
        unsigned long res1:16;  /* RES0 */
    } reg;
    uint64_t bits;
} prlar_t;

/* MPU Protection Region */
typedef struct {
    prbar_t prbar;
    prlar_t prlar;
} pr_t;

#endif /* __ASSEMBLY__ */

#endif /* ARM_ARM64_MPU_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
