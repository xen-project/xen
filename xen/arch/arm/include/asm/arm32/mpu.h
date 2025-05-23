/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ARM_ARM32_MPU_H
#define ARM_ARM32_MPU_H

#ifndef __ASSEMBLY__

/* MPU Protection Region */
typedef struct {
    uint32_t prbar;
    uint32_t prlar;
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
