/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mpu.h: Arm Memory Protection Unit definitions.
 */

#ifndef __ARM64_MPU_H__
#define __ARM64_MPU_H__

#define MPU_REGION_SHIFT  6
#define MPU_REGION_ALIGN  (_AC(1, UL) << MPU_REGION_SHIFT)
#define MPU_REGION_MASK   (~(MPU_REGION_ALIGN - 1))

#define NUM_MPU_REGIONS_SHIFT   8
#define NUM_MPU_REGIONS         (_AC(1, UL) << NUM_MPU_REGIONS_SHIFT)
#define NUM_MPU_REGIONS_MASK    (NUM_MPU_REGIONS - 1)
#endif /* __ARM64_MPU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
