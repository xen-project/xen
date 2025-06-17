/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_CPREGS_H
#define __ARM_MPU_CPREGS_H

/* CP15 CR0: MPU Type Register */
#define HMPUIR          p15,4,c0,c0,4

/* CP15 CR6: MPU Protection Region Base/Limit/Select Address Register */
#define HPRSELR         p15,4,c6,c2,1
#define HPRBAR          p15,4,c6,c3,0
#define HPRLAR          p15,4,c6,c3,1

/* CP15 CR6: MPU Protection Region Base/Limit Address Register */
#define HPRBAR0         p15,4,c6,c8,0
#define HPRLAR0         p15,4,c6,c8,1
#define HPRBAR1         p15,4,c6,c8,4
#define HPRLAR1         p15,4,c6,c8,5
#define HPRBAR2         p15,4,c6,c9,0
#define HPRLAR2         p15,4,c6,c9,1
#define HPRBAR3         p15,4,c6,c9,4
#define HPRLAR3         p15,4,c6,c9,5
#define HPRBAR4         p15,4,c6,c10,0
#define HPRLAR4         p15,4,c6,c10,1
#define HPRBAR5         p15,4,c6,c10,4
#define HPRLAR5         p15,4,c6,c10,5
#define HPRBAR6         p15,4,c6,c11,0
#define HPRLAR6         p15,4,c6,c11,1
#define HPRBAR7         p15,4,c6,c11,4
#define HPRLAR7         p15,4,c6,c11,5
#define HPRBAR8         p15,4,c6,c12,0
#define HPRLAR8         p15,4,c6,c12,1
#define HPRBAR9         p15,4,c6,c12,4
#define HPRLAR9         p15,4,c6,c12,5
#define HPRBAR10        p15,4,c6,c13,0
#define HPRLAR10        p15,4,c6,c13,1
#define HPRBAR11        p15,4,c6,c13,4
#define HPRLAR11        p15,4,c6,c13,5
#define HPRBAR12        p15,4,c6,c14,0
#define HPRLAR12        p15,4,c6,c14,1
#define HPRBAR13        p15,4,c6,c14,4
#define HPRLAR13        p15,4,c6,c14,5
#define HPRBAR14        p15,4,c6,c15,0
#define HPRLAR14        p15,4,c6,c15,1
#define HPRBAR15        p15,4,c6,c15,4
#define HPRLAR15        p15,4,c6,c15,5
#define HPRBAR16        p15,5,c6,c8,0
#define HPRLAR16        p15,5,c6,c8,1
#define HPRBAR17        p15,5,c6,c8,4
#define HPRLAR17        p15,5,c6,c8,5
#define HPRBAR18        p15,5,c6,c9,0
#define HPRLAR18        p15,5,c6,c9,1
#define HPRBAR19        p15,5,c6,c9,4
#define HPRLAR19        p15,5,c6,c9,5
#define HPRBAR20        p15,5,c6,c10,0
#define HPRLAR20        p15,5,c6,c10,1
#define HPRBAR21        p15,5,c6,c10,4
#define HPRLAR21        p15,5,c6,c10,5
#define HPRBAR22        p15,5,c6,c11,0
#define HPRLAR22        p15,5,c6,c11,1
#define HPRBAR23        p15,5,c6,c11,4
#define HPRLAR23        p15,5,c6,c11,5
#define HPRBAR24        p15,5,c6,c12,0
#define HPRLAR24        p15,5,c6,c12,1
#define HPRBAR25        p15,5,c6,c12,4
#define HPRLAR25        p15,5,c6,c12,5
#define HPRBAR26        p15,5,c6,c13,0
#define HPRLAR26        p15,5,c6,c13,1
#define HPRBAR27        p15,5,c6,c13,4
#define HPRLAR27        p15,5,c6,c13,5
#define HPRBAR28        p15,5,c6,c14,0
#define HPRLAR28        p15,5,c6,c14,1
#define HPRBAR29        p15,5,c6,c14,4
#define HPRLAR29        p15,5,c6,c14,5
#define HPRBAR30        p15,5,c6,c15,0
#define HPRLAR30        p15,5,c6,c15,1
#define HPRBAR31        p15,5,c6,c15,4
#define HPRLAR31        p15,5,c6,c15,5

/* Aliases of AArch64 names for use in common code */
#ifdef CONFIG_ARM_32
/* Alphabetically... */
#define MPUIR_EL2       HMPUIR
#define PRBAR_EL2       HPRBAR
#define PRLAR_EL2       HPRLAR
#define PRSELR_EL2      HPRSELR
#endif /* CONFIG_ARM_32 */

#endif /* __ARM_MPU_CPREGS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
