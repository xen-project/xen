/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_MPU_CPREGS_H
#define __ARM_MPU_CPREGS_H

/* CP15 CR0: MPU Type Register */
#define HMPUIR          p15,4,c0,c0,4

/* CP15 CR6: MPU Protection Region Base/Limit/Select Address Register */
#define HPRSELR         p15,4,c6,c2,1
#define HPRBAR          p15,4,c6,c3,0
#define HPRLAR          p15,4,c6,c8,1

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
