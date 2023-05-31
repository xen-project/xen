/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arm SVE feature code
 *
 * Copyright (C) 2022 ARM Ltd.
 */

#ifndef _ARM_ARM64_SVE_H
#define _ARM_ARM64_SVE_H

#define SVE_VL_MAX_BITS 2048U

/* Vector length must be multiple of 128 */
#define SVE_VL_MULTIPLE_VAL 128U

register_t compute_max_zcr(void);

#endif /* _ARM_ARM64_SVE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
