/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#ifndef ARM_ARCH_CAPABILITIES_H
#define ARM_ARCH_CAPABILITIES_H

#include <stdint.h>
#include <xen/sysctl.h>

#include <xen-tools/common-macros.h>

static inline
unsigned int arch_capabilities_arm_sve(unsigned int arch_capabilities)
{
#if defined(__arm__) || defined(__aarch64__)
    unsigned int sve_vl = MASK_EXTR(arch_capabilities,
                                    XEN_SYSCTL_PHYSCAP_ARM_SVE_MASK);

    /* Vector length is divided by 128 before storing it in arch_capabilities */
    return sve_vl * 128U;
#else
    return 0;
#endif
}

#endif /* ARM_ARCH_CAPABILITIES_H */
