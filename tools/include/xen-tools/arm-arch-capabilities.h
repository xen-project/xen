/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#ifndef ARM_ARCH_CAPABILITIES_H
#define ARM_ARCH_CAPABILITIES_H

#include <stdbool.h>
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

static inline
bool arch_capabilities_arm_gic_v2(unsigned int arch_capabilities)
{
#if defined(__arm__) || defined(__aarch64__)
    return MASK_EXTR(arch_capabilities, XEN_SYSCTL_PHYSCAP_ARM_GIC_V2);
#else
    return false;
#endif
}

static inline
bool arch_capabilities_arm_gic_v3(unsigned int arch_capabilities)
{
#if defined(__arm__) || defined(__aarch64__)
    return MASK_EXTR(arch_capabilities, XEN_SYSCTL_PHYSCAP_ARM_GIC_V3);
#else
    return false;
#endif
}

static inline
bool arch_capabilities_arm_timer_dt_freq(unsigned int arch_capabilities)
{
#if defined(__arm__) || defined(__aarch64__)
    return MASK_EXTR(arch_capabilities, XEN_SYSCTL_PHYSCAP_ARM_TIMER_DT_FREQ);
#else
    return false;
#endif
}

#endif /* ARM_ARCH_CAPABILITIES_H */
