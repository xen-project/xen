/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_ALTP2M_H__
#define __ASM_PPC_ALTP2M_H__

#include <xen/bug.h>

struct domain;
struct vcpu;

/* Alternate p2m on/off per domain */
static inline bool altp2m_active(const struct domain *d)
{
    /* Not implemented on PPC. */
    return false;
}

/* Alternate p2m VCPU */
static inline uint16_t altp2m_vcpu_idx(const struct vcpu *v)
{
    /* Not implemented on PPC, should not be reached. */
    ASSERT_UNREACHABLE();
    return 0;
}

#endif /* __ASM_PPC_ALTP2M_H__ */
