/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GENERIC_ALTP2M_H
#define __ASM_GENERIC_ALTP2M_H

#include <xen/bug.h>

struct domain;
struct vcpu;

/* Alternate p2m on/off per domain */
static inline bool altp2m_active(const struct domain *d)
{
    /* Not implemented on GENERIC. */
    return false;
}

/* Alternate p2m VCPU */
static inline unsigned int altp2m_vcpu_idx(const struct vcpu *v)
{
    /* Not implemented on GENERIC, should not be reached. */
    BUG();
    return 0;
}

#endif /* __ASM_GENERIC_ALTP2M_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: BSD
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
