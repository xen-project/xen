/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Alternate p2m HVM
 * Copyright (c) 2014, Intel Corporation.
 */

#ifndef __ASM_X86_ALTP2M_H
#define __ASM_X86_ALTP2M_H

#ifdef CONFIG_ALTP2M

#include <xen/types.h>
#include <xen/sched.h>         /* for struct vcpu, struct domain */
#include <asm/hvm/vcpu.h>      /* for vcpu_altp2m */

/* Alternate p2m HVM on/off per domain */
static inline bool altp2m_active(const struct domain *d)
{
    return d->arch.altp2m_active;
}

/* Alternate p2m VCPU */
void altp2m_vcpu_initialise(struct vcpu *v);
void altp2m_vcpu_destroy(struct vcpu *v);

int altp2m_vcpu_enable_ve(struct vcpu *v, gfn_t gfn);
void altp2m_vcpu_disable_ve(struct vcpu *v);

static inline uint16_t altp2m_vcpu_idx(const struct vcpu *v)
{
    return vcpu_altp2m(v).p2midx;
}
#else

static inline bool altp2m_active(const struct domain *d)
{
    return false;
}

/* Only declaration is needed. DCE will optimise it out when linking. */
uint16_t altp2m_vcpu_idx(const struct vcpu *v);
void altp2m_vcpu_initialise(struct vcpu *v);
void altp2m_vcpu_destroy(struct vcpu *v);
int altp2m_vcpu_enable_ve(struct vcpu *v, gfn_t gfn);
void altp2m_vcpu_disable_ve(struct vcpu *v);

#endif

#endif /* __ASM_X86_ALTP2M_H */
