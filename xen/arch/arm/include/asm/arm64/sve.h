/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arm SVE feature code
 *
 * Copyright (C) 2022 ARM Ltd.
 */

#ifndef _ARM_ARM64_SVE_H
#define _ARM_ARM64_SVE_H

#include <xen/sched.h>

#define SVE_VL_MAX_BITS 2048U

/* Vector length must be multiple of 128 */
#define SVE_VL_MULTIPLE_VAL 128U

static inline unsigned int sve_decode_vl(unsigned int sve_vl)
{
    /* SVE vector length is stored as VL/128 in xen_arch_domainconfig */
    return sve_vl * SVE_VL_MULTIPLE_VAL;
}

static inline unsigned int sve_encode_vl(unsigned int sve_vl_bits)
{
    return sve_vl_bits / SVE_VL_MULTIPLE_VAL;
}

register_t compute_max_zcr(void);
int sve_context_init(struct vcpu *v);
void sve_context_free(struct vcpu *v);
void sve_save_state(struct vcpu *v);
void sve_restore_state(struct vcpu *v);
bool sve_domctl_vl_param(int val, unsigned int *out);

#ifdef CONFIG_ARM64_SVE

extern int opt_dom0_sve;

static inline bool is_sve_domain(const struct domain *d)
{
    return d->arch.sve_vl > 0;
}

unsigned int get_sys_vl_len(void);

#else /* !CONFIG_ARM64_SVE */

#define opt_dom0_sve     0

static inline bool is_sve_domain(const struct domain *d)
{
    return false;
}

static inline unsigned int get_sys_vl_len(void)
{
    return 0;
}

#endif /* CONFIG_ARM64_SVE */

#endif /* _ARM_ARM64_SVE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
