/*
 * xen/include/asm-arm/tee/tee.h
 *
 * Generic part of TEE mediator subsystem
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2018 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ARCH_ARM_TEE_TEE_H__
#define __ARCH_ARM_TEE_TEE_H__

#include <xen/lib.h>
#include <xen/types.h>

#include <asm/regs.h>

#ifdef CONFIG_TEE

struct tee_mediator_ops {
    /*
     * Probe for TEE. Should return true if TEE found and
     * mediator is initialized.
     */
    bool (*probe)(void);

    /*
     * Called during domain construction if toolstack requests to enable
     * TEE support so mediator can inform TEE about new
     * guest and create own structures for the new domain.
     */
    int (*domain_init)(struct domain *d);

    /*
     * Called during domain destruction to relinquish resources used
     * by mediator itself. This function can return -ERESTART to indicate
     * that it does not finished work and should be called again.
     */
    int (*relinquish_resources)(struct domain *d);

    /* Handle SMCCC call for current domain. */
    bool (*handle_call)(struct cpu_user_regs *regs);
};

struct tee_mediator_desc {
    /* Printable name of the TEE. */
    const char *name;

    /* Mediator callbacks as described above. */
    const struct tee_mediator_ops *ops;

    /*
     * ID of TEE. Corresponds to xen_arch_domainconfig.tee_type.
     * Should be one of XEN_DOMCTL_CONFIG_TEE_xxx
     */
    uint16_t tee_type;
};

bool tee_handle_call(struct cpu_user_regs *regs);
int tee_domain_init(struct domain *d, uint16_t tee_type);
int tee_relinquish_resources(struct domain *d);
uint16_t tee_get_type(void);

#define REGISTER_TEE_MEDIATOR(_name, _namestr, _type, _ops)         \
static const struct tee_mediator_desc __tee_desc_##_name __used     \
__section(".teemediator.info") = {                                  \
    .name = _namestr,                                               \
    .ops = _ops,                                                    \
    .tee_type = _type                                               \
}

#else

static inline bool tee_handle_call(struct cpu_user_regs *regs)
{
    return false;
}

static inline int tee_domain_init(struct domain *d, uint16_t tee_type)
{
    if ( likely(tee_type == XEN_DOMCTL_CONFIG_TEE_NONE) )
        return 0;

    return -ENODEV;
}

static inline int tee_relinquish_resources(struct domain *d)
{
    return 0;
}

static inline uint16_t tee_get_type(void)
{
    return XEN_DOMCTL_CONFIG_TEE_NONE;
}

#endif  /* CONFIG_TEE */

#endif /* __ARCH_ARM_TEE_TEE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
