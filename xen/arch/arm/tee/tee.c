/*
 * xen/arch/arm/tee/tee.c
 *
 * Generic part of TEE mediator subsystem
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2018-2019 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/types.h>

#include <asm/tee/tee.h>

extern const struct tee_mediator_desc _steemediator[], _eteemediator[];
static const struct tee_mediator_desc __read_mostly *cur_mediator;

/*
 * TODO: Add function to alter Dom0 DTB, so we can properly describe
 * present TEE.
 */

bool tee_handle_call(struct cpu_user_regs *regs)
{
    if ( unlikely(!cur_mediator) )
        return false;

    return cur_mediator->ops->handle_call(regs);
}

int tee_domain_init(struct domain *d, uint16_t tee_type)
{
    if ( tee_type == XEN_DOMCTL_CONFIG_TEE_NONE )
        return 0;

    if ( !cur_mediator )
        return -ENODEV;

    if ( cur_mediator->tee_type != tee_type )
        return -EINVAL;

    return cur_mediator->ops->domain_init(d);
}

int tee_relinquish_resources(struct domain *d)
{
    if ( !cur_mediator )
        return 0;

    return cur_mediator->ops->relinquish_resources(d);
}

uint16_t tee_get_type(void)
{
    if ( !cur_mediator )
        return XEN_DOMCTL_CONFIG_TEE_NONE;

    return cur_mediator->tee_type;
}


static int __init tee_init(void)
{
    const struct tee_mediator_desc *desc;

    for ( desc = _steemediator; desc != _eteemediator; desc++ )
    {
        if ( desc->ops->probe() )
        {
            printk(XENLOG_INFO "Using TEE mediator for %s\n", desc->name);
            cur_mediator = desc;
            return 0;
        }
    }

    return 0;
}

__initcall(tee_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
