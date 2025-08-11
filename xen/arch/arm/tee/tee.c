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
#include <xen/param.h>
#include <xen/types.h>

#include <asm/tee/tee.h>

extern const struct tee_mediator_desc _steemediator[], _eteemediator[];
static const struct tee_mediator_desc __read_mostly *cur_mediator;

/* Select the TEE mediator using a name on command line. */
static char __initdata opt_mediator[16] = "";
string_param("tee", opt_mediator);

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

int tee_domain_teardown(struct domain *d)
{
    if ( !cur_mediator )
        return 0;

    return cur_mediator->ops->domain_teardown(d);
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
    bool select_mediator = strcmp(opt_mediator, "");

    if ( select_mediator )
        printk(XENLOG_INFO "TEE Mediator %s selected from command line\n",
               opt_mediator);

    /*
     * When a specific TEE is selected using the 'tee=' command line
     * argument, we panic if the probe fails or if the requested TEE is not
     * supported.
     */
    for ( desc = _steemediator; desc != _eteemediator; desc++ )
    {
        if ( select_mediator &&
             strncmp(opt_mediator, desc->cmdline_name, sizeof(opt_mediator)) )
            continue;

        if ( desc->ops->probe() )
        {
            printk(XENLOG_INFO "Using TEE mediator for %s\n", desc->name);
            cur_mediator = desc;
            return 0;
        }
        else if ( select_mediator )
        {
            panic("TEE mediator %s from command line probe failed\n",
                  opt_mediator);
            return -EFAULT;
        }
    }

    if ( select_mediator )
    {
        panic("TEE Mediator %s from command line not supported\n",
              opt_mediator);
        return -EINVAL;
    }

    return 0;
}

presmp_initcall(tee_init);

void __init init_tee_secondary(void)
{
    if ( cur_mediator && cur_mediator->ops->init_secondary )
        cur_mediator->ops->init_secondary();
}

void tee_free_domain_ctx(struct domain *d)
{
    if ( cur_mediator && cur_mediator->ops->free_domain_ctx)
        cur_mediator->ops->free_domain_ctx(d);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
