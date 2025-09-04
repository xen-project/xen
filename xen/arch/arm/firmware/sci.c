/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Generic part of the SCI (System Control Interface) subsystem.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (c) 2025 EPAM Systems
 */

#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/firmware/sci.h>

static const struct sci_mediator_ops __read_mostly *cur_mediator;

int sci_register(const struct sci_mediator_ops *ops)
{
    if ( cur_mediator )
        return -EEXIST;

    if ( !ops->domain_init || !ops->domain_destroy || !ops->handle_call )
        return -EINVAL;

    cur_mediator = ops;

    return 0;
};

bool sci_handle_call(struct cpu_user_regs *regs)
{
    if ( unlikely(!cur_mediator) )
        return false;

    return cur_mediator->handle_call(regs);
}

int sci_domain_init(struct domain *d, struct xen_domctl_createdomain *config)
{
    if ( !cur_mediator )
        return 0;

    return cur_mediator->domain_init(d, config);
}

int sci_domain_sanitise_config(struct xen_domctl_createdomain *config)
{
    if ( !cur_mediator )
        return 0;

    if ( !cur_mediator->domain_sanitise_config )
        return 0;

    return cur_mediator->domain_sanitise_config(config);
}

void sci_domain_destroy(struct domain *d)
{
    if ( !cur_mediator )
        return;

    cur_mediator->domain_destroy(d);
}

int sci_relinquish_resources(struct domain *d)
{
    if ( !cur_mediator )
        return 0;

    if ( !cur_mediator->relinquish_resources )
        return 0;

    return cur_mediator->relinquish_resources(d);
}

bool sci_dt_handle_node(struct domain *d, struct dt_device_node *node)
{
    if ( !cur_mediator )
        return 0;

    if ( !cur_mediator->dom0_dt_handle_node )
        return 0;

    return cur_mediator->dom0_dt_handle_node(d, node);
}

int sci_dt_finalize(struct domain *d, void *fdt)
{
    if ( !cur_mediator )
        return 0;

    if ( !cur_mediator->dom0_dt_finalize )
        return 0;

    return cur_mediator->dom0_dt_finalize(d, fdt);
}

int sci_assign_dt_device(struct domain *d, struct dt_device_node *dev)
{
    struct dt_phandle_args ac_spec;
    int index = 0;
    int ret;

    if ( !cur_mediator )
        return 0;

    if ( !cur_mediator->assign_dt_device )
        return 0;

    while ( !dt_parse_phandle_with_args(dev, "access-controllers",
                                        "#access-controller-cells", index,
                                        &ac_spec) )
    {
        printk(XENLOG_DEBUG "sci: assign device %s to %pd\n",
               dt_node_full_name(dev), d);

        ret = cur_mediator->assign_dt_device(d, &ac_spec);
        if ( ret )
            return ret;

        index++;
    }

    return 0;
}

static int __init sci_init(void)
{
    struct dt_device_node *np;
    unsigned int num_sci = 0;
    int rc;

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_FIRMWARE, NULL);
        if ( !rc && num_sci )
        {
            printk(XENLOG_ERR
                   "SCMI: Only one SCI controller is supported. found second %s\n",
                   np->name);
            return -EOPNOTSUPP;
        }
        else if ( !rc )
            num_sci++;
        else if ( rc != -EBADF && rc != -ENODEV )
            return rc;
    }

    return 0;
}

__initcall(sci_init);
