/*
 * Generic IOMMU framework via the device tree
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2014 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/device_tree.h>
#include <xen/iommu.h>
#include <xen/lib.h>

#include <asm/device.h>

/*
 * Deferred probe list is used to keep track of devices for which driver
 * requested deferred probing (returned -EAGAIN).
 */
static __initdata LIST_HEAD(deferred_probe_list);

static const struct iommu_ops *iommu_ops;

const struct iommu_ops *iommu_get_ops(void)
{
    return iommu_ops;
}

void __init iommu_set_ops(const struct iommu_ops *ops)
{
    BUG_ON(ops == NULL);

    if ( iommu_ops && iommu_ops != ops )
    {
        printk("WARNING: Cannot set IOMMU ops, already set to a different value\n");
        return;
    }

    iommu_ops = ops;
}

int __init iommu_hardware_setup(void)
{
    struct dt_device_node *np, *tmp;
    int rc;
    unsigned int num_iommus = 0;

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_IOMMU, NULL);
        if ( !rc )
            num_iommus++;
        else if ( rc == -EAGAIN )
        {
            /*
             * Nobody should use device's domain_list at such early stage,
             * so we can re-use it to link the device in the deferred list to
             * avoid introducing extra list_head field in struct dt_device_node.
             */
            ASSERT(list_empty(&np->domain_list));

            /*
             * Driver requested deferred probing, so add this device to
             * the deferred list for further processing.
             */
            list_add(&np->domain_list, &deferred_probe_list);
        }
        /*
         * Ignore the following error codes:
         *   - EBADF: Indicate the current is not an IOMMU
         *   - ENODEV: The IOMMU is not present or cannot be used by
         *     Xen.
         */
        else if ( rc != -EBADF && rc != -ENODEV )
            return rc;
    }

    /* Return immediately if there are no initialized devices. */
    if ( !num_iommus )
        return list_empty(&deferred_probe_list) ? -ENODEV : -EAGAIN;

    rc = 0;

    /*
     * Process devices in the deferred list if it is not empty.
     * Check that at least one device is initialized at each loop, otherwise
     * we may get an infinite loop. Also stop processing if we got an error
     * other than -EAGAIN.
     */
    while ( !list_empty(&deferred_probe_list) && num_iommus )
    {
        num_iommus = 0;

        list_for_each_entry_safe ( np, tmp, &deferred_probe_list, domain_list )
        {
            rc = device_init(np, DEVICE_IOMMU, NULL);
            if ( !rc )
            {
                num_iommus++;

                /* Remove initialized device from the deferred list. */
                list_del_init(&np->domain_list);
            }
            else if ( rc != -EAGAIN )
                return rc;
        }
    }

    return rc;
}

void __hwdom_init arch_iommu_check_autotranslated_hwdom(struct domain *d)
{
    /* ARM doesn't require specific check for hwdom */
    return;
}

int arch_iommu_domain_init(struct domain *d)
{
    return iommu_dt_domain_init(d);
}

void arch_iommu_domain_destroy(struct domain *d)
{
}

void __hwdom_init arch_iommu_hwdom_init(struct domain *d)
{
}
