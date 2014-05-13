/*
 * Code to passthrough a device tree node to a guest
 *
 * TODO: This contains only the necessary code to protected device passed to
 * dom0. It will need some updates when device passthrough will is added.
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

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/device_tree.h>

static spinlock_t dtdevs_lock = SPIN_LOCK_UNLOCKED;

int iommu_assign_dt_device(struct domain *d, struct dt_device_node *dev)
{
    int rc = -EBUSY;
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return -EINVAL;

    if ( !dt_device_is_protected(dev) )
        return -EINVAL;

    spin_lock(&dtdevs_lock);

    if ( !list_empty(&dev->domain_list) )
        goto fail;

    rc = hd->platform_ops->assign_dt_device(d, dev);

    if ( rc )
        goto fail;

    list_add(&dev->domain_list, &hd->dt_devices);
    dt_device_set_used_by(dev, d->domain_id);

fail:
    spin_unlock(&dtdevs_lock);

    return rc;
}

int iommu_deassign_dt_device(struct domain *d, struct dt_device_node *dev)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops )
        return -EINVAL;

    if ( !dt_device_is_protected(dev) )
        return -EINVAL;

    spin_lock(&dtdevs_lock);

    rc = hd->platform_ops->reassign_dt_device(d, hardware_domain, dev);
    if ( rc )
        goto fail;

    list_del(&dev->domain_list);

    dt_device_set_used_by(dev, hardware_domain->domain_id);
    list_add(&dev->domain_list, &domain_hvm_iommu(hardware_domain)->dt_devices);

fail:
    spin_unlock(&dtdevs_lock);

    return rc;
}

int iommu_dt_domain_init(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    INIT_LIST_HEAD(&hd->dt_devices);

    return 0;
}

void iommu_dt_domain_destroy(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct dt_device_node *dev, *_dev;
    int rc;

    list_for_each_entry_safe(dev, _dev, &hd->dt_devices, domain_list)
    {
        rc = iommu_deassign_dt_device(d, dev);
        if ( rc )
            dprintk(XENLOG_ERR, "Failed to deassign %s in domain %u\n",
                    dt_node_full_name(dev), d->domain_id);
    }
}
