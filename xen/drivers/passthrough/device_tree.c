/*
 * Code to passthrough a device tree node to a guest
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
#include <xen/guest_access.h>
#include <xen/iommu.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xsm/xsm.h>

#include <asm/iommu_fwspec.h>

static spinlock_t dtdevs_lock = SPIN_LOCK_UNLOCKED;

int iommu_assign_dt_device(struct domain *d, struct dt_device_node *dev)
{
    int rc = -EBUSY;
    struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) )
        return -EINVAL;

    if ( !dt_device_is_protected(dev) )
        return -EINVAL;

    spin_lock(&dtdevs_lock);

    if ( !list_empty(&dev->domain_list) )
        goto fail;

    /* The flag field doesn't matter to DT device. */
    rc = hd->platform_ops->assign_device(d, 0, dt_to_dev(dev), 0);

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
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !is_iommu_enabled(d) )
        return -EINVAL;

    if ( !dt_device_is_protected(dev) )
        return -EINVAL;

    spin_lock(&dtdevs_lock);

    rc = hd->platform_ops->reassign_device(d, NULL, 0, dt_to_dev(dev));
    if ( rc )
        goto fail;

    list_del_init(&dev->domain_list);
    dt_device_set_used_by(dev, DOMID_IO);

fail:
    spin_unlock(&dtdevs_lock);

    return rc;
}

static bool_t iommu_dt_device_is_assigned(const struct dt_device_node *dev)
{
    bool_t assigned = 0;

    if ( !dt_device_is_protected(dev) )
        return 0;

    spin_lock(&dtdevs_lock);
    assigned = !list_empty(&dev->domain_list);
    spin_unlock(&dtdevs_lock);

    return assigned;
}

int iommu_dt_domain_init(struct domain *d)
{
    INIT_LIST_HEAD(&dom_iommu(d)->dt_devices);

    return 0;
}

int iommu_release_dt_devices(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);
    struct dt_device_node *dev, *_dev;
    int rc;

    if ( !is_iommu_enabled(d) )
        return 0;

    list_for_each_entry_safe(dev, _dev, &hd->dt_devices, domain_list)
    {
        rc = iommu_deassign_dt_device(d, dev);
        if ( rc )
        {
            dprintk(XENLOG_ERR, "Failed to deassign %s in domain %u\n",
                    dt_node_full_name(dev), d->domain_id);
            return rc;
        }
    }

    return 0;
}

int iommu_add_dt_device(struct dt_device_node *np)
{
    const struct iommu_ops *ops = iommu_get_ops();
    struct dt_phandle_args iommu_spec;
    struct device *dev = dt_to_dev(np);
    int rc = 1, index = 0;

    if ( !iommu_enabled )
        return 1;

    if ( !ops )
        return -EINVAL;

    if ( dev_iommu_fwspec_get(dev) )
        return -EEXIST;

    /*
     * According to the Documentation/devicetree/bindings/iommu/iommu.txt
     * from Linux.
     */
    while ( !dt_parse_phandle_with_args(np, "iommus", "#iommu-cells",
                                        index, &iommu_spec) )
    {
        /*
         * The driver which supports generic IOMMU DT bindings must have
         * these callback implemented.
         */
        if ( !ops->add_device || !ops->dt_xlate )
        {
            /*
             * Some Device Trees may expose both legacy SMMU and generic
             * IOMMU bindings together. However, the SMMU driver is only
             * supporting the former and will protect them during the
             * initialization. So we need to skip them and not return
             * error here.
             *
             * XXX: This can be dropped when the SMMU is able to deal
             * with generic bindings.
             */
            if ( dt_device_is_protected(np) )
                return 0;
            else
                return -EINVAL;
        }

        if ( !dt_device_is_available(iommu_spec.np) )
            break;

        rc = iommu_fwspec_init(dev, &iommu_spec.np->dev);
        if ( rc )
            break;

        /*
         * Provide DT IOMMU specifier which describes the IOMMU master
         * interfaces of that device (device IDs, etc) to the driver.
         * The driver is responsible to decide how to interpret them.
         */
        rc = ops->dt_xlate(dev, &iommu_spec);
        if ( rc )
            break;

        index++;
    }

    /*
     * Add master device to the IOMMU if latter is present and available.
     * The driver is responsible to mark that device as protected.
     */
    if ( !rc )
        rc = ops->add_device(0, dev);

    if ( rc < 0 )
        iommu_fwspec_free(dev);

    return rc;
}

int iommu_do_dt_domctl(struct xen_domctl *domctl, struct domain *d,
                       XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int ret;
    struct dt_device_node *dev;

    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_assign_device:
        ASSERT(d);
        /* fall through */
    case XEN_DOMCTL_test_assign_device:
        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_DT )
            break;

        ret = -EINVAL;
        if ( (d && d->is_dying) || domctl->u.assign_device.flags )
            break;

        ret = dt_find_node_by_gpath(domctl->u.assign_device.u.dt.path,
                                    domctl->u.assign_device.u.dt.size,
                                    &dev);
        if ( ret )
            break;

        ret = xsm_assign_dtdevice(XSM_HOOK, d, dt_node_full_name(dev));
        if ( ret )
            break;

        if ( domctl->cmd == XEN_DOMCTL_test_assign_device )
        {
            if ( iommu_dt_device_is_assigned(dev) )
            {
                printk(XENLOG_G_ERR "%s already assigned.\n",
                       dt_node_full_name(dev));
                ret = -EINVAL;
            }
            break;
        }

        if ( d == dom_io )
            return -EINVAL;

        ret = iommu_add_dt_device(dev);
        /*
         * Ignore "-EEXIST" error code as it would mean that the device is
         * already added to the IOMMU (positive result). Such happens after
         * re-creating guest domain.
         */
        if ( ret < 0 && ret != -EEXIST )
        {
            printk(XENLOG_G_ERR "Failed to add %s to the IOMMU\n",
                   dt_node_full_name(dev));
            break;
        }

        ret = iommu_assign_dt_device(d, dev);

        if ( ret )
            printk(XENLOG_G_ERR "XEN_DOMCTL_assign_dt_device: assign \"%s\""
                   " to dom%u failed (%d)\n",
                   dt_node_full_name(dev), d->domain_id, ret);
        break;

    case XEN_DOMCTL_deassign_device:
        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_DT )
            break;

        ret = -EINVAL;
        if ( domctl->u.assign_device.flags )
            break;

        ret = dt_find_node_by_gpath(domctl->u.assign_device.u.dt.path,
                                    domctl->u.assign_device.u.dt.size,
                                    &dev);
        if ( ret )
            break;

        ret = xsm_deassign_dtdevice(XSM_HOOK, d, dt_node_full_name(dev));

        if ( d == dom_io )
            return -EINVAL;

        ret = iommu_deassign_dt_device(d, dev);

        if ( ret )
            printk(XENLOG_G_ERR "XEN_DOMCTL_assign_dt_device: assign \"%s\""
                   " to dom%u failed (%d)\n",
                   dt_node_full_name(dev), d->domain_id, ret);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}
