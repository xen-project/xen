/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on the code from:
 *   xen/arch/arm/device.c
 */

#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>

#include <asm/device.h>

#ifdef CONFIG_HAS_DEVICE_TREE

extern const struct device_desc _sdevice[], _edevice[];

int __init device_init(struct dt_device_node *dev, enum device_class class,
                       const void *data)
{
    const struct device_desc *desc;

    ASSERT(dev != NULL);

    if ( !dt_device_is_available(dev) || dt_device_for_passthrough(dev) )
        return  -ENODEV;

    for ( desc = _sdevice; desc != _edevice; desc++ )
    {
        if ( desc->class != class )
            continue;

        if ( dt_match_node(desc->dt_match, dev) )
        {
            ASSERT(desc->init != NULL);

            return desc->init(dev, data);
        }
    }

    return -EBADF;
}

enum device_class device_get_class(const struct dt_device_node *dev)
{
    const struct device_desc *desc;

    ASSERT(dev != NULL);

    for ( desc = _sdevice; desc != _edevice; desc++ )
    {
        if ( dt_match_node(desc->dt_match, dev) )
            return desc->class;
    }

    return DEVICE_UNKNOWN;
}

#endif

#ifdef CONFIG_ACPI

extern const struct acpi_device_desc _asdevice[], _aedevice[];

int __init acpi_device_init(enum device_class class, const void *data, int class_type)
{
    const struct acpi_device_desc *desc;

    for ( desc = _asdevice; desc != _aedevice; desc++ )
    {
        if ( ( desc->class != class ) || ( desc->class_type != class_type ) )
            continue;

        ASSERT(desc->init != NULL);

        return desc->init(data);
    }

    return -EBADF;
}

#endif
