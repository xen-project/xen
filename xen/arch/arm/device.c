/*
 * xen/arch/arm/device.c
 *
 * Helpers to use a device retrieved via the device tree.
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2013 Linaro Limited.
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

#include <asm/device.h>
#include <xen/errno.h>
#include <xen/lib.h>

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
