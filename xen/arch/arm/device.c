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

static bool_t __init device_is_compatible(const struct device_desc *desc,
                                          const struct dt_device_node *dev)
{
    const char *const *compat;

    if ( !desc->compatible )
        return 0;

    for ( compat = desc->compatible; *compat; compat++ )
    {
        if ( dt_device_is_compatible(dev, *compat) )
            return 1;
    }

    return 0;
}

int __init device_init(struct dt_device_node *dev, enum device_type type,
                       const void *data)
{
    const struct device_desc *desc;

    ASSERT(dev != NULL);

    if ( !dt_device_is_available(dev) )
        return  -ENODEV;

    for ( desc = _sdevice; desc != _edevice; desc++ )
    {
        if ( desc->type != type )
            continue;

        if ( device_is_compatible(desc, dev) )
        {
            ASSERT(desc->init != NULL);

            return desc->init(dev, data);
        }

    }

    return -EBADF;
}

enum device_type device_get_type(const struct dt_device_node *dev)
{
    const struct device_desc *desc;

    ASSERT(dev != NULL);

    for ( desc = _sdevice; desc != _edevice; desc++ )
    {
        if ( device_is_compatible(desc, dev) )
            return desc->type;
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
