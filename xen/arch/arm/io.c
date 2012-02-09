/*
 * xen/arch/arm/io.h
 *
 * ARM I/O handlers
 *
 * Copyright (c) 2011 Citrix Systems.
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

#include <xen/config.h>
#include <xen/lib.h>
#include <asm/current.h>

#include "io.h"

static const struct mmio_handler *const mmio_handlers[] =
{
    &vgic_distr_mmio_handler,
};
#define MMIO_HANDLER_NR ARRAY_SIZE(mmio_handlers)

int handle_mmio(mmio_info_t *info)
{
    struct vcpu *v = current;
    int i;

    for ( i = 0; i < MMIO_HANDLER_NR; i++ )
        if ( mmio_handlers[i]->check_handler(v, info->gpa) )
            return info->dabt.write ?
                mmio_handlers[i]->write_handler(v, info) :
                mmio_handlers[i]->read_handler(v, info);

    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
