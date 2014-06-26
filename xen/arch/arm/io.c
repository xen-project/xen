/*
 * xen/arch/arm/io.c
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
#include <xen/spinlock.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/mmio.h>

int handle_mmio(mmio_info_t *info)
{
    struct vcpu *v = current;
    int i;
    const struct mmio_handler *mmio_handler;
    const struct io_handler *io_handlers = &v->domain->arch.io_handlers;

    for ( i = 0; i < io_handlers->num_entries; i++ )
    {
        mmio_handler = &io_handlers->mmio_handlers[i];

        if ( (info->gpa >= mmio_handler->addr) &&
             (info->gpa < (mmio_handler->addr + mmio_handler->size)) )
        {
            return info->dabt.write ?
                mmio_handler->mmio_handler_ops->write_handler(v, info) :
                mmio_handler->mmio_handler_ops->read_handler(v, info);
        }
    }

    return 0;
}

void register_mmio_handler(struct domain *d,
                           const struct mmio_handler_ops *handle,
                           paddr_t addr, paddr_t size)
{
    struct io_handler *handler = &d->arch.io_handlers;

    BUG_ON(handler->num_entries >= MAX_IO_HANDLER);

    spin_lock(&handler->lock);

    handler->mmio_handlers[handler->num_entries].mmio_handler_ops = handle;
    handler->mmio_handlers[handler->num_entries].addr = addr;
    handler->mmio_handlers[handler->num_entries].size = size;
    dsb(ish);
    handler->num_entries++;

    spin_unlock(&handler->lock);
}

int domain_io_init(struct domain *d)
{
   spin_lock_init(&d->arch.io_handlers.lock);
   d->arch.io_handlers.num_entries = 0;

   return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
