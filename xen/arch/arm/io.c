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
#include <xen/sort.h>
#include <asm/current.h>
#include <asm/mmio.h>

static int handle_read(const struct mmio_handler *handler, struct vcpu *v,
                       mmio_info_t *info)
{
    const struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    /*
     * Initialize to zero to avoid leaking data if there is an
     * implementation error in the emulation (such as not correctly
     * setting r).
     */
    register_t r = 0;
    uint8_t size = (1 << dabt.size) * 8;

    if ( !handler->ops->read(v, info, &r, handler->priv) )
        return 0;

    /*
     * Sign extend if required.
     * Note that we expect the read handler to have zeroed the bits
     * outside the requested access size.
     */
    if ( dabt.sign && (r & (1UL << (size - 1))) )
    {
        /*
         * We are relying on register_t using the same as
         * an unsigned long in order to keep the 32-bit assembly
         * code smaller.
         */
        BUILD_BUG_ON(sizeof(register_t) != sizeof(unsigned long));
        r |= (~0UL) << size;
    }

    set_user_reg(regs, dabt.reg, r);

    return 1;
}

static int handle_write(const struct mmio_handler *handler, struct vcpu *v,
                        mmio_info_t *info)
{
    const struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    return handler->ops->write(v, info, get_user_reg(regs, dabt.reg),
                               handler->priv);
}

/* This function assumes that mmio regions are not overlapped */
static int cmp_mmio_handler(const void *key, const void *elem)
{
    const struct mmio_handler *handler0 = key;
    const struct mmio_handler *handler1 = elem;

    if ( handler0->addr < handler1->addr )
        return -1;

    if ( handler0->addr > (handler1->addr + handler1->size) )
        return 1;

    return 0;
}

static const struct mmio_handler *find_mmio_handler(struct domain *d,
                                                    paddr_t gpa)
{
    struct vmmio *vmmio = &d->arch.vmmio;
    struct mmio_handler key = {.addr = gpa};
    const struct mmio_handler *handler;

    read_lock(&vmmio->lock);
    handler = bsearch(&key, vmmio->handlers, vmmio->num_entries,
                      sizeof(*handler), cmp_mmio_handler);
    read_unlock(&vmmio->lock);

    return handler;
}

int handle_mmio(mmio_info_t *info)
{
    struct vcpu *v = current;
    const struct mmio_handler *handler = NULL;

    handler = find_mmio_handler(v->domain, info->gpa);
    if ( !handler )
        return 0;

    if ( info->dabt.write )
        return handle_write(handler, v, info);
    else
        return handle_read(handler, v, info);
}

void register_mmio_handler(struct domain *d,
                           const struct mmio_handler_ops *ops,
                           paddr_t addr, paddr_t size, void *priv)
{
    struct vmmio *vmmio = &d->arch.vmmio;
    struct mmio_handler *handler;

    BUG_ON(vmmio->num_entries >= vmmio->max_num_entries);

    write_lock(&vmmio->lock);

    handler = &vmmio->handlers[vmmio->num_entries];

    handler->ops = ops;
    handler->addr = addr;
    handler->size = size;
    handler->priv = priv;

    vmmio->num_entries++;

    /* Sort mmio handlers in ascending order based on base address */
    sort(vmmio->handlers, vmmio->num_entries, sizeof(struct mmio_handler),
         cmp_mmio_handler, NULL);

    write_unlock(&vmmio->lock);
}

int domain_io_init(struct domain *d, int max_count)
{
    rwlock_init(&d->arch.vmmio.lock);
    d->arch.vmmio.num_entries = 0;
    d->arch.vmmio.max_num_entries = max_count;
    d->arch.vmmio.handlers = xzalloc_array(struct mmio_handler, max_count);
    if ( !d->arch.vmmio.handlers )
        return -ENOMEM;

    return 0;
}

void domain_io_free(struct domain *d)
{
    xfree(d->arch.vmmio.handlers);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
