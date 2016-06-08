/*
 * intercept.c: Handle performance critical I/O packets in hypervisor space
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/domain.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <io_ports.h>
#include <xen/event.h>
#include <xen/iommu.h>

static bool_t hvm_mmio_accept(const struct hvm_io_handler *handler,
                              const ioreq_t *p)
{
    paddr_t first = hvm_mmio_first_byte(p), last;

    BUG_ON(handler->type != IOREQ_TYPE_COPY);

    if ( !handler->mmio.ops->check(current, first) )
        return 0;

    /* Make sure the handler will accept the whole access. */
    last = hvm_mmio_last_byte(p);
    if ( last != first &&
         !handler->mmio.ops->check(current, last) )
        domain_crash(current->domain);

    return 1;
}

static int hvm_mmio_read(const struct hvm_io_handler *handler,
                         uint64_t addr, uint32_t size, uint64_t *data)
{
    BUG_ON(handler->type != IOREQ_TYPE_COPY);

    return handler->mmio.ops->read(current, addr, size, data);
}

static int hvm_mmio_write(const struct hvm_io_handler *handler,
                          uint64_t addr, uint32_t size, uint64_t data)
{
    BUG_ON(handler->type != IOREQ_TYPE_COPY);

    return handler->mmio.ops->write(current, addr, size, data);
}

static const struct hvm_io_ops mmio_ops = {
    .accept = hvm_mmio_accept,
    .read = hvm_mmio_read,
    .write = hvm_mmio_write
};

static bool_t hvm_portio_accept(const struct hvm_io_handler *handler,
                                const ioreq_t *p)
{
    unsigned int start = handler->portio.port;
    unsigned int end = start + handler->portio.size;

    BUG_ON(handler->type != IOREQ_TYPE_PIO);

    return (p->addr >= start) && ((p->addr + p->size) <= end);
}

static int hvm_portio_read(const struct hvm_io_handler *handler,
                           uint64_t addr, uint32_t size, uint64_t *data)
{
    uint32_t val = ~0u;
    int rc;

    BUG_ON(handler->type != IOREQ_TYPE_PIO);

    rc = handler->portio.action(IOREQ_READ, addr, size, &val);
    *data = val;

    return rc;
}

static int hvm_portio_write(const struct hvm_io_handler *handler,
                            uint64_t addr, uint32_t size, uint64_t data)
{
    uint32_t val = data;

    BUG_ON(handler->type != IOREQ_TYPE_PIO);

    return handler->portio.action(IOREQ_WRITE, addr, size, &val);
}

static const struct hvm_io_ops portio_ops = {
    .accept = hvm_portio_accept,
    .read = hvm_portio_read,
    .write = hvm_portio_write
};

int hvm_process_io_intercept(const struct hvm_io_handler *handler,
                             ioreq_t *p)
{
    const struct hvm_io_ops *ops = handler->ops;
    int rc = X86EMUL_OKAY, i, step = p->df ? -p->size : p->size;
    uint64_t data;
    uint64_t addr;

    if ( p->dir == IOREQ_READ )
    {
        for ( i = 0; i < p->count; i++ )
        {
            addr = (p->type == IOREQ_TYPE_COPY) ?
                   p->addr + step * i :
                   p->addr;
            rc = ops->read(handler, addr, p->size, &data);
            if ( rc != X86EMUL_OKAY )
                break;

            if ( p->data_is_ptr )
            {
                switch ( hvm_copy_to_guest_phys(p->data + step * i,
                                                &data, p->size) )
                {
                case HVMCOPY_okay:
                    break;
                case HVMCOPY_bad_gfn_to_mfn:
                    /* Drop the write as real hardware would. */
                    continue;
                case HVMCOPY_bad_gva_to_gfn:
                case HVMCOPY_gfn_paged_out:
                case HVMCOPY_gfn_shared:
                    ASSERT_UNREACHABLE();
                    /* fall through */
                default:
                    domain_crash(current->domain);
                    return X86EMUL_UNHANDLEABLE;
                }
            }
            else
                p->data = data;
        }
    }
    else /* p->dir == IOREQ_WRITE */
    {
        for ( i = 0; i < p->count; i++ )
        {
            if ( p->data_is_ptr )
            {
                switch ( hvm_copy_from_guest_phys(&data, p->data + step * i,
                                                  p->size) )
                {
                case HVMCOPY_okay:
                    break;
                case HVMCOPY_bad_gfn_to_mfn:
                    data = ~0;
                    break;
                case HVMCOPY_bad_gva_to_gfn:
                case HVMCOPY_gfn_paged_out:
                case HVMCOPY_gfn_shared:
                    ASSERT_UNREACHABLE();
                    /* fall through */
                default:
                    domain_crash(current->domain);
                    return X86EMUL_UNHANDLEABLE;
                }
            }
            else
                data = p->data;

            addr = (p->type == IOREQ_TYPE_COPY) ?
                   p->addr + step * i :
                   p->addr;
            rc = ops->write(handler, addr, p->size, data);
            if ( rc != X86EMUL_OKAY )
                break;
        }
    }

    if ( i )
    {
        p->count = i;
        rc = X86EMUL_OKAY;
    }
    else if ( rc == X86EMUL_UNHANDLEABLE )
    {
        /*
         * Don't forward entire batches to the device model: This would
         * prevent the internal handlers to see subsequent iterations of
         * the request.
         */
        p->count = 1;
    }

    return rc;
}

const struct hvm_io_handler *hvm_find_io_handler(ioreq_t *p)
{
    struct domain *curr_d = current->domain;
    unsigned int i;

    BUG_ON((p->type != IOREQ_TYPE_PIO) &&
           (p->type != IOREQ_TYPE_COPY));

    for ( i = 0; i < curr_d->arch.hvm_domain.io_handler_count; i++ )
    {
        const struct hvm_io_handler *handler =
            &curr_d->arch.hvm_domain.io_handler[i];
        const struct hvm_io_ops *ops = handler->ops;

        if ( handler->type != p->type )
            continue;

        if ( ops->accept(handler, p) )
            return handler;
    }

    return NULL;
}

int hvm_io_intercept(ioreq_t *p)
{
    const struct hvm_io_handler *handler;
    const struct hvm_io_ops *ops;
    int rc;

    handler = hvm_find_io_handler(p);

    if ( handler == NULL )
        return X86EMUL_UNHANDLEABLE;

    rc = hvm_process_io_intercept(handler, p);

    ops = handler->ops;
    if ( ops->complete != NULL )
        ops->complete(handler);

    return rc;
}

struct hvm_io_handler *hvm_next_io_handler(struct domain *d)
{
    unsigned int i = d->arch.hvm_domain.io_handler_count++;

    ASSERT(d->arch.hvm_domain.io_handler);

    if ( i == NR_IO_HANDLERS )
    {
        domain_crash(d);
        return NULL;
    }

    return &d->arch.hvm_domain.io_handler[i];
}

void register_mmio_handler(struct domain *d,
                           const struct hvm_mmio_ops *ops)
{
    struct hvm_io_handler *handler = hvm_next_io_handler(d);

    if ( handler == NULL )
        return;

    handler->type = IOREQ_TYPE_COPY;
    handler->ops = &mmio_ops;
    handler->mmio.ops = ops;
}

void register_portio_handler(struct domain *d, unsigned int port,
                             unsigned int size, portio_action_t action)
{
    struct hvm_io_handler *handler = hvm_next_io_handler(d);

    if ( handler == NULL )
        return;

    handler->type = IOREQ_TYPE_PIO;
    handler->ops = &portio_ops;
    handler->portio.port = port;
    handler->portio.size = size;
    handler->portio.action = action;
}

void relocate_portio_handler(struct domain *d, unsigned int old_port,
                             unsigned int new_port, unsigned int size)
{
    unsigned int i;

    for ( i = 0; i < d->arch.hvm_domain.io_handler_count; i++ )
    {
        struct hvm_io_handler *handler =
            &d->arch.hvm_domain.io_handler[i];

        if ( handler->type != IOREQ_TYPE_PIO )
            continue;

        if ( (handler->portio.port == old_port) &&
             (handler->portio.size = size) )
        {
            handler->portio.port = new_port;
            break;
        }
    }
}

bool_t hvm_mmio_internal(paddr_t gpa)
{
    const struct hvm_io_handler *handler;
    const struct hvm_io_ops *ops;
    ioreq_t p = {
        .type = IOREQ_TYPE_COPY,
        .addr = gpa,
        .count = 1,
        .size = 1,
    };

    handler = hvm_find_io_handler(&p);

    if ( handler == NULL )
        return 0;

    ops = handler->ops;
    if ( ops->complete != NULL )
        ops->complete(handler);

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
