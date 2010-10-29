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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
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

extern const struct hvm_mmio_handler hpet_mmio_handler;
extern const struct hvm_mmio_handler vlapic_mmio_handler;
extern const struct hvm_mmio_handler vioapic_mmio_handler;
extern const struct hvm_mmio_handler msixtbl_mmio_handler;

#define HVM_MMIO_HANDLER_NR 4

static const struct hvm_mmio_handler *const
hvm_mmio_handlers[HVM_MMIO_HANDLER_NR] =
{
    &hpet_mmio_handler,
    &vlapic_mmio_handler,
    &vioapic_mmio_handler,
    &msixtbl_mmio_handler
};

static int hvm_mmio_access(struct vcpu *v,
                           ioreq_t *p,
                           hvm_mmio_read_t read_handler,
                           hvm_mmio_write_t write_handler)
{
    unsigned long data;
    int rc = X86EMUL_OKAY, i, sign = p->df ? -1 : 1;

    if ( !p->data_is_ptr )
    {
        if ( p->dir == IOREQ_READ )
        {
            rc = read_handler(v, p->addr, p->size, &data);
            p->data = data;
        }
        else /* p->dir == IOREQ_WRITE */
            rc = write_handler(v, p->addr, p->size, p->data);
        return rc;
    }

    if ( p->dir == IOREQ_READ )
    {
        for ( i = 0; i < p->count; i++ )
        {
            int ret;

            rc = read_handler(v, p->addr + (sign * i * p->size), p->size,
                              &data);
            if ( rc != X86EMUL_OKAY )
                break;
            ret = hvm_copy_to_guest_phys(p->data + (sign * i * p->size),
                                         &data,
                                         p->size);
            if ( (ret == HVMCOPY_gfn_paged_out) || 
                 (ret == HVMCOPY_gfn_shared) )
            {
                rc = X86EMUL_RETRY;
                break;
            }
        }
    }
    else
    {
        for ( i = 0; i < p->count; i++ )
        {
            int ret;

            ret = hvm_copy_from_guest_phys(&data,
                                           p->data + (sign * i * p->size),
                                           p->size);
            if ( (ret == HVMCOPY_gfn_paged_out) || 
                 (ret == HVMCOPY_gfn_shared) )
            {
                rc = X86EMUL_RETRY;
                break;
            }
            rc = write_handler(v, p->addr + (sign * i * p->size), p->size,
                               data);
            if ( rc != X86EMUL_OKAY )
                break;
        }
    }

    if ( i != 0 )
    {
        p->count = i;
        rc = X86EMUL_OKAY;
    }

    return rc;
}

int hvm_mmio_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    int i;

    for ( i = 0; i < HVM_MMIO_HANDLER_NR; i++ )
        if ( hvm_mmio_handlers[i]->check_handler(v, p->addr) )
            return hvm_mmio_access(
                v, p,
                hvm_mmio_handlers[i]->read_handler,
                hvm_mmio_handlers[i]->write_handler);

    return X86EMUL_UNHANDLEABLE;
}

static int process_portio_intercept(portio_action_t action, ioreq_t *p)
{
    int rc = X86EMUL_OKAY, i, sign = p->df ? -1 : 1;
    uint32_t data;

    if ( !p->data_is_ptr )
    {
        if ( p->dir == IOREQ_READ )
        {
            rc = action(IOREQ_READ, p->addr, p->size, &data);
            p->data = data;
        }
        else
        {
            data = p->data;
            rc = action(IOREQ_WRITE, p->addr, p->size, &data);
        }
        return rc;
    }

    if ( p->dir == IOREQ_READ )
    {
        for ( i = 0; i < p->count; i++ )
        {
            rc = action(IOREQ_READ, p->addr, p->size, &data);
            if ( rc != X86EMUL_OKAY )
                break;
            (void)hvm_copy_to_guest_phys(p->data + sign*i*p->size,
                                         &data, p->size);
        }
    }
    else /* p->dir == IOREQ_WRITE */
    {
        for ( i = 0; i < p->count; i++ )
        {
            data = 0;
            (void)hvm_copy_from_guest_phys(&data, p->data + sign*i*p->size,
                                           p->size);
            rc = action(IOREQ_WRITE, p->addr, p->size, &data);
            if ( rc != X86EMUL_OKAY )
                break;
        }
    }

    if ( i != 0 )
    {
        p->count = i;
        rc = X86EMUL_OKAY;
    }

    return rc;
}

/*
 * Check if the request is handled inside xen
 * return value: 0 --not handled; 1 --handled
 */
int hvm_io_intercept(ioreq_t *p, int type)
{
    struct vcpu *v = current;
    struct hvm_io_handler *handler =
        &v->domain->arch.hvm_domain.io_handler;
    int i;
    unsigned long addr, size;

    if ( type == HVM_PORTIO )
    {
        int rc = dpci_ioport_intercept(p);
        if ( (rc == X86EMUL_OKAY) || (rc == X86EMUL_RETRY) )
            return rc;
    }

    for ( i = 0; i < handler->num_slot; i++ )
    {
        if ( type != handler->hdl_list[i].type )
            continue;
        addr = handler->hdl_list[i].addr;
        size = handler->hdl_list[i].size;
        if ( (p->addr >= addr) &&
             ((p->addr + p->size) <= (addr + size)) )
        {
            if ( type == HVM_PORTIO )
                return process_portio_intercept(
                    handler->hdl_list[i].action.portio, p);
            return handler->hdl_list[i].action.mmio(p);
        }
    }

    return X86EMUL_UNHANDLEABLE;
}

void register_io_handler(
    struct domain *d, unsigned long addr, unsigned long size,
    void *action, int type)
{
    struct hvm_io_handler *handler = &d->arch.hvm_domain.io_handler;
    int num = handler->num_slot;

    BUG_ON(num >= MAX_IO_HANDLER);

    handler->hdl_list[num].addr = addr;
    handler->hdl_list[num].size = size;
    handler->hdl_list[num].action.ptr = action;
    handler->num_slot++;
}

void relocate_io_handler(
    struct domain *d, unsigned long old_addr, unsigned long new_addr,
    unsigned long size, int type)
{
    struct hvm_io_handler *handler = &d->arch.hvm_domain.io_handler;
    int i;

    for ( i = 0; i < handler->num_slot; i++ )
        if ( (handler->hdl_list[i].addr == old_addr) &&
             (handler->hdl_list[i].size == size) &&
             (handler->hdl_list[i].type == type) )
            handler->hdl_list[i].addr = new_addr;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
