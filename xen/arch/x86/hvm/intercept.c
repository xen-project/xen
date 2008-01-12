/*
 * intercept.c: Handle performance critical I/O packets in hypervisor space
 *
 * Copyright (c) 2004, Intel Corporation.
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
#include <asm/iommu.h>


extern struct hvm_mmio_handler hpet_mmio_handler;
extern struct hvm_mmio_handler vlapic_mmio_handler;
extern struct hvm_mmio_handler vioapic_mmio_handler;

#define HVM_MMIO_HANDLER_NR 3

static struct hvm_mmio_handler *hvm_mmio_handlers[HVM_MMIO_HANDLER_NR] =
{
    &hpet_mmio_handler,
    &vlapic_mmio_handler,
    &vioapic_mmio_handler
};

static inline void hvm_mmio_access(struct vcpu *v,
                                   ioreq_t *p,
                                   hvm_mmio_read_t read_handler,
                                   hvm_mmio_write_t write_handler)
{
    unsigned int tmp1, tmp2;
    unsigned long data;

    switch ( p->type ) {
    case IOREQ_TYPE_COPY:
    {
        if ( !p->data_is_ptr ) {
            if ( p->dir == IOREQ_READ )
                p->data = read_handler(v, p->addr, p->size);
            else    /* p->dir == IOREQ_WRITE */
                write_handler(v, p->addr, p->size, p->data);
        } else {    /* p->data_is_ptr */
            int i, sign = (p->df) ? -1 : 1;

            if ( p->dir == IOREQ_READ ) {
                for ( i = 0; i < p->count; i++ ) {
                    data = read_handler(v,
                        p->addr + (sign * i * p->size),
                        p->size);
                    (void)hvm_copy_to_guest_phys(
                        p->data + (sign * i * p->size),
                        &data,
                        p->size);
                }
            } else {/* p->dir == IOREQ_WRITE */
                for ( i = 0; i < p->count; i++ ) {
                    (void)hvm_copy_from_guest_phys(
                        &data,
                        p->data + (sign * i * p->size),
                        p->size);
                    write_handler(v,
                        p->addr + (sign * i * p->size),
                        p->size, data);
                }
            }
        }
        break;
    }

    case IOREQ_TYPE_AND:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 & (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_ADD:
        tmp1 = read_handler(v, p->addr, p->size);
        if (p->dir == IOREQ_WRITE) {
            tmp2 = tmp1 + (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_OR:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 | (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_XOR:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 ^ (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    case IOREQ_TYPE_XCHG:
        /*
         * Note that we don't need to be atomic here since VCPU is accessing
         * its own local APIC.
         */
        tmp1 = read_handler(v, p->addr, p->size);
        write_handler(v, p->addr, p->size, (unsigned long) p->data);
        p->data = tmp1;
        break;

    case IOREQ_TYPE_SUB:
        tmp1 = read_handler(v, p->addr, p->size);
        if ( p->dir == IOREQ_WRITE ) {
            tmp2 = tmp1 - (unsigned long) p->data;
            write_handler(v, p->addr, p->size, tmp2);
        }
        p->data = tmp1;
        break;

    default:
        printk("hvm_mmio_access: error ioreq type %x\n", p->type);
        domain_crash_synchronous();
        break;
    }
}

int hvm_buffered_io_send(ioreq_t *p)
{
    struct vcpu *v = current;
    struct hvm_ioreq_page *iorp = &v->domain->arch.hvm_domain.buf_ioreq;
    buffered_iopage_t *pg = iorp->va;
    buf_ioreq_t bp;
    /* Timeoffset sends 64b data, but no address. Use two consecutive slots. */
    int qw = 0;

    /* Ensure buffered_iopage fits in a page */
    BUILD_BUG_ON(sizeof(buffered_iopage_t) > PAGE_SIZE);

    /*
     * Return 0 for the cases we can't deal with:
     *  - 'addr' is only a 20-bit field, so we cannot address beyond 1MB
     *  - we cannot buffer accesses to guest memory buffers, as the guest
     *    may expect the memory buffer to be synchronously accessed
     *  - the count field is usually used with data_is_ptr and since we don't
     *    support data_is_ptr we do not waste space for the count field either
     */
    if ( (p->addr > 0xffffful) || p->data_is_ptr || (p->count != 1) )
        return 0;

    bp.type = p->type;
    bp.dir  = p->dir;
    switch ( p->size )
    {
    case 1:
        bp.size = 0;
        break;
    case 2:
        bp.size = 1;
        break;
    case 4:
        bp.size = 2;
        break;
    case 8:
        bp.size = 3;
        qw = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "unexpected ioreq size:%"PRId64"\n", p->size);
        return 0;
    }
    
    bp.data = p->data;
    bp.addr = p->addr;
    
    spin_lock(&iorp->lock);

    if ( (pg->write_pointer - pg->read_pointer) >=
         (IOREQ_BUFFER_SLOT_NUM - qw) )
    {
        /* The queue is full: send the iopacket through the normal path. */
        spin_unlock(&iorp->lock);
        return 0;
    }
    
    memcpy(&pg->buf_ioreq[pg->write_pointer % IOREQ_BUFFER_SLOT_NUM],
           &bp, sizeof(bp));
    
    if ( qw )
    {
        bp.data = p->data >> 32;
        memcpy(&pg->buf_ioreq[(pg->write_pointer+1) % IOREQ_BUFFER_SLOT_NUM],
               &bp, sizeof(bp));
    }

    /* Make the ioreq_t visible /before/ write_pointer. */
    wmb();
    pg->write_pointer += qw ? 2 : 1;

    spin_unlock(&iorp->lock);
    
    return 1;
}

int hvm_mmio_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    int i;

    for ( i = 0; i < HVM_MMIO_HANDLER_NR; i++ )
    {
        if ( hvm_mmio_handlers[i]->check_handler(v, p->addr) )
        {
            hvm_mmio_access(v, p,
                            hvm_mmio_handlers[i]->read_handler,
                            hvm_mmio_handlers[i]->write_handler);
            return 1;
        }
    }

    return 0;
}

static int process_portio_intercept(portio_action_t action, ioreq_t *p)
{
    int rc = 1, i, sign = p->df ? -1 : 1;
    uint32_t data;

    if ( p->dir == IOREQ_READ )
    {
        if ( !p->data_is_ptr )
        {
            rc = action(IOREQ_READ, p->addr, p->size, &data);
            p->data = data;
        }
        else
        {
            for ( i = 0; i < p->count; i++ )
            {
                rc = action(IOREQ_READ, p->addr, p->size, &data);
                (void)hvm_copy_to_guest_phys(p->data + sign*i*p->size,
                                             &data, p->size);
            }
        }
    }
    else /* p->dir == IOREQ_WRITE */
    {
        if ( !p->data_is_ptr )
        {
            data = p->data;
            rc = action(IOREQ_WRITE, p->addr, p->size, &data);
        }
        else
        {
            for ( i = 0; i < p->count; i++ )
            {
                data = 0;
                (void)hvm_copy_from_guest_phys(&data, p->data + sign*i*p->size,
                                               p->size);
                rc = action(IOREQ_WRITE, p->addr, p->size, &data);
            }
        }
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

    if ( (type == HVM_PORTIO) && (dpci_ioport_intercept(p)) )
        return 1;

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

    return 0;
}

int register_io_handler(
    struct domain *d, unsigned long addr, unsigned long size,
    void *action, int type)
{
    struct hvm_io_handler *handler = &d->arch.hvm_domain.io_handler;
    int num = handler->num_slot;

    BUG_ON(num >= MAX_IO_HANDLER);

    handler->hdl_list[num].addr = addr;
    handler->hdl_list[num].size = size;
    if ( (handler->hdl_list[num].type = type) == HVM_PORTIO )
        handler->hdl_list[num].action.portio = action;
    else
        handler->hdl_list[num].action.mmio = action;
    handler->num_slot++;

    return 1;
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
