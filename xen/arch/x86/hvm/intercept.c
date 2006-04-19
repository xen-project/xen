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


extern struct hvm_mmio_handler vlapic_mmio_handler;
extern struct hvm_mmio_handler vioapic_mmio_handler;

#define HVM_MMIO_HANDLER_NR 2

struct hvm_mmio_handler *hvm_mmio_handlers[HVM_MMIO_HANDLER_NR] =
{
    &vlapic_mmio_handler,
    &vioapic_mmio_handler
};

static inline void hvm_mmio_access(struct vcpu *v,
                                   ioreq_t *p,
                                   hvm_mmio_read_t read_handler,
                                   hvm_mmio_write_t write_handler)
{
    ioreq_t *req;
    vcpu_iodata_t *vio = get_vio(v->domain, v->vcpu_id);
    unsigned int tmp1, tmp2;
    unsigned long data;

    if (vio == NULL) {
        printk("vlapic_access: bad shared page\n");
        domain_crash_synchronous();
    }

    req = &vio->vp_ioreq;

    switch (req->type) {
    case IOREQ_TYPE_COPY:
    {
        int sign = (req->df) ? -1 : 1, i;

        if (!req->pdata_valid) {
            if (req->dir == IOREQ_READ){
                req->u.data = read_handler(v, req->addr, req->size);
            } else {                 /* req->dir != IOREQ_READ */
                write_handler(v, req->addr, req->size, req->u.data);
            }
        } else {                     /* !req->pdata_valid */
            if (req->dir == IOREQ_READ) {
                for (i = 0; i < req->count; i++) {
                    data = read_handler(v,
                      req->addr + (sign * i * req->size),
                      req->size);
                    hvm_copy(&data,
                      (unsigned long)p->u.pdata + (sign * i * req->size),
                      p->size,
                      HVM_COPY_OUT);
                }
            } else {                  /* !req->dir == IOREQ_READ */
                for (i = 0; i < req->count; i++) {
                    hvm_copy(&data,
                      (unsigned long)p->u.pdata + (sign * i * req->size),
                      p->size,
                      HVM_COPY_IN);
                    write_handler(v,
                      req->addr + (sign * i * req->size),
                      req->size, data);
                }
            }
        }
        break;
    }

    case IOREQ_TYPE_AND:
        tmp1 = read_handler(v, req->addr, req->size);
        if (req->dir == IOREQ_WRITE) {
            tmp2 = tmp1 & (unsigned long) req->u.data;
            write_handler(v, req->addr, req->size, tmp2);
        }
        req->u.data = tmp1;
        break;

    case IOREQ_TYPE_OR:
        tmp1 = read_handler(v, req->addr, req->size);
        if (req->dir == IOREQ_WRITE) {
            tmp2 = tmp1 | (unsigned long) req->u.data;
            write_handler(v, req->addr, req->size, tmp2);
        }
        req->u.data = tmp1;
        break;

    case IOREQ_TYPE_XOR:
        tmp1 = read_handler(v, req->addr, req->size);
        if (req->dir == IOREQ_WRITE) {
            tmp2 = tmp1 ^ (unsigned long) req->u.data;
            write_handler(v, req->addr, req->size, tmp2);
        }
        req->u.data = tmp1;
        break;

    case IOREQ_TYPE_XCHG:
        /* 
         * Note that we don't need to be atomic here since VCPU is accessing
         * its own local APIC.
         */
        tmp1 = read_handler(v, req->addr, req->size);
        write_handler(v, req->addr, req->size, (unsigned long) req->u.data);
        req->u.data = tmp1;
        break;

    default:
        printk("error ioreq type for local APIC %x\n", req->type);
        domain_crash_synchronous();
        break;
    }
}

int hvm_mmio_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    int i;

    /* XXX currently only APIC use intercept */
    if ( !hvm_apic_support(v->domain) )
        return 0;

    for ( i = 0; i < HVM_MMIO_HANDLER_NR; i++ ) {
        if ( hvm_mmio_handlers[i]->check_handler(v, p->addr) ) {
            hvm_mmio_access(v, p,
                            hvm_mmio_handlers[i]->read_handler,
                            hvm_mmio_handlers[i]->write_handler);
            return 1;
        }
    }
    return 0;
}

/*
 * Check if the request is handled inside xen
 * return value: 0 --not handled; 1 --handled
 */
int hvm_io_intercept(ioreq_t *p, int type)
{
    struct vcpu *v = current;
    struct hvm_io_handler *handler =
                           &(v->domain->arch.hvm_domain.io_handler);
    int i;
    unsigned long addr, size;

    for (i = 0; i < handler->num_slot; i++) {
        if( type != handler->hdl_list[i].type)
            continue;
        addr = handler->hdl_list[i].addr;
        size = handler->hdl_list[i].size;
        if (p->addr >= addr &&
            p->addr <  addr + size)
            return handler->hdl_list[i].action(p);
    }
    return 0;
}

int register_io_handler(unsigned long addr, unsigned long size,
                        intercept_action_t action, int type)
{
    struct vcpu *v = current;
    struct hvm_io_handler *handler =
                             &(v->domain->arch.hvm_domain.io_handler);
    int num = handler->num_slot;

    if (num >= MAX_IO_HANDLER) {
        printk("no extra space, register io interceptor failed!\n");
        domain_crash_synchronous();
    }

    handler->hdl_list[num].addr = addr;
    handler->hdl_list[num].size = size;
    handler->hdl_list[num].action = action;
    handler->hdl_list[num].type = type;
    handler->num_slot++;

    return 1;
}

/* hooks function for the HLT instruction emulation wakeup */
void hlt_timer_fn(void *data)
{
    struct vcpu *v = data;

    evtchn_set_pending(v, iopacket_port(v));
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
