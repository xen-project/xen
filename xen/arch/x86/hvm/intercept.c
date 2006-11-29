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

static struct hvm_mmio_handler *hvm_mmio_handlers[HVM_MMIO_HANDLER_NR] =
{
    &vlapic_mmio_handler,
    &vioapic_mmio_handler
};

struct hvm_buffered_io_range {
    unsigned long start_addr;
    unsigned long length;
};

#define HVM_BUFFERED_IO_RANGE_NR 1

static struct hvm_buffered_io_range buffered_stdvga_range = {0xA0000, 0x20000};
static struct hvm_buffered_io_range
*hvm_buffered_io_ranges[HVM_BUFFERED_IO_RANGE_NR] =
{
    &buffered_stdvga_range
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

    default:
        printk("hvm_mmio_access: error ioreq type %x\n", p->type);
        domain_crash_synchronous();
        break;
    }
}

int hvm_buffered_io_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    spinlock_t  *buffered_io_lock;
    buffered_iopage_t *buffered_iopage =
        (buffered_iopage_t *)(v->domain->arch.hvm_domain.buffered_io_va);
    unsigned long tmp_write_pointer = 0;
    int i;

    /* ignore READ ioreq_t! */
    if ( p->dir == IOREQ_READ )
        return 0;

    for ( i = 0; i < HVM_BUFFERED_IO_RANGE_NR; i++ ) {
        if ( p->addr >= hvm_buffered_io_ranges[i]->start_addr &&
             p->addr + p->size - 1 < hvm_buffered_io_ranges[i]->start_addr +
                                     hvm_buffered_io_ranges[i]->length )
            break;
    }

    if ( i == HVM_BUFFERED_IO_RANGE_NR )
        return 0;

    buffered_io_lock = &v->domain->arch.hvm_domain.buffered_io_lock;
    spin_lock(buffered_io_lock);

    if ( buffered_iopage->write_pointer - buffered_iopage->read_pointer ==
         (unsigned long)IOREQ_BUFFER_SLOT_NUM ) {
        /* the queue is full.
         * send the iopacket through the normal path.
         * NOTE: The arithimetic operation could handle the situation for
         * write_pointer overflow.
         */
        spin_unlock(buffered_io_lock);
        return 0;
    }

    tmp_write_pointer = buffered_iopage->write_pointer % IOREQ_BUFFER_SLOT_NUM;

    memcpy(&buffered_iopage->ioreq[tmp_write_pointer], p, sizeof(ioreq_t));

    /*make the ioreq_t visible before write_pointer*/
    wmb();
    buffered_iopage->write_pointer++;

    spin_unlock(buffered_io_lock);

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

int register_io_handler(
    struct domain *d, unsigned long addr, unsigned long size,
    intercept_action_t action, int type)
{
    struct hvm_io_handler *handler = &d->arch.hvm_domain.io_handler;
    int num = handler->num_slot;

    BUG_ON(num >= MAX_IO_HANDLER);

    handler->hdl_list[num].addr = addr;
    handler->hdl_list[num].size = size;
    handler->hdl_list[num].action = action;
    handler->hdl_list[num].type = type;
    handler->num_slot++;

    return 1;
}

static __inline__ void missed_ticks(struct periodic_time *pt)
{
    s_time_t missed_ticks;

    missed_ticks = NOW() - pt->scheduled;
    if ( missed_ticks > 0 ) {
        missed_ticks = missed_ticks / (s_time_t) pt->period + 1;
        if ( missed_ticks > 1000 ) {
            /* TODO: Adjust guest time togther */
            pt->pending_intr_nr++;
        }
        else {
            pt->pending_intr_nr += missed_ticks;
        }
        pt->scheduled += missed_ticks * pt->period;
    }
}

/* hook function for the platform periodic time */
void pt_timer_fn(void *data)
{
    struct vcpu *v = data;
    struct periodic_time *pt = &v->domain->arch.hvm_domain.pl_time.periodic_tm;

    pt->pending_intr_nr++;
    pt->scheduled += pt->period;

    /* Pick up missed timer ticks. */
    missed_ticks(pt);

    /* No need to run the timer while a VCPU is descheduled. */
    if ( test_bit(_VCPUF_running, &v->vcpu_flags) )
        set_timer(&pt->timer, pt->scheduled);

    vcpu_kick(v);
}

/* pick up missed timer ticks at deactive time */
void pickup_deactive_ticks(struct periodic_time *pt)
{
    if ( !active_timer(&(pt->timer)) ) {
        missed_ticks(pt);
        set_timer(&pt->timer, pt->scheduled);
    }
}

/*
 * period: fire frequency in ns.
 */
struct periodic_time * create_periodic_time(
        u32 period, 
        char irq,
        char one_shot,
        time_cb *cb,
        void *data)
{
    struct periodic_time *pt = &(current->domain->arch.hvm_domain.pl_time.periodic_tm);
    if ( pt->enabled ) {
        stop_timer (&pt->timer);
        pt->enabled = 0;
    }
    pt->bind_vcpu = 0; /* timer interrupt delivered to BSP by default */
    pt->pending_intr_nr = 0;
    pt->first_injected = 0;
    if (period < 900000) { /* < 0.9 ms */
        printk("HVM_PlatformTime: program too small period %u\n",period);
        period = 900000;   /* force to 0.9ms */
    }
    pt->period = period;
    pt->irq = irq;
    pt->period_cycles = (u64)period * cpu_khz / 1000000L;
    pt->one_shot = one_shot;
    if ( one_shot ) {
        printk("HVM_PL: No support for one shot platform time yet\n");
    }
    pt->scheduled = NOW() + period;
    set_timer (&pt->timer,pt->scheduled);
    pt->enabled = 1;
    pt->cb = cb;
    pt->priv = data;
    return pt;
}

void destroy_periodic_time(struct periodic_time *pt)
{
    if ( pt->enabled ) {
        stop_timer(&pt->timer);
        pt->enabled = 0;
    }
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
