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

static void pit_cal_count(struct hvm_virpit *vpit)
{
    u64 nsec_delta = (unsigned int)((NOW() - vpit->count_point));

    nsec_delta += vpit->count_advance;
    if (nsec_delta > vpit->period)
        HVM_DBG_LOG(DBG_LEVEL_1,
	            "HVM_PIT: long time has passed from last injection!");

    if(vpit->init_val == 0)
    {
        printk("PIT init value == 0!\n");
        domain_crash_synchronous();
    }

    vpit->count = vpit->init_val
                  - ((nsec_delta * PIT_FREQ / 1000000000ULL) % vpit->init_val);
}

static void pit_latch_io(struct hvm_virpit *vpit)
{
    pit_cal_count(vpit);

    switch(vpit->read_state) {
    case MSByte:
        vpit->count_MSB_latched=1;
        break;
    case LSByte:
        vpit->count_LSB_latched=1;
        break;
    case LSByte_multiple:
        vpit->count_LSB_latched=1;
        vpit->count_MSB_latched=1;
        break;
    case MSByte_multiple:
        HVM_DBG_LOG(DBG_LEVEL_1,
	            "HVM_PIT: latch PIT counter before MSB_multiple!");
        vpit->read_state=LSByte_multiple;
        vpit->count_LSB_latched=1;
        vpit->count_MSB_latched=1;
        break;
    default:
        domain_crash_synchronous();
    }
}

static int pit_read_io(struct hvm_virpit *vpit)
{
    if(vpit->count_LSB_latched) {
        /* Read Least Significant Byte */
        if(vpit->read_state==LSByte_multiple) {
            vpit->read_state=MSByte_multiple;
        }
        vpit->count_LSB_latched=0;
        return (vpit->count & 0xFF);
    } else if(vpit->count_MSB_latched) {
        /* Read Most Significant Byte */
        if(vpit->read_state==MSByte_multiple) {
            vpit->read_state=LSByte_multiple;
        }
        vpit->count_MSB_latched=0;
        return ((vpit->count>>8) & 0xFF);
    } else {
        /* Unlatched Count Read */
        HVM_DBG_LOG(DBG_LEVEL_1, "HVM_PIT: unlatched read");
        pit_cal_count(vpit);
        if(!(vpit->read_state & 0x1)) {
            /* Read Least Significant Byte */
            if(vpit->read_state==LSByte_multiple) {
                vpit->read_state=MSByte_multiple;
            }
            return (vpit->count & 0xFF);
        } else {
            /* Read Most Significant Byte */
            if(vpit->read_state==MSByte_multiple) {
                vpit->read_state=LSByte_multiple;
            }
            return ((vpit->count>>8) & 0xFF);
        }
    }
}

/* hvm_io_assist light-weight version, specific to PIT DM */ 
static void resume_pit_io(ioreq_t *p)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned long old_eax = regs->eax;
    p->state = STATE_INVALID;

    switch(p->size) {
    case 1:
        regs->eax = (old_eax & 0xffffff00) | (p->u.data & 0xff);
        break;
    case 2:
        regs->eax = (old_eax & 0xffff0000) | (p->u.data & 0xffff);
        break;
    case 4:
        regs->eax = (p->u.data & 0xffffffff);
        break;
    default:
        BUG();
    }
}

/* the intercept action for PIT DM retval:0--not handled; 1--handled */
int intercept_pit_io(ioreq_t *p)
{
    struct vcpu *v = current;
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    if (p->size != 1 ||
        p->pdata_valid ||
        p->type != IOREQ_TYPE_PIO)
        return 0;
    
    if (p->addr == PIT_MODE &&
        p->dir == 0 &&    /* write */
        ((p->u.data >> 4) & 0x3) == 0 && /* latch command */
        ((p->u.data >> 6) & 0x3) == (vpit->channel)) {/* right channel */
        pit_latch_io(vpit);
        return 1;
    }

    if (p->addr == (PIT_CH0 + vpit->channel) &&
        p->dir == 1) { /* read */
        p->u.data = pit_read_io(vpit);
        resume_pit_io(p);
        return 1;
    }

    return 0;
}

/* hooks function for the HLT instruction emulation wakeup */
void hlt_timer_fn(void *data)
{
    struct vcpu *v = data;

    evtchn_set_pending(v, iopacket_port(v));
}

static __inline__ void missed_ticks(struct hvm_virpit*vpit)
{
    int missed_ticks;

    missed_ticks = (NOW() - vpit->scheduled)/(s_time_t) vpit->period;
    if ( missed_ticks++ >= 0 ) {
        vpit->pending_intr_nr += missed_ticks;
        vpit->scheduled += missed_ticks * vpit->period;
    }
}

/* hooks function for the PIT when the guest is active */
static void pit_timer_fn(void *data)
{
    struct vcpu *v = data;
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    /* pick up missed timer tick */
    missed_ticks(vpit);
    if ( test_bit(_VCPUF_running, &v->vcpu_flags) ) {
        set_timer(&vpit->pit_timer, vpit->scheduled);
    }
}

/* pick up missed timer ticks at deactive time */
void pickup_deactive_ticks(struct hvm_virpit *vpit)
{
    if ( !active_timer(&(vpit->pit_timer)) ) {
        missed_ticks(vpit);
        set_timer(&vpit->pit_timer, vpit->scheduled);
    }
}

/* Only some PIT operations such as load init counter need a hypervisor hook.
 * leave all other operations in user space DM
 */
void hvm_hooks_assist(struct vcpu *v)
{
    vcpu_iodata_t *vio = get_vio(v->domain, v->vcpu_id);
    ioreq_t *p = &vio->vp_ioreq;
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);
    int rw_mode, reinit = 0;

    /* load init count*/
    if (p->state == STATE_IORESP_HOOK) {
        /* set up actimer, handle re-init */
        if ( active_timer(&(vpit->pit_timer)) ) {
            HVM_DBG_LOG(DBG_LEVEL_1, "HVM_PIT: guest reset PIT with channel %lx!\n", (unsigned long) ((p->u.data >> 24) & 0x3) );
            stop_timer(&(vpit->pit_timer));
            reinit = 1;
 
        }
        else {
            init_timer(&vpit->pit_timer, pit_timer_fn, v, v->processor);
        }

        /* init count for this channel */
        vpit->init_val = (p->u.data & 0xFFFF) ;
        /* frequency(ns) of pit */
        vpit->period = DIV_ROUND(((vpit->init_val) * 1000000000ULL), PIT_FREQ);
        HVM_DBG_LOG(DBG_LEVEL_1,"HVM_PIT: guest set init pit freq:%u ns, initval:0x%x\n", vpit->period, vpit->init_val);
        if (vpit->period < 900000) { /* < 0.9 ms */
            printk("HVM_PIT: guest programmed too small an init_val: %x\n",
                   vpit->init_val);
            vpit->period = 1000000;
        }
         vpit->period_cycles = (u64)vpit->period * cpu_khz / 1000000L;
         printk("HVM_PIT: guest freq in cycles=%lld\n",(long long)vpit->period_cycles);

        vpit->channel = ((p->u.data >> 24) & 0x3);
        vpit->first_injected = 0;

        vpit->count_LSB_latched = 0;
        vpit->count_MSB_latched = 0;

        rw_mode = ((p->u.data >> 26) & 0x3);
        switch(rw_mode) {
        case 0x1:
            vpit->read_state=LSByte;
            break;
        case 0x2:
            vpit->read_state=MSByte;
            break;
        case 0x3:
            vpit->read_state=LSByte_multiple;
            break;
        default:
            printk("HVM_PIT:wrong PIT rw_mode!\n");
            break;
        }

        vpit->scheduled = NOW() + vpit->period;
        set_timer(&vpit->pit_timer, vpit->scheduled);

        /*restore the state*/
        p->state = STATE_IORESP_READY;

        /* register handler to intercept the PIT io when vm_exit */
        if (!reinit) {
            register_portio_handler(0x40, 4, intercept_pit_io); 
        }
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
