/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_support.c: vmx specific support interface.
 * Copyright (c) 2005, Intel Corporation.
 *	Kun Tian (Kevin Tian) (Kevin.tian@intel.com)
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
 *
 */
#include <xen/config.h>
#include <xen/sched.h>
#include <xen/hypercall.h>
#include <xen/event.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>

/*
 * Only place to call vmx_io_assist is mmio/legacy_io emulation.
 * Since I/O emulation is synchronous, it shouldn't be called in
 * other places. This is not like x86, since IA-64 implements a
 * per-vp stack without continuation.
 */
void vmx_io_assist(struct vcpu *v)
{
    vcpu_iodata_t *vio;
    ioreq_t *p;

    /*
     * This shared page contains I/O request between emulation code
     * and device model.
     */
    vio = get_vio(v->domain, v->vcpu_id);
    if (!vio)
	panic_domain(vcpu_regs(v),"Corruption: bad shared page: %lx\n", (unsigned long)vio);

    p = &vio->vp_ioreq;

    if (p->state == STATE_IORESP_READY) {
        p->state = STATE_INVALID;
    }
    else {
        /* Can't block here, for the same reason as other places to
         * use vmx_wait_io. Simple return is safe since vmx_wait_io will
         * try to block again
         */
        return;
    }
}

/*
 * VMX domainN has two types of interrupt source: lsapic model within
 * HV, and device model within domain 0 (service OS). There're another
 * pending array in share page, manipulated by device model directly.
 * To conform to VT-i spec, we have to sync pending bits in shared page
 * into VPD. This has to be done before checking pending interrupt at
 * resume to guest. For domain 0, all the interrupt sources come from
 * HV, which then doesn't require this assist.
 */
void vmx_intr_assist(struct vcpu *v)
{
#ifdef V_IOSAPIC_READY
    /* Confirm virtual interrupt line signals, and set pending bits in vpd */
    if(v->vcpu_id==0)
        vmx_virq_line_assist(v);
#endif
    return;
}

void vmx_send_assist_req(struct vcpu *v)
{
    ioreq_t *p;

    p = &get_vio(v->domain, v->vcpu_id)->vp_ioreq;
    if (unlikely(p->state != STATE_INVALID)) {
        /* This indicates a bug in the device model.  Crash the
           domain. */
        printk("Device model set bad IO state %d.\n", p->state);
        domain_crash(v->domain);
        return;
    }
    wmb();
    p->state = STATE_IOREQ_READY;
    notify_via_xen_event_channel(v->arch.arch_vmx.xen_port);

    /*
     * Waiting for MMIO completion
     *   like the wait_on_xen_event_channel() macro like...
     *   but, we can't call do_softirq() at this point..
     */
    for (;;) {
        if (p->state != STATE_IOREQ_READY &&
            p->state != STATE_IOREQ_INPROCESS)
            break;

        set_bit(_VCPUF_blocked_in_xen, &current->vcpu_flags);
        mb(); /* set blocked status /then/ re-evaluate condition */
        if (p->state != STATE_IOREQ_READY &&
            p->state != STATE_IOREQ_INPROCESS)
        {
            clear_bit(_VCPUF_blocked_in_xen, &current->vcpu_flags);
            break;
        }

        /* I want to call __enter_scheduler() only */
        do_sched_op_compat(SCHEDOP_yield, 0);
        mb();
    }

    /* the code under this line is completer phase... */
    vmx_io_assist(v);
}

/* Wake up a vcpu whihc is waiting for interrupts to come in */
void vmx_prod_vcpu(struct vcpu *v)
{
    vcpu_unblock(v);
}
