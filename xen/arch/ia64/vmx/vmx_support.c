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
    ioreq_t *p = get_vio(v);

    if (p->state == STATE_IORESP_READY) {
        p->state = STATE_IOREQ_NONE;
    }
    else {
        /* Can't block here, for the same reason as other places to
         * use vmx_wait_io. Simple return is safe since vmx_wait_io will
         * try to block again
         */
        return;
    }
}

void vmx_send_assist_req(struct vcpu *v)
{
    ioreq_t *p = get_vio(v);

    if (unlikely(p->state != STATE_IOREQ_NONE)) {
        /* This indicates a bug in the device model.  Crash the
           domain. */
        printk("Device model set bad IO state %d.\n", p->state);
        domain_crash(v->domain);
        return;
    }
    wmb();
    p->state = STATE_IOREQ_READY;
    notify_via_xen_event_channel(v->arch.arch_vmx.xen_port);

    for (;;) {
        if (p->state != STATE_IOREQ_READY &&
            p->state != STATE_IOREQ_INPROCESS)
            break;

        set_bit(_VPF_blocked_in_xen, &current->pause_flags);
        mb(); /* set blocked status /then/ re-evaluate condition */
        if (p->state != STATE_IOREQ_READY &&
            p->state != STATE_IOREQ_INPROCESS)
        {
            clear_bit(_VPF_blocked_in_xen, &current->pause_flags);
            break;
        }

        raise_softirq(SCHEDULE_SOFTIRQ);
        do_softirq();
        mb();
    }

    /* the code under this line is completer phase... */
    vmx_io_assist(v);
}
