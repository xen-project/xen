
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
#include <public/io/ioreq.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>

/*
 * I/O emulation should be atomic from domain point of view. However,
 * when emulation code is waiting for I/O completion by do_block,
 * other events like DM interrupt, VBD, etc. may come and unblock
 * current exection flow. So we have to prepare for re-block if unblocked
 * by non I/O completion event.
 */
void vmx_wait_io(void)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    extern void do_block();
    int port = iopacket_port(d);

    do {
	if (!test_bit(port,
		&d->shared_info->evtchn_pending[0]))
	    do_block();

	/* Unblocked when some event is coming. Clear pending indication
	 * immediately if deciding to go for io assist
	  */
	if (test_and_clear_bit(port,
		&d->shared_info->evtchn_pending[0])) {
	    clear_bit(port/BITS_PER_LONG, &v->vcpu_info->evtchn_pending_sel);
	    clear_bit(0, &v->vcpu_info->evtchn_upcall_pending);
	    vmx_io_assist(v);
	}


	if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags)) {
	    /*
	     * Latest event is not I/O completion, so clear corresponding
	     * selector and pending indication, to allow real event coming
	     */
	    clear_bit(0, &v->vcpu_info->evtchn_upcall_pending);

	    /* Here atually one window is leaved before selector is cleared.
	     * However this window only delay the indication to coming event,
	     * nothing losed. Next loop will check I/O channel to fix this
	     * window.
	     */
	    clear_bit(port/BITS_PER_LONG, &v->vcpu_info->evtchn_pending_sel);
	}
	else
	    break;
    } while (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags));
}

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
	panic("Corruption: bad shared page: %lx\n", (unsigned long)vio);

    p = &vio->vp_ioreq;

    if (p->state == STATE_IORESP_HOOK)
	panic("Not supported: No hook available for DM request\n");

    if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags)) {
	if (p->state != STATE_IORESP_READY) {
	    /* Can't do_block here, for the same reason as other places to
	     * use vmx_wait_io. Simple return is safe since vmx_wait_io will
	     * try to block again
	     */
	    return; 
	} else
	    p->state = STATE_INVALID;

	clear_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags);
    } else
	return; /* Spurous event? */
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
    vcpu_iodata_t *vio;
    struct domain *d = v->domain;
    extern void vmx_vcpu_pend_batch_interrupt(VCPU *vcpu,
					unsigned long *pend_irr);
    int port = iopacket_port(d);

    /* I/O emulation is atomic, so it's impossible to see execution flow
     * out of vmx_wait_io, when guest is still waiting for response.
     */
    if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags))
	panic("!!!Bad resume to guest before I/O emulation is done.\n");

    /* Clear indicator specific to interrupt delivered from DM */
    if (test_and_clear_bit(port,
		&d->shared_info->evtchn_pending[0])) {
	if (!d->shared_info->evtchn_pending[port/BITS_PER_LONG])
	    clear_bit(port/BITS_PER_LONG, &v->vcpu_info->evtchn_pending_sel);

	if (!v->vcpu_info->evtchn_pending_sel)
	    clear_bit(0, &v->vcpu_info->evtchn_upcall_pending);
    }

    /* Even without event pending, we still need to sync pending bits
     * between DM and vlsapic. The reason is that interrupt delivery
     * shares same event channel as I/O emulation, with corresponding
     * indicator possibly cleared when vmx_wait_io().
     */
    vio = get_vio(v->domain, v->vcpu_id);
    if (!vio)
	panic("Corruption: bad shared page: %lx\n", (unsigned long)vio);

#ifdef V_IOSAPIC_READY
    /* Confirm virtual interrupt line signals, and set pending bits in vpd */
    vmx_virq_line_assist(v);
#endif
    return;
}
