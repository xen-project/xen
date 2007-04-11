/******************************************************************************
 * evtchn.c
 *
 * A simplified event channel for para-drivers in unmodified linux
 *
 * Copyright (c) 2002-2005, K A Fraser
 * Copyright (c) 2005, Intel Corporation <xiaofeng.ling@intel.com>
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <xen/evtchn.h>
#include <xen/interface/hvm/ioreq.h>
#include <xen/features.h>
#include "platform-pci.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

void *shared_info_area;

static DEFINE_MUTEX(irq_evtchn_mutex);

#define is_valid_evtchn(x)	((x) != 0)
#define evtchn_from_irq(x)	(irq_evtchn[irq].evtchn)

static struct {
	irqreturn_t(*handler) (int, void *, struct pt_regs *);
	void *dev_id;
	int evtchn;
	int close:1; /* close on unbind_from_irqhandler()? */
	int inuse:1;
} irq_evtchn[256];
static int evtchn_to_irq[NR_EVENT_CHANNELS] = {
	[0 ...  NR_EVENT_CHANNELS-1] = -1 };

static int find_unbound_irq(void)
{
	static int warned;
	int irq;

	for (irq = 0; irq < ARRAY_SIZE(irq_evtchn); irq++)
		if (!irq_evtchn[irq].inuse)
			return irq;

	if (!warned) {
		warned = 1;
		printk(KERN_WARNING "No available IRQ to bind to: "
		       "increase irq_evtchn[] size in evtchn.c.\n");
	}

	return -ENOSPC;
}

int irq_to_evtchn_port(int irq)
{
	return irq_evtchn[irq].evtchn;
}
EXPORT_SYMBOL(irq_to_evtchn_port);

void mask_evtchn(int port)
{
	shared_info_t *s = shared_info_area;
	synch_set_bit(port, &s->evtchn_mask[0]);
}
EXPORT_SYMBOL(mask_evtchn);

void unmask_evtchn(int port)
{
	unsigned int cpu;
	shared_info_t *s = shared_info_area;
	vcpu_info_t *vcpu_info;

	preempt_disable();
	cpu = smp_processor_id();
	vcpu_info = &s->vcpu_info[cpu];

	/* Slow path (hypercall) if this is a non-local port.  We only
	   ever bind event channels to vcpu 0 in HVM guests. */
	if (unlikely(cpu != 0)) {
		evtchn_unmask_t op = { .port = port };
		(void)HYPERVISOR_event_channel_op(EVTCHNOP_unmask,
						  &op);
		preempt_enable();
		return;
	}

	synch_clear_bit(port, &s->evtchn_mask[0]);

	/*
	 * The following is basically the equivalent of
	 * 'hw_resend_irq'. Just like a real IO-APIC we 'lose the
	 * interrupt edge' if the channel is masked.
	 */
	if (synch_test_bit(port, &s->evtchn_pending[0]) &&
	    !synch_test_and_set_bit(port / BITS_PER_LONG,
				    &vcpu_info->evtchn_pending_sel)) {
		vcpu_info->evtchn_upcall_pending = 1;
		if (!vcpu_info->evtchn_upcall_mask)
			force_evtchn_callback();
	}
	preempt_enable();
}
EXPORT_SYMBOL(unmask_evtchn);

int bind_listening_port_to_irqhandler(
	unsigned int remote_domain,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	struct evtchn_alloc_unbound alloc_unbound;
	int err, irq;

	mutex_lock(&irq_evtchn_mutex);

	irq = find_unbound_irq();
	if (irq < 0) {
		mutex_unlock(&irq_evtchn_mutex);
		return irq;
	}

	alloc_unbound.dom        = DOMID_SELF;
	alloc_unbound.remote_dom = remote_domain;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
					  &alloc_unbound);
	if (err) {
		mutex_unlock(&irq_evtchn_mutex);
		return err;
	}

	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = alloc_unbound.port;
	irq_evtchn[irq].close   = 1;
	irq_evtchn[irq].inuse   = 1;

	evtchn_to_irq[alloc_unbound.port] = irq;

	unmask_evtchn(alloc_unbound.port);

	mutex_unlock(&irq_evtchn_mutex);
	return irq;
}
EXPORT_SYMBOL(bind_listening_port_to_irqhandler);

int bind_caller_port_to_irqhandler(
	unsigned int caller_port,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq;

	mutex_lock(&irq_evtchn_mutex);

	irq = find_unbound_irq();
	if (irq < 0) {
		mutex_unlock(&irq_evtchn_mutex);
		return irq;
	}

	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = caller_port;
	irq_evtchn[irq].close   = 0;
	irq_evtchn[irq].inuse   = 1;

	evtchn_to_irq[caller_port] = irq;

	unmask_evtchn(caller_port);

	mutex_unlock(&irq_evtchn_mutex);
	return irq;
}
EXPORT_SYMBOL(bind_caller_port_to_irqhandler);

void unbind_from_irqhandler(unsigned int irq, void *dev_id)
{
	int evtchn = evtchn_from_irq(irq);

	mutex_lock(&irq_evtchn_mutex);

	if (is_valid_evtchn(evtchn)) {
		evtchn_to_irq[irq] = -1;
		mask_evtchn(evtchn);
		if (irq_evtchn[irq].close) {
			struct evtchn_close close = { .port = evtchn };
			HYPERVISOR_event_channel_op(EVTCHNOP_close, &close);
		}
	}

	irq_evtchn[irq].handler = NULL;
	irq_evtchn[irq].evtchn  = 0;
	irq_evtchn[irq].inuse   = 0;

	mutex_unlock(&irq_evtchn_mutex);
}
EXPORT_SYMBOL(unbind_from_irqhandler);

void notify_remote_via_irq(int irq)
{
	int evtchn = evtchn_from_irq(irq);
	if (is_valid_evtchn(evtchn))
		notify_remote_via_evtchn(evtchn);
}
EXPORT_SYMBOL(notify_remote_via_irq);

irqreturn_t evtchn_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned int l1i, port;
	/* XXX: All events are bound to vcpu0 but irq may be redirected. */
	int cpu = 0; /*smp_processor_id();*/
	irqreturn_t(*handler) (int, void *, struct pt_regs *);
	shared_info_t *s = shared_info_area;
	vcpu_info_t *v = &s->vcpu_info[cpu];
	unsigned long l1, l2;

	v->evtchn_upcall_pending = 0;
	/* NB. No need for a barrier here -- XCHG is a barrier on x86. */
	l1 = xchg(&v->evtchn_pending_sel, 0);
	while (l1 != 0) {
		l1i = __ffs(l1);
		l1 &= ~(1 << l1i);
		while ((l2 = s->evtchn_pending[l1i] & ~s->evtchn_mask[l1i])) {
			port = (l1i * BITS_PER_LONG) + __ffs(l2);
			synch_clear_bit(port, &s->evtchn_pending[0]);
			irq = evtchn_to_irq[port];
			if ((irq >= 0) &&
			    ((handler = irq_evtchn[irq].handler) != NULL))
				handler(irq, irq_evtchn[irq].dev_id, regs);
			else
				printk(KERN_WARNING "unexpected event channel "
				       "upcall on port %d!\n", port);
		}
	}

	return IRQ_HANDLED;
}

void force_evtchn_callback(void)
{
	(void)HYPERVISOR_xen_version(0, NULL);
}
EXPORT_SYMBOL(force_evtchn_callback);

void irq_suspend(void)
{
	mutex_lock(&irq_evtchn_mutex);
}

void irq_suspend_cancel(void)
{
	mutex_unlock(&irq_evtchn_mutex);
}

void irq_resume(void)
{
	int evtchn, irq;

	for (evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++) {
		mask_evtchn(evtchn);
		evtchn_to_irq[evtchn] = -1;
	}

	for (irq = 0; irq < ARRAY_SIZE(irq_evtchn); irq++)
		irq_evtchn[irq].evtchn = 0;

	mutex_unlock(&irq_evtchn_mutex);
}
