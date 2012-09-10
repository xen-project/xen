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
#include <linux/spinlock.h>
#include <xen/evtchn.h>
#include <xen/interface/hvm/ioreq.h>
#include <xen/features.h>
#include "platform-pci.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

void *shared_info_area;

#define is_valid_evtchn(x)	((x) != 0)
#define evtchn_from_irq(x)	(irq_evtchn[irq].evtchn)

static struct {
	spinlock_t lock;
	irq_handler_t handler;
	void *dev_id;
	int evtchn;
	int close:1; /* close on unbind_from_irqhandler()? */
	int inuse:1;
	int in_handler:1;
} irq_evtchn[256];
static int evtchn_to_irq[NR_EVENT_CHANNELS] = {
	[0 ...  NR_EVENT_CHANNELS-1] = -1 };

static DEFINE_SPINLOCK(irq_alloc_lock);

static int alloc_xen_irq(void)
{
	static int warned;
	int irq;

	spin_lock(&irq_alloc_lock);

	for (irq = 1; irq < ARRAY_SIZE(irq_evtchn); irq++) {
		if (irq_evtchn[irq].inuse) 
			continue;
		irq_evtchn[irq].inuse = 1;
		spin_unlock(&irq_alloc_lock);
		return irq;
	}

	if (!warned) {
		warned = 1;
		printk(KERN_WARNING "No available IRQ to bind to: "
		       "increase irq_evtchn[] size in evtchn.c.\n");
	}

	spin_unlock(&irq_alloc_lock);

	return -ENOSPC;
}

static void free_xen_irq(int irq)
{
	spin_lock(&irq_alloc_lock);
	irq_evtchn[irq].inuse = 0;
	spin_unlock(&irq_alloc_lock);
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
	evtchn_unmask_t op = { .port = port };
	VOID(HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &op));
}
EXPORT_SYMBOL(unmask_evtchn);

int bind_listening_port_to_irqhandler(
	unsigned int remote_domain,
	irq_handler_t handler,
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	struct evtchn_alloc_unbound alloc_unbound;
	int err, irq;

	irq = alloc_xen_irq();
	if (irq < 0)
		return irq;

	spin_lock_irq(&irq_evtchn[irq].lock);

	alloc_unbound.dom        = DOMID_SELF;
	alloc_unbound.remote_dom = remote_domain;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
					  &alloc_unbound);
	if (err) {
		spin_unlock_irq(&irq_evtchn[irq].lock);
		free_xen_irq(irq);
		return err;
	}

	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = alloc_unbound.port;
	irq_evtchn[irq].close   = 1;

	evtchn_to_irq[alloc_unbound.port] = irq;

	unmask_evtchn(alloc_unbound.port);

	spin_unlock_irq(&irq_evtchn[irq].lock);

	return irq;
}
EXPORT_SYMBOL(bind_listening_port_to_irqhandler);

int bind_caller_port_to_irqhandler(
	unsigned int caller_port,
	irq_handler_t handler,
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq;

	irq = alloc_xen_irq();
	if (irq < 0)
		return irq;

	spin_lock_irq(&irq_evtchn[irq].lock);

	irq_evtchn[irq].handler = handler;
	irq_evtchn[irq].dev_id  = dev_id;
	irq_evtchn[irq].evtchn  = caller_port;
	irq_evtchn[irq].close   = 0;

	evtchn_to_irq[caller_port] = irq;

	unmask_evtchn(caller_port);

	spin_unlock_irq(&irq_evtchn[irq].lock);

	return irq;
}
EXPORT_SYMBOL(bind_caller_port_to_irqhandler);

void unbind_from_irqhandler(unsigned int irq, void *dev_id)
{
	int evtchn;

	spin_lock_irq(&irq_evtchn[irq].lock);

	evtchn = evtchn_from_irq(irq);

	if (is_valid_evtchn(evtchn)) {
		evtchn_to_irq[evtchn] = -1;
		mask_evtchn(evtchn);
		if (irq_evtchn[irq].close) {
			struct evtchn_close close = { .port = evtchn };
			if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close))
				BUG();
		}
	}

	irq_evtchn[irq].handler = NULL;
	irq_evtchn[irq].evtchn  = 0;

	spin_unlock_irq(&irq_evtchn[irq].lock);

	while (irq_evtchn[irq].in_handler)
		cpu_relax();

	free_xen_irq(irq);
}
EXPORT_SYMBOL(unbind_from_irqhandler);

void notify_remote_via_irq(int irq)
{
	int evtchn;

	evtchn = evtchn_from_irq(irq);
	if (is_valid_evtchn(evtchn))
		notify_remote_via_evtchn(evtchn);
}
EXPORT_SYMBOL(notify_remote_via_irq);

static DEFINE_PER_CPU(unsigned int, last_processed_l1i) = { BITS_PER_LONG - 1 };
static DEFINE_PER_CPU(unsigned int, last_processed_l2i) = { BITS_PER_LONG - 1 };

static inline unsigned long active_evtchns(unsigned int cpu, shared_info_t *sh,
						unsigned int idx)
{
	return (sh->evtchn_pending[idx] & ~sh->evtchn_mask[idx]);
}

static irqreturn_t evtchn_interrupt(int irq, void *dev_id
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
				    , struct pt_regs *regs
#else
# define handler(irq, dev_id, regs) handler(irq, dev_id)
#endif
				    )
{
	unsigned int l1i, l2i, port;
	unsigned long masked_l1, masked_l2;
	/* XXX: All events are bound to vcpu0 but irq may be redirected. */
	int cpu = 0; /*smp_processor_id();*/
	irq_handler_t handler;
	shared_info_t *s = shared_info_area;
	vcpu_info_t *v = &s->vcpu_info[cpu];
	unsigned long l1, l2;

	v->evtchn_upcall_pending = 0;

#ifndef CONFIG_X86 /* No need for a barrier -- XCHG is a barrier on x86. */
	/* Clear master flag /before/ clearing selector flag. */
	wmb();
#endif
	l1 = xchg(&v->evtchn_pending_sel, 0);

	l1i = per_cpu(last_processed_l1i, cpu);
	l2i = per_cpu(last_processed_l2i, cpu);

	while (l1 != 0) {

		l1i = (l1i + 1) % BITS_PER_LONG;
		masked_l1 = l1 & ((~0UL) << l1i);

		if (masked_l1 == 0) { /* if we masked out all events, wrap around to the beginning */
			l1i = BITS_PER_LONG - 1;
			l2i = BITS_PER_LONG - 1;
			continue;
		}
		l1i = __ffs(masked_l1);

		do {
			l2 = active_evtchns(cpu, s, l1i);

			l2i = (l2i + 1) % BITS_PER_LONG;
			masked_l2 = l2 & ((~0UL) << l2i);

			if (masked_l2 == 0) { /* if we masked out all events, move on */
				l2i = BITS_PER_LONG - 1;
				break;
			}
			l2i = __ffs(masked_l2);

			/* process port */
			port = (l1i * BITS_PER_LONG) + l2i;
			synch_clear_bit(port, &s->evtchn_pending[0]);

			irq = evtchn_to_irq[port];
			if (irq < 0)
				continue;

			spin_lock(&irq_evtchn[irq].lock);
			handler = irq_evtchn[irq].handler;
			dev_id  = irq_evtchn[irq].dev_id;
			if (unlikely(handler == NULL)) {
				printk("Xen IRQ%d (port %d) has no handler!\n",
				       irq, port);
				spin_unlock(&irq_evtchn[irq].lock);
				continue;
			}
			irq_evtchn[irq].in_handler = 1;
			spin_unlock(&irq_evtchn[irq].lock);

			local_irq_enable();
			handler(irq, irq_evtchn[irq].dev_id, regs);
			local_irq_disable();

			spin_lock(&irq_evtchn[irq].lock);
			irq_evtchn[irq].in_handler = 0;
			spin_unlock(&irq_evtchn[irq].lock);

			/* if this is the final port processed, we'll pick up here+1 next time */
			per_cpu(last_processed_l1i, cpu) = l1i;
			per_cpu(last_processed_l2i, cpu) = l2i;

		} while (l2i != BITS_PER_LONG - 1);

		l2 = active_evtchns(cpu, s, l1i);
		if (l2 == 0) /* we handled all ports, so we can clear the selector bit */
			l1 &= ~(1UL << l1i);
	}

	return IRQ_HANDLED;
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
}

int xen_irq_init(struct pci_dev *pdev)
{
	int irq;

	for (irq = 0; irq < ARRAY_SIZE(irq_evtchn); irq++)
		spin_lock_init(&irq_evtchn[irq].lock);

	return request_irq(pdev->irq, evtchn_interrupt,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
			   SA_SHIRQ | SA_SAMPLE_RANDOM | SA_INTERRUPT,
#else
			   IRQF_SHARED |
#ifdef IRQF_SAMPLE_RANDOM
			   IRQF_SAMPLE_RANDOM |
#endif
			   IRQF_DISABLED,
#endif
			   "xen-platform-pci", pdev);
}
