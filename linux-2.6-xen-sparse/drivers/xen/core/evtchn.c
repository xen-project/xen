/******************************************************************************
 * evtchn.c
 * 
 * Communication via Xen event channels.
 * 
 * Copyright (c) 2002-2005, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/version.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/synch_bitops.h>
#include <xen/evtchn.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/physdev.h>
#include <asm/hypervisor.h>
#include <linux/mc146818rtc.h> /* RTC_IRQ */

/*
 * This lock protects updates to the following mapping and reference-count
 * arrays. The lock does not need to be acquired to read the mapping tables.
 */
static DEFINE_SPINLOCK(irq_mapping_update_lock);

/* IRQ <-> event-channel mappings. */
static int evtchn_to_irq[NR_EVENT_CHANNELS] = {
	[0 ...  NR_EVENT_CHANNELS-1] = -1 };

/* Packed IRQ information: binding type, sub-type index, and event channel. */
static u32 irq_info[NR_IRQS];

/* Binding types. */
enum {
	IRQT_UNBOUND,
	IRQT_PIRQ,
	IRQT_VIRQ,
	IRQT_IPI,
	IRQT_LOCAL_PORT,
	IRQT_CALLER_PORT
};

/* Constructor for packed IRQ information. */
static inline u32 mk_irq_info(u32 type, u32 index, u32 evtchn)
{
	return ((type << 24) | (index << 16) | evtchn);
}

/* Convenient shorthand for packed representation of an unbound IRQ. */
#define IRQ_UNBOUND	mk_irq_info(IRQT_UNBOUND, 0, 0)

/*
 * Accessors for packed IRQ information.
 */

static inline unsigned int evtchn_from_irq(int irq)
{
	return (u16)(irq_info[irq]);
}

static inline unsigned int index_from_irq(int irq)
{
	return (u8)(irq_info[irq] >> 16);
}

static inline unsigned int type_from_irq(int irq)
{
	return (u8)(irq_info[irq] >> 24);
}

/* IRQ <-> VIRQ mapping. */
DEFINE_PER_CPU(int, virq_to_irq[NR_VIRQS]) = {[0 ... NR_VIRQS-1] = -1};

/* IRQ <-> IPI mapping. */
#ifndef NR_IPIS
#define NR_IPIS 1
#endif
DEFINE_PER_CPU(int, ipi_to_irq[NR_IPIS]) = {[0 ... NR_IPIS-1] = -1};

/* Reference counts for bindings to IRQs. */
static int irq_bindcount[NR_IRQS];

/* Bitmap indicating which PIRQs require Xen to be notified on unmask. */
static DECLARE_BITMAP(pirq_needs_eoi, NR_PIRQS);

#ifdef CONFIG_SMP

static u8 cpu_evtchn[NR_EVENT_CHANNELS];
static unsigned long cpu_evtchn_mask[NR_CPUS][NR_EVENT_CHANNELS/BITS_PER_LONG];

static inline unsigned long active_evtchns(unsigned int cpu, shared_info_t *sh,
					   unsigned int idx)
{
	return (sh->evtchn_pending[idx] &
		cpu_evtchn_mask[cpu][idx] &
		~sh->evtchn_mask[idx]);
}

static void bind_evtchn_to_cpu(unsigned int chn, unsigned int cpu)
{
	int irq = evtchn_to_irq[chn];

	BUG_ON(irq == -1);
	set_native_irq_info(irq, cpumask_of_cpu(cpu));

	clear_bit(chn, (unsigned long *)cpu_evtchn_mask[cpu_evtchn[chn]]);
	set_bit(chn, (unsigned long *)cpu_evtchn_mask[cpu]);
	cpu_evtchn[chn] = cpu;
}

static void init_evtchn_cpu_bindings(void)
{
	int i;

	/* By default all event channels notify CPU#0. */
	for (i = 0; i < NR_IRQS; i++)
		set_native_irq_info(i, cpumask_of_cpu(0));

	memset(cpu_evtchn, 0, sizeof(cpu_evtchn));
	memset(cpu_evtchn_mask[0], ~0, sizeof(cpu_evtchn_mask[0]));
}

static inline unsigned int cpu_from_evtchn(unsigned int evtchn)
{
	return cpu_evtchn[evtchn];
}

#else

static inline unsigned long active_evtchns(unsigned int cpu, shared_info_t *sh,
					   unsigned int idx)
{
	return (sh->evtchn_pending[idx] & ~sh->evtchn_mask[idx]);
}

static void bind_evtchn_to_cpu(unsigned int chn, unsigned int cpu)
{
}

static void init_evtchn_cpu_bindings(void)
{
}

static inline unsigned int cpu_from_evtchn(unsigned int evtchn)
{
	return 0;
}

#endif

/* Upcall to generic IRQ layer. */
#ifdef CONFIG_X86
extern fastcall unsigned int do_IRQ(struct pt_regs *regs);
void __init xen_init_IRQ(void);
void __init init_IRQ(void)
{
	irq_ctx_init(0);
	xen_init_IRQ();
}
#if defined (__i386__)
static inline void exit_idle(void) {}
#define IRQ_REG orig_eax
#elif defined (__x86_64__)
#include <asm/idle.h>
#define IRQ_REG orig_rax
#endif
#define do_IRQ(irq, regs) do {		\
	(regs)->IRQ_REG = ~(irq);	\
	do_IRQ((regs));			\
} while (0)
#endif

/* Xen will never allocate port zero for any purpose. */
#define VALID_EVTCHN(chn)	((chn) != 0)

/*
 * Force a proper event-channel callback from Xen after clearing the
 * callback mask. We do this in a very simple manner, by making a call
 * down into Xen. The pending flag will be checked by Xen on return.
 */
void force_evtchn_callback(void)
{
	(void)HYPERVISOR_xen_version(0, NULL);
}
/* Not a GPL symbol: used in ubiquitous macros, so too restrictive. */
EXPORT_SYMBOL(force_evtchn_callback);

static DEFINE_PER_CPU(unsigned int, upcall_count) = { 0 };

/* NB. Interrupts are disabled on entry. */
asmlinkage void evtchn_do_upcall(struct pt_regs *regs)
{
	unsigned long  l1, l2;
	unsigned int   l1i, l2i, port, count;
	int            irq, cpu = smp_processor_id();
	shared_info_t *s = HYPERVISOR_shared_info;
	vcpu_info_t   *vcpu_info = &s->vcpu_info[cpu];

	do {
		/* Avoid a callback storm when we reenable delivery. */
		vcpu_info->evtchn_upcall_pending = 0;

		/* Nested invocations bail immediately. */
		if (unlikely(per_cpu(upcall_count, cpu)++))
			return;

#ifndef CONFIG_X86 /* No need for a barrier -- XCHG is a barrier on x86. */
		/* Clear master flag /before/ clearing selector flag. */
		rmb();
#endif
		l1 = xchg(&vcpu_info->evtchn_pending_sel, 0);
		while (l1 != 0) {
			l1i = __ffs(l1);
			l1 &= ~(1UL << l1i);

			while ((l2 = active_evtchns(cpu, s, l1i)) != 0) {
				l2i = __ffs(l2);

				port = (l1i * BITS_PER_LONG) + l2i;
				if ((irq = evtchn_to_irq[port]) != -1)
					do_IRQ(irq, regs);
				else {
					exit_idle();
					evtchn_device_upcall(port);
				}
			}
		}

		/* If there were nested callbacks then we have more to do. */
		count = per_cpu(upcall_count, cpu);
		per_cpu(upcall_count, cpu) = 0;
	} while (unlikely(count != 1));
}

static int find_unbound_irq(void)
{
	static int warned;
	int dynirq, irq;

	for (dynirq = 0; dynirq < NR_DYNIRQS; dynirq++) {
		irq = dynirq_to_irq(dynirq);
		if (irq_bindcount[irq] == 0)
			return irq;
	}

	if (!warned) {
		warned = 1;
		printk(KERN_WARNING "No available IRQ to bind to: "
		       "increase NR_DYNIRQS.\n");
	}

	return -ENOSPC;
}

static int bind_caller_port_to_irq(unsigned int caller_port)
{
	int irq;

	spin_lock(&irq_mapping_update_lock);

	if ((irq = evtchn_to_irq[caller_port]) == -1) {
		if ((irq = find_unbound_irq()) < 0)
			goto out;

		evtchn_to_irq[caller_port] = irq;
		irq_info[irq] = mk_irq_info(IRQT_CALLER_PORT, 0, caller_port);
	}

	irq_bindcount[irq]++;

 out:
	spin_unlock(&irq_mapping_update_lock);
	return irq;
}

static int bind_local_port_to_irq(unsigned int local_port)
{
	int irq;

	spin_lock(&irq_mapping_update_lock);

	BUG_ON(evtchn_to_irq[local_port] != -1);

	if ((irq = find_unbound_irq()) < 0) {
		struct evtchn_close close = { .port = local_port };
		if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close))
			BUG();
		goto out;
	}

	evtchn_to_irq[local_port] = irq;
	irq_info[irq] = mk_irq_info(IRQT_LOCAL_PORT, 0, local_port);
	irq_bindcount[irq]++;

 out:
	spin_unlock(&irq_mapping_update_lock);
	return irq;
}

static int bind_listening_port_to_irq(unsigned int remote_domain)
{
	struct evtchn_alloc_unbound alloc_unbound;
	int err;

	alloc_unbound.dom        = DOMID_SELF;
	alloc_unbound.remote_dom = remote_domain;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
					  &alloc_unbound);

	return err ? : bind_local_port_to_irq(alloc_unbound.port);
}

static int bind_interdomain_evtchn_to_irq(unsigned int remote_domain,
					  unsigned int remote_port)
{
	struct evtchn_bind_interdomain bind_interdomain;
	int err;

	bind_interdomain.remote_dom  = remote_domain;
	bind_interdomain.remote_port = remote_port;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain,
					  &bind_interdomain);

	return err ? : bind_local_port_to_irq(bind_interdomain.local_port);
}

static int bind_virq_to_irq(unsigned int virq, unsigned int cpu)
{
	struct evtchn_bind_virq bind_virq;
	int evtchn, irq;

	spin_lock(&irq_mapping_update_lock);

	if ((irq = per_cpu(virq_to_irq, cpu)[virq]) == -1) {
		if ((irq = find_unbound_irq()) < 0)
			goto out;

		bind_virq.virq = virq;
		bind_virq.vcpu = cpu;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq,
						&bind_virq) != 0)
			BUG();
		evtchn = bind_virq.port;

		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_VIRQ, virq, evtchn);

		per_cpu(virq_to_irq, cpu)[virq] = irq;

		bind_evtchn_to_cpu(evtchn, cpu);
	}

	irq_bindcount[irq]++;

 out:
	spin_unlock(&irq_mapping_update_lock);
	return irq;
}

static int bind_ipi_to_irq(unsigned int ipi, unsigned int cpu)
{
	struct evtchn_bind_ipi bind_ipi;
	int evtchn, irq;

	spin_lock(&irq_mapping_update_lock);

	if ((irq = per_cpu(ipi_to_irq, cpu)[ipi]) == -1) {
		if ((irq = find_unbound_irq()) < 0)
			goto out;

		bind_ipi.vcpu = cpu;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_ipi,
						&bind_ipi) != 0)
			BUG();
		evtchn = bind_ipi.port;

		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_IPI, ipi, evtchn);

		per_cpu(ipi_to_irq, cpu)[ipi] = irq;

		bind_evtchn_to_cpu(evtchn, cpu);
	}

	irq_bindcount[irq]++;

 out:
	spin_unlock(&irq_mapping_update_lock);
	return irq;
}

static void unbind_from_irq(unsigned int irq)
{
	struct evtchn_close close;
	int cpu, evtchn = evtchn_from_irq(irq);

	spin_lock(&irq_mapping_update_lock);

	if ((--irq_bindcount[irq] == 0) && VALID_EVTCHN(evtchn)) {
		close.port = evtchn;
		if ((type_from_irq(irq) != IRQT_CALLER_PORT) &&
		    HYPERVISOR_event_channel_op(EVTCHNOP_close, &close))
			BUG();

		switch (type_from_irq(irq)) {
		case IRQT_VIRQ:
			per_cpu(virq_to_irq, cpu_from_evtchn(evtchn))
				[index_from_irq(irq)] = -1;
			break;
		case IRQT_IPI:
			per_cpu(ipi_to_irq, cpu_from_evtchn(evtchn))
				[index_from_irq(irq)] = -1;
			break;
		default:
			break;
		}

		/* Closed ports are implicitly re-bound to VCPU0. */
		bind_evtchn_to_cpu(evtchn, 0);

		evtchn_to_irq[evtchn] = -1;
		irq_info[irq] = IRQ_UNBOUND;

		/* Zap stats across IRQ changes of use. */
		for_each_possible_cpu(cpu)
			kstat_cpu(cpu).irqs[irq] = 0;
	}

	spin_unlock(&irq_mapping_update_lock);
}

int bind_caller_port_to_irqhandler(
	unsigned int caller_port,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq, retval;

	irq = bind_caller_port_to_irq(caller_port);
	if (irq < 0)
		return irq;

	retval = request_irq(irq, handler, irqflags, devname, dev_id);
	if (retval != 0) {
		unbind_from_irq(irq);
		return retval;
	}

	return irq;
}
EXPORT_SYMBOL_GPL(bind_caller_port_to_irqhandler);

int bind_listening_port_to_irqhandler(
	unsigned int remote_domain,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq, retval;

	irq = bind_listening_port_to_irq(remote_domain);
	if (irq < 0)
		return irq;

	retval = request_irq(irq, handler, irqflags, devname, dev_id);
	if (retval != 0) {
		unbind_from_irq(irq);
		return retval;
	}

	return irq;
}
EXPORT_SYMBOL_GPL(bind_listening_port_to_irqhandler);

int bind_interdomain_evtchn_to_irqhandler(
	unsigned int remote_domain,
	unsigned int remote_port,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq, retval;

	irq = bind_interdomain_evtchn_to_irq(remote_domain, remote_port);
	if (irq < 0)
		return irq;

	retval = request_irq(irq, handler, irqflags, devname, dev_id);
	if (retval != 0) {
		unbind_from_irq(irq);
		return retval;
	}

	return irq;
}
EXPORT_SYMBOL_GPL(bind_interdomain_evtchn_to_irqhandler);

int bind_virq_to_irqhandler(
	unsigned int virq,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq, retval;

	irq = bind_virq_to_irq(virq, cpu);
	if (irq < 0)
		return irq;

	retval = request_irq(irq, handler, irqflags, devname, dev_id);
	if (retval != 0) {
		unbind_from_irq(irq);
		return retval;
	}

	return irq;
}
EXPORT_SYMBOL_GPL(bind_virq_to_irqhandler);

int bind_ipi_to_irqhandler(
	unsigned int ipi,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	int irq, retval;

	irq = bind_ipi_to_irq(ipi, cpu);
	if (irq < 0)
		return irq;

	retval = request_irq(irq, handler, irqflags, devname, dev_id);
	if (retval != 0) {
		unbind_from_irq(irq);
		return retval;
	}

	return irq;
}
EXPORT_SYMBOL_GPL(bind_ipi_to_irqhandler);

void unbind_from_irqhandler(unsigned int irq, void *dev_id)
{
	free_irq(irq, dev_id);
	unbind_from_irq(irq);
}
EXPORT_SYMBOL_GPL(unbind_from_irqhandler);

#ifdef CONFIG_SMP
/* Rebind an evtchn so that it gets delivered to a specific cpu */
static void rebind_irq_to_cpu(unsigned irq, unsigned tcpu)
{
	struct evtchn_bind_vcpu bind_vcpu;
	int evtchn = evtchn_from_irq(irq);

	if (!VALID_EVTCHN(evtchn))
		return;

	/* Send future instances of this interrupt to other vcpu. */
	bind_vcpu.port = evtchn;
	bind_vcpu.vcpu = tcpu;

	/*
	 * If this fails, it usually just indicates that we're dealing with a 
	 * virq or IPI channel, which don't actually need to be rebound. Ignore
	 * it, but don't do the xenlinux-level rebind in that case.
	 */
	if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_vcpu, &bind_vcpu) >= 0)
		bind_evtchn_to_cpu(evtchn, tcpu);
}

static void set_affinity_irq(unsigned irq, cpumask_t dest)
{
	unsigned tcpu = first_cpu(dest);
	rebind_irq_to_cpu(irq, tcpu);
}
#endif

int resend_irq_on_evtchn(unsigned int irq)
{
	int masked, evtchn = evtchn_from_irq(irq);
	shared_info_t *s = HYPERVISOR_shared_info;

	if (!VALID_EVTCHN(evtchn))
		return 1;

	masked = synch_test_and_set_bit(evtchn, s->evtchn_mask);
	synch_set_bit(evtchn, s->evtchn_pending);
	if (!masked)
		unmask_evtchn(evtchn);

	return 1;
}

/*
 * Interface to generic handling in irq.c
 */

static unsigned int startup_dynirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		unmask_evtchn(evtchn);
	return 0;
}

static void shutdown_dynirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		mask_evtchn(evtchn);
}

static void enable_dynirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		unmask_evtchn(evtchn);
}

static void disable_dynirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		mask_evtchn(evtchn);
}

static void ack_dynirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	move_native_irq(irq);

	if (VALID_EVTCHN(evtchn)) {
		mask_evtchn(evtchn);
		clear_evtchn(evtchn);
	}
}

static void end_dynirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn) && !(irq_desc[irq].status & IRQ_DISABLED))
		unmask_evtchn(evtchn);
}

static struct hw_interrupt_type dynirq_type = {
	.typename = "Dynamic-irq",
	.startup  = startup_dynirq,
	.shutdown = shutdown_dynirq,
	.enable   = enable_dynirq,
	.disable  = disable_dynirq,
	.ack      = ack_dynirq,
	.end      = end_dynirq,
#ifdef CONFIG_SMP
	.set_affinity = set_affinity_irq,
#endif
	.retrigger = resend_irq_on_evtchn,
};

static inline void pirq_unmask_notify(int pirq)
{
	struct physdev_eoi eoi = { .irq = pirq };
	if (unlikely(test_bit(pirq, pirq_needs_eoi)))
		(void)HYPERVISOR_physdev_op(PHYSDEVOP_eoi, &eoi);
}

static inline void pirq_query_unmask(int pirq)
{
	struct physdev_irq_status_query irq_status;
	irq_status.irq = pirq;
	(void)HYPERVISOR_physdev_op(PHYSDEVOP_irq_status_query, &irq_status);
	clear_bit(pirq, pirq_needs_eoi);
	if (irq_status.flags & XENIRQSTAT_needs_eoi)
		set_bit(pirq, pirq_needs_eoi);
}

/*
 * On startup, if there is no action associated with the IRQ then we are
 * probing. In this case we should not share with others as it will confuse us.
 */
#define probing_irq(_irq) (irq_desc[(_irq)].action == NULL)

static unsigned int startup_pirq(unsigned int irq)
{
	struct evtchn_bind_pirq bind_pirq;
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		goto out;

	bind_pirq.pirq  = irq;
	/* NB. We are happy to share unless we are probing. */
	bind_pirq.flags = probing_irq(irq) ? 0 : BIND_PIRQ__WILL_SHARE;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_pirq, &bind_pirq) != 0) {
		if (!probing_irq(irq))
			printk(KERN_INFO "Failed to obtain physical IRQ %d\n",
			       irq);
		return 0;
	}
	evtchn = bind_pirq.port;

	pirq_query_unmask(irq_to_pirq(irq));

	evtchn_to_irq[evtchn] = irq;
	bind_evtchn_to_cpu(evtchn, 0);
	irq_info[irq] = mk_irq_info(IRQT_PIRQ, irq, evtchn);

 out:
	unmask_evtchn(evtchn);
	pirq_unmask_notify(irq_to_pirq(irq));

	return 0;
}

static void shutdown_pirq(unsigned int irq)
{
	struct evtchn_close close;
	int evtchn = evtchn_from_irq(irq);

	if (!VALID_EVTCHN(evtchn))
		return;

	mask_evtchn(evtchn);

	close.port = evtchn;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close) != 0)
		BUG();

	bind_evtchn_to_cpu(evtchn, 0);
	evtchn_to_irq[evtchn] = -1;
	irq_info[irq] = IRQ_UNBOUND;
}

static void enable_pirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn)) {
		unmask_evtchn(evtchn);
		pirq_unmask_notify(irq_to_pirq(irq));
	}
}

static void disable_pirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		mask_evtchn(evtchn);
}

static void ack_pirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	move_native_irq(irq);

	if (VALID_EVTCHN(evtchn)) {
		mask_evtchn(evtchn);
		clear_evtchn(evtchn);
	}
}

static void end_pirq(unsigned int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn) && !(irq_desc[irq].status & IRQ_DISABLED)) {
		unmask_evtchn(evtchn);
		pirq_unmask_notify(irq_to_pirq(irq));
	}
}

static struct hw_interrupt_type pirq_type = {
	.typename = "Phys-irq",
	.startup  = startup_pirq,
	.shutdown = shutdown_pirq,
	.enable   = enable_pirq,
	.disable  = disable_pirq,
	.ack      = ack_pirq,
	.end      = end_pirq,
#ifdef CONFIG_SMP
	.set_affinity = set_affinity_irq,
#endif
	.retrigger = resend_irq_on_evtchn,
};

int irq_ignore_unhandled(unsigned int irq)
{
	struct physdev_irq_status_query irq_status = { .irq = irq };

	if (!is_running_on_xen())
		return 0;

	(void)HYPERVISOR_physdev_op(PHYSDEVOP_irq_status_query, &irq_status);
	return !!(irq_status.flags & XENIRQSTAT_shared);
}

void notify_remote_via_irq(int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		notify_remote_via_evtchn(evtchn);
}
EXPORT_SYMBOL_GPL(notify_remote_via_irq);

int irq_to_evtchn_port(int irq)
{
	return evtchn_from_irq(irq);
}
EXPORT_SYMBOL_GPL(irq_to_evtchn_port);

void mask_evtchn(int port)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	synch_set_bit(port, s->evtchn_mask);
}
EXPORT_SYMBOL_GPL(mask_evtchn);

void unmask_evtchn(int port)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	unsigned int cpu = smp_processor_id();
	vcpu_info_t *vcpu_info = &s->vcpu_info[cpu];

	BUG_ON(!irqs_disabled());

	/* Slow path (hypercall) if this is a non-local port. */
	if (unlikely(cpu != cpu_from_evtchn(port))) {
		struct evtchn_unmask unmask = { .port = port };
		(void)HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &unmask);
		return;
	}

	synch_clear_bit(port, s->evtchn_mask);

	/* Did we miss an interrupt 'edge'? Re-fire if so. */
	if (synch_test_bit(port, s->evtchn_pending) &&
	    !synch_test_and_set_bit(port / BITS_PER_LONG,
				    &vcpu_info->evtchn_pending_sel))
		vcpu_info->evtchn_upcall_pending = 1;
}
EXPORT_SYMBOL_GPL(unmask_evtchn);

void irq_resume(void)
{
	struct evtchn_bind_virq bind_virq;
	struct evtchn_bind_ipi  bind_ipi;
	int cpu, pirq, virq, ipi, irq, evtchn;

	init_evtchn_cpu_bindings();

	/* New event-channel space is not 'live' yet. */
	for (evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++)
		mask_evtchn(evtchn);

	/* Check that no PIRQs are still bound. */
	for (pirq = 0; pirq < NR_PIRQS; pirq++)
		BUG_ON(irq_info[pirq_to_irq(pirq)] != IRQ_UNBOUND);

	/* Secondary CPUs must have no VIRQ or IPI bindings. */
	for_each_possible_cpu(cpu) {
		if (cpu == 0)
			continue;
		for (virq = 0; virq < NR_VIRQS; virq++)
			BUG_ON(per_cpu(virq_to_irq, cpu)[virq] != -1);
		for (ipi = 0; ipi < NR_IPIS; ipi++)
			BUG_ON(per_cpu(ipi_to_irq, cpu)[ipi] != -1);
	}

	/* No IRQ <-> event-channel mappings. */
	for (irq = 0; irq < NR_IRQS; irq++)
		irq_info[irq] &= ~0xFFFF; /* zap event-channel binding */
	for (evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++)
		evtchn_to_irq[evtchn] = -1;

	/* Primary CPU: rebind VIRQs automatically. */
	for (virq = 0; virq < NR_VIRQS; virq++) {
		if ((irq = per_cpu(virq_to_irq, 0)[virq]) == -1)
			continue;

		BUG_ON(irq_info[irq] != mk_irq_info(IRQT_VIRQ, virq, 0));

		/* Get a new binding from Xen. */
		bind_virq.virq = virq;
		bind_virq.vcpu = 0;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq,
						&bind_virq) != 0)
			BUG();
		evtchn = bind_virq.port;

		/* Record the new mapping. */
		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_VIRQ, virq, evtchn);

		/* Ready for use. */
		unmask_evtchn(evtchn);
	}

	/* Primary CPU: rebind IPIs automatically. */
	for (ipi = 0; ipi < NR_IPIS; ipi++) {
		if ((irq = per_cpu(ipi_to_irq, 0)[ipi]) == -1)
			continue;

		BUG_ON(irq_info[irq] != mk_irq_info(IRQT_IPI, ipi, 0));

		/* Get a new binding from Xen. */
		bind_ipi.vcpu = 0;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_ipi,
						&bind_ipi) != 0)
			BUG();
		evtchn = bind_ipi.port;

		/* Record the new mapping. */
		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_IPI, ipi, evtchn);

		/* Ready for use. */
		unmask_evtchn(evtchn);
	}
}

void __init xen_init_IRQ(void)
{
	int i;

	init_evtchn_cpu_bindings();

	/* No event channels are 'live' right now. */
	for (i = 0; i < NR_EVENT_CHANNELS; i++)
		mask_evtchn(i);

	/* No IRQ -> event-channel mappings. */
	for (i = 0; i < NR_IRQS; i++)
		irq_info[i] = IRQ_UNBOUND;

	/* Dynamic IRQ space is currently unbound. Zero the refcnts. */
	for (i = 0; i < NR_DYNIRQS; i++) {
		irq_bindcount[dynirq_to_irq(i)] = 0;

		irq_desc[dynirq_to_irq(i)].status = IRQ_DISABLED;
		irq_desc[dynirq_to_irq(i)].action = NULL;
		irq_desc[dynirq_to_irq(i)].depth = 1;
		irq_desc[dynirq_to_irq(i)].chip = &dynirq_type;
	}

	/* Phys IRQ space is statically bound (1:1 mapping). Nail refcnts. */
	for (i = 0; i < NR_PIRQS; i++) {
		irq_bindcount[pirq_to_irq(i)] = 1;

#ifdef RTC_IRQ
		/* If not domain 0, force our RTC driver to fail its probe. */
		if ((i == RTC_IRQ) && !is_initial_xendomain())
			continue;
#endif

		irq_desc[pirq_to_irq(i)].status = IRQ_DISABLED;
		irq_desc[pirq_to_irq(i)].action = NULL;
		irq_desc[pirq_to_irq(i)].depth = 1;
		irq_desc[pirq_to_irq(i)].chip = &pirq_type;
	}
}
