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
#include <xen/interface/event_channel.h>
#include <xen/interface/physdev.h>
#include <asm/hypervisor.h>
#include <xen/evtchn.h>
#include <linux/mc146818rtc.h> /* RTC_IRQ */

/*
 * This lock protects updates to the following mapping and reference-count
 * arrays. The lock does not need to be acquired to read the mapping tables.
 */
static spinlock_t irq_mapping_update_lock;

/* IRQ <-> event-channel mappings. */
static int evtchn_to_irq[NR_EVENT_CHANNELS];

/* Packed IRQ information: binding type, sub-type index, and event channel. */
static u32 irq_info[NR_IRQS];

/* Binding types. */
enum { IRQT_UNBOUND, IRQT_PIRQ, IRQT_VIRQ, IRQT_IPI, IRQT_EVTCHN };

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
DEFINE_PER_CPU(int, virq_to_irq[NR_VIRQS]);

/* IRQ <-> IPI mapping. */
#ifndef NR_IPIS
#define NR_IPIS 1
#endif
DEFINE_PER_CPU(int, ipi_to_irq[NR_IPIS]);

/* Reference counts for bindings to IRQs. */
static int irq_bindcount[NR_IRQS];

/* Bitmap indicating which PIRQs require Xen to be notified on unmask. */
static unsigned long pirq_needs_unmask_notify[NR_PIRQS/sizeof(unsigned long)];

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
	clear_bit(chn, (unsigned long *)cpu_evtchn_mask[cpu_evtchn[chn]]);
	set_bit(chn, (unsigned long *)cpu_evtchn_mask[cpu]);
	cpu_evtchn[chn] = cpu;
}

static void init_evtchn_cpu_bindings(void)
{
	/* By default all event channels notify CPU#0. */
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
EXPORT_SYMBOL_GPL(force_evtchn_callback);

/* NB. Interrupts are disabled on entry. */
asmlinkage void evtchn_do_upcall(struct pt_regs *regs)
{
	unsigned long  l1, l2;
	unsigned int   l1i, l2i, port;
	int            irq, cpu = smp_processor_id();
	shared_info_t *s = HYPERVISOR_shared_info;
	vcpu_info_t   *vcpu_info = &s->vcpu_info[cpu];

	vcpu_info->evtchn_upcall_pending = 0;

	/* NB. No need for a barrier here -- XCHG is a barrier on x86. */
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
}

static int find_unbound_irq(void)
{
	int irq;

	for (irq = 0; irq < NR_IRQS; irq++)
		if (irq_bindcount[irq] == 0)
			break;

	if (irq == NR_IRQS)
		panic("No available IRQ to bind to: increase NR_IRQS!\n");

	return irq;
}

static int bind_evtchn_to_irq(unsigned int evtchn)
{
	int irq;

	spin_lock(&irq_mapping_update_lock);

	if ((irq = evtchn_to_irq[evtchn]) == -1) {
		irq = find_unbound_irq();
		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_EVTCHN, 0, evtchn);
	}

	irq_bindcount[irq]++;

	spin_unlock(&irq_mapping_update_lock);

	return irq;
}

static int bind_virq_to_irq(unsigned int virq, unsigned int cpu)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_bind_virq };
	int evtchn, irq;

	spin_lock(&irq_mapping_update_lock);

	if ((irq = per_cpu(virq_to_irq, cpu)[virq]) == -1) {
		op.u.bind_virq.virq = virq;
		op.u.bind_virq.vcpu = cpu;
		BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);
		evtchn = op.u.bind_virq.port;

		irq = find_unbound_irq();
		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_VIRQ, virq, evtchn);

		per_cpu(virq_to_irq, cpu)[virq] = irq;

		bind_evtchn_to_cpu(evtchn, cpu);
	}

	irq_bindcount[irq]++;

	spin_unlock(&irq_mapping_update_lock);

	return irq;
}

static int bind_ipi_to_irq(unsigned int ipi, unsigned int cpu)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_bind_ipi };
	int evtchn, irq;

	spin_lock(&irq_mapping_update_lock);

	if ((irq = per_cpu(ipi_to_irq, cpu)[ipi]) == -1) {
		op.u.bind_ipi.vcpu = cpu;
		BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);
		evtchn = op.u.bind_ipi.port;

		irq = find_unbound_irq();
		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_IPI, ipi, evtchn);

		per_cpu(ipi_to_irq, cpu)[ipi] = irq;

		bind_evtchn_to_cpu(evtchn, cpu);
	}

	irq_bindcount[irq]++;

	spin_unlock(&irq_mapping_update_lock);

	return irq;
}

static void unbind_from_irq(unsigned int irq)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_close };
	int evtchn = evtchn_from_irq(irq);

	spin_lock(&irq_mapping_update_lock);

	if ((--irq_bindcount[irq] == 0) && VALID_EVTCHN(evtchn)) {
		op.u.close.port = evtchn;
		BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);

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
	}

	spin_unlock(&irq_mapping_update_lock);
}

int bind_evtchn_to_irqhandler(
	unsigned int evtchn,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	unsigned int irq;
	int retval;

	irq = bind_evtchn_to_irq(evtchn);
	retval = request_irq(irq, handler, irqflags, devname, dev_id);
	if (retval != 0) {
		unbind_from_irq(irq);
		return retval;
	}

	return irq;
}
EXPORT_SYMBOL_GPL(bind_evtchn_to_irqhandler);

int bind_virq_to_irqhandler(
	unsigned int virq,
	unsigned int cpu,
	irqreturn_t (*handler)(int, void *, struct pt_regs *),
	unsigned long irqflags,
	const char *devname,
	void *dev_id)
{
	unsigned int irq;
	int retval;

	irq = bind_virq_to_irq(virq, cpu);
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
	unsigned int irq;
	int retval;

	irq = bind_ipi_to_irq(ipi, cpu);
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
static void do_nothing_function(void *ign)
{
}
#endif

/* Rebind an evtchn so that it gets delivered to a specific cpu */
static void rebind_irq_to_cpu(unsigned irq, unsigned tcpu)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_bind_vcpu };
	int evtchn;

	spin_lock(&irq_mapping_update_lock);

	evtchn = evtchn_from_irq(irq);
	if (!VALID_EVTCHN(evtchn)) {
		spin_unlock(&irq_mapping_update_lock);
		return;
	}

	/* Send future instances of this interrupt to other vcpu. */
	op.u.bind_vcpu.port = evtchn;
	op.u.bind_vcpu.vcpu = tcpu;

	/*
	 * If this fails, it usually just indicates that we're dealing with a 
	 * virq or IPI channel, which don't actually need to be rebound. Ignore
	 * it, but don't do the xenlinux-level rebind in that case.
	 */
	if (HYPERVISOR_event_channel_op(&op) >= 0)
		bind_evtchn_to_cpu(evtchn, tcpu);

	spin_unlock(&irq_mapping_update_lock);

	/*
	 * Now send the new target processor a NOP IPI. When this returns, it
	 * will check for any pending interrupts, and so service any that got 
	 * delivered to the wrong processor by mistake.
	 * 
	 * XXX: The only time this is called with interrupts disabled is from
	 * the hotplug/hotunplug path. In that case, all cpus are stopped with 
	 * interrupts disabled, and the missed interrupts will be picked up
	 * when they start again. This is kind of a hack.
	 */
	if (!irqs_disabled())
		smp_call_function(do_nothing_function, NULL, 0, 0);
}


static void set_affinity_irq(unsigned irq, cpumask_t dest)
{
	unsigned tcpu = first_cpu(dest);
	rebind_irq_to_cpu(irq, tcpu);
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
	"Dynamic-irq",
	startup_dynirq,
	shutdown_dynirq,
	enable_dynirq,
	disable_dynirq,
	ack_dynirq,
	end_dynirq,
	set_affinity_irq
};

static inline void pirq_unmask_notify(int pirq)
{
	physdev_op_t op;
	if (unlikely(test_bit(pirq, &pirq_needs_unmask_notify[0]))) {
		op.cmd = PHYSDEVOP_IRQ_UNMASK_NOTIFY;
		(void)HYPERVISOR_physdev_op(&op);
	}
}

static inline void pirq_query_unmask(int pirq)
{
	physdev_op_t op;
	op.cmd = PHYSDEVOP_IRQ_STATUS_QUERY;
	op.u.irq_status_query.irq = pirq;
	(void)HYPERVISOR_physdev_op(&op);
	clear_bit(pirq, &pirq_needs_unmask_notify[0]);
	if (op.u.irq_status_query.flags & PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY)
		set_bit(pirq, &pirq_needs_unmask_notify[0]);
}

/*
 * On startup, if there is no action associated with the IRQ then we are
 * probing. In this case we should not share with others as it will confuse us.
 */
#define probing_irq(_irq) (irq_desc[(_irq)].action == NULL)

static unsigned int startup_pirq(unsigned int irq)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_bind_pirq };
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		goto out;

	op.u.bind_pirq.pirq  = irq;
	/* NB. We are happy to share unless we are probing. */
	op.u.bind_pirq.flags = probing_irq(irq) ? 0 : BIND_PIRQ__WILL_SHARE;
	if (HYPERVISOR_event_channel_op(&op) != 0) {
		if (!probing_irq(irq))
			printk(KERN_INFO "Failed to obtain physical IRQ %d\n",
			       irq);
		return 0;
	}
	evtchn = op.u.bind_pirq.port;

	pirq_query_unmask(irq_to_pirq(irq));

	bind_evtchn_to_cpu(evtchn, 0);
	evtchn_to_irq[evtchn] = irq;
	irq_info[irq] = mk_irq_info(IRQT_PIRQ, irq, evtchn);

 out:
	unmask_evtchn(evtchn);
	pirq_unmask_notify(irq_to_pirq(irq));

	return 0;
}

static void shutdown_pirq(unsigned int irq)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_close };
	int evtchn = evtchn_from_irq(irq);

	if (!VALID_EVTCHN(evtchn))
		return;

	mask_evtchn(evtchn);

	op.u.close.port = evtchn;
	BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);

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
	"Phys-irq",
	startup_pirq,
	shutdown_pirq,
	enable_pirq,
	disable_pirq,
	ack_pirq,
	end_pirq,
	set_affinity_irq
};

void hw_resend_irq(struct hw_interrupt_type *h, unsigned int i)
{
	int evtchn = evtchn_from_irq(i);
	shared_info_t *s = HYPERVISOR_shared_info;
	if (!VALID_EVTCHN(evtchn))
		return;
	BUG_ON(!synch_test_bit(evtchn, &s->evtchn_mask[0]));
	synch_set_bit(evtchn, &s->evtchn_pending[0]);
}

void notify_remote_via_irq(int irq)
{
	int evtchn = evtchn_from_irq(irq);

	if (VALID_EVTCHN(evtchn))
		notify_remote_via_evtchn(evtchn);
}
EXPORT_SYMBOL_GPL(notify_remote_via_irq);

void mask_evtchn(int port)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	synch_set_bit(port, &s->evtchn_mask[0]);
}
EXPORT_SYMBOL_GPL(mask_evtchn);

void unmask_evtchn(int port)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	unsigned int cpu = smp_processor_id();
	vcpu_info_t *vcpu_info = &s->vcpu_info[cpu];

	/* Slow path (hypercall) if this is a non-local port. */
	if (unlikely(cpu != cpu_from_evtchn(port))) {
		evtchn_op_t op = { .cmd = EVTCHNOP_unmask,
				   .u.unmask.port = port };
		(void)HYPERVISOR_event_channel_op(&op);
		return;
	}

	synch_clear_bit(port, &s->evtchn_mask[0]);

	/*
	 * The following is basically the equivalent of 'hw_resend_irq'. Just
	 * like a real IO-APIC we 'lose the interrupt edge' if the channel is
	 * masked.
	 */
	if (synch_test_bit(port, &s->evtchn_pending[0]) &&
	    !synch_test_and_set_bit(port / BITS_PER_LONG,
				    &vcpu_info->evtchn_pending_sel)) {
		vcpu_info->evtchn_upcall_pending = 1;
		if (!vcpu_info->evtchn_upcall_mask)
			force_evtchn_callback();
	}
}
EXPORT_SYMBOL_GPL(unmask_evtchn);

void irq_resume(void)
{
	evtchn_op_t op;
	int         cpu, pirq, virq, ipi, irq, evtchn;

	init_evtchn_cpu_bindings();

	/* New event-channel space is not 'live' yet. */
	for (evtchn = 0; evtchn < NR_EVENT_CHANNELS; evtchn++)
		mask_evtchn(evtchn);

	/* Check that no PIRQs are still bound. */
	for (pirq = 0; pirq < NR_PIRQS; pirq++)
		BUG_ON(irq_info[pirq_to_irq(pirq)] != IRQ_UNBOUND);

	/* Secondary CPUs must have no VIRQ or IPI bindings. */
	for (cpu = 1; cpu < NR_CPUS; cpu++) {
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
		memset(&op, 0, sizeof(op));
		op.cmd              = EVTCHNOP_bind_virq;
		op.u.bind_virq.virq = virq;
		op.u.bind_virq.vcpu = 0;
		BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);
		evtchn = op.u.bind_virq.port;

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
		memset(&op, 0, sizeof(op));
		op.cmd = EVTCHNOP_bind_ipi;
		op.u.bind_ipi.vcpu = 0;
		BUG_ON(HYPERVISOR_event_channel_op(&op) != 0);
		evtchn = op.u.bind_ipi.port;

		/* Record the new mapping. */
		evtchn_to_irq[evtchn] = irq;
		irq_info[irq] = mk_irq_info(IRQT_IPI, ipi, evtchn);

		/* Ready for use. */
		unmask_evtchn(evtchn);
	}
}

void __init init_IRQ(void)
{
	int i;
	int cpu;

	irq_ctx_init(0);

	spin_lock_init(&irq_mapping_update_lock);

	init_evtchn_cpu_bindings();

	/* No VIRQ or IPI bindings. */
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		for (i = 0; i < NR_VIRQS; i++)
			per_cpu(virq_to_irq, cpu)[i] = -1;
		for (i = 0; i < NR_IPIS; i++)
			per_cpu(ipi_to_irq, cpu)[i] = -1;
	}

	/* No event-channel -> IRQ mappings. */
	for (i = 0; i < NR_EVENT_CHANNELS; i++) {
		evtchn_to_irq[i] = -1;
		mask_evtchn(i); /* No event channels are 'live' right now. */
	}

	/* No IRQ -> event-channel mappings. */
	for (i = 0; i < NR_IRQS; i++)
		irq_info[i] = IRQ_UNBOUND;

	/* Dynamic IRQ space is currently unbound. Zero the refcnts. */
	for (i = 0; i < NR_DYNIRQS; i++) {
		irq_bindcount[dynirq_to_irq(i)] = 0;

		irq_desc[dynirq_to_irq(i)].status  = IRQ_DISABLED;
		irq_desc[dynirq_to_irq(i)].action  = NULL;
		irq_desc[dynirq_to_irq(i)].depth   = 1;
		irq_desc[dynirq_to_irq(i)].handler = &dynirq_type;
	}

	/* Phys IRQ space is statically bound (1:1 mapping). Nail refcnts. */
	for (i = 0; i < NR_PIRQS; i++) {
		irq_bindcount[pirq_to_irq(i)] = 1;

#ifdef RTC_IRQ
		/* If not domain 0, force our RTC driver to fail its probe. */
		if ((i == RTC_IRQ) &&
		    !(xen_start_info->flags & SIF_INITDOMAIN))
			continue;
#endif

		irq_desc[pirq_to_irq(i)].status  = IRQ_DISABLED;
		irq_desc[pirq_to_irq(i)].action  = NULL;
		irq_desc[pirq_to_irq(i)].depth   = 1;
		irq_desc[pirq_to_irq(i)].handler = &pirq_type;
	}
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
