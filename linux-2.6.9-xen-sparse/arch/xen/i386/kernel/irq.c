/*
 *	linux/arch/i386/kernel/irq.c
 *
 *	Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the code used by various IRQ handling routines:
 * asking for different IRQ's should be done through these routines
 * instead of just grabbing them. Thus setups with different IRQ numbers
 * shouldn't result in any weird surprises, and installing new handlers
 * should be easier.
 */

/*
 * (mostly architecture independent, will move to kernel/irq.c in 2.5.)
 *
 * IRQs are in fact implemented a bit like signal handlers for the kernel.
 * Naturally it's not a 1:1 relation, but there are similarities.
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/timex.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/irq.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>

#include <asm/atomic.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/desc.h>
#include <asm/irq.h>

/*
 * Linux has a controller-independent x86 interrupt architecture.
 * every controller has a 'controller-template', that is used
 * by the main code to do the right thing. Each driver-visible
 * interrupt source is transparently wired to the apropriate
 * controller. Thus drivers need not be aware of the
 * interrupt-controller.
 *
 * Various interrupt controllers we handle: 8259 PIC, SMP IO-APIC,
 * PIIX4's internal 8259 PIC and SGI's Visual Workstation Cobalt (IO-)APIC.
 * (IO-APICs assumed to be messaging to Pentium local-APICs)
 *
 * the code is designed to be easily extended with new/different
 * interrupt controllers, without having to do assembly magic.
 */

/*
 * Controller mappings for all interrupt sources:
 */
irq_desc_t irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handler = &no_irq_type,
		.lock = SPIN_LOCK_UNLOCKED
	}
};

static void register_irq_proc (unsigned int irq);

/*
 * per-CPU IRQ handling stacks
 */
#ifdef CONFIG_4KSTACKS
union irq_ctx *hardirq_ctx[NR_CPUS];
union irq_ctx *softirq_ctx[NR_CPUS];
#endif

/*
 * Special irq handlers.
 */

irqreturn_t no_action(int cpl, void *dev_id, struct pt_regs *regs)
{ return IRQ_NONE; }

/*
 * Generic no controller code
 */

static void enable_none(unsigned int irq) { }
static unsigned int startup_none(unsigned int irq) { return 0; }
static void disable_none(unsigned int irq) { }
static void ack_none(unsigned int irq)
{
/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves, it doesn't deserve
 * a generic callback i think.
 */
#ifdef CONFIG_X86
	printk("unexpected IRQ trap at vector %02x\n", irq);
#ifdef CONFIG_X86_LOCAL_APIC
	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 */
	ack_APIC_irq();
#endif
#endif
}

/* startup is the same as "enable", shutdown is same as "disable" */
#define shutdown_none	disable_none
#define end_none	enable_none

struct hw_interrupt_type no_irq_type = {
	"none",
	startup_none,
	shutdown_none,
	enable_none,
	disable_none,
	ack_none,
	end_none
};

atomic_t irq_err_count;
#if defined(CONFIG_X86_IO_APIC) && defined(APIC_MISMATCH_DEBUG)
atomic_t irq_mis_count;
#endif

/*
 * Generic, controller-independent functions:
 */

int show_interrupts(struct seq_file *p, void *v)
{
	int i = *(loff_t *) v, j;
	struct irqaction * action;
	unsigned long flags;

	if (i == 0) {
		seq_printf(p, "           ");
		for (j=0; j<NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "CPU%d       ",j);
		seq_putc(p, '\n');
	}

	if (i < NR_IRQS) {
		spin_lock_irqsave(&irq_desc[i].lock, flags);
		action = irq_desc[i].action;
		if (!action) 
			goto skip;
		seq_printf(p, "%3d: ",i);
#ifndef CONFIG_SMP
		seq_printf(p, "%10u ", kstat_irqs(i));
#else
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", kstat_cpu(j).irqs[i]);
#endif
		seq_printf(p, " %14s", irq_desc[i].handler->typename);
		seq_printf(p, "  %s", action->name);

		for (action=action->next; action; action = action->next)
			seq_printf(p, ", %s", action->name);

		seq_putc(p, '\n');
skip:
		spin_unlock_irqrestore(&irq_desc[i].lock, flags);
	} else if (i == NR_IRQS) {
		seq_printf(p, "NMI: ");
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", nmi_count(j));
		seq_putc(p, '\n');
#ifdef CONFIG_X86_LOCAL_APIC
		seq_printf(p, "LOC: ");
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", irq_stat[j].apic_timer_irqs);
		seq_putc(p, '\n');
#endif
		seq_printf(p, "ERR: %10u\n", atomic_read(&irq_err_count));
#if defined(CONFIG_X86_IO_APIC) && defined(APIC_MISMATCH_DEBUG)
		seq_printf(p, "MIS: %10u\n", atomic_read(&irq_mis_count));
#endif
	}
	return 0;
}




#ifdef CONFIG_SMP
inline void synchronize_irq(unsigned int irq)
{
	while (irq_desc[irq].status & IRQ_INPROGRESS)
		cpu_relax();
}
#endif

/*
 * This should really return information about whether
 * we should do bottom half handling etc. Right now we
 * end up _always_ checking the bottom half, which is a
 * waste of time and is not what some drivers would
 * prefer.
 */
asmlinkage int handle_IRQ_event(unsigned int irq,
		struct pt_regs *regs, struct irqaction *action)
{
	int status = 1;	/* Force the "do bottom halves" bit */
	int ret, retval = 0;

	if (!(action->flags & SA_INTERRUPT))
		local_irq_enable();

	do {
		ret = action->handler(irq, action->dev_id, regs);
		if (ret == IRQ_HANDLED)
			status |= action->flags;
		retval |= ret;
		action = action->next;
	} while (action);
	if (status & SA_SAMPLE_RANDOM)
		add_interrupt_randomness(irq);
	local_irq_disable();
	return retval;
}

static void __report_bad_irq(int irq, irq_desc_t *desc, irqreturn_t action_ret)
{
	struct irqaction *action;

	if (action_ret != IRQ_HANDLED && action_ret != IRQ_NONE) {
		printk(KERN_ERR "irq event %d: bogus return value %x\n",
				irq, action_ret);
	} else {
		printk(KERN_ERR "irq %d: nobody cared!\n", irq);
	}
	dump_stack();
	printk(KERN_ERR "handlers:\n");
	action = desc->action;
	do {
		printk(KERN_ERR "[<%p>]", action->handler);
		print_symbol(" (%s)",
			(unsigned long)action->handler);
		printk("\n");
		action = action->next;
	} while (action);
}

static void report_bad_irq(int irq, irq_desc_t *desc, irqreturn_t action_ret)
{
	static int count = 100;

	if (count) {
		count--;
		__report_bad_irq(irq, desc, action_ret);
	}
}

static int noirqdebug;

static int __init noirqdebug_setup(char *str)
{
	noirqdebug = 1;
	printk("IRQ lockup detection disabled\n");
	return 1;
}

__setup("noirqdebug", noirqdebug_setup);

/*
 * If 99,900 of the previous 100,000 interrupts have not been handled then
 * assume that the IRQ is stuck in some manner.  Drop a diagnostic and try to
 * turn the IRQ off.
 *
 * (The other 100-of-100,000 interrupts may have been a correctly-functioning
 *  device sharing an IRQ with the failing one)
 *
 * Called under desc->lock
 */
static void note_interrupt(int irq, irq_desc_t *desc, irqreturn_t action_ret)
{
	if (action_ret != IRQ_HANDLED) {
		desc->irqs_unhandled++;
		if (action_ret != IRQ_NONE)
			report_bad_irq(irq, desc, action_ret);
	}

	desc->irq_count++;
	if (desc->irq_count < 100000)
		return;

	desc->irq_count = 0;
	if (desc->irqs_unhandled > 99900) {
		/*
		 * The interrupt is stuck
		 */
		__report_bad_irq(irq, desc, action_ret);
		/*
		 * Now kill the IRQ
		 */
		printk(KERN_EMERG "Disabling IRQ #%d\n", irq);
		desc->status |= IRQ_DISABLED;
		desc->handler->disable(irq);
	}
	desc->irqs_unhandled = 0;
}

/*
 * Generic enable/disable code: this just calls
 * down into the PIC-specific version for the actual
 * hardware disable after having gotten the irq
 * controller lock. 
 */
 
/**
 *	disable_irq_nosync - disable an irq without waiting
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.  Disables and Enables are
 *	nested.
 *	Unlike disable_irq(), this function does not ensure existing
 *	instances of the IRQ handler have completed before returning.
 *
 *	This function may be called from IRQ context.
 */
 
inline void disable_irq_nosync(unsigned int irq)
{
	irq_desc_t *desc = irq_desc + irq;
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	if (!desc->depth++) {
		desc->status |= IRQ_DISABLED;
		desc->handler->disable(irq);
	}
	spin_unlock_irqrestore(&desc->lock, flags);
}

/**
 *	disable_irq - disable an irq and wait for completion
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.  Enables and Disables are
 *	nested.
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
 
void disable_irq(unsigned int irq)
{
	irq_desc_t *desc = irq_desc + irq;
	disable_irq_nosync(irq);
	if (desc->action)
		synchronize_irq(irq);
}

/**
 *	enable_irq - enable handling of an irq
 *	@irq: Interrupt to enable
 *
 *	Undoes the effect of one call to disable_irq().  If this
 *	matches the last disable, processing of interrupts on this
 *	IRQ line is re-enabled.
 *
 *	This function may be called from IRQ context.
 */
 
void enable_irq(unsigned int irq)
{
	irq_desc_t *desc = irq_desc + irq;
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	switch (desc->depth) {
	case 1: {
		unsigned int status = desc->status & ~IRQ_DISABLED;
		desc->status = status;
		if ((status & (IRQ_PENDING | IRQ_REPLAY)) == IRQ_PENDING) {
			desc->status = status | IRQ_REPLAY;
			hw_resend_irq(desc->handler,irq);
		}
		desc->handler->enable(irq);
		/* fall-through */
	}
	default:
		desc->depth--;
		break;
	case 0:
		printk("enable_irq(%u) unbalanced from %p\n", irq,
		       __builtin_return_address(0));
	}
	spin_unlock_irqrestore(&desc->lock, flags);
}

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
asmlinkage unsigned int do_IRQ(int irq, struct pt_regs *regs)
{	
	/* 
	 * We ack quickly, we don't want the irq controller
	 * thinking we're snobs just because some other CPU has
	 * disabled global interrupts (we have already done the
	 * INT_ACK cycles, it's too late to try to pretend to the
	 * controller that we aren't taking the interrupt).
	 *
	 * 0 return value means that this irq is already being
	 * handled by some other CPU. (or is disabled)
	 */
	irq_desc_t *desc = irq_desc + irq;
	struct irqaction * action;
	unsigned int status;

	irq_enter();

#ifdef CONFIG_DEBUG_STACKOVERFLOW
	/* Debugging check for stack overflow: is there less than 1KB free? */
	{
		long esp;

		__asm__ __volatile__("andl %%esp,%0" :
					"=r" (esp) : "0" (THREAD_SIZE - 1));
		if (unlikely(esp < (sizeof(struct thread_info) + STACK_WARN))) {
			printk("do_IRQ: stack overflow: %ld\n",
				esp - sizeof(struct thread_info));
			dump_stack();
		}
	}
#endif
	kstat_this_cpu.irqs[irq]++;
	spin_lock(&desc->lock);
	desc->handler->ack(irq);
	/*
	   REPLAY is when Linux resends an IRQ that was dropped earlier
	   WAITING is used by probe to mark irqs that are being tested
	   */
	status = desc->status & ~(IRQ_REPLAY | IRQ_WAITING);
	status |= IRQ_PENDING; /* we _want_ to handle it */

	/*
	 * If the IRQ is disabled for whatever reason, we cannot
	 * use the action we have.
	 */
	action = NULL;
	if (likely(!(status & (IRQ_DISABLED | IRQ_INPROGRESS)))) {
		action = desc->action;
		status &= ~IRQ_PENDING; /* we commit to handling */
		status |= IRQ_INPROGRESS; /* we are handling it */
	}
	desc->status = status;

	/*
	 * If there is no IRQ handler or it was disabled, exit early.
	   Since we set PENDING, if another processor is handling
	   a different instance of this same irq, the other processor
	   will take care of it.
	 */
	if (unlikely(!action))
		goto out;

	/*
	 * Edge triggered interrupts need to remember
	 * pending events.
	 * This applies to any hw interrupts that allow a second
	 * instance of the same irq to arrive while we are in do_IRQ
	 * or in the handler. But the code here only handles the _second_
	 * instance of the irq, not the third or fourth. So it is mostly
	 * useful for irq hardware that does not mask cleanly in an
	 * SMP environment.
	 */
#ifdef CONFIG_4KSTACKS

	for (;;) {
		irqreturn_t action_ret;
		u32 *isp;
		union irq_ctx * curctx;
		union irq_ctx * irqctx;

		curctx = (union irq_ctx *) current_thread_info();
		irqctx = hardirq_ctx[smp_processor_id()];

		spin_unlock(&desc->lock);

		/*
		 * this is where we switch to the IRQ stack. However, if we are already using
		 * the IRQ stack (because we interrupted a hardirq handler) we can't do that
		 * and just have to keep using the current stack (which is the irq stack already
		 * after all)
		 */

		if (curctx == irqctx)
			action_ret = handle_IRQ_event(irq, regs, action);
		else {
			/* build the stack frame on the IRQ stack */
			isp = (u32*) ((char*)irqctx + sizeof(*irqctx));
			irqctx->tinfo.task = curctx->tinfo.task;
			irqctx->tinfo.previous_esp = current_stack_pointer();

			*--isp = (u32) action;
			*--isp = (u32) regs;
			*--isp = (u32) irq;

			asm volatile(
				"       xchgl   %%ebx,%%esp     \n"
				"       call    handle_IRQ_event \n"
				"       xchgl   %%ebx,%%esp     \n"
				: "=a"(action_ret)
				: "b"(isp)
				: "memory", "cc", "edx", "ecx"
			);


		}
		spin_lock(&desc->lock);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		if (curctx != irqctx)
			irqctx->tinfo.task = NULL;
		if (likely(!(desc->status & IRQ_PENDING)))
			break;
		desc->status &= ~IRQ_PENDING;
	}

#else

	for (;;) {
		irqreturn_t action_ret;

		spin_unlock(&desc->lock);

		action_ret = handle_IRQ_event(irq, regs, action);

		spin_lock(&desc->lock);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		if (likely(!(desc->status & IRQ_PENDING)))
			break;
		desc->status &= ~IRQ_PENDING;
	}
#endif
	desc->status &= ~IRQ_INPROGRESS;

out:
	/*
	 * The ->end() handler has to deal with interrupts which got
	 * disabled while the handler was running.
	 */
	desc->handler->end(irq);
	spin_unlock(&desc->lock);

	irq_exit();

	return 1;
}

int can_request_irq(unsigned int irq, unsigned long irqflags)
{
	struct irqaction *action;

	if (irq >= NR_IRQS)
		return 0;
	action = irq_desc[irq].action;
	if (action) {
		if (irqflags & action->flags & SA_SHIRQ)
			action = NULL;
	}
	return !action;
}

/**
 *	request_irq - allocate an interrupt line
 *	@irq: Interrupt line to allocate
 *	@handler: Function to be called when the IRQ occurs
 *	@irqflags: Interrupt type flags
 *	@devname: An ascii name for the claiming device
 *	@dev_id: A cookie passed back to the handler function
 *
 *	This call allocates interrupt resources and enables the
 *	interrupt line and IRQ handling. From the point this
 *	call is made your handler function may be invoked. Since
 *	your handler function must clear any interrupt the board 
 *	raises, you must take care both to initialise your hardware
 *	and to set up the interrupt handler in the right order.
 *
 *	Dev_id must be globally unique. Normally the address of the
 *	device data structure is used as the cookie. Since the handler
 *	receives this value it makes sense to use it.
 *
 *	If your interrupt is shared you must pass a non NULL dev_id
 *	as this is required when freeing the interrupt.
 *
 *	Flags:
 *
 *	SA_SHIRQ		Interrupt is shared
 *
 *	SA_INTERRUPT		Disable local interrupts while processing
 *
 *	SA_SAMPLE_RANDOM	The interrupt can be used for entropy
 *
 */
 
int request_irq(unsigned int irq, 
		irqreturn_t (*handler)(int, void *, struct pt_regs *),
		unsigned long irqflags, 
		const char * devname,
		void *dev_id)
{
	int retval;
	struct irqaction * action;

#if 1
	/*
	 * Sanity-check: shared interrupts should REALLY pass in
	 * a real dev-ID, otherwise we'll have trouble later trying
	 * to figure out which interrupt is which (messes up the
	 * interrupt freeing logic etc).
	 */
	if (irqflags & SA_SHIRQ) {
		if (!dev_id)
			printk("Bad boy: %s (at 0x%x) called us without a dev_id!\n", devname, (&irq)[-1]);
	}
#endif

	if (irq >= NR_IRQS)
		return -EINVAL;
	if (!handler)
		return -EINVAL;

	action = (struct irqaction *)
			kmalloc(sizeof(struct irqaction), GFP_ATOMIC);
	if (!action)
		return -ENOMEM;

	action->handler = handler;
	action->flags = irqflags;
	cpus_clear(action->mask);
	action->name = devname;
	action->next = NULL;
	action->dev_id = dev_id;

	retval = setup_irq(irq, action);
	if (retval)
		kfree(action);
	return retval;
}

EXPORT_SYMBOL(request_irq);

/**
 *	free_irq - free an interrupt
 *	@irq: Interrupt line to free
 *	@dev_id: Device identity to free
 *
 *	Remove an interrupt handler. The handler is removed and if the
 *	interrupt line is no longer in use by any driver it is disabled.
 *	On a shared IRQ the caller must ensure the interrupt is disabled
 *	on the card it drives before calling this function. The function
 *	does not return until any executing interrupts for this IRQ
 *	have completed.
 *
 *	This function must not be called from interrupt context. 
 */
 
void free_irq(unsigned int irq, void *dev_id)
{
	irq_desc_t *desc;
	struct irqaction **p;
	unsigned long flags;

	if (irq >= NR_IRQS)
		return;

	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock,flags);
	p = &desc->action;
	for (;;) {
		struct irqaction * action = *p;

		if (action) {
			struct irqaction **pp = p;
			p = &action->next;
			if (action->dev_id != dev_id)
				continue;

			/* Found it - now remove it from the list of entries */
			*pp = action->next;
			if (!desc->action) {
				desc->status |= IRQ_DISABLED;
				desc->handler->shutdown(irq);
			}
			spin_unlock_irqrestore(&desc->lock,flags);

			/* Wait to make sure it's not being used on another CPU */
			synchronize_irq(irq);

#define SA_STATIC_ACTION 0x01000000 /* Is it our duty to free the action? */
			if (!(action->flags & SA_STATIC_ACTION))
				kfree(action);
			return;
		}
		printk("Trying to free free IRQ%d\n",irq);
		spin_unlock_irqrestore(&desc->lock,flags);
		return;
	}
}

EXPORT_SYMBOL(free_irq);

/*
 * IRQ autodetection code..
 *
 * This depends on the fact that any interrupt that
 * comes in on to an unassigned handler will get stuck
 * with "IRQ_WAITING" cleared and the interrupt
 * disabled.
 */

static DECLARE_MUTEX(probe_sem);

/**
 *	probe_irq_on	- begin an interrupt autodetect
 *
 *	Commence probing for an interrupt. The interrupts are scanned
 *	and a mask of potential interrupt lines is returned.
 *
 */
 
unsigned long probe_irq_on(void)
{
	unsigned int i;
	irq_desc_t *desc;
	unsigned long val;
	unsigned long delay;

	down(&probe_sem);
	/* 
	 * something may have generated an irq long ago and we want to
	 * flush such a longstanding irq before considering it as spurious. 
	 */
	for (i = NR_PIRQS-1; i > 0; i--)  {
		desc = irq_desc + i;

		spin_lock_irq(&desc->lock);
		if (!irq_desc[i].action) 
			irq_desc[i].handler->startup(i);
		spin_unlock_irq(&desc->lock);
	}

	/* Wait for longstanding interrupts to trigger. */
	for (delay = jiffies + HZ/50; time_after(delay, jiffies); )
		/* about 20ms delay */ barrier();

	/*
	 * enable any unassigned irqs
	 * (we must startup again here because if a longstanding irq
	 * happened in the previous stage, it may have masked itself)
	 */
	for (i = NR_PIRQS-1; i > 0; i--) {
		desc = irq_desc + i;

		spin_lock_irq(&desc->lock);
		if (!desc->action) {
			desc->status |= IRQ_AUTODETECT | IRQ_WAITING;
			if (desc->handler->startup(i))
				desc->status |= IRQ_PENDING;
		}
		spin_unlock_irq(&desc->lock);
	}

	/*
	 * Wait for spurious interrupts to trigger
	 */
	for (delay = jiffies + HZ/10; time_after(delay, jiffies); )
		/* about 100ms delay */ barrier();

	/*
	 * Now filter out any obviously spurious interrupts
	 */
	val = 0;
	for (i = 0; i < NR_PIRQS; i++) {
		irq_desc_t *desc = irq_desc + i;
		unsigned int status;

		spin_lock_irq(&desc->lock);
		status = desc->status;

		if (status & IRQ_AUTODETECT) {
			/* It triggered already - consider it spurious. */
			if (!(status & IRQ_WAITING)) {
				desc->status = status & ~IRQ_AUTODETECT;
				desc->handler->shutdown(i);
			} else
				if (i < 32)
					val |= 1 << i;
		}
		spin_unlock_irq(&desc->lock);
	}

	return val;
}

EXPORT_SYMBOL(probe_irq_on);

/*
 * Return a mask of triggered interrupts (this
 * can handle only legacy ISA interrupts).
 */
 
/**
 *	probe_irq_mask - scan a bitmap of interrupt lines
 *	@val:	mask of interrupts to consider
 *
 *	Scan the ISA bus interrupt lines and return a bitmap of
 *	active interrupts. The interrupt probe logic state is then
 *	returned to its previous value.
 *
 *	Note: we need to scan all the irq's even though we will
 *	only return ISA irq numbers - just so that we reset them
 *	all to a known state.
 */
unsigned int probe_irq_mask(unsigned long val)
{
	int i;
	unsigned int mask;

	mask = 0;
	for (i = 0; i < NR_PIRQS; i++) {
		irq_desc_t *desc = irq_desc + i;
		unsigned int status;

		spin_lock_irq(&desc->lock);
		status = desc->status;

		if (status & IRQ_AUTODETECT) {
			if (i < 16 && !(status & IRQ_WAITING))
				mask |= 1 << i;

			desc->status = status & ~IRQ_AUTODETECT;
			desc->handler->shutdown(i);
		}
		spin_unlock_irq(&desc->lock);
	}
	up(&probe_sem);

	return mask & val;
}

/*
 * Return the one interrupt that triggered (this can
 * handle any interrupt source).
 */

/**
 *	probe_irq_off	- end an interrupt autodetect
 *	@val: mask of potential interrupts (unused)
 *
 *	Scans the unused interrupt lines and returns the line which
 *	appears to have triggered the interrupt. If no interrupt was
 *	found then zero is returned. If more than one interrupt is
 *	found then minus the first candidate is returned to indicate
 *	their is doubt.
 *
 *	The interrupt probe logic state is returned to its previous
 *	value.
 *
 *	BUGS: When used in a module (which arguably shouldnt happen)
 *	nothing prevents two IRQ probe callers from overlapping. The
 *	results of this are non-optimal.
 */
 
int probe_irq_off(unsigned long val)
{
	int i, irq_found, nr_irqs;

	nr_irqs = 0;
	irq_found = 0;
	for (i = 0; i < NR_PIRQS; i++) {
		irq_desc_t *desc = irq_desc + i;
		unsigned int status;

		spin_lock_irq(&desc->lock);
		status = desc->status;

		if (status & IRQ_AUTODETECT) {
			if (!(status & IRQ_WAITING)) {
				if (!nr_irqs)
					irq_found = i;
				nr_irqs++;
			}
			desc->status = status & ~IRQ_AUTODETECT;
			desc->handler->shutdown(i);
		}
		spin_unlock_irq(&desc->lock);
	}
	up(&probe_sem);

	if (nr_irqs > 1)
		irq_found = -irq_found;
	return irq_found;
}

EXPORT_SYMBOL(probe_irq_off);

/* this was setup_x86_irq but it seems pretty generic */
int setup_irq(unsigned int irq, struct irqaction * new)
{
	int shared = 0;
	unsigned long flags;
	struct irqaction *old, **p;
	irq_desc_t *desc = irq_desc + irq;

	if (desc->handler == &no_irq_type)
		return -ENOSYS;
	/*
	 * Some drivers like serial.c use request_irq() heavily,
	 * so we have to be careful not to interfere with a
	 * running system.
	 */
	if (new->flags & SA_SAMPLE_RANDOM) {
		/*
		 * This function might sleep, we want to call it first,
		 * outside of the atomic block.
		 * Yes, this might clear the entropy pool if the wrong
		 * driver is attempted to be loaded, without actually
		 * installing a new handler, but is this really a problem,
		 * only the sysadmin is able to do this.
		 */
		rand_initialize_irq(irq);
	}

	/*
	 * The following block of code has to be executed atomically
	 */
	spin_lock_irqsave(&desc->lock,flags);
	p = &desc->action;
	if ((old = *p) != NULL) {
		/* Can't share interrupts unless both agree to */
		if (!(old->flags & new->flags & SA_SHIRQ)) {
			spin_unlock_irqrestore(&desc->lock,flags);
			return -EBUSY;
		}

		/* add new interrupt at end of irq queue */
		do {
			p = &old->next;
			old = *p;
		} while (old);
		shared = 1;
	}

	*p = new;

	if (!shared) {
		desc->depth = 0;
		desc->status &= ~(IRQ_DISABLED | IRQ_AUTODETECT | IRQ_WAITING | IRQ_INPROGRESS);
		desc->handler->startup(irq);
	}
	spin_unlock_irqrestore(&desc->lock,flags);

	register_irq_proc(irq);
	return 0;
}

static struct proc_dir_entry * root_irq_dir;
static struct proc_dir_entry * irq_dir [NR_IRQS];

#ifdef CONFIG_SMP

static struct proc_dir_entry *smp_affinity_entry[NR_IRQS];

cpumask_t irq_affinity[NR_IRQS] = { [0 ... NR_IRQS-1] = CPU_MASK_ALL };

static int irq_affinity_read_proc(char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
	int len = cpumask_scnprintf(page, count, irq_affinity[(long)data]);
	if (count - len < 2)
		return -EINVAL;
	len += sprintf(page + len, "\n");
	return len;
}

static int irq_affinity_write_proc(struct file *file, const char __user *buffer,
					unsigned long count, void *data)
{
	int irq = (long)data, full_count = count, err;
	cpumask_t new_value, tmp;

	if (!irq_desc[irq].handler->set_affinity)
		return -EIO;

	err = cpumask_parse(buffer, count, new_value);
	if (err)
		return err;

	/*
	 * Do not allow disabling IRQs completely - it's a too easy
	 * way to make the system unusable accidentally :-) At least
	 * one online CPU still has to be targeted.
	 */
	cpus_and(tmp, new_value, cpu_online_map);
	if (cpus_empty(tmp))
		return -EINVAL;

	irq_affinity[irq] = new_value;
	irq_desc[irq].handler->set_affinity(irq,
					cpumask_of_cpu(first_cpu(new_value)));

	return full_count;
}

#endif
#define MAX_NAMELEN 10

static void register_irq_proc (unsigned int irq)
{
	char name [MAX_NAMELEN];

	if (!root_irq_dir || (irq_desc[irq].handler == &no_irq_type) ||
			irq_dir[irq])
		return;

	memset(name, 0, MAX_NAMELEN);
	sprintf(name, "%d", irq);

	/* create /proc/irq/1234 */
	irq_dir[irq] = proc_mkdir(name, root_irq_dir);

#ifdef CONFIG_SMP
	{
		struct proc_dir_entry *entry;

		/* create /proc/irq/1234/smp_affinity */
		entry = create_proc_entry("smp_affinity", 0600, irq_dir[irq]);

		if (entry) {
			entry->nlink = 1;
			entry->data = (void *)(long)irq;
			entry->read_proc = irq_affinity_read_proc;
			entry->write_proc = irq_affinity_write_proc;
		}

		smp_affinity_entry[irq] = entry;
	}
#endif
}

void init_irq_proc (void)
{
	int i;

	/* create /proc/irq */
	root_irq_dir = proc_mkdir("irq", NULL);
	create_prof_cpu_mask(root_irq_dir);
	/*
	 * Create entries for all existing IRQs.
	 */
	for (i = 0; i < NR_IRQS; i++)
		register_irq_proc(i);
}


#ifdef CONFIG_4KSTACKS
/*
 * These should really be __section__(".bss.page_aligned") as well, but
 * gcc's 3.0 and earlier don't handle that correctly.
 */
static char softirq_stack[NR_CPUS * THREAD_SIZE]  __attribute__((__aligned__(THREAD_SIZE)));
static char hardirq_stack[NR_CPUS * THREAD_SIZE]  __attribute__((__aligned__(THREAD_SIZE)));

/*
 * allocate per-cpu stacks for hardirq and for softirq processing
 */
void irq_ctx_init(int cpu)
{
	union irq_ctx *irqctx;

	if (hardirq_ctx[cpu])
		return;

	irqctx = (union irq_ctx*) &hardirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = HARDIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	hardirq_ctx[cpu] = irqctx;

	irqctx = (union irq_ctx*) &softirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = SOFTIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	softirq_ctx[cpu] = irqctx;

	printk("CPU %u irqstacks, hard=%p soft=%p\n",
		cpu,hardirq_ctx[cpu],softirq_ctx[cpu]);
}

extern asmlinkage void __do_softirq(void);

asmlinkage void do_softirq(void)
{
	unsigned long flags;
	struct thread_info *curctx;
	union irq_ctx *irqctx;
	u32 *isp;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	if (local_softirq_pending()) {
		curctx = current_thread_info();
		irqctx = softirq_ctx[smp_processor_id()];
		irqctx->tinfo.task = curctx->task;
		irqctx->tinfo.previous_esp = current_stack_pointer();

		/* build the stack frame on the softirq stack */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));


		asm volatile(
			"       xchgl   %%ebx,%%esp     \n"
			"       call    __do_softirq    \n"
			"       movl    %%ebx,%%esp     \n"
			: "=b"(isp)
			: "0"(isp)
			: "memory", "cc", "edx", "ecx", "eax"
		);
	}

	local_irq_restore(flags);
}

EXPORT_SYMBOL(do_softirq);
#endif
