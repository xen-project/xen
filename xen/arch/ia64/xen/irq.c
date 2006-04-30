/*
 *	linux/arch/ia64/kernel/irq.c
 *
 *	Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the code used by various IRQ handling routines:
 * asking for different IRQ's should be done through these routines
 * instead of just grabbing them. Thus setups with different IRQ numbers
 * shouldn't result in any weird surprises, and installing new handlers
 * should be easier.
 *
 * Copyright (C) Ashok Raj<ashok.raj@intel.com>, Intel Corporation 2004
 *
 * 4/14/2004: Added code to handle cpu migration and do safe irq
 *			migration without lossing interrupts for iosapic
 *			architecture.
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
#include <linux/sched.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/timex.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/seq_file.h>

#include <asm/atomic.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/delay.h>
#include <xen/irq.h>
#include <asm/hw_irq.h>

#include <xen/event.h>
#define apicid_to_phys_cpu_present(x)	1

/*
 * Linux has a controller-independent x86 interrupt architecture.
 * every controller has a 'controller-template', that is used
 * by the main code to do the right thing. Each driver-visible
 * interrupt source is transparently wired to the appropriate
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
		.status = IRQ_DISABLED | IRQ_GUEST,
		.handler = &no_irq_type,
		.lock = SPIN_LOCK_UNLOCKED
	}
};

/*
 * Special irq handlers.
 */

void no_action(int cpl, void *dev_id, struct pt_regs *regs) { }

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
	printk(KERN_ERR "Unexpected irq vector 0x%x on CPU %u!\n", irq, smp_processor_id());
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

/* Some placeholder here, which are used by other files and we
 * don't want to change too much now. Later they should be cleaned.
 */
#ifdef CONFIG_SMP
inline void synchronize_irq(unsigned int irq) {}
EXPORT_SYMBOL(synchronize_irq);
#endif

static int noirqdebug;

static int __init noirqdebug_setup(char *str)
{
	noirqdebug = 1;
	printk("IRQ lockup detection disabled\n");
	return 1;
}

__setup("noirqdebug", noirqdebug_setup);

/*
 * Generic enable/disable code: this just calls
 * down into the PIC-specific version for the actual
 * hardware disable after having gotten the irq
 * controller lock.
 */

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs)
{
	irq_desc_t *desc = irq_desc + irq;
	struct irqaction * action;
	unsigned int status;

	if (likely(desc->status & IRQ_PER_CPU)) {
		/*
		 * No locking required for CPU-local interrupts:
		 */
		desc->handler->ack(irq);
		local_irq_enable();
		desc->action->handler(irq, desc->action->dev_id, regs);
		local_irq_disable();
		desc->handler->end(irq);
		return 1;
	}

	spin_lock(&desc->lock);

	if (desc->status & IRQ_GUEST) {
		/* __do_IRQ_guest(irq); */
		vcpu_pend_interrupt(dom0->vcpu[0],irq);
		vcpu_wake(dom0->vcpu[0]);
		spin_unlock(&desc->lock);
		return 1;
	}

	desc->handler->ack(irq);
	status = desc->status & ~IRQ_REPLAY;
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
	 * Since we set PENDING, if another processor is handling
	 * a different instance of this same irq, the other processor
	 * will take care of it.
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
	for (;;) {
		spin_unlock_irq(&desc->lock);
		action->handler(irq, action->dev_id, regs);
		spin_lock_irq(&desc->lock);

		if (likely(!(desc->status & IRQ_PENDING)))
			break;

		desc->status &= ~IRQ_PENDING;
	}
	desc->status &= ~IRQ_INPROGRESS;

out:
	/*
	 * The ->end() handler has to deal with interrupts which got
	 * disabled while the handler was running.
	 */
	desc->handler->end(irq);
	spin_unlock(&desc->lock);

	return 1;
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

	/*
	 * Sanity-check: shared interrupts should REALLY pass in
	 * a real dev-ID, otherwise we'll have trouble later trying
	 * to figure out which interrupt is which (messes up the
	 * interrupt freeing logic etc).
	 */
	if (irqflags & SA_SHIRQ) {
		if (!dev_id)
			printk(KERN_ERR "Bad boy: %s called us without a dev_id!\n", devname);
	}

	if (irq >= NR_IRQS)
		return -EINVAL;
	if (!handler)
		return -EINVAL;

	action = xmalloc(struct irqaction);
	if (!action)
		return -ENOMEM;

	action->handler = (void *) handler;
	action->name = devname;
	action->dev_id = dev_id;

	retval = setup_irq(irq, action);
	if (retval)
		xfree(action);
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

void free_irq(unsigned int irq)
{
	irq_desc_t *desc;
	unsigned long flags;

	if (irq >= NR_IRQS)
		return;

	desc = irq_descp(irq);
	spin_lock_irqsave(&desc->lock,flags);
	if (desc->action) {
		struct irqaction * action = desc->action;
		desc->action = NULL;
				desc->status |= IRQ_DISABLED;
				desc->handler->shutdown(irq);
			spin_unlock_irqrestore(&desc->lock,flags);

			/* Wait to make sure it's not being used on another CPU */
			synchronize_irq(irq);
			xfree(action);
			return;
		}
		printk(KERN_ERR "Trying to free free IRQ%d\n",irq);
		spin_unlock_irqrestore(&desc->lock,flags);
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

int setup_irq(unsigned int irq, struct irqaction * new)
{
	unsigned long flags;
	struct irqaction *old, **p;
	irq_desc_t *desc = irq_descp(irq);

	/*
	 * The following block of code has to be executed atomically
	 */
	spin_lock_irqsave(&desc->lock,flags);
	p = &desc->action;
	if ((old = *p) != NULL) {
		spin_unlock_irqrestore(&desc->lock,flags);
		return -EBUSY;
	}

	*p = new;

	desc->depth = 0;
	desc->status &= ~(IRQ_DISABLED | IRQ_INPROGRESS | IRQ_GUEST);
	desc->handler->startup(irq);
	spin_unlock_irqrestore(&desc->lock,flags);

	return 0;
}

/*
 * HANDLING OF GUEST-BOUND PHYSICAL IRQS
 */

#define IRQ_MAX_GUESTS 7
typedef struct {
    u8 nr_guests;
    u8 in_flight;
    u8 shareable;
    struct domain *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

void __do_IRQ_guest(int irq)
{
    irq_desc_t         *desc = &irq_desc[irq];
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i;

    for ( i = 0; i < action->nr_guests; i++ )
    {
        d = action->guest[i];
        if ( !test_and_set_bit(irq, &d->pirq_mask) )
            action->in_flight++;
        send_guest_pirq(d, irq);
    }
}

int pirq_guest_eoi(struct domain *d, int irq)
{
    irq_desc_t *desc;

    if ( (irq < 0) || (irq >= NR_IRQS) )
        return -EINVAL;

    desc = &irq_desc[irq];
    spin_lock_irq(&desc->lock);
    if ( test_and_clear_bit(irq, &d->pirq_mask) &&
         (--((irq_guest_action_t *)desc->action)->in_flight == 0) )
        desc->handler->end(irq);
    spin_unlock_irq(&desc->lock);

    return 0;

}

int pirq_guest_unmask(struct domain *d)
{
    irq_desc_t    *desc;
    int            irq;
    shared_info_t *s = d->shared_info;

    for ( irq = find_first_bit(d->pirq_mask, NR_PIRQS);
          irq < NR_PIRQS;
          irq = find_next_bit(d->pirq_mask, NR_PIRQS, irq+1) )
    {
        desc = &irq_desc[irq];
        spin_lock_irq(&desc->lock);
        if ( !test_bit(d->pirq_to_evtchn[irq], &s->evtchn_mask[0]) &&
             test_and_clear_bit(irq, &d->pirq_mask) &&
             (--((irq_guest_action_t *)desc->action)->in_flight == 0) )
            desc->handler->end(irq);
        spin_unlock_irq(&desc->lock);
    }

    return 0;
}

int pirq_guest_bind(struct vcpu *v, int irq, int will_share)
{
    irq_desc_t         *desc = &irq_desc[irq];
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 rc = 0;

    spin_lock_irqsave(&desc->lock, flags);

    action = (irq_guest_action_t *)desc->action;

    if ( !(desc->status & IRQ_GUEST) )
    {
        if ( desc->action != NULL )
        {
            DPRINTK("Cannot bind IRQ %d to guest. In use by '%s'.\n",
                    irq, desc->action->name);
            rc = -EBUSY;
            goto out;
        }

        action = xmalloc(irq_guest_action_t);
        if ( (desc->action = (struct irqaction *)action) == NULL )
        {
            DPRINTK("Cannot bind IRQ %d to guest. Out of memory.\n", irq);
            rc = -ENOMEM;
            goto out;
        }

        action->nr_guests = 0;
        action->in_flight = 0;
        action->shareable = will_share;
        
        desc->depth = 0;
        desc->status |= IRQ_GUEST;
        desc->status &= ~IRQ_DISABLED;
        desc->handler->startup(irq);

        /* Attempt to bind the interrupt target to the correct CPU. */
#if 0 /* FIXME CONFIG_SMP ??? */
        if ( desc->handler->set_affinity != NULL )
            desc->handler->set_affinity(
                irq, apicid_to_phys_cpu_present(d->processor));
#endif
    }
    else if ( !will_share || !action->shareable )
    {
        DPRINTK("Cannot bind IRQ %d to guest. Will not share with others.\n",
                irq);
        rc = -EBUSY;
        goto out;
    }

    if ( action->nr_guests == IRQ_MAX_GUESTS )
    {
        DPRINTK("Cannot bind IRQ %d to guest. Already at max share.\n", irq);
        rc = -EBUSY;
        goto out;
    }

    action->guest[action->nr_guests++] = v->domain;

 out:
    spin_unlock_irqrestore(&desc->lock, flags);
    return rc;
}

int pirq_guest_unbind(struct domain *d, int irq)
{
    irq_desc_t         *desc = &irq_desc[irq];
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 i;

    spin_lock_irqsave(&desc->lock, flags);

    action = (irq_guest_action_t *)desc->action;

    if ( test_and_clear_bit(irq, &d->pirq_mask) &&
         (--action->in_flight == 0) )
        desc->handler->end(irq);

    if ( action->nr_guests == 1 )
    {
        desc->action = NULL;
        xfree(action);
        desc->depth   = 1;
        desc->status |= IRQ_DISABLED;
        desc->status &= ~IRQ_GUEST;
        desc->handler->shutdown(irq);
    }
    else
    {
        i = 0;
        while ( action->guest[i] != d )
            i++;
        memmove(&action->guest[i], &action->guest[i+1], IRQ_MAX_GUESTS-i-1);
        action->nr_guests--;
    }

    spin_unlock_irqrestore(&desc->lock, flags);    
    return 0;
}

void
xen_debug_irq(unsigned long vector, struct pt_regs *regs)
{
//FIXME: For debug only, can be removed
	static char firstirq = 1;
	static char firsttime[256];
	static char firstpend[256];
	if (firstirq) {
		int i;
		for (i=0;i<256;i++) firsttime[i] = 1;
		for (i=0;i<256;i++) firstpend[i] = 1;
		firstirq = 0;
	}
	if (firsttime[vector]) {
		printf("**** (entry) First received int on vector=%lu,itc=%lx\n",
			(unsigned long) vector, ia64_get_itc());
		firsttime[vector] = 0;
	}
}

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	sub_preempt_count(IRQ_EXIT_OFFSET);
}

/*
 * ONLY gets called from ia64_leave_kernel
 * ONLY call with interrupts enabled
 */
void process_soft_irq(void)
{
	if (!in_interrupt() && local_softirq_pending()) {
		add_preempt_count(SOFTIRQ_OFFSET);
		do_softirq();
		sub_preempt_count(SOFTIRQ_OFFSET);
	}
}

// this is a temporary hack until real console input is implemented
extern void domain_pend_keyboard_interrupt(int irq);
irqreturn_t guest_forward_keyboard_input(int irq, void *nada, struct pt_regs *regs)
{
	domain_pend_keyboard_interrupt(irq);
	return 0;
}

void serial_input_init(void)
{
	int retval;
	int irq = 0x30;	// FIXME

	retval = request_irq(irq,guest_forward_keyboard_input,SA_INTERRUPT,"siminput",NULL);
	if (retval) {
		printk("serial_input_init: broken request_irq call\n");
		while(1);
	}
}
