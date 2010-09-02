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
#include <asm/pgalloc.h>
#include <asm/delay.h>
#include <xen/irq.h>
#include <asm/hw_irq.h>

#include <xen/event.h>
#define apicid_to_phys_cpu_present(x)	1

#ifdef CONFIG_IA64_GENERIC
unsigned int __ia64_local_vector_to_irq (ia64_vector vec)
{
	return (unsigned int) vec;
}
#endif

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
irq_desc_t irq_desc[NR_IRQS] = {
	[0 ... NR_IRQS-1] = {
		.status = IRQ_DISABLED,
		.handler = &no_irq_type,
		.lock = SPIN_LOCK_UNLOCKED
	}
};

struct irq_cfg irq_cfg[NR_IRQS] = {
    [0 ... NR_IRQS-1] ={
        .vector = -1,
        .cpu_mask = CPU_MASK_ALL,
}
};

void __do_IRQ_guest(int irq);

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

hw_irq_controller no_irq_type = {
	"none",
	startup_none,
	shutdown_none,
	enable_none,
	disable_none,
	ack_none,
	end_none
};

atomic_t irq_err_count;

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
		__do_IRQ_guest(irq);
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

/*
 * IRQ autodetection code..
 *
 * This depends on the fact that any interrupt that
 * comes in on to an unassigned handler will get stuck
 * with "IRQ_WAITING" cleared and the interrupt
 * disabled.
 */

int setup_vector(unsigned int vector, struct irqaction * new)
{
	unsigned long flags;
	struct irqaction *old, **p;
	irq_desc_t *desc = irq_descp(vector);
    struct irq_cfg *cfg = irq_cfg(vector);

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
	desc->handler->startup(vector);
	desc->handler->enable(vector);
    desc->chip_data = cfg;
    cfg->vector = vector;
	spin_unlock_irqrestore(&desc->lock,flags);

	return 0;
}

/* Vectors reserved by xen (and thus not sharable with domains).  */
unsigned long ia64_xen_vector[BITS_TO_LONGS(NR_IRQS)];

int setup_irq_vector(unsigned int vec, struct irqaction * new)
{
	int res;

	if ( vec == IA64_INVALID_VECTOR )
		return -ENOSYS;
	/* Reserve the vector (and thus the irq).  */
	if (test_and_set_bit(vec, ia64_xen_vector))
		return -EBUSY;
	res = setup_vector (vec, new);
	return res;
}

void release_irq_vector(unsigned int vec)
{
	unsigned long flags;
	irq_desc_t *desc;
    struct irq_cfg *cfg;

	if ( vec == IA64_INVALID_VECTOR )
		return;

	desc = irq_descp(vec);
    cfg = irq_cfg(vec);

	spin_lock_irqsave(&desc->lock, flags);
	clear_bit(vec, ia64_xen_vector);
	desc->action = NULL;
	desc->depth = 1;
	desc->status |= IRQ_DISABLED;
	desc->handler->shutdown(vec);
    desc->chip_data = NULL;
    cfg->vector = -1;
	spin_unlock_irqrestore(&desc->lock, flags);

	while (desc->status & IRQ_INPROGRESS)
		cpu_relax();
}

/*
 * HANDLING OF GUEST-BOUND PHYSICAL IRQS
 */

#define IRQ_MAX_GUESTS 7
typedef struct {
    u8 nr_guests;
    u8 in_flight;
    u8 shareable;
    u8 ack_type;
#define ACKTYPE_NONE   0     /* No final acknowledgement is required */
#define ACKTYPE_UNMASK 1     /* Unmask notification is required */
    struct domain *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

static inline void set_pirq_eoi(struct domain *d, unsigned int irq)
{
    if ( d->arch.pirq_eoi_map )
        set_bit(irq, d->arch.pirq_eoi_map);
}

static inline void clear_pirq_eoi(struct domain *d, unsigned int irq)
{
    if ( d->arch.pirq_eoi_map )
        clear_bit(irq, d->arch.pirq_eoi_map);
}

static void _irq_guest_eoi(irq_desc_t *desc)
{
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    unsigned int i, vector = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST_EOI_PENDING) )
        return;

    for ( i = 0; i < action->nr_guests; ++i )
        clear_pirq_eoi(action->guest[i], vector);

    desc->status &= ~(IRQ_INPROGRESS|IRQ_GUEST_EOI_PENDING);
    desc->handler->enable(vector);
}

static struct timer irq_guest_eoi_timer[NR_IRQS];
static void irq_guest_eoi_timer_fn(void *data)
{
	irq_desc_t *desc = data;
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	_irq_guest_eoi(desc);
	spin_unlock_irqrestore(&desc->lock, flags);
}

void __do_IRQ_guest(int irq)
{
    irq_desc_t         *desc = &irq_desc[irq];
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i, already_pending = 0;

    for ( i = 0; i < action->nr_guests; i++ )
    {
        d = action->guest[i];
        if ( (action->ack_type != ACKTYPE_NONE) &&
             !test_and_set_bit(irq, &d->pirq_mask) )
            action->in_flight++;
		if ( hvm_do_IRQ_dpci(d, irq) )
		{
			if ( action->ack_type == ACKTYPE_NONE )
			{
				already_pending += !!(desc->status & IRQ_INPROGRESS);
				desc->status |= IRQ_INPROGRESS; /* cleared during hvm eoi */
			}
		}
		else if ( send_guest_pirq(d, irq) &&
				(action->ack_type == ACKTYPE_NONE) )
		{
			already_pending++;
		}
	}

	if ( already_pending == action->nr_guests )
	{
		stop_timer(&irq_guest_eoi_timer[irq]);
		desc->handler->disable(irq);
        desc->status |= IRQ_GUEST_EOI_PENDING;
        for ( i = 0; i < already_pending; ++i )
        {
            d = action->guest[i];
            set_pirq_eoi(d, irq);
            /*
             * Could check here whether the guest unmasked the event by now
             * (or perhaps just re-issue the send_guest_pirq()), and if it
             * can now accept the event,
             * - clear all the pirq_eoi bits we already set,
             * - re-enable the vector, and
             * - skip the timer setup below.
             */
        }
		init_timer(&irq_guest_eoi_timer[irq],
				irq_guest_eoi_timer_fn, desc, smp_processor_id());
		set_timer(&irq_guest_eoi_timer[irq], NOW() + MILLISECS(1));
	}
}

static int pirq_acktype(int irq)
{
    irq_desc_t *desc = &irq_desc[irq];

    if (!strcmp(desc->handler->typename, "IO-SAPIC-level"))
        return ACKTYPE_UNMASK;

    if (!strcmp(desc->handler->typename, "IO-SAPIC-edge"))
        return ACKTYPE_NONE;

    return ACKTYPE_NONE;
}

int pirq_guest_eoi(struct domain *d, int irq)
{
    irq_desc_t *desc;
    irq_guest_action_t *action;

    if ( (irq < 0) || (irq >= NR_IRQS) )
        return -EINVAL;

    desc = &irq_desc[irq];
    spin_lock_irq(&desc->lock);
    action = (irq_guest_action_t *)desc->action;

    if ( action->ack_type == ACKTYPE_NONE )
    {
        ASSERT(!test_bit(irq, d->pirq_mask));
        stop_timer(&irq_guest_eoi_timer[irq]);
        _irq_guest_eoi(desc);
    }

    if ( test_and_clear_bit(irq, &d->pirq_mask) && (--action->in_flight == 0) )
    {
        ASSERT(action->ack_type == ACKTYPE_UNMASK);
        desc->handler->end(irq);
    }
    spin_unlock_irq(&desc->lock);

    return 0;

}

int pirq_guest_unmask(struct domain *d)
{
    int            irq;
    shared_info_t *s = d->shared_info;

    for ( irq = find_first_bit(d->pirq_mask, NR_IRQS);
          irq < NR_IRQS;
          irq = find_next_bit(d->pirq_mask, NR_IRQS, irq+1) )
    {
        if ( !test_bit(d->pirq_to_evtchn[irq], &s->evtchn_mask[0]) )
            pirq_guest_eoi(d, irq);

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

    if (desc->handler == &no_irq_type) {
        spin_unlock_irqrestore(&desc->lock, flags);
        return -ENOSYS;
    }

    action = (irq_guest_action_t *)desc->action;

    if ( !(desc->status & IRQ_GUEST) )
    {
        if ( desc->action != NULL )
        {
            gdprintk(XENLOG_INFO,
                    "Cannot bind IRQ %d to guest. In use by '%s'.\n",
                    irq, desc->action->name);
            rc = -EBUSY;
            goto out;
        }

        action = xmalloc(irq_guest_action_t);
        if ( (desc->action = (struct irqaction *)action) == NULL )
        {
            gdprintk(XENLOG_INFO,
                    "Cannot bind IRQ %d to guest. Out of memory.\n",
                    irq);
            rc = -ENOMEM;
            goto out;
        }

        action->nr_guests = 0;
        action->in_flight = 0;
        action->shareable = will_share;
        action->ack_type  = pirq_acktype(irq);
        
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
        gdprintk(XENLOG_INFO,
                "Cannot bind IRQ %d to guest. Will not share with others.\n",
                irq);
        rc = -EBUSY;
        goto out;
    }

    if ( action->nr_guests == IRQ_MAX_GUESTS )
    {
        gdprintk(XENLOG_INFO,
                "Cannot bind IRQ %d to guest. Already at max share.\n",
                irq);
        rc = -EBUSY;
        goto out;
    }

    action->guest[action->nr_guests++] = v->domain;

    if ( action->ack_type != ACKTYPE_NONE )
        set_pirq_eoi(v->domain, irq);
    else
        clear_pirq_eoi(v->domain, irq);

 out:
    spin_unlock_irqrestore(&desc->lock, flags);
    return rc;
}

void pirq_guest_unbind(struct domain *d, int irq)
{
    irq_desc_t         *desc = &irq_desc[irq];
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 i;

    spin_lock_irqsave(&desc->lock, flags);

    action = (irq_guest_action_t *)desc->action;

    for ( i = 0; (i < action->nr_guests) && (action->guest[i] != d); i++ )
        continue;
    BUG_ON(i == action->nr_guests);
    memmove(&action->guest[i], &action->guest[i+1], IRQ_MAX_GUESTS-i-1);
    action->nr_guests--;

    if ( action->ack_type == ACKTYPE_UNMASK )
        if ( test_and_clear_bit(irq, &d->pirq_mask) &&
             (--action->in_flight == 0) )
            desc->handler->end(irq);

    if ( !action->nr_guests )
    {
        BUG_ON(action->in_flight != 0);
        desc->action = NULL;
        xfree(action);
        desc->depth   = 1;
        desc->status |= IRQ_DISABLED;
        desc->status &= ~IRQ_GUEST;
        desc->handler->shutdown(irq);
    }

    spin_unlock_irqrestore(&desc->lock, flags);    
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
		printk("**** (entry) First received int on vector=%lu,itc=%lx\n",
			(unsigned long) vector, ia64_get_itc());
		firsttime[vector] = 0;
	}
}

void pirq_set_affinity(struct domain *d, int irq, const cpumask_t *mask)
{
	/* FIXME */
}

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	sub_preempt_count(IRQ_EXIT_OFFSET);
}
