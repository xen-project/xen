/*
 *      linux/arch/i386/kernel/irq.c
 *
 *      Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the code used by various IRQ handling routines:
 * asking for different IRQ's should be done through these routines
 * instead of just grabbing them. Thus setup_irqs with different IRQ numbers
 * shouldn't result in any weird surprises, and installing new handlers
 * should be easier.
 */

/*
 * (mostly architecture independent, will move to kernel/irq.c in 2.5.)
 *
 * IRQs are in fact implemented a bit like signal handlers for the kernel.
 * Naturally it's not a 1:1 relation, but there are similarities.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/interrupt.h>
#include <xen/irq.h>
#include <xen/slab.h>
#include <xen/event.h>
#include <asm/mpspec.h>
#include <asm/io_apic.h>
#include <asm/msr.h>
#include <asm/hardirq.h>
#include <asm/ptrace.h>
#include <asm/atomic.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/flushtlb.h>
#include <xen/delay.h>
#include <xen/perfc.h>
#include <asm/smpboot.h>

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
irq_desc_t irq_desc[NR_IRQS] __cacheline_aligned =
{ [0 ... NR_IRQS-1] = { 0, &no_irq_type, NULL, 0, SPIN_LOCK_UNLOCKED}};

static void __do_IRQ_guest(int irq);

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
 * each architecture has to answer this themselves, it doesnt deserve
 * a generic callback i think.
 */
#if CONFIG_X86
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
#define shutdown_none   disable_none
#define end_none        enable_none

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
#ifdef CONFIG_X86_IO_APIC
#ifdef APIC_MISMATCH_DEBUG
atomic_t irq_mis_count;
#endif
#endif

/*
 * Generic, controller-independent functions:
 */

/*
 * This should really return information about whether
 * we should do bottom half handling etc. Right now we
 * end up _always_ checking the bottom half, which is a
 * waste of time and is not what some drivers would
 * prefer.
 */
static int handle_IRQ_event(unsigned int irq, 
                            struct pt_regs * regs, 
                            struct irqaction * action)
{
    int status;
    int cpu = smp_processor_id();

    irq_enter(cpu, irq);

    status = 1; /* Force the "do bottom halves" bit */

    if (!(action->flags & SA_INTERRUPT))
        __sti();

    do {
        status |= action->flags;
        action->handler(irq, action->dev_id, regs);
        action = action->next;
    } while (action);

    __cli();

    irq_exit(cpu, irq);

    return status;
}

/*
 * Generic enable/disable code: this just calls
 * down into the PIC-specific version for the actual
 * hardware disable after having gotten the irq
 * controller lock. 
 */
 
/**
 *      disable_irq_nosync - disable an irq without waiting
 *      @irq: Interrupt to disable
 *
 *      Disable the selected interrupt line.  Disables and Enables are
 *      nested.
 *      Unlike disable_irq(), this function does not ensure existing
 *      instances of the IRQ handler have completed before returning.
 *
 *      This function may be called from IRQ context.
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
 *      disable_irq - disable an irq and wait for completion
 *      @irq: Interrupt to disable
 *
 *      Disable the selected interrupt line.  Enables and Disables are
 *      nested.
 *      This function waits for any pending IRQ handlers for this interrupt
 *      to complete before returning. If you use this function while
 *      holding a resource the IRQ handler may need you will deadlock.
 *
 *      This function may be called - with care - from IRQ context.
 */
 
void disable_irq(unsigned int irq)
{
    disable_irq_nosync(irq);

    if (!local_irq_count(smp_processor_id())) {
        do {
            barrier();
            cpu_relax();
        } while (irq_desc[irq].status & IRQ_INPROGRESS);
    }
}

/**
 *      enable_irq - enable handling of an irq
 *      @irq: Interrupt to enable
 *
 *      Undoes the effect of one call to disable_irq().  If this
 *      matches the last disable, processing of interrupts on this
 *      IRQ line is re-enabled.
 *
 *      This function may be called from IRQ context.
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
asmlinkage unsigned int do_IRQ(struct pt_regs regs)
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
    int irq = regs.orig_eax & 0xff; /* high bits used in ret_from_ code  */
    irq_desc_t *desc = irq_desc + irq;
    struct irqaction * action;
    unsigned int status;

#ifdef PERF_COUNTERS
    int cpu = smp_processor_id();
    u32 cc_start, cc_end;

    perfc_incra(irqs, cpu);
    rdtscl(cc_start);
#endif

    spin_lock(&desc->lock);
    desc->handler->ack(irq);

    /*
      REPLAY is when Linux resends an IRQ that was dropped earlier
      WAITING is used by probe to mark irqs that are being tested
    */
    status = desc->status & ~(IRQ_REPLAY | IRQ_WAITING);
    status |= IRQ_PENDING; /* we _want_ to handle it */

    /* We hook off guest-bound IRQs for special handling. */
    if ( status & IRQ_GUEST )
    {
        __do_IRQ_guest(irq);
        spin_unlock(&desc->lock);
        return 1;
    }

    /*
     * If the IRQ is disabled for whatever reason, we cannot use the action we 
     * have.
     */
    action = NULL;
    if (!(status & (IRQ_DISABLED | IRQ_INPROGRESS))) {
        action = desc->action;
        status &= ~IRQ_PENDING; /* we commit to handling */
        status |= IRQ_INPROGRESS; /* we are handling it */
    }
    desc->status = status;

    /*
     * If there is no IRQ handler or it was disabled, exit early. Since we set 
     * PENDING, if another processor is handling a different instance of this 
     * same irq, the other processor will take care of it.
     */
    if (!action)
        goto out;

    /*
     * Edge triggered interrupts need to remember pending events. This applies 
     * to any hw interrupts that allow a second instance of the same irq to 
     * arrive while we are in do_IRQ or in the handler. But the code here only 
     * handles the _second_ instance of the irq, not the third or fourth. So 
     * it is mostly useful for irq hardware that does not mask cleanly in an
     * SMP environment.
     */
    for (;;) {
        spin_unlock(&desc->lock);
        handle_IRQ_event(irq, &regs, action);
        spin_lock(&desc->lock);
                
        if (!(desc->status & IRQ_PENDING))
            break;
        desc->status &= ~IRQ_PENDING;
    }
    desc->status &= ~IRQ_INPROGRESS;
 out:
    /*
     * The ->end() handler has to deal with interrupts which got disabled 
     * while the handler was running.
     */
    desc->handler->end(irq);
    spin_unlock(&desc->lock);

#ifdef PERF_COUNTERS
    rdtscl(cc_end);

    if ( !action || (!(action->flags & SA_NOPROFILE)) )
    {
        perfc_adda(irq_time, cpu, cc_end - cc_start);
#ifndef NDEBUG
        if ( (cc_end - cc_start) > (cpu_khz * 100) )
            printk("Long interrupt %08x -> %08x\n", cc_start, cc_end);
#endif
    }
#endif

    return 1;
}

/**
 *      request_irq - allocate an interrupt line
 *      @irq: Interrupt line to allocate
 *      @handler: Function to be called when the IRQ occurs
 *      @irqflags: Interrupt type flags
 *      @devname: An ascii name for the claiming device
 *      @dev_id: A cookie passed back to the handler function
 *
 *      This call allocates interrupt resources and enables the
 *      interrupt line and IRQ handling. From the point this
 *      call is made your handler function may be invoked. Since
 *      your handler function must clear any interrupt the board 
 *      raises, you must take care both to initialise your hardware
 *      and to set up the interrupt handler in the right order.
 *
 *      Dev_id must be globally unique. Normally the address of the
 *      device data structure is used as the cookie. Since the handler
 *      receives this value it makes sense to use it.
 *
 *      If your interrupt is shared you must pass a non NULL dev_id
 *      as this is required when freeing the interrupt.
 *
 *      Flags:
 *
 *      SA_SHIRQ                Interrupt is shared
 *
 *      SA_INTERRUPT            Disable local interrupts while processing
 */
 
int request_irq(unsigned int irq, 
                void (*handler)(int, void *, struct pt_regs *),
                unsigned long irqflags, 
                const char * devname,
                void *dev_id)
{
    int retval;
    struct irqaction * action;

    if (irq >= NR_IRQS)
        return -EINVAL;
    if (!handler)
        return -EINVAL;

    action = (struct irqaction *)
        kmalloc(sizeof(struct irqaction), GFP_KERNEL);
    if (!action)
        return -ENOMEM;

    action->handler = handler;
    action->flags = irqflags;
    action->mask = 0;
    action->name = devname;
    action->next = NULL;
    action->dev_id = dev_id;

    retval = setup_irq(irq, action);
    if (retval)
        kfree(action);

    return retval;
}

/**
 *      free_irq - free an interrupt
 *      @irq: Interrupt line to free
 *      @dev_id: Device identity to free
 *
 *      Remove an interrupt handler. The handler is removed and if the
 *      interrupt line is no longer in use by any driver it is disabled.
 *      On a shared IRQ the caller must ensure the interrupt is disabled
 *      on the card it drives before calling this function. The function
 *      does not return until any executing interrupts for this IRQ
 *      have completed.
 *
 *      This function may be called from interrupt context. 
 *
 *      Bugs: Attempting to free an irq in a handler for the same irq hangs
 *            the machine.
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

#ifdef CONFIG_SMP
            /* Wait to make sure it's not being used on another CPU */
            while (desc->status & IRQ_INPROGRESS) {
                barrier();
                cpu_relax();
            }
#endif
            kfree(action);
            return;
        }
        printk("Trying to free free IRQ%d\n",irq);
        spin_unlock_irqrestore(&desc->lock,flags);
        return;
    }
}

int setup_irq(unsigned int irq, struct irqaction * new)
{
    int shared = 0;
    unsigned long flags;
    struct irqaction *old, **p;
    irq_desc_t *desc = irq_desc + irq;

    /*
     * The following block of code has to be executed atomically
     */
    spin_lock_irqsave(&desc->lock,flags);

    if ( desc->status & IRQ_GUEST )
    {
        spin_unlock_irqrestore(&desc->lock,flags);
        return -EBUSY;
    }

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
        desc->status &= ~(IRQ_DISABLED | IRQ_AUTODETECT | IRQ_WAITING);
        desc->handler->startup(irq);
    }

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
    struct task_struct *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

static void __do_IRQ_guest(int irq)
{
    irq_desc_t *desc = &irq_desc[irq];
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct task_struct *p;
    int i;

    for ( i = 0; i < action->nr_guests; i++ )
    {
        p = action->guest[i];
        if ( !test_and_set_bit(irq, &p->pirq_mask) )
            action->in_flight++;
        send_guest_pirq(p, irq);
    }
}

int pirq_guest_unmask(struct task_struct *p)
{
    irq_desc_t *desc;
    int i, j, pirq;
    u32 m;
    shared_info_t *s = p->shared_info;

    for ( i = 0; i < 2; i++ )
    {
        m = p->pirq_mask[i];
        while ( (j = ffs(m)) != 0 )
        {
            m &= ~(1 << --j);
            pirq = (i << 5) + j;
            desc = &irq_desc[pirq];
            spin_lock_irq(&desc->lock);
            if ( !test_bit(p->pirq_to_evtchn[pirq], &s->evtchn_mask[0]) &&
                 test_and_clear_bit(pirq, &p->pirq_mask) &&
                 (--((irq_guest_action_t *)desc->action)->in_flight == 0) )
                desc->handler->end(pirq);
            spin_unlock_irq(&desc->lock);
        }
    }

    return 0;
}

int pirq_guest_bind(struct task_struct *p, int irq, int will_share)
{
    unsigned long flags;
    irq_desc_t *desc = &irq_desc[irq];
    irq_guest_action_t *action;
    int rc = 0;

    if ( !IS_CAPABLE_PHYSDEV(p) )
        return -EPERM;

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

        action = kmalloc(sizeof(irq_guest_action_t), GFP_KERNEL);
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
        desc->status &= ~(IRQ_DISABLED | IRQ_AUTODETECT | IRQ_WAITING);
        desc->handler->startup(irq);

        /* Attempt to bind the interrupt target to the correct CPU. */
        if ( desc->handler->set_affinity != NULL )
            desc->handler->set_affinity(
                irq, apicid_to_phys_cpu_present(p->processor));
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

    action->guest[action->nr_guests++] = p;

 out:
    spin_unlock_irqrestore(&desc->lock, flags);
    return rc;
}

int pirq_guest_unbind(struct task_struct *p, int irq)
{
    unsigned long flags;
    irq_desc_t *desc = &irq_desc[irq];
    irq_guest_action_t *action;
    int i;

    spin_lock_irqsave(&desc->lock, flags);

    action = (irq_guest_action_t *)desc->action;

    if ( test_and_clear_bit(irq, &p->pirq_mask) &&
         (--action->in_flight == 0) )
        desc->handler->end(irq);

    if ( action->nr_guests == 1 )
    {
        desc->action = NULL;
        kfree(action);
        desc->status |= IRQ_DISABLED;
        desc->status &= ~IRQ_GUEST;
        desc->handler->shutdown(irq);
    }
    else
    {
        i = 0;
        while ( action->guest[i] != p )
            i++;
        memmove(&action->guest[i], &action->guest[i+1], IRQ_MAX_GUESTS-i-1);
        action->nr_guests--;
    }

    spin_unlock_irqrestore(&desc->lock, flags);    
    return 0;
}
