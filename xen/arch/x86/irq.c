/******************************************************************************
 * arch/x86/irq.c
 * 
 * Portions of this file are:
 *  Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/irq.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/keyhandler.h>
#include <asm/current.h>
#include <asm/smpboot.h>

/* opt_noirqbalance: If true, software IRQ balancing/affinity is disabled. */
int opt_noirqbalance = 0;
boolean_param("noirqbalance", opt_noirqbalance);

irq_desc_t irq_desc[NR_IRQS];

static void __do_IRQ_guest(int vector);

void no_action(int cpl, void *dev_id, struct cpu_user_regs *regs) { }

static void enable_none(unsigned int vector) { }
static unsigned int startup_none(unsigned int vector) { return 0; }
static void disable_none(unsigned int vector) { }
static void ack_none(unsigned int vector)
{
    ack_bad_irq(vector);
}

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

asmlinkage void do_IRQ(struct cpu_user_regs *regs)
{
    unsigned int      vector = regs->entry_vector;
    irq_desc_t       *desc = &irq_desc[vector];
    struct irqaction *action;

    perfc_incrc(irqs);

    spin_lock(&desc->lock);
    desc->handler->ack(vector);

    if ( likely(desc->status & IRQ_GUEST) )
    {
        __do_IRQ_guest(vector);
        spin_unlock(&desc->lock);
        return;
    }

    desc->status &= ~IRQ_REPLAY;
    desc->status |= IRQ_PENDING;

    /*
     * Since we set PENDING, if another processor is handling a different 
     * instance of this same irq, the other processor will take care of it.
     */
    if ( desc->status & (IRQ_DISABLED | IRQ_INPROGRESS) )
        goto out;

    desc->status |= IRQ_INPROGRESS;

    action = desc->action;
    while ( desc->status & IRQ_PENDING )
    {
        desc->status &= ~IRQ_PENDING;
        irq_enter();
        spin_unlock_irq(&desc->lock);
        action->handler(vector_to_irq(vector), action->dev_id, regs);
        spin_lock_irq(&desc->lock);
        irq_exit();
    }

    desc->status &= ~IRQ_INPROGRESS;

 out:
    desc->handler->end(vector);
    spin_unlock(&desc->lock);
}

void free_irq(unsigned int irq)
{
    unsigned int  vector = irq_to_vector(irq);
    irq_desc_t   *desc = &irq_desc[vector];
    unsigned long flags;

    spin_lock_irqsave(&desc->lock,flags);
    desc->action  = NULL;
    desc->depth   = 1;
    desc->status |= IRQ_DISABLED;
    desc->handler->shutdown(irq);
    spin_unlock_irqrestore(&desc->lock,flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );
}

int setup_irq(unsigned int irq, struct irqaction *new)
{
    unsigned int  vector = irq_to_vector(irq);
    irq_desc_t   *desc = &irq_desc[vector];
    unsigned long flags;
 
    spin_lock_irqsave(&desc->lock,flags);

    if ( desc->action != NULL )
    {
        spin_unlock_irqrestore(&desc->lock,flags);
        return -EBUSY;
    }

    desc->action  = new;
    desc->depth   = 0;
    desc->status &= ~IRQ_DISABLED;
    desc->handler->startup(vector);

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
    u8 ack_type;
#define ACKTYPE_NONE   0 /* Final ACK is not required */
#define ACKTYPE_SINGLE 1 /* Final ACK on any CPU */
#define ACKTYPE_MULTI  2 /* Final ACK on the CPU that was interrupted */
    cpumask_t cpu_ack_map;
    struct domain *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

static void __do_IRQ_guest(int vector)
{
    unsigned int        irq = vector_to_irq(vector);
    irq_desc_t         *desc = &irq_desc[vector];
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i;

    if ( unlikely(action->nr_guests == 0) )
    {
        /* An interrupt may slip through while freeing an ACKTYPE_MULTI irq. */
        ASSERT(action->ack_type == ACKTYPE_MULTI);
        desc->handler->end(vector);
        return;
    }

    if ( action->ack_type == ACKTYPE_MULTI )
        cpu_set(smp_processor_id(), action->cpu_ack_map);

    for ( i = 0; i < action->nr_guests; i++ )
    {
        d = action->guest[i];
        if ( (action->ack_type != ACKTYPE_NONE) &&
             !test_and_set_bit(irq, &d->pirq_mask) )
            action->in_flight++;
        send_guest_pirq(d, irq);
    }
}

static void end_guest_irq(void *data)
{
    irq_desc_t         *desc = data;
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    unsigned long       flags;

    spin_lock_irqsave(&desc->lock, flags);
    if ( (desc->status & IRQ_GUEST) &&
         (action->in_flight == 0) &&
         test_and_clear_bit(smp_processor_id(), &action->cpu_ack_map) )
        desc->handler->end(desc - irq_desc);
    spin_unlock_irqrestore(&desc->lock, flags);    
}

int pirq_guest_unmask(struct domain *d)
{
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    cpumask_t           cpu_ack_map = CPU_MASK_NONE;
    unsigned int        pirq, cpu = smp_processor_id();
    shared_info_t      *s = d->shared_info;

    for ( pirq = find_first_bit(d->pirq_mask, NR_PIRQS);
          pirq < NR_PIRQS;
          pirq = find_next_bit(d->pirq_mask, NR_PIRQS, pirq+1) )
    {
        desc   = &irq_desc[irq_to_vector(pirq)];
        action = (irq_guest_action_t *)desc->action;

        spin_lock_irq(&desc->lock);
        if ( !test_bit(d->pirq_to_evtchn[pirq], &s->evtchn_mask[0]) &&
             test_and_clear_bit(pirq, &d->pirq_mask) )
        {
            ASSERT(action->ack_type != ACKTYPE_NONE);
            if ( --action->in_flight == 0 )
            {
                if ( (action->ack_type == ACKTYPE_SINGLE) ||
                     test_and_clear_bit(cpu, &action->cpu_ack_map) )
                    desc->handler->end(irq_to_vector(pirq));
                cpu_ack_map = action->cpu_ack_map;
            }
        }
        spin_unlock_irq(&desc->lock);

        if ( !cpus_empty(cpu_ack_map) )
        {
            on_selected_cpus(cpu_ack_map, end_guest_irq, desc, 1, 0);
            cpu_ack_map = CPU_MASK_NONE;
        }
    }

    return 0;
}

int pirq_acktype(int irq)
{
    irq_desc_t  *desc;
    unsigned int vector;

    vector = irq_to_vector(irq);
    if ( vector == 0 )
        return ACKTYPE_NONE;

    desc = &irq_desc[vector];

    /*
     * Edge-triggered IO-APIC interrupts need no final acknowledgement:
     * we ACK early during interrupt processing.
     */
    if ( !strcmp(desc->handler->typename, "IO-APIC-edge") )
        return ACKTYPE_NONE;

    /* Legacy PIC interrupts can be acknowledged from any CPU. */
    if ( !strcmp(desc->handler->typename, "XT-PIC") )
        return ACKTYPE_SINGLE;

    /*
     * By default assume that an interrupt must be finally acknowledged on
     * the CPU on which it was received. This is true for level-triggered
     * IO-APIC interrupts, for example, where we tickle the LAPIC to EOI.
     */
    return ACKTYPE_MULTI;
}

int pirq_guest_bind(struct vcpu *v, int irq, int will_share)
{
    unsigned int        vector;
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 rc = 0;
    cpumask_t           cpumask = CPU_MASK_NONE;

    if ( (irq < 0) || (irq >= NR_IRQS) )
        return -EINVAL;

    vector = irq_to_vector(irq);
    if ( vector == 0 )
        return -EINVAL;

    desc = &irq_desc[vector];

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

        action->nr_guests   = 0;
        action->in_flight   = 0;
        action->shareable   = will_share;
        action->ack_type    = pirq_acktype(irq);
        action->cpu_ack_map = CPU_MASK_NONE;

        desc->depth = 0;
        desc->status |= IRQ_GUEST;
        desc->status &= ~IRQ_DISABLED;
        desc->handler->startup(vector);

        /* Attempt to bind the interrupt target to the correct CPU. */
        cpu_set(v->processor, cpumask);
        if ( !opt_noirqbalance && (desc->handler->set_affinity != NULL) )
            desc->handler->set_affinity(vector, cpumask);
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
    unsigned int        vector = irq_to_vector(irq);
    irq_desc_t         *desc = &irq_desc[vector];
    irq_guest_action_t *action;
    cpumask_t           cpu_ack_map;
    unsigned long       flags;
    int                 i;

    BUG_ON(vector == 0);

    spin_lock_irqsave(&desc->lock, flags);

    action = (irq_guest_action_t *)desc->action;

    i = 0;
    while ( action->guest[i] && (action->guest[i] != d) )
        i++;
    memmove(&action->guest[i], &action->guest[i+1], IRQ_MAX_GUESTS-i-1);
    action->nr_guests--;

    switch ( action->ack_type )
    {
    case ACKTYPE_SINGLE:
        if ( test_and_clear_bit(irq, &d->pirq_mask) &&
             (--action->in_flight == 0) )
            desc->handler->end(vector);
        break;
    case ACKTYPE_MULTI:
        if ( test_and_clear_bit(irq, &d->pirq_mask) )
            --action->in_flight;
        while ( action->in_flight == 0 )
        {
            /* We cannot release guest info until all pending ACKs are done. */
            cpu_ack_map = action->cpu_ack_map;
            if ( cpus_empty(cpu_ack_map) )
                break;

            /* We cannot hold the lock while interrupting other CPUs. */
            spin_unlock_irqrestore(&desc->lock, flags);    
            on_selected_cpus(cpu_ack_map, end_guest_irq, desc, 1, 1);
            spin_lock_irqsave(&desc->lock, flags);

            /* The world can change while we do not hold the lock. */
            if ( !(desc->status & IRQ_GUEST) )
                goto out;
            if ( (action->ack_type != ACKTYPE_MULTI) ||
                 (action->nr_guests != 0) )
                break;
        }
        break;
    }

    BUG_ON(test_bit(irq, &d->pirq_mask));

    if ( action->nr_guests != 0 )
        goto out;

    BUG_ON(action->in_flight != 0);
    BUG_ON(!cpus_empty(action->cpu_ack_map));

    desc->action = NULL;
    xfree(action);
    desc->depth   = 1;
    desc->status |= IRQ_DISABLED;
    desc->status &= ~IRQ_GUEST;
    desc->handler->shutdown(vector);

 out:
    spin_unlock_irqrestore(&desc->lock, flags);    
    return 0;
}

extern void dump_ioapic_irq_info(void);

static void dump_irqs(unsigned char key)
{
    int i, irq, vector;
    irq_desc_t *desc;
    irq_guest_action_t *action;
    struct domain *d;
    unsigned long flags;

    printk("Guest interrupt information:\n");

    for ( irq = 0; irq < NR_IRQS; irq++ )
    {
        vector = irq_to_vector(irq);
        if ( vector == 0 )
            continue;

        desc = &irq_desc[vector];

        spin_lock_irqsave(&desc->lock, flags);

        if ( desc->status & IRQ_GUEST )
        {
            action = (irq_guest_action_t *)desc->action;

            printk("    IRQ%3d Vec%3d: type=%-15s status=%08x "
                   "in-flight=%d domain-list=",
                   irq, vector, desc->handler->typename,
                   desc->status, action->in_flight);

            for ( i = 0; i < action->nr_guests; i++ )
            {
                d = action->guest[i];
                printk("%u(%c%c%c%c)",
                       d->domain_id,
                       (test_bit(d->pirq_to_evtchn[irq],
                                 &d->shared_info->evtchn_pending[0]) ?
                        'P' : '-'),
                       (test_bit(d->pirq_to_evtchn[irq]/BITS_PER_LONG,
                                 &d->shared_info->vcpu_info[0].
                                 evtchn_pending_sel) ?
                        'S' : '-'),
                       (test_bit(d->pirq_to_evtchn[irq],
                                 &d->shared_info->evtchn_mask[0]) ?
                        'M' : '-'),
                       (test_bit(irq, &d->pirq_mask) ?
                        'M' : '-'));
                if ( i != action->nr_guests )
                    printk(",");
            }

            printk("\n");
        }

        spin_unlock_irqrestore(&desc->lock, flags);
    }

    dump_ioapic_irq_info();
}

static int __init setup_dump_irqs(void)
{
    register_keyhandler('i', dump_irqs, "dump interrupt bindings");
    return 0;
}
__initcall(setup_dump_irqs);
