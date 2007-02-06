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
#include <xen/compat.h>
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
#define ACKTYPE_NONE   0     /* No final acknowledgement is required */
#define ACKTYPE_UNMASK 1     /* Unmask PIC hardware (from any CPU)   */
#define ACKTYPE_EOI    2     /* EOI on the CPU that was interrupted  */
    cpumask_t cpu_eoi_map;   /* CPUs that need to EOI this interrupt */
    struct domain *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

/*
 * Stack of interrupts awaiting EOI on each CPU. These must be popped in
 * order, as only the current highest-priority pending irq can be EOIed.
 */
struct pending_eoi {
    u8 vector; /* Vector awaiting EOI */
    u8 ready;  /* Ready for EOI now?  */
};
static DEFINE_PER_CPU(struct pending_eoi, pending_eoi[NR_VECTORS]);
#define pending_eoi_sp(p) ((p)[NR_VECTORS-1].vector)

static void __do_IRQ_guest(int vector)
{
    unsigned int        irq = vector_to_irq(vector);
    irq_desc_t         *desc = &irq_desc[vector];
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i, sp;
    struct pending_eoi *peoi = this_cpu(pending_eoi);

    if ( unlikely(action->nr_guests == 0) )
    {
        /* An interrupt may slip through while freeing an ACKTYPE_EOI irq. */
        ASSERT(action->ack_type == ACKTYPE_EOI);
        ASSERT(desc->status & IRQ_DISABLED);
        desc->handler->end(vector);
        return;
    }

    if ( action->ack_type == ACKTYPE_EOI )
    {
        sp = pending_eoi_sp(peoi);
        ASSERT((sp == 0) || (peoi[sp-1].vector < vector));
        ASSERT(sp < (NR_VECTORS-1));
        peoi[sp].vector = vector;
        peoi[sp].ready = 0;
        pending_eoi_sp(peoi) = sp+1;
        cpu_set(smp_processor_id(), action->cpu_eoi_map);
    }

    for ( i = 0; i < action->nr_guests; i++ )
    {
        d = action->guest[i];
        if ( (action->ack_type != ACKTYPE_NONE) &&
             !test_and_set_bit(irq, d->pirq_mask) )
            action->in_flight++;
        send_guest_pirq(d, irq);
    }
}

/* Flush all ready EOIs from the top of this CPU's pending-EOI stack. */
static void flush_ready_eoi(void *unused)
{
    struct pending_eoi *peoi = this_cpu(pending_eoi);
    irq_desc_t         *desc;
    int                 vector, sp;

    ASSERT(!local_irq_is_enabled());

    sp = pending_eoi_sp(peoi);

    while ( (--sp >= 0) && peoi[sp].ready )
    {
        vector = peoi[sp].vector;
        desc = &irq_desc[vector];
        spin_lock(&desc->lock);
        desc->handler->end(vector);
        spin_unlock(&desc->lock);
    }

    pending_eoi_sp(peoi) = sp+1;
}

static void __set_eoi_ready(irq_desc_t *desc)
{
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct pending_eoi *peoi = this_cpu(pending_eoi);
    int                 vector, sp;

    vector = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST) ||
         (action->in_flight != 0) ||
         !cpu_test_and_clear(smp_processor_id(), action->cpu_eoi_map) )
        return;

    sp = pending_eoi_sp(peoi);
    do {
        ASSERT(sp > 0);
    } while ( peoi[--sp].vector != vector );
    ASSERT(!peoi[sp].ready);
    peoi[sp].ready = 1;
}

/* Mark specified IRQ as ready-for-EOI (if it really is) and attempt to EOI. */
static void set_eoi_ready(void *data)
{
    irq_desc_t *desc = data;

    ASSERT(!local_irq_is_enabled());

    spin_lock(&desc->lock);
    __set_eoi_ready(desc);
    spin_unlock(&desc->lock);

    flush_ready_eoi(NULL);
}

static void __pirq_guest_eoi(struct domain *d, int irq)
{
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;

    desc   = &irq_desc[irq_to_vector(irq)];
    action = (irq_guest_action_t *)desc->action;

    spin_lock_irq(&desc->lock);

    ASSERT(!test_bit(irq, d->pirq_mask) ||
           (action->ack_type != ACKTYPE_NONE));

    if ( unlikely(!test_and_clear_bit(irq, d->pirq_mask)) ||
         unlikely(--action->in_flight != 0) )
    {
        spin_unlock_irq(&desc->lock);
        return;
    }

    if ( action->ack_type == ACKTYPE_UNMASK )
    {
        ASSERT(cpus_empty(action->cpu_eoi_map));
        desc->handler->end(irq_to_vector(irq));
        spin_unlock_irq(&desc->lock);
        return;
    }

    ASSERT(action->ack_type == ACKTYPE_EOI);
        
    cpu_eoi_map = action->cpu_eoi_map;

    if ( cpu_test_and_clear(smp_processor_id(), cpu_eoi_map) )
    {
        __set_eoi_ready(desc);
        spin_unlock(&desc->lock);
        flush_ready_eoi(NULL);
        local_irq_enable();
    }
    else
    {
        spin_unlock_irq(&desc->lock);
    }

    if ( !cpus_empty(cpu_eoi_map) )
        on_selected_cpus(cpu_eoi_map, set_eoi_ready, desc, 1, 0);
}

int pirq_guest_eoi(struct domain *d, int irq)
{
    if ( (irq < 0) || (irq >= NR_IRQS) )
        return -EINVAL;

    __pirq_guest_eoi(d, irq);

    return 0;
}

int pirq_guest_unmask(struct domain *d)
{
    unsigned int   irq;
    shared_info_t *s = d->shared_info;

    for ( irq = find_first_bit(d->pirq_mask, NR_IRQS);
          irq < NR_IRQS;
          irq = find_next_bit(d->pirq_mask, NR_IRQS, irq+1) )
    {
        if ( !test_bit(d->pirq_to_evtchn[irq], __shared_info_addr(d, s, evtchn_mask)) )
            __pirq_guest_eoi(d, irq);
    }

    return 0;
}

extern int ioapic_ack_new;
int pirq_acktype(int irq)
{
    irq_desc_t  *desc;
    unsigned int vector;

    vector = irq_to_vector(irq);
    if ( vector == 0 )
        return ACKTYPE_NONE;

    desc = &irq_desc[vector];

    if ( desc->handler == &no_irq_type )
        return ACKTYPE_NONE;

    /*
     * Edge-triggered IO-APIC and LAPIC interrupts need no final
     * acknowledgement: we ACK early during interrupt processing.
     */
    if ( !strcmp(desc->handler->typename, "IO-APIC-edge") ||
         !strcmp(desc->handler->typename, "local-APIC-edge") )
        return ACKTYPE_NONE;

    /*
     * Level-triggered IO-APIC interrupts need to be acknowledged on the CPU
     * on which they were received. This is because we tickle the LAPIC to EOI.
     */
    if ( !strcmp(desc->handler->typename, "IO-APIC-level") )
        return ioapic_ack_new ? ACKTYPE_EOI : ACKTYPE_UNMASK;

    /* Legacy PIC interrupts can be acknowledged from any CPU. */
    if ( !strcmp(desc->handler->typename, "XT-PIC") )
        return ACKTYPE_UNMASK;

    if ( strstr(desc->handler->typename, "MPIC") )
    {
        if ( desc->status & IRQ_LEVEL )
            return (desc->status & IRQ_PER_CPU) ? ACKTYPE_EOI : ACKTYPE_UNMASK;
        return ACKTYPE_NONE; /* edge-triggered => no final EOI */
    }

    printk("Unknown PIC type '%s' for IRQ %d\n", desc->handler->typename, irq);
    BUG();

    return 0;
}

int pirq_shared(int irq)
{
    unsigned int        vector;
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 shared;

    vector = irq_to_vector(irq);
    if ( vector == 0 )
        return 0;

    desc = &irq_desc[vector];

    spin_lock_irqsave(&desc->lock, flags);
    action = (irq_guest_action_t *)desc->action;
    shared = ((desc->status & IRQ_GUEST) && (action->nr_guests > 1));
    spin_unlock_irqrestore(&desc->lock, flags);

    return shared;
}

int pirq_guest_bind(struct vcpu *v, int irq, int will_share)
{
    unsigned int        vector;
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 rc = 0;
    cpumask_t           cpumask = CPU_MASK_NONE;

 retry:
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

        action->nr_guests   = 0;
        action->in_flight   = 0;
        action->shareable   = will_share;
        action->ack_type    = pirq_acktype(irq);
        cpus_clear(action->cpu_eoi_map);

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
        gdprintk(XENLOG_INFO, "Cannot bind IRQ %d to guest. "
               "Will not share with others.\n",
                irq);
        rc = -EBUSY;
        goto out;
    }
    else if ( action->nr_guests == 0 )
    {
        /*
         * Indicates that an ACKTYPE_EOI interrupt is being released.
         * Wait for that to happen before continuing.
         */
        ASSERT(action->ack_type == ACKTYPE_EOI);
        ASSERT(desc->status & IRQ_DISABLED);
        spin_unlock_irqrestore(&desc->lock, flags);
        cpu_relax();
        goto retry;
    }

    if ( action->nr_guests == IRQ_MAX_GUESTS )
    {
        gdprintk(XENLOG_INFO, "Cannot bind IRQ %d to guest. "
               "Already at max share.\n", irq);
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
    cpumask_t           cpu_eoi_map;
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
    case ACKTYPE_UNMASK:
        if ( test_and_clear_bit(irq, d->pirq_mask) &&
             (--action->in_flight == 0) )
            desc->handler->end(vector);
        break;
    case ACKTYPE_EOI:
        /* NB. If #guests == 0 then we clear the eoi_map later on. */
        if ( test_and_clear_bit(irq, d->pirq_mask) &&
             (--action->in_flight == 0) &&
             (action->nr_guests != 0) )
        {
            cpu_eoi_map = action->cpu_eoi_map;
            spin_unlock_irqrestore(&desc->lock, flags);    
            on_selected_cpus(cpu_eoi_map, set_eoi_ready, desc, 1, 0);
            spin_lock_irqsave(&desc->lock, flags);
        }
        break;
    }

    /*
     * The guest cannot re-bind to this IRQ until this function returns. So,
     * when we have flushed this IRQ from pirq_mask, it should remain flushed.
     */
    BUG_ON(test_bit(irq, d->pirq_mask));

    if ( action->nr_guests != 0 )
        goto out;

    BUG_ON(action->in_flight != 0);

    /* Disabling IRQ before releasing the desc_lock avoids an IRQ storm. */
    desc->depth   = 1;
    desc->status |= IRQ_DISABLED;
    desc->handler->disable(vector);

    /*
     * Mark any remaining pending EOIs as ready to flush.
     * NOTE: We will need to make this a stronger barrier if in future we allow
     * an interrupt vectors to be re-bound to a different PIC. In that case we
     * would need to flush all ready EOIs before returning as otherwise the
     * desc->handler could change and we would call the wrong 'end' hook.
     */
    cpu_eoi_map = action->cpu_eoi_map;
    if ( !cpus_empty(cpu_eoi_map) )
    {
        BUG_ON(action->ack_type != ACKTYPE_EOI);
        spin_unlock_irqrestore(&desc->lock, flags);
        on_selected_cpus(cpu_eoi_map, set_eoi_ready, desc, 1, 1);
        spin_lock_irqsave(&desc->lock, flags);
    }

    BUG_ON(!cpus_empty(action->cpu_eoi_map));

    desc->action = NULL;
    xfree(action);
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
                                 shared_info_addr(d, evtchn_pending)) ?
                        'P' : '-'),
                       (test_bit(d->pirq_to_evtchn[irq]/BITS_PER_GUEST_LONG(d),
                                 vcpu_info_addr(d->vcpu[0], evtchn_pending_sel)) ?
                        'S' : '-'),
                       (test_bit(d->pirq_to_evtchn[irq],
                                 shared_info_addr(d, evtchn_mask)) ?
                        'M' : '-'),
                       (test_bit(irq, d->pirq_mask) ?
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
