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
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/trace.h>
#include <asm/msi.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <public/physdev.h>

/* opt_noirqbalance: If true, software IRQ balancing/affinity is disabled. */
int opt_noirqbalance = 0;
boolean_param("noirqbalance", opt_noirqbalance);

unsigned int __read_mostly nr_irqs_gsi = 16;
irq_desc_t irq_desc[NR_VECTORS];

static DEFINE_SPINLOCK(vector_lock);
int vector_irq[NR_VECTORS] __read_mostly = {
    [0 ... NR_VECTORS - 1] = FREE_TO_ASSIGN_IRQ
};

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

int free_irq_vector(int vector)
{
    int irq;

    BUG_ON((vector > LAST_DYNAMIC_VECTOR) || (vector < FIRST_DYNAMIC_VECTOR));

    spin_lock(&vector_lock);
    if ((irq = vector_irq[vector]) == AUTO_ASSIGN_IRQ)
        vector_irq[vector] = FREE_TO_ASSIGN_IRQ;
    spin_unlock(&vector_lock);

    return (irq == AUTO_ASSIGN_IRQ) ? 0 : -EINVAL;
}

int assign_irq_vector(int irq)
{
    static unsigned current_vector = FIRST_DYNAMIC_VECTOR;
    unsigned vector;

    BUG_ON(irq >= nr_irqs_gsi && irq != AUTO_ASSIGN_IRQ);

    spin_lock(&vector_lock);

    if ((irq != AUTO_ASSIGN_IRQ) && (irq_to_vector(irq) > 0)) {
        spin_unlock(&vector_lock);
        return irq_to_vector(irq);
    }

    vector = current_vector;
    while (vector_irq[vector] != FREE_TO_ASSIGN_IRQ) {
        vector += 8;
        if (vector > LAST_DYNAMIC_VECTOR)
            vector = FIRST_DYNAMIC_VECTOR + ((vector + 1) & 7);

        if (vector == current_vector) {
            spin_unlock(&vector_lock);
            return -ENOSPC;
        }
    }

    current_vector = vector;
    vector_irq[vector] = irq;
    if (irq != AUTO_ASSIGN_IRQ)
        IO_APIC_VECTOR(irq) = vector;

    spin_unlock(&vector_lock);

    return vector;
}

asmlinkage void do_IRQ(struct cpu_user_regs *regs)
{
    unsigned int      vector = regs->entry_vector;
    irq_desc_t       *desc = &irq_desc[vector];
    struct irqaction *action;
    uint32_t          tsc_in;

    perfc_incr(irqs);

    spin_lock(&desc->lock);
    desc->handler->ack(vector);

    if ( likely(desc->status & IRQ_GUEST) )
    {
        irq_enter();
        tsc_in = tb_init_done ? get_cycles() : 0;
        __do_IRQ_guest(vector);
        TRACE_3D(TRC_TRACE_IRQ, vector, tsc_in, get_cycles());
        irq_exit();
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
        tsc_in = tb_init_done ? get_cycles() : 0;
        action->handler(vector_to_irq(vector), action->dev_id, regs);
        TRACE_3D(TRC_TRACE_IRQ, vector, tsc_in, get_cycles());
        spin_lock_irq(&desc->lock);
        irq_exit();
    }

    desc->status &= ~IRQ_INPROGRESS;

 out:
    desc->handler->end(vector);
    spin_unlock(&desc->lock);
}

int request_irq_vector(unsigned int vector,
        void (*handler)(int, void *, struct cpu_user_regs *),
        unsigned long irqflags, const char * devname, void *dev_id)
{
    struct irqaction * action;
    int retval;

    /*
     * Sanity-check: shared interrupts must pass in a real dev-ID,
     * otherwise we'll have trouble later trying to figure out
     * which interrupt is which (messes up the interrupt freeing
     * logic etc).
     */
    if (vector >= NR_VECTORS)
        return -EINVAL;
    if (!handler)
        return -EINVAL;

    action = xmalloc(struct irqaction);
    if (!action)
        return -ENOMEM;

    action->handler = handler;
    action->name = devname;
    action->dev_id = dev_id;

    retval = setup_irq_vector(vector, action);
    if (retval)
        xfree(action);

    return retval;
}

void release_irq_vector(unsigned int vector)
{
    irq_desc_t *desc = &irq_desc[vector];
    unsigned long flags;

    spin_lock_irqsave(&desc->lock,flags);
    desc->action  = NULL;
    desc->depth   = 1;
    desc->status |= IRQ_DISABLED;
    desc->handler->shutdown(vector);
    spin_unlock_irqrestore(&desc->lock,flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );
}

int setup_irq_vector(unsigned int vector, struct irqaction *new)
{
    irq_desc_t *desc = &irq_desc[vector];
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
        clear_pirq_eoi(action->guest[i],
                       domain_vector_to_irq(action->guest[i], vector));

    desc->status &= ~(IRQ_INPROGRESS|IRQ_GUEST_EOI_PENDING);
    desc->handler->enable(vector);
}

static struct timer irq_guest_eoi_timer[NR_VECTORS];
static void irq_guest_eoi_timer_fn(void *data)
{
    irq_desc_t *desc = data;
    unsigned long flags;

    spin_lock_irqsave(&desc->lock, flags);
    _irq_guest_eoi(desc);
    spin_unlock_irqrestore(&desc->lock, flags);
}

static void __do_IRQ_guest(int vector)
{
    irq_desc_t         *desc = &irq_desc[vector];
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i, sp, already_pending = 0;
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
        unsigned int irq;
        d = action->guest[i];
        irq = domain_vector_to_irq(d, vector);
        if ( (action->ack_type != ACKTYPE_NONE) &&
             !test_and_set_bit(irq, d->pirq_mask) )
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
        stop_timer(&irq_guest_eoi_timer[vector]);
        desc->handler->disable(vector);
        desc->status |= IRQ_GUEST_EOI_PENDING;
        for ( i = 0; i < already_pending; ++i )
        {
            d = action->guest[i];
            set_pirq_eoi(d, domain_vector_to_irq(d, vector));
            /*
             * Could check here whether the guest unmasked the event by now
             * (or perhaps just re-issue the send_guest_pirq()), and if it
             * can now accept the event,
             * - clear all the pirq_eoi bits we already set,
             * - re-enable the vector, and
             * - skip the timer setup below.
             */
        }
        init_timer(&irq_guest_eoi_timer[vector],
                   irq_guest_eoi_timer_fn, desc, smp_processor_id());
        set_timer(&irq_guest_eoi_timer[vector], NOW() + MILLISECS(1));
    }
}

/*
 * Retrieve Xen irq-descriptor corresponding to a domain-specific irq.
 * The descriptor is returned locked. This function is safe against changes
 * to the per-domain irq-to-vector mapping.
 */
irq_desc_t *domain_spin_lock_irq_desc(
    struct domain *d, int irq, unsigned long *pflags)
{
    unsigned int vector;
    unsigned long flags;
    irq_desc_t *desc;

    for ( ; ; )
    {
        vector = domain_irq_to_vector(d, irq);
        if ( vector <= 0 )
            return NULL;
        desc = &irq_desc[vector];
        spin_lock_irqsave(&desc->lock, flags);
        if ( vector == domain_irq_to_vector(d, irq) )
            break;
        spin_unlock_irqrestore(&desc->lock, flags);
    }

    if ( pflags != NULL )
        *pflags = flags;
    return desc;
}

/* Flush all ready EOIs from the top of this CPU's pending-EOI stack. */
static void flush_ready_eoi(void)
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

    flush_ready_eoi();
}

static void __pirq_guest_eoi(struct domain *d, int irq)
{
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;
    int                 vector;

    ASSERT(local_irq_is_enabled());
    desc = domain_spin_lock_irq_desc(d, irq, NULL);
    if ( desc == NULL )
        return;

    action = (irq_guest_action_t *)desc->action;
    vector = desc - irq_desc;

    if ( action->ack_type == ACKTYPE_NONE )
    {
        ASSERT(!test_bit(irq, d->pirq_mask));
        stop_timer(&irq_guest_eoi_timer[vector]);
        _irq_guest_eoi(desc);
    }

    if ( unlikely(!test_and_clear_bit(irq, d->pirq_mask)) ||
         unlikely(--action->in_flight != 0) )
    {
        spin_unlock_irq(&desc->lock);
        return;
    }

    if ( action->ack_type == ACKTYPE_UNMASK )
    {
        ASSERT(cpus_empty(action->cpu_eoi_map));
        desc->handler->end(vector);
        spin_unlock_irq(&desc->lock);
        return;
    }

    ASSERT(action->ack_type == ACKTYPE_EOI);
        
    cpu_eoi_map = action->cpu_eoi_map;

    if ( cpu_test_and_clear(smp_processor_id(), cpu_eoi_map) )
    {
        __set_eoi_ready(desc);
        spin_unlock(&desc->lock);
        flush_ready_eoi();
        local_irq_enable();
    }
    else
    {
        spin_unlock_irq(&desc->lock);
    }

    if ( !cpus_empty(cpu_eoi_map) )
        on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 0);
}

int pirq_guest_eoi(struct domain *d, int irq)
{
    if ( (irq < 0) || (irq >= d->nr_pirqs) )
        return -EINVAL;

    __pirq_guest_eoi(d, irq);

    return 0;
}

int pirq_guest_unmask(struct domain *d)
{
    unsigned int irq, nr = d->nr_pirqs;

    for ( irq = find_first_bit(d->pirq_mask, nr);
          irq < nr;
          irq = find_next_bit(d->pirq_mask, nr, irq+1) )
    {
        if ( !test_bit(d->pirq_to_evtchn[irq], &shared_info(d, evtchn_mask)) )
            __pirq_guest_eoi(d, irq);
    }

    return 0;
}

extern int ioapic_ack_new;
static int pirq_acktype(struct domain *d, int irq)
{
    irq_desc_t  *desc;
    unsigned int vector;

    vector = domain_irq_to_vector(d, irq);
    if ( vector <= 0 )
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
     * MSIs are treated as edge-triggered interrupts, except
     * when there is no proper way to mask them.
     */
    if ( desc->handler == &pci_msi_type )
        return msi_maskable_irq(desc->msi_desc) ? ACKTYPE_NONE : ACKTYPE_EOI;

    /*
     * Level-triggered IO-APIC interrupts need to be acknowledged on the CPU
     * on which they were received. This is because we tickle the LAPIC to EOI.
     */
    if ( !strcmp(desc->handler->typename, "IO-APIC-level") )
        return ioapic_ack_new ? ACKTYPE_EOI : ACKTYPE_UNMASK;

    /* Legacy PIC interrupts can be acknowledged from any CPU. */
    if ( !strcmp(desc->handler->typename, "XT-PIC") )
        return ACKTYPE_UNMASK;

    printk("Unknown PIC type '%s' for IRQ %d\n", desc->handler->typename, irq);
    BUG();

    return 0;
}

int pirq_shared(struct domain *d, int irq)
{
    irq_desc_t         *desc;
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 shared;

    desc = domain_spin_lock_irq_desc(d, irq, &flags);
    if ( desc == NULL )
        return 0;

    action = (irq_guest_action_t *)desc->action;
    shared = ((desc->status & IRQ_GUEST) && (action->nr_guests > 1));

    spin_unlock_irqrestore(&desc->lock, flags);

    return shared;
}

int pirq_guest_bind(struct vcpu *v, int irq, int will_share)
{
    unsigned int        vector;
    irq_desc_t         *desc;
    irq_guest_action_t *action, *newaction = NULL;
    int                 rc = 0;
    cpumask_t           cpumask = CPU_MASK_NONE;

    WARN_ON(!spin_is_locked(&v->domain->event_lock));
    BUG_ON(!local_irq_is_enabled());

 retry:
    desc = domain_spin_lock_irq_desc(v->domain, irq, NULL);
    if ( desc == NULL )
    {
        rc = -EINVAL;
        goto out;
    }

    action = (irq_guest_action_t *)desc->action;
    vector = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST) )
    {
        if ( desc->action != NULL )
        {
            gdprintk(XENLOG_INFO,
                    "Cannot bind IRQ %d to guest. In use by '%s'.\n",
                    irq, desc->action->name);
            rc = -EBUSY;
            goto unlock_out;
        }

        if ( newaction == NULL )
        {
            spin_unlock_irq(&desc->lock);
            if ( (newaction = xmalloc(irq_guest_action_t)) != NULL )
                goto retry;
            gdprintk(XENLOG_INFO,
                     "Cannot bind IRQ %d to guest. Out of memory.\n",
                     irq);
            rc = -ENOMEM;
            goto out;
        }

        action = newaction;
        desc->action = (struct irqaction *)action;
        newaction = NULL;

        action->nr_guests   = 0;
        action->in_flight   = 0;
        action->shareable   = will_share;
        action->ack_type    = pirq_acktype(v->domain, irq);
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
        gdprintk(XENLOG_INFO, "Cannot bind IRQ %d to guest. %s.\n",
                 irq,
                 will_share ?
                 "Others do not share" :
                 "Will not share with others");
        rc = -EBUSY;
        goto unlock_out;
    }
    else if ( action->nr_guests == 0 )
    {
        /*
         * Indicates that an ACKTYPE_EOI interrupt is being released.
         * Wait for that to happen before continuing.
         */
        ASSERT(action->ack_type == ACKTYPE_EOI);
        ASSERT(desc->status & IRQ_DISABLED);
        spin_unlock_irq(&desc->lock);
        cpu_relax();
        goto retry;
    }

    if ( action->nr_guests == IRQ_MAX_GUESTS )
    {
        gdprintk(XENLOG_INFO, "Cannot bind IRQ %d to guest. "
               "Already at max share.\n", irq);
        rc = -EBUSY;
        goto unlock_out;
    }

    action->guest[action->nr_guests++] = v->domain;

    if ( action->ack_type != ACKTYPE_NONE )
        set_pirq_eoi(v->domain, irq);
    else
        clear_pirq_eoi(v->domain, irq);

 unlock_out:
    spin_unlock_irq(&desc->lock);
 out:
    if ( newaction != NULL )
        xfree(newaction);
    return rc;
}

static irq_guest_action_t *__pirq_guest_unbind(
    struct domain *d, int irq, irq_desc_t *desc)
{
    unsigned int        vector;
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;
    int                 i;

    BUG_ON(!(desc->status & IRQ_GUEST));

    action = (irq_guest_action_t *)desc->action;
    vector = desc - irq_desc;

    for ( i = 0; (i < action->nr_guests) && (action->guest[i] != d); i++ )
        continue;
    BUG_ON(i == action->nr_guests);
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
            spin_unlock_irq(&desc->lock);
            on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 0);
            spin_lock_irq(&desc->lock);
        }
        break;
    case ACKTYPE_NONE:
        stop_timer(&irq_guest_eoi_timer[vector]);
        _irq_guest_eoi(desc);
        break;
    }

    /*
     * The guest cannot re-bind to this IRQ until this function returns. So,
     * when we have flushed this IRQ from pirq_mask, it should remain flushed.
     */
    BUG_ON(test_bit(irq, d->pirq_mask));

    if ( action->nr_guests != 0 )
        return NULL;

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
        spin_unlock_irq(&desc->lock);
        on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 1);
        spin_lock_irq(&desc->lock);
    }

    BUG_ON(!cpus_empty(action->cpu_eoi_map));

    desc->action = NULL;
    desc->status &= ~IRQ_GUEST;
    desc->status &= ~IRQ_INPROGRESS;
    kill_timer(&irq_guest_eoi_timer[vector]);
    desc->handler->shutdown(vector);

    /* Caller frees the old guest descriptor block. */
    return action;
}

void pirq_guest_unbind(struct domain *d, int irq)
{
    irq_guest_action_t *oldaction = NULL;
    irq_desc_t *desc;
    int vector;

    WARN_ON(!spin_is_locked(&d->event_lock));

    BUG_ON(!local_irq_is_enabled());
    desc = domain_spin_lock_irq_desc(d, irq, NULL);

    if ( desc == NULL )
    {
        vector = -domain_irq_to_vector(d, irq);
        BUG_ON(vector <= 0);
        desc = &irq_desc[vector];
        spin_lock_irq(&desc->lock);
        d->arch.pirq_vector[irq] = d->arch.vector_pirq[vector] = 0;
    }
    else
    {
        oldaction = __pirq_guest_unbind(d, irq, desc);
    }

    spin_unlock_irq(&desc->lock);

    if ( oldaction != NULL )
        xfree(oldaction);
}

static int pirq_guest_force_unbind(struct domain *d, int irq)
{
    irq_desc_t *desc;
    irq_guest_action_t *action, *oldaction = NULL;
    int i, bound = 0;

    WARN_ON(!spin_is_locked(&d->event_lock));

    BUG_ON(!local_irq_is_enabled());
    desc = domain_spin_lock_irq_desc(d, irq, NULL);
    BUG_ON(desc == NULL);

    if ( !(desc->status & IRQ_GUEST) )
        goto out;

    action = (irq_guest_action_t *)desc->action;
    for ( i = 0; (i < action->nr_guests) && (action->guest[i] != d); i++ )
        continue;
    if ( i == action->nr_guests )
        goto out;

    bound = 1;
    oldaction = __pirq_guest_unbind(d, irq, desc);

 out:
    spin_unlock_irq(&desc->lock);

    if ( oldaction != NULL )
        xfree(oldaction);

    return bound;
}

int get_free_pirq(struct domain *d, int type, int index)
{
    int i;

    ASSERT(spin_is_locked(&d->event_lock));

    if ( type == MAP_PIRQ_TYPE_GSI )
    {
        for ( i = 16; i < nr_irqs_gsi; i++ )
            if ( !d->arch.pirq_vector[i] )
                break;
        if ( i == nr_irqs_gsi )
            return -ENOSPC;
    }
    else
    {
        for ( i = d->nr_pirqs - 1; i >= 16; i-- )
            if ( !d->arch.pirq_vector[i] )
                break;
        if ( i == 16 )
            return -ENOSPC;
    }

    return i;
}

int map_domain_pirq(
    struct domain *d, int pirq, int vector, int type, void *data)
{
    int ret = 0;
    int old_vector, old_pirq;
    irq_desc_t *desc;
    unsigned long flags;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev = NULL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( pirq < 0 || pirq >= d->nr_pirqs || vector < 0 || vector >= NR_VECTORS )
    {
        dprintk(XENLOG_G_ERR, "dom%d: invalid pirq %d or vector %d\n",
                d->domain_id, pirq, vector);
        return -EINVAL;
    }

    old_vector = domain_irq_to_vector(d, pirq);
    old_pirq = domain_vector_to_irq(d, vector);

    if ( (old_vector && (old_vector != vector) ) ||
         (old_pirq && (old_pirq != pirq)) )
    {
        dprintk(XENLOG_G_ERR, "dom%d: pirq %d or vector %d already mapped\n",
                d->domain_id, pirq, vector);
        return -EINVAL;
    }

    ret = irq_permit_access(d, pirq);
    if ( ret )
    {
        dprintk(XENLOG_G_ERR, "dom%d: could not permit access to irq %d\n",
                d->domain_id, pirq);
        return ret;
    }

    desc = &irq_desc[vector];

    if ( type == MAP_PIRQ_TYPE_MSI )
    {
        struct msi_info *msi = (struct msi_info *)data;

        ret = -ENODEV;
        if ( !cpu_has_apic )
            goto done;

        pdev = pci_get_pdev(msi->bus, msi->devfn);
        ret = pci_enable_msi(msi, &msi_desc);
        if ( ret )
            goto done;

        spin_lock_irqsave(&desc->lock, flags);

        if ( desc->handler != &no_irq_type )
            dprintk(XENLOG_G_ERR, "dom%d: vector %d in use\n",
              d->domain_id, vector);
        desc->handler = &pci_msi_type;
        d->arch.pirq_vector[pirq] = vector;
        d->arch.vector_pirq[vector] = pirq;
        setup_msi_irq(pdev, msi_desc);
        spin_unlock_irqrestore(&desc->lock, flags);
    } else
    {
        spin_lock_irqsave(&desc->lock, flags);
        d->arch.pirq_vector[pirq] = vector;
        d->arch.vector_pirq[vector] = pirq;
        spin_unlock_irqrestore(&desc->lock, flags);
    }

 done:
    return ret;
}

/* The pirq should have been unbound before this call. */
int unmap_domain_pirq(struct domain *d, int pirq)
{
    unsigned long flags;
    irq_desc_t *desc;
    int vector, ret = 0;
    bool_t forced_unbind;
    struct msi_desc *msi_desc = NULL;

    if ( (pirq < 0) || (pirq >= d->nr_pirqs) )
        return -EINVAL;

    if ( !IS_PRIV(current->domain) )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));

    vector = domain_irq_to_vector(d, pirq);
    if ( vector <= 0 )
    {
        dprintk(XENLOG_G_ERR, "dom%d: pirq %d not mapped\n",
                d->domain_id, pirq);
        ret = -EINVAL;
        goto done;
    }

    forced_unbind = pirq_guest_force_unbind(d, pirq);
    if ( forced_unbind )
        dprintk(XENLOG_G_WARNING, "dom%d: forcing unbind of pirq %d\n",
                d->domain_id, pirq);

    desc = &irq_desc[vector];

    if ( (msi_desc = desc->msi_desc) != NULL )
        pci_disable_msi(msi_desc);

    spin_lock_irqsave(&desc->lock, flags);

    BUG_ON(vector != domain_irq_to_vector(d, pirq));

    if ( msi_desc )
        teardown_msi_vector(vector);

    if ( desc->handler == &pci_msi_type )
        desc->handler = &no_irq_type;

    if ( !forced_unbind )
    {
        d->arch.pirq_vector[pirq] = 0;
        d->arch.vector_pirq[vector] = 0;
    }
    else
    {
        d->arch.pirq_vector[pirq] = -vector;
        d->arch.vector_pirq[vector] = -pirq;
    }

    spin_unlock_irqrestore(&desc->lock, flags);
    if (msi_desc)
    {
        msi_free_vector(msi_desc);
        free_irq_vector(vector);
    }

    ret = irq_deny_access(d, pirq);
    if ( ret )
        dprintk(XENLOG_G_ERR, "dom%d: could not deny access to irq %d\n",
                d->domain_id, pirq);

 done:
    return ret;
}

void free_domain_pirqs(struct domain *d)
{
    int i;

    spin_lock(&pcidevs_lock);
    spin_lock(&d->event_lock);

    for ( i = 0; i < d->nr_pirqs; i++ )
        if ( d->arch.pirq_vector[i] > 0 )
            unmap_domain_pirq(d, i);

    spin_unlock(&d->event_lock);
    spin_unlock(&pcidevs_lock);
}

extern void dump_ioapic_irq_info(void);

static void dump_irqs(unsigned char key)
{
    int i, glob_irq, irq, vector;
    irq_desc_t *desc;
    irq_guest_action_t *action;
    struct domain *d;
    unsigned long flags;

    printk("Guest interrupt information:\n");

    for ( vector = 0; vector < NR_VECTORS; vector++ )
    {

        glob_irq = vector_to_irq(vector);

        desc = &irq_desc[vector];
        if ( desc == NULL || desc->handler == &no_irq_type )
            continue;

        spin_lock_irqsave(&desc->lock, flags);

        if ( !(desc->status & IRQ_GUEST) )
            printk("   Vec%3d IRQ%3d: type=%-15s status=%08x "
                   "mapped, unbound\n",
                   vector, glob_irq, desc->handler->typename, desc->status);
        else
        {
            action = (irq_guest_action_t *)desc->action;

            printk("   Vec%3d IRQ%3d: type=%-15s status=%08x "
                   "in-flight=%d domain-list=",
                   vector, glob_irq, desc->handler->typename,
                   desc->status, action->in_flight);

            for ( i = 0; i < action->nr_guests; i++ )
            {
                d = action->guest[i];
                irq = domain_vector_to_irq(d, vector);
                printk("%u:%3d(%c%c%c%c)",
                       d->domain_id, irq,
                       (test_bit(d->pirq_to_evtchn[glob_irq],
                                 &shared_info(d, evtchn_pending)) ?
                        'P' : '-'),
                       (test_bit(d->pirq_to_evtchn[glob_irq] /
                                 BITS_PER_EVTCHN_WORD(d),
                                 &vcpu_info(d->vcpu[0], evtchn_pending_sel)) ?
                        'S' : '-'),
                       (test_bit(d->pirq_to_evtchn[glob_irq],
                                 &shared_info(d, evtchn_mask)) ?
                        'M' : '-'),
                       (test_bit(glob_irq, d->pirq_mask) ?
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

static struct keyhandler dump_irqs_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_irqs,
    .desc = "dump interrupt bindings"
};

static int __init setup_dump_irqs(void)
{
    register_keyhandler('i', &dump_irqs_keyhandler);
    return 0;
}
__initcall(setup_dump_irqs);

#ifdef CONFIG_HOTPLUG_CPU
#include <asm/mach-generic/mach_apic.h>
#include <xen/delay.h>

void fixup_irqs(cpumask_t map)
{
    unsigned int vector, sp;
    static int warned;
    irq_guest_action_t *action;
    struct pending_eoi *peoi;
    irq_desc_t         *desc;
    unsigned long       flags;

    /* Direct all future interrupts away from this CPU. */
    for ( vector = 0; vector < NR_VECTORS; vector++ )
    {
        cpumask_t mask;
        if ( vector_to_irq(vector) == 2 )
            continue;

        desc = &irq_desc[vector];

        spin_lock_irqsave(&desc->lock, flags);

        cpus_and(mask, desc->affinity, map);
        if ( any_online_cpu(mask) == NR_CPUS )
        {
            printk("Breaking affinity for vector %u (irq %i)\n",
                   vector, vector_to_irq(vector));
            mask = map;
        }
        if ( desc->handler->set_affinity )
            desc->handler->set_affinity(vector, mask);
        else if ( desc->action && !(warned++) )
            printk("Cannot set affinity for vector %u (irq %i)\n",
                   vector, vector_to_irq(vector));

        spin_unlock_irqrestore(&desc->lock, flags);
    }

    /* Service any interrupts that beat us in the re-direction race. */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    /* Clean up cpu_eoi_map of every interrupt to exclude this CPU. */
    for ( vector = 0; vector < NR_VECTORS; vector++ )
    {
        if ( !(irq_desc[vector].status & IRQ_GUEST) )
            continue;
        action = (irq_guest_action_t *)irq_desc[vector].action;
        cpu_clear(smp_processor_id(), action->cpu_eoi_map);
    }

    /* Flush the interrupt EOI stack. */
    peoi = this_cpu(pending_eoi);
    for ( sp = 0; sp < pending_eoi_sp(peoi); sp++ )
        peoi[sp].ready = 1;
    flush_ready_eoi();
}
#endif
