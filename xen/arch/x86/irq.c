/******************************************************************************
 * arch/x86/irq.c
 * 
 * Portions of this file are:
 *  Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/delay.h>
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
#include <asm/mach-generic/mach_apic.h>
#include <public/physdev.h>

/* opt_noirqbalance: If true, software IRQ balancing/affinity is disabled. */
int __read_mostly opt_noirqbalance = 0;
boolean_param("noirqbalance", opt_noirqbalance);

unsigned int __read_mostly nr_irqs_gsi = 16;
unsigned int __read_mostly nr_irqs = 1024;
integer_param("nr_irqs", nr_irqs);

u8 __read_mostly *irq_vector;
struct irq_desc __read_mostly *irq_desc = NULL;

int __read_mostly *irq_status = NULL;
#define IRQ_UNUSED      (0)
#define IRQ_USED        (1)
#define IRQ_RSVD        (2)

#define IRQ_VECTOR_UNASSIGNED (0)

DECLARE_BITMAP(used_vectors, NR_VECTORS);

struct irq_cfg __read_mostly *irq_cfg = NULL;

static struct timer *__read_mostly irq_guest_eoi_timer;

static DEFINE_SPINLOCK(vector_lock);

DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
    [0 ... NR_VECTORS - 1] = -1
};

DEFINE_PER_CPU(struct cpu_user_regs *, __irq_regs);

static LIST_HEAD(irq_ratelimit_list);
static DEFINE_SPINLOCK(irq_ratelimit_lock);
static struct timer irq_ratelimit_timer;

/* irq_ratelimit: the max irq rate allowed in every 10ms, set 0 to disable */
static unsigned int __read_mostly irq_ratelimit_threshold = 10000;
integer_param("irq_ratelimit", irq_ratelimit_threshold);

int check_irq_status(int irq)
{
    return irq_status[irq] != IRQ_UNUSED ? 1 : 0;
}

/* Must be called when irq disabled */
void lock_vector_lock(void)
{
    /* Used to the online set of cpus does not change
     * during assign_irq_vector.
     */
    spin_lock(&vector_lock);
}

void unlock_vector_lock(void)
{
    spin_unlock(&vector_lock);
}

static int __bind_irq_vector(int irq, int vector, cpumask_t domain)
{
    cpumask_t mask;
    int cpu;
    struct irq_cfg *cfg = irq_cfg(irq);

    BUG_ON((unsigned)irq >= nr_irqs);
    BUG_ON((unsigned)vector >= NR_VECTORS);

    cpus_and(mask, domain, cpu_online_map);
    if (cpus_empty(mask))
        return -EINVAL;
    if ((cfg->vector == vector) && cpus_equal(cfg->domain, domain))
        return 0;
    if (cfg->vector != IRQ_VECTOR_UNASSIGNED) 
        return -EBUSY;
    for_each_cpu_mask(cpu, mask)
        per_cpu(vector_irq, cpu)[vector] = irq;
    cfg->vector = vector;
    cfg->domain = domain;
    irq_status[irq] = IRQ_USED;
    if (IO_APIC_IRQ(irq))
        irq_vector[irq] = vector;
    return 0;
}

int bind_irq_vector(int irq, int vector, cpumask_t domain)
{
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&vector_lock, flags);
    ret = __bind_irq_vector(irq, vector, domain);
    spin_unlock_irqrestore(&vector_lock, flags);
    return ret;
}

static inline int find_unassigned_irq(void)
{
    int irq;

    for (irq = nr_irqs_gsi; irq < nr_irqs; irq++)
        if (irq_status[irq] == IRQ_UNUSED)
            return irq;
    return -ENOSPC;
}

/*
 * Dynamic irq allocate and deallocation for MSI
 */
int create_irq(void)
{
    unsigned long flags;
    int irq, ret;
    irq = -ENOSPC;

    spin_lock_irqsave(&vector_lock, flags);

    irq = find_unassigned_irq();
    if (irq < 0)
         goto out;
    ret = __assign_irq_vector(irq, irq_cfg(irq), TARGET_CPUS);
    if (ret < 0)
        irq = ret;
out:
     spin_unlock_irqrestore(&vector_lock, flags);

    return irq;
}

static void dynamic_irq_cleanup(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;
    struct irqaction *action;

    spin_lock_irqsave(&desc->lock, flags);
    desc->status  |= IRQ_DISABLED;
    desc->handler->shutdown(irq);
    action = desc->action;
    desc->action  = NULL;
    desc->depth   = 1;
    desc->msi_desc = NULL;
    desc->handler = &no_irq_type;
    cpus_setall(desc->affinity);
    spin_unlock_irqrestore(&desc->lock, flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );

    if (action)
        xfree(action);
}

static void init_one_irq_status(int irq);

static void __clear_irq_vector(int irq)
{
    int cpu, vector;
    cpumask_t tmp_mask;
    struct irq_cfg *cfg = irq_cfg(irq);

    BUG_ON(!cfg->vector);

    vector = cfg->vector;
    cpus_and(tmp_mask, cfg->domain, cpu_online_map);

    for_each_cpu_mask(cpu, tmp_mask)
        per_cpu(vector_irq, cpu)[vector] = -1;

    cfg->vector = IRQ_VECTOR_UNASSIGNED;
    cpus_clear(cfg->domain);
    init_one_irq_status(irq);

    if (likely(!cfg->move_in_progress))
        return;
    for_each_cpu_mask(cpu, tmp_mask) {
        for (vector = FIRST_DYNAMIC_VECTOR; vector <= LAST_DYNAMIC_VECTOR;
                                vector++) {
            if (per_cpu(vector_irq, cpu)[vector] != irq)
                continue;
            per_cpu(vector_irq, cpu)[vector] = -1;
             break;
        }
     }

    cfg->move_in_progress = 0;
}

void clear_irq_vector(int irq)
{
    unsigned long flags;

    spin_lock_irqsave(&vector_lock, flags);
    __clear_irq_vector(irq);
    spin_unlock_irqrestore(&vector_lock, flags);
}

void destroy_irq(unsigned int irq)
{
    BUG_ON(!MSI_IRQ(irq));
    dynamic_irq_cleanup(irq);
    clear_irq_vector(irq);
}

int irq_to_vector(int irq)
{
    int vector = -1;
    struct irq_cfg *cfg;

    BUG_ON(irq >= nr_irqs || irq < 0);

    if (IO_APIC_IRQ(irq))
        vector = irq_vector[irq];
    else if(MSI_IRQ(irq)) {
        cfg = irq_cfg(irq);
        vector = cfg->vector;
    } else
        vector = LEGACY_VECTOR(irq);

    return vector;
}

static void init_one_irq_desc(struct irq_desc *desc)
{
    desc->status  = IRQ_DISABLED;
    desc->handler = &no_irq_type;
    desc->action  = NULL;
    desc->depth   = 1;
    desc->msi_desc = NULL;
    spin_lock_init(&desc->lock);
    cpus_setall(desc->affinity);
    INIT_LIST_HEAD(&desc->rl_link);
}

static void init_one_irq_status(int irq)
{
    irq_status[irq] = IRQ_UNUSED;
}

static void init_one_irq_cfg(struct irq_cfg *cfg)
{
    cfg->vector = IRQ_VECTOR_UNASSIGNED;
    cpus_clear(cfg->domain);
    cpus_clear(cfg->old_domain);
}

int init_irq_data(void)
{
    struct irq_desc *desc;
    struct irq_cfg *cfg;
    int irq;

    irq_desc = xmalloc_array(struct irq_desc, nr_irqs);
    irq_cfg = xmalloc_array(struct irq_cfg, nr_irqs);
    irq_status = xmalloc_array(int, nr_irqs);
    irq_guest_eoi_timer = xmalloc_array(struct timer, nr_irqs);
    irq_vector = xmalloc_array(u8, nr_irqs_gsi);
    
    if (!irq_desc || !irq_cfg || !irq_status ||! irq_vector ||
        !irq_guest_eoi_timer)
        return -ENOMEM;

    memset(irq_desc, 0,  nr_irqs * sizeof(*irq_desc));
    memset(irq_cfg, 0,  nr_irqs * sizeof(*irq_cfg));
    memset(irq_status, 0,  nr_irqs * sizeof(*irq_status));
    memset(irq_vector, 0, nr_irqs_gsi * sizeof(*irq_vector));
    memset(irq_guest_eoi_timer, 0, nr_irqs * sizeof(*irq_guest_eoi_timer));
    
    for (irq = 0; irq < nr_irqs; irq++) {
        desc = irq_to_desc(irq);
        cfg = irq_cfg(irq);
        desc->irq = irq;
        desc->chip_data = cfg;
        init_one_irq_desc(desc);
        init_one_irq_cfg(cfg);
        init_one_irq_status(irq);
    }

    /* Never allocate the hypercall vector or Linux/BSD fast-trap vector. */
    set_bit(LEGACY_SYSCALL_VECTOR, used_vectors);
    set_bit(HYPERCALL_VECTOR, used_vectors);
    
    /* IRQ_MOVE_CLEANUP_VECTOR used for clean up vectors */
    set_bit(IRQ_MOVE_CLEANUP_VECTOR, used_vectors);

    return 0;
}

static void __do_IRQ_guest(int vector);

void no_action(int cpl, void *dev_id, struct cpu_user_regs *regs) { }

static void enable_none(unsigned int vector) { }
static unsigned int startup_none(unsigned int vector) { return 0; }
static void disable_none(unsigned int vector) { }
static void ack_none(unsigned int irq)
{
    ack_bad_irq(irq);
}

#define shutdown_none   disable_none
#define end_none        enable_none

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

int __assign_irq_vector(int irq, struct irq_cfg *cfg, cpumask_t mask)
{
    /*
     * NOTE! The local APIC isn't very good at handling
     * multiple interrupts at the same interrupt level.
     * As the interrupt level is determined by taking the
     * vector number and shifting that right by 4, we
     * want to spread these out a bit so that they don't
     * all fall in the same interrupt level.
     *
     * Also, we've got to be careful not to trash gate
     * 0x80, because int 0x80 is hm, kind of importantish. ;)
     */
    static int current_vector = FIRST_DYNAMIC_VECTOR, current_offset = 0;
    unsigned int old_vector;
    int cpu, err;
    cpumask_t tmp_mask;

    if ((cfg->move_in_progress) || cfg->move_cleanup_count)
        return -EBUSY;

    old_vector = irq_to_vector(irq);
    if (old_vector) {
        cpus_and(tmp_mask, mask, cpu_online_map);
        cpus_and(tmp_mask, cfg->domain, tmp_mask);
        if (!cpus_empty(tmp_mask)) {
            cfg->vector = old_vector;
            return 0;
        }
    }

    /* Only try and allocate irqs on cpus that are present */
    cpus_and(mask, mask, cpu_online_map);

    err = -ENOSPC;
    for_each_cpu_mask(cpu, mask) {
        int new_cpu;
        int vector, offset;

        tmp_mask = vector_allocation_domain(cpu);
        cpus_and(tmp_mask, tmp_mask, cpu_online_map);

        vector = current_vector;
        offset = current_offset;
next:
        vector += 8;
        if (vector > LAST_DYNAMIC_VECTOR) {
            /* If out of vectors on large boxen, must share them. */
            offset = (offset + 1) % 8;
            vector = FIRST_DYNAMIC_VECTOR + offset;
        }
        if (unlikely(current_vector == vector))
            continue;

        if (test_bit(vector, used_vectors))
            goto next;

        for_each_cpu_mask(new_cpu, tmp_mask)
            if (per_cpu(vector_irq, new_cpu)[vector] != -1)
                goto next;
        /* Found one! */
        current_vector = vector;
        current_offset = offset;
        if (old_vector) {
            cfg->move_in_progress = 1;
            cpus_copy(cfg->old_domain, cfg->domain);
        }
        for_each_cpu_mask(new_cpu, tmp_mask)
            per_cpu(vector_irq, new_cpu)[vector] = irq;
        cfg->vector = vector;
        cpus_copy(cfg->domain, tmp_mask);

        irq_status[irq] = IRQ_USED;
            if (IO_APIC_IRQ(irq))
                    irq_vector[irq] = vector;
        err = 0;
        break;
    }
    return err;
}

int assign_irq_vector(int irq)
{
    int ret;
    unsigned long flags;
    struct irq_cfg *cfg = &irq_cfg[irq];
    struct irq_desc *desc = irq_to_desc(irq);
    
    BUG_ON(irq >= nr_irqs || irq <0);

    spin_lock_irqsave(&vector_lock, flags);
    ret = __assign_irq_vector(irq, cfg, TARGET_CPUS);
    if (!ret) {
        ret = cfg->vector;
        cpus_copy(desc->affinity, cfg->domain);
    }
    spin_unlock_irqrestore(&vector_lock, flags);
    return ret;
}

/*
 * Initialize vector_irq on a new cpu. This function must be called
 * with vector_lock held.
 */
void __setup_vector_irq(int cpu)
{
    int irq, vector;
    struct irq_cfg *cfg;

    /* Clear vector_irq */
    for (vector = 0; vector < NR_VECTORS; ++vector)
        per_cpu(vector_irq, cpu)[vector] = -1;
    /* Mark the inuse vectors */
    for (irq = 0; irq < nr_irqs; ++irq) {
        cfg = irq_cfg(irq);
        if (!cpu_isset(cpu, cfg->domain))
            continue;
        vector = irq_to_vector(irq);
        per_cpu(vector_irq, cpu)[vector] = irq;
    }
}

void move_masked_irq(int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (likely(!(desc->status & IRQ_MOVE_PENDING)))
		return;
    
    desc->status &= ~IRQ_MOVE_PENDING;

    if (unlikely(cpus_empty(desc->pending_mask)))
        return;

    if (!desc->handler->set_affinity)
        return;

	/*
	 * If there was a valid mask to work with, please
	 * do the disable, re-program, enable sequence.
	 * This is *not* particularly important for level triggered
	 * but in a edge trigger case, we might be setting rte
	 * when an active trigger is comming in. This could
	 * cause some ioapics to mal-function.
	 * Being paranoid i guess!
	 *
	 * For correct operation this depends on the caller
	 * masking the irqs.
	 */
    if (likely(cpus_intersects(desc->pending_mask, cpu_online_map)))
        desc->handler->set_affinity(irq, desc->pending_mask);

	cpus_clear(desc->pending_mask);
}

void move_native_irq(int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    if (likely(!(desc->status & IRQ_MOVE_PENDING)))
        return;

    if (unlikely(desc->status & IRQ_DISABLED))
        return;

    desc->handler->disable(irq);
    move_masked_irq(irq);
    desc->handler->enable(irq);
}

/* For re-setting irq interrupt affinity for specific irq */
void irq_set_affinity(int irq, cpumask_t mask)
{
    struct irq_desc *desc = irq_to_desc(irq);
    
    if (!desc->handler->set_affinity)
        return;
    
    ASSERT(spin_is_locked(&desc->lock));
    desc->status |= IRQ_MOVE_PENDING;
    cpus_copy(desc->pending_mask, mask);
}

asmlinkage void do_IRQ(struct cpu_user_regs *regs)
{
    struct irqaction *action;
    uint32_t          tsc_in;
    struct irq_desc  *desc;
    unsigned int      vector = regs->entry_vector;
    int irq = __get_cpu_var(vector_irq[vector]);
    struct cpu_user_regs *old_regs = set_irq_regs(regs);
    
    perfc_incr(irqs);

    if (irq < 0) {
        ack_APIC_irq();
        printk("%s: %d.%d No irq handler for vector (irq %d)\n",
                __func__, smp_processor_id(), vector, irq);
        set_irq_regs(old_regs);
        return;
    }

    desc = irq_to_desc(irq);

    spin_lock(&desc->lock);
    desc->handler->ack(irq);

    if ( likely(desc->status & IRQ_GUEST) )
    {
        if ( irq_ratelimit_timer.function && /* irq rate limiting enabled? */
             unlikely(desc->rl_cnt++ >= irq_ratelimit_threshold) )
        {
            s_time_t now = NOW();
            if ( now < (desc->rl_quantum_start + MILLISECS(10)) )
            {
                desc->handler->disable(irq);
                /*
                 * If handler->disable doesn't actually mask the interrupt, a 
                 * disabled irq still can fire. This check also avoids possible 
                 * deadlocks if ratelimit_timer_fn runs at the same time.
                 */
                if ( likely(list_empty(&desc->rl_link)) )
                {
                    spin_lock(&irq_ratelimit_lock);
                    if ( list_empty(&irq_ratelimit_list) )
                        set_timer(&irq_ratelimit_timer, now + MILLISECS(10));
                    list_add(&desc->rl_link, &irq_ratelimit_list);
                    spin_unlock(&irq_ratelimit_lock);
                }
                goto out;
            }
            desc->rl_cnt = 0;
            desc->rl_quantum_start = now;
        }

        irq_enter();
        tsc_in = tb_init_done ? get_cycles() : 0;
        __do_IRQ_guest(irq);
        TRACE_3D(TRC_TRACE_IRQ, irq, tsc_in, get_cycles());
        irq_exit();
        spin_unlock(&desc->lock);
        set_irq_regs(old_regs);
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
        action->handler(irq, action->dev_id, regs);
        TRACE_3D(TRC_TRACE_IRQ, irq, tsc_in, get_cycles());
        spin_lock_irq(&desc->lock);
        irq_exit();
    }

    desc->status &= ~IRQ_INPROGRESS;

 out:
    desc->handler->end(irq);
    spin_unlock(&desc->lock);
    set_irq_regs(old_regs);
}

static void irq_ratelimit_timer_fn(void *data)
{
    struct irq_desc *desc, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&irq_ratelimit_lock, flags);

    list_for_each_entry_safe ( desc, tmp, &irq_ratelimit_list, rl_link )
    {
        spin_lock(&desc->lock);
        desc->handler->enable(desc->irq);
        list_del(&desc->rl_link);
        INIT_LIST_HEAD(&desc->rl_link);
        spin_unlock(&desc->lock);
    }

    spin_unlock_irqrestore(&irq_ratelimit_lock, flags);
}

static int __init irq_ratelimit_init(void)
{
    if ( irq_ratelimit_threshold )
        init_timer(&irq_ratelimit_timer, irq_ratelimit_timer_fn, NULL, 0);
    return 0;
}
__initcall(irq_ratelimit_init);

int request_irq(unsigned int irq,
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
    if (irq >= nr_irqs)
        return -EINVAL;
    if (!handler)
        return -EINVAL;

    action = xmalloc(struct irqaction);
    if (!action)
        return -ENOMEM;

    action->handler = handler;
    action->name = devname;
    action->dev_id = dev_id;
    action->free_on_release = 1;

    retval = setup_irq(irq, action);
    if (retval)
        xfree(action);

    return retval;
}

void release_irq(unsigned int irq)
{
    struct irq_desc *desc;
    unsigned long flags;
    struct irqaction *action;

    desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock,flags);
    action = desc->action;
    desc->action  = NULL;
    desc->depth   = 1;
    desc->status |= IRQ_DISABLED;
    desc->handler->shutdown(irq);
    spin_unlock_irqrestore(&desc->lock,flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );

    if (action && action->free_on_release)
        xfree(action);
}

int setup_irq(unsigned int irq, struct irqaction *new)
{
    struct irq_desc *desc;
    unsigned long flags;

    desc = irq_to_desc(irq);
 
    spin_lock_irqsave(&desc->lock,flags);

    if ( desc->action != NULL )
    {
        spin_unlock_irqrestore(&desc->lock,flags);
        return -EBUSY;
    }

    desc->action  = new;
    desc->depth   = 0;
    desc->status &= ~IRQ_DISABLED;
    desc->handler->startup(irq);

    if ( !check_irq_status(irq) )
        irq_status[irq] = IRQ_USED;

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
    u8 eoi_vector;           /* vector awaiting the EOI*/
    struct domain *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

/*
 * Stack of interrupts awaiting EOI on each CPU. These must be popped in
 * order, as only the current highest-priority pending irq can be EOIed.
 */
struct pending_eoi {
    u8 vector; /* vector awaiting EOI */
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

static void _irq_guest_eoi(struct irq_desc *desc)
{
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    unsigned int i, irq = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST_EOI_PENDING) )
        return;

    for ( i = 0; i < action->nr_guests; ++i )
        clear_pirq_eoi(action->guest[i],
                       domain_irq_to_pirq(action->guest[i], irq));

    desc->status &= ~(IRQ_INPROGRESS|IRQ_GUEST_EOI_PENDING);
    desc->handler->enable(irq);
}

static void irq_guest_eoi_timer_fn(void *data)
{
    struct irq_desc *desc = data;
    unsigned long flags;

    spin_lock_irqsave(&desc->lock, flags);
    _irq_guest_eoi(desc);
    spin_unlock_irqrestore(&desc->lock, flags);
}

static void __do_IRQ_guest(int irq)
{
    struct irq_desc         *desc = irq_to_desc(irq);
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i, sp, already_pending = 0;
    struct pending_eoi *peoi = this_cpu(pending_eoi);
    int vector = get_irq_regs()->entry_vector;

    if ( unlikely(action->nr_guests == 0) )
    {
        /* An interrupt may slip through while freeing an ACKTYPE_EOI irq. */
        ASSERT(action->ack_type == ACKTYPE_EOI);
        ASSERT(desc->status & IRQ_DISABLED);
        desc->handler->end(irq);
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
        action->eoi_vector = vector;
    }

    for ( i = 0; i < action->nr_guests; i++ )
    {
        unsigned int pirq;
        d = action->guest[i];
        pirq = domain_irq_to_pirq(d, irq);
        if ( (action->ack_type != ACKTYPE_NONE) &&
             !test_and_set_bit(pirq, d->pirq_mask) )
            action->in_flight++;
        if ( hvm_do_IRQ_dpci(d, pirq) )
        {
            if ( action->ack_type == ACKTYPE_NONE )
            {
                already_pending += !!(desc->status & IRQ_INPROGRESS);
                desc->status |= IRQ_INPROGRESS; /* cleared during hvm eoi */
            }
        }
        else if ( send_guest_pirq(d, pirq) &&
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
            set_pirq_eoi(d, domain_irq_to_pirq(d, irq));
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

/*
 * Retrieve Xen irq-descriptor corresponding to a domain-specific irq.
 * The descriptor is returned locked. This function is safe against changes
 * to the per-domain irq-to-vector mapping.
 */
struct irq_desc *domain_spin_lock_irq_desc(
    struct domain *d, int pirq, unsigned long *pflags)
{
    unsigned int irq;
    unsigned long flags;
    struct irq_desc *desc;

    for ( ; ; )
    {
        irq = domain_pirq_to_irq(d, pirq);
        if ( irq <= 0 )
            return NULL;
        desc = irq_to_desc(irq);
        spin_lock_irqsave(&desc->lock, flags);
        if ( irq == domain_pirq_to_irq(d, pirq) )
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
    struct irq_desc         *desc;
    int                irq, sp;

    ASSERT(!local_irq_is_enabled());

    sp = pending_eoi_sp(peoi);

    while ( (--sp >= 0) && peoi[sp].ready )
    {
        irq = __get_cpu_var(vector_irq[peoi[sp].vector]);
        ASSERT(irq > 0);
        desc = irq_to_desc(irq);
        spin_lock(&desc->lock);
        desc->handler->end(irq);
        spin_unlock(&desc->lock);
    }

    pending_eoi_sp(peoi) = sp+1;
}

static void __set_eoi_ready(struct irq_desc *desc)
{
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct pending_eoi *peoi = this_cpu(pending_eoi);
    int                 irq, sp;

    irq = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST) ||
         (action->in_flight != 0) ||
         !cpu_test_and_clear(smp_processor_id(), action->cpu_eoi_map) )
        return;

    sp = pending_eoi_sp(peoi);

    do {
        ASSERT(sp > 0);
    } while ( peoi[--sp].vector != action->eoi_vector );
    ASSERT(!peoi[sp].ready);
    peoi[sp].ready = 1;
}

/* Mark specified IRQ as ready-for-EOI (if it really is) and attempt to EOI. */
static void set_eoi_ready(void *data)
{
    struct irq_desc *desc = data;

    ASSERT(!local_irq_is_enabled());

    spin_lock(&desc->lock);
    __set_eoi_ready(desc);
    spin_unlock(&desc->lock);

    flush_ready_eoi();
}

static void __pirq_guest_eoi(struct domain *d, int pirq)
{
    struct irq_desc         *desc;
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;
    int                 irq;

    ASSERT(local_irq_is_enabled());
    desc = domain_spin_lock_irq_desc(d, pirq, NULL);
    if ( desc == NULL )
        return;

    action = (irq_guest_action_t *)desc->action;
    irq = desc - irq_desc;

    if ( action->ack_type == ACKTYPE_NONE )
    {
        ASSERT(!test_bit(pirq, d->pirq_mask));
        stop_timer(&irq_guest_eoi_timer[irq]);
        _irq_guest_eoi(desc);
    }

    if ( unlikely(!test_and_clear_bit(pirq, d->pirq_mask)) ||
         unlikely(--action->in_flight != 0) )
    {
        spin_unlock_irq(&desc->lock);
        return;
    }

    if ( action->ack_type == ACKTYPE_UNMASK )
    {
        ASSERT(cpus_empty(action->cpu_eoi_map));
        desc->handler->end(irq);
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
    if ( (irq < 0) || (irq > d->nr_pirqs) )
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
static int pirq_acktype(struct domain *d, int pirq)
{
    struct irq_desc  *desc;
    unsigned int irq;

    irq = domain_pirq_to_irq(d, pirq);
    if ( irq <= 0 )
        return ACKTYPE_NONE;

    desc = irq_to_desc(irq);

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

int pirq_shared(struct domain *d, int pirq)
{
    struct irq_desc         *desc;
    irq_guest_action_t *action;
    unsigned long       flags;
    int                 shared;

    desc = domain_spin_lock_irq_desc(d, pirq, &flags);
    if ( desc == NULL )
        return 0;

    action = (irq_guest_action_t *)desc->action;
    shared = ((desc->status & IRQ_GUEST) && (action->nr_guests > 1));

    spin_unlock_irqrestore(&desc->lock, flags);

    return shared;
}

int pirq_guest_bind(struct vcpu *v, int pirq, int will_share)
{
    unsigned int        irq;
    struct irq_desc         *desc;
    irq_guest_action_t *action, *newaction = NULL;
    int                 rc = 0;
    cpumask_t           cpumask = CPU_MASK_NONE;

    WARN_ON(!spin_is_locked(&v->domain->event_lock));
    BUG_ON(!local_irq_is_enabled());

 retry:
    desc = domain_spin_lock_irq_desc(v->domain, pirq, NULL);
    if ( desc == NULL )
    {
        rc = -EINVAL;
        goto out;
    }

    action = (irq_guest_action_t *)desc->action;
    irq = desc - irq_desc;

    if ( !(desc->status & IRQ_GUEST) )
    {
        if ( desc->action != NULL )
        {
            gdprintk(XENLOG_INFO,
                    "Cannot bind IRQ %d to guest. In use by '%s'.\n",
                    pirq, desc->action->name);
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
                     pirq);
            rc = -ENOMEM;
            goto out;
        }

        action = newaction;
        desc->action = (struct irqaction *)action;
        newaction = NULL;

        action->nr_guests   = 0;
        action->in_flight   = 0;
        action->shareable   = will_share;
        action->ack_type    = pirq_acktype(v->domain, pirq);
        cpus_clear(action->cpu_eoi_map);

        desc->depth = 0;
        desc->status |= IRQ_GUEST;
        desc->status &= ~IRQ_DISABLED;
        desc->handler->startup(irq);

        /* Attempt to bind the interrupt target to the correct CPU. */
        cpu_set(v->processor, cpumask);
        if ( !opt_noirqbalance && (desc->handler->set_affinity != NULL) )
            desc->handler->set_affinity(irq, cpumask);
    }
    else if ( !will_share || !action->shareable )
    {
        gdprintk(XENLOG_INFO, "Cannot bind IRQ %d to guest. %s.\n",
                 pirq,
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
               "Already at max share.\n", pirq);
        rc = -EBUSY;
        goto unlock_out;
    }

    action->guest[action->nr_guests++] = v->domain;

    if ( action->ack_type != ACKTYPE_NONE )
        set_pirq_eoi(v->domain, pirq);
    else
        clear_pirq_eoi(v->domain, pirq);

 unlock_out:
    spin_unlock_irq(&desc->lock);
 out:
    if ( newaction != NULL )
        xfree(newaction);
    return rc;
}

static irq_guest_action_t *__pirq_guest_unbind(
    struct domain *d, int pirq, struct irq_desc *desc)
{
    unsigned int        irq;
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;
    int                 i;

    BUG_ON(!(desc->status & IRQ_GUEST));

    action = (irq_guest_action_t *)desc->action;
    irq = desc - irq_desc;

    for ( i = 0; (i < action->nr_guests) && (action->guest[i] != d); i++ )
        continue;
    BUG_ON(i == action->nr_guests);
    memmove(&action->guest[i], &action->guest[i+1], IRQ_MAX_GUESTS-i-1);
    action->nr_guests--;

    switch ( action->ack_type )
    {
    case ACKTYPE_UNMASK:
        if ( test_and_clear_bit(pirq, d->pirq_mask) &&
             (--action->in_flight == 0) )
            desc->handler->end(irq);
        break;
    case ACKTYPE_EOI:
        /* NB. If #guests == 0 then we clear the eoi_map later on. */
        if ( test_and_clear_bit(pirq, d->pirq_mask) &&
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
        stop_timer(&irq_guest_eoi_timer[irq]);
        _irq_guest_eoi(desc);
        break;
    }

    /*
     * The guest cannot re-bind to this IRQ until this function returns. So,
     * when we have flushed this IRQ from pirq_mask, it should remain flushed.
     */
    BUG_ON(test_bit(pirq, d->pirq_mask));

    if ( action->nr_guests != 0 )
        return NULL;

    BUG_ON(action->in_flight != 0);

    /* Disabling IRQ before releasing the desc_lock avoids an IRQ storm. */
    desc->depth   = 1;
    desc->status |= IRQ_DISABLED;
    desc->handler->disable(irq);

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
    kill_timer(&irq_guest_eoi_timer[irq]);
    desc->handler->shutdown(irq);

    /* Caller frees the old guest descriptor block. */
    return action;
}

void pirq_guest_unbind(struct domain *d, int pirq)
{
    irq_guest_action_t *oldaction = NULL;
    struct irq_desc *desc;
    int irq;

    WARN_ON(!spin_is_locked(&d->event_lock));

    BUG_ON(!local_irq_is_enabled());
    desc = domain_spin_lock_irq_desc(d, pirq, NULL);

    if ( desc == NULL )
    {
        irq = -domain_pirq_to_irq(d, pirq);
        BUG_ON(irq <= 0);
        desc = irq_to_desc(irq);
        spin_lock_irq(&desc->lock);
        d->arch.pirq_irq[pirq] = d->arch.irq_pirq[irq] = 0;
    }
    else
    {
        oldaction = __pirq_guest_unbind(d, pirq, desc);
    }

    spin_unlock_irq(&desc->lock);

    if ( oldaction != NULL )
        xfree(oldaction);
}

static int pirq_guest_force_unbind(struct domain *d, int irq)
{
    struct irq_desc *desc;
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
            if ( !d->arch.pirq_irq[i] )
                break;
        if ( i == nr_irqs_gsi )
            return -ENOSPC;
    }
    else
    {
        for ( i = d->nr_pirqs - 1; i >= nr_irqs_gsi; i-- )
            if ( !d->arch.pirq_irq[i] )
                break;
        if ( i < nr_irqs_gsi )
            return -ENOSPC;
    }

    return i;
}

int map_domain_pirq(
    struct domain *d, int pirq, int irq, int type, void *data)
{
    int ret = 0;
    int old_irq, old_pirq;
    struct irq_desc *desc;
    unsigned long flags;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev = NULL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));
    
    desc = irq_to_desc(irq);

    if ( !IS_PRIV(current->domain) &&
         !(IS_PRIV_FOR(current->domain, d) &&
          irq_access_permitted(current->domain, pirq)))
        return -EPERM;

    if ( pirq < 0 || pirq >= d->nr_pirqs || irq < 0 || irq >= nr_irqs )
    {
        dprintk(XENLOG_G_ERR, "dom%d: invalid pirq %d or irq %d\n",
                d->domain_id, pirq, irq);
        return -EINVAL;
    }

    if ( desc->action )
    {
        dprintk(XENLOG_G_WARNING, "Attempt to map in-use IRQ by Xen,"
                        " irq:%d!\n", irq);
        return 0;
    }

    old_irq = domain_pirq_to_irq(d, pirq);
    old_pirq = domain_irq_to_pirq(d, irq);

    if ( (old_irq && (old_irq != irq) ) ||
         (old_pirq && (old_pirq != pirq)) )
    {
        dprintk(XENLOG_G_WARNING, "dom%d: pirq %d or irq %d already mapped\n",
                d->domain_id, pirq, irq);
        return 0;
    }

    ret = irq_permit_access(d, pirq);
    if ( ret )
    {
        dprintk(XENLOG_G_ERR, "dom%d: could not permit access to irq %d\n",
                d->domain_id, pirq);
        return ret;
    }


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
            dprintk(XENLOG_G_ERR, "dom%d: irq %d in use\n",
              d->domain_id, irq);
        desc->handler = &pci_msi_type;
        d->arch.pirq_irq[pirq] = irq;
        d->arch.irq_pirq[irq] = pirq;
        setup_msi_irq(pdev, msi_desc, irq);
        spin_unlock_irqrestore(&desc->lock, flags);
    } else
    {
        spin_lock_irqsave(&desc->lock, flags);
        d->arch.pirq_irq[pirq] = irq;
        d->arch.irq_pirq[irq] = pirq;
        spin_unlock_irqrestore(&desc->lock, flags);
    }

 done:
    return ret;
}

/* The pirq should have been unbound before this call. */
int unmap_domain_pirq(struct domain *d, int pirq)
{
    unsigned long flags;
    struct irq_desc *desc;
    int irq, ret = 0;
    bool_t forced_unbind;
    struct msi_desc *msi_desc = NULL;

    if ( (pirq < 0) || (pirq >= d->nr_pirqs) )
        return -EINVAL;

    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));

    irq = domain_pirq_to_irq(d, pirq);
    if ( irq <= 0 )
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

    desc = irq_to_desc(irq);

    if ( (msi_desc = desc->msi_desc) != NULL )
        pci_disable_msi(msi_desc);

    spin_lock_irqsave(&desc->lock, flags);

    BUG_ON(irq != domain_pirq_to_irq(d, pirq));

    if ( !forced_unbind )
    {
        d->arch.pirq_irq[pirq] = 0;
        d->arch.irq_pirq[irq] = 0;
    }
    else
    {
        d->arch.pirq_irq[pirq] = -irq;
        d->arch.irq_pirq[irq] = -pirq;
    }

    spin_unlock_irqrestore(&desc->lock, flags);
    if (msi_desc)
        msi_free_irq(msi_desc);

    ret = irq_deny_access(d, pirq);
    if ( ret )
        dprintk(XENLOG_G_ERR, "dom%d: could not deny access to irq %d\n",
                d->domain_id, pirq);

    if ( desc->handler == &pci_msi_type )
        desc->handler = &no_irq_type;

 done:
    return ret;
}

void free_domain_pirqs(struct domain *d)
{
    int i;

    spin_lock(&pcidevs_lock);
    spin_lock(&d->event_lock);

    for ( i = 0; i < d->nr_pirqs; i++ )
        if ( d->arch.pirq_irq[i] > 0 )
            unmap_domain_pirq(d, i);

    spin_unlock(&d->event_lock);
    spin_unlock(&pcidevs_lock);
}

extern void dump_ioapic_irq_info(void);

static void dump_irqs(unsigned char key)
{
    int i, irq, pirq;
    struct irq_desc *desc;
    struct irq_cfg *cfg;
    irq_guest_action_t *action;
    struct domain *d;
    unsigned long flags;

    printk("Guest interrupt information:\n");

    for ( irq = 0; irq < nr_irqs; irq++ )
    {

        desc = irq_to_desc(irq);
        cfg = desc->chip_data;

        if ( !desc->handler || desc->handler == &no_irq_type )
            continue;

        spin_lock_irqsave(&desc->lock, flags);

        if ( !(desc->status & IRQ_GUEST) )
            /* Only show CPU0 - CPU31's affinity info.*/
            printk("   IRQ:%4d, IRQ affinity:0x%08x, Vec:%3d type=%-15s"
                    " status=%08x mapped, unbound\n",
                   irq, *(int*)desc->affinity.bits, cfg->vector,
                    desc->handler->typename, desc->status);
        else
        {
            action = (irq_guest_action_t *)desc->action;

            printk("   IRQ:%4d, IRQ affinity:0x%08x, Vec:%3d type=%-15s "
                    "status=%08x in-flight=%d domain-list=",
                   irq, *(int*)desc->affinity.bits, cfg->vector,
                   desc->handler->typename, desc->status, action->in_flight);

            for ( i = 0; i < action->nr_guests; i++ )
            {
                d = action->guest[i];
                pirq = domain_irq_to_pirq(d, irq);
                printk("%u:%3d(%c%c%c%c)",
                       d->domain_id, pirq,
                       (test_bit(d->pirq_to_evtchn[pirq],
                                 &shared_info(d, evtchn_pending)) ?
                        'P' : '-'),
                       (test_bit(d->pirq_to_evtchn[pirq] /
                                 BITS_PER_EVTCHN_WORD(d),
                                 &vcpu_info(d->vcpu[0], evtchn_pending_sel)) ?
                        'S' : '-'),
                       (test_bit(d->pirq_to_evtchn[pirq],
                                 &shared_info(d, evtchn_mask)) ?
                        'M' : '-'),
                       (test_bit(pirq, d->pirq_mask) ?
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

/* A cpu has been removed from cpu_online_mask.  Re-set irq affinities. */
void fixup_irqs(void)
{
    unsigned int irq, sp;
    static int warned;
    struct irq_desc *desc;
    irq_guest_action_t *action;
    struct pending_eoi *peoi;

    for ( irq = 0; irq < nr_irqs; irq++ )
    {
        int break_affinity = 0;
        int set_affinity = 1;
        cpumask_t affinity;

        if ( irq == 2 )
            continue;

        desc = irq_to_desc(irq);

        spin_lock(&desc->lock);

        affinity = desc->affinity;
        if ( !desc->action || cpus_equal(affinity, cpu_online_map) )
        {
            spin_unlock(&desc->lock);
            continue;
        }

        cpus_and(affinity, affinity, cpu_online_map);
        if ( any_online_cpu(affinity) == NR_CPUS )
        {
            break_affinity = 1;
            affinity = cpu_online_map;
        }

        if ( desc->handler->disable )
            desc->handler->disable(irq);

        if ( desc->handler->set_affinity )
            desc->handler->set_affinity(irq, affinity);
        else if ( !(warned++) )
            set_affinity = 0;

        if ( desc->handler->enable )
            desc->handler->enable(irq);

        spin_unlock(&desc->lock);

        if ( break_affinity && set_affinity )
            printk("Broke affinity for irq %i\n", irq);
        else if ( !set_affinity )
            printk("Cannot set affinity for irq %i\n", irq);
    }

    /* That doesn't seem sufficient.  Give it 1ms. */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    /* Clean up cpu_eoi_map of every interrupt to exclude this CPU. */
    for ( irq = 0; irq < nr_irqs; irq++ )
    {
        desc = irq_to_desc(irq);
        if ( !(desc->status & IRQ_GUEST) )
            continue;
        action = (irq_guest_action_t *)desc->action;
        cpu_clear(smp_processor_id(), action->cpu_eoi_map);
    }

    /* Flush the interrupt EOI stack. */
    peoi = this_cpu(pending_eoi);
    for ( sp = 0; sp < pending_eoi_sp(peoi); sp++ )
        peoi[sp].ready = 1;
    flush_ready_eoi();
}
