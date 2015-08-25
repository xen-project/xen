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
#include <xen/symbols.h>
#include <xen/trace.h>
#include <xen/softirq.h>
#include <xsm/xsm.h>
#include <asm/msi.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/mach-generic/mach_apic.h>
#include <public/physdev.h>

static void parse_irq_vector_map_param(char *s);

/* opt_noirqbalance: If true, software IRQ balancing/affinity is disabled. */
bool_t __read_mostly opt_noirqbalance = 0;
boolean_param("noirqbalance", opt_noirqbalance);

unsigned int __read_mostly nr_irqs_gsi = 16;
unsigned int __read_mostly nr_irqs;
integer_param("nr_irqs", nr_irqs);

/* This default may be changed by the AMD IOMMU code */
int __read_mostly opt_irq_vector_map = OPT_IRQ_VECTOR_MAP_DEFAULT;
custom_param("irq_vector_map", parse_irq_vector_map_param);

vmask_t global_used_vector_map;

struct irq_desc __read_mostly *irq_desc = NULL;

static DECLARE_BITMAP(used_vectors, NR_VECTORS);

static DEFINE_SPINLOCK(vector_lock);

DEFINE_PER_CPU(vector_irq_t, vector_irq);

DEFINE_PER_CPU(struct cpu_user_regs *, __irq_regs);

static LIST_HEAD(irq_ratelimit_list);
static DEFINE_SPINLOCK(irq_ratelimit_lock);
static struct timer irq_ratelimit_timer;

/* irq_ratelimit: the max irq rate allowed in every 10ms, set 0 to disable */
static unsigned int __read_mostly irq_ratelimit_threshold = 10000;
integer_param("irq_ratelimit", irq_ratelimit_threshold);

static void __init parse_irq_vector_map_param(char *s)
{
    char *ss;

    do {
        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !strcmp(s, "none"))
            opt_irq_vector_map=OPT_IRQ_VECTOR_MAP_NONE;
        else if ( !strcmp(s, "global"))
            opt_irq_vector_map=OPT_IRQ_VECTOR_MAP_GLOBAL;
        else if ( !strcmp(s, "per-device"))
            opt_irq_vector_map=OPT_IRQ_VECTOR_MAP_PERDEV;

        s = ss + 1;
    } while ( ss );
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

static void trace_irq_mask(u32 event, int irq, int vector, cpumask_t *mask)
{
    struct {
        unsigned int irq:16, vec:16;
        unsigned int mask[6];
    } d;
    d.irq = irq;
    d.vec = vector;
    memset(d.mask, 0, sizeof(d.mask));
    memcpy(d.mask, mask, min(sizeof(d.mask), sizeof(cpumask_t)));
    trace_var(event, 1, sizeof(d), &d);
}

static int __init __bind_irq_vector(int irq, int vector, const cpumask_t *cpu_mask)
{
    cpumask_t online_mask;
    int cpu;
    struct irq_desc *desc = irq_to_desc(irq);

    BUG_ON((unsigned)irq >= nr_irqs);
    BUG_ON((unsigned)vector >= NR_VECTORS);

    cpumask_and(&online_mask, cpu_mask, &cpu_online_map);
    if (cpumask_empty(&online_mask))
        return -EINVAL;
    if ( (desc->arch.vector == vector) &&
         cpumask_equal(desc->arch.cpu_mask, &online_mask) )
        return 0;
    if ( desc->arch.vector != IRQ_VECTOR_UNASSIGNED )
        return -EBUSY;
    trace_irq_mask(TRC_HW_IRQ_BIND_VECTOR, irq, vector, &online_mask);
    for_each_cpu(cpu, &online_mask)
        per_cpu(vector_irq, cpu)[vector] = irq;
    desc->arch.vector = vector;
    cpumask_copy(desc->arch.cpu_mask, &online_mask);
    if ( desc->arch.used_vectors )
    {
        ASSERT(!test_bit(vector, desc->arch.used_vectors));
        set_bit(vector, desc->arch.used_vectors);
    }
    desc->arch.used = IRQ_USED;
    return 0;
}

int __init bind_irq_vector(int irq, int vector, const cpumask_t *cpu_mask)
{
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&vector_lock, flags);
    ret = __bind_irq_vector(irq, vector, cpu_mask);
    spin_unlock_irqrestore(&vector_lock, flags);
    return ret;
}

/*
 * Dynamic irq allocate and deallocation for MSI
 */
int create_irq(nodeid_t node)
{
    int irq, ret;
    struct irq_desc *desc;

    for (irq = nr_irqs_gsi; irq < nr_irqs; irq++)
    {
        desc = irq_to_desc(irq);
        if (cmpxchg(&desc->arch.used, IRQ_UNUSED, IRQ_RESERVED) == IRQ_UNUSED)
           break;
    }

    if (irq >= nr_irqs)
         return -ENOSPC;

    ret = init_one_irq_desc(desc);
    if (!ret)
    {
        cpumask_t *mask = NULL;

        if ( node != NUMA_NO_NODE )
        {
            mask = &node_to_cpumask(node);
            if (cpumask_empty(mask))
                mask = NULL;
        }
        ret = assign_irq_vector(irq, mask);
    }
    if (ret < 0)
    {
        desc->arch.used = IRQ_UNUSED;
        irq = ret;
    }
    else if ( hardware_domain )
    {
        ret = irq_permit_access(hardware_domain, irq);
        if ( ret )
            printk(XENLOG_G_ERR
                   "Could not grant Dom0 access to IRQ%d (error %d)\n",
                   irq, ret);
    }

    return irq;
}

void destroy_irq(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;
    struct irqaction *action;

    BUG_ON(!MSI_IRQ(irq));

    if ( hardware_domain )
    {
        int err = irq_deny_access(hardware_domain, irq);

        if ( err )
            printk(XENLOG_G_ERR
                   "Could not revoke Dom0 access to IRQ%u (error %d)\n",
                   irq, err);
    }

    spin_lock_irqsave(&desc->lock, flags);
    desc->status  &= ~IRQ_GUEST;
    desc->handler->shutdown(desc);
    desc->status |= IRQ_DISABLED;
    action = desc->action;
    desc->action  = NULL;
    desc->msi_desc = NULL;
    cpumask_setall(desc->affinity);
    spin_unlock_irqrestore(&desc->lock, flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );

    spin_lock_irqsave(&desc->lock, flags);
    desc->handler = &no_irq_type;
    clear_irq_vector(irq);
    desc->arch.used_vectors = NULL;
    spin_unlock_irqrestore(&desc->lock, flags);

    xfree(action);
}

static void __clear_irq_vector(int irq)
{
    int cpu, vector, old_vector;
    cpumask_t tmp_mask;
    struct irq_desc *desc = irq_to_desc(irq);

    BUG_ON(!desc->arch.vector);

    /* Always clear desc->arch.vector */
    vector = desc->arch.vector;
    cpumask_and(&tmp_mask, desc->arch.cpu_mask, &cpu_online_map);

    for_each_cpu(cpu, &tmp_mask) {
        ASSERT( per_cpu(vector_irq, cpu)[vector] == irq );
        per_cpu(vector_irq, cpu)[vector] = ~irq;
    }

    desc->arch.vector = IRQ_VECTOR_UNASSIGNED;
    cpumask_clear(desc->arch.cpu_mask);

    if ( desc->arch.used_vectors )
    {
        ASSERT(test_bit(vector, desc->arch.used_vectors));
        clear_bit(vector, desc->arch.used_vectors);
    }

    desc->arch.used = IRQ_UNUSED;

    trace_irq_mask(TRC_HW_IRQ_CLEAR_VECTOR, irq, vector, &tmp_mask);

    if ( likely(!desc->arch.move_in_progress) )
        return;

    /* If we were in motion, also clear desc->arch.old_vector */
    old_vector = desc->arch.old_vector;
    cpumask_and(&tmp_mask, desc->arch.old_cpu_mask, &cpu_online_map);

    for_each_cpu(cpu, &tmp_mask) {
        ASSERT( per_cpu(vector_irq, cpu)[old_vector] == irq );
        TRACE_3D(TRC_HW_IRQ_MOVE_FINISH, irq, old_vector, cpu);
        per_cpu(vector_irq, cpu)[old_vector] = ~irq;
    }

    desc->arch.old_vector = IRQ_VECTOR_UNASSIGNED;
    cpumask_clear(desc->arch.old_cpu_mask);

    if ( desc->arch.used_vectors )
    {
        ASSERT(test_bit(old_vector, desc->arch.used_vectors));
        clear_bit(old_vector, desc->arch.used_vectors);
    }

    desc->arch.move_in_progress = 0;
}

void clear_irq_vector(int irq)
{
    unsigned long flags;

    spin_lock_irqsave(&vector_lock, flags);
    __clear_irq_vector(irq);
    spin_unlock_irqrestore(&vector_lock, flags);
}

int irq_to_vector(int irq)
{
    int vector = -1;

    BUG_ON(irq >= nr_irqs || irq < 0);

    if (IO_APIC_IRQ(irq))
    {
        vector = irq_to_desc(irq)->arch.vector;
        if (vector >= FIRST_LEGACY_VECTOR && vector <= LAST_LEGACY_VECTOR)
            vector = 0;
    }
    else if (MSI_IRQ(irq))
        vector = irq_to_desc(irq)->arch.vector;
    else
        vector = LEGACY_VECTOR(irq);

    return vector;
}

int arch_init_one_irq_desc(struct irq_desc *desc)
{
    if ( !zalloc_cpumask_var(&desc->arch.cpu_mask) )
        return -ENOMEM;

    if ( !alloc_cpumask_var(&desc->arch.old_cpu_mask) )
    {
        free_cpumask_var(desc->arch.cpu_mask);
        return -ENOMEM;
    }

    if ( !alloc_cpumask_var(&desc->arch.pending_mask) )
    {
        free_cpumask_var(desc->arch.old_cpu_mask);
        free_cpumask_var(desc->arch.cpu_mask);
        return -ENOMEM;
    }

    desc->arch.vector = IRQ_VECTOR_UNASSIGNED;
    desc->arch.old_vector = IRQ_VECTOR_UNASSIGNED;

    return 0;
}

int __init init_irq_data(void)
{
    struct irq_desc *desc;
    int irq, vector;

    for (vector = 0; vector < NR_VECTORS; ++vector)
        this_cpu(vector_irq)[vector] = INT_MIN;

    irq_desc = xzalloc_array(struct irq_desc, nr_irqs);
    
    if ( !irq_desc )
        return -ENOMEM;

    for (irq = 0; irq < nr_irqs_gsi; irq++) {
        desc = irq_to_desc(irq);
        desc->irq = irq;
        init_one_irq_desc(desc);
    }
    for (; irq < nr_irqs; irq++)
        irq_to_desc(irq)->irq = irq;

    /* Never allocate the hypercall vector or Linux/BSD fast-trap vector. */
    set_bit(LEGACY_SYSCALL_VECTOR, used_vectors);
    set_bit(HYPERCALL_VECTOR, used_vectors);
    
    /* IRQ_MOVE_CLEANUP_VECTOR used for clean up vectors */
    set_bit(IRQ_MOVE_CLEANUP_VECTOR, used_vectors);

    return 0;
}

static void __do_IRQ_guest(int vector);

static void ack_none(struct irq_desc *desc)
{
    ack_bad_irq(desc->irq);
}

hw_irq_controller no_irq_type = {
    "none",
    irq_startup_none,
    irq_shutdown_none,
    irq_enable_none,
    irq_disable_none,
    ack_none,
};

static vmask_t *irq_get_used_vector_mask(int irq)
{
    vmask_t *ret = NULL;

    if ( opt_irq_vector_map == OPT_IRQ_VECTOR_MAP_GLOBAL )
    {
        struct irq_desc *desc = irq_to_desc(irq);

        ret = &global_used_vector_map;

        if ( desc->arch.used_vectors )
        {
            printk(XENLOG_INFO "%s: Strange, unassigned irq %d already has used_vectors!\n",
                   __func__, irq);
        }
        else
        {
            int vector;
            
            vector = irq_to_vector(irq);
            if ( vector > 0 )
            {
                printk(XENLOG_INFO "%s: Strange, irq %d already assigned vector %d!\n",
                       __func__, irq, vector);
                
                ASSERT(!test_bit(vector, ret));

                set_bit(vector, ret);
            }
        }
    }
    else if ( IO_APIC_IRQ(irq) &&
              opt_irq_vector_map != OPT_IRQ_VECTOR_MAP_NONE )
    {
        ret = io_apic_get_used_vector_map(irq);
    }

    return ret;
}

static int __assign_irq_vector(
    int irq, struct irq_desc *desc, const cpumask_t *mask)
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
    int cpu, err, old_vector;
    cpumask_t tmp_mask;
    vmask_t *irq_used_vectors = NULL;

    old_vector = irq_to_vector(irq);
    if (old_vector > 0) {
        cpumask_and(&tmp_mask, mask, &cpu_online_map);
        if (cpumask_intersects(&tmp_mask, desc->arch.cpu_mask)) {
            desc->arch.vector = old_vector;
            return 0;
        }
    }

    if ( desc->arch.move_in_progress || desc->arch.move_cleanup_count )
        return -EAGAIN;

    err = -ENOSPC;

    /* This is the only place normal IRQs are ever marked
     * as "in use".  If they're not in use yet, check to see
     * if we need to assign a global vector mask. */
    if ( desc->arch.used == IRQ_USED )
    {
        irq_used_vectors = desc->arch.used_vectors;
    }
    else
        irq_used_vectors = irq_get_used_vector_mask(irq);

    for_each_cpu(cpu, mask) {
        int new_cpu;
        int vector, offset;

        /* Only try and allocate irqs on cpus that are present. */
        if (!cpu_online(cpu))
            continue;

        cpumask_and(&tmp_mask, vector_allocation_cpumask(cpu),
                    &cpu_online_map);

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

        if (irq_used_vectors
            && test_bit(vector, irq_used_vectors) )
            goto next;

        for_each_cpu(new_cpu, &tmp_mask)
            if (per_cpu(vector_irq, new_cpu)[vector] >= 0)
                goto next;
        /* Found one! */
        current_vector = vector;
        current_offset = offset;
        if (old_vector > 0) {
            desc->arch.move_in_progress = 1;
            cpumask_copy(desc->arch.old_cpu_mask, desc->arch.cpu_mask);
            desc->arch.old_vector = desc->arch.vector;
        }
        trace_irq_mask(TRC_HW_IRQ_ASSIGN_VECTOR, irq, vector, &tmp_mask);
        for_each_cpu(new_cpu, &tmp_mask)
            per_cpu(vector_irq, new_cpu)[vector] = irq;
        desc->arch.vector = vector;
        cpumask_copy(desc->arch.cpu_mask, &tmp_mask);

        desc->arch.used = IRQ_USED;
        ASSERT((desc->arch.used_vectors == NULL)
               || (desc->arch.used_vectors == irq_used_vectors));
        desc->arch.used_vectors = irq_used_vectors;

        if ( desc->arch.used_vectors )
        {
            ASSERT(!test_bit(vector, desc->arch.used_vectors));

            set_bit(vector, desc->arch.used_vectors);
        }

        err = 0;
        break;
    }
    return err;
}

int assign_irq_vector(int irq, const cpumask_t *mask)
{
    int ret;
    unsigned long flags;
    struct irq_desc *desc = irq_to_desc(irq);
    
    BUG_ON(irq >= nr_irqs || irq <0);

    spin_lock_irqsave(&vector_lock, flags);
    ret = __assign_irq_vector(irq, desc, mask ?: TARGET_CPUS);
    if (!ret) {
        ret = desc->arch.vector;
        cpumask_copy(desc->affinity, desc->arch.cpu_mask);
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

    /* Clear vector_irq */
    for (vector = 0; vector < NR_VECTORS; ++vector)
        per_cpu(vector_irq, cpu)[vector] = INT_MIN;
    /* Mark the inuse vectors */
    for (irq = 0; irq < nr_irqs; ++irq) {
        struct irq_desc *desc = irq_to_desc(irq);

        if (!irq_desc_initialized(desc) ||
            !cpumask_test_cpu(cpu, desc->arch.cpu_mask))
            continue;
        vector = irq_to_vector(irq);
        per_cpu(vector_irq, cpu)[vector] = irq;
    }
}

void move_masked_irq(struct irq_desc *desc)
{
    cpumask_t *pending_mask = desc->arch.pending_mask;

    if (likely(!(desc->status & IRQ_MOVE_PENDING)))
        return;
    
    desc->status &= ~IRQ_MOVE_PENDING;

    if (unlikely(cpumask_empty(pending_mask)))
        return;

    if (!desc->handler->set_affinity)
        return;

    /*
     * If there was a valid mask to work with, please do the disable, 
     * re-program, enable sequence. This is *not* particularly important for 
     * level triggered but in a edge trigger case, we might be setting rte when 
     * an active trigger is comming in. This could cause some ioapics to 
     * mal-function. Being paranoid i guess!
     *
     * For correct operation this depends on the caller masking the irqs.
     */
    if ( likely(cpumask_intersects(pending_mask, &cpu_online_map)) )
        desc->handler->set_affinity(desc, pending_mask);

    cpumask_clear(pending_mask);
}

void move_native_irq(struct irq_desc *desc)
{
    if (likely(!(desc->status & IRQ_MOVE_PENDING)))
        return;

    if (unlikely(desc->status & IRQ_DISABLED))
        return;

    desc->handler->disable(desc);
    move_masked_irq(desc);
    desc->handler->enable(desc);
}

void irq_move_cleanup_interrupt(struct cpu_user_regs *regs)
{
    unsigned vector, me;

    ack_APIC_irq();

    me = smp_processor_id();
    for ( vector = FIRST_DYNAMIC_VECTOR;
          vector <= LAST_HIPRIORITY_VECTOR; vector++)
    {
        unsigned int irq;
        unsigned int irr;
        struct irq_desc *desc;
        irq = __get_cpu_var(vector_irq)[vector];

        if ((int)irq < 0)
            continue;

        if ( vector >= FIRST_LEGACY_VECTOR && vector <= LAST_LEGACY_VECTOR )
            continue;

        desc = irq_to_desc(irq);
        if (!desc)
            continue;

        spin_lock(&desc->lock);
        if (!desc->arch.move_cleanup_count)
            goto unlock;

        if ( vector == desc->arch.vector &&
             cpumask_test_cpu(me, desc->arch.cpu_mask) )
            goto unlock;

        irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
        /*
         * Check if the vector that needs to be cleanedup is
         * registered at the cpu's IRR. If so, then this is not
         * the best time to clean it up. Lets clean it up in the
         * next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
         * to myself.
         */
        if (irr  & (1 << (vector % 32))) {
            send_IPI_self(IRQ_MOVE_CLEANUP_VECTOR);
            TRACE_3D(TRC_HW_IRQ_MOVE_CLEANUP_DELAY,
                     irq, vector, smp_processor_id());
            goto unlock;
        }

        TRACE_3D(TRC_HW_IRQ_MOVE_CLEANUP,
                 irq, vector, smp_processor_id());

        __get_cpu_var(vector_irq)[vector] = ~irq;
        desc->arch.move_cleanup_count--;

        if ( desc->arch.move_cleanup_count == 0 )
        {
            desc->arch.old_vector = IRQ_VECTOR_UNASSIGNED;
            cpumask_clear(desc->arch.old_cpu_mask);

            if ( desc->arch.used_vectors )
            {
                ASSERT(test_bit(vector, desc->arch.used_vectors));
                clear_bit(vector, desc->arch.used_vectors);
            }
        }
unlock:
        spin_unlock(&desc->lock);
    }
}

static void send_cleanup_vector(struct irq_desc *desc)
{
    cpumask_t cleanup_mask;

    cpumask_and(&cleanup_mask, desc->arch.old_cpu_mask, &cpu_online_map);
    desc->arch.move_cleanup_count = cpumask_weight(&cleanup_mask);
    send_IPI_mask(&cleanup_mask, IRQ_MOVE_CLEANUP_VECTOR);

    desc->arch.move_in_progress = 0;
}

void irq_complete_move(struct irq_desc *desc)
{
    unsigned vector, me;

    if (likely(!desc->arch.move_in_progress))
        return;

    vector = (u8)get_irq_regs()->entry_vector;
    me = smp_processor_id();

    if ( vector == desc->arch.vector &&
         cpumask_test_cpu(me, desc->arch.cpu_mask) )
        send_cleanup_vector(desc);
}

unsigned int set_desc_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    unsigned int irq;
    int ret;
    unsigned long flags;
    cpumask_t dest_mask;

    if (!cpumask_intersects(mask, &cpu_online_map))
        return BAD_APICID;

    irq = desc->irq;

    spin_lock_irqsave(&vector_lock, flags);
    ret = __assign_irq_vector(irq, desc, mask);
    spin_unlock_irqrestore(&vector_lock, flags);

    if (ret < 0)
        return BAD_APICID;

    cpumask_copy(desc->affinity, mask);
    cpumask_and(&dest_mask, mask, desc->arch.cpu_mask);

    return cpu_mask_to_apicid(&dest_mask);
}

/* For re-setting irq interrupt affinity for specific irq */
void irq_set_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    if (!desc->handler->set_affinity)
        return;
    
    ASSERT(spin_is_locked(&desc->lock));
    desc->status &= ~IRQ_MOVE_PENDING;
    wmb();
    cpumask_copy(desc->arch.pending_mask, mask);
    wmb();
    desc->status |= IRQ_MOVE_PENDING;
}

void pirq_set_affinity(struct domain *d, int pirq, const cpumask_t *mask)
{
    unsigned long flags;
    struct irq_desc *desc = domain_spin_lock_irq_desc(d, pirq, &flags);

    if ( !desc )
        return;
    irq_set_affinity(desc, mask);
    spin_unlock_irqrestore(&desc->lock, flags);
}

DEFINE_PER_CPU(unsigned int, irq_count);

uint8_t alloc_hipriority_vector(void)
{
    static uint8_t next = FIRST_HIPRIORITY_VECTOR;
    BUG_ON(next < FIRST_HIPRIORITY_VECTOR);
    BUG_ON(next > LAST_HIPRIORITY_VECTOR);
    return next++;
}

static void (*direct_apic_vector[NR_VECTORS])(struct cpu_user_regs *);
void set_direct_apic_vector(
    uint8_t vector, void (*handler)(struct cpu_user_regs *))
{
    BUG_ON(direct_apic_vector[vector] != NULL);
    direct_apic_vector[vector] = handler;
}

void alloc_direct_apic_vector(
    uint8_t *vector, void (*handler)(struct cpu_user_regs *))
{
    static DEFINE_SPINLOCK(lock);

    spin_lock(&lock);
    if (*vector == 0) {
        *vector = alloc_hipriority_vector();
        set_direct_apic_vector(*vector, handler);
    }
    spin_unlock(&lock);
}

void do_IRQ(struct cpu_user_regs *regs)
{
    struct irqaction *action;
    uint32_t          tsc_in;
    struct irq_desc  *desc;
    unsigned int      vector = (u8)regs->entry_vector;
    int irq = __get_cpu_var(vector_irq[vector]);
    struct cpu_user_regs *old_regs = set_irq_regs(regs);
    
    perfc_incr(irqs);
    this_cpu(irq_count)++;
    irq_enter();

    if (irq < 0) {
        if (direct_apic_vector[vector] != NULL) {
            (*direct_apic_vector[vector])(regs);
        } else {
            const char *kind = ", LAPIC";

            if ( apic_isr_read(vector) )
                ack_APIC_irq();
            else
                kind = "";
            if ( ! ( vector >= FIRST_LEGACY_VECTOR &&
                     vector <= LAST_LEGACY_VECTOR &&
                     bogus_8259A_irq(vector - FIRST_LEGACY_VECTOR) ) )
            {
                printk("CPU%u: No irq handler for vector %02x (IRQ %d%s)\n",
                       smp_processor_id(), vector, irq, kind);
                desc = irq_to_desc(~irq);
                if ( ~irq < nr_irqs && irq_desc_initialized(desc) )
                {
                    spin_lock(&desc->lock);
                    printk("IRQ%d a=%04lx[%04lx,%04lx] v=%02x[%02x] t=%s s=%08x\n",
                           ~irq, *cpumask_bits(desc->affinity),
                           *cpumask_bits(desc->arch.cpu_mask),
                           *cpumask_bits(desc->arch.old_cpu_mask),
                           desc->arch.vector, desc->arch.old_vector,
                           desc->handler->typename, desc->status);
                    spin_unlock(&desc->lock);
                }
            }
            TRACE_1D(TRC_HW_IRQ_UNMAPPED_VECTOR, vector);
        }
        goto out_no_unlock;
    }

    desc = irq_to_desc(irq);

    spin_lock(&desc->lock);
    desc->handler->ack(desc);

    if ( likely(desc->status & IRQ_GUEST) )
    {
        if ( irq_ratelimit_timer.function && /* irq rate limiting enabled? */
             unlikely(desc->rl_cnt++ >= irq_ratelimit_threshold) )
        {
            s_time_t now = NOW();
            if ( now < (desc->rl_quantum_start + MILLISECS(10)) )
            {
                desc->handler->disable(desc);
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

        tsc_in = tb_init_done ? get_cycles() : 0;
        __do_IRQ_guest(irq);
        TRACE_3D(TRC_HW_IRQ_HANDLED, irq, tsc_in, get_cycles());
        goto out_no_end;
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
        spin_unlock_irq(&desc->lock);
        tsc_in = tb_init_done ? get_cycles() : 0;
        action->handler(irq, action->dev_id, regs);
        TRACE_3D(TRC_HW_IRQ_HANDLED, irq, tsc_in, get_cycles());
        spin_lock_irq(&desc->lock);
    }

    desc->status &= ~IRQ_INPROGRESS;

 out:
    if ( desc->handler->end )
        desc->handler->end(desc, vector);
 out_no_end:
    spin_unlock(&desc->lock);
 out_no_unlock:
    irq_exit();
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
        desc->handler->enable(desc);
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

int __init request_irq(unsigned int irq, unsigned int irqflags,
        void (*handler)(int, void *, struct cpu_user_regs *),
        const char * devname, void *dev_id)
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

    retval = setup_irq(irq, irqflags, action);
    if (retval)
        xfree(action);

    return retval;
}

void __init release_irq(unsigned int irq, const void *dev_id)
{
    struct irq_desc *desc;
    unsigned long flags;
    struct irqaction *action;

    desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock,flags);
    action = desc->action;
    desc->action  = NULL;
    desc->handler->shutdown(desc);
    desc->status |= IRQ_DISABLED;
    spin_unlock_irqrestore(&desc->lock,flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );

    if (action && action->free_on_release)
        xfree(action);
}

int __init setup_irq(unsigned int irq, unsigned int irqflags,
                     struct irqaction *new)
{
    struct irq_desc *desc;
    unsigned long flags;

    ASSERT(irqflags == 0);

    desc = irq_to_desc(irq);
 
    spin_lock_irqsave(&desc->lock,flags);

    if ( desc->action != NULL )
    {
        spin_unlock_irqrestore(&desc->lock,flags);
        return -EBUSY;
    }

    desc->action  = new;
    desc->status &= ~IRQ_DISABLED;
    desc->handler->startup(desc);

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
    cpumask_var_t cpu_eoi_map; /* CPUs that need to EOI this interrupt */
    struct timer eoi_timer;
    struct domain *guest[IRQ_MAX_GUESTS];
} irq_guest_action_t;

/*
 * Stack of interrupts awaiting EOI on each CPU. These must be popped in
 * order, as only the current highest-priority pending irq can be EOIed.
 */
struct pending_eoi {
    u32 ready:1;  /* Ready for EOI now?  */
    u32 irq:23;   /* irq of the vector */
    u32 vector:8; /* vector awaiting EOI */
};

static DEFINE_PER_CPU(struct pending_eoi, pending_eoi[NR_DYNAMIC_VECTORS]);
#define pending_eoi_sp(p) ((p)[NR_DYNAMIC_VECTORS-1].vector)

bool_t cpu_has_pending_apic_eoi(void)
{
    return (pending_eoi_sp(this_cpu(pending_eoi)) != 0);
}

static inline void set_pirq_eoi(struct domain *d, unsigned int irq)
{
    if ( d->arch.pirq_eoi_map )
    {
        ASSERT(irq < PAGE_SIZE * BITS_PER_BYTE);
        set_bit(irq, d->arch.pirq_eoi_map);
    }
}

static inline void clear_pirq_eoi(struct domain *d, unsigned int irq)
{
    if ( d->arch.pirq_eoi_map )
    {
        ASSERT(irq < PAGE_SIZE * BITS_PER_BYTE);
        clear_bit(irq, d->arch.pirq_eoi_map);
    }
}

static void set_eoi_ready(void *data);

static void irq_guest_eoi_timer_fn(void *data)
{
    struct irq_desc *desc = data;
    unsigned int irq = desc - irq_desc;
    irq_guest_action_t *action;
    cpumask_t cpu_eoi_map;
    unsigned long flags;

    spin_lock_irqsave(&desc->lock, flags);
    
    if ( !(desc->status & IRQ_GUEST) )
        goto out;

    action = (irq_guest_action_t *)desc->action;

    if ( action->ack_type != ACKTYPE_NONE )
    {
        unsigned int i;
        for ( i = 0; i < action->nr_guests; i++ )
        {
            struct domain *d = action->guest[i];
            unsigned int pirq = domain_irq_to_pirq(d, irq);
            if ( test_and_clear_bool(pirq_info(d, pirq)->masked) )
                action->in_flight--;
        }
    }

    if ( action->in_flight != 0 )
        goto out;

    switch ( action->ack_type )
    {
    case ACKTYPE_UNMASK:
        if ( desc->handler->end )
            desc->handler->end(desc, 0);
        break;
    case ACKTYPE_EOI:
        cpumask_copy(&cpu_eoi_map, action->cpu_eoi_map);
        spin_unlock_irq(&desc->lock);
        on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 0);
        spin_lock_irq(&desc->lock);
        break;
    }

 out:
    spin_unlock_irqrestore(&desc->lock, flags);
}

static void __do_IRQ_guest(int irq)
{
    struct irq_desc         *desc = irq_to_desc(irq);
    irq_guest_action_t *action = (irq_guest_action_t *)desc->action;
    struct domain      *d;
    int                 i, sp;
    struct pending_eoi *peoi = this_cpu(pending_eoi);
    unsigned int        vector = (u8)get_irq_regs()->entry_vector;

    if ( unlikely(action->nr_guests == 0) )
    {
        /* An interrupt may slip through while freeing an ACKTYPE_EOI irq. */
        ASSERT(action->ack_type == ACKTYPE_EOI);
        ASSERT(desc->status & IRQ_DISABLED);
        if ( desc->handler->end )
            desc->handler->end(desc, vector);
        return;
    }

    if ( action->ack_type == ACKTYPE_EOI )
    {
        sp = pending_eoi_sp(peoi);
        ASSERT((sp == 0) || (peoi[sp-1].vector < vector));
        ASSERT(sp < (NR_DYNAMIC_VECTORS-1));
        peoi[sp].irq = irq;
        peoi[sp].vector = vector;
        peoi[sp].ready = 0;
        pending_eoi_sp(peoi) = sp+1;
        cpumask_set_cpu(smp_processor_id(), action->cpu_eoi_map);
    }

    for ( i = 0; i < action->nr_guests; i++ )
    {
        struct pirq *pirq;

        d = action->guest[i];
        pirq = pirq_info(d, domain_irq_to_pirq(d, irq));
        if ( (action->ack_type != ACKTYPE_NONE) &&
             !test_and_set_bool(pirq->masked) )
            action->in_flight++;
        if ( !hvm_do_IRQ_dpci(d, pirq) )
            send_guest_pirq(d, pirq);
    }

    if ( action->ack_type != ACKTYPE_NONE )
    {
        stop_timer(&action->eoi_timer);
        migrate_timer(&action->eoi_timer, smp_processor_id());
        set_timer(&action->eoi_timer, NOW() + MILLISECS(1));
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
    const struct pirq *info = pirq_info(d, pirq);

    return info ? pirq_spin_lock_irq_desc(info, pflags) : NULL;
}

/*
 * Same with struct pirq already looked up.
 */
struct irq_desc *pirq_spin_lock_irq_desc(
    const struct pirq *pirq, unsigned long *pflags)
{
    struct irq_desc *desc;
    unsigned long flags;

    for ( ; ; )
    {
        int irq = pirq->arch.irq;

        if ( irq <= 0 )
            return NULL;

        desc = irq_to_desc(irq);
        spin_lock_irqsave(&desc->lock, flags);
        if ( irq == pirq->arch.irq )
            break;
        spin_unlock_irqrestore(&desc->lock, flags);
    }

    if ( pflags )
        *pflags = flags;

    return desc;
}

static int prepare_domain_irq_pirq(struct domain *d, int irq, int pirq,
                                struct pirq **pinfo)
{
    int err = radix_tree_insert(&d->arch.irq_pirq, irq,
                                radix_tree_int_to_ptr(0));
    struct pirq *info;

    if ( err && err != -EEXIST )
        return err;
    info = pirq_get_info(d, pirq);
    if ( !info )
    {
        if ( !err )
            radix_tree_delete(&d->arch.irq_pirq, irq);
        return -ENOMEM;
    }
    *pinfo = info;
    return 0;
}

static void set_domain_irq_pirq(struct domain *d, int irq, struct pirq *pirq)
{
    radix_tree_replace_slot(
        radix_tree_lookup_slot(&d->arch.irq_pirq, irq),
        radix_tree_int_to_ptr(pirq->pirq));
    pirq->arch.irq = irq;
}

static void clear_domain_irq_pirq(struct domain *d, int irq, struct pirq *pirq)
{
    pirq->arch.irq = 0;
    radix_tree_replace_slot(
        radix_tree_lookup_slot(&d->arch.irq_pirq, irq),
        radix_tree_int_to_ptr(0));
}

static void cleanup_domain_irq_pirq(struct domain *d, int irq,
                                    struct pirq *pirq)
{
    pirq_cleanup_check(pirq, d);
    radix_tree_delete(&d->arch.irq_pirq, irq);
}

int init_domain_irq_mapping(struct domain *d)
{
    unsigned int i;
    int err = 0;

    radix_tree_init(&d->arch.irq_pirq);
    if ( is_hvm_domain(d) )
        radix_tree_init(&d->arch.hvm_domain.emuirq_pirq);

    for ( i = 1; platform_legacy_irq(i); ++i )
    {
        struct pirq *info;

        if ( IO_APIC_IRQ(i) )
            continue;
        err = prepare_domain_irq_pirq(d, i, i, &info);
        if ( err )
            break;
        set_domain_irq_pirq(d, i, info);
    }

    if ( err )
        cleanup_domain_irq_mapping(d);
    return err;
}

void cleanup_domain_irq_mapping(struct domain *d)
{
    radix_tree_destroy(&d->arch.irq_pirq, NULL);
    if ( is_hvm_domain(d) )
        radix_tree_destroy(&d->arch.hvm_domain.emuirq_pirq, NULL);
}

struct pirq *alloc_pirq_struct(struct domain *d)
{
    size_t sz = is_hvm_domain(d) ? sizeof(struct pirq) :
                                   offsetof(struct pirq, arch.hvm);
    struct pirq *pirq = xzalloc_bytes(sz);

    if ( pirq )
    {
        if ( is_hvm_domain(d) )
        {
            pirq->arch.hvm.emuirq = IRQ_UNBOUND;
            pt_pirq_init(d, &pirq->arch.hvm.dpci);
        }
    }

    return pirq;
}

void (pirq_cleanup_check)(struct pirq *pirq, struct domain *d)
{
    /*
     * Check whether all fields have their default values, and delete
     * the entry from the tree if so.
     *
     * NB: Common parts were already checked.
     */
    if ( pirq->arch.irq )
        return;

    if ( is_hvm_domain(d) )
    {
        if ( pirq->arch.hvm.emuirq != IRQ_UNBOUND )
            return;
        if ( !pt_pirq_cleanup_check(&pirq->arch.hvm.dpci) )
            return;
    }

    if ( radix_tree_delete(&d->pirq_tree, pirq->pirq) != pirq )
        BUG();
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
        irq = peoi[sp].irq;
        ASSERT(irq > 0);
        desc = irq_to_desc(irq);
        spin_lock(&desc->lock);
        if ( desc->handler->end )
            desc->handler->end(desc, peoi[sp].vector);
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
         !cpumask_test_and_clear_cpu(smp_processor_id(),
                                     action->cpu_eoi_map) )
        return;

    sp = pending_eoi_sp(peoi);

    do {
        ASSERT(sp > 0);
    } while ( peoi[--sp].irq != irq );
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

void pirq_guest_eoi(struct pirq *pirq)
{
    struct irq_desc *desc;

    ASSERT(local_irq_is_enabled());
    desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( desc )
        desc_guest_eoi(desc, pirq);
}

void desc_guest_eoi(struct irq_desc *desc, struct pirq *pirq)
{
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;
    int                 irq;

    if ( !(desc->status & IRQ_GUEST) )
    {
        spin_unlock_irq(&desc->lock);
        return;
    }

    action = (irq_guest_action_t *)desc->action;
    irq = desc - irq_desc;

    if ( unlikely(!test_and_clear_bool(pirq->masked)) ||
         unlikely(--action->in_flight != 0) )
    {
        spin_unlock_irq(&desc->lock);
        return;
    }

    if ( action->ack_type == ACKTYPE_UNMASK )
    {
        ASSERT(cpumask_empty(action->cpu_eoi_map));
        if ( desc->handler->end )
            desc->handler->end(desc, 0);
        spin_unlock_irq(&desc->lock);
        return;
    }

    ASSERT(action->ack_type == ACKTYPE_EOI);
        
    cpumask_copy(&cpu_eoi_map, action->cpu_eoi_map);

    if ( __cpumask_test_and_clear_cpu(smp_processor_id(), &cpu_eoi_map) )
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

    if ( !cpumask_empty(&cpu_eoi_map) )
        on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 0);
}

int pirq_guest_unmask(struct domain *d)
{
    unsigned int pirq = 0, n, i;
    struct pirq *pirqs[16];

    do {
        n = radix_tree_gang_lookup(&d->pirq_tree, (void **)pirqs, pirq,
                                   ARRAY_SIZE(pirqs));
        for ( i = 0; i < n; ++i )
        {
            pirq = pirqs[i]->pirq;
            if ( pirqs[i]->masked &&
                 !evtchn_port_is_masked(d, evtchn_from_port(d, pirqs[i]->evtchn)) )
                pirq_guest_eoi(pirqs[i]);
        }
    } while ( ++pirq < d->nr_pirqs && n == ARRAY_SIZE(pirqs) );

    return 0;
}

static int pirq_acktype(struct domain *d, int pirq)
{
    struct irq_desc  *desc;
    int irq;

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
    if ( desc->msi_desc )
        return msi_maskable_irq(desc->msi_desc) ? ACKTYPE_NONE : ACKTYPE_EOI;

    /*
     * Level-triggered IO-APIC interrupts need to be acknowledged on the CPU
     * on which they were received. This is because we tickle the LAPIC to EOI.
     */
    if ( !strcmp(desc->handler->typename, "IO-APIC-level") )
        return desc->handler->ack == irq_complete_move ?
               ACKTYPE_EOI : ACKTYPE_UNMASK;

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

int pirq_guest_bind(struct vcpu *v, struct pirq *pirq, int will_share)
{
    unsigned int        irq;
    struct irq_desc         *desc;
    irq_guest_action_t *action, *newaction = NULL;
    int                 rc = 0;

    WARN_ON(!spin_is_locked(&v->domain->event_lock));
    BUG_ON(!local_irq_is_enabled());

 retry:
    desc = pirq_spin_lock_irq_desc(pirq, NULL);
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
            printk(XENLOG_G_INFO
                   "Cannot bind IRQ%d to dom%d. In use by '%s'.\n",
                   pirq->pirq, v->domain->domain_id, desc->action->name);
            rc = -EBUSY;
            goto unlock_out;
        }

        if ( newaction == NULL )
        {
            spin_unlock_irq(&desc->lock);
            if ( (newaction = xmalloc(irq_guest_action_t)) != NULL &&
                 zalloc_cpumask_var(&newaction->cpu_eoi_map) )
                goto retry;
            xfree(newaction);
            printk(XENLOG_G_INFO
                   "Cannot bind IRQ%d to dom%d. Out of memory.\n",
                   pirq->pirq, v->domain->domain_id);
            return -ENOMEM;
        }

        action = newaction;
        desc->action = (struct irqaction *)action;
        newaction = NULL;

        action->nr_guests   = 0;
        action->in_flight   = 0;
        action->shareable   = will_share;
        action->ack_type    = pirq_acktype(v->domain, pirq->pirq);
        init_timer(&action->eoi_timer, irq_guest_eoi_timer_fn, desc, 0);

        desc->status |= IRQ_GUEST;

        /* Attempt to bind the interrupt target to the correct CPU. */
        if ( !opt_noirqbalance && (desc->handler->set_affinity != NULL) )
            desc->handler->set_affinity(desc, cpumask_of(v->processor));

        desc->status &= ~IRQ_DISABLED;
        desc->handler->startup(desc);
    }
    else if ( !will_share || !action->shareable )
    {
        printk(XENLOG_G_INFO "Cannot bind IRQ%d to dom%d. %s.\n",
               pirq->pirq, v->domain->domain_id,
               will_share ? "Others do not share"
                          : "Will not share with others");
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
        printk(XENLOG_G_INFO "Cannot bind IRQ%d to dom%d. "
               "Already at max share.\n",
               pirq->pirq, v->domain->domain_id);
        rc = -EBUSY;
        goto unlock_out;
    }

    action->guest[action->nr_guests++] = v->domain;

    if ( action->ack_type != ACKTYPE_NONE )
        set_pirq_eoi(v->domain, pirq->pirq);
    else
        clear_pirq_eoi(v->domain, pirq->pirq);

 unlock_out:
    spin_unlock_irq(&desc->lock);
 out:
    if ( newaction != NULL )
    {
        free_cpumask_var(newaction->cpu_eoi_map);
        xfree(newaction);
    }
    return rc;
}

static irq_guest_action_t *__pirq_guest_unbind(
    struct domain *d, struct pirq *pirq, struct irq_desc *desc)
{
    unsigned int        irq;
    irq_guest_action_t *action;
    cpumask_t           cpu_eoi_map;
    int                 i;

    action = (irq_guest_action_t *)desc->action;
    irq = desc - irq_desc;

    if ( unlikely(action == NULL) )
    {
        dprintk(XENLOG_G_WARNING, "dom%d: pirq %d: desc->action is NULL!\n",
                d->domain_id, pirq->pirq);
        return NULL;
    }

    BUG_ON(!(desc->status & IRQ_GUEST));

    for ( i = 0; (i < action->nr_guests) && (action->guest[i] != d); i++ )
        continue;
    BUG_ON(i == action->nr_guests);
    memmove(&action->guest[i], &action->guest[i+1],
            (action->nr_guests-i-1) * sizeof(action->guest[0]));
    action->nr_guests--;

    switch ( action->ack_type )
    {
    case ACKTYPE_UNMASK:
        if ( test_and_clear_bool(pirq->masked) &&
             (--action->in_flight == 0) &&
             desc->handler->end )
                desc->handler->end(desc, 0);
        break;
    case ACKTYPE_EOI:
        /* NB. If #guests == 0 then we clear the eoi_map later on. */
        if ( test_and_clear_bool(pirq->masked) &&
             (--action->in_flight == 0) &&
             (action->nr_guests != 0) )
        {
            cpumask_copy(&cpu_eoi_map, action->cpu_eoi_map);
            spin_unlock_irq(&desc->lock);
            on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 0);
            spin_lock_irq(&desc->lock);
        }
        break;
    }

    /*
     * The guest cannot re-bind to this IRQ until this function returns. So,
     * when we have flushed this IRQ from ->masked, it should remain flushed.
     */
    BUG_ON(pirq->masked);

    if ( action->nr_guests != 0 )
        return NULL;

    BUG_ON(action->in_flight != 0);

    /* Disabling IRQ before releasing the desc_lock avoids an IRQ storm. */
    desc->handler->disable(desc);
    desc->status |= IRQ_DISABLED;

    /*
     * Mark any remaining pending EOIs as ready to flush.
     * NOTE: We will need to make this a stronger barrier if in future we allow
     * an interrupt vectors to be re-bound to a different PIC. In that case we
     * would need to flush all ready EOIs before returning as otherwise the
     * desc->handler could change and we would call the wrong 'end' hook.
     */
    cpumask_copy(&cpu_eoi_map, action->cpu_eoi_map);
    if ( !cpumask_empty(&cpu_eoi_map) )
    {
        BUG_ON(action->ack_type != ACKTYPE_EOI);
        spin_unlock_irq(&desc->lock);
        on_selected_cpus(&cpu_eoi_map, set_eoi_ready, desc, 1);
        spin_lock_irq(&desc->lock);
    }

    BUG_ON(!cpumask_empty(action->cpu_eoi_map));

    desc->action = NULL;
    desc->status &= ~(IRQ_GUEST|IRQ_INPROGRESS);
    desc->handler->shutdown(desc);

    /* Caller frees the old guest descriptor block. */
    return action;
}

void pirq_guest_unbind(struct domain *d, struct pirq *pirq)
{
    irq_guest_action_t *oldaction = NULL;
    struct irq_desc *desc;
    int irq = 0;

    WARN_ON(!spin_is_locked(&d->event_lock));

    BUG_ON(!local_irq_is_enabled());
    desc = pirq_spin_lock_irq_desc(pirq, NULL);

    if ( desc == NULL )
    {
        irq = -pirq->arch.irq;
        BUG_ON(irq <= 0);
        desc = irq_to_desc(irq);
        spin_lock_irq(&desc->lock);
        clear_domain_irq_pirq(d, irq, pirq);
    }
    else
    {
        oldaction = __pirq_guest_unbind(d, pirq, desc);
    }

    spin_unlock_irq(&desc->lock);

    if ( oldaction != NULL )
    {
        kill_timer(&oldaction->eoi_timer);
        free_cpumask_var(oldaction->cpu_eoi_map);
        xfree(oldaction);
    }
    else if ( irq > 0 )
        cleanup_domain_irq_pirq(d, irq, pirq);
}

static int pirq_guest_force_unbind(struct domain *d, struct pirq *pirq)
{
    struct irq_desc *desc;
    irq_guest_action_t *action, *oldaction = NULL;
    int i, bound = 0;

    WARN_ON(!spin_is_locked(&d->event_lock));

    BUG_ON(!local_irq_is_enabled());
    desc = pirq_spin_lock_irq_desc(pirq, NULL);
    BUG_ON(desc == NULL);

    if ( !(desc->status & IRQ_GUEST) )
        goto out;

    action = (irq_guest_action_t *)desc->action;
    if ( unlikely(action == NULL) )
    {
        dprintk(XENLOG_G_WARNING, "dom%d: pirq %d: desc->action is NULL!\n",
            d->domain_id, pirq->pirq);
        goto out;
    }

    for ( i = 0; (i < action->nr_guests) && (action->guest[i] != d); i++ )
        continue;
    if ( i == action->nr_guests )
        goto out;

    bound = 1;
    oldaction = __pirq_guest_unbind(d, pirq, desc);

 out:
    spin_unlock_irq(&desc->lock);

    if ( oldaction != NULL )
    {
        kill_timer(&oldaction->eoi_timer);
        free_cpumask_var(oldaction->cpu_eoi_map);
        xfree(oldaction);
    }

    return bound;
}

static inline bool_t is_free_pirq(const struct domain *d,
                                  const struct pirq *pirq)
{
    return !pirq || (!pirq->arch.irq && (!is_hvm_domain(d) ||
        pirq->arch.hvm.emuirq == IRQ_UNBOUND));
}

int get_free_pirq(struct domain *d, int type)
{
    int i;

    ASSERT(spin_is_locked(&d->event_lock));

    if ( type == MAP_PIRQ_TYPE_GSI )
    {
        for ( i = 16; i < nr_irqs_gsi; i++ )
            if ( is_free_pirq(d, pirq_info(d, i)) )
            {
                pirq_get_info(d, i);
                return i;
            }
    }
    for ( i = d->nr_pirqs - 1; i >= nr_irqs_gsi; i-- )
        if ( is_free_pirq(d, pirq_info(d, i)) )
        {
            pirq_get_info(d, i);
            return i;
        }

    return -ENOSPC;
}

int get_free_pirqs(struct domain *d, unsigned int nr)
{
    unsigned int i, found = 0;

    ASSERT(spin_is_locked(&d->event_lock));

    for ( i = d->nr_pirqs - 1; i >= nr_irqs_gsi; --i )
        if ( is_free_pirq(d, pirq_info(d, i)) )
        {
            pirq_get_info(d, i);
            if ( ++found == nr )
                return i;
        }
        else
            found = 0;

    return -ENOSPC;
}

int map_domain_pirq(
    struct domain *d, int pirq, int irq, int type, void *data)
{
    int ret = 0;
    int old_irq, old_pirq;
    struct pirq *info;
    struct irq_desc *desc;
    unsigned long flags;

    ASSERT(spin_is_locked(&d->event_lock));

    if ( !irq_access_permitted(current->domain, irq))
        return -EPERM;

    if ( pirq < 0 || pirq >= d->nr_pirqs || irq <= 0 || irq >= nr_irqs )
    {
        dprintk(XENLOG_G_ERR, "dom%d: invalid pirq %d or irq %d\n",
                d->domain_id, pirq, irq);
        return -EINVAL;
    }

    old_irq = domain_pirq_to_irq(d, pirq);
    old_pirq = domain_irq_to_pirq(d, irq);

    if ( (old_irq > 0 && (old_irq != irq) ) ||
         (old_pirq && (old_pirq != pirq)) )
    {
        dprintk(XENLOG_G_WARNING,
                "dom%d: pirq %d or irq %d already mapped (%d,%d)\n",
                d->domain_id, pirq, irq, old_pirq, old_irq);
        return 0;
    }

    ret = xsm_map_domain_irq(XSM_HOOK, d, irq, data);
    if ( ret )
    {
        dprintk(XENLOG_G_ERR, "dom%d: could not permit access to irq %d mapping to pirq %d\n",
                d->domain_id, irq, pirq);
        return ret;
    }

    ret = irq_permit_access(d, irq);
    if ( ret )
    {
        printk(XENLOG_G_ERR
               "dom%d: could not permit access to IRQ%d (pirq %d)\n",
               d->domain_id, irq, pirq);
        return ret;
    }

    ret = prepare_domain_irq_pirq(d, irq, pirq, &info);
    if ( ret )
        goto revoke;

    desc = irq_to_desc(irq);

    if ( type == MAP_PIRQ_TYPE_MSI || type == MAP_PIRQ_TYPE_MULTI_MSI )
    {
        struct msi_info *msi = (struct msi_info *)data;
        struct msi_desc *msi_desc;
        struct pci_dev *pdev;
        unsigned int nr = 0;

        ASSERT(spin_is_locked(&pcidevs_lock));

        ret = -ENODEV;
        if ( !cpu_has_apic )
            goto done;

        pdev = pci_get_pdev(msi->seg, msi->bus, msi->devfn);
        ret = pci_enable_msi(msi, &msi_desc);
        if ( ret )
        {
            if ( ret > 0 )
            {
                msi->entry_nr = ret;
                ret = -ENFILE;
            }
            goto done;
        }

        spin_lock_irqsave(&desc->lock, flags);

        if ( desc->handler != &no_irq_type )
        {
            spin_unlock_irqrestore(&desc->lock, flags);
            dprintk(XENLOG_G_ERR, "dom%d: irq %d in use\n",
                    d->domain_id, irq);
            pci_disable_msi(msi_desc);
            msi_desc->irq = -1;
            msi_free_irq(msi_desc);
            ret = -EBUSY;
            goto done;
        }

        while ( !(ret = setup_msi_irq(desc, msi_desc + nr)) )
        {
            if ( opt_irq_vector_map == OPT_IRQ_VECTOR_MAP_PERDEV &&
                 !desc->arch.used_vectors )
            {
                desc->arch.used_vectors = &pdev->arch.used_vectors;
                if ( desc->arch.vector != IRQ_VECTOR_UNASSIGNED )
                {
                    int vector = desc->arch.vector;

                    ASSERT(!test_bit(vector, desc->arch.used_vectors));
                    set_bit(vector, desc->arch.used_vectors);
                }
            }
            if ( type == MAP_PIRQ_TYPE_MSI ||
                 msi_desc->msi_attrib.type != PCI_CAP_ID_MSI ||
                 ++nr == msi->entry_nr )
                break;

            set_domain_irq_pirq(d, irq, info);
            spin_unlock_irqrestore(&desc->lock, flags);

            info = NULL;
            irq = create_irq(NUMA_NO_NODE);
            ret = irq >= 0 ? prepare_domain_irq_pirq(d, irq, pirq + nr, &info)
                           : irq;
            if ( ret )
                break;
            msi_desc[nr].irq = irq;

            if ( irq_permit_access(d, irq) != 0 )
                printk(XENLOG_G_WARNING
                       "dom%d: could not permit access to IRQ%d (pirq %d)\n",
                       d->domain_id, irq, pirq);

            desc = irq_to_desc(irq);
            spin_lock_irqsave(&desc->lock, flags);

            if ( desc->handler != &no_irq_type )
            {
                dprintk(XENLOG_G_ERR, "dom%d: irq %d (pirq %u) in use (%s)\n",
                        d->domain_id, irq, pirq + nr, desc->handler->typename);
                ret = -EBUSY;
                break;
            }
        }

        if ( ret )
        {
            spin_unlock_irqrestore(&desc->lock, flags);
            pci_disable_msi(msi_desc);
            if ( nr )
            {
                ASSERT(msi_desc->irq >= 0);
                desc = irq_to_desc(msi_desc->irq);
                spin_lock_irqsave(&desc->lock, flags);
                desc->handler = &no_irq_type;
                desc->msi_desc = NULL;
                spin_unlock_irqrestore(&desc->lock, flags);
            }
            while ( nr-- )
            {
                if ( irq >= 0 && irq_deny_access(d, irq) )
                    printk(XENLOG_G_ERR
                           "dom%d: could not revoke access to IRQ%d (pirq %d)\n",
                           d->domain_id, irq, pirq);
                if ( info )
                    cleanup_domain_irq_pirq(d, irq, info);
                info = pirq_info(d, pirq + nr);
                irq = info->arch.irq;
            }
            msi_desc->irq = -1;
            msi_free_irq(msi_desc);
            goto done;
        }

        set_domain_irq_pirq(d, irq, info);
        spin_unlock_irqrestore(&desc->lock, flags);
    }
    else
    {
        spin_lock_irqsave(&desc->lock, flags);
        set_domain_irq_pirq(d, irq, info);
        spin_unlock_irqrestore(&desc->lock, flags);
    }

done:
    if ( ret )
    {
        cleanup_domain_irq_pirq(d, irq, info);
 revoke:
        if ( irq_deny_access(d, irq) )
            printk(XENLOG_G_ERR
                   "dom%d: could not revoke access to IRQ%d (pirq %d)\n",
                   d->domain_id, irq, pirq);
    }
    return ret;
}

/* The pirq should have been unbound before this call. */
int unmap_domain_pirq(struct domain *d, int pirq)
{
    unsigned long flags;
    struct irq_desc *desc;
    int irq, ret = 0, rc;
    unsigned int i, nr = 1;
    bool_t forced_unbind;
    struct pirq *info;
    struct msi_desc *msi_desc = NULL;

    if ( (pirq < 0) || (pirq >= d->nr_pirqs) )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));

    info = pirq_info(d, pirq);
    if ( !info || (irq = info->arch.irq) <= 0 )
    {
        dprintk(XENLOG_G_ERR, "dom%d: pirq %d not mapped\n",
                d->domain_id, pirq);
        ret = -EINVAL;
        goto done;
    }

    desc = irq_to_desc(irq);
    msi_desc = desc->msi_desc;
    if ( msi_desc && msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
    {
        if ( msi_desc->msi_attrib.entry_nr )
        {
            printk(XENLOG_G_ERR
                   "dom%d: trying to unmap secondary MSI pirq %d\n",
                   d->domain_id, pirq);
            ret = -EBUSY;
            goto done;
        }
        nr = msi_desc->msi.nvec;
    }

    ret = xsm_unmap_domain_irq(XSM_HOOK, d, irq, msi_desc);
    if ( ret )
        goto done;

    forced_unbind = pirq_guest_force_unbind(d, info);
    if ( forced_unbind )
        dprintk(XENLOG_G_WARNING, "dom%d: forcing unbind of pirq %d\n",
                d->domain_id, pirq);

    if ( msi_desc != NULL )
        pci_disable_msi(msi_desc);

    spin_lock_irqsave(&desc->lock, flags);

    for ( i = 0; ; )
    {
        BUG_ON(irq != domain_pirq_to_irq(d, pirq + i));

        if ( !forced_unbind )
            clear_domain_irq_pirq(d, irq, info);
        else
        {
            info->arch.irq = -irq;
            radix_tree_replace_slot(
                radix_tree_lookup_slot(&d->arch.irq_pirq, irq),
                radix_tree_int_to_ptr(-pirq));
        }

        if ( msi_desc )
        {
            desc->handler = &no_irq_type;
            desc->msi_desc = NULL;
        }

        if ( ++i == nr )
            break;

        spin_unlock_irqrestore(&desc->lock, flags);

        if ( !forced_unbind )
           cleanup_domain_irq_pirq(d, irq, info);

        rc = irq_deny_access(d, irq);
        if ( rc )
        {
            printk(XENLOG_G_ERR
                   "dom%d: could not deny access to IRQ%d (pirq %d)\n",
                   d->domain_id, irq, pirq + i);
            ret = rc;
        }

        do {
            info = pirq_info(d, pirq + i);
            if ( info && (irq = info->arch.irq) > 0 )
                break;
            printk(XENLOG_G_ERR "dom%d: MSI pirq %d not mapped\n",
                   d->domain_id, pirq + i);
        } while ( ++i < nr );

        if ( i == nr )
        {
            desc = NULL;
            break;
        }

        desc = irq_to_desc(irq);
        BUG_ON(desc->msi_desc != msi_desc + i);

        spin_lock_irqsave(&desc->lock, flags);
    }

    if ( desc )
    {
        spin_unlock_irqrestore(&desc->lock, flags);

        if ( !forced_unbind )
            cleanup_domain_irq_pirq(d, irq, info);

        rc = irq_deny_access(d, irq);
        if ( rc )
        {
            printk(XENLOG_G_ERR
                   "dom%d: could not deny access to IRQ%d (pirq %d)\n",
                   d->domain_id, irq, pirq + nr - 1);
            ret = rc;
        }
    }

    if (msi_desc)
        msi_free_irq(msi_desc);

 done:
    return ret;
}

void free_domain_pirqs(struct domain *d)
{
    int i;

    spin_lock(&pcidevs_lock);
    spin_lock(&d->event_lock);

    for ( i = 0; i < d->nr_pirqs; i++ )
        if ( domain_pirq_to_irq(d, i) > 0 )
            unmap_domain_pirq(d, i);

    spin_unlock(&d->event_lock);
    spin_unlock(&pcidevs_lock);
}

static void dump_irqs(unsigned char key)
{
    int i, irq, pirq;
    struct irq_desc *desc;
    irq_guest_action_t *action;
    struct evtchn *evtchn;
    struct domain *d;
    const struct pirq *info;
    unsigned long flags;
    char *ssid;

    printk("IRQ information:\n");

    for ( irq = 0; irq < nr_irqs; irq++ )
    {
        if ( !(irq & 0x1f) )
            process_pending_softirqs();

        desc = irq_to_desc(irq);

        if ( !irq_desc_initialized(desc) || desc->handler == &no_irq_type )
            continue;

        ssid = in_irq() ? NULL : xsm_show_irq_sid(irq);

        spin_lock_irqsave(&desc->lock, flags);

        cpumask_scnprintf(keyhandler_scratch, sizeof(keyhandler_scratch),
                          desc->affinity);
        printk("   IRQ:%4d affinity:%s vec:%02x type=%-15s"
               " status=%08x ",
               irq, keyhandler_scratch, desc->arch.vector,
               desc->handler->typename, desc->status);

        if ( ssid )
            printk("Z=%-25s ", ssid);

        if ( desc->status & IRQ_GUEST )
        {
            action = (irq_guest_action_t *)desc->action;

            printk("in-flight=%d domain-list=", action->in_flight);

            for ( i = 0; i < action->nr_guests; i++ )
            {
                d = action->guest[i];
                pirq = domain_irq_to_pirq(d, irq);
                info = pirq_info(d, pirq);
                evtchn = evtchn_from_port(d, info->evtchn);
                printk("%u:%3d(%c%c%c)",
                       d->domain_id, pirq,
                       (evtchn_port_is_pending(d, evtchn) ? 'P' : '-'),
                       (evtchn_port_is_masked(d, evtchn) ? 'M' : '-'),
                       (info->masked ? 'M' : '-'));
                if ( i != action->nr_guests )
                    printk(",");
            }

            printk("\n");
        }
        else if ( desc->action )
            printk("%ps()\n", desc->action->handler);
        else
            printk("mapped, unbound\n");

        spin_unlock_irqrestore(&desc->lock, flags);

        xfree(ssid);
    }

    process_pending_softirqs();
    printk("Direct vector information:\n");
    for ( i = FIRST_DYNAMIC_VECTOR; i < NR_VECTORS; ++i )
        if ( direct_apic_vector[i] )
            printk("   %#02x -> %ps()\n", i, direct_apic_vector[i]);

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
        if ( !irq_desc_initialized(desc) )
            continue;

        spin_lock(&desc->lock);

        cpumask_copy(&affinity, desc->affinity);
        if ( !desc->action || cpumask_subset(&affinity, &cpu_online_map) )
        {
            spin_unlock(&desc->lock);
            continue;
        }

        cpumask_and(&affinity, &affinity, &cpu_online_map);
        if ( cpumask_empty(&affinity) )
        {
            break_affinity = 1;
            cpumask_copy(&affinity, &cpu_online_map);
        }

        if ( desc->handler->disable )
            desc->handler->disable(desc);

        if ( desc->handler->set_affinity )
            desc->handler->set_affinity(desc, &affinity);
        else if ( !(warned++) )
            set_affinity = 0;

        if ( desc->handler->enable )
            desc->handler->enable(desc);

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
        cpumask_clear_cpu(smp_processor_id(), action->cpu_eoi_map);
    }

    /* Flush the interrupt EOI stack. */
    peoi = this_cpu(pending_eoi);
    for ( sp = 0; sp < pending_eoi_sp(peoi); sp++ )
        peoi[sp].ready = 1;
    flush_ready_eoi();
}

int map_domain_emuirq_pirq(struct domain *d, int pirq, int emuirq)
{
    int old_emuirq = IRQ_UNBOUND, old_pirq = IRQ_UNBOUND;
    struct pirq *info;

    ASSERT(spin_is_locked(&d->event_lock));

    if ( !is_hvm_domain(d) )
        return -EINVAL;

    if ( pirq < 0 || pirq >= d->nr_pirqs ||
            emuirq == IRQ_UNBOUND || emuirq >= (int) nr_irqs )
    {
        dprintk(XENLOG_G_ERR, "dom%d: invalid pirq %d or emuirq %d\n",
                d->domain_id, pirq, emuirq);
        return -EINVAL;
    }

    old_emuirq = domain_pirq_to_emuirq(d, pirq);
    if ( emuirq != IRQ_PT )
        old_pirq = domain_emuirq_to_pirq(d, emuirq);

    if ( (old_emuirq != IRQ_UNBOUND && (old_emuirq != emuirq) ) ||
         (old_pirq != IRQ_UNBOUND && (old_pirq != pirq)) )
    {
        dprintk(XENLOG_G_WARNING, "dom%d: pirq %d or emuirq %d already mapped\n",
                d->domain_id, pirq, emuirq);
        return 0;
    }

    info = pirq_get_info(d, pirq);
    if ( !info )
        return -ENOMEM;

    /* do not store emuirq mappings for pt devices */
    if ( emuirq != IRQ_PT )
    {
        int err = radix_tree_insert(&d->arch.hvm_domain.emuirq_pirq, emuirq,
                                    radix_tree_int_to_ptr(pirq));

        switch ( err )
        {
        case 0:
            break;
        case -EEXIST:
            radix_tree_replace_slot(
                radix_tree_lookup_slot(
                    &d->arch.hvm_domain.emuirq_pirq, emuirq),
                radix_tree_int_to_ptr(pirq));
            break;
        default:
            pirq_cleanup_check(info, d);
            return err;
        }
    }
    info->arch.hvm.emuirq = emuirq;

    return 0;
}

int unmap_domain_pirq_emuirq(struct domain *d, int pirq)
{
    int emuirq, ret = 0;
    struct pirq *info;

    if ( !is_hvm_domain(d) )
        return -EINVAL;

    if ( (pirq < 0) || (pirq >= d->nr_pirqs) )
        return -EINVAL;

    ASSERT(spin_is_locked(&d->event_lock));

    emuirq = domain_pirq_to_emuirq(d, pirq);
    if ( emuirq == IRQ_UNBOUND )
    {
        dprintk(XENLOG_G_ERR, "dom%d: pirq %d not mapped\n",
                d->domain_id, pirq);
        ret = -EINVAL;
        goto done;
    }

    info = pirq_info(d, pirq);
    if ( info )
    {
        info->arch.hvm.emuirq = IRQ_UNBOUND;
        pirq_cleanup_check(info, d);
    }
    if ( emuirq != IRQ_PT )
        radix_tree_delete(&d->arch.hvm_domain.emuirq_pirq, emuirq);

 done:
    return ret;
}

void arch_evtchn_bind_pirq(struct domain *d, int pirq)
{
    int irq = domain_pirq_to_irq(d, pirq);
    struct irq_desc *desc;
    unsigned long flags;

    if ( irq <= 0 )
        return;

    if ( is_hvm_domain(d) )
        map_domain_emuirq_pirq(d, pirq, IRQ_PT);

    desc = irq_to_desc(irq);
    spin_lock_irqsave(&desc->lock, flags);
    if ( desc->msi_desc )
        guest_mask_msi_irq(desc, 0);
    spin_unlock_irqrestore(&desc->lock, flags);
}

bool_t hvm_domain_use_pirq(const struct domain *d, const struct pirq *pirq)
{
    return is_hvm_domain(d) && pirq &&
           pirq->arch.hvm.emuirq != IRQ_UNBOUND; 
}
