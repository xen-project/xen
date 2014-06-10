/*
 * xen/arch/arm/gic.c
 *
 * ARM Generic Interrupt Controller support
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/list.h>
#include <xen/device_tree.h>
#include <asm/p2m.h>
#include <asm/domain.h>
#include <asm/platform.h>

#include <asm/gic.h>

/* Access to the GIC Distributor registers through the fixmap */
#define GICD ((volatile uint32_t *) FIXMAP_ADDR(FIXMAP_GICD))
#define GICC ((volatile uint32_t *) FIXMAP_ADDR(FIXMAP_GICC1))
#define GICH ((volatile uint32_t *) FIXMAP_ADDR(FIXMAP_GICH))
static void gic_restore_pending_irqs(struct vcpu *v);

/* Global state */
static struct {
    paddr_t dbase;       /* Address of distributor registers */
    paddr_t cbase;       /* Address of CPU interface registers */
    paddr_t hbase;       /* Address of virtual interface registers */
    paddr_t vbase;       /* Address of virtual cpu interface registers */
    unsigned int lines;  /* Number of interrupts (SPIs + PPIs + SGIs) */
    unsigned int maintenance_irq; /* IRQ maintenance */
    unsigned int cpus;
    spinlock_t lock;
} gic;

static DEFINE_PER_CPU(uint64_t, lr_mask);

static uint8_t nr_lrs;
#define lr_all_full() (this_cpu(lr_mask) == ((1 << nr_lrs) - 1))

/* The GIC mapping of CPU interfaces does not necessarily match the
 * logical CPU numbering. Let's use mapping as returned by the GIC
 * itself
 */
static DEFINE_PER_CPU(u8, gic_cpu_id);

/* Maximum cpu interface per GIC */
#define NR_GIC_CPU_IF 8

#undef GIC_DEBUG

static void gic_update_one_lr(struct vcpu *v, int i);

static unsigned int gic_cpu_mask(const cpumask_t *cpumask)
{
    unsigned int cpu;
    unsigned int mask = 0;
    cpumask_t possible_mask;

    cpumask_and(&possible_mask, cpumask, &cpu_possible_map);
    for_each_cpu(cpu, &possible_mask)
    {
        ASSERT(cpu < NR_GIC_CPU_IF);
        mask |= per_cpu(gic_cpu_id, cpu);
    }

    return mask;
}

unsigned int gic_number_lines(void)
{
    return gic.lines;
}

void gic_save_state(struct vcpu *v)
{
    int i;
    ASSERT(!local_irq_is_enabled());

    /* No need for spinlocks here because interrupts are disabled around
     * this call and it only accesses struct vcpu fields that cannot be
     * accessed simultaneously by another pCPU.
     */
    for ( i=0; i<nr_lrs; i++)
        v->arch.gic_lr[i] = GICH[GICH_LR + i];
    v->arch.lr_mask = this_cpu(lr_mask);
    v->arch.gic_apr = GICH[GICH_APR];
    v->arch.gic_vmcr = GICH[GICH_VMCR];
    /* Disable until next VCPU scheduled */
    GICH[GICH_HCR] = 0;
    isb();
}

void gic_restore_state(struct vcpu *v)
{
    int i;

    if ( is_idle_vcpu(v) )
        return;

    this_cpu(lr_mask) = v->arch.lr_mask;
    for ( i=0; i<nr_lrs; i++)
        GICH[GICH_LR + i] = v->arch.gic_lr[i];
    GICH[GICH_APR] = v->arch.gic_apr;
    GICH[GICH_VMCR] = v->arch.gic_vmcr;
    GICH[GICH_HCR] = GICH_HCR_EN;
    isb();

    gic_restore_pending_irqs(v);
}

static void gic_irq_enable(struct irq_desc *desc)
{
    int irq = desc->irq;
    unsigned long flags;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&gic.lock, flags);
    desc->status &= ~IRQ_DISABLED;
    dsb(sy);
    /* Enable routing */
    GICD[GICD_ISENABLER + irq / 32] = (1u << (irq % 32));
    spin_unlock_irqrestore(&gic.lock, flags);
}

static void gic_irq_disable(struct irq_desc *desc)
{
    int irq = desc->irq;
    unsigned long flags;

    ASSERT(spin_is_locked(&desc->lock));

    spin_lock_irqsave(&gic.lock, flags);
    /* Disable routing */
    GICD[GICD_ICENABLER + irq / 32] = (1u << (irq % 32));
    desc->status |= IRQ_DISABLED;
    spin_unlock_irqrestore(&gic.lock, flags);
}

static unsigned int gic_irq_startup(struct irq_desc *desc)
{
    gic_irq_enable(desc);

    return 0;
}

static void gic_irq_shutdown(struct irq_desc *desc)
{
    gic_irq_disable(desc);
}

static void gic_irq_ack(struct irq_desc *desc)
{
    /* No ACK -- reading IAR has done this for us */
}

static void gic_host_irq_end(struct irq_desc *desc)
{
    int irq = desc->irq;
    /* Lower the priority */
    GICC[GICC_EOIR] = irq;
    /* Deactivate */
    GICC[GICC_DIR] = irq;
}

static void gic_guest_irq_end(struct irq_desc *desc)
{
    int irq = desc->irq;
    /* Lower the priority of the IRQ */
    GICC[GICC_EOIR] = irq;
    /* Deactivation happens in maintenance interrupt / via GICV */
}

static void gic_irq_set_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    BUG();
}

/* XXX different for level vs edge */
static hw_irq_controller gic_host_irq_type = {
    .typename = "gic",
    .startup = gic_irq_startup,
    .shutdown = gic_irq_shutdown,
    .enable = gic_irq_enable,
    .disable = gic_irq_disable,
    .ack = gic_irq_ack,
    .end = gic_host_irq_end,
    .set_affinity = gic_irq_set_affinity,
};
static hw_irq_controller gic_guest_irq_type = {
    .typename = "gic",
    .startup = gic_irq_startup,
    .shutdown = gic_irq_shutdown,
    .enable = gic_irq_enable,
    .disable = gic_irq_disable,
    .ack = gic_irq_ack,
    .end = gic_guest_irq_end,
    .set_affinity = gic_irq_set_affinity,
};

/*
 * - needs to be called with a valid cpu_mask, ie each cpu in the mask has
 * already called gic_cpu_init
 * - desc.lock must be held
 * - arch.type must be valid (i.e != DT_IRQ_TYPE_INVALID)
 */
static void gic_set_irq_properties(struct irq_desc *desc,
                                   const cpumask_t *cpu_mask,
                                   unsigned int priority)
{
    volatile unsigned char *bytereg;
    uint32_t cfg, edgebit;
    unsigned int mask;
    unsigned int irq = desc->irq;
    unsigned int type = desc->arch.type;

    ASSERT(type != DT_IRQ_TYPE_INVALID);
    ASSERT(spin_is_locked(&desc->lock));

    spin_lock(&gic.lock);

    mask = gic_cpu_mask(cpu_mask);

    /* Set edge / level */
    cfg = GICD[GICD_ICFGR + irq / 16];
    edgebit = 2u << (2 * (irq % 16));
    if ( type & DT_IRQ_TYPE_LEVEL_MASK )
        cfg &= ~edgebit;
    else if ( type & DT_IRQ_TYPE_EDGE_BOTH )
        cfg |= edgebit;
    GICD[GICD_ICFGR + irq / 16] = cfg;

    /* Set target CPU mask (RAZ/WI on uniprocessor) */
    bytereg = (unsigned char *) (GICD + GICD_ITARGETSR);
    bytereg[irq] = mask;

    /* Set priority */
    bytereg = (unsigned char *) (GICD + GICD_IPRIORITYR);
    bytereg[irq] = priority;

    spin_unlock(&gic.lock);
}

/* Program the GIC to route an interrupt to the host (i.e. Xen)
 * - needs to be called with desc.lock held
 */
void gic_route_irq_to_xen(struct irq_desc *desc, const cpumask_t *cpu_mask,
                          unsigned int priority)
{
    ASSERT(priority <= 0xff);     /* Only 8 bits of priority */
    ASSERT(desc->irq < gic.lines);/* Can't route interrupts that don't exist */
    ASSERT(desc->status & IRQ_DISABLED);
    ASSERT(spin_is_locked(&desc->lock));

    desc->handler = &gic_host_irq_type;

    gic_set_irq_properties(desc, cpu_mask, priority);
}

/* Program the GIC to route an interrupt to a guest
 *   - desc.lock must be held
 */
void gic_route_irq_to_guest(struct domain *d, struct irq_desc *desc,
                            const cpumask_t *cpu_mask, unsigned int priority)
{
    struct pending_irq *p;
    ASSERT(spin_is_locked(&desc->lock));

    desc->handler = &gic_guest_irq_type;
    desc->status |= IRQ_GUEST;

    gic_set_irq_properties(desc, cpumask_of(smp_processor_id()), GIC_PRI_IRQ);

    /* TODO: do not assume delivery to vcpu0 */
    p = irq_to_pending(d->vcpu[0], desc->irq);
    p->desc = desc;
}

static void __init gic_dist_init(void)
{
    uint32_t type;
    uint32_t cpumask;
    int i;

    cpumask = GICD[GICD_ITARGETSR] & 0xff;
    cpumask |= cpumask << 8;
    cpumask |= cpumask << 16;

    /* Disable the distributor */
    GICD[GICD_CTLR] = 0;

    type = GICD[GICD_TYPER];
    gic.lines = 32 * ((type & GICD_TYPE_LINES) + 1);
    gic.cpus = 1 + ((type & GICD_TYPE_CPUS) >> 5);
    printk("GIC: %d lines, %d cpu%s%s (IID %8.8x).\n",
           gic.lines, gic.cpus, (gic.cpus == 1) ? "" : "s",
           (type & GICD_TYPE_SEC) ? ", secure" : "",
           GICD[GICD_IIDR]);

    /* Default all global IRQs to level, active low */
    for ( i = 32; i < gic.lines; i += 16 )
        GICD[GICD_ICFGR + i / 16] = 0x0;

    /* Route all global IRQs to this CPU */
    for ( i = 32; i < gic.lines; i += 4 )
        GICD[GICD_ITARGETSR + i / 4] = cpumask;

    /* Default priority for global interrupts */
    for ( i = 32; i < gic.lines; i += 4 )
        GICD[GICD_IPRIORITYR + i / 4] =
            GIC_PRI_IRQ<<24 | GIC_PRI_IRQ<<16 | GIC_PRI_IRQ<<8 | GIC_PRI_IRQ;

    /* Disable all global interrupts */
    for ( i = 32; i < gic.lines; i += 32 )
        GICD[GICD_ICENABLER + i / 32] = (uint32_t)~0ul;

    /* Turn on the distributor */
    GICD[GICD_CTLR] = GICD_CTL_ENABLE;
}

static void __cpuinit gic_cpu_init(void)
{
    int i;

    this_cpu(gic_cpu_id) = GICD[GICD_ITARGETSR] & 0xff;

    /* The first 32 interrupts (PPI and SGI) are banked per-cpu, so
     * even though they are controlled with GICD registers, they must
     * be set up here with the other per-cpu state. */
    GICD[GICD_ICENABLER] = 0xffff0000; /* Disable all PPI */
    GICD[GICD_ISENABLER] = 0x0000ffff; /* Enable all SGI */
    /* Set SGI priorities */
    for (i = 0; i < 16; i += 4)
        GICD[GICD_IPRIORITYR + i / 4] =
            GIC_PRI_IPI<<24 | GIC_PRI_IPI<<16 | GIC_PRI_IPI<<8 | GIC_PRI_IPI;
    /* Set PPI priorities */
    for (i = 16; i < 32; i += 4)
        GICD[GICD_IPRIORITYR + i / 4] =
            GIC_PRI_IRQ<<24 | GIC_PRI_IRQ<<16 | GIC_PRI_IRQ<<8 | GIC_PRI_IRQ;

    /* Local settings: interface controller */
    GICC[GICC_PMR] = 0xff;                /* Don't mask by priority */
    GICC[GICC_BPR] = 0;                   /* Finest granularity of priority */
    GICC[GICC_CTLR] = GICC_CTL_ENABLE|GICC_CTL_EOI;    /* Turn on delivery */
}

static void gic_cpu_disable(void)
{
    GICC[GICC_CTLR] = 0;
}

static void __cpuinit gic_hyp_init(void)
{
    uint32_t vtr;

    vtr = GICH[GICH_VTR];
    nr_lrs  = (vtr & GICH_VTR_NRLRGS) + 1;

    GICH[GICH_MISR] = GICH_MISR_EOI;
    this_cpu(lr_mask) = 0ULL;
}

static void __cpuinit gic_hyp_disable(void)
{
    GICH[GICH_HCR] = 0;
}

int gic_irq_xlate(const u32 *intspec, unsigned int intsize,
                  unsigned int *out_hwirq,
                  unsigned int *out_type)
{
    if ( intsize < 3 )
        return -EINVAL;

    /* Get the interrupt number and add 16 to skip over SGIs */
    *out_hwirq = intspec[1] + 16;

    /* For SPIs, we need to add 16 more to get the GIC irq ID number */
    if ( !intspec[0] )
        *out_hwirq += 16;

    if ( out_type )
        *out_type = intspec[2] & DT_IRQ_TYPE_SENSE_MASK;

    return 0;
}

/* Set up the GIC */
void __init gic_init(void)
{
    static const struct dt_device_match gic_ids[] __initconst =
    {
        DT_MATCH_GIC,
        { /* sentinel */ },
    };
    struct dt_device_node *node;
    int res;

    node = dt_find_interrupt_controller(gic_ids);
    if ( !node )
        panic("Unable to find compatible GIC in the device tree");

    dt_device_set_used_by(node, DOMID_XEN);

    res = dt_device_get_address(node, 0, &gic.dbase, NULL);
    if ( res || !gic.dbase || (gic.dbase & ~PAGE_MASK) )
        panic("GIC: Cannot find a valid address for the distributor");

    res = dt_device_get_address(node, 1, &gic.cbase, NULL);
    if ( res || !gic.cbase || (gic.cbase & ~PAGE_MASK) )
        panic("GIC: Cannot find a valid address for the CPU");

    res = dt_device_get_address(node, 2, &gic.hbase, NULL);
    if ( res || !gic.hbase || (gic.hbase & ~PAGE_MASK) )
        panic("GIC: Cannot find a valid address for the hypervisor");

    res = dt_device_get_address(node, 3, &gic.vbase, NULL);
    if ( res || !gic.vbase || (gic.vbase & ~PAGE_MASK) )
        panic("GIC: Cannot find a valid address for the virtual CPU");

    res = platform_get_irq(node, 0);
    if ( res < 0 )
        panic("GIC: Cannot find the maintenance IRQ");
    gic.maintenance_irq = res;

    /* Set the GIC as the primary interrupt controller */
    dt_interrupt_controller = node;

    /* TODO: Add check on distributor, cpu size */

    printk("GIC initialization:\n"
              "        gic_dist_addr=%"PRIpaddr"\n"
              "        gic_cpu_addr=%"PRIpaddr"\n"
              "        gic_hyp_addr=%"PRIpaddr"\n"
              "        gic_vcpu_addr=%"PRIpaddr"\n"
              "        gic_maintenance_irq=%u\n",
              gic.dbase, gic.cbase, gic.hbase, gic.vbase,
              gic.maintenance_irq);

    if ( (gic.dbase & ~PAGE_MASK) || (gic.cbase & ~PAGE_MASK) ||
         (gic.hbase & ~PAGE_MASK) || (gic.vbase & ~PAGE_MASK) )
        panic("GIC interfaces not page aligned");

    set_fixmap(FIXMAP_GICD, gic.dbase >> PAGE_SHIFT, DEV_SHARED);
    BUILD_BUG_ON(FIXMAP_ADDR(FIXMAP_GICC1) !=
                 FIXMAP_ADDR(FIXMAP_GICC2)-PAGE_SIZE);
    set_fixmap(FIXMAP_GICC1, gic.cbase >> PAGE_SHIFT, DEV_SHARED);
    if ( platform_has_quirk(PLATFORM_QUIRK_GIC_64K_STRIDE) )
        set_fixmap(FIXMAP_GICC2, (gic.cbase >> PAGE_SHIFT) + 0x10, DEV_SHARED);
    else
        set_fixmap(FIXMAP_GICC2, (gic.cbase >> PAGE_SHIFT) + 0x1, DEV_SHARED);
    set_fixmap(FIXMAP_GICH, gic.hbase >> PAGE_SHIFT, DEV_SHARED);

    /* Global settings: interrupt distributor */
    spin_lock_init(&gic.lock);
    spin_lock(&gic.lock);

    gic_dist_init();
    gic_cpu_init();
    gic_hyp_init();

    spin_unlock(&gic.lock);
}

void send_SGI_mask(const cpumask_t *cpumask, enum gic_sgi sgi)
{
    unsigned int mask = 0;
    cpumask_t online_mask;

    ASSERT(sgi < 16); /* There are only 16 SGIs */

    cpumask_and(&online_mask, cpumask, &cpu_online_map);
    mask = gic_cpu_mask(&online_mask);

    dsb(sy);

    GICD[GICD_SGIR] = GICD_SGI_TARGET_LIST
        | (mask<<GICD_SGI_TARGET_SHIFT)
        | sgi;
}

void send_SGI_one(unsigned int cpu, enum gic_sgi sgi)
{
    ASSERT(cpu < NR_GIC_CPU_IF);  /* Targets bitmap only supports 8 CPUs */
    send_SGI_mask(cpumask_of(cpu), sgi);
}

void send_SGI_self(enum gic_sgi sgi)
{
    ASSERT(sgi < 16); /* There are only 16 SGIs */

    dsb(sy);

    GICD[GICD_SGIR] = GICD_SGI_TARGET_SELF
        | sgi;
}

void send_SGI_allbutself(enum gic_sgi sgi)
{
   ASSERT(sgi < 16); /* There are only 16 SGIs */

   dsb(sy);

   GICD[GICD_SGIR] = GICD_SGI_TARGET_OTHERS
       | sgi;
}

void smp_send_state_dump(unsigned int cpu)
{
    send_SGI_one(cpu, GIC_SGI_DUMP_STATE);
}

/* Set up the per-CPU parts of the GIC for a secondary CPU */
void __cpuinit gic_init_secondary_cpu(void)
{
    spin_lock(&gic.lock);
    gic_cpu_init();
    gic_hyp_init();
    spin_unlock(&gic.lock);
}

/* Shut down the per-CPU GIC interface */
void gic_disable_cpu(void)
{
    ASSERT(!local_irq_is_enabled());

    spin_lock(&gic.lock);
    gic_cpu_disable();
    gic_hyp_disable();
    spin_unlock(&gic.lock);
}

static inline void gic_set_lr(int lr, struct pending_irq *p,
        unsigned int state)
{
    uint32_t lr_val;

    BUG_ON(lr >= nr_lrs);
    BUG_ON(lr < 0);
    BUG_ON(state & ~(GICH_LR_STATE_MASK<<GICH_LR_STATE_SHIFT));

    lr_val = state | ((p->priority >> 3) << GICH_LR_PRIORITY_SHIFT) |
        ((p->irq & GICH_LR_VIRTUAL_MASK) << GICH_LR_VIRTUAL_SHIFT);
    if ( p->desc != NULL )
        lr_val |= GICH_LR_HW | (p->desc->irq << GICH_LR_PHYSICAL_SHIFT);

    GICH[GICH_LR + lr] = lr_val;

    set_bit(GIC_IRQ_GUEST_VISIBLE, &p->status);
    clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
    p->lr = lr;
}

static inline void gic_add_to_lr_pending(struct vcpu *v, struct pending_irq *n)
{
    struct pending_irq *iter;

    if ( !list_empty(&n->lr_queue) )
        return;

    list_for_each_entry ( iter, &v->arch.vgic.lr_pending, lr_queue )
    {
        if ( iter->priority > n->priority )
        {
            list_add_tail(&n->lr_queue, &iter->lr_queue);
            return;
        }
    }
    list_add_tail(&n->lr_queue, &v->arch.vgic.lr_pending);
}

void gic_remove_from_queues(struct vcpu *v, unsigned int virtual_irq)
{
    struct pending_irq *p = irq_to_pending(v, virtual_irq);
    unsigned long flags;

    spin_lock_irqsave(&gic.lock, flags);
    if ( !list_empty(&p->lr_queue) )
        list_del_init(&p->lr_queue);
    spin_unlock_irqrestore(&gic.lock, flags);
}

void gic_raise_inflight_irq(struct vcpu *v, unsigned int virtual_irq)
{
    struct pending_irq *n = irq_to_pending(v, virtual_irq);

    if ( list_empty(&n->lr_queue) )
    {
        if ( v == current )
            gic_update_one_lr(v, n->lr);
    }
#ifdef GIC_DEBUG
    else
        gdprintk(XENLOG_DEBUG, "trying to inject irq=%u into d%dv%d, when it is still lr_pending\n",
                 virtual_irq, v->domain->domain_id, v->vcpu_id);
#endif
}

void gic_raise_guest_irq(struct vcpu *v, unsigned int virtual_irq,
        unsigned int priority)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&gic.lock, flags);

    if ( v == current && list_empty(&v->arch.vgic.lr_pending) )
    {
        i = find_first_zero_bit(&this_cpu(lr_mask), nr_lrs);
        if (i < nr_lrs) {
            set_bit(i, &this_cpu(lr_mask));
            gic_set_lr(i, irq_to_pending(v, virtual_irq), GICH_LR_PENDING);
            goto out;
        }
    }

    gic_add_to_lr_pending(v, irq_to_pending(v, virtual_irq));

out:
    spin_unlock_irqrestore(&gic.lock, flags);
    return;
}

static void gic_update_one_lr(struct vcpu *v, int i)
{
    struct pending_irq *p;
    uint32_t lr;
    int irq;

    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    lr = GICH[GICH_LR + i];
    irq = (lr >> GICH_LR_VIRTUAL_SHIFT) & GICH_LR_VIRTUAL_MASK;
    p = irq_to_pending(v, irq);
    if ( lr & GICH_LR_ACTIVE )
    {
        if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) &&
             test_and_clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status) )
        {
            if ( p->desc == NULL )
                GICH[GICH_LR + i] = lr | GICH_LR_PENDING;
            else
                gdprintk(XENLOG_WARNING, "unable to inject hw irq=%d into d%dv%d: already active in LR%d\n",
                         irq, v->domain->domain_id, v->vcpu_id, i);
        }
    } else if ( lr & GICH_LR_PENDING ) {
        int q __attribute__ ((unused)) = test_and_clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
#ifdef GIC_DEBUG
        if ( q )
            gdprintk(XENLOG_DEBUG, "trying to inject irq=%d into d%dv%d, when it is already pending in LR%d\n",
                    irq, v->domain->domain_id, v->vcpu_id, i);
#endif
    } else {
        GICH[GICH_LR + i] = 0;
        clear_bit(i, &this_cpu(lr_mask));

        if ( p->desc != NULL )
            p->desc->status &= ~IRQ_INPROGRESS;
        clear_bit(GIC_IRQ_GUEST_VISIBLE, &p->status);
        p->lr = GIC_INVALID_LR;
        if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) &&
             test_bit(GIC_IRQ_GUEST_QUEUED, &p->status) )
            gic_raise_guest_irq(v, irq, p->priority);
        else
            list_del_init(&p->inflight);
    }
}

void gic_clear_lrs(struct vcpu *v)
{
    int i = 0;
    unsigned long flags;

    /* The idle domain has no LRs to be cleared. Since gic_restore_state
     * doesn't write any LR registers for the idle domain they could be
     * non-zero. */
    if ( is_idle_vcpu(v) )
        return;

    spin_lock_irqsave(&v->arch.vgic.lock, flags);

    while ((i = find_next_bit((const unsigned long *) &this_cpu(lr_mask),
                              nr_lrs, i)) < nr_lrs ) {
        gic_update_one_lr(v, i);
        i++;
    }

    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
}

static void gic_restore_pending_irqs(struct vcpu *v)
{
    int i;
    struct pending_irq *p, *t;
    unsigned long flags;

    list_for_each_entry_safe ( p, t, &v->arch.vgic.lr_pending, lr_queue )
    {
        i = find_first_zero_bit(&this_cpu(lr_mask), nr_lrs);
        if ( i >= nr_lrs ) return;

        spin_lock_irqsave(&gic.lock, flags);
        gic_set_lr(i, p, GICH_LR_PENDING);
        list_del_init(&p->lr_queue);
        set_bit(i, &this_cpu(lr_mask));
        spin_unlock_irqrestore(&gic.lock, flags);
    }

}

void gic_clear_pending_irqs(struct vcpu *v)
{
    struct pending_irq *p, *t;
    unsigned long flags;

    spin_lock_irqsave(&gic.lock, flags);
    v->arch.lr_mask = 0;
    list_for_each_entry_safe ( p, t, &v->arch.vgic.lr_pending, lr_queue )
        list_del_init(&p->lr_queue);
    spin_unlock_irqrestore(&gic.lock, flags);
}

int gic_events_need_delivery(void)
{
    return (!list_empty(&current->arch.vgic.lr_pending) ||
            this_cpu(lr_mask));
}

void gic_inject(void)
{
    gic_restore_pending_irqs(current);


    if ( !list_empty(&current->arch.vgic.lr_pending) && lr_all_full() )
        GICH[GICH_HCR] |= GICH_HCR_UIE;
    else
        GICH[GICH_HCR] &= ~GICH_HCR_UIE;

}

static void do_sgi(struct cpu_user_regs *regs, int othercpu, enum gic_sgi sgi)
{
    /* Lower the priority */
    GICC[GICC_EOIR] = sgi;

    switch (sgi)
    {
    case GIC_SGI_EVENT_CHECK:
        /* Nothing to do, will check for events on return path */
        break;
    case GIC_SGI_DUMP_STATE:
        dump_execstate(regs);
        break;
    case GIC_SGI_CALL_FUNCTION:
        smp_call_function_interrupt();
        break;
    default:
        panic("Unhandled SGI %d on CPU%d", sgi, smp_processor_id());
        break;
    }

    /* Deactivate */
    GICC[GICC_DIR] = sgi;
}

/* Accept an interrupt from the GIC and dispatch its handler */
void gic_interrupt(struct cpu_user_regs *regs, int is_fiq)
{
    uint32_t intack;
    unsigned int irq;


    do  {
        intack = GICC[GICC_IAR];
        irq = intack & GICC_IA_IRQ;

        if ( likely(irq >= 16 && irq < 1021) )
        {
            local_irq_enable();
            do_IRQ(regs, irq, is_fiq);
            local_irq_disable();
        }
        else if (unlikely(irq < 16))
        {
            unsigned int cpu = (intack & GICC_IA_CPU_MASK) >> GICC_IA_CPU_SHIFT;
            do_sgi(regs, cpu, irq);
        }
        else
        {
            local_irq_disable();
            break;
        }
    } while (1);
}

int gicv_setup(struct domain *d)
{
    int ret;

    /*
     * The hardware domain gets the hardware address.
     * Guests get the virtual platform layout.
     */
    if ( is_hardware_domain(d) )
    {
        d->arch.vgic.dbase = gic.dbase;
        d->arch.vgic.cbase = gic.cbase;
    }
    else
    {
        d->arch.vgic.dbase = GUEST_GICD_BASE;
        d->arch.vgic.cbase = GUEST_GICC_BASE;
    }

    d->arch.vgic.nr_lines = 0;

    /*
     * Map the gic virtual cpu interface in the gic cpu interface
     * region of the guest.
     *
     * The second page is always mapped at +4K irrespective of the
     * GIC_64K_STRIDE quirk. The DTB passed to the guest reflects this.
     */
    ret = map_mmio_regions(d, d->arch.vgic.cbase,
                           d->arch.vgic.cbase + PAGE_SIZE - 1,
                           gic.vbase);
    if (ret)
        return ret;

    if ( !platform_has_quirk(PLATFORM_QUIRK_GIC_64K_STRIDE) )
        ret = map_mmio_regions(d, d->arch.vgic.cbase + PAGE_SIZE,
                               d->arch.vgic.cbase + (2 * PAGE_SIZE) - 1,
                               gic.vbase + PAGE_SIZE);
    else
        ret = map_mmio_regions(d, d->arch.vgic.cbase + PAGE_SIZE,
                               d->arch.vgic.cbase + (2 * PAGE_SIZE) - 1,
                               gic.vbase + 16*PAGE_SIZE);

    return ret;

}

static void maintenance_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    /*
     * This is a dummy interrupt handler.
     * Receiving the interrupt is going to cause gic_inject to be called
     * on return to guest that is going to clear the old LRs and inject
     * new interrupts.
     */
}

void gic_dump_info(struct vcpu *v)
{
    int i;
    struct pending_irq *p;

    printk("GICH_LRs (vcpu %d) mask=%"PRIx64"\n", v->vcpu_id, v->arch.lr_mask);
    if ( v == current )
    {
        for ( i = 0; i < nr_lrs; i++ )
            printk("   HW_LR[%d]=%x\n", i, GICH[GICH_LR + i]);
    } else {
        for ( i = 0; i < nr_lrs; i++ )
            printk("   VCPU_LR[%d]=%x\n", i, v->arch.gic_lr[i]);
    }

    list_for_each_entry ( p, &v->arch.vgic.inflight_irqs, inflight )
    {
        printk("Inflight irq=%d lr=%u\n", p->irq, p->lr);
    }

    list_for_each_entry( p, &v->arch.vgic.lr_pending, lr_queue )
    {
        printk("Pending irq=%d\n", p->irq);
    }

}

void __cpuinit init_maintenance_interrupt(void)
{
    request_irq(gic.maintenance_irq, 0, maintenance_interrupt,
                "irq-maintenance", NULL);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
