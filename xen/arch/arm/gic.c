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
#include <xen/softirq.h>
#include <xen/list.h>
#include <xen/device_tree.h>
#include <asm/p2m.h>
#include <asm/domain.h>

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
    unsigned int lines;
    unsigned int cpus;
    spinlock_t lock;
} gic;

static irq_desc_t irq_desc[NR_IRQS];
static DEFINE_PER_CPU(irq_desc_t[NR_LOCAL_IRQS], local_irq_desc);
static DEFINE_PER_CPU(uint64_t, lr_mask);

unsigned nr_lrs;

irq_desc_t *__irq_to_desc(int irq)
{
    if (irq < NR_LOCAL_IRQS) return &this_cpu(local_irq_desc)[irq];
    return &irq_desc[irq-NR_LOCAL_IRQS];
}

void gic_save_state(struct vcpu *v)
{
    int i;

    spin_lock_irq(&gic.lock);
    for ( i=0; i<nr_lrs; i++)
        v->arch.gic_lr[i] = GICH[GICH_LR + i];
    v->arch.lr_mask = this_cpu(lr_mask);
    spin_unlock_irq(&gic.lock);
    v->arch.gic_apr = GICH[GICH_APR];
    /* Disable until next VCPU scheduled */
    GICH[GICH_HCR] = 0;
    isb();
}

void gic_restore_state(struct vcpu *v)
{
    int i;

    if ( is_idle_vcpu(v) )
        return;

    spin_lock_irq(&gic.lock);
    this_cpu(lr_mask) = v->arch.lr_mask;
    for ( i=0; i<nr_lrs; i++)
        GICH[GICH_LR + i] = v->arch.gic_lr[i];
    spin_unlock_irq(&gic.lock);
    GICH[GICH_APR] = v->arch.gic_apr;
    GICH[GICH_HCR] = GICH_HCR_EN;
    isb();

    gic_restore_pending_irqs(v);
}

static unsigned int gic_irq_startup(struct irq_desc *desc)
{
    uint32_t enabler;
    int irq = desc->irq;

    /* Enable routing */
    enabler = GICD[GICD_ISENABLER + irq / 32];
    GICD[GICD_ISENABLER + irq / 32] = enabler | (1u << (irq % 32));

    return 0;
}

static void gic_irq_shutdown(struct irq_desc *desc)
{
    uint32_t enabler;
    int irq = desc->irq;

    /* Disable routing */
    enabler = GICD[GICD_ICENABLER + irq / 32];
    GICD[GICD_ICENABLER + irq / 32] = enabler | (1u << (irq % 32));
}

static void gic_irq_enable(struct irq_desc *desc)
{

}

static void gic_irq_disable(struct irq_desc *desc)
{

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

/* needs to be called with gic.lock held */
static void gic_set_irq_properties(unsigned int irq, bool_t level,
        unsigned int cpu_mask, unsigned int priority)
{
    volatile unsigned char *bytereg;
    uint32_t cfg, edgebit;

    /* Set edge / level */
    cfg = GICD[GICD_ICFGR + irq / 16];
    edgebit = 2u << (2 * (irq % 16));
    if ( level )
        cfg &= ~edgebit;
    else
        cfg |= edgebit;
    GICD[GICD_ICFGR + irq / 16] = cfg;

    /* Set target CPU mask (RAZ/WI on uniprocessor) */
    bytereg = (unsigned char *) (GICD + GICD_ITARGETSR);
    bytereg[irq] = cpu_mask;

    /* Set priority */
    bytereg = (unsigned char *) (GICD + GICD_IPRIORITYR);
    bytereg[irq] = priority;

}

/* Program the GIC to route an interrupt */
static int gic_route_irq(unsigned int irq, bool_t level,
                         unsigned int cpu_mask, unsigned int priority)
{
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;

    ASSERT(!(cpu_mask & ~0xff));  /* Targets bitmap only supports 8 CPUs */
    ASSERT(priority <= 0xff);     /* Only 8 bits of priority */
    ASSERT(irq < gic.lines + 32); /* Can't route interrupts that don't exist */

    spin_lock_irqsave(&desc->lock, flags);
    spin_lock(&gic.lock);

    if ( desc->action != NULL )
    {
        spin_unlock(&gic.lock);
        spin_unlock(&desc->lock);
        return -EBUSY;
    }

    desc->handler = &gic_host_irq_type;

    /* Disable interrupt */
    desc->handler->shutdown(desc);

    gic_set_irq_properties(irq, level, cpu_mask, priority);

    spin_unlock(&gic.lock);
    spin_unlock_irqrestore(&desc->lock, flags);
    return 0;
}

static void __init gic_dist_init(void)
{
    uint32_t type;
    uint32_t cpumask = 1 << smp_processor_id();
    int i;

    cpumask |= cpumask << 8;
    cpumask |= cpumask << 16;

    /* Disable the distributor */
    GICD[GICD_CTLR] = 0;

    type = GICD[GICD_TYPER];
    gic.lines = 32 * (type & GICD_TYPE_LINES);
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
        GICD[GICD_ICFGR + i / 4] = cpumask;

    /* Default priority for global interrupts */
    for ( i = 32; i < gic.lines; i += 4 )
        GICD[GICD_IPRIORITYR + i / 4] = 0xa0a0a0a0;

    /* Disable all global interrupts */
    for ( i = 32; i < gic.lines; i += 32 )
        GICD[GICD_ICENABLER + i / 32] = (uint32_t)~0ul;

    /* Turn on the distributor */
    GICD[GICD_CTLR] = GICD_CTL_ENABLE;
}

static void __cpuinit gic_cpu_init(void)
{
    int i;

    /* The first 32 interrupts (PPI and SGI) are banked per-cpu, so
     * even though they are controlled with GICD registers, they must
     * be set up here with the other per-cpu state. */
    GICD[GICD_ICENABLER] = 0xffff0000; /* Disable all PPI */
    GICD[GICD_ISENABLER] = 0x0000ffff; /* Enable all SGI */
    /* Set PPI and SGI priorities */
    for (i = 0; i < 32; i += 4)
        GICD[GICD_IPRIORITYR + i / 4] = 0xa0a0a0a0;

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

/* Set up the GIC */
void __init gic_init(void)
{
    printk("GIC initialization:\n"
              "        gic_dist_addr=%"PRIpaddr"\n"
              "        gic_cpu_addr=%"PRIpaddr"\n"
              "        gic_hyp_addr=%"PRIpaddr"\n"
              "        gic_vcpu_addr=%"PRIpaddr"\n",
              early_info.gic.gic_dist_addr, early_info.gic.gic_cpu_addr,
              early_info.gic.gic_hyp_addr, early_info.gic.gic_vcpu_addr);
    if ( !early_info.gic.gic_dist_addr ||
         !early_info.gic.gic_cpu_addr ||
         !early_info.gic.gic_hyp_addr ||
         !early_info.gic.gic_vcpu_addr )
        panic("the physical address of one of the GIC interfaces is missing\n");
    if ( (early_info.gic.gic_dist_addr & ~PAGE_MASK) ||
         (early_info.gic.gic_cpu_addr & ~PAGE_MASK) ||
         (early_info.gic.gic_hyp_addr & ~PAGE_MASK) ||
         (early_info.gic.gic_vcpu_addr & ~PAGE_MASK) )
        panic("GIC interfaces not page aligned.\n");

    gic.dbase = early_info.gic.gic_dist_addr;
    gic.cbase = early_info.gic.gic_cpu_addr;
    gic.hbase = early_info.gic.gic_hyp_addr;
    gic.vbase = early_info.gic.gic_vcpu_addr;
    set_fixmap(FIXMAP_GICD, gic.dbase >> PAGE_SHIFT, DEV_SHARED);
    BUILD_BUG_ON(FIXMAP_ADDR(FIXMAP_GICC1) !=
                 FIXMAP_ADDR(FIXMAP_GICC2)-PAGE_SIZE);
    set_fixmap(FIXMAP_GICC1, gic.cbase >> PAGE_SHIFT, DEV_SHARED);
    set_fixmap(FIXMAP_GICC2, (gic.cbase >> PAGE_SHIFT) + 1, DEV_SHARED);
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
    unsigned long mask = cpumask_bits(cpumask)[0];

    ASSERT(sgi < 16); /* There are only 16 SGIs */

    mask &= cpumask_bits(&cpu_online_map)[0];

    ASSERT(mask < 0x100); /* The target bitmap only supports 8 CPUs */

    dsb();

    GICD[GICD_SGIR] = GICD_SGI_TARGET_LIST
        | (mask<<GICD_SGI_TARGET_SHIFT)
        | sgi;
}

void send_SGI_one(unsigned int cpu, enum gic_sgi sgi)
{
    ASSERT(cpu < 7);  /* Targets bitmap only supports 8 CPUs */
    send_SGI_mask(cpumask_of(cpu), sgi);
}

void send_SGI_self(enum gic_sgi sgi)
{
    ASSERT(sgi < 16); /* There are only 16 SGIs */

    dsb();

    GICD[GICD_SGIR] = GICD_SGI_TARGET_SELF
        | sgi;
}

void send_SGI_allbutself(enum gic_sgi sgi)
{
   ASSERT(sgi < 16); /* There are only 16 SGIs */

   dsb();

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
    spin_lock_irq(&gic.lock);
    gic_cpu_disable();
    gic_hyp_disable();
    spin_unlock_irq(&gic.lock);
}

void gic_route_ppis(void)
{
    /* XXX should get these from DT */
    /* GIC maintenance */
    gic_route_irq(25, 1, 1u << smp_processor_id(), 0xa0);
    /* Hypervisor Timer */
    gic_route_irq(26, 1, 1u << smp_processor_id(), 0xa0);
    /* Virtual Timer */
    gic_route_irq(27, 1, 1u << smp_processor_id(), 0xa0);
    /* Physical Timer */
    gic_route_irq(30, 1, 1u << smp_processor_id(), 0xa0);
}

void gic_route_spis(void)
{
    /* XXX should get these from DT */
    /* UART */
    gic_route_irq(37, 0, 1u << smp_processor_id(), 0xa0);
}

void __init release_irq(unsigned int irq)
{
    struct irq_desc *desc;
    unsigned long flags;
   struct irqaction *action;

    desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock,flags);
    action = desc->action;
    desc->action  = NULL;
    desc->status |= IRQ_DISABLED;

    spin_lock(&gic.lock);
    desc->handler->shutdown(desc);
    spin_unlock(&gic.lock);

    spin_unlock_irqrestore(&desc->lock,flags);

    /* Wait to make sure it's not being used on another CPU */
    do { smp_mb(); } while ( desc->status & IRQ_INPROGRESS );

    if (action && action->free_on_release)
        xfree(action);
}

static int __setup_irq(struct irq_desc *desc, unsigned int irq,
                       struct irqaction *new)
{
    if ( desc->action != NULL )
        return -EBUSY;

    desc->action  = new;
    desc->status &= ~IRQ_DISABLED;
    dsb();

    desc->handler->startup(desc);

    return 0;
}

int __init setup_irq(unsigned int irq, struct irqaction *new)
{
    int rc;
    unsigned long flags;
    struct irq_desc *desc;

    desc = irq_to_desc(irq);

    spin_lock_irqsave(&desc->lock, flags);

    rc = __setup_irq(desc, irq, new);

    spin_unlock_irqrestore(&desc->lock, flags);

    return rc;
}

static inline void gic_set_lr(int lr, unsigned int virtual_irq,
        unsigned int state, unsigned int priority)
{
    int maintenance_int = GICH_LR_MAINTENANCE_IRQ;

    BUG_ON(lr > nr_lrs);

    GICH[GICH_LR + lr] = state |
        maintenance_int |
        ((priority >> 3) << GICH_LR_PRIORITY_SHIFT) |
        ((virtual_irq & GICH_LR_VIRTUAL_MASK) << GICH_LR_VIRTUAL_SHIFT);
}

void gic_set_guest_irq(struct vcpu *v, unsigned int virtual_irq,
        unsigned int state, unsigned int priority)
{
    int i;
    struct pending_irq *iter, *n;
    unsigned long flags;

    spin_lock_irqsave(&gic.lock, flags);

    if ( v->is_running && list_empty(&v->arch.vgic.lr_pending) )
    {
        i = find_first_zero_bit(&this_cpu(lr_mask), nr_lrs);
        if (i < nr_lrs) {
            set_bit(i, &this_cpu(lr_mask));
            gic_set_lr(i, virtual_irq, state, priority);
            goto out;
        }
    }

    n = irq_to_pending(v, virtual_irq);
    if ( !list_empty(&n->lr_queue) )
        goto out;

    list_for_each_entry ( iter, &v->arch.vgic.lr_pending, lr_queue )
    {
        if ( iter->priority > priority )
        {
            list_add_tail(&n->lr_queue, &iter->lr_queue);
            goto out;
        }
    }
    list_add_tail(&n->lr_queue, &v->arch.vgic.lr_pending);

out:
    spin_unlock_irqrestore(&gic.lock, flags);
    return;
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
        gic_set_lr(i, p->irq, GICH_LR_PENDING, p->priority);
        list_del_init(&p->lr_queue);
        set_bit(i, &this_cpu(lr_mask));
        spin_unlock_irqrestore(&gic.lock, flags);
    }

}

static void gic_inject_irq_start(void)
{
    register_t hcr = READ_SYSREG(HCR_EL2);
    WRITE_SYSREG(hcr | HCR_VI, HCR_EL2);
    isb();
}

static void gic_inject_irq_stop(void)
{
    register_t hcr = READ_SYSREG(HCR_EL2);
    if (hcr & HCR_VI) {
        WRITE_SYSREG(hcr & ~HCR_VI, HCR_EL2);
        isb();
    }
}

void gic_inject(void)
{
    if ( vcpu_info(current, evtchn_upcall_pending) )
        vgic_vcpu_inject_irq(current, VGIC_IRQ_EVTCHN_CALLBACK, 1);

    gic_restore_pending_irqs(current);
    if (!this_cpu(lr_mask))
        gic_inject_irq_stop();
    else
        gic_inject_irq_start();
}

int gic_route_irq_to_guest(struct domain *d, unsigned int irq,
                           const char * devname)
{
    struct irqaction *action;
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;
    int retval;

    action = xmalloc(struct irqaction);
    if (!action)
        return -ENOMEM;

    action->dev_id = d;
    action->name = devname;

    spin_lock_irqsave(&desc->lock, flags);
    spin_lock(&gic.lock);

    desc->handler = &gic_guest_irq_type;
    desc->status |= IRQ_GUEST;

    gic_set_irq_properties(irq, 1, 1u << smp_processor_id(), 0xa0);

    retval = __setup_irq(desc, irq, action);
    if (retval) {
        xfree(action);
        goto out;
    }

out:
    spin_unlock(&gic.lock);
    spin_unlock_irqrestore(&desc->lock, flags);
    return retval;
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
    default:
        panic("Unhandled SGI %d on CPU%d\n", sgi, smp_processor_id());
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
    /* map the gic virtual cpu interface in the gic cpu interface region of
     * the guest */
    return map_mmio_regions(d, gic.cbase,
                        gic.cbase + (2 * PAGE_SIZE) - 1,
                        gic.vbase);
}

static void maintenance_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    int i = 0, virq;
    uint32_t lr;
    struct vcpu *v = current;
    uint64_t eisr = GICH[GICH_EISR0] | (((uint64_t) GICH[GICH_EISR1]) << 32);

    while ((i = find_next_bit((const long unsigned int *) &eisr,
                              64, i)) < 64) {
        struct pending_irq *p;

        spin_lock_irq(&gic.lock);
        lr = GICH[GICH_LR + i];
        virq = lr & GICH_LR_VIRTUAL_MASK;
        GICH[GICH_LR + i] = 0;
        clear_bit(i, &this_cpu(lr_mask));

        if ( !list_empty(&v->arch.vgic.lr_pending) ) {
            p = list_entry(v->arch.vgic.lr_pending.next, typeof(*p), lr_queue);
            gic_set_lr(i, p->irq, GICH_LR_PENDING, p->priority);
            list_del_init(&p->lr_queue);
            set_bit(i, &this_cpu(lr_mask));
        } else {
            gic_inject_irq_stop();
        }
        spin_unlock_irq(&gic.lock);

        spin_lock_irq(&v->arch.vgic.lock);
        p = irq_to_pending(v, virq);
        if ( p->desc != NULL ) {
            p->desc->status &= ~IRQ_INPROGRESS;
            GICC[GICC_DIR] = virq;
        }
        list_del_init(&p->inflight);
        spin_unlock_irq(&v->arch.vgic.lock);

        i++;
    }
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
        printk("Inflight irq=%d\n", p->irq);
    }

    list_for_each_entry( p, &v->arch.vgic.lr_pending, lr_queue )
    {
        printk("Pending irq=%d\n", p->irq);
    }

}

void __cpuinit init_maintenance_interrupt(void)
{
    request_irq(25, maintenance_interrupt, 0, "irq-maintenance", NULL);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
