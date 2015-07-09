/*
 * xen/arch/arm/vgic.c
 *
 * ARM Virtual Generic Interrupt Controller support
 *
 * Ian Campbell <ian.campbell@citrix.com>
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

#include <xen/bitops.h>
#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/perfc.h>

#include <asm/current.h>

#include <asm/mmio.h>
#include <asm/gic.h>
#include <asm/vgic.h>

static inline struct vgic_irq_rank *vgic_get_rank(struct vcpu *v, int rank)
{
    if ( rank == 0 )
        return v->arch.vgic.private_irqs;
    else if ( rank <= DOMAIN_NR_RANKS(v->domain) )
        return &v->domain->arch.vgic.shared_irqs[rank - 1];
    else
        return NULL;
}

/*
 * Returns rank corresponding to a GICD_<FOO><n> register for
 * GICD_<FOO> with <b>-bits-per-interrupt.
 */
struct vgic_irq_rank *vgic_rank_offset(struct vcpu *v, int b, int n,
                                              int s)
{
    int rank = REG_RANK_NR(b, (n >> s));

    return vgic_get_rank(v, rank);
}

struct vgic_irq_rank *vgic_rank_irq(struct vcpu *v, unsigned int irq)
{
    int rank = irq/32;

    return vgic_get_rank(v, rank);
}

static void vgic_init_pending_irq(struct pending_irq *p, unsigned int virq)
{
    INIT_LIST_HEAD(&p->inflight);
    INIT_LIST_HEAD(&p->lr_queue);
    p->irq = virq;
}

int domain_vgic_init(struct domain *d, unsigned int nr_spis)
{
    int i;
    int ret;

    d->arch.vgic.ctlr = 0;

    /* Limit the number of virtual SPIs supported to (1020 - 32) = 988  */
    if ( nr_spis > (1020 - NR_LOCAL_IRQS) )
        return -EINVAL;

    d->arch.vgic.nr_spis = nr_spis;

    switch ( d->arch.vgic.version )
    {
#ifdef HAS_GICV3
    case GIC_V3:
        if ( vgic_v3_init(d) )
           return -ENODEV;
        break;
#endif
    case GIC_V2:
        if ( vgic_v2_init(d) )
            return -ENODEV;
        break;
    default:
        printk(XENLOG_G_ERR "d%d: Unknown vGIC version %u\n",
               d->domain_id, d->arch.vgic.version);
        return -ENODEV;
    }

    spin_lock_init(&d->arch.vgic.lock);

    d->arch.vgic.shared_irqs =
        xzalloc_array(struct vgic_irq_rank, DOMAIN_NR_RANKS(d));
    if ( d->arch.vgic.shared_irqs == NULL )
        return -ENOMEM;

    d->arch.vgic.pending_irqs =
        xzalloc_array(struct pending_irq, d->arch.vgic.nr_spis);
    if ( d->arch.vgic.pending_irqs == NULL )
        return -ENOMEM;

    for (i=0; i<d->arch.vgic.nr_spis; i++)
        vgic_init_pending_irq(&d->arch.vgic.pending_irqs[i], i + 32);

    for (i=0; i<DOMAIN_NR_RANKS(d); i++)
        spin_lock_init(&d->arch.vgic.shared_irqs[i].lock);

    ret = d->arch.vgic.handler->domain_init(d);
    if ( ret )
        return ret;

    d->arch.vgic.allocated_irqs =
        xzalloc_array(unsigned long, BITS_TO_LONGS(vgic_num_irqs(d)));
    if ( !d->arch.vgic.allocated_irqs )
        return -ENOMEM;

    /* vIRQ0-15 (SGIs) are reserved */
    for ( i = 0; i < NR_GIC_SGI; i++ )
        set_bit(i, d->arch.vgic.allocated_irqs);

    return 0;
}

void register_vgic_ops(struct domain *d, const struct vgic_ops *ops)
{
   d->arch.vgic.handler = ops;
}

void domain_vgic_free(struct domain *d)
{
    int i;
    int ret;

    for ( i = 0; i < (d->arch.vgic.nr_spis); i++ )
    {
        struct pending_irq *p = spi_to_pending(d, i + 32);

        if ( p->desc )
        {
            ret = release_guest_irq(d, p->irq);
            if ( ret )
                dprintk(XENLOG_G_WARNING, "d%u: Failed to release virq %u ret = %d\n",
                        d->domain_id, p->irq, ret);
        }
    }

    xfree(d->arch.vgic.shared_irqs);
    xfree(d->arch.vgic.pending_irqs);
    xfree(d->arch.vgic.allocated_irqs);
}

int vcpu_vgic_init(struct vcpu *v)
{
    int i;

    v->arch.vgic.private_irqs = xzalloc(struct vgic_irq_rank);
    if ( v->arch.vgic.private_irqs == NULL )
      return -ENOMEM;

    spin_lock_init(&v->arch.vgic.private_irqs->lock);

    v->domain->arch.vgic.handler->vcpu_init(v);

    memset(&v->arch.vgic.pending_irqs, 0, sizeof(v->arch.vgic.pending_irqs));
    for (i = 0; i < 32; i++)
        vgic_init_pending_irq(&v->arch.vgic.pending_irqs[i], i);

    INIT_LIST_HEAD(&v->arch.vgic.inflight_irqs);
    INIT_LIST_HEAD(&v->arch.vgic.lr_pending);
    spin_lock_init(&v->arch.vgic.lock);

    return 0;
}

int vcpu_vgic_free(struct vcpu *v)
{
    xfree(v->arch.vgic.private_irqs);
    return 0;
}

/* takes the rank lock */
struct vcpu *vgic_get_target_vcpu(struct vcpu *v, unsigned int irq)
{
    struct domain *d = v->domain;
    struct vcpu *v_target;
    struct vgic_irq_rank *rank = vgic_rank_irq(v, irq);
    unsigned long flags;

    vgic_lock_rank(v, rank, flags);
    v_target = d->arch.vgic.handler->get_target_vcpu(v, irq);
    vgic_unlock_rank(v, rank, flags);
    return v_target;
}

void vgic_migrate_irq(struct vcpu *old, struct vcpu *new, unsigned int irq)
{
    unsigned long flags;
    struct pending_irq *p = irq_to_pending(old, irq);

    /* nothing to do for virtual interrupts */
    if ( p->desc == NULL )
        return;

    /* migration already in progress, no need to do anything */
    if ( test_bit(GIC_IRQ_GUEST_MIGRATING, &p->status) )
        return;

    perfc_incr(vgic_irq_migrates);

    spin_lock_irqsave(&old->arch.vgic.lock, flags);

    if ( list_empty(&p->inflight) )
    {
        irq_set_affinity(p->desc, cpumask_of(new->processor));
        spin_unlock_irqrestore(&old->arch.vgic.lock, flags);
        return;
    }
    /* If the IRQ is still lr_pending, re-inject it to the new vcpu */
    if ( !list_empty(&p->lr_queue) )
    {
        clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
        list_del_init(&p->lr_queue);
        list_del_init(&p->inflight);
        irq_set_affinity(p->desc, cpumask_of(new->processor));
        spin_unlock_irqrestore(&old->arch.vgic.lock, flags);
        vgic_vcpu_inject_irq(new, irq);
        return;
    }
    /* if the IRQ is in a GICH_LR register, set GIC_IRQ_GUEST_MIGRATING
     * and wait for the EOI */
    if ( !list_empty(&p->inflight) )
        set_bit(GIC_IRQ_GUEST_MIGRATING, &p->status);

    spin_unlock_irqrestore(&old->arch.vgic.lock, flags);
}

void arch_move_irqs(struct vcpu *v)
{
    const cpumask_t *cpu_mask = cpumask_of(v->processor);
    struct domain *d = v->domain;
    struct pending_irq *p;
    struct vcpu *v_target;
    int i;

    for ( i = 32; i < vgic_num_irqs(d); i++ )
    {
        v_target = vgic_get_target_vcpu(v, i);
        p = irq_to_pending(v_target, i);

        if ( v_target == v && !test_bit(GIC_IRQ_GUEST_MIGRATING, &p->status) )
            irq_set_affinity(p->desc, cpu_mask);
    }
}

void vgic_disable_irqs(struct vcpu *v, uint32_t r, int n)
{
    struct domain *d = v->domain;
    const unsigned long mask = r;
    struct pending_irq *p;
    unsigned int irq;
    unsigned long flags;
    int i = 0;
    struct vcpu *v_target;

    while ( (i = find_next_bit(&mask, 32, i)) < 32 ) {
        irq = i + (32 * n);
        v_target = d->arch.vgic.handler->get_target_vcpu(v, irq);
        p = irq_to_pending(v_target, irq);
        clear_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        gic_remove_from_queues(v_target, irq);
        if ( p->desc != NULL )
        {
            spin_lock_irqsave(&p->desc->lock, flags);
            p->desc->handler->disable(p->desc);
            spin_unlock_irqrestore(&p->desc->lock, flags);
        }
        i++;
    }
}

void vgic_enable_irqs(struct vcpu *v, uint32_t r, int n)
{
    struct domain *d = v->domain;
    const unsigned long mask = r;
    struct pending_irq *p;
    unsigned int irq;
    unsigned long flags;
    int i = 0;
    struct vcpu *v_target;

    while ( (i = find_next_bit(&mask, 32, i)) < 32 ) {
        irq = i + (32 * n);
        v_target = d->arch.vgic.handler->get_target_vcpu(v, irq);
        p = irq_to_pending(v_target, irq);
        set_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        spin_lock_irqsave(&v_target->arch.vgic.lock, flags);
        if ( !list_empty(&p->inflight) && !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
            gic_raise_guest_irq(v_target, irq, p->priority);
        spin_unlock_irqrestore(&v_target->arch.vgic.lock, flags);
        if ( p->desc != NULL )
        {
            irq_set_affinity(p->desc, cpumask_of(v_target->processor));
            spin_lock_irqsave(&p->desc->lock, flags);
            p->desc->handler->enable(p->desc);
            spin_unlock_irqrestore(&p->desc->lock, flags);
        }
        i++;
    }
}

int vgic_to_sgi(struct vcpu *v, register_t sgir, enum gic_sgi_mode irqmode, int virq,
                const struct sgi_target *target)
{
    struct domain *d = v->domain;
    int vcpuid;
    int i;
    unsigned int base;
    unsigned long int bitmap;

    ASSERT( virq < 16 );

    switch ( irqmode )
    {
    case SGI_TARGET_LIST:
        perfc_incr(vgic_sgi_list);
        base = target->aff1 << 4;
        bitmap = target->list;
        for_each_set_bit( i, &bitmap, sizeof(target->list) * 8 )
        {
            vcpuid = base + i;
            if ( d->vcpu[vcpuid] == NULL || !is_vcpu_online(d->vcpu[vcpuid]) )
            {
                gprintk(XENLOG_WARNING, "VGIC: write r=%"PRIregister" \
                        target->list=%hx, wrong CPUTargetList \n",
                        sgir, target->list);
                continue;
            }
            vgic_vcpu_inject_irq(d->vcpu[vcpuid], virq);
        }
        break;
    case SGI_TARGET_OTHERS:
        perfc_incr(vgic_sgi_others);
        for ( i = 0; i < d->max_vcpus; i++ )
        {
            if ( i != current->vcpu_id && d->vcpu[i] != NULL &&
                 is_vcpu_online(d->vcpu[i]) )
                vgic_vcpu_inject_irq(d->vcpu[i], virq);
        }
        break;
    case SGI_TARGET_SELF:
        perfc_incr(vgic_sgi_self);
        vgic_vcpu_inject_irq(d->vcpu[current->vcpu_id], virq);
        break;
    default:
        gprintk(XENLOG_WARNING,
                "vGICD:unhandled GICD_SGIR write %"PRIregister" \
                 with wrong mode\n", sgir);
        return 0;
    }

    return 1;
}

struct pending_irq *irq_to_pending(struct vcpu *v, unsigned int irq)
{
    struct pending_irq *n;
    /* Pending irqs allocation strategy: the first vgic.nr_spis irqs
     * are used for SPIs; the rests are used for per cpu irqs */
    if ( irq < 32 )
        n = &v->arch.vgic.pending_irqs[irq];
    else
        n = &v->domain->arch.vgic.pending_irqs[irq - 32];
    return n;
}

struct pending_irq *spi_to_pending(struct domain *d, unsigned int irq)
{
    ASSERT(irq >= NR_LOCAL_IRQS);

    return &d->arch.vgic.pending_irqs[irq - 32];
}

void vgic_clear_pending_irqs(struct vcpu *v)
{
    struct pending_irq *p, *t;
    unsigned long flags;

    spin_lock_irqsave(&v->arch.vgic.lock, flags);
    list_for_each_entry_safe ( p, t, &v->arch.vgic.inflight_irqs, inflight )
        list_del_init(&p->inflight);
    gic_clear_pending_irqs(v);
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
}

void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int virq)
{
    uint8_t priority;
    struct vgic_irq_rank *rank = vgic_rank_irq(v, virq);
    struct pending_irq *iter, *n = irq_to_pending(v, virq);
    unsigned long flags;
    bool_t running;

    vgic_lock_rank(v, rank, flags);
    priority = v->domain->arch.vgic.handler->get_irq_priority(v, virq);
    vgic_unlock_rank(v, rank, flags);

    spin_lock_irqsave(&v->arch.vgic.lock, flags);

    /* vcpu offline */
    if ( test_bit(_VPF_down, &v->pause_flags) )
    {
        spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
        return;
    }

    set_bit(GIC_IRQ_GUEST_QUEUED, &n->status);

    if ( !list_empty(&n->inflight) )
    {
        gic_raise_inflight_irq(v, virq);
        goto out;
    }

    n->priority = priority;

    /* the irq is enabled */
    if ( test_bit(GIC_IRQ_GUEST_ENABLED, &n->status) )
        gic_raise_guest_irq(v, virq, priority);

    list_for_each_entry ( iter, &v->arch.vgic.inflight_irqs, inflight )
    {
        if ( iter->priority > priority )
        {
            list_add_tail(&n->inflight, &iter->inflight);
            goto out;
        }
    }
    list_add_tail(&n->inflight, &v->arch.vgic.inflight_irqs);
out:
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
    /* we have a new higher priority irq, inject it into the guest */
    running = v->is_running;
    vcpu_unblock(v);
    if ( running && v != current )
    {
        perfc_incr(vgic_cross_cpu_intr_inject);
        smp_send_event_check_mask(cpumask_of(v->processor));
    }
}

void vgic_vcpu_inject_spi(struct domain *d, unsigned int virq)
{
    struct vcpu *v;

    /* the IRQ needs to be an SPI */
    ASSERT(virq >= 32 && virq <= vgic_num_irqs(d));

    v = vgic_get_target_vcpu(d->vcpu[0], virq);
    vgic_vcpu_inject_irq(v, virq);
}

void arch_evtchn_inject(struct vcpu *v)
{
    vgic_vcpu_inject_irq(v, v->domain->arch.evtchn_irq);
}

int vgic_emulate(struct cpu_user_regs *regs, union hsr hsr)
{
    struct vcpu *v = current;

    ASSERT(v->domain->arch.vgic.handler->emulate_sysreg != NULL);

    return v->domain->arch.vgic.handler->emulate_sysreg(regs, hsr);
}

bool_t vgic_reserve_virq(struct domain *d, unsigned int virq)
{
    if ( virq >= vgic_num_irqs(d) )
        return 0;

    return !test_and_set_bit(virq, d->arch.vgic.allocated_irqs);
}

int vgic_allocate_virq(struct domain *d, bool_t spi)
{
    int first, end;
    unsigned int virq;

    if ( !spi )
    {
        /* We only allocate PPIs. SGIs are all reserved */
        first = 16;
        end = 32;
    }
    else
    {
        first = 32;
        end = vgic_num_irqs(d);
    }

    /*
     * There is no spinlock to protect allocated_irqs, therefore
     * test_and_set_bit may fail. If so retry it.
     */
    do
    {
        virq = find_next_zero_bit(d->arch.vgic.allocated_irqs, end, first);
        if ( virq >= end )
            return -1;
    }
    while ( test_and_set_bit(virq, d->arch.vgic.allocated_irqs) );

    return virq;
}

void vgic_free_virq(struct domain *d, unsigned int virq)
{
    clear_bit(virq, d->arch.vgic.allocated_irqs);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

