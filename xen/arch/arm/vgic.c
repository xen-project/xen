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

int domain_vgic_init(struct domain *d)
{
    int i;

    d->arch.vgic.ctlr = 0;

    /* Currently nr_lines in vgic and gic doesn't have the same meanings
     * Here nr_lines = number of SPIs
     */
    if ( is_hardware_domain(d) )
        d->arch.vgic.nr_lines = gic_number_lines() - 32;
    else
        d->arch.vgic.nr_lines = 0; /* We don't need SPIs for the guest */

    switch ( gic_hw_version() )
    {
#ifdef CONFIG_ARM_64
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
        return -ENODEV;
    }

    spin_lock_init(&d->arch.vgic.lock);

    d->arch.vgic.shared_irqs =
        xzalloc_array(struct vgic_irq_rank, DOMAIN_NR_RANKS(d));
    if ( d->arch.vgic.shared_irqs == NULL )
        return -ENOMEM;

    d->arch.vgic.pending_irqs =
        xzalloc_array(struct pending_irq, d->arch.vgic.nr_lines);
    if ( d->arch.vgic.pending_irqs == NULL )
        return -ENOMEM;

    for (i=0; i<d->arch.vgic.nr_lines; i++)
    {
        INIT_LIST_HEAD(&d->arch.vgic.pending_irqs[i].inflight);
        INIT_LIST_HEAD(&d->arch.vgic.pending_irqs[i].lr_queue);
    }
    for (i=0; i<DOMAIN_NR_RANKS(d); i++)
        spin_lock_init(&d->arch.vgic.shared_irqs[i].lock);

    d->arch.vgic.handler->domain_init(d);

    return 0;
}

void register_vgic_ops(struct domain *d, const struct vgic_ops *ops)
{
   d->arch.vgic.handler = ops;
}

void domain_vgic_free(struct domain *d)
{
    xfree(d->arch.vgic.shared_irqs);
    xfree(d->arch.vgic.pending_irqs);
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
    {
        INIT_LIST_HEAD(&v->arch.vgic.pending_irqs[i].inflight);
        INIT_LIST_HEAD(&v->arch.vgic.pending_irqs[i].lr_queue);
    }

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

    for ( i = 32; i < (d->arch.vgic.nr_lines + 32); i++ )
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

/* TODO: unsigned long is used to fit vcpu_mask.*/
int vgic_to_sgi(struct vcpu *v, register_t sgir, enum gic_sgi_mode irqmode, int virq,
                unsigned long vcpu_mask)
{
    struct domain *d = v->domain;
    int vcpuid;
    int i;

    ASSERT(d->max_vcpus < 8*sizeof(vcpu_mask));

    ASSERT( virq < 16 );

    switch ( irqmode )
    {
    case SGI_TARGET_LIST:
        break;
    case SGI_TARGET_OTHERS:
        /*
         * We expect vcpu_mask to be 0 for SGI_TARGET_OTHERS and
         * SGI_TARGET_SELF mode. So Force vcpu_mask to 0
         */
        vcpu_mask = 0;
        for ( i = 0; i < d->max_vcpus; i++ )
        {
            if ( i != current->vcpu_id && d->vcpu[i] != NULL &&
                 is_vcpu_online(d->vcpu[i]) )
                set_bit(i, &vcpu_mask);
        }
        break;
    case SGI_TARGET_SELF:
        /*
         * We expect vcpu_mask to be 0 for SGI_TARGET_OTHERS and
         * SGI_TARGET_SELF mode. So Force vcpu_mask to 0
         */
        vcpu_mask = 0;
        set_bit(current->vcpu_id, &vcpu_mask);
        break;
    default:
        gdprintk(XENLOG_WARNING,
                 "vGICD:unhandled GICD_SGIR write %"PRIregister" \
                  with wrong mode\n", sgir);
        return 0;
    }

    for_each_set_bit( vcpuid, &vcpu_mask, d->max_vcpus )
    {
        if ( d->vcpu[vcpuid] != NULL && !is_vcpu_online(d->vcpu[vcpuid]) )
        {
            gdprintk(XENLOG_WARNING, "VGIC: write r=%"PRIregister" \
                     vcpu_mask=%lx, wrong CPUTargetList\n", sgir, vcpu_mask);
            continue;
        }
        vgic_vcpu_inject_irq(d->vcpu[vcpuid], virq);
    }
    return 1;
}

struct pending_irq *irq_to_pending(struct vcpu *v, unsigned int irq)
{
    struct pending_irq *n;
    /* Pending irqs allocation strategy: the first vgic.nr_lines irqs
     * are used for SPIs; the rests are used for per cpu irqs */
    if ( irq < 32 )
        n = &v->arch.vgic.pending_irqs[irq];
    else
        n = &v->domain->arch.vgic.pending_irqs[irq - 32];
    return n;
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

void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int irq)
{
    uint8_t priority;
    struct vgic_irq_rank *rank = vgic_rank_irq(v, irq);
    struct pending_irq *iter, *n = irq_to_pending(v, irq);
    unsigned long flags;
    bool_t running;

    vgic_lock_rank(v, rank, flags);
    priority = v->domain->arch.vgic.handler->get_irq_priority(v, irq);
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
        gic_raise_inflight_irq(v, irq);
        goto out;
    }

    n->irq = irq;
    n->priority = priority;

    /* the irq is enabled */
    if ( test_bit(GIC_IRQ_GUEST_ENABLED, &n->status) )
        gic_raise_guest_irq(v, irq, priority);

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
        smp_send_event_check_mask(cpumask_of(v->processor));
}

void vgic_vcpu_inject_spi(struct domain *d, unsigned int irq)
{
    struct vcpu *v;

    /* the IRQ needs to be an SPI */
    ASSERT(irq >= 32 && irq <= gic_number_lines());

    v = vgic_get_target_vcpu(d->vcpu[0], irq);
    vgic_vcpu_inject_irq(v, irq);
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

