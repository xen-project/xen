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

/*
 * Returns rank corresponding to a GICD_<FOO><n> register for
 * GICD_<FOO> with <b>-bits-per-interrupt.
 */
struct vgic_irq_rank *vgic_rank_offset(struct vcpu *v, int b, int n,
                                              int s)
{
    int rank = REG_RANK_NR(b, (n >> s));

    if ( rank == 0 )
        return v->arch.vgic.private_irqs;
    else if ( rank <= DOMAIN_NR_RANKS(v->domain) )
        return &v->domain->arch.vgic.shared_irqs[rank - 1];
    else
        return NULL;
}

static struct vgic_irq_rank *vgic_rank_irq(struct vcpu *v, unsigned int irq)
{
    return vgic_rank_offset(v, 8, irq, DABT_WORD);
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
    case GIC_V2:
        if ( vgic_v2_init(d) )
            return -ENODEV;
        break;
    default:
        return -ENODEV;
    }

    d->arch.vgic.shared_irqs =
        xzalloc_array(struct vgic_irq_rank, DOMAIN_NR_RANKS(d));
    if ( d->arch.vgic.shared_irqs == NULL )
        return -ENOMEM;

    d->arch.vgic.pending_irqs =
        xzalloc_array(struct pending_irq, d->arch.vgic.nr_lines);
    if ( d->arch.vgic.pending_irqs == NULL )
    {
        xfree(d->arch.vgic.shared_irqs);
        return -ENOMEM;
    }

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

void vgic_disable_irqs(struct vcpu *v, uint32_t r, int n)
{
    const unsigned long mask = r;
    struct pending_irq *p;
    unsigned int irq;
    unsigned long flags;
    int i = 0;

    while ( (i = find_next_bit(&mask, 32, i)) < 32 ) {
        irq = i + (32 * n);
        p = irq_to_pending(v, irq);
        clear_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        gic_remove_from_queues(v, irq);
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
    const unsigned long mask = r;
    struct pending_irq *p;
    unsigned int irq;
    unsigned long flags;
    int i = 0;

    while ( (i = find_next_bit(&mask, 32, i)) < 32 ) {
        irq = i + (32 * n);
        p = irq_to_pending(v, irq);
        set_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        /* We need to force the first injection of evtchn_irq because
         * evtchn_upcall_pending is already set by common code on vcpu
         * creation. */
        if ( irq == v->domain->arch.evtchn_irq &&
             vcpu_info(current, evtchn_upcall_pending) &&
             list_empty(&p->inflight) )
            vgic_vcpu_inject_irq(v, irq);
        else {
            unsigned long flags;
            spin_lock_irqsave(&v->arch.vgic.lock, flags);
            if ( !list_empty(&p->inflight) && !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
                gic_raise_guest_irq(v, irq, p->priority);
            spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
        }
        if ( p->desc != NULL )
        {
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

    spin_lock_irqsave(&v->arch.vgic.lock, flags);

    if ( !list_empty(&n->inflight) )
    {
        set_bit(GIC_IRQ_GUEST_QUEUED, &n->status);
        gic_raise_inflight_irq(v, irq);
        goto out;
    }

    /* vcpu offline */
    if ( test_bit(_VPF_down, &v->pause_flags) )
    {
        spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
        return;
    }

    priority = vgic_byte_read(rank->ipriority[REG_RANK_INDEX(8, irq, DABT_WORD)], 0, irq & 0x3);

    n->irq = irq;
    set_bit(GIC_IRQ_GUEST_QUEUED, &n->status);
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

