/*
 * xen/arch/arm/gic-vgic.c
 *
 * ARM Generic Interrupt Controller virtualization support
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

#include <xen/errno.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/domain.h>
#include <asm/gic.h>
#include <asm/vgic.h>

#define lr_all_full() (this_cpu(lr_mask) == ((1 << gic_get_nr_lrs()) - 1))

#undef GIC_DEBUG

static void gic_update_one_lr(struct vcpu *v, int i);

static inline void gic_set_lr(int lr, struct pending_irq *p,
                              unsigned int state)
{
    ASSERT(!local_irq_is_enabled());

    clear_bit(GIC_IRQ_GUEST_PRISTINE_LPI, &p->status);

    gic_hw_ops->update_lr(lr, p->irq, p->priority,
                          p->desc ? p->desc->irq : INVALID_IRQ, state);

    set_bit(GIC_IRQ_GUEST_VISIBLE, &p->status);
    clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
    p->lr = lr;
}

static inline void gic_add_to_lr_pending(struct vcpu *v, struct pending_irq *n)
{
    struct pending_irq *iter;

    ASSERT(spin_is_locked(&v->arch.vgic.lock));

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

void gic_remove_from_lr_pending(struct vcpu *v, struct pending_irq *p)
{
    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    list_del_init(&p->lr_queue);
}

void gic_raise_inflight_irq(struct vcpu *v, unsigned int virtual_irq)
{
    struct pending_irq *n = irq_to_pending(v, virtual_irq);

    /* If an LPI has been removed meanwhile, there is nothing left to raise. */
    if ( unlikely(!n) )
        return;

    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    /* Don't try to update the LR if the interrupt is disabled */
    if ( !test_bit(GIC_IRQ_GUEST_ENABLED, &n->status) )
        return;

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

/*
 * Find an unused LR to insert an IRQ into, starting with the LR given
 * by @lr. If this new interrupt is a PRISTINE LPI, scan the other LRs to
 * avoid inserting the same IRQ twice. This situation can occur when an
 * event gets discarded while the LPI is in an LR, and a new LPI with the
 * same number gets mapped quickly afterwards.
 */
static unsigned int gic_find_unused_lr(struct vcpu *v,
                                       struct pending_irq *p,
                                       unsigned int lr)
{
    unsigned int nr_lrs = gic_get_nr_lrs();
    unsigned long *lr_mask = (unsigned long *) &this_cpu(lr_mask);
    struct gic_lr lr_val;

    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    if ( unlikely(test_bit(GIC_IRQ_GUEST_PRISTINE_LPI, &p->status)) )
    {
        unsigned int used_lr;

        for_each_set_bit(used_lr, lr_mask, nr_lrs)
        {
            gic_hw_ops->read_lr(used_lr, &lr_val);
            if ( lr_val.virq == p->irq )
                return used_lr;
        }
    }

    lr = find_next_zero_bit(lr_mask, nr_lrs, lr);

    return lr;
}

void gic_raise_guest_irq(struct vcpu *v, unsigned int virtual_irq,
        unsigned int priority)
{
    int i;
    unsigned int nr_lrs = gic_get_nr_lrs();
    struct pending_irq *p = irq_to_pending(v, virtual_irq);

    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    if ( unlikely(!p) )
        /* An unmapped LPI does not need to be raised. */
        return;

    if ( v == current && list_empty(&v->arch.vgic.lr_pending) )
    {
        i = gic_find_unused_lr(v, p, 0);

        if (i < nr_lrs) {
            set_bit(i, &this_cpu(lr_mask));
            gic_set_lr(i, p, GICH_LR_PENDING);
            return;
        }
    }

    gic_add_to_lr_pending(v, p);
}

static void gic_update_one_lr(struct vcpu *v, int i)
{
    struct pending_irq *p;
    int irq;
    struct gic_lr lr_val;

    ASSERT(spin_is_locked(&v->arch.vgic.lock));
    ASSERT(!local_irq_is_enabled());

    gic_hw_ops->read_lr(i, &lr_val);
    irq = lr_val.virq;
    p = irq_to_pending(v, irq);
    /*
     * An LPI might have been unmapped, in which case we just clean up here.
     * If that LPI is marked as PRISTINE, the information in the LR is bogus,
     * as it belongs to a previous, already unmapped LPI. So we discard it
     * here as well.
     */
    if ( unlikely(!p ||
                  test_and_clear_bit(GIC_IRQ_GUEST_PRISTINE_LPI, &p->status)) )
    {
        ASSERT(is_lpi(irq));

        gic_hw_ops->clear_lr(i);
        clear_bit(i, &this_cpu(lr_mask));

        return;
    }

    if ( lr_val.active )
    {
        set_bit(GIC_IRQ_GUEST_ACTIVE, &p->status);
        if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) &&
             test_and_clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status) )
        {
            if ( p->desc == NULL )
            {
                lr_val.pending = true;
                gic_hw_ops->write_lr(i, &lr_val);
            }
            else
                gdprintk(XENLOG_WARNING, "unable to inject hw irq=%d into d%dv%d: already active in LR%d\n",
                         irq, v->domain->domain_id, v->vcpu_id, i);
        }
    }
    else if ( lr_val.pending )
    {
        int q __attribute__ ((unused)) = test_and_clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
#ifdef GIC_DEBUG
        if ( q )
            gdprintk(XENLOG_DEBUG, "trying to inject irq=%d into d%dv%d, when it is already pending in LR%d\n",
                    irq, v->domain->domain_id, v->vcpu_id, i);
#endif
    }
    else
    {
        gic_hw_ops->clear_lr(i);
        clear_bit(i, &this_cpu(lr_mask));

        if ( p->desc != NULL )
            clear_bit(_IRQ_INPROGRESS, &p->desc->status);
        clear_bit(GIC_IRQ_GUEST_VISIBLE, &p->status);
        clear_bit(GIC_IRQ_GUEST_ACTIVE, &p->status);
        p->lr = GIC_INVALID_LR;
        if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) &&
             test_bit(GIC_IRQ_GUEST_QUEUED, &p->status) &&
             !test_bit(GIC_IRQ_GUEST_MIGRATING, &p->status) )
            gic_raise_guest_irq(v, irq, p->priority);
        else {
            list_del_init(&p->inflight);
            /*
             * Remove from inflight, then change physical affinity. It
             * makes sure that when a new interrupt is received on the
             * next pcpu, inflight is already cleared. No concurrent
             * accesses to inflight.
             */
            smp_wmb();
            if ( test_bit(GIC_IRQ_GUEST_MIGRATING, &p->status) )
            {
                struct vcpu *v_target = vgic_get_target_vcpu(v, irq);
                irq_set_affinity(p->desc, cpumask_of(v_target->processor));
                clear_bit(GIC_IRQ_GUEST_MIGRATING, &p->status);
            }
        }
    }
}

void vgic_sync_from_lrs(struct vcpu *v)
{
    int i = 0;
    unsigned long flags;
    unsigned int nr_lrs = gic_get_nr_lrs();

    /* The idle domain has no LRs to be cleared. Since gic_restore_state
     * doesn't write any LR registers for the idle domain they could be
     * non-zero. */
    if ( is_idle_vcpu(v) )
        return;

    gic_hw_ops->update_hcr_status(GICH_HCR_UIE, false);

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
    int lr = 0;
    struct pending_irq *p, *t, *p_r;
    struct list_head *inflight_r;
    unsigned long flags;
    unsigned int nr_lrs = gic_get_nr_lrs();
    int lrs = nr_lrs;

    spin_lock_irqsave(&v->arch.vgic.lock, flags);

    if ( list_empty(&v->arch.vgic.lr_pending) )
        goto out;

    inflight_r = &v->arch.vgic.inflight_irqs;
    list_for_each_entry_safe ( p, t, &v->arch.vgic.lr_pending, lr_queue )
    {
        lr = gic_find_unused_lr(v, p, lr);
        if ( lr >= nr_lrs )
        {
            /* No more free LRs: find a lower priority irq to evict */
            list_for_each_entry_reverse( p_r, inflight_r, inflight )
            {
                if ( p_r->priority == p->priority )
                    goto out;
                if ( test_bit(GIC_IRQ_GUEST_VISIBLE, &p_r->status) &&
                     !test_bit(GIC_IRQ_GUEST_ACTIVE, &p_r->status) )
                    goto found;
            }
            /* We didn't find a victim this time, and we won't next
             * time, so quit */
            goto out;

found:
            lr = p_r->lr;
            p_r->lr = GIC_INVALID_LR;
            set_bit(GIC_IRQ_GUEST_QUEUED, &p_r->status);
            clear_bit(GIC_IRQ_GUEST_VISIBLE, &p_r->status);
            gic_add_to_lr_pending(v, p_r);
            inflight_r = &p_r->inflight;
        }

        gic_set_lr(lr, p, GICH_LR_PENDING);
        list_del_init(&p->lr_queue);
        set_bit(lr, &this_cpu(lr_mask));

        /* We can only evict nr_lrs entries */
        lrs--;
        if ( lrs == 0 )
            break;
    }

out:
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
}

void gic_clear_pending_irqs(struct vcpu *v)
{
    struct pending_irq *p, *t;

    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    v->arch.lr_mask = 0;
    list_for_each_entry_safe ( p, t, &v->arch.vgic.lr_pending, lr_queue )
        gic_remove_from_lr_pending(v, p);
}

/**
 * vgic_vcpu_pending_irq() - determine if interrupts need to be injected
 * @vcpu: The vCPU on which to check for interrupts.
 *
 * Checks whether there is an interrupt on the given VCPU which needs
 * handling in the guest. This requires at least one IRQ to be pending
 * and enabled.
 *
 * Returns: 1 if the guest should run to handle interrupts, 0 otherwise.
 */
int vgic_vcpu_pending_irq(struct vcpu *v)
{
    struct pending_irq *p;
    unsigned long flags;
    const unsigned long apr = gic_hw_ops->read_apr(0);
    int mask_priority;
    int active_priority;
    int rc = 0;

    /* We rely on reading the VMCR, which is only accessible locally. */
    ASSERT(v == current);

    mask_priority = gic_hw_ops->read_vmcr_priority();
    active_priority = find_next_bit(&apr, 32, 0);

    spin_lock_irqsave(&v->arch.vgic.lock, flags);

    /* TODO: We order the guest irqs by priority, but we don't change
     * the priority of host irqs. */

    /* find the first enabled non-active irq, the queue is already
     * ordered by priority */
    list_for_each_entry( p, &v->arch.vgic.inflight_irqs, inflight )
    {
        if ( GIC_PRI_TO_GUEST(p->priority) >= mask_priority )
            goto out;
        if ( GIC_PRI_TO_GUEST(p->priority) >= active_priority )
            goto out;
        if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) )
        {
            rc = 1;
            goto out;
        }
    }

out:
    spin_unlock_irqrestore(&v->arch.vgic.lock, flags);
    return rc;
}

void vgic_sync_to_lrs(void)
{
    ASSERT(!local_irq_is_enabled());

    gic_restore_pending_irqs(current);

    if ( !list_empty(&current->arch.vgic.lr_pending) && lr_all_full() )
        gic_hw_ops->update_hcr_status(GICH_HCR_UIE, true);
}

void gic_dump_vgic_info(struct vcpu *v)
{
    struct pending_irq *p;

    list_for_each_entry ( p, &v->arch.vgic.inflight_irqs, inflight )
        printk("Inflight irq=%u lr=%u\n", p->irq, p->lr);

    list_for_each_entry( p, &v->arch.vgic.lr_pending, lr_queue )
        printk("Pending irq=%d\n", p->irq);
}

struct irq_desc *vgic_get_hw_irq_desc(struct domain *d, struct vcpu *v,
                                      unsigned int virq)
{
    struct pending_irq *p;

    ASSERT(!v && virq >= 32);

    if ( !v )
        v = d->vcpu[0];

    p = irq_to_pending(v, virq);
    if ( !p )
        return NULL;

    return p->desc;
}

int vgic_connect_hw_irq(struct domain *d, struct vcpu *v, unsigned int virq,
                        struct irq_desc *desc, bool connect)
{
    unsigned long flags;
    /*
     * Use vcpu0 to retrieve the pending_irq struct. Given that we only
     * route SPIs to guests, it doesn't make any difference.
     */
    struct vcpu *v_target = vgic_get_target_vcpu(d->vcpu[0], virq);
    struct vgic_irq_rank *rank = vgic_rank_irq(v_target, virq);
    struct pending_irq *p = irq_to_pending(v_target, virq);
    int ret = 0;

    /* "desc" is optional when we disconnect an IRQ. */
    ASSERT(connect && desc);

    /* We are taking to rank lock to prevent parallel connections. */
    vgic_lock_rank(v_target, rank, flags);

    if ( connect )
    {
        /* The VIRQ should not be already enabled by the guest */
        if ( !p->desc &&
             !test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) )
            p->desc = desc;
        else
            ret = -EBUSY;
    }
    else
    {
        if ( desc && p->desc != desc )
            ret = -EINVAL;
        else
            p->desc = NULL;
    }

    vgic_unlock_rank(v_target, rank, flags);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
