/*
 * Copyright (C) 2015, 2016 ARM Ltd.
 * Imported from Linux ("new" KVM VGIC) and heavily adapted to Xen.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/list_sort.h>
#include <xen/sched.h>
#include <asm/bug.h>
#include <asm/event.h>
#include <asm/new_vgic.h>

#include "vgic.h"

/*
 * Locking order is always:
 *   vgic->lock
 *     vgic_cpu->ap_list_lock
 *       vgic->lpi_list_lock
 *         desc->lock
 *           vgic_irq->irq_lock
 *
 * If you need to take multiple locks, always take the upper lock first,
 * then the lower ones, e.g. first take the ap_list_lock, then the irq_lock.
 * If you are already holding a lock and need to take a higher one, you
 * have to drop the lower ranking lock first and re-acquire it after having
 * taken the upper one.
 *
 * When taking more than one ap_list_lock at the same time, always take the
 * lowest numbered VCPU's ap_list_lock first, so:
 *   vcpuX->vcpu_id < vcpuY->vcpu_id:
 *     spin_lock(vcpuX->arch.vgic.ap_list_lock);
 *     spin_lock(vcpuY->arch.vgic.ap_list_lock);
 *
 * Since the VGIC must support injecting virtual interrupts from ISRs, we have
 * to use the spin_lock_irqsave/spin_unlock_irqrestore versions of outer
 * spinlocks for any lock that may be taken while injecting an interrupt.
 */

/*
 * Iterate over the VM's list of mapped LPIs to find the one with a
 * matching interrupt ID and return a reference to the IRQ structure.
 *
 * TODO: This is more documentation of how it should be done. A list is
 * not a good data structure for Dom0's LPIs, it merely serves as an
 * example here how to properly do the locking, allocation and refcounting.
 * So lpi_list_head should be replaced with something more appropriate.
 */
static struct vgic_irq *vgic_get_lpi(struct domain *d, uint32_t intid)
{
    struct vgic_dist *dist = &d->arch.vgic;
    struct vgic_irq *irq = NULL;

    spin_lock(&dist->lpi_list_lock);

    list_for_each_entry( irq, &dist->lpi_list_head, lpi_list )
    {
        if ( irq->intid != intid )
            continue;

        /*
         * This increases the refcount, the caller is expected to
         * call vgic_put_irq() later once it's finished with the IRQ.
         */
        vgic_get_irq_kref(irq);
        goto out_unlock;
    }
    irq = NULL;

out_unlock:
    spin_unlock(&dist->lpi_list_lock);

    return irq;
}

/**
 * vgic_get_irq() - obtain a reference to a virtual IRQ
 * @d:        The domain the virtual IRQ belongs to.
 * @vcpu:     For private IRQs (SGIs, PPIs) the virtual CPU this IRQ
 *            is associated with. Will be ignored for SPIs and LPIs.
 * @intid:    The virtual IRQ number.
 *
 * This looks up the virtual interrupt ID to get the corresponding
 * struct vgic_irq. It also increases the refcount, so any caller is expected
 * to call vgic_put_irq() once it's finished with this IRQ.
 *
 * Return: The pointer to the requested struct vgic_irq.
 */
struct vgic_irq *vgic_get_irq(struct domain *d, struct vcpu *vcpu,
                              uint32_t intid)
{
    /* SGIs and PPIs */
    if ( intid <= VGIC_MAX_PRIVATE )
        return &vcpu->arch.vgic.private_irqs[intid];

    /* SPIs */
    if ( intid <= VGIC_MAX_SPI )
        return &d->arch.vgic.spis[intid - VGIC_NR_PRIVATE_IRQS];

    /* LPIs */
    if ( intid >= VGIC_MIN_LPI )
        return vgic_get_lpi(d, intid);

    ASSERT_UNREACHABLE();

    return NULL;
}

/**
 * vgic_put_irq() - drop the reference to a virtual IRQ
 * @d:        The domain the virtual IRQ belongs to.
 * @irq:      The pointer to struct vgic_irq, as obtained from vgic_get_irq().
 *
 * This drops the reference to a virtual IRQ. It decreases the refcount
 * of the pointer, so dynamic IRQs can be freed when no longer needed.
 * This should always be called after a vgic_get_irq(), though the reference
 * can be deliberately held for longer periods, if needed.
 *
 * TODO: A linked list is not a good data structure for LPIs in Dom0.
 * Replace this with proper data structure once we get proper LPI support.
 */
void vgic_put_irq(struct domain *d, struct vgic_irq *irq)
{
    struct vgic_dist *dist = &d->arch.vgic;

    if ( irq->intid < VGIC_MIN_LPI )
        return;

    spin_lock(&dist->lpi_list_lock);
    if ( !atomic_dec_and_test(&irq->refcount) )
    {
        spin_unlock(&dist->lpi_list_lock);
        return;
    };

    list_del(&irq->lpi_list);
    dist->lpi_list_count--;
    spin_unlock(&dist->lpi_list_lock);

    xfree(irq);
}

/**
 * vgic_target_oracle() - compute the target vcpu for an irq
 * @irq:    The irq to route. Must be already locked.
 *
 * Based on the current state of the interrupt (enabled, pending,
 * active, vcpu and target_vcpu), compute the next vcpu this should be
 * given to. Return NULL if this shouldn't be injected at all.
 *
 * Requires the IRQ lock to be held.
 *
 * Returns: The pointer to the virtual CPU this interrupt should be injected
 *          to. Will be NULL if this IRQ does not need to be injected.
 */
static struct vcpu *vgic_target_oracle(struct vgic_irq *irq)
{
    ASSERT(spin_is_locked(&irq->irq_lock));

    /* If the interrupt is active, it must stay on the current vcpu */
    if ( irq->active )
        return irq->vcpu ? : irq->target_vcpu;

    /*
     * If the IRQ is not active but enabled and pending, we should direct
     * it to its configured target VCPU.
     * If the distributor is disabled, pending interrupts shouldn't be
     * forwarded.
     */
    if ( irq->enabled && irq_is_pending(irq) )
    {
        if ( unlikely(irq->target_vcpu &&
                      !irq->target_vcpu->domain->arch.vgic.enabled) )
            return NULL;

        return irq->target_vcpu;
    }

    /*
     * If neither active nor pending and enabled, then this IRQ should not
     * be queued to any VCPU.
     */
    return NULL;
}

/*
 * The order of items in the ap_lists defines how we'll pack things in LRs as
 * well, the first items in the list being the first things populated in the
 * LRs.
 *
 * A hard rule is that active interrupts can never be pushed out of the LRs
 * (and therefore take priority) since we cannot reliably trap on deactivation
 * of IRQs and therefore they have to be present in the LRs.
 *
 * Otherwise things should be sorted by the priority field and the GIC
 * hardware support will take care of preemption of priority groups etc.
 *
 * Return negative if "a" sorts before "b", 0 to preserve order, and positive
 * to sort "b" before "a".
 */
static int vgic_irq_cmp(void *priv, struct list_head *a, struct list_head *b)
{
    struct vgic_irq *irqa = container_of(a, struct vgic_irq, ap_list);
    struct vgic_irq *irqb = container_of(b, struct vgic_irq, ap_list);
    bool penda, pendb;
    int ret;

    spin_lock(&irqa->irq_lock);
    spin_lock(&irqb->irq_lock);

    if ( irqa->active || irqb->active )
    {
        ret = (int)irqb->active - (int)irqa->active;
        goto out;
    }

    penda = irqa->enabled && irq_is_pending(irqa);
    pendb = irqb->enabled && irq_is_pending(irqb);

    if ( !penda || !pendb )
    {
        ret = (int)pendb - (int)penda;
        goto out;
    }

    /* Both pending and enabled, sort by priority */
    ret = irqa->priority - irqb->priority;
out:
    spin_unlock(&irqb->irq_lock);
    spin_unlock(&irqa->irq_lock);
    return ret;
}

/* Must be called with the ap_list_lock held */
static void vgic_sort_ap_list(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;

    ASSERT(spin_is_locked(&vgic_cpu->ap_list_lock));

    list_sort(NULL, &vgic_cpu->ap_list_head, vgic_irq_cmp);
}

/*
 * Only valid injection if changing level for level-triggered IRQs or for a
 * rising edge.
 */
static bool vgic_validate_injection(struct vgic_irq *irq, bool level)
{
    /* For edge interrupts we only care about a rising edge. */
    if ( irq->config == VGIC_CONFIG_EDGE )
        return level;

    /* For level interrupts we have to act when the line level changes. */
    return irq->line_level != level;
}

/**
 * vgic_queue_irq_unlock() - Queue an IRQ to a VCPU, to be injected to a guest.
 * @d:        The domain the virtual IRQ belongs to.
 * @irq:      A pointer to the vgic_irq of the virtual IRQ, with the lock held.
 * @flags:    The flags used when having grabbed the IRQ lock.
 *
 * Check whether an IRQ needs to (and can) be queued to a VCPU's ap list.
 * Do the queuing if necessary, taking the right locks in the right order.
 *
 * Needs to be entered with the IRQ lock already held, but will return
 * with all locks dropped.
 */
void vgic_queue_irq_unlock(struct domain *d, struct vgic_irq *irq,
                           unsigned long flags)
{
    struct vcpu *vcpu;

    ASSERT(spin_is_locked(&irq->irq_lock));

retry:
    vcpu = vgic_target_oracle(irq);
    if ( irq->vcpu || !vcpu )
    {
        /*
         * If this IRQ is already on a VCPU's ap_list, then it
         * cannot be moved or modified and there is no more work for
         * us to do.
         *
         * Otherwise, if the irq is not pending and enabled, it does
         * not need to be inserted into an ap_list and there is also
         * no more work for us to do.
         */
        spin_unlock_irqrestore(&irq->irq_lock, flags);

        /*
         * We have to kick the VCPU here, because we could be
         * queueing an edge-triggered interrupt for which we
         * get no EOI maintenance interrupt. In that case,
         * while the IRQ is already on the VCPU's AP list, the
         * VCPU could have EOI'ed the original interrupt and
         * won't see this one until it exits for some other
         * reason.
         */
        if ( vcpu )
            vcpu_kick(vcpu);

        return;
    }

    /*
     * We must unlock the irq lock to take the ap_list_lock where
     * we are going to insert this new pending interrupt.
     */
    spin_unlock_irqrestore(&irq->irq_lock, flags);

    /* someone can do stuff here, which we re-check below */

    spin_lock_irqsave(&vcpu->arch.vgic.ap_list_lock, flags);
    spin_lock(&irq->irq_lock);

    /*
     * Did something change behind our backs?
     *
     * There are two cases:
     * 1) The irq lost its pending state or was disabled behind our
     *    backs and/or it was queued to another VCPU's ap_list.
     * 2) Someone changed the affinity on this irq behind our
     *    backs and we are now holding the wrong ap_list_lock.
     *
     * In both cases, drop the locks and retry.
     */

    if ( unlikely(irq->vcpu || vcpu != vgic_target_oracle(irq)) )
    {
        spin_unlock(&irq->irq_lock);
        spin_unlock_irqrestore(&vcpu->arch.vgic.ap_list_lock, flags);

        spin_lock_irqsave(&irq->irq_lock, flags);
        goto retry;
    }

    /*
     * Grab a reference to the irq to reflect the fact that it is
     * now in the ap_list.
     */
    vgic_get_irq_kref(irq);
    list_add_tail(&irq->ap_list, &vcpu->arch.vgic.ap_list_head);
    irq->vcpu = vcpu;

    spin_unlock(&irq->irq_lock);
    spin_unlock_irqrestore(&vcpu->arch.vgic.ap_list_lock, flags);

    vcpu_kick(vcpu);

    return;
}

/**
 * vgic_inject_irq() - Inject an IRQ from a device to the vgic
 * @d:       The domain pointer
 * @vcpu:    The vCPU for private IRQs (PPIs, SGIs). Ignored for SPIs and LPIs.
 * @intid:   The INTID to inject a new state to.
 * @level:   Edge-triggered:  true:  to trigger the interrupt
 *                            false: to ignore the call
 *           Level-sensitive  true:  raise the input signal
 *                            false: lower the input signal
 *
 * Injects an instance of the given virtual IRQ into a domain.
 * The VGIC is not concerned with devices being active-LOW or active-HIGH for
 * level-sensitive interrupts.  You can think of the level parameter as 1
 * being HIGH and 0 being LOW and all devices being active-HIGH.
 */
void vgic_inject_irq(struct domain *d, struct vcpu *vcpu, unsigned int intid,
                     bool level)
{
    struct vgic_irq *irq;
    unsigned long flags;

    irq = vgic_get_irq(d, vcpu, intid);
    if ( !irq )
        return;

    spin_lock_irqsave(&irq->irq_lock, flags);

    if ( !vgic_validate_injection(irq, level) )
    {
        /* Nothing to see here, move along... */
        spin_unlock_irqrestore(&irq->irq_lock, flags);
        vgic_put_irq(d, irq);
        return;
    }

    if ( irq->config == VGIC_CONFIG_LEVEL )
        irq->line_level = level;
    else
        irq->pending_latch = true;

    vgic_queue_irq_unlock(d, irq, flags);
    vgic_put_irq(d, irq);

    return;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
