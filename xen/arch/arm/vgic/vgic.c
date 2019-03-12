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

/**
 * vgic_prune_ap_list() - Remove non-relevant interrupts from the ap_list
 *
 * @vcpu:       The VCPU of which the ap_list should be pruned.
 *
 * Go over the list of interrupts on a VCPU's ap_list, and prune those that
 * we won't have to consider in the near future.
 * This removes interrupts that have been successfully handled by the guest,
 * or that have otherwise became obsolete (not pending anymore).
 * Also this moves interrupts between VCPUs, if their affinity has changed.
 */
static void vgic_prune_ap_list(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;
    struct vgic_irq *irq, *tmp;
    unsigned long flags;

retry:
    spin_lock_irqsave(&vgic_cpu->ap_list_lock, flags);

    list_for_each_entry_safe( irq, tmp, &vgic_cpu->ap_list_head, ap_list )
    {
        struct vcpu *target_vcpu, *vcpuA, *vcpuB;

        spin_lock(&irq->irq_lock);

        BUG_ON(vcpu != irq->vcpu);

        target_vcpu = vgic_target_oracle(irq);

        if ( !target_vcpu )
        {
            /*
             * We don't need to process this interrupt any
             * further, move it off the list.
             */
            list_del(&irq->ap_list);
            irq->vcpu = NULL;
            spin_unlock(&irq->irq_lock);

            /*
             * This vgic_put_irq call matches the
             * vgic_get_irq_kref in vgic_queue_irq_unlock,
             * where we added the LPI to the ap_list. As
             * we remove the irq from the list, we drop
             * also drop the refcount.
             */
            vgic_put_irq(vcpu->domain, irq);
            continue;
        }

        if ( target_vcpu == vcpu )
        {
            /* We're on the right CPU */
            spin_unlock(&irq->irq_lock);
            continue;
        }

        /* This interrupt looks like it has to be migrated. */

        spin_unlock(&irq->irq_lock);
        spin_unlock_irqrestore(&vgic_cpu->ap_list_lock, flags);

        /*
         * Ensure locking order by always locking the smallest
         * ID first.
         */
        if ( vcpu->vcpu_id < target_vcpu->vcpu_id )
        {
            vcpuA = vcpu;
            vcpuB = target_vcpu;
        }
        else
        {
            vcpuA = target_vcpu;
            vcpuB = vcpu;
        }

        spin_lock_irqsave(&vcpuA->arch.vgic.ap_list_lock, flags);
        spin_lock(&vcpuB->arch.vgic.ap_list_lock);
        spin_lock(&irq->irq_lock);

        /*
         * If the affinity has been preserved, move the
         * interrupt around. Otherwise, it means things have
         * changed while the interrupt was unlocked, and we
         * need to replay this.
         *
         * In all cases, we cannot trust the list not to have
         * changed, so we restart from the beginning.
         */
        if ( target_vcpu == vgic_target_oracle(irq) )
        {
            struct vgic_cpu *new_cpu = &target_vcpu->arch.vgic;

            list_del(&irq->ap_list);
            irq->vcpu = target_vcpu;
            list_add_tail(&irq->ap_list, &new_cpu->ap_list_head);
        }

        spin_unlock(&irq->irq_lock);
        spin_unlock(&vcpuB->arch.vgic.ap_list_lock);
        spin_unlock_irqrestore(&vcpuA->arch.vgic.ap_list_lock, flags);
        goto retry;
    }

    spin_unlock_irqrestore(&vgic_cpu->ap_list_lock, flags);
}

static void vgic_fold_lr_state(struct vcpu *vcpu)
{
    vgic_v2_fold_lr_state(vcpu);
}

/* Requires the irq_lock to be held. */
static void vgic_populate_lr(struct vcpu *vcpu,
                             struct vgic_irq *irq, int lr)
{
    ASSERT(spin_is_locked(&irq->irq_lock));

    vgic_v2_populate_lr(vcpu, irq, lr);
}

static void vgic_set_underflow(struct vcpu *vcpu)
{
    ASSERT(vcpu == current);

    gic_hw_ops->update_hcr_status(GICH_HCR_UIE, true);
}

/* Requires the ap_list_lock to be held. */
static int compute_ap_list_depth(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;
    struct vgic_irq *irq;
    int count = 0;

    ASSERT(spin_is_locked(&vgic_cpu->ap_list_lock));

    list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list)
        count++;

    return count;
}

/* Requires the VCPU's ap_list_lock to be held. */
static void vgic_flush_lr_state(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;
    struct vgic_irq *irq;
    int count = 0;

    ASSERT(spin_is_locked(&vgic_cpu->ap_list_lock));

    if ( compute_ap_list_depth(vcpu) > gic_get_nr_lrs() )
        vgic_sort_ap_list(vcpu);

    list_for_each_entry( irq, &vgic_cpu->ap_list_head, ap_list )
    {
        spin_lock(&irq->irq_lock);

        if ( likely(vgic_target_oracle(irq) == vcpu) )
            vgic_populate_lr(vcpu, irq, count++);

        spin_unlock(&irq->irq_lock);

        if ( count == gic_get_nr_lrs() )
        {
            if ( !list_is_last(&irq->ap_list, &vgic_cpu->ap_list_head) )
                vgic_set_underflow(vcpu);
            break;
        }
    }

    vcpu->arch.vgic.used_lrs = count;
}

/**
 * vgic_sync_from_lrs() - Update VGIC state from hardware after a guest's run.
 * @vcpu: the VCPU for which to transfer from the LRs to the IRQ list.
 *
 * Sync back the hardware VGIC state after the guest has run, into our
 * VGIC emulation structures, It reads the LRs and updates the respective
 * struct vgic_irq, taking level/edge into account.
 * This is the high level function which takes care of the conditions,
 * also bails out early if there were no interrupts queued.
 * Was: kvm_vgic_sync_hwstate()
 */
void vgic_sync_from_lrs(struct vcpu *vcpu)
{
    /* An empty ap_list_head implies used_lrs == 0 */
    if ( list_empty(&vcpu->arch.vgic.ap_list_head) )
        return;

    vgic_fold_lr_state(vcpu);

    vgic_prune_ap_list(vcpu);
}

/**
 * vgic_sync_to_lrs() - flush emulation state into the hardware on guest entry
 *
 * Before we enter a guest, we have to translate the virtual GIC state of a
 * VCPU into the GIC virtualization hardware registers, namely the LRs.
 * This is the high level function which takes care about the conditions
 * and the locking, also bails out early if there are no interrupts queued.
 * Was: kvm_vgic_flush_hwstate()
 */
void vgic_sync_to_lrs(void)
{
    /*
     * If there are no virtual interrupts active or pending for this
     * VCPU, then there is no work to do and we can bail out without
     * taking any lock.  There is a potential race with someone injecting
     * interrupts to the VCPU, but it is a benign race as the VCPU will
     * either observe the new interrupt before or after doing this check,
     * and introducing additional synchronization mechanism doesn't change
     * this.
     */
    if ( list_empty(&current->arch.vgic.ap_list_head) )
        return;

    ASSERT(!local_irq_is_enabled());

    spin_lock(&current->arch.vgic.ap_list_lock);
    vgic_flush_lr_state(current);
    spin_unlock(&current->arch.vgic.ap_list_lock);

    gic_hw_ops->update_hcr_status(GICH_HCR_EN, 1);
}

/**
 * vgic_vcpu_pending_irq() - determine if interrupts need to be injected
 * @vcpu: The vCPU on which to check for interrupts.
 *
 * Checks whether there is an interrupt on the given VCPU which needs
 * handling in the guest. This requires at least one IRQ to be pending
 * and enabled.
 *
 * Returns: > 0 if the guest should run to handle interrupts, 0 otherwise.
 */
int vgic_vcpu_pending_irq(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;
    struct vgic_irq *irq;
    unsigned long flags;
    int ret = 0;

    if ( !vcpu->domain->arch.vgic.enabled )
        return 0;

    spin_lock_irqsave(&vgic_cpu->ap_list_lock, flags);

    list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list)
    {
        spin_lock(&irq->irq_lock);
        ret = irq_is_pending(irq) && irq->enabled;
        spin_unlock(&irq->irq_lock);

        if ( ret )
            break;
    }

    spin_unlock_irqrestore(&vgic_cpu->ap_list_lock, flags);

    return ret;
}

void vgic_kick_vcpus(struct domain *d)
{
    struct vcpu *vcpu;

    /*
     * We've injected an interrupt, time to find out who deserves
     * a good kick...
     */
    for_each_vcpu( d, vcpu )
    {
        if ( vgic_vcpu_pending_irq(vcpu) )
            vcpu_kick(vcpu);
    }
}

bool vgic_evtchn_irq_pending(struct vcpu *v)
{
    struct vgic_irq *irq;
    unsigned long flags;
    bool pending;

    /* Does not work for LPIs. */
    ASSERT(!is_lpi(v->domain->arch.evtchn_irq));

    irq = vgic_get_irq(v->domain, v, v->domain->arch.evtchn_irq);
    spin_lock_irqsave(&irq->irq_lock, flags);
    pending = irq_is_pending(irq);
    spin_unlock_irqrestore(&irq->irq_lock, flags);
    vgic_put_irq(v->domain, irq);

    return pending;
}

bool vgic_reserve_virq(struct domain *d, unsigned int virq)
{
    if ( virq >= vgic_num_irqs(d) )
        return false;

    return !test_and_set_bit(virq, d->arch.vgic.allocated_irqs);
}

int vgic_allocate_virq(struct domain *d, bool spi)
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
    } while ( test_and_set_bit(virq, d->arch.vgic.allocated_irqs) );

    return virq;
}

void vgic_free_virq(struct domain *d, unsigned int virq)
{
    clear_bit(virq, d->arch.vgic.allocated_irqs);
}

void gic_dump_vgic_info(struct vcpu *v)
{
    struct vgic_cpu *vgic_cpu = &v->arch.vgic;
    struct vgic_irq *irq;
    unsigned long flags;

    spin_lock_irqsave(&v->arch.vgic.ap_list_lock, flags);

    if ( !list_empty(&vgic_cpu->ap_list_head) )
        printk("   active or pending interrupts queued:\n");

    list_for_each_entry ( irq, &vgic_cpu->ap_list_head, ap_list )
    {
        spin_lock(&irq->irq_lock);
        printk("     %s %s irq %u: %spending, %sactive, %senabled\n",
               irq->hw ? "hardware" : "virtual",
               irq->config == VGIC_CONFIG_LEVEL ? "level" : "edge",
               irq->intid, irq_is_pending(irq) ? "" : "not ",
               irq->active ? "" : "not ", irq->enabled ? "" : "not ");
        spin_unlock(&irq->irq_lock);
    }

    spin_unlock_irqrestore(&v->arch.vgic.ap_list_lock, flags);
}

void vgic_clear_pending_irqs(struct vcpu *v)
{
    /*
     * TODO: It is unclear whether we really need this, so we might instead
     * remove it on the caller site.
     */
}

/**
 * arch_move_irqs() - migrate the physical affinity of hardware mapped vIRQs
 * @v:  the vCPU, already assigned to the new pCPU
 *
 * arch_move_irqs() updates the physical affinity of all virtual IRQs
 * targetting this given vCPU. This only affects hardware mapped IRQs. The
 * new pCPU to target is already set in v->processor.
 * This is called by the core code after a vCPU has been migrated to a new
 * physical CPU.
 */
void arch_move_irqs(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned int i;

    /* We only target SPIs with this function */
    for ( i = 0; i < d->arch.vgic.nr_spis; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(d, NULL, i + VGIC_NR_PRIVATE_IRQS);
        unsigned long flags;

        if ( !irq )
            continue;

        spin_lock_irqsave(&irq->irq_lock, flags);

        /* Only hardware mapped vIRQs that are targeting this vCPU. */
        if ( irq->hw && irq->target_vcpu == v)
        {
            irq_desc_t *desc = irq_to_desc(irq->hwintid);

            irq_set_affinity(desc, cpumask_of(v->processor));
        }

        spin_unlock_irqrestore(&irq->irq_lock, flags);
        vgic_put_irq(d, irq);
    }
}

struct irq_desc *vgic_get_hw_irq_desc(struct domain *d, struct vcpu *v,
                                      unsigned int virq)
{
    struct irq_desc *desc = NULL;
    struct vgic_irq *irq = vgic_get_irq(d, v, virq);
    unsigned long flags;

    if ( !irq )
        return NULL;

    spin_lock_irqsave(&irq->irq_lock, flags);
    if ( irq->hw )
    {
        ASSERT(irq->hwintid >= VGIC_NR_PRIVATE_IRQS);
        desc = irq_to_desc(irq->hwintid);
    }
    spin_unlock_irqrestore(&irq->irq_lock, flags);

    vgic_put_irq(d, irq);

    return desc;
}

bool vgic_emulate(struct cpu_user_regs *regs, union hsr hsr)
{
    ASSERT(current->domain->arch.vgic.version == GIC_V3);

    return false;
}

/*
 * was:
 *      int kvm_vgic_map_phys_irq(struct vcpu *vcpu, u32 virt_irq, u32 phys_irq)
 *      int kvm_vgic_unmap_phys_irq(struct vcpu *vcpu, unsigned int virt_irq)
 */
int vgic_connect_hw_irq(struct domain *d, struct vcpu *vcpu,
                        unsigned int virt_irq, struct irq_desc *desc,
                        bool connect)
{
    struct vgic_irq *irq = vgic_get_irq(d, vcpu, virt_irq);
    unsigned long flags;
    int ret = 0;

    if ( !irq )
        return -EINVAL;

    spin_lock_irqsave(&irq->irq_lock, flags);

    if ( connect )                      /* assign a mapped IRQ */
    {
        /* The VIRQ should not be already enabled by the guest */
        if ( !irq->hw && !irq->enabled )
        {
            irq->hw = true;
            irq->hwintid = desc->irq;
        }
        else
            ret = -EBUSY;
    }
    else                                /* remove a mapped IRQ */
    {
        if ( desc && irq->hwintid != desc->irq )
        {
            ret = -EINVAL;
        }
        else
        {
            irq->hw = false;
            irq->hwintid = 0;
        }
    }

    spin_unlock_irqrestore(&irq->irq_lock, flags);
    vgic_put_irq(d, irq);

    return ret;
}

static unsigned int translate_irq_type(bool is_level)
{
    return is_level ? IRQ_TYPE_LEVEL_HIGH : IRQ_TYPE_EDGE_RISING;
}

void vgic_sync_hardware_irq(struct domain *d,
                            irq_desc_t *desc, struct vgic_irq *irq)
{
    unsigned long flags;

    spin_lock_irqsave(&desc->lock, flags);
    spin_lock(&irq->irq_lock);

    /*
     * We forbid tinkering with the hardware IRQ association during
     * a domain's lifetime.
     */
    ASSERT(irq->hw && desc->irq == irq->hwintid);

    if ( irq->enabled )
    {
        /*
         * We might end up from various callers, so check that the
         * interrrupt is disabled before trying to change the config.
         */
        if ( irq_type_set_by_domain(d) &&
             test_bit(_IRQ_DISABLED, &desc->status) )
            gic_set_irq_type(desc, translate_irq_type(irq->config));

        if ( irq->target_vcpu )
            irq_set_affinity(desc, cpumask_of(irq->target_vcpu->processor));
        desc->handler->enable(desc);
    }
    else
        desc->handler->disable(desc);

    spin_unlock(&irq->irq_lock);
    spin_unlock_irqrestore(&desc->lock, flags);
}

unsigned int vgic_max_vcpus(const struct domain *d)
{
    unsigned int vgic_vcpu_limit;

    switch ( d->arch.vgic.version )
    {
    case GIC_INVALID:
        /*
         * Since evtchn_init would call domain_max_vcpus for poll_mask
         * allocation before the VGIC has been initialised, we need to
         * return some safe value in this case. As this is for allocation
         * purposes, go with the maximum value.
         */
        vgic_vcpu_limit = MAX_VIRT_CPUS;
        break;
    case GIC_V2:
        vgic_vcpu_limit = VGIC_V2_MAX_CPUS;
        break;
    default:
        BUG();
    }

    return min_t(unsigned int, MAX_VIRT_CPUS, vgic_vcpu_limit);
}

#ifdef CONFIG_HAS_GICV3
/* Dummy implementation to allow building without actual vGICv3 support. */
void vgic_v3_setup_hw(paddr_t dbase,
                      unsigned int nr_rdist_regions,
                      const struct rdist_region *regions,
                      unsigned int intid_bits)
{
    panic("New VGIC implementation does not yet support GICv3.");
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
