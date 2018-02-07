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

#include <asm/new_vgic.h>
#include <asm/bug.h>
#include <asm/gic.h>
#include <xen/sched.h>
#include <xen/sizes.h>

#include "vgic.h"

static struct {
    bool enabled;
    paddr_t dbase;          /* Distributor interface address */
    paddr_t cbase;          /* CPU interface address & size */
    paddr_t csize;
    paddr_t vbase;          /* Virtual CPU interface address */

    /* Offset to add to get an 8kB contiguous region if GIC is aliased */
    uint32_t aliased_offset;
} gic_v2_hw_data;

void vgic_v2_setup_hw(paddr_t dbase, paddr_t cbase, paddr_t csize,
                      paddr_t vbase, uint32_t aliased_offset)
{
    gic_v2_hw_data.enabled = true;
    gic_v2_hw_data.dbase = dbase;
    gic_v2_hw_data.cbase = cbase;
    gic_v2_hw_data.csize = csize;
    gic_v2_hw_data.vbase = vbase;
    gic_v2_hw_data.aliased_offset = aliased_offset;

    printk("Using the new VGIC implementation.\n");
}

/*
 * transfer the content of the LRs back into the corresponding ap_list:
 * - active bit is transferred as is
 * - pending bit is
 *   - transferred as is in case of edge sensitive IRQs
 *   - set to the line-level (resample time) for level sensitive IRQs
 */
void vgic_v2_fold_lr_state(struct vcpu *vcpu)
{
    struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic;
    unsigned int used_lrs = vcpu->arch.vgic.used_lrs;
    unsigned long flags;
    unsigned int lr;

    if ( !used_lrs )    /* No LRs used, so nothing to sync back here. */
        return;

    gic_hw_ops->update_hcr_status(GICH_HCR_UIE, false);

    for ( lr = 0; lr < used_lrs; lr++ )
    {
        struct gic_lr lr_val;
        uint32_t intid;
        struct vgic_irq *irq;
        struct irq_desc *desc = NULL;

        gic_hw_ops->read_lr(lr, &lr_val);

        /*
         * TODO: Possible optimization to avoid reading LRs:
         * Read the ELRSR to find out which of our LRs have been cleared
         * by the guest. We just need to know the IRQ number for those, which
         * we could save in an array when populating the LRs.
         * This trades one MMIO access (ELRSR) for possibly more than one (LRs),
         * but requires some more code to save the IRQ number and to handle
         * those finished IRQs according to the algorithm below.
         * We need some numbers to justify this: chances are that we don't
         * have many LRs in use most of the time, so we might not save much.
         */
        gic_hw_ops->clear_lr(lr);

        intid = lr_val.virq;
        irq = vgic_get_irq(vcpu->domain, vcpu, intid);

        local_irq_save(flags);

        /*
         * We check this here without taking the lock, because the locking
         * order forces us to do so. irq->hw is a "write-once" member, so
         * whenever we read true, the associated hardware IRQ will not go
         * away anymore.
         * TODO: rework this if possible, either by using the desc pointer
         * directly in struct vgic_irq or by changing the locking order.
         * Especially if we ever drop the assumption above.
         */
        if ( irq->hw )
        {
            desc = irq_to_desc(irq->hwintid);
            spin_lock(&desc->lock);
        }

        spin_lock(&irq->irq_lock);

        /*
         * If a hardware mapped IRQ has been handled for good, we need to
         * clear the _IRQ_INPROGRESS bit to allow handling of new IRQs.
         *
         * TODO: This is probably racy, but is so already in the existing
         * VGIC. A fix does not seem to be trivial.
         */
        if ( irq->hw && !lr_val.active && !lr_val.pending )
            clear_bit(_IRQ_INPROGRESS, &desc->status);

        /* Always preserve the active bit */
        irq->active = lr_val.active;

        /* Edge is the only case where we preserve the pending bit */
        if ( irq->config == VGIC_CONFIG_EDGE && lr_val.pending )
        {
            irq->pending_latch = true;

            if ( vgic_irq_is_sgi(intid) )
                irq->source |= (1U << lr_val.virt.source);
        }

        /* Clear soft pending state when level irqs have been acked. */
        if ( irq->config == VGIC_CONFIG_LEVEL && !lr_val.pending )
            irq->pending_latch = false;

        /*
         * Level-triggered mapped IRQs are special because we only
         * observe rising edges as input to the VGIC.
         *
         * If the guest never acked the interrupt we have to sample
         * the physical line and set the line level, because the
         * device state could have changed or we simply need to
         * process the still pending interrupt later.
         *
         * If this causes us to lower the level, we have to also clear
         * the physical active state, since we will otherwise never be
         * told when the interrupt becomes asserted again.
         */
        if ( vgic_irq_is_mapped_level(irq) && lr_val.pending )
        {
            ASSERT(irq->hwintid >= VGIC_NR_PRIVATE_IRQS);

            irq->line_level = gic_read_pending_state(desc);

            if ( !irq->line_level )
                gic_set_active_state(desc, false);
        }

        spin_unlock(&irq->irq_lock);
        if ( desc )
            spin_unlock(&desc->lock);
        local_irq_restore(flags);

        vgic_put_irq(vcpu->domain, irq);
    }

    gic_hw_ops->update_hcr_status(GICH_HCR_EN, false);
    vgic_cpu->used_lrs = 0;
}

/**
 * vgic_v2_populate_lr() - Populates an LR with the state of a given IRQ.
 * @vcpu: The VCPU which the given @irq belongs to.
 * @irq:  The IRQ to convert into an LR. The irq_lock must be held already.
 * @lr:   The LR number to transfer the state into.
 *
 * This moves a virtual IRQ, represented by its vgic_irq, into a list register.
 * Apart from translating the logical state into the LR bitfields, it also
 * changes some state in the vgic_irq.
 * For an edge sensitive IRQ the pending state is cleared in struct vgic_irq,
 * for a level sensitive IRQ the pending state value is unchanged, as it is
 * dictated directly by the input line level.
 *
 * If @irq describes an SGI with multiple sources, we choose the
 * lowest-numbered source VCPU and clear that bit in the source bitmap.
 *
 * The irq_lock must be held by the caller.
 */
void vgic_v2_populate_lr(struct vcpu *vcpu, struct vgic_irq *irq, int lr)
{
    struct gic_lr lr_val = {0};

    lr_val.virq = irq->intid;

    if ( irq_is_pending(irq) )
    {
        lr_val.pending = true;

        if ( irq->config == VGIC_CONFIG_EDGE )
            irq->pending_latch = false;

        if ( vgic_irq_is_sgi(irq->intid) )
        {
            uint32_t src = ffs(irq->source);

            BUG_ON(!src);
            lr_val.virt.source = (src - 1);
            irq->source &= ~(1 << (src - 1));
            if ( irq->source )
                irq->pending_latch = true;
        }
    }

    lr_val.active = irq->active;

    if ( irq->hw )
    {
        lr_val.hw_status = true;
        lr_val.hw.pirq = irq->hwintid;
        /*
         * Never set pending+active on a HW interrupt, as the
         * pending state is kept at the physical distributor
         * level.
         */
        if ( irq->active && irq_is_pending(irq) )
            lr_val.pending = false;
    }
    else
    {
        if ( irq->config == VGIC_CONFIG_LEVEL )
            lr_val.virt.eoi = true;
    }

    /*
     * Level-triggered mapped IRQs are special because we only observe
     * rising edges as input to the VGIC.  We therefore lower the line
     * level here, so that we can take new virtual IRQs.  See
     * vgic_v2_fold_lr_state for more info.
     */
    if ( vgic_irq_is_mapped_level(irq) && lr_val.pending )
        irq->line_level = false;

    /* The GICv2 LR only holds five bits of priority. */
    lr_val.priority = irq->priority >> 3;

    gic_hw_ops->write_lr(lr, &lr_val);
}

void vgic_v2_enable(struct vcpu *vcpu)
{
    /* Get the show on the road... */
    gic_hw_ops->update_hcr_status(GICH_HCR_EN, true);
}

int vgic_v2_map_resources(struct domain *d)
{
    struct vgic_dist *dist = &d->arch.vgic;
    paddr_t cbase, csize;
    paddr_t vbase;
    int ret;

    /*
     * The hardware domain gets the hardware address.
     * Guests get the virtual platform layout.
     */
    if ( is_hardware_domain(d) )
    {
        d->arch.vgic.vgic_dist_base = gic_v2_hw_data.dbase;
        /*
         * For the hardware domain, we always map the whole HW CPU
         * interface region in order to match the device tree (the "reg"
         * properties is copied as it is).
         * Note that we assume the size of the CPU interface is always
         * aligned to PAGE_SIZE.
         */
        cbase = gic_v2_hw_data.cbase;
        csize = gic_v2_hw_data.csize;
        vbase = gic_v2_hw_data.vbase;
    }
    else
    {
        d->arch.vgic.vgic_dist_base = GUEST_GICD_BASE;
        /*
         * The CPU interface exposed to the guest is always 8kB. We may
         * need to add an offset to the virtual CPU interface base
         * address when in the GIC is aliased to get a 8kB contiguous
         * region.
         */
        BUILD_BUG_ON(GUEST_GICC_SIZE != SZ_8K);
        cbase = GUEST_GICC_BASE;
        csize = GUEST_GICC_SIZE;
        vbase = gic_v2_hw_data.vbase + gic_v2_hw_data.aliased_offset;
    }


    ret = vgic_register_dist_iodev(d, gaddr_to_gfn(dist->vgic_dist_base),
                                   VGIC_V2);
    if ( ret )
    {
        gdprintk(XENLOG_ERR, "Unable to register VGIC MMIO regions\n");
        return ret;
    }

    /*
     * Map the gic virtual cpu interface in the gic cpu interface
     * region of the guest.
     */
    ret = map_mmio_regions(d, gaddr_to_gfn(cbase), csize / PAGE_SIZE,
                           maddr_to_mfn(vbase));
    if ( ret )
    {
        gdprintk(XENLOG_ERR, "Unable to remap VGIC CPU to VCPU\n");
        return ret;
    }

    dist->ready = true;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
