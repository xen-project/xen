/*
 * VGIC MMIO handling functions
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
 */

#include <xen/bitops.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/new_vgic.h>
#include <asm/byteorder.h>

#include "vgic.h"
#include "vgic-mmio.h"

unsigned long vgic_mmio_read_raz(struct vcpu *vcpu,
                                 paddr_t addr, unsigned int len)
{
    return 0;
}

unsigned long vgic_mmio_read_rao(struct vcpu *vcpu,
                                 paddr_t addr, unsigned int len)
{
    return -1UL;
}

void vgic_mmio_write_wi(struct vcpu *vcpu, paddr_t addr,
                        unsigned int len, unsigned long val)
{
    /* Ignore */
}

/*
 * Read accesses to both GICD_ICENABLER and GICD_ISENABLER return the value
 * of the enabled bit, so there is only one function for both here.
 */
unsigned long vgic_mmio_read_enable(struct vcpu *vcpu,
                                    paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    uint32_t value = 0;
    unsigned int i;

    /* Loop over all IRQs affected by this read */
    for ( i = 0; i < len * 8; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        if ( irq->enabled )
            value |= (1U << i);

        vgic_put_irq(vcpu->domain, irq);
    }

    return value;
}

void vgic_mmio_write_senable(struct vcpu *vcpu,
                             paddr_t addr, unsigned int len,
                             unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    unsigned int i;

    for_each_set_bit( i, &val, len * 8 )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);
        unsigned long flags;
        irq_desc_t *desc;

        spin_lock_irqsave(&irq->irq_lock, flags);

        if ( irq->enabled )            /* skip already enabled IRQs */
        {
            spin_unlock_irqrestore(&irq->irq_lock, flags);
            vgic_put_irq(vcpu->domain, irq);
            continue;
        }

        irq->enabled = true;
        if ( irq->hw )
        {
            /*
             * The irq cannot be a PPI, we only support delivery
             * of SPIs to guests.
             */
            ASSERT(irq->hwintid >= VGIC_NR_PRIVATE_IRQS);

            desc = irq_to_desc(irq->hwintid);
        }
        else
            desc = NULL;

        vgic_queue_irq_unlock(vcpu->domain, irq, flags);

        if ( desc )
            vgic_sync_hardware_irq(vcpu->domain, desc, irq);

        vgic_put_irq(vcpu->domain, irq);
    }
}

void vgic_mmio_write_cenable(struct vcpu *vcpu,
                             paddr_t addr, unsigned int len,
                             unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    unsigned int i;

    for_each_set_bit( i, &val, len * 8 )
    {
        struct vgic_irq *irq;
        unsigned long flags;
        irq_desc_t *desc;

        irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);
        spin_lock_irqsave(&irq->irq_lock, flags);

        if ( !irq->enabled )            /* skip already disabled IRQs */
        {
            spin_unlock_irqrestore(&irq->irq_lock, flags);
            vgic_put_irq(vcpu->domain, irq);
            continue;
        }

        irq->enabled = false;

        if ( irq->hw )
        {
            /*
             * The irq cannot be a PPI, we only support delivery
             * of SPIs to guests.
             */
            ASSERT(irq->hwintid >= VGIC_NR_PRIVATE_IRQS);

            desc = irq_to_desc(irq->hwintid);
        }
        else
            desc = NULL;

        spin_unlock_irqrestore(&irq->irq_lock, flags);

        if ( desc )
            vgic_sync_hardware_irq(vcpu->domain, desc, irq);

        vgic_put_irq(vcpu->domain, irq);
    }
}

unsigned long vgic_mmio_read_pending(struct vcpu *vcpu,
                                     paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    uint32_t value = 0;
    unsigned int i;

    /* Loop over all IRQs affected by this read */
    for ( i = 0; i < len * 8; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        if ( irq_is_pending(irq) )
            value |= (1U << i);

        vgic_put_irq(vcpu->domain, irq);
    }

    return value;
}

void vgic_mmio_write_spending(struct vcpu *vcpu,
                              paddr_t addr, unsigned int len,
                              unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    unsigned int i;
    unsigned long flags;
    irq_desc_t *desc;

    for_each_set_bit( i, &val, len * 8 )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        spin_lock_irqsave(&irq->irq_lock, flags);
        irq->pending_latch = true;

        /* To observe the locking order, just take the irq_desc pointer here. */
        if ( irq->hw )
            desc = irq_to_desc(irq->hwintid);
        else
            desc = NULL;

        vgic_queue_irq_unlock(vcpu->domain, irq, flags);

        /*
         * When the VM sets the pending state for a HW interrupt on the virtual
         * distributor we set the active state on the physical distributor,
         * because the virtual interrupt can become active and then the guest
         * can deactivate it.
         */
        if ( desc )
        {
            spin_lock_irqsave(&desc->lock, flags);
            spin_lock(&irq->irq_lock);

            /* This h/w IRQ should still be assigned to the virtual IRQ. */
            ASSERT(irq->hw && desc->irq == irq->hwintid);

            gic_set_active_state(desc, true);

            spin_unlock(&irq->irq_lock);
            spin_unlock_irqrestore(&desc->lock, flags);
        }

        vgic_put_irq(vcpu->domain, irq);
    }
}

void vgic_mmio_write_cpending(struct vcpu *vcpu,
                              paddr_t addr, unsigned int len,
                              unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    unsigned int i;
    unsigned long flags;
    irq_desc_t *desc;

    for_each_set_bit( i, &val, len * 8 )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        spin_lock_irqsave(&irq->irq_lock, flags);
        irq->pending_latch = false;

        /* To observe the locking order, just take the irq_desc pointer here. */
        if ( irq->hw )
            desc = irq_to_desc(irq->hwintid);
        else
            desc = NULL;

        spin_unlock_irqrestore(&irq->irq_lock, flags);

        /*
         * We don't want the guest to effectively mask the physical
         * interrupt by doing a write to SPENDR followed by a write to
         * CPENDR for HW interrupts, so we clear the active state on
         * the physical side if the virtual interrupt is not active.
         * This may lead to taking an additional interrupt on the
         * host, but that should not be a problem as the worst that
         * can happen is an additional vgic injection.  We also clear
         * the pending state to maintain proper semantics for edge HW
         * interrupts.
         */
        if ( desc )
        {
            spin_lock_irqsave(&desc->lock, flags);
            spin_lock(&irq->irq_lock);

            /* This h/w IRQ should still be assigned to the virtual IRQ. */
            ASSERT(irq->hw && desc->irq == irq->hwintid);

            /* Check that we didn't become pending again meanwhile. */
            if ( !irq_is_pending(irq) )
            {
                gic_set_pending_state(desc, false);
                if ( !irq->active )
                    gic_set_active_state(desc, false);
            }

            spin_unlock(&irq->irq_lock);
            spin_unlock_irqrestore(&desc->lock, flags);
        }


        vgic_put_irq(vcpu->domain, irq);
    }
}

/*
 * The actual active bit for a virtual IRQ is held in the LR. Our shadow
 * copy in struct vgic_irq is only synced when needed and may not be
 * up-to-date all of the time.
 * Returning the actual active state is quite costly (stopping all
 * VCPUs processing any affected vIRQs), so we use a simple implementation
 * to get the best possible answer.
 */
unsigned long vgic_mmio_read_active(struct vcpu *vcpu,
                                    paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    uint32_t value = 0;
    unsigned int i;

    /* Loop over all IRQs affected by this read */
    for ( i = 0; i < len * 8; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        if ( irq->active )
            value |= (1U << i);

        vgic_put_irq(vcpu->domain, irq);
    }

    return value;
}

/*
 * We don't actually support clearing the active state of an IRQ (yet).
 * However there is a chance that most guests use this for initialization.
 * We check whether this MMIO access would actually affect any active IRQ,
 * and only print our warning in this case. So clearing already non-active
 * IRQs would not be moaned about in the logs.
 */
void vgic_mmio_write_cactive(struct vcpu *vcpu,
                             paddr_t addr, unsigned int len,
                             unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    unsigned int i;

    for_each_set_bit( i, &val, len * 8 )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        /*
         * If we know that the IRQ is active or we can't be sure about
         * it (because it is currently in a CPU), log the not properly
         * emulated MMIO access.
         */
        if ( irq->active || irq->vcpu )
            printk(XENLOG_G_ERR
                   "%pv: vGICD: IRQ%u: clearing active state not supported\n",
                   vcpu, irq->intid);

        vgic_put_irq(vcpu->domain, irq);
    }
}

/*
 * We don't actually support setting the active state of an IRQ (yet).
 * We check whether this MMIO access would actually affect any non-active IRQ,
 * and only print our warning in this case.
 */
void vgic_mmio_write_sactive(struct vcpu *vcpu,
                             paddr_t addr, unsigned int len,
                             unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 1);
    unsigned int i;

    for_each_set_bit( i, &val, len * 8 )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        /*
         * If we know that the IRQ is not active or we can't be sure about
         * it (because it is currently in a CPU), log the not properly
         * emulated MMIO access.
         */
        if ( !irq->active || irq->vcpu )
            printk(XENLOG_G_ERR
                   "%pv: vGICD: IRQ%u: setting active state not supported\n",
                   vcpu, irq->intid);

        vgic_put_irq(vcpu->domain, irq);
    }
}

unsigned long vgic_mmio_read_priority(struct vcpu *vcpu,
                                      paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    unsigned int i;
    uint32_t val = 0;

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        val |= (uint32_t)irq->priority << (i * 8);

        vgic_put_irq(vcpu->domain, irq);
    }

    return val;
}

/*
 * We currently don't handle changing the priority of an interrupt that
 * is already pending on a VCPU. If there is a need for this, we would
 * need to make this VCPU exit and re-evaluate the priorities, potentially
 * leading to this interrupt getting presented now to the guest (if it has
 * been masked by the priority mask before).
 */
void vgic_mmio_write_priority(struct vcpu *vcpu,
                              paddr_t addr, unsigned int len,
                              unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    unsigned int i;
    unsigned long flags;

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        spin_lock_irqsave(&irq->irq_lock, flags);
        /* Narrow the priority range to what we actually support */
        irq->priority = (val >> (i * 8)) & GENMASK(7, 8 - VGIC_PRI_BITS);
        spin_unlock_irqrestore(&irq->irq_lock, flags);

        vgic_put_irq(vcpu->domain, irq);
    }
}

unsigned long vgic_mmio_read_config(struct vcpu *vcpu,
                                    paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 2);
    uint32_t value = 0;
    int i;

    for ( i = 0; i < len * 4; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        if ( irq->config == VGIC_CONFIG_EDGE )
            value |= (2U << (i * 2));

        vgic_put_irq(vcpu->domain, irq);
    }

    return value;
}

void vgic_mmio_write_config(struct vcpu *vcpu,
                            paddr_t addr, unsigned int len,
                            unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 2);
    int i;
    unsigned long flags;

    for ( i = 0; i < len * 4; i++ )
    {
        struct vgic_irq *irq;

        /*
         * The configuration cannot be changed for SGIs in general,
         * for PPIs this is IMPLEMENTATION DEFINED. The arch timer
         * code relies on PPIs being level triggered, so we also
         * make them read-only here.
         */
        if ( intid + i < VGIC_NR_PRIVATE_IRQS )
            continue;

        irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);
        spin_lock_irqsave(&irq->irq_lock, flags);

        if ( test_bit(i * 2 + 1, &val) )
            irq->config = VGIC_CONFIG_EDGE;
        else
            irq->config = VGIC_CONFIG_LEVEL;

        spin_unlock_irqrestore(&irq->irq_lock, flags);
        vgic_put_irq(vcpu->domain, irq);
    }
}

static int match_region(const void *key, const void *elt)
{
    const unsigned int offset = (unsigned long)key;
    const struct vgic_register_region *region = elt;

    if ( offset < region->reg_offset )
        return -1;

    if ( offset >= region->reg_offset + region->len )
        return 1;

    return 0;
}

static const struct vgic_register_region *
vgic_find_mmio_region(const struct vgic_register_region *regions,
                      int nr_regions, unsigned int offset)
{
    return bsearch((void *)(uintptr_t)offset, regions, nr_regions,
                   sizeof(regions[0]), match_region);
}

static bool check_region(const struct domain *d,
                         const struct vgic_register_region *region,
                         paddr_t addr, int len)
{
    unsigned int flags, nr_irqs = d->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;

    switch ( len )
    {
    case sizeof(uint8_t):
        flags = VGIC_ACCESS_8bit;
        break;
    case sizeof(uint32_t):
        flags = VGIC_ACCESS_32bit;
        break;
    case sizeof(uint64_t):
        flags = VGIC_ACCESS_64bit;
        break;
    default:
        return false;
    }

    if ( (region->access_flags & flags) && IS_ALIGNED(addr, len) )
    {
        if ( !region->bits_per_irq )
            return true;

        /* Do we access a non-allocated IRQ? */
        return VGIC_ADDR_TO_INTID(addr, region->bits_per_irq) < nr_irqs;
    }

    return false;
}

static const struct vgic_register_region *
vgic_get_mmio_region(struct vcpu *vcpu, struct vgic_io_device *iodev,
                     paddr_t addr, unsigned int len)
{
    const struct vgic_register_region *region;

    region = vgic_find_mmio_region(iodev->regions, iodev->nr_regions,
                                   addr - gfn_to_gaddr(iodev->base_fn));
    if ( !region || !check_region(vcpu->domain, region, addr, len) )
        return NULL;

    return region;
}

static int dispatch_mmio_read(struct vcpu *vcpu, mmio_info_t *info,
                              register_t *r, void *priv)
{
    struct vgic_io_device *iodev = priv;
    const struct vgic_register_region *region;
    unsigned long data = 0;
    paddr_t addr = info->gpa;
    int len = 1U << info->dabt.size;

    region = vgic_get_mmio_region(vcpu, iodev, addr, len);
    if ( !region )
    {
        memset(r, 0, len);
        return 0;
    }

    switch (iodev->iodev_type)
    {
    case IODEV_DIST:
        data = region->read(vcpu, addr, len);
        break;
    case IODEV_REDIST:
        data = region->read(iodev->redist_vcpu, addr, len);
        break;
    }

    memcpy(r, &data, len);

    return 1;
}

static int dispatch_mmio_write(struct vcpu *vcpu, mmio_info_t *info,
                               register_t r, void *priv)
{
    struct vgic_io_device *iodev = priv;
    const struct vgic_register_region *region;
    unsigned long data = r;
    paddr_t addr = info->gpa;
    int len = 1U << info->dabt.size;

    region = vgic_get_mmio_region(vcpu, iodev, addr, len);
    if ( !region )
        return 0;

    switch (iodev->iodev_type)
    {
    case IODEV_DIST:
        region->write(vcpu, addr, len, data);
        break;
    case IODEV_REDIST:
        region->write(iodev->redist_vcpu, addr, len, data);
        break;
    }

    return 1;
}

struct mmio_handler_ops vgic_io_ops = {
    .read = dispatch_mmio_read,
    .write = dispatch_mmio_write,
};

int vgic_register_dist_iodev(struct domain *d, gfn_t dist_base_fn,
                             enum vgic_type type)
{
    struct vgic_io_device *io_device = &d->arch.vgic.dist_iodev;
    unsigned int len;

    switch ( type )
    {
    case VGIC_V2:
        len = vgic_v2_init_dist_iodev(io_device);
        break;
    default:
        BUG();
    }

    io_device->base_fn = dist_base_fn;
    io_device->iodev_type = IODEV_DIST;
    io_device->redist_vcpu = NULL;

    register_mmio_handler(d, &vgic_io_ops, gfn_to_gaddr(dist_base_fn), len,
                          io_device);

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
