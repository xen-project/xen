/*
 * VGICv2 MMIO handling functions
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
#include <xen/sched.h>
#include <xen/sizes.h>
#include <asm/new_vgic.h>

#include "vgic.h"
#include "vgic-mmio.h"

static unsigned long vgic_mmio_read_v2_misc(struct vcpu *vcpu,
                                            paddr_t addr, unsigned int len)
{
    uint32_t value;

    switch ( addr & 0x0c )      /* filter for the 4 registers handled here */
    {
    case GICD_CTLR:
        value = vcpu->domain->arch.vgic.enabled ? GICD_CTL_ENABLE : 0;
        break;
    case GICD_TYPER:
        value = vcpu->domain->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;
        value = (value >> 5) - 1;       /* stored as multiples of 32 */
        value |= (vcpu->domain->max_vcpus - 1) << GICD_TYPE_CPUS_SHIFT;
        break;
    case GICD_IIDR:
        value = (PRODUCT_ID_KVM << 24) |
                (VARIANT_ID_XEN << 16) |
                (IMPLEMENTER_ARM << 0);
        break;
    default:
        return 0;
    }

    return value;
}

static void vgic_mmio_write_v2_misc(struct vcpu *vcpu,
                                    paddr_t addr, unsigned int len,
                                    unsigned long val)
{
    struct vgic_dist *dist = &vcpu->domain->arch.vgic;
    bool enabled;

    switch ( addr & 0x0c )      /* filter for the 4 registers handled here */
    {
    case GICD_CTLR:
        domain_lock(vcpu->domain);

        /*
         * Store the new enabled state in our distributor structure.
         * Work out whether it was disabled before and now got enabled,
         * so that we signal all VCPUs to check for interrupts to be injected.
         */
        enabled = dist->enabled;
        dist->enabled = val & GICD_CTL_ENABLE;
        enabled = !enabled && dist->enabled;

        domain_unlock(vcpu->domain);

        if ( enabled )
            vgic_kick_vcpus(vcpu->domain);

        break;
    case GICD_TYPER:
    case GICD_IIDR:
        /* read-only, writes ignored */
        return;
    }
}

static void vgic_mmio_write_sgir(struct vcpu *source_vcpu,
                                 paddr_t addr, unsigned int len,
                                 unsigned long val)
{
    struct domain *d = source_vcpu->domain;
    unsigned int nr_vcpus = d->max_vcpus;
    unsigned int intid = val & GICD_SGI_INTID_MASK;
    unsigned long targets = (val & GICD_SGI_TARGET_MASK) >>
                            GICD_SGI_TARGET_SHIFT;
    unsigned int vcpu_id;

    switch ( val & GICD_SGI_TARGET_LIST_MASK )
    {
    case GICD_SGI_TARGET_LIST:                    /* as specified by targets */
        targets &= GENMASK(nr_vcpus - 1, 0);      /* limit to existing VCPUs */
        break;
    case GICD_SGI_TARGET_OTHERS:
        targets = GENMASK(nr_vcpus - 1, 0);       /* all, ...   */
        targets &= ~(1U << source_vcpu->vcpu_id); /*   but self */
        break;
    case GICD_SGI_TARGET_SELF:                    /* this very vCPU only */
        targets = (1U << source_vcpu->vcpu_id);
        break;
    case 0x3:                                     /* reserved */
        return;
    }

    for_each_set_bit( vcpu_id, &targets, 8 )
    {
        struct vcpu *vcpu = d->vcpu[vcpu_id];
        struct vgic_irq *irq = vgic_get_irq(d, vcpu, intid);
        unsigned long flags;

        spin_lock_irqsave(&irq->irq_lock, flags);

        irq->pending_latch = true;
        irq->source |= 1U << source_vcpu->vcpu_id;

        vgic_queue_irq_unlock(d, irq, flags);
        vgic_put_irq(d, irq);
    }
}

static unsigned long vgic_mmio_read_target(struct vcpu *vcpu,
                                           paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    uint32_t val = 0;
    unsigned int i;

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        val |= (uint32_t)irq->targets << (i * 8);

        vgic_put_irq(vcpu->domain, irq);
    }

    return val;
}

static void vgic_mmio_write_target(struct vcpu *vcpu,
                                   paddr_t addr, unsigned int len,
                                   unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    uint8_t cpu_mask = GENMASK(vcpu->domain->max_vcpus - 1, 0);
    unsigned int i;
    unsigned long flags;

    /* GICD_ITARGETSR[0-7] are read-only */
    if ( intid < VGIC_NR_PRIVATE_IRQS )
        return;

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, NULL, intid + i);

        spin_lock_irqsave(&irq->irq_lock, flags);

        irq->targets = (val >> (i * 8)) & cpu_mask;
        if ( irq->targets )
        {
            irq->target_vcpu = vcpu->domain->vcpu[ffs(irq->targets) - 1];
            if ( irq->hw )
            {
                struct irq_desc *desc = irq_to_desc(irq->hwintid);

                irq_set_affinity(desc, cpumask_of(irq->target_vcpu->processor));
            }
        }
        else
            irq->target_vcpu = NULL;

        spin_unlock_irqrestore(&irq->irq_lock, flags);
        vgic_put_irq(vcpu->domain, irq);
    }
}

static unsigned long vgic_mmio_read_sgipend(struct vcpu *vcpu,
                                            paddr_t addr, unsigned int len)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    uint32_t val = 0;
    unsigned int i;

    ASSERT(intid < VGIC_NR_SGIS);

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        val |= (uint32_t)irq->source << (i * 8);

        vgic_put_irq(vcpu->domain, irq);
    }

    return val;
}

static void vgic_mmio_write_sgipendc(struct vcpu *vcpu,
                                     paddr_t addr, unsigned int len,
                                     unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    unsigned int i;
    unsigned long flags;

    ASSERT(intid < VGIC_NR_SGIS);

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        spin_lock_irqsave(&irq->irq_lock, flags);

        irq->source &= ~((val >> (i * 8)) & 0xff);
        if ( !irq->source )
            irq->pending_latch = false;

        spin_unlock_irqrestore(&irq->irq_lock, flags);
        vgic_put_irq(vcpu->domain, irq);
    }
}

static void vgic_mmio_write_sgipends(struct vcpu *vcpu,
                                     paddr_t addr, unsigned int len,
                                     unsigned long val)
{
    uint32_t intid = VGIC_ADDR_TO_INTID(addr, 8);
    unsigned int i;
    unsigned long flags;

    ASSERT(intid < VGIC_NR_SGIS);

    for ( i = 0; i < len; i++ )
    {
        struct vgic_irq *irq = vgic_get_irq(vcpu->domain, vcpu, intid + i);

        spin_lock_irqsave(&irq->irq_lock, flags);

        irq->source |= (val >> (i * 8)) & 0xff;

        if ( irq->source )
        {
            irq->pending_latch = true;
            vgic_queue_irq_unlock(vcpu->domain, irq, flags);
        }
        else
        {
            spin_unlock_irqrestore(&irq->irq_lock, flags);
        }
        vgic_put_irq(vcpu->domain, irq);
    }
}

static const struct vgic_register_region vgic_v2_dist_registers[] = {
    REGISTER_DESC_WITH_LENGTH(GICD_CTLR,
        vgic_mmio_read_v2_misc, vgic_mmio_write_v2_misc, 12,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_IGROUPR,
        vgic_mmio_read_rao, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ISENABLER,
        vgic_mmio_read_enable, vgic_mmio_write_senable, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICENABLER,
        vgic_mmio_read_enable, vgic_mmio_write_cenable, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ISPENDR,
        vgic_mmio_read_pending, vgic_mmio_write_spending, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICPENDR,
        vgic_mmio_read_pending, vgic_mmio_write_cpending, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ISACTIVER,
        vgic_mmio_read_active, vgic_mmio_write_sactive, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICACTIVER,
        vgic_mmio_read_active, vgic_mmio_write_cactive, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_IPRIORITYR,
        vgic_mmio_read_priority, vgic_mmio_write_priority, 8,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ITARGETSR,
        vgic_mmio_read_target, vgic_mmio_write_target, 8,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICFGR,
        vgic_mmio_read_config, vgic_mmio_write_config, 2,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_LENGTH(GICD_SGIR,
        vgic_mmio_read_raz, vgic_mmio_write_sgir, 4,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_LENGTH(GICD_CPENDSGIR,
        vgic_mmio_read_sgipend, vgic_mmio_write_sgipendc, 16,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
    REGISTER_DESC_WITH_LENGTH(GICD_SPENDSGIR,
        vgic_mmio_read_sgipend, vgic_mmio_write_sgipends, 16,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
};

unsigned int vgic_v2_init_dist_iodev(struct vgic_io_device *dev)
{
    dev->regions = vgic_v2_dist_registers;
    dev->nr_regions = ARRAY_SIZE(vgic_v2_dist_registers);

    return SZ_4K;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
