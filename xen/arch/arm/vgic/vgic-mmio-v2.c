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

static const struct vgic_register_region vgic_v2_dist_registers[] = {
    REGISTER_DESC_WITH_LENGTH(GICD_CTLR,
        vgic_mmio_read_v2_misc, vgic_mmio_write_v2_misc, 12,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_IGROUPR,
        vgic_mmio_read_rao, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ISENABLER,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICENABLER,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ISPENDR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICPENDR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ISACTIVER,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICACTIVER,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 1,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_IPRIORITYR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 8,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ITARGETSR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 8,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
    REGISTER_DESC_WITH_BITS_PER_IRQ(GICD_ICFGR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 2,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_LENGTH(GICD_SGIR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 4,
        VGIC_ACCESS_32bit),
    REGISTER_DESC_WITH_LENGTH(GICD_CPENDSGIR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 16,
        VGIC_ACCESS_32bit | VGIC_ACCESS_8bit),
    REGISTER_DESC_WITH_LENGTH(GICD_SPENDSGIR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 16,
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
