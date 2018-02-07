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

static const struct vgic_register_region vgic_v2_dist_registers[] = {
    REGISTER_DESC_WITH_LENGTH(GICD_CTLR,
        vgic_mmio_read_raz, vgic_mmio_write_wi, 12,
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
