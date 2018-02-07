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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
