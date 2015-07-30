/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/acpi.h>
#include <xen/iommu.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

static int __init get_iommu_msi_capabilities(
    u16 seg, u8 bus, u8 dev, u8 func, struct amd_iommu *iommu)
{
    int pos;

    pos = pci_find_cap_offset(seg, bus, dev, func, PCI_CAP_ID_MSI);

    if ( !pos )
        return -ENODEV;

    AMD_IOMMU_DEBUG("Found MSI capability block at %#x\n", pos);

    iommu->msi.msi_attrib.type = PCI_CAP_ID_MSI;
    iommu->msi.msi_attrib.pos = pos;
    iommu->msi.msi_attrib.is_64 = 1;
    return 0;
}

static int __init get_iommu_capabilities(
    u16 seg, u8 bus, u8 dev, u8 func, u16 cap_ptr, struct amd_iommu *iommu)
{
    u8 type;

    iommu->cap.header = pci_conf_read32(seg, bus, dev, func, cap_ptr);
    type = get_field_from_reg_u32(iommu->cap.header, PCI_CAP_TYPE_MASK,
                                  PCI_CAP_TYPE_SHIFT);

    if ( type != PCI_CAP_TYPE_IOMMU )
        return -ENODEV;

    return 0;
}

void __init get_iommu_features(struct amd_iommu *iommu)
{
    u32 low, high;
    int i = 0 ;
    static const char *__initdata feature_str[] = {
        "- Prefetch Pages Command", 
        "- Peripheral Page Service Request", 
        "- X2APIC Supported", 
        "- NX bit Supported", 
        "- Guest Translation", 
        "- Reserved bit [5]",
        "- Invalidate All Command", 
        "- Guest APIC supported", 
        "- Hardware Error Registers", 
        "- Performance Counters", 
        NULL
    };

    ASSERT( iommu->mmio_base );

    if ( !iommu_has_cap(iommu, PCI_CAP_EFRSUP_SHIFT) )
    {
        iommu->features = 0;
        return;
    }

    low = readl(iommu->mmio_base + IOMMU_EXT_FEATURE_MMIO_OFFSET);
    high = readl(iommu->mmio_base + IOMMU_EXT_FEATURE_MMIO_OFFSET + 4);

    iommu->features = ((u64)high << 32) | low;

    printk("AMD-Vi: IOMMU Extended Features:\n");

    while ( feature_str[i] )
    {
        if ( amd_iommu_has_feature(iommu, i) )
            printk( " %s\n", feature_str[i]);
        i++;
    }
}

int __init amd_iommu_detect_one_acpi(
    const struct acpi_ivrs_hardware *ivhd_block)
{
    struct amd_iommu *iommu;
    u8 bus, dev, func;
    int rt = 0;

    if ( ivhd_block->header.length < sizeof(*ivhd_block) )
    {
        AMD_IOMMU_DEBUG("Invalid IVHD Block Length!\n");
        return -ENODEV;
    }

    if ( !ivhd_block->header.device_id ||
        !ivhd_block->capability_offset || !ivhd_block->base_address)
    {
        AMD_IOMMU_DEBUG("Invalid IVHD Block!\n");
        return -ENODEV;
    }

    iommu = xzalloc(struct amd_iommu);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Error allocating amd_iommu\n");
        return -ENOMEM;
    }

    spin_lock_init(&iommu->lock);

    iommu->seg = ivhd_block->pci_segment_group;
    iommu->bdf = ivhd_block->header.device_id;
    iommu->cap_offset = ivhd_block->capability_offset;
    iommu->mmio_base_phys = ivhd_block->base_address;

    /* override IOMMU HT flags */
    iommu->ht_flags = ivhd_block->header.flags;

    bus = PCI_BUS(iommu->bdf);
    dev = PCI_SLOT(iommu->bdf);
    func = PCI_FUNC(iommu->bdf);

    rt = get_iommu_capabilities(iommu->seg, bus, dev, func,
                                iommu->cap_offset, iommu);
    if ( rt )
        goto out;

    rt = get_iommu_msi_capabilities(iommu->seg, bus, dev, func, iommu);
    if ( rt )
        goto out;

    rt = pci_ro_device(iommu->seg, bus, PCI_DEVFN(dev, func));
    if ( rt )
        printk(XENLOG_ERR
               "Could not mark config space of %04x:%02x:%02x.%u read-only (%d)\n",
               iommu->seg, bus, dev, func, rt);

    list_add_tail(&iommu->list, &amd_iommu_head);
    rt = 0;

 out:
    if ( rt )
        xfree(iommu);

    return rt;
}
