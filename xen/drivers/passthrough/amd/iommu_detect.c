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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/iommu.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm/hvm/svm/amd-iommu-acpi.h>

static int __init get_iommu_msi_capabilities(
    u16 seg, u8 bus, u8 dev, u8 func, struct amd_iommu *iommu)
{
    int pos;
    u16 control;

    pos = pci_find_cap_offset(seg, bus, dev, func, PCI_CAP_ID_MSI);

    if ( !pos )
        return -ENODEV;

    AMD_IOMMU_DEBUG("Found MSI capability block at %#x\n", pos);

    iommu->msi_cap = pos;
    control = pci_conf_read16(seg, bus, dev, func,
                              iommu->msi_cap + PCI_MSI_FLAGS);
    iommu->maskbit = control & PCI_MSI_FLAGS_MASKBIT;
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

int __init amd_iommu_detect_one_acpi(void *ivhd)
{
    struct amd_iommu *iommu;
    u8 bus, dev, func;
    struct acpi_ivhd_block_header *ivhd_block;
    int rt = 0;

    ivhd_block = (struct acpi_ivhd_block_header *)ivhd;

    if ( ivhd_block->header.length < sizeof(struct acpi_ivhd_block_header) )
    {
        AMD_IOMMU_DEBUG("Invalid IVHD Block Length!\n");
        return -ENODEV;
    }

    if ( !ivhd_block->header.dev_id ||
        !ivhd_block->cap_offset || !ivhd_block->mmio_base)
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

    iommu->seg = ivhd_block->pci_segment;
    iommu->bdf = ivhd_block->header.dev_id;
    iommu->cap_offset = ivhd_block->cap_offset;
    iommu->mmio_base_phys = ivhd_block->mmio_base;

    /* override IOMMU support flags */
    iommu->coherent = get_field_from_byte(ivhd_block->header.flags,
                        AMD_IOMMU_ACPI_COHERENT_MASK,
                        AMD_IOMMU_ACPI_COHERENT_SHIFT);
    iommu->iotlb_support = get_field_from_byte(ivhd_block->header.flags,
                        AMD_IOMMU_ACPI_IOTLB_SUP_MASK,
                        AMD_IOMMU_ACPI_IOTLB_SUP_SHIFT);
    iommu->isochronous = get_field_from_byte(ivhd_block->header.flags,
                        AMD_IOMMU_ACPI_ISOC_MASK,
                        AMD_IOMMU_ACPI_ISOC_SHIFT);
    iommu->res_pass_pw = get_field_from_byte(ivhd_block->header.flags,
                        AMD_IOMMU_ACPI_RES_PASS_PW_MASK,
                        AMD_IOMMU_ACPI_RES_PASS_PW_SHIFT);
    iommu->pass_pw = get_field_from_byte(ivhd_block->header.flags,
                        AMD_IOMMU_ACPI_PASS_PW_MASK,
                        AMD_IOMMU_ACPI_PASS_PW_SHIFT);
    iommu->ht_tunnel_enable = get_field_from_byte(ivhd_block->header.flags,
                        AMD_IOMMU_ACPI_HT_TUN_ENB_MASK,
                        AMD_IOMMU_ACPI_HT_TUN_ENB_SHIFT);

    bus = PCI_BUS(iommu->bdf);
    dev = PCI_SLOT(iommu->bdf);
    func = PCI_FUNC(iommu->bdf);

    rt = get_iommu_capabilities(iommu->seg, bus, dev, func,
                                iommu->cap_offset, iommu);
    if ( rt )
        return -ENODEV;

    rt = get_iommu_msi_capabilities(iommu->seg, bus, dev, func, iommu);
    if ( rt )
        return -ENODEV;

    list_add_tail(&iommu->list, &amd_iommu_head);

    return 0;
}
