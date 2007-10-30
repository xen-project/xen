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
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm-x86/fixmap.h>
#include "pci-direct.h"
#include "pci_regs.h"

extern int nr_amd_iommus;

int __init map_iommu_mmio_region(struct amd_iommu *iommu)
{
    unsigned long mfn;

    if ( nr_amd_iommus > MAX_AMD_IOMMUS ) {
        gdprintk(XENLOG_ERR,
            "IOMMU: nr_amd_iommus %d > MAX_IOMMUS\n", nr_amd_iommus);
        return -ENOMEM;
    }

    iommu->mmio_base = (void *) fix_to_virt(FIX_IOMMU_MMIO_BASE_0 +
                       nr_amd_iommus * MMIO_PAGES_PER_IOMMU);
    mfn = (unsigned long)iommu->mmio_base_phys >> PAGE_SHIFT;
    map_pages_to_xen((unsigned long)iommu->mmio_base, mfn,
                    MMIO_PAGES_PER_IOMMU, PAGE_HYPERVISOR_NOCACHE);

    memset((u8*)iommu->mmio_base, 0, IOMMU_MMIO_REGION_LENGTH);

    return 0;
}

void __init unmap_iommu_mmio_region(struct amd_iommu *iommu)
{
    if ( iommu->mmio_base ) {
        iounmap(iommu->mmio_base);
        iommu->mmio_base = NULL;
    }
}

void __init register_iommu_dev_table_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64, addr_lo, addr_hi;
    u32 entry;

    addr_64 = (u64)virt_to_maddr(iommu->dev_table.buffer);
    addr_lo = addr_64 & DMA_32BIT_MASK;
    addr_hi = addr_64 >> 32;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
        IOMMU_DEV_TABLE_BASE_LOW_MASK,
        IOMMU_DEV_TABLE_BASE_LOW_SHIFT, &entry);
    set_field_in_reg_u32((iommu->dev_table.alloc_size / PAGE_SIZE) - 1,
        entry, IOMMU_DEV_TABLE_SIZE_MASK,
        IOMMU_DEV_TABLE_SIZE_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_DEV_TABLE_BASE_LOW_OFFSET);

    set_field_in_reg_u32((u32)addr_hi, 0,
        IOMMU_DEV_TABLE_BASE_HIGH_MASK,
        IOMMU_DEV_TABLE_BASE_HIGH_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_DEV_TABLE_BASE_HIGH_OFFSET);
}

void __init register_iommu_cmd_buffer_in_mmio_space(struct amd_iommu *iommu)
{
    u64 addr_64, addr_lo, addr_hi;
    u32 power_of2_entries;
    u32 entry;

    addr_64 = (u64)virt_to_maddr(iommu->cmd_buffer.buffer);
    addr_lo = addr_64 & DMA_32BIT_MASK;
    addr_hi = addr_64 >> 32;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
        IOMMU_CMD_BUFFER_BASE_LOW_MASK,
        IOMMU_CMD_BUFFER_BASE_LOW_SHIFT, &entry);
    writel(entry, iommu->mmio_base + IOMMU_CMD_BUFFER_BASE_LOW_OFFSET);

    power_of2_entries = get_order_from_bytes(iommu->cmd_buffer.alloc_size) +
        IOMMU_CMD_BUFFER_POWER_OF2_ENTRIES_PER_PAGE;

    set_field_in_reg_u32((u32)addr_hi, 0,
        IOMMU_CMD_BUFFER_BASE_HIGH_MASK,
        IOMMU_CMD_BUFFER_BASE_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(power_of2_entries, entry,
        IOMMU_CMD_BUFFER_LENGTH_MASK,
        IOMMU_CMD_BUFFER_LENGTH_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_CMD_BUFFER_BASE_HIGH_OFFSET);
}

static void __init set_iommu_translation_control(struct amd_iommu *iommu,
            int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
    set_field_in_reg_u32(iommu->ht_tunnel_support ? IOMMU_CONTROL_ENABLED :
        IOMMU_CONTROL_ENABLED, entry,
        IOMMU_CONTROL_HT_TUNNEL_TRANSLATION_MASK,
        IOMMU_CONTROL_HT_TUNNEL_TRANSLATION_SHIFT, &entry);
    set_field_in_reg_u32(enable ? IOMMU_CONTROL_ENABLED :
        IOMMU_CONTROL_ENABLED, entry,
        IOMMU_CONTROL_TRANSLATION_ENABLE_MASK,
        IOMMU_CONTROL_TRANSLATION_ENABLE_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

static void __init set_iommu_command_buffer_control(struct amd_iommu *iommu,
            int enable)
{
    u32 entry;

    entry = readl(iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
    set_field_in_reg_u32(enable ? IOMMU_CONTROL_ENABLED :
        IOMMU_CONTROL_ENABLED, entry,
        IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_MASK,
        IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_SHIFT, &entry);
    writel(entry, iommu->mmio_base+IOMMU_CONTROL_MMIO_OFFSET);
}

void __init enable_iommu(struct amd_iommu *iommu)
{
    set_iommu_command_buffer_control(iommu, IOMMU_CONTROL_ENABLED);
    set_iommu_translation_control(iommu, IOMMU_CONTROL_ENABLED);
    printk("AMD IOMMU %d: Enabled\n", nr_amd_iommus);
}


