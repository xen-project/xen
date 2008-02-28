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
#include <asm/hvm/svm/amd-iommu-acpi.h>

extern unsigned long amd_iommu_page_entries;
extern unsigned short ivrs_bdf_entries;
extern struct ivrs_mappings *ivrs_mappings;

static struct amd_iommu * __init find_iommu_from_bdf_cap(
           u16 bdf, u8 cap_offset)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu( iommu )
        if ( iommu->bdf == bdf && iommu->cap_offset == cap_offset )
            return iommu;

    return NULL;
}

static void __init reserve_iommu_exclusion_range(struct amd_iommu *iommu,
           unsigned long base, unsigned long limit)
{
    /* need to extend exclusion range? */
    if ( iommu->exclusion_enable )
    {
        if ( iommu->exclusion_base < base )
            base = iommu->exclusion_base;
        if ( iommu->exclusion_limit > limit )
            limit = iommu->exclusion_limit;
    }

    iommu->exclusion_enable = IOMMU_CONTROL_ENABLED;
    iommu->exclusion_base = base;
    iommu->exclusion_limit = limit;
}

static void __init reserve_iommu_exclusion_range_all(struct amd_iommu *iommu,
           unsigned long base, unsigned long limit)
{
    reserve_iommu_exclusion_range(iommu, base, limit);
    iommu->exclusion_allow_all = IOMMU_CONTROL_ENABLED;
}

static void __init reserve_unity_map_for_device(u16 bdf, unsigned long base,
           unsigned long length, u8 iw, u8 ir)
{
    unsigned long old_top, new_top;

    /* need to extend unity-mapped range? */
    if ( ivrs_mappings[bdf].unity_map_enable )
    {
        old_top = ivrs_mappings[bdf].addr_range_start +
            ivrs_mappings[bdf].addr_range_length;
        new_top = base + length;
        if ( old_top > new_top )
            new_top = old_top;
        if ( ivrs_mappings[bdf].addr_range_start < base )
            base = ivrs_mappings[bdf].addr_range_start;
        length = new_top - base;
   }

    /* extend r/w permissioms and keep aggregate */
    if ( iw )
        ivrs_mappings[bdf].write_permission = IOMMU_CONTROL_ENABLED;
    if ( ir )
        ivrs_mappings[bdf].read_permission = IOMMU_CONTROL_ENABLED;
    ivrs_mappings[bdf].unity_map_enable = IOMMU_CONTROL_ENABLED;
    ivrs_mappings[bdf].addr_range_start = base;
    ivrs_mappings[bdf].addr_range_length = length;
}

static int __init register_exclusion_range_for_all_devices(
           unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    unsigned long range_top, iommu_top, length;
    struct amd_iommu *iommu;
    u16 bdf;

    /* is part of exclusion range inside of IOMMU virtual address space? */
    /* note: 'limit' parameter is assumed to be page-aligned */
    range_top = limit + PAGE_SIZE;
    iommu_top = max_page * PAGE_SIZE;
    if ( base < iommu_top )
    {
        if (range_top > iommu_top)
            range_top = iommu_top;
        length = range_top - base;
        /* reserve r/w unity-mapped page entries for devices */
        /* note: these entries are part of the exclusion range */
        for (bdf = 0; bdf < ivrs_bdf_entries; ++bdf)
            reserve_unity_map_for_device(bdf, base, length, iw, ir);
        /* push 'base' just outside of virtual address space */
        base = iommu_top;
    }
    /* register IOMMU exclusion range settings */
    if (limit >= iommu_top)
    {
        for_each_amd_iommu( iommu )
            reserve_iommu_exclusion_range_all(iommu, base, limit);
    }

    return 0;
}

static int __init register_exclusion_range_for_device(u16 bdf,
           unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    unsigned long range_top, iommu_top, length;
    struct amd_iommu *iommu;
    u16 bus, devfn, req;

    bus = bdf >> 8;
    devfn = bdf & 0xFF;
    iommu = find_iommu_for_device(bus, devfn);
    if ( !iommu )
    {
        dprintk(XENLOG_ERR, "IVMD Error: No IOMMU for Dev_Id 0x%x!\n", bdf);
        return -ENODEV;
    }
    req = ivrs_mappings[bdf].dte_requestor_id;

    /* note: 'limit' parameter is assumed to be page-aligned */
    range_top = limit + PAGE_SIZE;
    iommu_top = max_page * PAGE_SIZE;
    if ( base < iommu_top )
    {
        if (range_top > iommu_top)
            range_top = iommu_top;
        length = range_top - base;
        /* reserve unity-mapped page entries for device */
        /* note: these entries are part of the exclusion range */
        reserve_unity_map_for_device(bdf, base, length, iw, ir);
        reserve_unity_map_for_device(req, base, length, iw, ir);

        /* push 'base' just outside of virtual address space */
        base = iommu_top;
    }

   /* register IOMMU exclusion range settings for device */
   if ( limit >= iommu_top  )
    {
        reserve_iommu_exclusion_range(iommu, base, limit);
        ivrs_mappings[bdf].dte_allow_exclusion = IOMMU_CONTROL_ENABLED;
        ivrs_mappings[req].dte_allow_exclusion = IOMMU_CONTROL_ENABLED;
    }

    return 0;
}

static int __init register_exclusion_range_for_iommu_devices(
           struct amd_iommu *iommu,
           unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    unsigned long range_top, iommu_top, length;
    u16 bus, devfn, bdf, req;

    /* is part of exclusion range inside of IOMMU virtual address space? */
    /* note: 'limit' parameter is assumed to be page-aligned */
    range_top = limit + PAGE_SIZE;
    iommu_top = max_page * PAGE_SIZE;
    if ( base < iommu_top )
    {
        if (range_top > iommu_top)
            range_top = iommu_top;
        length = range_top - base;
        /* reserve r/w unity-mapped page entries for devices */
        /* note: these entries are part of the exclusion range */
        for ( bdf = 0; bdf < ivrs_bdf_entries; ++bdf )
        {
            bus = bdf >> 8;
            devfn = bdf & 0xFF;
            if ( iommu == find_iommu_for_device(bus, devfn) )
            {
                reserve_unity_map_for_device(bdf, base, length, iw, ir);
                req = ivrs_mappings[bdf].dte_requestor_id;
                reserve_unity_map_for_device(req, base, length, iw, ir);
            }
        }

        /* push 'base' just outside of virtual address space */
        base = iommu_top;
    }

    /* register IOMMU exclusion range settings */
    if (limit >= iommu_top)
        reserve_iommu_exclusion_range_all(iommu, base, limit);
    return 0;
}

static int __init parse_ivmd_device_select(
           struct acpi_ivmd_block_header *ivmd_block,
           unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    u16 bdf;

    bdf = ivmd_block->header.dev_id;
    if (bdf >= ivrs_bdf_entries)
    {
        dprintk(XENLOG_ERR, "IVMD Error: Invalid Dev_Id 0x%x\n", bdf);
        return -ENODEV;
    }

    return register_exclusion_range_for_device(bdf, base, limit, iw, ir);
}

static int __init parse_ivmd_device_range(
           struct acpi_ivmd_block_header *ivmd_block,
           unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    u16 first_bdf, last_bdf, bdf;
    int error;

    first_bdf = ivmd_block->header.dev_id;
    if (first_bdf >= ivrs_bdf_entries)
    {
       dprintk(XENLOG_ERR, "IVMD Error: "
                    "Invalid Range_First Dev_Id 0x%x\n", first_bdf);
       return -ENODEV;
    }

    last_bdf = ivmd_block->last_dev_id;
    if (last_bdf >= ivrs_bdf_entries || last_bdf <= first_bdf)
    {
        dprintk(XENLOG_ERR, "IVMD Error: "
                    "Invalid Range_Last Dev_Id 0x%x\n", last_bdf);
        return -ENODEV;
    }

      dprintk(XENLOG_ERR, " Dev_Id Range: 0x%x -> 0x%x\n",
                    first_bdf, last_bdf);

    for ( bdf = first_bdf, error = 0;
       bdf <= last_bdf && !error; ++bdf )
    {
       error = register_exclusion_range_for_device(
                     bdf, base, limit, iw, ir);
    }

   return error;
}

static int __init parse_ivmd_device_iommu(
           struct acpi_ivmd_block_header *ivmd_block,
           unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    struct amd_iommu *iommu;

    /* find target IOMMU */
    iommu = find_iommu_from_bdf_cap(ivmd_block->header.dev_id,
                                    ivmd_block->cap_offset);
    if ( !iommu )
    {
       dprintk(XENLOG_ERR,
           "IVMD Error: No IOMMU for Dev_Id 0x%x  Cap 0x%x\n",
            ivmd_block->header.dev_id, ivmd_block->cap_offset);
       return -ENODEV;
    }

    return register_exclusion_range_for_iommu_devices(
                 iommu, base, limit, iw, ir);
}

static int __init parse_ivmd_block(struct acpi_ivmd_block_header *ivmd_block)
{
    unsigned long start_addr, mem_length, base, limit;
    u8 iw, ir;

    if (ivmd_block->header.length <
       sizeof(struct acpi_ivmd_block_header))
    {
       dprintk(XENLOG_ERR, "IVMD Error: Invalid Block Length!\n");
       return -ENODEV;
    }

    start_addr = (unsigned long)ivmd_block->start_addr;
    mem_length = (unsigned long)ivmd_block->mem_length;
    base = start_addr & PAGE_MASK;
    limit = (start_addr + mem_length - 1) & PAGE_MASK;

    dprintk(XENLOG_INFO, "IVMD Block: Type 0x%x\n",
                  ivmd_block->header.type);
    dprintk(XENLOG_INFO, " Start_Addr_Phys 0x%lx\n", start_addr);
    dprintk(XENLOG_INFO, " Mem_Length 0x%lx\n", mem_length);

    if ( get_field_from_byte(ivmd_block->header.flags,
                             AMD_IOMMU_ACPI_EXCLUSION_RANGE_MASK,
                             AMD_IOMMU_ACPI_EXCLUSION_RANGE_SHIFT) )
        iw = ir = IOMMU_CONTROL_ENABLED;
    else if ( get_field_from_byte(ivmd_block->header.flags,
                                  AMD_IOMMU_ACPI_UNITY_MAPPING_MASK,
                                  AMD_IOMMU_ACPI_UNITY_MAPPING_SHIFT) )
    {
        iw = get_field_from_byte(ivmd_block->header.flags,
                                 AMD_IOMMU_ACPI_IW_PERMISSION_MASK,
                                 AMD_IOMMU_ACPI_IW_PERMISSION_SHIFT);
        ir = get_field_from_byte(ivmd_block->header.flags,
                                 AMD_IOMMU_ACPI_IR_PERMISSION_MASK,
                                 AMD_IOMMU_ACPI_IR_PERMISSION_SHIFT);
    }
    else
    {
       dprintk(KERN_ERR, "IVMD Error: Invalid Flag Field!\n");
       return -ENODEV;
    }

    switch( ivmd_block->header.type )
    {
    case AMD_IOMMU_ACPI_IVMD_ALL_TYPE:
        return register_exclusion_range_for_all_devices(
           base, limit, iw, ir);

    case AMD_IOMMU_ACPI_IVMD_ONE_TYPE:
        return parse_ivmd_device_select(ivmd_block,
           base, limit, iw, ir);

    case AMD_IOMMU_ACPI_IVMD_RANGE_TYPE:
        return parse_ivmd_device_range(ivmd_block,
            base, limit, iw, ir);

    case AMD_IOMMU_ACPI_IVMD_IOMMU_TYPE:
        return parse_ivmd_device_iommu(ivmd_block,
           base, limit, iw, ir);

    default:
        dprintk(XENLOG_ERR, "IVMD Error: Invalid Block Type!\n");
        return -ENODEV;
    }
}

static u16 __init parse_ivhd_device_padding(u16 pad_length,
           u16 header_length, u16 block_length)
{
    if ( header_length < (block_length + pad_length) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    return pad_length;
}

static u16 __init parse_ivhd_device_select(
           union acpi_ivhd_device *ivhd_device)
{
    u16 bdf;

    bdf = ivhd_device->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    /* override flags for device */
    ivrs_mappings[bdf].dte_sys_mgt_enable =
        get_field_from_byte(ivhd_device->header.flags,
                            AMD_IOMMU_ACPI_SYS_MGT_MASK,
                            AMD_IOMMU_ACPI_SYS_MGT_SHIFT);

    return sizeof(struct acpi_ivhd_device_header);
}

static u16 __init parse_ivhd_device_range(
           union acpi_ivhd_device *ivhd_device,
           u16 header_length, u16 block_length)
{
    u16 dev_length, first_bdf, last_bdf, bdf;
    u8 sys_mgt;

    dev_length = sizeof(struct acpi_ivhd_device_range);
    if ( header_length < (block_length + dev_length) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( ivhd_device->range.trailer.type !=
        AMD_IOMMU_ACPI_IVHD_DEV_RANGE_END) {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Range: End_Type 0x%x\n",
                ivhd_device->range.trailer.type);
        return 0;
    }

    first_bdf = ivhd_device->header.dev_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
       dprintk(XENLOG_ERR, "IVHD Error: "
           "Invalid Range: First Dev_Id 0x%x\n", first_bdf);
       return 0;
    }

    last_bdf = ivhd_device->range.trailer.dev_id;
    if ( last_bdf >= ivrs_bdf_entries || last_bdf <= first_bdf )
    {
       dprintk(XENLOG_ERR, "IVHD Error: "
           "Invalid Range: Last Dev_Id 0x%x\n", last_bdf);
       return 0;
    }

    dprintk(XENLOG_INFO, " Dev_Id Range: 0x%x -> 0x%x\n",
        first_bdf, last_bdf);

    /* override flags for range of devices */
    sys_mgt = get_field_from_byte(ivhd_device->header.flags,
                                 AMD_IOMMU_ACPI_SYS_MGT_MASK,
                                 AMD_IOMMU_ACPI_SYS_MGT_SHIFT);
    for ( bdf = first_bdf; bdf <= last_bdf; ++bdf )
        ivrs_mappings[bdf].dte_sys_mgt_enable = sys_mgt;

    return dev_length;
}

static u16 __init parse_ivhd_device_alias(
           union acpi_ivhd_device *ivhd_device,
           u16 header_length, u16 block_length)
{
    u16 dev_length, alias_id, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_alias);
    if ( header_length < (block_length + dev_length) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
            "Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = ivhd_device->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    alias_id = ivhd_device->alias.dev_id;
    if ( alias_id >= ivrs_bdf_entries )
    {
       dprintk(XENLOG_ERR, "IVHD Error: "
               "Invalid Alias Dev_Id 0x%x\n", alias_id);
       return 0;
    }

    dprintk(XENLOG_INFO, " Dev_Id Alias: 0x%x\n", alias_id);

    /* override requestor_id and flags for device */
    ivrs_mappings[bdf].dte_requestor_id = alias_id;
    ivrs_mappings[bdf].dte_sys_mgt_enable =
            get_field_from_byte(ivhd_device->header.flags,
                                AMD_IOMMU_ACPI_SYS_MGT_MASK,
                                AMD_IOMMU_ACPI_SYS_MGT_SHIFT);
    ivrs_mappings[alias_id].dte_sys_mgt_enable =
            ivrs_mappings[bdf].dte_sys_mgt_enable;

    return dev_length;
}

static u16 __init parse_ivhd_device_alias_range(
           union acpi_ivhd_device *ivhd_device,
           u16 header_length, u16 block_length)
{

    u16 dev_length, first_bdf, last_bdf, alias_id, bdf;
    u8 sys_mgt;

    dev_length = sizeof(struct acpi_ivhd_device_alias_range);
    if ( header_length < (block_length + dev_length) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( ivhd_device->alias_range.trailer.type !=
       AMD_IOMMU_ACPI_IVHD_DEV_RANGE_END )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Range: End_Type 0x%x\n",
                ivhd_device->alias_range.trailer.type);
        return 0;
    }

    first_bdf = ivhd_device->header.dev_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        dprintk(XENLOG_ERR,"IVHD Error: "
                "Invalid Range: First Dev_Id 0x%x\n", first_bdf);
        return 0;
    }

    last_bdf = ivhd_device->alias_range.trailer.dev_id;
    if ( last_bdf >= ivrs_bdf_entries || last_bdf <= first_bdf )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Range: Last Dev_Id 0x%x\n", last_bdf);
        return 0;
    }

    alias_id = ivhd_device->alias_range.alias.dev_id;
    if ( alias_id >= ivrs_bdf_entries )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Alias Dev_Id 0x%x\n", alias_id);
        return 0;
    }

    dprintk(XENLOG_INFO, " Dev_Id Range: 0x%x -> 0x%x\n",
            first_bdf, last_bdf);
    dprintk(XENLOG_INFO, " Dev_Id Alias: 0x%x\n", alias_id);

    /* override requestor_id and flags for range of devices */
    sys_mgt = get_field_from_byte(ivhd_device->header.flags,
                                  AMD_IOMMU_ACPI_SYS_MGT_MASK,
                                  AMD_IOMMU_ACPI_SYS_MGT_SHIFT);
    for ( bdf = first_bdf; bdf <= last_bdf; ++bdf )
    {
        ivrs_mappings[bdf].dte_requestor_id = alias_id;
        ivrs_mappings[bdf].dte_sys_mgt_enable = sys_mgt;
    }
    ivrs_mappings[alias_id].dte_sys_mgt_enable = sys_mgt;

    return dev_length;
}

static u16 __init parse_ivhd_device_extended(
           union acpi_ivhd_device *ivhd_device,
           u16 header_length, u16 block_length)
{
    u16 dev_length, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_extended);
    if ( header_length < (block_length + dev_length) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = ivhd_device->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    /* override flags for device */
    ivrs_mappings[bdf].dte_sys_mgt_enable =
        get_field_from_byte(ivhd_device->header.flags,
                            AMD_IOMMU_ACPI_SYS_MGT_MASK,
                            AMD_IOMMU_ACPI_SYS_MGT_SHIFT);

    return dev_length;
}

static u16 __init parse_ivhd_device_extended_range(
           union acpi_ivhd_device *ivhd_device,
           u16 header_length, u16 block_length)
{
    u16 dev_length, first_bdf, last_bdf, bdf;
    u8 sys_mgt;

    dev_length = sizeof(struct acpi_ivhd_device_extended_range);
    if ( header_length < (block_length + dev_length) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( ivhd_device->extended_range.trailer.type !=
        AMD_IOMMU_ACPI_IVHD_DEV_RANGE_END )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Range: End_Type 0x%x\n",
                ivhd_device->extended_range.trailer.type);
        return 0;
    }

    first_bdf = ivhd_device->header.dev_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
       dprintk(XENLOG_ERR, "IVHD Error: "
           "Invalid Range: First Dev_Id 0x%x\n", first_bdf);
       return 0;
    }

    last_bdf = ivhd_device->extended_range.trailer.dev_id;
    if ( last_bdf >= ivrs_bdf_entries || last_bdf <= first_bdf )
    {
        dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Range: Last Dev_Id 0x%x\n", last_bdf);
        return 0;
    }

    dprintk(XENLOG_INFO, " Dev_Id Range: 0x%x -> 0x%x\n",
            first_bdf, last_bdf);

    /* override flags for range of devices */
    sys_mgt = get_field_from_byte(ivhd_device->header.flags,
                                  AMD_IOMMU_ACPI_SYS_MGT_MASK,
                                  AMD_IOMMU_ACPI_SYS_MGT_SHIFT);
    for ( bdf = first_bdf; bdf <= last_bdf; ++bdf )
        ivrs_mappings[bdf].dte_sys_mgt_enable = sys_mgt;

    return dev_length;
}

static int __init parse_ivhd_block(struct acpi_ivhd_block_header *ivhd_block)
{
    union acpi_ivhd_device *ivhd_device;
    u16 block_length, dev_length;
    struct amd_iommu *iommu;

    if ( ivhd_block->header.length <
        sizeof(struct acpi_ivhd_block_header) )
    {
        dprintk(XENLOG_ERR, "IVHD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    iommu = find_iommu_from_bdf_cap(ivhd_block->header.dev_id,
            ivhd_block->cap_offset);
    if ( !iommu )
    {
        dprintk(XENLOG_ERR,
                "IVHD Error: No IOMMU for Dev_Id 0x%x  Cap 0x%x\n",
                ivhd_block->header.dev_id, ivhd_block->cap_offset);
       return -ENODEV;
    }

    dprintk(XENLOG_INFO, "IVHD Block:\n");
    dprintk(XENLOG_INFO, " Cap_Offset 0x%x\n",
            ivhd_block->cap_offset);
    dprintk(XENLOG_INFO, " MMIO_BAR_Phys 0x%lx\n",
            (unsigned long)ivhd_block->mmio_base);
    dprintk(XENLOG_INFO, " PCI_Segment 0x%x\n",
            ivhd_block->pci_segment);
    dprintk(XENLOG_INFO, " IOMMU_Info 0x%x\n",
            ivhd_block->iommu_info);

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
    iommu->ht_tunnel_enable = get_field_from_byte(
                                          ivhd_block->header.flags,
                                          AMD_IOMMU_ACPI_HT_TUN_ENB_MASK,
                                          AMD_IOMMU_ACPI_HT_TUN_ENB_SHIFT);

    /* parse Device Entries */
    block_length = sizeof(struct acpi_ivhd_block_header);
    while( ivhd_block->header.length >=
       (block_length + sizeof(struct acpi_ivhd_device_header)) )
    {
        ivhd_device = (union acpi_ivhd_device *)
                ((u8 *)ivhd_block + block_length);

        dprintk(XENLOG_INFO, "IVHD Device Entry:\n");
        dprintk(XENLOG_INFO, " Type 0x%x\n",
                ivhd_device->header.type);
        dprintk(XENLOG_INFO, " Dev_Id 0x%x\n",
                ivhd_device->header.dev_id);
        dprintk(XENLOG_INFO, " Flags 0x%x\n",
                ivhd_device->header.flags);

        switch( ivhd_device->header.type )
        {
        case AMD_IOMMU_ACPI_IVHD_DEV_U32_PAD:
            dev_length = parse_ivhd_device_padding(
                sizeof(u32),
                ivhd_block->header.length, block_length);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_U64_PAD:
            dev_length = parse_ivhd_device_padding(
                sizeof(u64),
                ivhd_block->header.length, block_length);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_SELECT:
            dev_length = parse_ivhd_device_select(ivhd_device);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_RANGE_START:
            dev_length = parse_ivhd_device_range(ivhd_device,
                ivhd_block->header.length, block_length);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_ALIAS_SELECT:
            dev_length = parse_ivhd_device_alias(
                ivhd_device,
                ivhd_block->header.length, block_length);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_ALIAS_RANGE:
            dev_length = parse_ivhd_device_alias_range(
                ivhd_device,
                ivhd_block->header.length, block_length);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_EXT_SELECT:
            dev_length = parse_ivhd_device_extended(
                ivhd_device,
                ivhd_block->header.length, block_length);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_EXT_RANGE:
            dev_length = parse_ivhd_device_extended_range(
                ivhd_device,
                ivhd_block->header.length, block_length);
            break;
        default:
            dprintk(XENLOG_ERR, "IVHD Error: "
                "Invalid Device Type!\n");
            dev_length = 0;
            break;
        }

        block_length += dev_length;
        if ( !dev_length )
            return -ENODEV;
    }

    return 0;
}

static int __init parse_ivrs_block(struct acpi_ivrs_block_header *ivrs_block)
{
    struct acpi_ivhd_block_header *ivhd_block;
    struct acpi_ivmd_block_header *ivmd_block;

    switch(ivrs_block->type)
    {
    case AMD_IOMMU_ACPI_IVHD_TYPE:
        ivhd_block = (struct acpi_ivhd_block_header *)ivrs_block;
        return parse_ivhd_block(ivhd_block);

    case AMD_IOMMU_ACPI_IVMD_ALL_TYPE:
    case AMD_IOMMU_ACPI_IVMD_ONE_TYPE:
    case AMD_IOMMU_ACPI_IVMD_RANGE_TYPE:
    case AMD_IOMMU_ACPI_IVMD_IOMMU_TYPE:
        ivmd_block = (struct acpi_ivmd_block_header *)ivrs_block;
        return parse_ivmd_block(ivmd_block);

    default:
        dprintk(XENLOG_ERR, "IVRS Error: Invalid Block Type!\n");
        return -ENODEV;
    }

    return 0;
}

void __init dump_acpi_table_header(struct acpi_table_header *table)
{
    int i;

    printk(XENLOG_INFO "AMD IOMMU: ACPI Table:\n");
    printk(XENLOG_INFO " Signature ");
    for ( i = 0; i < ACPI_NAME_SIZE; ++i )
        printk("%c", table->signature[i]);
    printk("\n");

    printk(" Length 0x%x\n", table->length);
    printk(" Revision 0x%x\n", table->revision);
    printk(" CheckSum 0x%x\n", table->checksum);

    printk(" OEM_Id ");
    for ( i = 0; i < ACPI_OEM_ID_SIZE; ++i )
        printk("%c", table->oem_id[i]);
    printk("\n");

    printk(" OEM_Table_Id ");
    for ( i = 0; i < ACPI_OEM_TABLE_ID_SIZE; ++i )
        printk("%c", table->oem_table_id[i]);
    printk("\n");

    printk(" OEM_Revision 0x%x\n", table->oem_revision);

    printk(" Creator_Id ");
    for ( i = 0; i < ACPI_NAME_SIZE; ++i )
        printk("%c", table->asl_compiler_id[i]);
    printk("\n");

    printk(" Creator_Revision 0x%x\n",
       table->asl_compiler_revision);
}

int __init parse_ivrs_table(unsigned long phys_addr,
                                  unsigned long size)
{
    struct acpi_ivrs_block_header *ivrs_block;
    unsigned long length, i;
    u8 checksum, *raw_table;
    int error = 0;
    struct acpi_table_header  *table =
        (struct acpi_table_header *) __acpi_map_table(phys_addr, size);

    BUG_ON(!table);

#if 0
    dump_acpi_table_header(table);
#endif

    /* validate checksum: sum of entire table == 0 */
    checksum = 0;
    raw_table = (u8 *)table;
    for ( i = 0; i < table->length; ++i )
        checksum += raw_table[i];
    if ( checksum )
    {
        dprintk(XENLOG_ERR, "IVRS Error: "
                "Invalid Checksum 0x%x\n", checksum);
        return -ENODEV;
    }

    /* parse IVRS blocks */
    length = sizeof(struct acpi_ivrs_table_header);
    while( error == 0 && table->length >
       (length + sizeof(struct acpi_ivrs_block_header)) )
    {
        ivrs_block = (struct acpi_ivrs_block_header *)
                ((u8 *)table + length);

        dprintk(XENLOG_INFO, "IVRS Block:\n");
        dprintk(XENLOG_INFO, " Type 0x%x\n", ivrs_block->type);
        dprintk(XENLOG_INFO, " Flags 0x%x\n", ivrs_block->flags);
        dprintk(XENLOG_INFO, " Length 0x%x\n", ivrs_block->length);
        dprintk(XENLOG_INFO, " Dev_Id 0x%x\n", ivrs_block->dev_id);

        if (table->length >= (length + ivrs_block->length))
           error = parse_ivrs_block(ivrs_block);
        else
        {
           dprintk(XENLOG_ERR, "IVRS Error: "
               "Table Length Exceeded: 0x%x -> 0x%lx\n",
               table->length,
               (length + ivrs_block->length));
           return -ENODEV;
        }
        length += ivrs_block->length;
    }

    return error;
}
