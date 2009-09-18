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
extern unsigned short last_bdf;
extern int ioapic_bdf[MAX_IO_APICS];

static void add_ivrs_mapping_entry(
    u16 bdf, u16 alias_id, u8 flags, struct amd_iommu *iommu)
{
    u8 sys_mgt, lint1_pass, lint0_pass, nmi_pass, ext_int_pass, init_pass;
    ASSERT( ivrs_mappings != NULL );

    /* setup requestor id */
    ivrs_mappings[bdf].dte_requestor_id = alias_id;

    /* override flags for range of devices */
    sys_mgt = get_field_from_byte(flags,
                                  AMD_IOMMU_ACPI_SYS_MGT_MASK,
                                  AMD_IOMMU_ACPI_SYS_MGT_SHIFT);
    lint1_pass = get_field_from_byte(flags,
                                  AMD_IOMMU_ACPI_LINT1_PASS_MASK,
                                  AMD_IOMMU_ACPI_LINT1_PASS_SHIFT);
    lint0_pass = get_field_from_byte(flags,
                                  AMD_IOMMU_ACPI_LINT0_PASS_MASK,
                                  AMD_IOMMU_ACPI_LINT0_PASS_SHIFT);
    nmi_pass = get_field_from_byte(flags,
                                  AMD_IOMMU_ACPI_NMI_PASS_MASK,
                                  AMD_IOMMU_ACPI_NMI_PASS_SHIFT);
    ext_int_pass = get_field_from_byte(flags,
                                  AMD_IOMMU_ACPI_EINT_PASS_MASK,
                                  AMD_IOMMU_ACPI_EINT_PASS_SHIFT);
    init_pass = get_field_from_byte(flags,
                                  AMD_IOMMU_ACPI_INIT_PASS_MASK,
                                  AMD_IOMMU_ACPI_INIT_PASS_SHIFT);

    ivrs_mappings[bdf].dte_sys_mgt_enable = sys_mgt;
    ivrs_mappings[bdf].dte_lint1_pass = lint1_pass;
    ivrs_mappings[bdf].dte_lint0_pass = lint0_pass;
    ivrs_mappings[bdf].dte_nmi_pass = nmi_pass;
    ivrs_mappings[bdf].dte_ext_int_pass = ext_int_pass;
    ivrs_mappings[bdf].dte_init_pass = init_pass;

    /* allocate per-device interrupt remapping table */
    if ( ivrs_mappings[alias_id].intremap_table == NULL )
        ivrs_mappings[alias_id].intremap_table =
            amd_iommu_alloc_intremap_table();
    /* assgin iommu hardware */
    ivrs_mappings[bdf].iommu = iommu;
}

static struct amd_iommu * __init find_iommu_from_bdf_cap(
    u16 bdf, u8 cap_offset)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
        if ( (iommu->bdf == bdf) && (iommu->cap_offset == cap_offset) )
            return iommu;

    return NULL;
}

static void __init reserve_iommu_exclusion_range(
    struct amd_iommu *iommu, uint64_t base, uint64_t limit)
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

static void __init reserve_iommu_exclusion_range_all(
    struct amd_iommu *iommu,
    unsigned long base, unsigned long limit)
{
    reserve_iommu_exclusion_range(iommu, base, limit);
    iommu->exclusion_allow_all = IOMMU_CONTROL_ENABLED;
}

static void __init reserve_unity_map_for_device(
    u16 bdf, unsigned long base,
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
    ivrs_mappings[bdf].write_permission = iw;
    ivrs_mappings[bdf].read_permission = ir;
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
        if ( range_top > iommu_top )
            range_top = iommu_top;
        length = range_top - base;
        /* reserve r/w unity-mapped page entries for devices */
        /* note: these entries are part of the exclusion range */
        for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
            reserve_unity_map_for_device(bdf, base, length, iw, ir);
        /* push 'base' just outside of virtual address space */
        base = iommu_top;
    }
    /* register IOMMU exclusion range settings */
    if ( limit >= iommu_top )
    {
        for_each_amd_iommu( iommu )
            reserve_iommu_exclusion_range_all(iommu, base, limit);
    }

    return 0;
}

static int __init register_exclusion_range_for_device(
    u16 bdf, unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    unsigned long range_top, iommu_top, length;
    struct amd_iommu *iommu;
    u16 req;

    iommu = find_iommu_for_device(bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("IVMD Error: No IOMMU for Dev_Id 0x%x!\n", bdf);
        return -ENODEV;
    }
    req = ivrs_mappings[bdf].dte_requestor_id;

    /* note: 'limit' parameter is assumed to be page-aligned */
    range_top = limit + PAGE_SIZE;
    iommu_top = max_page * PAGE_SIZE;
    if ( base < iommu_top )
    {
        if ( range_top > iommu_top )
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
    u16 bdf, req;

    /* is part of exclusion range inside of IOMMU virtual address space? */
    /* note: 'limit' parameter is assumed to be page-aligned */
    range_top = limit + PAGE_SIZE;
    iommu_top = max_page * PAGE_SIZE;
    if ( base < iommu_top )
    {
        if ( range_top > iommu_top )
            range_top = iommu_top;
        length = range_top - base;
        /* reserve r/w unity-mapped page entries for devices */
        /* note: these entries are part of the exclusion range */
        for ( bdf = 0; bdf < ivrs_bdf_entries; bdf++ )
        {
            if ( iommu == find_iommu_for_device(bdf) )
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
    if ( limit >= iommu_top )
        reserve_iommu_exclusion_range_all(iommu, base, limit);
    return 0;
}

static int __init parse_ivmd_device_select(
    struct acpi_ivmd_block_header *ivmd_block,
    unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    u16 bdf;

    bdf = ivmd_block->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Dev_Id 0x%x\n", bdf);
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
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG(
            "IVMD Error: Invalid Range_First Dev_Id 0x%x\n", first_bdf);
        return -ENODEV;
    }

    last_bdf = ivmd_block->last_dev_id;
    if ( (last_bdf >= ivrs_bdf_entries) || (last_bdf <= first_bdf) )
    {
        AMD_IOMMU_DEBUG(
            "IVMD Error: Invalid Range_Last Dev_Id 0x%x\n", last_bdf);
        return -ENODEV;
    }

    for ( bdf = first_bdf, error = 0; (bdf <= last_bdf) && !error; bdf++ )
        error = register_exclusion_range_for_device(
            bdf, base, limit, iw, ir);

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
        AMD_IOMMU_DEBUG("IVMD Error: No IOMMU for Dev_Id 0x%x  Cap 0x%x\n",
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

    if ( ivmd_block->header.length <
         sizeof(struct acpi_ivmd_block_header) )
    {
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    start_addr = (unsigned long)ivmd_block->start_addr;
    mem_length = (unsigned long)ivmd_block->mem_length;
    base = start_addr & PAGE_MASK;
    limit = (start_addr + mem_length - 1) & PAGE_MASK;

    AMD_IOMMU_DEBUG("IVMD Block: Type 0x%x\n",ivmd_block->header.type);
    AMD_IOMMU_DEBUG(" Start_Addr_Phys 0x%lx\n", start_addr);
    AMD_IOMMU_DEBUG(" Mem_Length 0x%lx\n", mem_length);

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
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Flag Field!\n");
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
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Block Type!\n");
        return -ENODEV;
    }
}

static u16 __init parse_ivhd_device_padding(
    u16 pad_length, u16 header_length, u16 block_length)
{
    if ( header_length < (block_length + pad_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    return pad_length;
}

static u16 __init parse_ivhd_device_select(
    union acpi_ivhd_device *ivhd_device, struct amd_iommu *iommu)
{
    u16 bdf;

    bdf = ivhd_device->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    add_ivrs_mapping_entry(bdf, bdf, ivhd_device->header.flags, iommu);

    return sizeof(struct acpi_ivhd_device_header);
}

static u16 __init parse_ivhd_device_range(
    union acpi_ivhd_device *ivhd_device,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, first_bdf, last_bdf, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_range);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( ivhd_device->range.trailer.type !=
         AMD_IOMMU_ACPI_IVHD_DEV_RANGE_END )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                "Invalid Range: End_Type 0x%x\n",
                ivhd_device->range.trailer.type);
        return 0;
    }

    first_bdf = ivhd_device->header.dev_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: First Dev_Id 0x%x\n", first_bdf);
        return 0;
    }

    last_bdf = ivhd_device->range.trailer.dev_id;
    if ( (last_bdf >= ivrs_bdf_entries) || (last_bdf <= first_bdf) )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: Last Dev_Id 0x%x\n", last_bdf);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Range: 0x%x -> 0x%x\n", first_bdf, last_bdf);

    for ( bdf = first_bdf; bdf <= last_bdf; bdf++ )
        add_ivrs_mapping_entry(bdf, bdf, ivhd_device->header.flags, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_alias(
    union acpi_ivhd_device *ivhd_device,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, alias_id, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_alias);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = ivhd_device->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    alias_id = ivhd_device->alias.dev_id;
    if ( alias_id >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Alias Dev_Id 0x%x\n", alias_id);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Alias: 0x%x\n", alias_id);

    add_ivrs_mapping_entry(bdf, alias_id, ivhd_device->header.flags, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_alias_range(
    union acpi_ivhd_device *ivhd_device,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{

    u16 dev_length, first_bdf, last_bdf, alias_id, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_alias_range);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( ivhd_device->alias_range.trailer.type !=
         AMD_IOMMU_ACPI_IVHD_DEV_RANGE_END )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                "Invalid Range: End_Type 0x%x\n",
                ivhd_device->alias_range.trailer.type);
        return 0;
    }

    first_bdf = ivhd_device->header.dev_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: First Dev_Id 0x%x\n", first_bdf);
        return 0;
    }

    last_bdf = ivhd_device->alias_range.trailer.dev_id;
    if ( last_bdf >= ivrs_bdf_entries || last_bdf <= first_bdf )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: Last Dev_Id 0x%x\n", last_bdf);
        return 0;
    }

    alias_id = ivhd_device->alias_range.alias.dev_id;
    if ( alias_id >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Alias Dev_Id 0x%x\n", alias_id);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Range: 0x%x -> 0x%x\n", first_bdf, last_bdf);
    AMD_IOMMU_DEBUG(" Dev_Id Alias: 0x%x\n", alias_id);

    for ( bdf = first_bdf; bdf <= last_bdf; bdf++ )
        add_ivrs_mapping_entry(bdf, alias_id, ivhd_device->header.flags, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_extended(
    union acpi_ivhd_device *ivhd_device,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_extended);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = ivhd_device->header.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    add_ivrs_mapping_entry(bdf, bdf, ivhd_device->header.flags, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_extended_range(
    union acpi_ivhd_device *ivhd_device,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, first_bdf, last_bdf, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_extended_range);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( ivhd_device->extended_range.trailer.type !=
         AMD_IOMMU_ACPI_IVHD_DEV_RANGE_END )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                "Invalid Range: End_Type 0x%x\n",
                ivhd_device->extended_range.trailer.type);
        return 0;
    }

    first_bdf = ivhd_device->header.dev_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: First Dev_Id 0x%x\n", first_bdf);
        return 0;
    }

    last_bdf = ivhd_device->extended_range.trailer.dev_id;
    if ( (last_bdf >= ivrs_bdf_entries) || (last_bdf <= first_bdf) )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: Last Dev_Id 0x%x\n", last_bdf);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Range: 0x%x -> 0x%x\n",
            first_bdf, last_bdf);

    for ( bdf = first_bdf; bdf <= last_bdf; bdf++ )
        add_ivrs_mapping_entry(bdf, bdf, ivhd_device->header.flags, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_special(
    union acpi_ivhd_device *ivhd_device,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, bdf;

    dev_length = sizeof(struct acpi_ivhd_device_special);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = ivhd_device->special.dev_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id 0x%x\n", bdf);
        return 0;
    }

    add_ivrs_mapping_entry(bdf, bdf, ivhd_device->header.flags, iommu);
    /* set device id of ioapic */
    ioapic_bdf[ivhd_device->special.handle] = bdf;
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
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    iommu = find_iommu_from_bdf_cap(ivhd_block->header.dev_id,
                                    ivhd_block->cap_offset);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("IVHD Error: No IOMMU for Dev_Id 0x%x  Cap 0x%x\n",
                ivhd_block->header.dev_id, ivhd_block->cap_offset);
        return -ENODEV;
    }

    /* parse Device Entries */
    block_length = sizeof(struct acpi_ivhd_block_header);
    while ( ivhd_block->header.length >=
            (block_length + sizeof(struct acpi_ivhd_device_header)) )
    {
        ivhd_device = (union acpi_ivhd_device *)
            ((u8 *)ivhd_block + block_length);

        AMD_IOMMU_DEBUG( "IVHD Device Entry:\n");
        AMD_IOMMU_DEBUG( " Type 0x%x\n", ivhd_device->header.type);
        AMD_IOMMU_DEBUG( " Dev_Id 0x%x\n", ivhd_device->header.dev_id);
        AMD_IOMMU_DEBUG( " Flags 0x%x\n", ivhd_device->header.flags);

        switch ( ivhd_device->header.type )
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
            dev_length = parse_ivhd_device_select(ivhd_device, iommu);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_RANGE_START:
            dev_length = parse_ivhd_device_range(
                ivhd_device,
                ivhd_block->header.length, block_length, iommu);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_ALIAS_SELECT:
            dev_length = parse_ivhd_device_alias(
                ivhd_device,
                ivhd_block->header.length, block_length, iommu);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_ALIAS_RANGE:
            dev_length = parse_ivhd_device_alias_range(
                ivhd_device,
                ivhd_block->header.length, block_length, iommu);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_EXT_SELECT:
            dev_length = parse_ivhd_device_extended(
                ivhd_device,
                ivhd_block->header.length, block_length, iommu);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_EXT_RANGE:
            dev_length = parse_ivhd_device_extended_range(
                ivhd_device,
                ivhd_block->header.length, block_length, iommu);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_SPECIAL:
            dev_length = parse_ivhd_device_special(
                ivhd_device,
                ivhd_block->header.length, block_length, iommu);
            break;
        default:
            AMD_IOMMU_DEBUG("IVHD Error: Invalid Device Type!\n");
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

    switch ( ivrs_block->type )
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
        AMD_IOMMU_DEBUG("IVRS Error: Invalid Block Type!\n");
        return -ENODEV;
    }

    return 0;
}

static void __init dump_acpi_table_header(struct acpi_table_header *table)
{
    int i;

    AMD_IOMMU_DEBUG("ACPI Table:\n");
    AMD_IOMMU_DEBUG(" Signature ");
    for ( i = 0; i < ACPI_NAME_SIZE; i++ )
        printk("%c", table->signature[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" Length 0x%x\n", table->length);
    AMD_IOMMU_DEBUG(" Revision 0x%x\n", table->revision);
    AMD_IOMMU_DEBUG(" CheckSum 0x%x\n", table->checksum);

    AMD_IOMMU_DEBUG(" OEM_Id ");
    for ( i = 0; i < ACPI_OEM_ID_SIZE; i++ )
        printk("%c", table->oem_id[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" OEM_Table_Id ");
    for ( i = 0; i < ACPI_OEM_TABLE_ID_SIZE; i++ )
        printk("%c", table->oem_table_id[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" OEM_Revision 0x%x\n", table->oem_revision);

    AMD_IOMMU_DEBUG(" Creator_Id ");
    for ( i = 0; i < ACPI_NAME_SIZE; i++ )
        printk("%c", table->asl_compiler_id[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" Creator_Revision 0x%x\n",
           table->asl_compiler_revision);

}

static int __init parse_ivrs_table(struct acpi_table_header *_table)
{
    struct acpi_ivrs_block_header *ivrs_block;
    unsigned long length;
    int error = 0;
    struct acpi_table_header *table = (struct acpi_table_header *)_table;

    BUG_ON(!table);

    if ( amd_iommu_debug )
        dump_acpi_table_header(table);

    /* parse IVRS blocks */
    length = sizeof(struct acpi_ivrs_table_header);
    while ( (error == 0) && (table->length > (length + sizeof(*ivrs_block))) )
    {
        ivrs_block = (struct acpi_ivrs_block_header *)
            ((u8 *)table + length);

        AMD_IOMMU_DEBUG("IVRS Block:\n");
        AMD_IOMMU_DEBUG(" Type 0x%x\n", ivrs_block->type);
        AMD_IOMMU_DEBUG(" Flags 0x%x\n", ivrs_block->flags);
        AMD_IOMMU_DEBUG(" Length 0x%x\n", ivrs_block->length);
        AMD_IOMMU_DEBUG(" Dev_Id 0x%x\n", ivrs_block->dev_id);

        if ( table->length < (length + ivrs_block->length) )
        {
            AMD_IOMMU_DEBUG("IVRS Error: "
                    "Table Length Exceeded: 0x%x -> 0x%lx\n",
                    table->length,
                    (length + ivrs_block->length));
            return -ENODEV;
        }

        error = parse_ivrs_block(ivrs_block);
        length += ivrs_block->length;
    }

    return error;
}

static int __init detect_iommu_acpi(struct acpi_table_header *_table)
{
    struct acpi_ivrs_block_header *ivrs_block;
    struct acpi_table_header *table = (struct acpi_table_header *)_table;
    unsigned long i;
    unsigned long length = sizeof(struct acpi_ivrs_table_header);
    u8 checksum, *raw_table;

    /* validate checksum: sum of entire table == 0 */
    checksum = 0;
    raw_table = (u8 *)table;
    for ( i = 0; i < table->length; i++ )
        checksum += raw_table[i];
    if ( checksum )
    {
        AMD_IOMMU_DEBUG("IVRS Error: "
                "Invalid Checksum 0x%x\n", checksum);
        return -ENODEV;
    }

    while ( table->length > (length + sizeof(*ivrs_block)) )
    {
        ivrs_block = (struct acpi_ivrs_block_header *) ((u8 *)table + length);
        if ( table->length < (length + ivrs_block->length) )
            return -ENODEV;
        if ( ivrs_block->type == AMD_IOMMU_ACPI_IVHD_TYPE )
            if ( amd_iommu_detect_one_acpi((void*)ivrs_block) != 0 )
                return -ENODEV;
        length += ivrs_block->length;
    }
    return 0;
}

#define UPDATE_LAST_BDF(x) do {\
   if ((x) > last_bdf) \
       last_bdf = (x); \
   } while(0);

static int __init get_last_bdf_ivhd(void *ivhd)
{
    union acpi_ivhd_device *ivhd_device;
    u16 block_length, dev_length;
    struct acpi_ivhd_block_header *ivhd_block;

    ivhd_block = (struct acpi_ivhd_block_header *)ivhd;

    if ( ivhd_block->header.length <
         sizeof(struct acpi_ivhd_block_header) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    block_length = sizeof(struct acpi_ivhd_block_header);
    while ( ivhd_block->header.length >=
            (block_length + sizeof(struct acpi_ivhd_device_header)) )
    {
        ivhd_device = (union acpi_ivhd_device *)
            ((u8 *)ivhd_block + block_length);

        switch ( ivhd_device->header.type )
        {
        case AMD_IOMMU_ACPI_IVHD_DEV_U32_PAD:
            dev_length = sizeof(u32);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_U64_PAD:
            dev_length = sizeof(u64);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_SELECT:
            UPDATE_LAST_BDF(ivhd_device->header.dev_id);
            dev_length = sizeof(struct acpi_ivhd_device_header);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_ALIAS_SELECT:
            UPDATE_LAST_BDF(ivhd_device->header.dev_id);
            dev_length = sizeof(struct acpi_ivhd_device_alias);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_EXT_SELECT:
            UPDATE_LAST_BDF(ivhd_device->header.dev_id);
            dev_length = sizeof(struct acpi_ivhd_device_extended);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_RANGE_START:
            UPDATE_LAST_BDF(ivhd_device->range.trailer.dev_id);
            dev_length = sizeof(struct acpi_ivhd_device_range);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_ALIAS_RANGE:
            UPDATE_LAST_BDF(ivhd_device->alias_range.trailer.dev_id)
            dev_length = sizeof(struct acpi_ivhd_device_alias_range);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_EXT_RANGE:
            UPDATE_LAST_BDF(ivhd_device->extended_range.trailer.dev_id)
            dev_length = sizeof(struct acpi_ivhd_device_extended_range);
            break;
        case AMD_IOMMU_ACPI_IVHD_DEV_SPECIAL:
            UPDATE_LAST_BDF(ivhd_device->special.dev_id)
            dev_length = sizeof(struct acpi_ivhd_device_special);
            break;
        default:
            AMD_IOMMU_DEBUG("IVHD Error: Invalid Device Type!\n");
            dev_length = 0;
            break;
        }

        block_length += dev_length;
        if ( !dev_length )
            return -ENODEV;
    }

    return 0;
}

static int __init get_last_bdf_acpi(struct acpi_table_header *_table)
{
    struct acpi_ivrs_block_header *ivrs_block;
    struct acpi_table_header *table = (struct acpi_table_header *)_table;
    unsigned long length = sizeof(struct acpi_ivrs_table_header);

    while ( table->length > (length + sizeof(*ivrs_block)) )
    {
        ivrs_block = (struct acpi_ivrs_block_header *) ((u8 *)table + length);
        if ( table->length < (length + ivrs_block->length) )
            return -ENODEV;
        if ( ivrs_block->type == AMD_IOMMU_ACPI_IVHD_TYPE )
            if ( get_last_bdf_ivhd((void*)ivrs_block) != 0 )
                return -ENODEV;
        length += ivrs_block->length;
    }
   return 0;
}

int __init amd_iommu_detect_acpi(void)
{
    return acpi_table_parse(AMD_IOMMU_ACPI_IVRS_SIG, detect_iommu_acpi);
}

int __init amd_iommu_get_ivrs_dev_entries(void)
{
    acpi_table_parse(AMD_IOMMU_ACPI_IVRS_SIG, get_last_bdf_acpi);
    return last_bdf + 1;
}

int __init amd_iommu_update_ivrs_mapping_acpi(void)
{
    return acpi_table_parse(AMD_IOMMU_ACPI_IVRS_SIG, parse_ivrs_table);
}
