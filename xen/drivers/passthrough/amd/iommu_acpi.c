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
#include <asm/apicdef.h>
#include <asm/io_apic.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

/* Some helper structures, particularly to deal with ranges. */

struct acpi_ivhd_device_range {
   struct acpi_ivrs_device4 start;
   struct acpi_ivrs_device4 end;
};

struct acpi_ivhd_device_alias_range {
   struct acpi_ivrs_device8a alias;
   struct acpi_ivrs_device4 end;
};

struct acpi_ivhd_device_extended_range {
   struct acpi_ivrs_device8b extended;
   struct acpi_ivrs_device4 end;
};

union acpi_ivhd_device {
   struct acpi_ivrs_de_header header;
   struct acpi_ivrs_device4 select;
   struct acpi_ivhd_device_range range;
   struct acpi_ivrs_device8a alias;
   struct acpi_ivhd_device_alias_range alias_range;
   struct acpi_ivrs_device8b extended;
   struct acpi_ivhd_device_extended_range extended_range;
   struct acpi_ivrs_device8c special;
};

static void __init add_ivrs_mapping_entry(
    u16 bdf, u16 alias_id, u8 flags, struct amd_iommu *iommu)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(iommu->seg);

    ASSERT( ivrs_mappings != NULL );

    /* setup requestor id */
    ivrs_mappings[bdf].dte_requestor_id = alias_id;

    /* override flags for range of devices */
    ivrs_mappings[bdf].device_flags = flags;

    if (ivrs_mappings[alias_id].intremap_table == NULL )
    {
         /* allocate per-device interrupt remapping table */
         if ( amd_iommu_perdev_intremap )
             ivrs_mappings[alias_id].intremap_table =
                amd_iommu_alloc_intremap_table(
                    &ivrs_mappings[alias_id].intremap_inuse);
         else
         {
             if ( shared_intremap_table == NULL  )
                 shared_intremap_table = amd_iommu_alloc_intremap_table(
                     &shared_intremap_inuse);
             ivrs_mappings[alias_id].intremap_table = shared_intremap_table;
             ivrs_mappings[alias_id].intremap_inuse = shared_intremap_inuse;
         }
    }
    /* assgin iommu hardware */
    ivrs_mappings[bdf].iommu = iommu;
}

static struct amd_iommu * __init find_iommu_from_bdf_cap(
    u16 seg, u16 bdf, u16 cap_offset)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
        if ( (iommu->seg == seg) && (iommu->bdf == bdf) &&
             (iommu->cap_offset == cap_offset) )
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
    u16 seg, u16 bdf, unsigned long base,
    unsigned long length, u8 iw, u8 ir)
{
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);
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
    int seg = 0; /* XXX */
    unsigned long range_top, iommu_top, length;
    struct amd_iommu *iommu;
    unsigned int bdf;

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
            reserve_unity_map_for_device(seg, bdf, base, length, iw, ir);
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
    int seg = 0; /* XXX */
    struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);
    unsigned long range_top, iommu_top, length;
    struct amd_iommu *iommu;
    u16 req;

    iommu = find_iommu_for_device(seg, bdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("IVMD Error: No IOMMU for Dev_Id %#x!\n", bdf);
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
        reserve_unity_map_for_device(seg, bdf, base, length, iw, ir);
        reserve_unity_map_for_device(seg, req, base, length, iw, ir);

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
    unsigned int bdf;
    u16 req;

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
            if ( iommu == find_iommu_for_device(iommu->seg, bdf) )
            {
                reserve_unity_map_for_device(iommu->seg, bdf, base, length,
                                             iw, ir);
                req = get_ivrs_mappings(iommu->seg)[bdf].dte_requestor_id;
                reserve_unity_map_for_device(iommu->seg, req, base, length,
                                             iw, ir);
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
    const struct acpi_ivrs_memory *ivmd_block,
    unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    u16 bdf;

    bdf = ivmd_block->header.device_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Dev_Id %#x\n", bdf);
        return -ENODEV;
    }

    return register_exclusion_range_for_device(bdf, base, limit, iw, ir);
}

static int __init parse_ivmd_device_range(
    const struct acpi_ivrs_memory *ivmd_block,
    unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    unsigned int first_bdf, last_bdf, bdf;
    int error;

    first_bdf = ivmd_block->header.device_id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVMD Error: "
                        "Invalid Range_First Dev_Id %#x\n", first_bdf);
        return -ENODEV;
    }

    last_bdf = ivmd_block->aux_data;
    if ( (last_bdf >= ivrs_bdf_entries) || (last_bdf <= first_bdf) )
    {
        AMD_IOMMU_DEBUG("IVMD Error: "
                        "Invalid Range_Last Dev_Id %#x\n", last_bdf);
        return -ENODEV;
    }

    for ( bdf = first_bdf, error = 0; (bdf <= last_bdf) && !error; bdf++ )
        error = register_exclusion_range_for_device(
            bdf, base, limit, iw, ir);

    return error;
}

static int __init parse_ivmd_device_iommu(
    const struct acpi_ivrs_memory *ivmd_block,
    unsigned long base, unsigned long limit, u8 iw, u8 ir)
{
    int seg = 0; /* XXX */
    struct amd_iommu *iommu;

    /* find target IOMMU */
    iommu = find_iommu_from_bdf_cap(seg, ivmd_block->header.device_id,
                                    ivmd_block->aux_data);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("IVMD Error: No IOMMU for Dev_Id %#x Cap %#x\n",
                        ivmd_block->header.device_id, ivmd_block->aux_data);
        return -ENODEV;
    }

    return register_exclusion_range_for_iommu_devices(
        iommu, base, limit, iw, ir);
}

static int __init parse_ivmd_block(const struct acpi_ivrs_memory *ivmd_block)
{
    unsigned long start_addr, mem_length, base, limit;
    u8 iw, ir;

    if ( ivmd_block->header.length < sizeof(*ivmd_block) )
    {
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    start_addr = (unsigned long)ivmd_block->start_address;
    mem_length = (unsigned long)ivmd_block->memory_length;
    base = start_addr & PAGE_MASK;
    limit = (start_addr + mem_length - 1) & PAGE_MASK;

    AMD_IOMMU_DEBUG("IVMD Block: type %#x phys %#lx len %#lx\n",
                    ivmd_block->header.type, start_addr, mem_length);

    if ( ivmd_block->header.flags & ACPI_IVMD_EXCLUSION_RANGE )
        iw = ir = IOMMU_CONTROL_ENABLED;
    else if ( ivmd_block->header.flags & ACPI_IVMD_UNITY )
    {
        iw = ivmd_block->header.flags & ACPI_IVMD_READ ?
            IOMMU_CONTROL_ENABLED : IOMMU_CONTROL_DISABLED;
        ir = ivmd_block->header.flags & ACPI_IVMD_WRITE ?
            IOMMU_CONTROL_ENABLED : IOMMU_CONTROL_DISABLED;
    }
    else
    {
        AMD_IOMMU_DEBUG("IVMD Error: Invalid Flag Field!\n");
        return -ENODEV;
    }

    switch( ivmd_block->header.type )
    {
    case ACPI_IVRS_TYPE_MEMORY_ALL:
        return register_exclusion_range_for_all_devices(
            base, limit, iw, ir);

    case ACPI_IVRS_TYPE_MEMORY_ONE:
        return parse_ivmd_device_select(ivmd_block,
                                        base, limit, iw, ir);

    case ACPI_IVRS_TYPE_MEMORY_RANGE:
        return parse_ivmd_device_range(ivmd_block,
                                       base, limit, iw, ir);

    case ACPI_IVRS_TYPE_MEMORY_IOMMU:
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
    const struct acpi_ivrs_device4 *select, struct amd_iommu *iommu)
{
    u16 bdf;

    bdf = select->header.id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id %#x\n", bdf);
        return 0;
    }

    add_ivrs_mapping_entry(bdf, bdf, select->header.data_setting, iommu);

    return sizeof(*select);
}

static u16 __init parse_ivhd_device_range(
    const struct acpi_ivhd_device_range *range,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    unsigned int dev_length, first_bdf, last_bdf, bdf;

    dev_length = sizeof(*range);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( range->end.header.type != ACPI_IVRS_TYPE_END )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: End_Type %#x\n",
                        range->end.header.type);
        return 0;
    }

    first_bdf = range->start.header.id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: First Dev_Id %#x\n", first_bdf);
        return 0;
    }

    last_bdf = range->end.header.id;
    if ( (last_bdf >= ivrs_bdf_entries) || (last_bdf <= first_bdf) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: Last Dev_Id %#x\n", last_bdf);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Range: %#x -> %#x\n", first_bdf, last_bdf);

    for ( bdf = first_bdf; bdf <= last_bdf; bdf++ )
        add_ivrs_mapping_entry(bdf, bdf, range->start.header.data_setting,
                               iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_alias(
    const struct acpi_ivrs_device8a *alias,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, alias_id, bdf;

    dev_length = sizeof(*alias);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = alias->header.id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id %#x\n", bdf);
        return 0;
    }

    alias_id = alias->used_id;
    if ( alias_id >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Alias Dev_Id %#x\n", alias_id);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Alias: %#x\n", alias_id);

    add_ivrs_mapping_entry(bdf, alias_id, alias->header.data_setting, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_alias_range(
    const struct acpi_ivhd_device_alias_range *range,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{

    unsigned int dev_length, first_bdf, last_bdf, alias_id, bdf;

    dev_length = sizeof(*range);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( range->end.header.type != ACPI_IVRS_TYPE_END )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: End_Type %#x\n",
                        range->end.header.type);
        return 0;
    }

    first_bdf = range->alias.header.id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: First Dev_Id %#x\n", first_bdf);
        return 0;
    }

    last_bdf = range->end.header.id;
    if ( last_bdf >= ivrs_bdf_entries || last_bdf <= first_bdf )
    {
        AMD_IOMMU_DEBUG(
            "IVHD Error: Invalid Range: Last Dev_Id %#x\n", last_bdf);
        return 0;
    }

    alias_id = range->alias.used_id;
    if ( alias_id >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Alias Dev_Id %#x\n", alias_id);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Range: %#x -> %#x alias %#x\n",
                    first_bdf, last_bdf, alias_id);

    for ( bdf = first_bdf; bdf <= last_bdf; bdf++ )
        add_ivrs_mapping_entry(bdf, alias_id, range->alias.header.data_setting,
                               iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_extended(
    const struct acpi_ivrs_device8b *ext,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, bdf;

    dev_length = sizeof(*ext);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = ext->header.id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id %#x\n", bdf);
        return 0;
    }

    add_ivrs_mapping_entry(bdf, bdf, ext->header.data_setting, iommu);

    return dev_length;
}

static u16 __init parse_ivhd_device_extended_range(
    const struct acpi_ivhd_device_extended_range *range,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    unsigned int dev_length, first_bdf, last_bdf, bdf;

    dev_length = sizeof(*range);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    if ( range->end.header.type != ACPI_IVRS_TYPE_END )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: End_Type %#x\n",
                        range->end.header.type);
        return 0;
    }

    first_bdf = range->extended.header.id;
    if ( first_bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: First Dev_Id %#x\n", first_bdf);
        return 0;
    }

    last_bdf = range->end.header.id;
    if ( (last_bdf >= ivrs_bdf_entries) || (last_bdf <= first_bdf) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: "
                        "Invalid Range: Last Dev_Id %#x\n", last_bdf);
        return 0;
    }

    AMD_IOMMU_DEBUG(" Dev_Id Range: %#x -> %#x\n",
                    first_bdf, last_bdf);

    for ( bdf = first_bdf; bdf <= last_bdf; bdf++ )
        add_ivrs_mapping_entry(bdf, bdf, range->extended.header.data_setting,
                               iommu);

    return dev_length;
}

static DECLARE_BITMAP(ioapic_cmdline, ARRAY_SIZE(ioapic_sbdf)) __initdata;

static void __init parse_ivrs_ioapic(char *str)
{
    const char *s = str;
    unsigned long id;
    unsigned int seg, bus, dev, func;

    ASSERT(*s == '[');
    id = simple_strtoul(s + 1, &s, 0);
    if ( id >= ARRAY_SIZE(ioapic_sbdf) || *s != ']' || *++s != '=' )
        return;

    s = parse_pci(s + 1, &seg, &bus, &dev, &func);
    if ( !s || *s )
        return;

    ioapic_sbdf[id].bdf = PCI_BDF(bus, dev, func);
    ioapic_sbdf[id].seg = seg;
    __set_bit(id, ioapic_cmdline);
}
custom_param("ivrs_ioapic[", parse_ivrs_ioapic);

static void __init parse_ivrs_hpet(char *str)
{
    const char *s = str;
    unsigned long id;
    unsigned int seg, bus, dev, func;

    ASSERT(*s == '[');
    id = simple_strtoul(s + 1, &s, 0);
    if ( id != (typeof(hpet_sbdf.id))id || *s != ']' || *++s != '=' )
        return;

    s = parse_pci(s + 1, &seg, &bus, &dev, &func);
    if ( !s || *s )
        return;

    hpet_sbdf.id = id;
    hpet_sbdf.bdf = PCI_BDF(bus, dev, func);
    hpet_sbdf.seg = seg;
    hpet_sbdf.init = HPET_CMDL;
}
custom_param("ivrs_hpet[", parse_ivrs_hpet);

static u16 __init parse_ivhd_device_special(
    const struct acpi_ivrs_device8c *special, u16 seg,
    u16 header_length, u16 block_length, struct amd_iommu *iommu)
{
    u16 dev_length, bdf;
    int apic;

    dev_length = sizeof(*special);
    if ( header_length < (block_length + dev_length) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Length!\n");
        return 0;
    }

    bdf = special->used_id;
    if ( bdf >= ivrs_bdf_entries )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Device_Entry Dev_Id %#x\n", bdf);
        return 0;
    }

    AMD_IOMMU_DEBUG("IVHD Special: %04x:%02x:%02x.%u variety %#x handle %#x\n",
                    seg, PCI_BUS(bdf), PCI_SLOT(bdf), PCI_FUNC(bdf),
                    special->variety, special->handle);
    add_ivrs_mapping_entry(bdf, bdf, special->header.data_setting, iommu);

    switch ( special->variety )
    {
    case ACPI_IVHD_IOAPIC:
        if ( !iommu_intremap )
            break;
        /*
         * Some BIOSes have IOAPIC broken entries so we check for IVRS
         * consistency here --- whether entry's IOAPIC ID is valid and
         * whether there are conflicting/duplicated entries.
         */
        apic = find_first_bit(ioapic_cmdline, ARRAY_SIZE(ioapic_sbdf));
        while ( apic < ARRAY_SIZE(ioapic_sbdf) )
        {
            if ( ioapic_sbdf[apic].bdf == bdf &&
                 ioapic_sbdf[apic].seg == seg )
                break;
            apic = find_next_bit(ioapic_cmdline, ARRAY_SIZE(ioapic_sbdf),
                                 apic + 1);
        }
        if ( apic < ARRAY_SIZE(ioapic_sbdf) )
        {
            AMD_IOMMU_DEBUG("IVHD: Command line override present for IO-APIC %#x"
                            "(IVRS: %#x devID %04x:%02x:%02x.%u)\n",
                            apic, special->handle, seg, PCI_BUS(bdf),
                            PCI_SLOT(bdf), PCI_FUNC(bdf));
            break;
        }

        for ( apic = 0; apic < nr_ioapics; apic++ )
        {
            if ( IO_APIC_ID(apic) != special->handle )
                continue;

            if ( special->handle >= ARRAY_SIZE(ioapic_sbdf) )
            {
                printk(XENLOG_ERR "IVHD Error: IO-APIC %#x entry beyond bounds\n",
                       special->handle);
                return 0;
            }

            if ( test_bit(special->handle, ioapic_cmdline) )
                AMD_IOMMU_DEBUG("IVHD: Command line override present for IO-APIC %#x\n",
                                special->handle);
            else if ( ioapic_sbdf[special->handle].pin_2_idx )
            {
                if ( ioapic_sbdf[special->handle].bdf == bdf &&
                     ioapic_sbdf[special->handle].seg == seg )
                    AMD_IOMMU_DEBUG("IVHD Warning: Duplicate IO-APIC %#x entries\n",
                                    special->handle);
                else
                {
                    printk(XENLOG_ERR "IVHD Error: Conflicting IO-APIC %#x entries\n",
                           special->handle);
                    if ( amd_iommu_perdev_intremap )
                        return 0;
                }
            }
            else
            {
                /* set device id of ioapic */
                ioapic_sbdf[special->handle].bdf = bdf;
                ioapic_sbdf[special->handle].seg = seg;

                ioapic_sbdf[special->handle].pin_2_idx = xmalloc_array(
                    u16, nr_ioapic_entries[apic]);
                if ( nr_ioapic_entries[apic] &&
                     !ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx )
                {
                    printk(XENLOG_ERR "IVHD Error: Out of memory\n");
                    return 0;
                }
                memset(ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx, -1,
                       nr_ioapic_entries[apic] *
                       sizeof(*ioapic_sbdf->pin_2_idx));
            }
            break;
        }
        if ( apic == nr_ioapics )
        {
            printk(XENLOG_ERR "IVHD Error: Invalid IO-APIC %#x\n",
                   special->handle);
            return 0;
        }
        break;
    case ACPI_IVHD_HPET:
        switch (hpet_sbdf.init)
        {
        case HPET_IVHD:
            printk(XENLOG_WARNING "Only one IVHD HPET entry is supported.\n");
            break;
        case HPET_CMDL:
            AMD_IOMMU_DEBUG("IVHD: Command line override present for HPET %#x "
                            "(IVRS: %#x devID %04x:%02x:%02x.%u)\n",
                            hpet_sbdf.id, special->handle, seg, PCI_BUS(bdf),
                            PCI_SLOT(bdf), PCI_FUNC(bdf));
            break;
        case HPET_NONE:
            /* set device id of hpet */
            hpet_sbdf.id = special->handle;
            hpet_sbdf.bdf = bdf;
            hpet_sbdf.seg = seg;
            hpet_sbdf.init = HPET_IVHD;
            break;
        default:
            ASSERT(0);
            break;
        }
        break;
    default:
        printk(XENLOG_ERR "Unrecognized IVHD special variety %#x\n",
               special->variety);
        return 0;
    }

    return dev_length;
}

static int __init parse_ivhd_block(const struct acpi_ivrs_hardware *ivhd_block)
{
    const union acpi_ivhd_device *ivhd_device;
    u16 block_length, dev_length;
    struct amd_iommu *iommu;

    if ( ivhd_block->header.length < sizeof(*ivhd_block) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    iommu = find_iommu_from_bdf_cap(ivhd_block->pci_segment_group,
                                    ivhd_block->header.device_id,
                                    ivhd_block->capability_offset);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("IVHD Error: No IOMMU for Dev_Id %#x Cap %#x\n",
                        ivhd_block->header.device_id,
                        ivhd_block->capability_offset);
        return -ENODEV;
    }

    /* parse Device Entries */
    block_length = sizeof(*ivhd_block);
    while ( ivhd_block->header.length >=
            (block_length + sizeof(struct acpi_ivrs_de_header)) )
    {
        ivhd_device = (const void *)((const u8 *)ivhd_block + block_length);

        AMD_IOMMU_DEBUG("IVHD Device Entry: type %#x id %#x flags %#x\n",
                        ivhd_device->header.type, ivhd_device->header.id,
                        ivhd_device->header.data_setting);

        switch ( ivhd_device->header.type )
        {
        case ACPI_IVRS_TYPE_PAD4:
            dev_length = parse_ivhd_device_padding(
                sizeof(u32),
                ivhd_block->header.length, block_length);
            break;
        case ACPI_IVRS_TYPE_PAD8:
            dev_length = parse_ivhd_device_padding(
                sizeof(u64),
                ivhd_block->header.length, block_length);
            break;
        case ACPI_IVRS_TYPE_SELECT:
            dev_length = parse_ivhd_device_select(&ivhd_device->select, iommu);
            break;
        case ACPI_IVRS_TYPE_START:
            dev_length = parse_ivhd_device_range(
                &ivhd_device->range,
                ivhd_block->header.length, block_length, iommu);
            break;
        case ACPI_IVRS_TYPE_ALIAS_SELECT:
            dev_length = parse_ivhd_device_alias(
                &ivhd_device->alias,
                ivhd_block->header.length, block_length, iommu);
            break;
        case ACPI_IVRS_TYPE_ALIAS_START:
            dev_length = parse_ivhd_device_alias_range(
                &ivhd_device->alias_range,
                ivhd_block->header.length, block_length, iommu);
            break;
        case ACPI_IVRS_TYPE_EXT_SELECT:
            dev_length = parse_ivhd_device_extended(
                &ivhd_device->extended,
                ivhd_block->header.length, block_length, iommu);
            break;
        case ACPI_IVRS_TYPE_EXT_START:
            dev_length = parse_ivhd_device_extended_range(
                &ivhd_device->extended_range,
                ivhd_block->header.length, block_length, iommu);
            break;
        case ACPI_IVRS_TYPE_SPECIAL:
            dev_length = parse_ivhd_device_special(
                &ivhd_device->special, ivhd_block->pci_segment_group,
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

static int __init parse_ivrs_block(const struct acpi_ivrs_header *ivrs_block)
{
    const struct acpi_ivrs_hardware *ivhd_block;
    const struct acpi_ivrs_memory *ivmd_block;

    switch ( ivrs_block->type )
    {
    case ACPI_IVRS_TYPE_HARDWARE:
        ivhd_block = container_of(ivrs_block, const struct acpi_ivrs_hardware,
                                  header);
        return parse_ivhd_block(ivhd_block);

    case ACPI_IVRS_TYPE_MEMORY_ALL:
    case ACPI_IVRS_TYPE_MEMORY_ONE:
    case ACPI_IVRS_TYPE_MEMORY_RANGE:
    case ACPI_IVRS_TYPE_MEMORY_IOMMU:
        ivmd_block = container_of(ivrs_block, const struct acpi_ivrs_memory,
                                  header);
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

    AMD_IOMMU_DEBUG(" Length %#x\n", table->length);
    AMD_IOMMU_DEBUG(" Revision %#x\n", table->revision);
    AMD_IOMMU_DEBUG(" CheckSum %#x\n", table->checksum);

    AMD_IOMMU_DEBUG(" OEM_Id ");
    for ( i = 0; i < ACPI_OEM_ID_SIZE; i++ )
        printk("%c", table->oem_id[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" OEM_Table_Id ");
    for ( i = 0; i < ACPI_OEM_TABLE_ID_SIZE; i++ )
        printk("%c", table->oem_table_id[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" OEM_Revision %#x\n", table->oem_revision);

    AMD_IOMMU_DEBUG(" Creator_Id ");
    for ( i = 0; i < ACPI_NAME_SIZE; i++ )
        printk("%c", table->asl_compiler_id[i]);
    printk("\n");

    AMD_IOMMU_DEBUG(" Creator_Revision %#x\n",
                    table->asl_compiler_revision);

}

static int __init parse_ivrs_table(struct acpi_table_header *table)
{
    const struct acpi_ivrs_header *ivrs_block;
    unsigned long length;
    unsigned int apic;
    bool_t sb_ioapic = !iommu_intremap;
    int error = 0;

    BUG_ON(!table);

    if ( iommu_debug )
        dump_acpi_table_header(table);

    /* parse IVRS blocks */
    length = sizeof(struct acpi_table_ivrs);
    while ( (error == 0) && (table->length > (length + sizeof(*ivrs_block))) )
    {
        ivrs_block = (struct acpi_ivrs_header *)((u8 *)table + length);

        AMD_IOMMU_DEBUG("IVRS Block: type %#x flags %#x len %#x id %#x\n",
                        ivrs_block->type, ivrs_block->flags,
                        ivrs_block->length, ivrs_block->device_id);

        if ( table->length < (length + ivrs_block->length) )
        {
            AMD_IOMMU_DEBUG("IVRS Error: "
                            "Table Length Exceeded: %#x -> %#lx\n",
                            table->length,
                            (length + ivrs_block->length));
            return -ENODEV;
        }

        error = parse_ivrs_block(ivrs_block);
        length += ivrs_block->length;
    }

    /* Each IO-APIC must have been mentioned in the table. */
    for ( apic = 0; !error && iommu_intremap && apic < nr_ioapics; ++apic )
    {
        if ( !nr_ioapic_entries[apic] )
            continue;

        if ( !ioapic_sbdf[IO_APIC_ID(apic)].seg &&
             /* SB IO-APIC is always on this device in AMD systems. */
             ioapic_sbdf[IO_APIC_ID(apic)].bdf == PCI_BDF(0, 0x14, 0) )
            sb_ioapic = 1;

        if ( ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx )
            continue;

        if ( !test_bit(IO_APIC_ID(apic), ioapic_cmdline) )
        {
            printk(XENLOG_ERR "IVHD Error: no information for IO-APIC %#x\n",
                   IO_APIC_ID(apic));
            if ( amd_iommu_perdev_intremap )
                return -ENXIO;
        }

        ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx = xmalloc_array(
            u16, nr_ioapic_entries[apic]);
        if ( ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx )
            memset(ioapic_sbdf[IO_APIC_ID(apic)].pin_2_idx, -1,
                   nr_ioapic_entries[apic] * sizeof(*ioapic_sbdf->pin_2_idx));
        else
        {
            printk(XENLOG_ERR "IVHD Error: Out of memory\n");
            error = -ENOMEM;
        }
    }

    if ( !error && !sb_ioapic )
    {
        if ( amd_iommu_perdev_intremap )
            error = -ENXIO;
        printk("%sNo southbridge IO-APIC found in IVRS table\n",
               amd_iommu_perdev_intremap ? XENLOG_ERR : XENLOG_WARNING);
    }

    return error;
}

static int __init detect_iommu_acpi(struct acpi_table_header *table)
{
    const struct acpi_ivrs_header *ivrs_block;
    unsigned long i;
    unsigned long length = sizeof(struct acpi_table_ivrs);
    u8 checksum, *raw_table;

    /* validate checksum: sum of entire table == 0 */
    checksum = 0;
    raw_table = (u8 *)table;
    for ( i = 0; i < table->length; i++ )
        checksum += raw_table[i];
    if ( checksum )
    {
        AMD_IOMMU_DEBUG("IVRS Error: Invalid Checksum %#x\n", checksum);
        return -ENODEV;
    }

    while ( table->length > (length + sizeof(*ivrs_block)) )
    {
        ivrs_block = (struct acpi_ivrs_header *)((u8 *)table + length);
        if ( table->length < (length + ivrs_block->length) )
            return -ENODEV;
        if ( ivrs_block->type == ACPI_IVRS_TYPE_HARDWARE &&
             amd_iommu_detect_one_acpi(
                 container_of(ivrs_block, const struct acpi_ivrs_hardware,
                              header)) != 0 )
            return -ENODEV;
        length += ivrs_block->length;
    }
    return 0;
}

#define UPDATE_LAST_BDF(x) do {\
   if ((x) > last_bdf) \
       last_bdf = (x); \
   } while(0);

static int __init get_last_bdf_ivhd(
    const struct acpi_ivrs_hardware *ivhd_block)
{
    const union acpi_ivhd_device *ivhd_device;
    u16 block_length, dev_length;
    int last_bdf = 0;

    if ( ivhd_block->header.length < sizeof(*ivhd_block) )
    {
        AMD_IOMMU_DEBUG("IVHD Error: Invalid Block Length!\n");
        return -ENODEV;
    }

    block_length = sizeof(*ivhd_block);
    while ( ivhd_block->header.length >=
            (block_length + sizeof(struct acpi_ivrs_de_header)) )
    {
        ivhd_device = (const void *)((u8 *)ivhd_block + block_length);

        switch ( ivhd_device->header.type )
        {
        case ACPI_IVRS_TYPE_PAD4:
            dev_length = sizeof(u32);
            break;
        case ACPI_IVRS_TYPE_PAD8:
            dev_length = sizeof(u64);
            break;
        case ACPI_IVRS_TYPE_SELECT:
            UPDATE_LAST_BDF(ivhd_device->select.header.id);
            dev_length = sizeof(ivhd_device->header);
            break;
        case ACPI_IVRS_TYPE_ALIAS_SELECT:
            UPDATE_LAST_BDF(ivhd_device->alias.header.id);
            dev_length = sizeof(ivhd_device->alias);
            break;
        case ACPI_IVRS_TYPE_EXT_SELECT:
            UPDATE_LAST_BDF(ivhd_device->extended.header.id);
            dev_length = sizeof(ivhd_device->extended);
            break;
        case ACPI_IVRS_TYPE_START:
            UPDATE_LAST_BDF(ivhd_device->range.end.header.id);
            dev_length = sizeof(ivhd_device->range);
            break;
        case ACPI_IVRS_TYPE_ALIAS_START:
            UPDATE_LAST_BDF(ivhd_device->alias_range.end.header.id)
            dev_length = sizeof(ivhd_device->alias_range);
            break;
        case ACPI_IVRS_TYPE_EXT_START:
            UPDATE_LAST_BDF(ivhd_device->extended_range.end.header.id)
            dev_length = sizeof(ivhd_device->extended_range);
            break;
        case ACPI_IVRS_TYPE_SPECIAL:
            UPDATE_LAST_BDF(ivhd_device->special.used_id)
            dev_length = sizeof(ivhd_device->special);
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

    return last_bdf;
}

static int __init get_last_bdf_acpi(struct acpi_table_header *table)
{
    const struct acpi_ivrs_header *ivrs_block;
    unsigned long length = sizeof(struct acpi_table_ivrs);
    int last_bdf = 0;

    while ( table->length > (length + sizeof(*ivrs_block)) )
    {
        ivrs_block = (struct acpi_ivrs_header *)((u8 *)table + length);
        if ( table->length < (length + ivrs_block->length) )
            return -ENODEV;
        if ( ivrs_block->type == ACPI_IVRS_TYPE_HARDWARE )
        {
            int ret = get_last_bdf_ivhd(
                 container_of(ivrs_block, const struct acpi_ivrs_hardware,
                              header));

            if ( ret < 0 )
                return ret;
            UPDATE_LAST_BDF(ret);
        }
        length += ivrs_block->length;
    }

    return last_bdf;
}

int __init amd_iommu_detect_acpi(void)
{
    return acpi_table_parse(ACPI_SIG_IVRS, detect_iommu_acpi);
}

int __init amd_iommu_get_ivrs_dev_entries(void)
{
    int ret = acpi_table_parse(ACPI_SIG_IVRS, get_last_bdf_acpi);

    return ret < 0 ? ret : (ret | PCI_FUNC(~0)) + 1;
}

int __init amd_iommu_update_ivrs_mapping_acpi(void)
{
    if ( unlikely(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI) )
        return -EPERM;

    return acpi_table_parse(ACPI_SIG_IVRS, parse_ivrs_table);
}
