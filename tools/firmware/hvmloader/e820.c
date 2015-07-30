/*
 * HVM e820 support.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
 * Copyright (c) 2011, Citrix Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "util.h"

struct e820map memory_map;

void memory_map_setup(void)
{
    unsigned int nr_entries = E820MAX, i;
    int rc;
    uint64_t alloc_addr = RESERVED_MEMORY_DYNAMIC_START;
    uint64_t alloc_size = RESERVED_MEMORY_DYNAMIC_END - alloc_addr;

    rc = get_mem_mapping_layout(memory_map.map, &nr_entries);

    if ( rc || !nr_entries )
    {
        printf("Get guest memory maps[%d] failed. (%d)\n", nr_entries, rc);
        BUG();
    }

    memory_map.nr_map = nr_entries;

    for ( i = 0; i < nr_entries; i++ )
    {
        if ( memory_map.map[i].type == E820_RESERVED &&
             check_overlap(alloc_addr, alloc_size,
                           memory_map.map[i].addr, memory_map.map[i].size) )
        {
            printf("Fail to setup memory map due to conflict");
            printf(" on dynamic reserved memory range.\n");
            BUG();
        }
    }
}

/*
 * Sometimes hvmloader may have relocated RAM so low_mem_pgend/high_mem_end
 * would be changed over there. But memory_map[] just records the
 * original low/high memory, so we need to sync these entries once
 * hvmloader modifies low/high memory.
 */
void adjust_memory_map(void)
{
    uint32_t low_mem_end = hvm_info->low_mem_pgend << PAGE_SHIFT;
    uint64_t high_mem_end = (uint64_t)hvm_info->high_mem_pgend << PAGE_SHIFT;
    unsigned int i;

    for ( i = 0; i < memory_map.nr_map; i++ )
    {
        uint64_t map_start = memory_map.map[i].addr;
        uint64_t map_size = memory_map.map[i].size;
        uint64_t map_end = map_start + map_size;

        /* If we need to adjust lowmem. */
        if ( memory_map.map[i].type == E820_RAM &&
             low_mem_end > map_start && low_mem_end < map_end )
        {
            memory_map.map[i].size = low_mem_end - map_start;
            continue;
        }

        /* Modify the existing highmem region if it exists. */
        if ( memory_map.map[i].type == E820_RAM &&
             high_mem_end && map_start == ((uint64_t)1 << 32) )
        {
            if ( high_mem_end != map_end )
                memory_map.map[i].size = high_mem_end - map_start;
            high_mem_end = 0;
            continue;
        }
    }

    /* If there was no highmem region, just create one. */
    if ( high_mem_end )
    {
        memory_map.map[i].addr = ((uint64_t)1 << 32);
        memory_map.map[i].size =
                ((uint64_t)hvm_info->high_mem_pgend << PAGE_SHIFT) -
                    memory_map.map[i].addr;
        memory_map.map[i].type = E820_RAM;
    }
}

void dump_e820_table(struct e820entry *e820, unsigned int nr)
{
    uint64_t last_end = 0, start, end;
    int i;

    printf("E820 table:\n");

    for ( i = 0; i < nr; i++ )
    {
        start = e820[i].addr;
        end = e820[i].addr + e820[i].size;

        if ( start < last_end )
            printf(" OVERLAP!!\n");
        else if ( start > last_end )
            printf(" HOLE: %08x:%08x - %08x:%08x\n",
                   (uint32_t)(last_end >> 32), (uint32_t)last_end,
                   (uint32_t)(start >> 32), (uint32_t)start);

        printf(" [%02d]: %08x:%08x - %08x:%08x: ", i,
               (uint32_t)(start >> 32), (uint32_t)start,
               (uint32_t)(end >> 32), (uint32_t)end);
        switch ( e820[i].type )
        {
        case E820_RAM:
            printf("RAM\n");
            break;
        case E820_RESERVED:
            printf("RESERVED\n");
            break;
        case E820_ACPI:
            printf("ACPI\n");
            break;
        case E820_NVS:
            printf("NVS\n");
            break;
        default:
            printf("UNKNOWN (%08x)\n", e820[i].type);
            break;
        }

        last_end = end;
    }
}

/* Create an E820 table based on memory parameters provided in hvm_info. */
int build_e820_table(struct e820entry *e820,
                     unsigned int lowmem_reserved_base,
                     unsigned int bios_image_base)
{
    unsigned int nr = 0, i, j;
    uint32_t low_mem_end = hvm_info->low_mem_pgend << PAGE_SHIFT;

    if ( !lowmem_reserved_base )
            lowmem_reserved_base = 0xA0000;

    /* Lowmem must be at least 512K to keep Windows happy) */
    ASSERT ( lowmem_reserved_base > 512<<10 );

    ASSERT ( bios_image_base < 0x100000 );

    /*
     * 0x0-lowmem_reserved_base: Ordinary RAM.
     */
    e820[nr].addr = 0x00000;
    e820[nr].size = lowmem_reserved_base;
    e820[nr].type = E820_RAM;
    nr++;

    /* lowmem_reserved_base-0xA0000: reserved by BIOS implementation. */
    if ( lowmem_reserved_base < 0xA0000 )
    {
        /* Reserved for internal use. */
        e820[nr].addr = lowmem_reserved_base;
        e820[nr].size = 0xA0000-lowmem_reserved_base;
        e820[nr].type = E820_RESERVED;
        nr++;
    }

    /*
     * Following regions are standard regions of the PC memory map.
     * They are not covered by e820 regions. OSes will not use as RAM.
     * 0xA0000-0xC0000: VGA memory-mapped I/O. Not covered by E820.
     * 0xC0000-0xE0000: 16-bit devices, expansion ROMs (inc. vgabios).
     * TODO: free pages which turn out to be unused.
     */

    /*
     * BIOS region.
     */
    e820[nr].addr = bios_image_base;
    e820[nr].size = 0x100000-bios_image_base;
    e820[nr].type = E820_RESERVED;
    nr++;

    /*
     * Explicitly reserve space for special pages.
     * This space starts at RESERVED_MEMBASE an extends to cover various
     * fixed hardware mappings (e.g., LAPIC, IOAPIC, default SVGA framebuffer).
     *
     * If igd_opregion_pgbase we need to split the RESERVED region in two.
     */

    if ( igd_opregion_pgbase )
    {
        uint32_t igd_opregion_base = igd_opregion_pgbase << PAGE_SHIFT;

        e820[nr].addr = RESERVED_MEMBASE;
        e820[nr].size = (uint32_t) igd_opregion_base - RESERVED_MEMBASE;
        e820[nr].type = E820_RESERVED;
        nr++;

        e820[nr].addr = igd_opregion_base;
        e820[nr].size = IGD_OPREGION_PAGES * PAGE_SIZE;
        e820[nr].type = E820_NVS;
        nr++;

        e820[nr].addr = igd_opregion_base + IGD_OPREGION_PAGES * PAGE_SIZE;
        e820[nr].size = (uint32_t)-e820[nr].addr;
        e820[nr].type = E820_RESERVED;
        nr++;
    }
    else
    {
        e820[nr].addr = RESERVED_MEMBASE;
        e820[nr].size = (uint32_t)-e820[nr].addr;
        e820[nr].type = E820_RESERVED;
        nr++;
    }

    /* Low RAM goes here. Reserve space for special pages. */
    BUG_ON(low_mem_end < (2u << 20));

    /*
     * Construct E820 table according to recorded memory map.
     *
     * The memory map created by toolstack may include,
     *
     * #1. Low memory region
     *
     * Low RAM starts at least from 1M to make sure all standard regions
     * of the PC memory map, like BIOS, VGA memory-mapped I/O and vgabios,
     * have enough space.
     *
     * #2. Reserved regions if they exist
     *
     * #3. High memory region if it exists
     *
     * Note we just have one low memory entry and one high mmeory entry if
     * exists.
     */
    for ( i = 0; i < memory_map.nr_map; i++ )
    {
        e820[nr] = memory_map.map[i];
        nr++;
    }

    /* Finally we need to sort all e820 entries. */
    for ( j = 0; j < nr - 1; j++ )
    {
        for ( i = j + 1; i < nr; i++ )
        {
            if ( e820[j].addr > e820[i].addr )
            {
                struct e820entry tmp = e820[j];

                e820[j] = e820[i];
                e820[i] = tmp;
            }
        }
    }

    return nr;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
