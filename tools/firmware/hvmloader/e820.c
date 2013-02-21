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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "config.h"
#include "util.h"

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
    unsigned int nr = 0;

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

    /* Low RAM goes here. Reserve space for special pages. */
    BUG_ON((hvm_info->low_mem_pgend << PAGE_SHIFT) < (2u << 20));
    e820[nr].addr = 0x100000;
    e820[nr].size = (hvm_info->low_mem_pgend << PAGE_SHIFT) - e820[nr].addr;
    e820[nr].type = E820_RAM;
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


    if ( hvm_info->high_mem_pgend )
    {
        e820[nr].addr = ((uint64_t)1 << 32);
        e820[nr].size =
            ((uint64_t)hvm_info->high_mem_pgend << PAGE_SHIFT) - e820[nr].addr;
        e820[nr].type = E820_RAM;
        nr++;
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
