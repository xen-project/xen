/*
 *  lib.c - Architecture-Specific Low-Level ACPI Support
 *
 *  Copyright (C) 2015, Shannon Zhao <shannon.zhao@linaro.org>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/acpi.h>
#include <xen/init.h>
#include <xen/mm.h>

#include <asm/fixmap.h>

static bool fixmap_inuse;

char *__acpi_map_table(paddr_t phys, unsigned long size)
{
    unsigned long base, offset;
    mfn_t mfn;
    unsigned int idx;

    /* No arch specific implementation after early boot */
    if ( system_state >= SYS_STATE_boot )
        return NULL;

    offset = phys & (PAGE_SIZE - 1);
    base = FIXMAP_ADDR(FIX_ACPI_BEGIN) + offset;

    /* Check the fixmap is big enough to map the region */
    if ( (FIXMAP_ADDR(FIX_ACPI_END) + PAGE_SIZE - base) < size )
        return NULL;

    /* With the fixmap, we can only map one region at the time */
    if ( fixmap_inuse )
        return NULL;

    fixmap_inuse = true;

    size += offset;
    mfn = maddr_to_mfn(phys);
    idx = FIX_ACPI_BEGIN;

    do {
        set_fixmap(idx, mfn, PAGE_HYPERVISOR);
        size -= min(size, (unsigned long)PAGE_SIZE);
        mfn = mfn_add(mfn, 1);
        idx++;
    } while ( size > 0 );

    return (char *)base;
}

bool __acpi_unmap_table(const void *ptr, unsigned long size)
{
    vaddr_t vaddr = (vaddr_t)ptr;
    unsigned int idx;

    /* We are only handling fixmap address in the arch code */
    if ( (vaddr < FIXMAP_ADDR(FIX_ACPI_BEGIN)) ||
         (vaddr >= (FIXMAP_ADDR(FIX_ACPI_END) + PAGE_SIZE)) )
        return false;

    /*
     * __acpi_map_table() will always return a pointer in the first page
     * for the ACPI fixmap region. The caller is expected to free with
     * the same address.
     */
    ASSERT((vaddr & PAGE_MASK) == FIXMAP_ADDR(FIX_ACPI_BEGIN));

    /* The region allocated fit in the ACPI fixmap region. */
    ASSERT(size < (FIXMAP_ADDR(FIX_ACPI_END) + PAGE_SIZE - vaddr));
    ASSERT(fixmap_inuse);

    fixmap_inuse = false;

    size += vaddr - FIXMAP_ADDR(FIX_ACPI_BEGIN);
    idx = FIX_ACPI_BEGIN;

    do
    {
        clear_fixmap(idx);
        size -= min(size, (unsigned long)PAGE_SIZE);
        idx++;
    } while ( size > 0 );

    return true;
}

/* True to indicate PSCI 0.2+ is implemented */
bool __init acpi_psci_present(void)
{
    return acpi_gbl_FADT.arm_boot_flags & ACPI_FADT_PSCI_COMPLIANT;
}

/* True to indicate HVC is present instead of SMC as the PSCI conduit */
bool __init acpi_psci_hvc_present(void)
{
    return acpi_gbl_FADT.arm_boot_flags & ACPI_FADT_PSCI_USE_HVC;
}

paddr_t __init acpi_get_table_offset(struct membank tbl_add[],
                                     EFI_MEM_RES index)
{
    int i;
    paddr_t offset = 0;

    for ( i = 0; i < index; i++ )
    {
        /* Aligned with 64bit (8 bytes) */
        offset += ROUNDUP(tbl_add[i].size, 8);
    }

    return offset;
}
