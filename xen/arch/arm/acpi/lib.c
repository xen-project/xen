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
#include <xen/mm.h>

char *__acpi_map_table(paddr_t phys, unsigned long size)
{
    unsigned long base, offset, mapped_size;
    int idx;

    offset = phys & (PAGE_SIZE - 1);
    mapped_size = PAGE_SIZE - offset;
    set_fixmap(FIXMAP_ACPI_BEGIN, maddr_to_mfn(phys), PAGE_HYPERVISOR);
    base = FIXMAP_ADDR(FIXMAP_ACPI_BEGIN);

    /* Most cases can be covered by the below. */
    idx = FIXMAP_ACPI_BEGIN;
    while ( mapped_size < size )
    {
        if ( ++idx > FIXMAP_ACPI_END )
            return NULL;    /* cannot handle this */
        phys += PAGE_SIZE;
        set_fixmap(idx, maddr_to_mfn(phys), PAGE_HYPERVISOR);
        mapped_size += PAGE_SIZE;
    }

    return ((char *) base + offset);
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
