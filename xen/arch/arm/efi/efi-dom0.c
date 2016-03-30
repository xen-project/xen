/*
 *  efi-dom0.c - Domain0 EFI Boot Support
 *
 *  Copyright (C) 2016 Shannon Zhao <shannon.zhao@linaro.org>
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

#include "efi.h"
#include "efi-dom0.h"
#include <asm/setup.h>
#include <asm/acpi.h>

struct meminfo __initdata acpi_mem;
/* Constant to indicate "Xen" in unicode u16 format */
static const CHAR16 xen_efi_fw_vendor[] = {0x0058, 0x0065, 0x006E, 0x0000};

size_t __init estimate_efi_size(int mem_nr_banks)
{
    size_t size;
    size_t est_size = sizeof(EFI_SYSTEM_TABLE);
    size_t ect_size = sizeof(EFI_CONFIGURATION_TABLE);
    size_t emd_size = sizeof(EFI_MEMORY_DESCRIPTOR);
    size_t fw_vendor_size = sizeof(xen_efi_fw_vendor);
    int acpi_mem_nr_banks = 0;

    if ( !acpi_disabled )
        acpi_mem_nr_banks = acpi_mem.nr_banks;

    size = ROUNDUP(est_size + ect_size + fw_vendor_size, 8);
    /* plus 1 for new created tables */
    size += ROUNDUP(emd_size * (mem_nr_banks + acpi_mem_nr_banks + 1), 8);

    return size;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
