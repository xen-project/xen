/*
 *  acpi_mmconfig.c - Architecture-Specific Low-Level ACPI Boot Support
 *
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Jun Nakajima <jun.nakajima@intel.com>
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * copied from Linux
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/acpi.h>
#include <xen/irq.h>
#include <xen/dmi.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <mach_apic.h>
#include <mach_mpparse.h>

#include "mmconfig.h"

/* The physical address of the MMCONFIG aperture.  Set from ACPI tables. */
struct acpi_mcfg_allocation *pci_mmcfg_config;
int pci_mmcfg_config_num;

int __init acpi_parse_mcfg(struct acpi_table_header *header)
{
    struct acpi_table_mcfg *mcfg;
    unsigned long i;

    if (!header)
        return -EINVAL;

    mcfg = (struct acpi_table_mcfg *)header;

    /* how many config structures do we have */
    pci_mmcfg_config_num = 0;
    i = header->length - sizeof(struct acpi_table_mcfg);
    while (i >= sizeof(struct acpi_mcfg_allocation)) {
        ++pci_mmcfg_config_num;
        i -= sizeof(struct acpi_mcfg_allocation);
    };
    if (pci_mmcfg_config_num == 0) {
        printk(KERN_ERR PREFIX "MMCONFIG has no entries\n");
        return -ENODEV;
    }

    pci_mmcfg_config = xmalloc_array(struct acpi_mcfg_allocation,
                                     pci_mmcfg_config_num);
    if (!pci_mmcfg_config) {
        printk(KERN_WARNING PREFIX
               "No memory for MCFG config tables\n");
        return -ENOMEM;
    }

    memcpy(pci_mmcfg_config, &mcfg[1],
           pci_mmcfg_config_num * sizeof(*pci_mmcfg_config));

    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        if (pci_mmcfg_config[i].address > 0xFFFFFFFF) {
            printk(KERN_ERR PREFIX
                   "MMCONFIG not in low 4GB of memory\n");
            xfree(pci_mmcfg_config);
            pci_mmcfg_config_num = 0;
            return -ENODEV;
        }
    }

    return 0;
}
