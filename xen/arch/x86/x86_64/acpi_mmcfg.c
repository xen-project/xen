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
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * copied from Linux
 */

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

static int __init acpi_mcfg_check_entry(struct acpi_table_mcfg *mcfg,
                                        struct acpi_mcfg_allocation *cfg)
{
    int year;

    if (cfg->address < 0xFFFFFFFF)
        return 0;

    if (!strncmp(mcfg->header.oem_id, "SGI", 3))
        return 0;

    if (mcfg->header.revision >= 1 &&
        dmi_get_date(DMI_BIOS_DATE, &year, NULL, NULL) &&
        year >= 2010)
            return 0;

    printk(KERN_ERR "MCFG region for %04x:%02x-%02x at %#"PRIx64
                    " (above 4GB) ignored\n",
           cfg->pci_segment, cfg->start_bus_number, cfg->end_bus_number,
           cfg->address);
    return -EINVAL;
}

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
        pci_mmcfg_config_num = 0;
        return -ENOMEM;
    }

    memcpy(pci_mmcfg_config, &mcfg[1],
           pci_mmcfg_config_num * sizeof(*pci_mmcfg_config));

    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        if (acpi_mcfg_check_entry(mcfg, &pci_mmcfg_config[i])) {
            xfree(pci_mmcfg_config);
            pci_mmcfg_config_num = 0;
            return -ENODEV;
        }
        pci_add_segment(pci_mmcfg_config[i].pci_segment);
    }

    return 0;
}
