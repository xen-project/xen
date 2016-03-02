/*
 *  ARM Specific Low-Level ACPI Boot Support
 *
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Jun Nakajima <jun.nakajima@intel.com>
 *  Copyright (C) 2014, Naresh Bhat <naresh.bhat@linaro.org>
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/init.h>
#include <xen/acpi.h>
#include <xen/errno.h>
#include <acpi/actables.h>
#include <xen/mm.h>

#include <asm/acpi.h>

static int __init acpi_parse_fadt(struct acpi_table_header *table)
{
    struct acpi_table_fadt *fadt = (struct acpi_table_fadt *)table;

    /*
     * Revision in table header is the FADT Major revision, and there
     * is a minor revision of FADT which was introduced by ACPI 6.0,
     * we only deal with ACPI 6.0 or newer revision to get GIC and SMP
     * boot protocol configuration data, or we will disable ACPI.
     */
    if ( table->revision > 6
         || (table->revision == 6 && fadt->minor_revision >= 0) )
        return 0;

    printk("Unsupported FADT revision %d.%d, should be 6.0+, will disable ACPI\n",
            table->revision, fadt->minor_revision);

    return -EINVAL;
}

/*
 * acpi_boot_table_init() called from setup_arch(), always.
 *      1. find RSDP and get its address, and then find XSDT
 *      2. extract all tables and checksums them all
 *
 * return value: (currently ignored)
 *	0: success
 *	!0: failure
 *
 * We can parse ACPI boot-time tables such as FADT, MADT after
 * this function is called.
 */
int __init acpi_boot_table_init(void)
{
    int error;

    /* Initialize the ACPI boot-time table parser. */
    error = acpi_table_init();
    if ( error )
    {
        disable_acpi();
        return error;
    }

    if ( acpi_table_parse(ACPI_SIG_FADT, acpi_parse_fadt) )
    {
        /* disable ACPI if no FADT is found */
        disable_acpi();
        printk("Can't find FADT\n");
    }

    return 0;
}
