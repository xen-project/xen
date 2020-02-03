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
#include <xen/param.h>
#include <xen/device_tree.h>

#include <asm/acpi.h>
#include <asm/smp.h>
#include <asm/setup.h>

/* Processors with enabled flag and sane MPIDR */
static unsigned int __initdata enabled_cpus = 1;
static bool __initdata bootcpu_valid;

/* total number of cpus in this system */
static unsigned int __initdata total_cpus;

/*
 * acpi_map_gic_cpu_interface - generates a logical cpu number
 * and map to MPIDR represented by GICC structure
 */
static void __init
acpi_map_gic_cpu_interface(struct acpi_madt_generic_interrupt *processor)
{
    int i;
    int rc;
    u64 mpidr = processor->arm_mpidr & MPIDR_HWID_MASK;
    bool enabled = processor->flags & ACPI_MADT_ENABLED;

    if ( mpidr == MPIDR_INVALID )
    {
        printk("Skip MADT cpu entry with invalid MPIDR\n");
        return;
    }

    total_cpus++;
    if ( !enabled )
    {
        printk("Skipping disabled CPU entry with 0x%"PRIx64" MPIDR\n", mpidr);
        return;
    }

    if ( enabled_cpus >=  NR_CPUS )
    {
        printk("NR_CPUS limit of %d reached, Processor %d/0x%"PRIx64" ignored.\n",
               NR_CPUS, total_cpus, mpidr);
        return;
    }

    /* Check if GICC structure of boot CPU is available in the MADT */
    if ( cpu_logical_map(0) == mpidr )
    {
        if ( bootcpu_valid )
        {
            printk("Firmware bug, duplicate boot CPU MPIDR: 0x%"PRIx64" in MADT\n",
                   mpidr);
            return;
        }
        bootcpu_valid = true;
        return;
    }

    /*
     * Duplicate MPIDRs are a recipe for disaster. Scan
     * all initialized entries and check for
     * duplicates. If any is found just ignore the CPU.
     */
    for ( i = 1; i < enabled_cpus; i++ )
    {
        if ( cpu_logical_map(i) == mpidr )
        {
            printk("Firmware bug, duplicate CPU MPIDR: 0x%"PRIx64" in MADT\n",
                   mpidr);
            return;
        }
    }

    if ( !acpi_psci_present() )
    {
        printk("PSCI not present, skipping CPU MPIDR 0x%"PRIx64"\n",
               mpidr);
        return;
    }

    if ( (rc = arch_cpu_init(enabled_cpus, NULL)) < 0 )
    {
        printk("cpu%d: init failed (0x%"PRIx64" MPIDR): %d\n",
               enabled_cpus, mpidr, rc);
        return;
    }

    /* map the logical cpu id to cpu MPIDR */
    cpu_logical_map(enabled_cpus) = mpidr;

    enabled_cpus++;
}

static int __init
acpi_parse_gic_cpu_interface(struct acpi_subtable_header *header,
                             const unsigned long end)
{
    struct acpi_madt_generic_interrupt *processor =
               container_of(header, struct acpi_madt_generic_interrupt, header);

    if ( BAD_MADT_ENTRY(processor, end) )
        return -EINVAL;

    acpi_table_print_madt_entry(header);
    acpi_map_gic_cpu_interface(processor);
    return 0;
}

/* Parse GIC cpu interface entries in MADT for SMP init */
void __init acpi_smp_init_cpus(void)
{
    int count, i;

    /*
     * do a partial walk of MADT to determine how many CPUs
     * we have including disabled CPUs, and get information
     * we need for SMP init
     */
    count = acpi_table_parse_madt(ACPI_MADT_TYPE_GENERIC_INTERRUPT,
                    acpi_parse_gic_cpu_interface, 0);

    if ( count <= 0 )
    {
        printk("Error parsing GIC CPU interface entry\n");
        return;
    }

    if ( !bootcpu_valid )
    {
        printk("MADT missing boot CPU MPIDR, not enabling secondaries\n");
        return;
    }

    for ( i = 0; i < enabled_cpus; i++ )
        cpumask_set_cpu(i, &cpu_possible_map);

    /* Make boot-up look pretty */
    printk("%d CPUs enabled, %d CPUs total\n", enabled_cpus, total_cpus);
}

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

static bool __initdata param_acpi_off;
static bool __initdata param_acpi_force;

static int __init parse_acpi_param(const char *arg)
{
    if ( !arg )
        return -EINVAL;

    /* Interpret the parameter for use within Xen. */
    if ( !parse_bool(arg, NULL) )
        param_acpi_off = true;
    else if ( !strcmp(arg, "force") ) /* force ACPI to be enabled */
        param_acpi_force = true;
    else
        return -EINVAL;

    return 0;
}
custom_param("acpi", parse_acpi_param);

static int __init dt_scan_depth1_nodes(const void *fdt, int node,
                                       const char *uname, int depth,
                                       u32 address_cells, u32 size_cells,
                                       void *data)
{
    /*
     * Return 1 as soon as we encounter a node at depth 1 that is
     * not the /chosen node.
     */
    if (depth == 1 && (strcmp(uname, "chosen") != 0))
        return 1;
    return 0;
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
    int error = 0;

    /*
     * Enable ACPI instead of device tree unless
     * - ACPI has been disabled explicitly (acpi=off), or
     * - the device tree is not empty (it has more than just a /chosen node)
     *   and ACPI has not been force enabled (acpi=force)
     */
    if ( param_acpi_off)
        goto disable;
    if ( !param_acpi_force &&
         device_tree_for_each_node(device_tree_flattened, 0,
                                   dt_scan_depth1_nodes, NULL) )
        goto disable;

    /*
     * ACPI is disabled at this point. Enable it in order to parse
     * the ACPI tables.
     */
    enable_acpi();

    /* Initialize the ACPI boot-time table parser. */
    error = acpi_table_init();
    if ( error )
    {
        printk("%s: Unable to initialize table parser (%d)\n",
               __FUNCTION__, error);
        goto disable;
    }

    error = acpi_table_parse(ACPI_SIG_FADT, acpi_parse_fadt);
    if ( error )
    {
        printk("%s: FADT not found (%d)\n", __FUNCTION__, error);
        goto disable;
    }

    return 0;

disable:
    disable_acpi();

    return error;
}
