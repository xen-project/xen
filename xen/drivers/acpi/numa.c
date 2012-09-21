/*
 *  acpi_numa.c - ACPI NUMA support
 *
 *  Copyright (C) 2002 Takayoshi Kochi <t-kochi@bq.jp.nec.com>
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
 */
#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/acpi.h>
#include <xen/numa.h>
#include <acpi/acmacros.h>

#define ACPI_NUMA	0x80000000
#define _COMPONENT	ACPI_NUMA
ACPI_MODULE_NAME("numa")

int __initdata srat_rev;

void __init acpi_table_print_srat_entry(struct acpi_subtable_header * header)
{

	ACPI_FUNCTION_NAME("acpi_table_print_srat_entry");

	if (!header)
		return;

	switch (header->type) {

	case ACPI_SRAT_TYPE_CPU_AFFINITY:
#ifdef ACPI_DEBUG_OUTPUT
		{
			struct acpi_srat_cpu_affinity *p =
			    container_of(header, struct acpi_srat_cpu_affinity, header);
			u32 proximity_domain = p->proximity_domain_lo;

			if (srat_rev >= 2) {
				proximity_domain |= p->proximity_domain_hi[0] << 8;
				proximity_domain |= p->proximity_domain_hi[1] << 16;
				proximity_domain |= p->proximity_domain_hi[2] << 24;
			}
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "SRAT Processor (id[0x%02x] eid[0x%02x]) in proximity domain %d %s\n",
					  p->apic_id, p->local_sapic_eid,
					  proximity_domain,
					  p->flags & ACPI_SRAT_CPU_ENABLED
					  ? "enabled" : "disabled"));
		}
#endif				/* ACPI_DEBUG_OUTPUT */
		break;

	case ACPI_SRAT_TYPE_MEMORY_AFFINITY:
#ifdef ACPI_DEBUG_OUTPUT
		{
			struct acpi_srat_mem_affinity *p =
			    container_of(header, struct acpi_srat_mem_affinity, header);
			u32 proximity_domain = p->proximity_domain;

			if (srat_rev < 2)
				proximity_domain &= 0xff;
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "SRAT Memory (%#"PRIx64
					  " length %#"PRIx64")"
					  " in proximity domain %d %s%s\n",
					  p->base_address, p->length,
					  proximity_domain,
					  p->flags & ACPI_SRAT_MEM_ENABLED
					  ? "enabled" : "disabled",
					  p->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE
					  ? " hot-pluggable" : ""));
		}
#endif				/* ACPI_DEBUG_OUTPUT */
		break;

	case ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY:
#ifdef ACPI_DEBUG_OUTPUT
		{
			struct acpi_srat_x2apic_cpu_affinity *p =
			    (struct acpi_srat_x2apic_cpu_affinity *)header;
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "SRAT Processor (x2apicid[0x%08x]) in"
					  " proximity domain %d %s\n",
					  p->apic_id,
					  p->proximity_domain,
					  (p->flags & ACPI_SRAT_CPU_ENABLED) ?
					  "enabled" : "disabled"));
		}
#endif				/* ACPI_DEBUG_OUTPUT */
		break;
	default:
		printk(KERN_WARNING PREFIX
		       "Found unsupported SRAT entry (type = %#x)\n",
		       header->type);
		break;
	}
}

static int __init acpi_parse_slit(struct acpi_table_header *table)
{
	acpi_numa_slit_init((struct acpi_table_slit *)table);

	return 0;
}

static int __init
acpi_parse_x2apic_affinity(struct acpi_subtable_header *header,
			   const unsigned long end)
{
	struct acpi_srat_x2apic_cpu_affinity *processor_affinity;

	processor_affinity = (struct acpi_srat_x2apic_cpu_affinity *)header;
	if (!processor_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	acpi_numa_x2apic_affinity_init(processor_affinity);

	return 0;
}

static int __init
acpi_parse_processor_affinity(struct acpi_subtable_header * header,
			      const unsigned long end)
{
	struct acpi_srat_cpu_affinity *processor_affinity
		= container_of(header, struct acpi_srat_cpu_affinity, header);

	if (!processor_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	acpi_numa_processor_affinity_init(processor_affinity);

	return 0;
}

static int __init
acpi_parse_memory_affinity(struct acpi_subtable_header * header,
			   const unsigned long end)
{
	struct acpi_srat_mem_affinity *memory_affinity
		= container_of(header, struct acpi_srat_mem_affinity, header);

	if (!memory_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	acpi_numa_memory_affinity_init(memory_affinity);

	return 0;
}

int __init acpi_parse_srat(struct acpi_table_header *table)
{
	if (!table)
		return -EINVAL;

	srat_rev = table->revision;

	return 0;
}

int __init
acpi_table_parse_srat(int id, acpi_madt_entry_handler handler,
		      unsigned int max_entries)
{
	return acpi_table_parse_entries(ACPI_SIG_SRAT,
					sizeof(struct acpi_table_srat), id,
					handler, max_entries);
}

int __init acpi_numa_init(void)
{
	/* SRAT: Static Resource Affinity Table */
	if (!acpi_table_parse(ACPI_SIG_SRAT, acpi_parse_srat)) {
		acpi_table_parse_srat(ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY,
				      acpi_parse_x2apic_affinity, NR_CPUS);
		acpi_table_parse_srat(ACPI_SRAT_TYPE_CPU_AFFINITY,
				      acpi_parse_processor_affinity, NR_CPUS);
		acpi_table_parse_srat(ACPI_SRAT_TYPE_MEMORY_AFFINITY,
				      acpi_parse_memory_affinity,
				      NR_NODE_MEMBLKS);
	}

	/* SLIT: System Locality Information Table */
	acpi_table_parse(ACPI_SIG_SLIT, acpi_parse_slit);

	acpi_numa_arch_fixup();
	return 0;
}

#if 0
int acpi_get_pxm(acpi_handle h)
{
	unsigned long pxm;
	acpi_status status;
	acpi_handle handle;
	acpi_handle phandle = h;

	do {
		handle = phandle;
		status = acpi_evaluate_integer(handle, "_PXM", NULL, &pxm);
		if (ACPI_SUCCESS(status))
			return (int)pxm;
		status = acpi_get_parent(handle, &phandle);
	} while (ACPI_SUCCESS(status));
	return -1;
}

EXPORT_SYMBOL(acpi_get_pxm);
#endif
