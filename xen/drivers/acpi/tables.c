/*
 *  acpi_tables.c - ACPI Boot-Time Table Parsing
 *
 *  Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
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
 */

#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <xen/errno.h>
#include <xen/acpi.h>

#define PREFIX			"ACPI: "

#define ACPI_MAX_TABLES		128

static const char *__initdata
mps_inti_flags_polarity[] = { "dfl", "high", "res", "low" };
static const char *__initdata
mps_inti_flags_trigger[] = { "dfl", "edge", "res", "level" };

static int acpi_apic_instance __initdata;

void __init acpi_table_print_madt_entry(struct acpi_subtable_header *header)
{
	if (!header)
		return;

	switch (header->type) {

	case ACPI_MADT_TYPE_LOCAL_APIC:
		{
			struct acpi_madt_local_apic *p =
			    (struct acpi_madt_local_apic *)header;
			printk(KERN_INFO PREFIX
			       "LAPIC (acpi_id[0x%02x] lapic_id[0x%02x] %s)\n",
			       p->processor_id, p->id,
			       (p->lapic_flags & ACPI_MADT_ENABLED) ? "enabled" : "disabled");
		}
		break;

	case ACPI_MADT_TYPE_LOCAL_X2APIC:
		{
			struct acpi_madt_local_x2apic *p =
			    (struct acpi_madt_local_x2apic *)header;
			printk(KERN_INFO PREFIX
			       "X2APIC (apic_id[0x%02x] uid[0x%02x] %s)\n",
			       p->local_apic_id, p->uid,
			       (p->lapic_flags & ACPI_MADT_ENABLED) ?
			       "enabled" : "disabled");
		}
		break;

	case ACPI_MADT_TYPE_IO_APIC:
		{
			struct acpi_madt_io_apic *p =
			    (struct acpi_madt_io_apic *)header;
			printk(KERN_INFO PREFIX
			       "IOAPIC (id[0x%02x] address[0x%08x] gsi_base[%d])\n",
			       p->id, p->address, p->global_irq_base);
		}
		break;

	case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE:
		{
			struct acpi_madt_interrupt_override *p =
			    (struct acpi_madt_interrupt_override *)header;
			printk(KERN_INFO PREFIX
			       "INT_SRC_OVR (bus %d bus_irq %d global_irq %d %s %s)\n",
			       p->bus, p->source_irq, p->global_irq,
			       mps_inti_flags_polarity[p->inti_flags & ACPI_MADT_POLARITY_MASK],
			       mps_inti_flags_trigger[(p->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2]);
			if (p->inti_flags  &
			    ~(ACPI_MADT_POLARITY_MASK | ACPI_MADT_TRIGGER_MASK))
				printk(KERN_INFO PREFIX
				       "INT_SRC_OVR unexpected reserved flags: %#x\n",
				       p->inti_flags  &
					~(ACPI_MADT_POLARITY_MASK | ACPI_MADT_TRIGGER_MASK));

		}
		break;

	case ACPI_MADT_TYPE_NMI_SOURCE:
		{
			struct acpi_madt_nmi_source *p =
			    (struct acpi_madt_nmi_source *)header;
			printk(KERN_INFO PREFIX
			       "NMI_SRC (%s %s global_irq %d)\n",
			       mps_inti_flags_polarity[p->inti_flags & ACPI_MADT_POLARITY_MASK],
			       mps_inti_flags_trigger[(p->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2],
			       p->global_irq);
		}
		break;

	case ACPI_MADT_TYPE_LOCAL_APIC_NMI:
		{
			struct acpi_madt_local_apic_nmi *p =
			    (struct acpi_madt_local_apic_nmi *)header;
			printk(KERN_INFO PREFIX
			       "LAPIC_NMI (acpi_id[0x%02x] %s %s lint[%#x])\n",
			       p->processor_id,
			       mps_inti_flags_polarity[p->inti_flags & ACPI_MADT_POLARITY_MASK	],
			       mps_inti_flags_trigger[(p->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2],
			       p->lint);
		}
		break;

	case ACPI_MADT_TYPE_LOCAL_X2APIC_NMI:
		{
			u16 polarity, trigger;
			struct acpi_madt_local_x2apic_nmi *p =
			    (struct acpi_madt_local_x2apic_nmi *)header;

			polarity = p->inti_flags & ACPI_MADT_POLARITY_MASK;
			trigger = (p->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2;

			printk(KERN_INFO PREFIX
			       "X2APIC_NMI (uid[0x%02x] %s %s lint[%#x])\n",
			       p->uid,
			       mps_inti_flags_polarity[polarity],
			       mps_inti_flags_trigger[trigger],
			       p->lint);
		}
		break;

	case ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE:
		{
			struct acpi_madt_local_apic_override *p =
			    (struct acpi_madt_local_apic_override *)header;
			printk(KERN_INFO PREFIX
			       "LAPIC_ADDR_OVR (address[%p])\n",
			       (void *)(unsigned long)p->address);
		}
		break;

	case ACPI_MADT_TYPE_IO_SAPIC:
		{
			struct acpi_madt_io_sapic *p =
			    (struct acpi_madt_io_sapic *)header;
			printk(KERN_INFO PREFIX
			       "IOSAPIC (id[%#x] address[%p] gsi_base[%d])\n",
			       p->id, (void *)(unsigned long)p->address,
			       p->global_irq_base);
		}
		break;

	case ACPI_MADT_TYPE_LOCAL_SAPIC:
		{
			struct acpi_madt_local_sapic *p =
			    (struct acpi_madt_local_sapic *)header;
			printk(KERN_INFO PREFIX
			       "LSAPIC (acpi_id[0x%02x] lsapic_id[0x%02x] lsapic_eid[0x%02x] %s)\n",
			       p->processor_id, p->id, p->eid,
			       (p->lapic_flags & ACPI_MADT_ENABLED) ? "enabled" : "disabled");
		}
		break;

	case ACPI_MADT_TYPE_INTERRUPT_SOURCE:
		{
			struct acpi_madt_interrupt_source *p =
			    (struct acpi_madt_interrupt_source *)header;
			printk(KERN_INFO PREFIX
			       "PLAT_INT_SRC (%s %s type[%#x] id[0x%04x] eid[%#x] iosapic_vector[%#x] global_irq[%#x]\n",
			       mps_inti_flags_polarity[p->inti_flags & ACPI_MADT_POLARITY_MASK],
			       mps_inti_flags_trigger[(p->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2],
			       p->type, p->id, p->eid, p->io_sapic_vector,
			       p->global_irq);
		}
		break;

	case ACPI_MADT_TYPE_GENERIC_INTERRUPT:
		{
			struct acpi_madt_generic_interrupt *p =
				container_of(header, struct acpi_madt_generic_interrupt, header);

			printk(KERN_DEBUG PREFIX
			       "GICC (acpi_id[0x%04x] address[0x%"PRIx64"] MPIDR[0x%"PRIx64"] %s)\n",
			       p->uid, p->base_address,
			       p->arm_mpidr,
			       (p->flags & ACPI_MADT_ENABLED) ? "enabled" : "disabled");

		}
		break;

	case ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR:
		{
			struct acpi_madt_generic_distributor *p =
				container_of(header, struct acpi_madt_generic_distributor, header);

			printk(KERN_DEBUG PREFIX
			       "GIC Distributor (gic_id[0x%04x] address[0x%"PRIx64"] gsi_base[%d])\n",
			       p->gic_id, p->base_address,
			       p->global_irq_base);
		}
		break;

	default:
		printk(KERN_WARNING PREFIX
		       "Found unsupported MADT entry (type = %#x)\n",
		       header->type);
		break;
	}
}

static struct acpi_subtable_header * __init
acpi_get_entry(const char *id, unsigned long table_size,
	       const struct acpi_table_header *table_header,
	       enum acpi_madt_type entry_id, unsigned int entry_index)
{
	struct acpi_subtable_header *entry;
	int count = 0;
	unsigned long table_end;

	if (!table_size)
		return NULL;

	if (!table_header) {
		printk(KERN_WARNING PREFIX "%4.4s not present\n", id);
		return NULL;
	}

	table_end = (unsigned long)table_header + table_header->length;

	/* Parse all entries looking for a match. */
	entry = (void *)table_header + table_size;

	while ((unsigned long)(entry + 1) < table_end) {
		if (entry->length < sizeof(*entry)) {
			printk(KERN_ERR PREFIX "[%4.4s:%#x] Invalid length\n",
			       id, entry_id);
			return NULL;
		}

		if (entry->type == entry_id) {
			if (count == entry_index)
				return entry;
			count++;
		}

		entry = (void *)entry + entry->length;
	}

	return NULL;
}

struct acpi_subtable_header * __init
acpi_table_get_entry_madt(enum acpi_madt_type entry_id,
			  unsigned int entry_index)
{
	struct acpi_table_header *table_header;
	acpi_status status;

	status = acpi_get_table(ACPI_SIG_MADT, acpi_apic_instance,
				&table_header);
	if (ACPI_FAILURE(status)) {
		printk(KERN_WARNING PREFIX "%4.4s not present\n",
		       ACPI_SIG_MADT);
		return NULL;
	}

	return acpi_get_entry(ACPI_SIG_MADT, sizeof(struct acpi_table_madt),
			      table_header, entry_id, entry_index);
}

int __init
acpi_parse_entries(char *id, unsigned long table_size,
		   acpi_table_entry_handler handler,
		   struct acpi_table_header *table_header,
		   int entry_id, unsigned int max_entries)
{
	struct acpi_subtable_header *entry;
	int count = 0;
	unsigned long table_end;

	if (acpi_disabled)
		return -ENODEV;

	if (!id || !handler)
		return -EINVAL;

	if (!table_size)
		return -EINVAL;

	if (!table_header) {
		printk(KERN_WARNING PREFIX "%4.4s not present\n", id);
		return -ENODEV;
	}

	table_end = (unsigned long)table_header + table_header->length;

	/* Parse all entries looking for a match. */

	entry = (struct acpi_subtable_header *)
	    ((unsigned long)table_header + table_size);

	while (((unsigned long)entry) + sizeof(struct acpi_subtable_header) <
	       table_end) {
		if (entry->length < sizeof(*entry)) {
			printk(KERN_ERR PREFIX "[%4.4s:%#x] Invalid length\n",
			       id, entry_id);
			return -ENODATA;
		}

		if (entry->type == entry_id
		    && (!max_entries || count < max_entries)) {
			if (handler(entry, table_end))
				return -EINVAL;

			count++;
		}

		entry = (struct acpi_subtable_header *)
		    ((unsigned long)entry + entry->length);
	}

	if (max_entries && count > max_entries) {
		printk(KERN_WARNING PREFIX "[%4.4s:%#x] ignored %i entries of "
		       "%i found\n", id, entry_id, count - max_entries, count);
	}

	return count;
}

int __init
acpi_table_parse_entries(char *id,
			 unsigned long table_size,
			 int entry_id,
			 acpi_table_entry_handler handler,
			 unsigned int max_entries)
{
	struct acpi_table_header *table_header = NULL;
	u32 instance = 0;

	if (acpi_disabled)
		return -ENODEV;

	if (!id || !handler)
		return -EINVAL;

	if (!strncmp(id, ACPI_SIG_MADT, 4))
		instance = acpi_apic_instance;

	acpi_get_table(id, instance, &table_header);
	if (!table_header) {
		printk(KERN_WARNING PREFIX "%4.4s not present\n", id);
		return -ENODEV;
	}

	return acpi_parse_entries(id, table_size, handler, table_header,
				  entry_id, max_entries);
}

int __init
acpi_table_parse_madt(enum acpi_madt_type id,
		      acpi_table_entry_handler handler, unsigned int max_entries)
{
	return acpi_table_parse_entries(ACPI_SIG_MADT,
					    sizeof(struct acpi_table_madt), id,
					    handler, max_entries);
}

/**
 * acpi_table_parse - find table with @id, run @handler on it
 *
 * @id: table id to find
 * @handler: handler to run
 *
 * Scan the ACPI System Descriptor Table (STD) for a table matching @id,
 * run @handler on it.
 */
int __init acpi_table_parse(char *id, acpi_table_handler handler)
{
	struct acpi_table_header *table = NULL;

	if (acpi_disabled)
		return -ENODEV;

	if (!handler)
		return -EINVAL;

	if (strncmp(id, ACPI_SIG_MADT, 4) == 0)
		acpi_get_table(id, acpi_apic_instance, &table);
	else
		acpi_get_table(id, 0, &table);

	if (table) {
		return handler(table);
	} else
		return -ENODEV;
}

/* 
 * The BIOS is supposed to supply a single APIC/MADT,
 * but some report two.  Provide a knob to use either.
 * (don't you wish instance 0 and 1 were not the same?)
 */
static void __init check_multiple_madt(void)
{
	struct acpi_table_header *table = NULL;

	acpi_get_table(ACPI_SIG_MADT, 2, &table);
	if (table) {
		printk(KERN_WARNING PREFIX
		       "BIOS bug: multiple APIC/MADT found,"
		       " using %d\n", acpi_apic_instance);
		printk(KERN_WARNING PREFIX
		       "If \"acpi_apic_instance=%d\" works better, "
		       "notify linux-acpi@vger.kernel.org\n",
		       acpi_apic_instance ? 0 : 2);

	} else
		acpi_apic_instance = 0;

	return;
}

/*
 * acpi_table_init()
 *
 * find RSDP, find and checksum SDT/XSDT.
 * checksum all tables, print SDT/XSDT
 *
 * result: sdt_entry[] is initialized
 */

int __init acpi_table_init(void)
{
	acpi_status status;

	status = acpi_initialize_tables(NULL, ACPI_MAX_TABLES, 0);
	if (ACPI_FAILURE(status))
		return -EINVAL;

	check_multiple_madt();
	return 0;
}

static int __init acpi_parse_apic_instance(char *str)
{

	acpi_apic_instance = simple_strtoul(str, NULL, 0);

	printk(KERN_NOTICE PREFIX "Shall use APIC/MADT table %d\n",
	       acpi_apic_instance);

	return 0;
}
custom_param("acpi_apic_instance", acpi_parse_apic_instance);
