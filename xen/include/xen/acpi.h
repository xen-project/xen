/*
 * acpi.h - ACPI Interface
 *
 * Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef _LINUX_ACPI_H
#define _LINUX_ACPI_H

#ifndef _LINUX
#define _LINUX
#endif

#include <xen/list.h>

#include <acpi/acpi.h>
#include <asm/acpi.h>

#define ACPI_MADT_GET_(fld, x) (((x) & ACPI_MADT_##fld##_MASK) / \
	(ACPI_MADT_##fld##_MASK & -ACPI_MADT_##fld##_MASK))

#define ACPI_MADT_GET_POLARITY(inti)	ACPI_MADT_GET_(POLARITY, inti)
#define ACPI_MADT_GET_TRIGGER(inti)	ACPI_MADT_GET_(TRIGGER, inti)

/*
 * Fixmap pages to reserve for ACPI boot-time tables (see asm-x86/fixmap.h or
 * asm-arm/config.h)
 */
#define NUM_FIXMAP_ACPI_PAGES  4

#define BAD_MADT_ENTRY(entry, end) (                                        \
                (!(entry)) || (unsigned long)(entry) + sizeof(*(entry)) > (end) ||  \
                (entry)->header.length < sizeof(*(entry)))

#ifdef CONFIG_ACPI

enum acpi_interrupt_id {
	ACPI_INTERRUPT_PMI	= 1,
	ACPI_INTERRUPT_INIT,
	ACPI_INTERRUPT_CPEI,
	ACPI_INTERRUPT_COUNT
};

typedef int (*acpi_madt_entry_handler) (struct acpi_subtable_header *header, const unsigned long end);

typedef int (*acpi_table_handler) (struct acpi_table_header *table);

typedef int (*acpi_table_entry_handler) (struct acpi_subtable_header *header, const unsigned long end);

unsigned int acpi_get_processor_id (unsigned int cpu);
char * __acpi_map_table (paddr_t phys_addr, unsigned long size);
int acpi_boot_init (void);
int acpi_boot_table_init (void);
int acpi_numa_init (void);
int erst_init(void);
void acpi_hest_init(void);

int acpi_table_init (void);
int acpi_table_parse(char *id, acpi_table_handler handler);
int acpi_parse_entries(char *id, unsigned long table_size,
		       acpi_table_entry_handler handler,
		       struct acpi_table_header *table_header,
		       int entry_id, unsigned int max_entries);
int acpi_table_parse_entries(char *id, unsigned long table_size,
	int entry_id, acpi_table_entry_handler handler, unsigned int max_entries);
struct acpi_subtable_header *acpi_table_get_entry_madt(enum acpi_madt_type id,
						      unsigned int entry_index);
int acpi_table_parse_madt(enum acpi_madt_type id, acpi_table_entry_handler handler, unsigned int max_entries);
int acpi_table_parse_srat(int id, acpi_madt_entry_handler handler,
	unsigned int max_entries);
int acpi_parse_srat(struct acpi_table_header *);
void acpi_table_print (struct acpi_table_header *header, unsigned long phys_addr);
void acpi_table_print_madt_entry (struct acpi_subtable_header *madt);
void acpi_table_print_srat_entry (struct acpi_subtable_header *srat);

/* the following four functions are architecture-dependent */
void acpi_numa_slit_init (struct acpi_table_slit *slit);
void acpi_numa_processor_affinity_init(const struct acpi_srat_cpu_affinity *);
void acpi_numa_x2apic_affinity_init(const struct acpi_srat_x2apic_cpu_affinity *);
void acpi_numa_memory_affinity_init(const struct acpi_srat_mem_affinity *);
void acpi_numa_arch_fixup(void);

#ifdef CONFIG_ACPI_HOTPLUG_CPU
/* Arch dependent functions for cpu hotplug support */
int acpi_map_lsapic(acpi_handle handle, int *pcpu);
int acpi_unmap_lsapic(int cpu);
#endif /* CONFIG_ACPI_HOTPLUG_CPU */

extern int acpi_mp_config;

extern u32 pci_mmcfg_base_addr;

#else	/*!CONFIG_ACPI*/

#define acpi_mp_config	0

static inline int acpi_boot_init(void)
{
	return 0;
}

static inline int acpi_boot_table_init(void)
{
	return 0;
}

#endif 	/*!CONFIG_ACPI*/

int get_cpu_id(u32 acpi_id);

unsigned int acpi_register_gsi (u32 gsi, int edge_level, int active_high_low);
int acpi_gsi_to_irq (u32 gsi, unsigned int *irq);

/*
 * This function undoes the effect of one call to acpi_register_gsi().
 * If this matches the last registration, any IRQ resources for gsi
 * are freed.
 */
#ifdef CONFIG_ACPI_DEALLOCATE_IRQ
void acpi_unregister_gsi (u32 gsi);
#endif

#ifdef	CONFIG_ACPI_CSTATE
/*
 * Set highest legal C-state
 * 0: C0 okay, but not C1
 * 1: C1 okay, but not C2
 * 2: C2 okay, but not C3 etc.
 */

extern unsigned int max_cstate;

static inline unsigned int acpi_get_cstate_limit(void)
{
	return max_cstate;
}
static inline void acpi_set_cstate_limit(unsigned int new_limit)
{
	max_cstate = new_limit;
	return;
}
#else
static inline unsigned int acpi_get_cstate_limit(void) { return 0; }
static inline void acpi_set_cstate_limit(unsigned int new_limit) { return; }
#endif

#ifdef XEN_GUEST_HANDLE_PARAM
int acpi_set_pdc_bits(u32 acpi_id, XEN_GUEST_HANDLE_PARAM(uint32));
#endif
int arch_acpi_set_pdc_bits(u32 acpi_id, u32 *, u32 mask);

#ifdef CONFIG_ACPI_NUMA
int acpi_get_pxm(acpi_handle handle);
#else
static inline int acpi_get_pxm(acpi_handle handle)
{
	return 0;
}
#endif

void acpi_reboot(void);

void acpi_dmar_zap(void);
void acpi_dmar_reinstate(void);

#endif /*_LINUX_ACPI_H*/
