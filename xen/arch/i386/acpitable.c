/*
 *  acpitable.c - IA32-specific ACPI boot-time initialization (Revision: 1)
 *
 *  Copyright (C) 1999 Andrew Henroid
 *  Copyright (C) 2001 Richard Schaal
 *  Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Jun Nakajima <jun.nakajima@intel.com>
 *  Copyright (C) 2001 Arjan van de Ven <arjanv@redhat.com>
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
 * $Id: acpitable.c,v 1.7 2001/11/04 12:21:18 fenrus Exp $
 */
#include <xen/config.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/slab.h>
#include <xen/pci.h>
#include <asm/mpspec.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <asm/io_apic.h>

#ifdef CONFIG_X86_IO_APIC

#include "acpitable.h"

static acpi_table_handler acpi_boot_ops[ACPI_TABLE_COUNT];


static unsigned char __init
acpi_checksum(void *buffer, int length)
{
	int i;
	unsigned char *bytebuffer;
	unsigned char sum = 0;

	if (!buffer || length <= 0)
		return 0;

	bytebuffer = (unsigned char *) buffer;

	for (i = 0; i < length; i++)
		sum += *(bytebuffer++);

	return sum;
}

static void __init
acpi_print_table_header(acpi_table_header * header)
{
	if (!header)
		return;

	printk(KERN_INFO "ACPI table found: %.4s v%d [%.6s %.8s %d.%d]\n",
	       header->signature, header->revision, header->oem_id,
	       header->oem_table_id, header->oem_revision >> 16,
	       header->oem_revision & 0xffff);

	return;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_scan_memory_for_rsdp
 *
 * PARAMETERS:  address       - Starting pointer for search
 *              length        - Maximum length to search
 *
 * RETURN:      Pointer to the RSDP if found and valid, otherwise NULL.
 *
 * DESCRIPTION: Search a block of memory for the RSDP signature
 *
 ******************************************************************************/

static void *__init
acpi_tb_scan_memory_for_rsdp(void *address, int length)
{
	u32 offset;

	if (length <= 0)
		return NULL;

	/* Search from given start addr for the requested length  */

	offset = 0;

	while (offset < length) {
		/* The signature must match and the checksum must be correct */
		if (strncmp(address, RSDP_SIG, sizeof(RSDP_SIG) - 1) == 0 &&
		    acpi_checksum(address, RSDP_CHECKSUM_LENGTH) == 0) {
			/* If so, we have found the RSDP */
			printk(KERN_INFO "ACPI: RSDP located at physical address %p\n",
			       address);
			return address;
		}
		offset += RSDP_SCAN_STEP;
		address += RSDP_SCAN_STEP;
	}

	/* Searched entire block, no RSDP was found */
	printk(KERN_INFO "ACPI: Searched entire block, no RSDP was found.\n");
	return NULL;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_find_root_pointer
 *
 * PARAMETERS:  none
 *
 * RETURN:      physical address of the RSDP 
 *
 * DESCRIPTION: Search lower 1_mbyte of memory for the root system descriptor
 *              pointer structure.  If it is found, set *RSDP to point to it.
 *
 *              NOTE: The RSDP must be either in the first 1_k of the Extended
 *              BIOS Data Area or between E0000 and FFFFF (ACPI 1.0 section
 *              5.2.2; assertion #421).
 *
 ******************************************************************************/

static struct acpi_table_rsdp * __init
acpi_find_root_pointer(void)
{
	struct acpi_table_rsdp * rsdp;

	/*
	 * Physical address is given
	 */
	/*
	 * Region 1) Search EBDA (low memory) paragraphs
	 */
	rsdp = acpi_tb_scan_memory_for_rsdp(__va(LO_RSDP_WINDOW_BASE),
					 LO_RSDP_WINDOW_SIZE);

	if (rsdp)
		return rsdp;

	/*
	 * Region 2) Search upper memory: 16-byte boundaries in E0000h-F0000h
	 */
	rsdp = acpi_tb_scan_memory_for_rsdp(__va(HI_RSDP_WINDOW_BASE),
					       HI_RSDP_WINDOW_SIZE);

	
					     
	if (rsdp)
		return rsdp;

	printk(KERN_ERR "ACPI: System description tables not found\n");
	return NULL;
}


/*
 * Temporarily use the virtual area starting from FIX_IO_APIC_BASE_END,
 * to map the target physical address. The problem is that set_fixmap()
 * provides a single page, and it is possible that the page is not
 * sufficient.
 * By using this area, we can map up to MAX_IO_APICS pages temporarily,
 * i.e. until the next __va_range() call.
 *
 * Important Safety Note:  The fixed I/O APIC page numbers are *subtracted*
 * from the fixed base.  That's why we start at FIX_IO_APIC_BASE_END and
 * count idx down while incrementing the phys address.
 */
static __init char *
__va_range(unsigned long phys, unsigned long size)
{
	unsigned long base, offset, mapped_size;
	int idx;

	offset = phys & (PAGE_SIZE - 1);
	mapped_size = PAGE_SIZE - offset;
	set_fixmap(FIX_IO_APIC_BASE_END, phys);
	base = fix_to_virt(FIX_IO_APIC_BASE_END);
	dprintk("__va_range(0x%lx, 0x%lx): idx=%d mapped at %lx\n", phys, size,
		FIX_IO_APIC_BASE_END, base);

	/*
	 * Most cases can be covered by the below.
	 */
	idx = FIX_IO_APIC_BASE_END;
	while (mapped_size < size) {
		if (--idx < FIX_IO_APIC_BASE_0)
			return 0;	/* cannot handle this */
		phys += PAGE_SIZE;
		set_fixmap(idx, phys);
		mapped_size += PAGE_SIZE;
	}

	return ((unsigned char *) base + offset);
}

static int __init acpi_tables_init(void)
{
	int result = -ENODEV;
	acpi_table_header *header = NULL;
	struct acpi_table_rsdp *rsdp = NULL;
	struct acpi_table_rsdt *rsdt = NULL;
	struct acpi_table_rsdt saved_rsdt;
	int tables = 0;
	int type = 0;
	int i = 0;


	rsdp = (struct acpi_table_rsdp *) acpi_find_root_pointer();

	if (!rsdp)
		return -ENODEV;
		
	printk(KERN_INFO "%.8s v%d [%.6s]\n", rsdp->signature, rsdp->revision,
	       rsdp->oem_id);
	       
	if (strncmp(rsdp->signature, RSDP_SIG,strlen(RSDP_SIG))) {
		printk(KERN_WARNING "RSDP table signature incorrect\n");
		return -EINVAL;
	}

	rsdt = (struct acpi_table_rsdt *)
	    __va_range(rsdp->rsdt_address, sizeof(struct acpi_table_rsdt));

	if (!rsdt) {
		printk(KERN_WARNING "ACPI: Invalid root system description tables (RSDT)\n");
		return -ENODEV;
	}
	
	header = & rsdt->header;
	acpi_print_table_header(header);
	
	if (strncmp(header->signature, RSDT_SIG, strlen(RSDT_SIG))) {
		printk(KERN_WARNING "ACPI: RSDT signature incorrect\n");
		return -ENODEV;
	}
		
	/* 
	 * The number of tables is computed by taking the 
	 * size of all entries (header size minus total 
	 * size of RSDT) divided by the size of each entry
	 * (4-byte table pointers).
	 */
	tables = (header->length - sizeof(acpi_table_header)) / 4;
		    
	memcpy(&saved_rsdt, rsdt, sizeof(saved_rsdt));

	if (saved_rsdt.header.length > sizeof(saved_rsdt)) {
		printk(KERN_WARNING "ACPI: Too big length in RSDT: %d\n", saved_rsdt.header.length);
		return -ENODEV;
	}

	for (i = 0; i < tables; i++) {
		/* Map in header, then map in full table length. */
		header = (acpi_table_header *)
			    __va_range(saved_rsdt.entry[i],
				       sizeof(acpi_table_header));
		if (!header)
			break;
		header = (acpi_table_header *)
			    __va_range(saved_rsdt.entry[i], header->length);
		if (!header)
			break;

		acpi_print_table_header(header);
		
		if (acpi_checksum(header,header->length)) {
			printk(KERN_WARNING "ACPI %s has invalid checksum\n", 
				acpi_table_signatures[i]);
			continue;
		}
		
		for (type = 0; type < ACPI_TABLE_COUNT; type++)
			if (!strncmp((char *) &header->signature,
			     acpi_table_signatures[type],strlen(acpi_table_signatures[type])))
				break;

		if (type >= ACPI_TABLE_COUNT) {
			printk(KERN_WARNING "ACPI: Unsupported table %.4s\n",
			       header->signature);
			continue;
		}


		if (!acpi_boot_ops[type])
			continue;
			
		result = acpi_boot_ops[type] (header,
						 (unsigned long) saved_rsdt.
						 entry[i]);
	}

	return result;
}

static int total_cpus __initdata = 0;
int have_acpi_tables;

extern void __init MP_processor_info(struct mpc_config_processor *);

static void __init
acpi_parse_lapic(struct acpi_table_lapic *local_apic)
{
	struct mpc_config_processor proc_entry;
	int ix = 0;

	if (!local_apic)
		return;

	printk(KERN_INFO "LAPIC (acpi_id[0x%04x] id[0x%x] enabled[%d])\n",
		local_apic->acpi_id, local_apic->id, local_apic->flags.enabled);

	printk(KERN_INFO "CPU %d (0x%02x00)", total_cpus, local_apic->id);

	if (local_apic->flags.enabled) {
		printk(" enabled");
		ix = local_apic->id;
		if (ix >= MAX_APICS) {
			printk(KERN_WARNING
			       "Processor #%d INVALID - (Max ID: %d).\n", ix,
			       MAX_APICS);
			return;
		}
		/* 
		 * Fill in the info we want to save.  Not concerned about 
		 * the processor ID.  Processor features aren't present in 
		 * the table.
		 */
		proc_entry.mpc_type = MP_PROCESSOR;
		proc_entry.mpc_apicid = local_apic->id;
		proc_entry.mpc_cpuflag = CPU_ENABLED;
		if (proc_entry.mpc_apicid == boot_cpu_physical_apicid) {
			printk(" (BSP)");
			proc_entry.mpc_cpuflag |= CPU_BOOTPROCESSOR;
		}
		proc_entry.mpc_cpufeature =
		    (boot_cpu_data.x86 << 8) | 
		    (boot_cpu_data.x86_model << 4) | 
		     boot_cpu_data.x86_mask;
		proc_entry.mpc_featureflag = boot_cpu_data.x86_capability[0];
		proc_entry.mpc_reserved[0] = 0;
		proc_entry.mpc_reserved[1] = 0;
		proc_entry.mpc_apicver = 0x10;	/* integrated APIC */
		MP_processor_info(&proc_entry);
	} else {
		printk(" disabled");
	}
	printk("\n");

	total_cpus++;
	return;
}

static void __init
acpi_parse_ioapic(struct acpi_table_ioapic *ioapic)
{

	if (!ioapic)
		return;

	printk(KERN_INFO
	       "IOAPIC (id[0x%x] address[0x%x] global_irq_base[0x%x])\n",
	       ioapic->id, ioapic->address, ioapic->global_irq_base);

	if (nr_ioapics >= MAX_IO_APICS) {
		printk(KERN_WARNING
		       "Max # of I/O APICs (%d) exceeded (found %d).\n",
		       MAX_IO_APICS, nr_ioapics);
/*		panic("Recompile kernel with bigger MAX_IO_APICS!\n");   */
	}
}


/* Interrupt source overrides inform the machine about exceptions
   to the normal "PIC" mode interrupt routing */
   
static void __init
acpi_parse_int_src_ovr(struct acpi_table_int_src_ovr *intsrc)
{
	if (!intsrc)
		return;

	printk(KERN_INFO
	       "INT_SRC_OVR (bus[%d] irq[0x%x] global_irq[0x%x] polarity[0x%x] trigger[0x%x])\n",
	       intsrc->bus, intsrc->bus_irq, intsrc->global_irq,
	       intsrc->flags.polarity, intsrc->flags.trigger);
}

/*
 * At this point, we look at the interrupt assignment entries in the MPS
 * table.
 */ 
 
static void __init acpi_parse_nmi_src(struct acpi_table_nmi_src *nmisrc)
{
	if (!nmisrc)
		return;

	printk(KERN_INFO
	       "NMI_SRC (polarity[0x%x] trigger[0x%x] global_irq[0x%x])\n",
	       nmisrc->flags.polarity, nmisrc->flags.trigger,
	       nmisrc->global_irq);

}
static void __init
acpi_parse_lapic_nmi(struct acpi_table_lapic_nmi *localnmi)
{
	if (!localnmi)
		return;

	printk(KERN_INFO
	       "LAPIC_NMI (acpi_id[0x%04x] polarity[0x%x] trigger[0x%x] lint[0x%x])\n",
	       localnmi->acpi_id, localnmi->flags.polarity,
	       localnmi->flags.trigger, localnmi->lint);
}
static void __init
acpi_parse_lapic_addr_ovr(struct acpi_table_lapic_addr_ovr *lapic_addr_ovr)
{
	if (!lapic_addr_ovr)
		return;

	printk(KERN_INFO "LAPIC_ADDR_OVR (address[0x%lx])\n",
	       (unsigned long) lapic_addr_ovr->address);

}

static void __init
acpi_parse_plat_int_src(struct acpi_table_plat_int_src *plintsrc)
{
	if (!plintsrc)
		return;

	printk(KERN_INFO
	       "PLAT_INT_SRC (polarity[0x%x] trigger[0x%x] type[0x%x] id[0x%04x] eid[0x%x] iosapic_vector[0x%x] global_irq[0x%x]\n",
	       plintsrc->flags.polarity, plintsrc->flags.trigger,
	       plintsrc->type, plintsrc->id, plintsrc->eid,
	       plintsrc->iosapic_vector, plintsrc->global_irq);
}
static int __init
acpi_parse_madt(acpi_table_header * header, unsigned long phys)
{

	struct acpi_table_madt *madt;	    
	acpi_madt_entry_header *entry_header;
	int table_size;
	
	madt = (struct acpi_table_madt *) __va_range(phys, header->length);

	if (!madt)
		return -EINVAL;

	table_size = (int) (header->length - sizeof(*madt));
	entry_header =
	    (acpi_madt_entry_header *) ((void *) madt + sizeof(*madt));

	while (entry_header && (table_size > 0)) {
		switch (entry_header->type) {
		case ACPI_MADT_LAPIC:
			acpi_parse_lapic((struct acpi_table_lapic *)
					 entry_header);
			break;
		case ACPI_MADT_IOAPIC:
			acpi_parse_ioapic((struct acpi_table_ioapic *)
					  entry_header);
			break;
		case ACPI_MADT_INT_SRC_OVR:
			acpi_parse_int_src_ovr((struct acpi_table_int_src_ovr *)
					       entry_header);
			break;
		case ACPI_MADT_NMI_SRC:
			acpi_parse_nmi_src((struct acpi_table_nmi_src *)
					   entry_header);
			break;
		case ACPI_MADT_LAPIC_NMI:
			acpi_parse_lapic_nmi((struct acpi_table_lapic_nmi *)
					     entry_header);
			break;
		case ACPI_MADT_LAPIC_ADDR_OVR:
			acpi_parse_lapic_addr_ovr((struct
						   acpi_table_lapic_addr_ovr *)
						  entry_header);
			break;
		case ACPI_MADT_PLAT_INT_SRC:
			acpi_parse_plat_int_src((struct acpi_table_plat_int_src
						 *) entry_header);
			break;
		default:
			printk(KERN_WARNING
			       "Unsupported MADT entry type 0x%x\n",
			       entry_header->type);
			break;
		}
		table_size -= entry_header->length;
		entry_header =
		    (acpi_madt_entry_header *) ((void *) entry_header +
						entry_header->length);
	}

	if (!total_cpus) {
		printk("ACPI: No Processors found in the APCI table.\n");
		return -EINVAL;
	}

	printk(KERN_INFO "%d CPUs total\n", total_cpus);

	if (madt->lapic_address)
		mp_lapic_addr = madt->lapic_address;
	else
		mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;

	printk(KERN_INFO "Local APIC address %x\n", madt->lapic_address);

	return 0;
}

extern int opt_noacpi;

/*
 * Configure the processor info using MADT in the ACPI tables. If we fail to
 * configure that, then we use the MPS tables.
 */
void __init
config_acpi_tables(void)
{
	memset(&acpi_boot_ops, 0, sizeof(acpi_boot_ops));
	acpi_boot_ops[ACPI_APIC] = acpi_parse_madt;

	if (!opt_noacpi && !acpi_tables_init()) {
		have_acpi_tables = 1;
		printk("Enabling the CPU's according to the ACPI table\n");
	}
}

#endif /* CONFIG_X86_IO_APIC */
