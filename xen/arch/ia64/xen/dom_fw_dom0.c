/******************************************************************************
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
/*
 *  Xen domain firmware emulation support
 *  Copyright (C) 2004 Hewlett-Packard Co.
 *       Dan Magenheimer (dan.magenheimer@hp.com)
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/list.h>
#include <xen/acpi.h>
#include <acpi/actables.h>

#include <asm/dom_fw.h>
#include <asm/dom_fw_common.h>
#include <asm/dom_fw_dom0.h>
#include <asm/dom_fw_utils.h>

#include <linux/sort.h>

struct acpi_backup_table_entry {
	struct list_head list;
	unsigned long pa;
	unsigned long size;
	unsigned char data[0];
};

static LIST_HEAD(acpi_backup_table_list);

static u32 lsapic_nbr;

/* Modify lsapic table.  Provides LPs.  */
static int __init
acpi_update_lsapic(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_local_sapic *lsapic =
		container_of(header, struct acpi_madt_local_sapic, header);
	int enable;

	if (!header)
		return -EINVAL;

	if (lsapic_nbr < dom0->max_vcpus && dom0->vcpu[lsapic_nbr] != NULL)
		enable = 1;
	else
		enable = 0;

	if ((lsapic->lapic_flags & ACPI_MADT_ENABLED) && enable) {
		printk("enable lsapic entry: 0x%lx\n", (u64) lsapic);
		lsapic->id = lsapic_nbr;
		lsapic->eid = 0;
		lsapic_nbr++;
	} else if (lsapic->lapic_flags & ACPI_MADT_ENABLED) {
		printk("DISABLE lsapic entry: 0x%lx\n", (u64) lsapic);
		lsapic->lapic_flags &= ~ACPI_MADT_ENABLED;
		lsapic->id = 0;
		lsapic->eid = 0;
	}
	return 0;
}

static int __init
acpi_patch_plat_int_src(struct acpi_subtable_header * header,
			const unsigned long end)
{
	struct acpi_madt_interrupt_source *plintsrc =
		container_of(header, struct acpi_madt_interrupt_source,
			     header);

	if (!header)
		return -EINVAL;

	if (plintsrc->type == ACPI_INTERRUPT_CPEI) {
		printk("ACPI_INTERRUPT_CPEI disabled for Domain0\n");
		plintsrc->type = -1;
	}
	return 0;
}

static int __init
acpi_update_madt_checksum(struct acpi_table_header *table)
{
	struct acpi_table_madt *acpi_madt;

	if (!table)
		return -EINVAL;

	acpi_madt = (struct acpi_table_madt *)table;
	acpi_madt->header.checksum = 0;
	acpi_madt->header.checksum = -acpi_tb_checksum((u8*)acpi_madt,
						       table->length);

	return 0;
}

static int __init
acpi_backup_table(struct acpi_table_header *table)
{
	struct acpi_backup_table_entry *entry;

	entry = xmalloc_bytes(sizeof(*entry) + table->length);
	if (!entry) {
		dprintk(XENLOG_WARNING, "Failed to allocate memory for "
		        "%.4s table backup\n", table->signature);
		return -ENOMEM;
	}

	entry->pa = __pa(table);
	entry->size = table->length;

	memcpy(entry->data, table, table->length);

	list_add(&entry->list, &acpi_backup_table_list);

	printk(XENLOG_INFO "Backup %.4s table stored @0x%p\n",
	       table->signature, entry->data);

	return 0;
}

void
acpi_restore_tables()
{
	struct acpi_backup_table_entry *entry;

	list_for_each_entry(entry, &acpi_backup_table_list, list) {
		printk(XENLOG_INFO "Restoring backup %.4s table @0x%p\n",
		       ((struct acpi_table_header *)entry->data)->signature,
		       entry->data);

		memcpy(__va(entry->pa), entry->data, entry->size);
		/* Only called from kexec path, no need to free entries */
	}
}

static int __init __acpi_table_disable(struct acpi_table_header *header)
{
	printk("Disabling ACPI table: %4.4s\n", header->signature);

	memcpy(header->oem_id, "xxxxxx", 6);
	memcpy(header->oem_id+1, header->signature, 4);
	memcpy(header->oem_table_id, "Xen     ", 8);
	memcpy(header->signature, "OEMx", 4);
	header->checksum = 0;
	header->checksum = -acpi_tb_checksum((u8*)header, header->length);

	return 0;
}

static void __init acpi_table_disable(char *id)
{
	acpi_table_parse(id, __acpi_table_disable);
}

/* base is physical address of acpi table */
static void __init touch_acpi_table(void)
{
	struct acpi_table_header *madt = NULL;

	lsapic_nbr = 0;

	acpi_get_table(ACPI_SIG_MADT, 0, &madt);

	/*
	 * Modify dom0 MADT:
	 *  - Disable CPUs that would exceed max vCPUs for the domain
	 *  - Virtualize id/eid for indexing into domain vCPU array
	 *  - Hide CPEI interrupt source
	 *
	 * ACPI tables must be backed-up before modification!
	 *
	 * We update the checksum each time we modify to keep the
	 * ACPI CA from warning about invalid checksums.
	 */
	acpi_table_parse(ACPI_SIG_MADT, acpi_backup_table);

	if (acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_SAPIC,
				  acpi_update_lsapic, 0) < 0)
		printk("Error parsing MADT - no LAPIC entries\n");

	acpi_update_madt_checksum(madt);

	if (acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_SOURCE,
				  acpi_patch_plat_int_src, 0) < 0)
		printk("Error parsing MADT - no PLAT_INT_SRC entries\n");

	acpi_update_madt_checksum(madt);

	/*
	 * SRAT & SLIT tables aren't useful for Dom0 until
	 * we support more NUMA configuration information in Xen.
	 *
	 * NB - backup ACPI tables first.
	 */
	acpi_table_parse(ACPI_SIG_SRAT, acpi_backup_table);
	acpi_table_parse(ACPI_SIG_SLIT, acpi_backup_table);

	acpi_table_disable(ACPI_SIG_SRAT);
	acpi_table_disable(ACPI_SIG_SLIT);
	return;
}

void __init efi_systable_init_dom0(struct fw_tables *tables)
{
	int i = 1;

	touch_acpi_table();

	/* Write messages to the console.  */
	printk("Domain0 EFI passthrough:");
	if (efi.mps != EFI_INVALID_TABLE_ADDR) {
		tables->efi_tables[i].guid = MPS_TABLE_GUID;
		tables->efi_tables[i].table = efi.mps;
		printk(" MPS=0x%lx", tables->efi_tables[i].table);
		i++;
	}
	if (efi.acpi20 != EFI_INVALID_TABLE_ADDR) {
		tables->efi_tables[i].guid = ACPI_20_TABLE_GUID;
		tables->efi_tables[i].table = efi.acpi20;
		printk(" ACPI 2.0=0x%lx", tables->efi_tables[i].table);
		i++;
	}
	if (efi.acpi != EFI_INVALID_TABLE_ADDR) {
		tables->efi_tables[i].guid = ACPI_TABLE_GUID;
		tables->efi_tables[i].table = efi.acpi;
		printk(" ACPI=0x%lx", tables->efi_tables[i].table);
		i++;
	}
	if (efi.smbios != EFI_INVALID_TABLE_ADDR) {
		tables->efi_tables[i].guid = SMBIOS_TABLE_GUID;
		tables->efi_tables[i].table = efi.smbios;
		printk(" SMBIOS=0x%lx", tables->efi_tables[i].table);
		i++;
	}
	if (efi.hcdp != EFI_INVALID_TABLE_ADDR) {
		tables->efi_tables[i].guid = HCDP_TABLE_GUID;
		tables->efi_tables[i].table = efi.hcdp;
		printk(" HCDP=0x%lx", tables->efi_tables[i].table);
		i++;
	}
	printk("\n");
	BUG_ON(i > NUM_EFI_SYS_TABLES);
}

static void __init
setup_dom0_memmap_info(struct domain *d, struct fw_tables *tables)
{
	int i;
	size_t size;
	unsigned int num_pages;
	efi_memory_desc_t *md;
	efi_memory_desc_t *last_mem_md = NULL;
	xen_ia64_memmap_info_t *memmap_info;
	unsigned long paddr_start;
	unsigned long paddr_end;

	size = sizeof(*memmap_info) +
		(tables->num_mds + 1) * sizeof(tables->efi_memmap[0]);
	num_pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	for (i = tables->num_mds - 1; i >= 0; i--) {
		md = &tables->efi_memmap[i];
		if (md->attribute == EFI_MEMORY_WB &&
		    md->type == EFI_CONVENTIONAL_MEMORY &&
		    md->num_pages >
		    ((num_pages + 1) << (PAGE_SHIFT - EFI_PAGE_SHIFT))) {
			last_mem_md = md;
			break;
		}
	}

	if (last_mem_md == NULL) {
		printk("%s: warning: "
		       "no dom0 contiguous memory to hold memory map\n",
		       __func__);
		return;
	}
	paddr_end = last_mem_md->phys_addr +
	    (last_mem_md->num_pages << EFI_PAGE_SHIFT);
	paddr_start = (paddr_end - (num_pages << PAGE_SHIFT)) & PAGE_MASK;
	last_mem_md->num_pages -= (paddr_end - paddr_start) >> EFI_PAGE_SHIFT;

	md = &tables->efi_memmap[tables->num_mds];
	tables->num_mds++;
	md->type = EFI_RUNTIME_SERVICES_DATA;
	md->phys_addr = paddr_start;
	md->virt_addr = 0;
	md->num_pages = num_pages << (PAGE_SHIFT - EFI_PAGE_SHIFT);
	md->attribute = EFI_MEMORY_WB;

	BUG_ON(tables->fw_tables_size <
	       sizeof(*tables) +
	       sizeof(tables->efi_memmap[0]) * tables->num_mds);
	/* with this sort, md doesn't point memmap table */
	sort(tables->efi_memmap, tables->num_mds,
	     sizeof(efi_memory_desc_t), efi_mdt_cmp, NULL);

	memmap_info = domain_mpa_to_imva(d, paddr_start);
	memmap_info->efi_memdesc_size = sizeof(md[0]);
	memmap_info->efi_memdesc_version = EFI_MEMORY_DESCRIPTOR_VERSION;
	memmap_info->efi_memmap_size = tables->num_mds * sizeof(md[0]);
	dom_fw_copy_to(d,
		       paddr_start + offsetof(xen_ia64_memmap_info_t, memdesc),
		       &tables->efi_memmap[0], memmap_info->efi_memmap_size);
	d->shared_info->arch.memmap_info_num_pages = num_pages;
	d->shared_info->arch.memmap_info_pfn = paddr_start >> PAGE_SHIFT;
}

/* setup_guest() @ libxc/xc_linux_build() arranges memory for domU.
 * however no one arranges memory for dom0,
 * instead we allocate pages manually.
 */
static void
assign_new_domain0_range(struct domain *d, const efi_memory_desc_t * md)
{
	if (md->type == EFI_PAL_CODE ||
	    md->type == EFI_RUNTIME_SERVICES_DATA ||
	    md->type == EFI_CONVENTIONAL_MEMORY) {
		unsigned long start = md->phys_addr & PAGE_MASK;
		unsigned long end =
			md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);
		unsigned long addr;

		if (end == start) {
			/* md->num_pages = 0 is allowed. */
			return;
		}

		for (addr = start; addr < end; addr += PAGE_SIZE)
			assign_new_domain0_page(d, addr);
	}
}

/* Complete the dom0 memmap.  */
int __init
complete_dom0_memmap(struct domain *d, struct fw_tables *tables)
{
	u64 addr;
	void *efi_map_start, *efi_map_end, *p;
	u64 efi_desc_size;
	int i;

	for (i = 0; i < tables->num_mds; i++)
		assign_new_domain0_range(d, &tables->efi_memmap[i]);

	/* Walk through all MDT entries.
	   Copy all interesting entries.  */
	efi_map_start = __va(ia64_boot_param->efi_memmap);
	efi_map_end = efi_map_start + ia64_boot_param->efi_memmap_size;
	efi_desc_size = ia64_boot_param->efi_memdesc_size;


	/* EFI memory descriptor is using 4k page, while xen is using 16k page.
	 * To avoid identity mapping for EFI_ACPI_RECLAIM_MEMORY etc. being
	 * blocked by WB mapping, scan memory descriptor twice.
	 * First: setup identity mapping for EFI_ACPI_RECLAIM_MEMORY etc.
	 * Second: setup mapping for EFI_CONVENTIONAL_MEMORY etc.
	 */
  
	/* first scan, setup identity mapping for EFI_ACPI_RECLAIM_MEMORY etc. */
	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
		const efi_memory_desc_t *md = p;
		efi_memory_desc_t *dom_md = &tables->efi_memmap[tables->num_mds];
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;
		u64 end = start + size;
		u64 mpaddr;
		unsigned long flags;

		switch (md->type) {
		case EFI_RUNTIME_SERVICES_CODE:
		case EFI_RUNTIME_SERVICES_DATA:
		case EFI_ACPI_RECLAIM_MEMORY:
		case EFI_ACPI_MEMORY_NVS:
		case EFI_RESERVED_TYPE:
			/*
			 * Map into dom0 - We must respect protection
			 * and cache attributes.  Not all of these pages
			 * are writable!!!
			 */
			flags = ASSIGN_writable;	/* dummy - zero */
			if (md->attribute & EFI_MEMORY_WP)
				flags |= ASSIGN_readonly;
			if ((md->attribute & EFI_MEMORY_UC) &&
			    !(md->attribute & EFI_MEMORY_WB))
				flags |= ASSIGN_nocache;

			assign_domain_mach_page(d, start, size, flags);

			/* Fall-through.  */
		case EFI_MEMORY_MAPPED_IO:
			/* Will be mapped with ioremap.  */
			/* Copy descriptor.  */
			*dom_md = *md;
			dom_md->virt_addr = 0;
			tables->num_mds++;
			break;

		case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
			flags = ASSIGN_writable;	/* dummy - zero */
			if (md->attribute & EFI_MEMORY_UC)
				flags |= ASSIGN_nocache;

			if (start > 0x1ffffffff0000000UL) {
				mpaddr = 0x4000000000000UL - size;
				printk(XENLOG_INFO "Remapping IO ports from "
				       "%lx to %lx\n", start, mpaddr);
			} else
				mpaddr = start;

			/* Map into dom0.  */
			assign_domain_mmio_page(d, mpaddr, start, size, flags);
			/* Copy descriptor.  */
			*dom_md = *md;
			dom_md->phys_addr = mpaddr;
			dom_md->virt_addr = 0;
			tables->num_mds++;
			break;

		case EFI_CONVENTIONAL_MEMORY:
		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA:
			break;

		case EFI_UNUSABLE_MEMORY:
		case EFI_PAL_CODE:
			/*
			 * We don't really need these, but holes in the
			 * memory map may cause Linux to assume there are
			 * uncacheable ranges within a granule.
			 */
			dom_md->type = EFI_UNUSABLE_MEMORY;
			dom_md->phys_addr = start;
			dom_md->virt_addr = 0;
			dom_md->num_pages = (end - start) >> EFI_PAGE_SHIFT;
			dom_md->attribute = EFI_MEMORY_WB;
			tables->num_mds++;
			break;

		default:
			/* Print a warning but continue.  */
			printk("complete_dom0_memmap: warning: "
			       "unhandled MDT entry type %u\n", md->type);
		}
	}

 
	/* secend scan, setup mapping for EFI_CONVENTIONAL_MEMORY etc. */
	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
		const efi_memory_desc_t *md = p;
		efi_memory_desc_t *dom_md = &tables->efi_memmap[tables->num_mds];
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;
		u64 end = start + size;

		switch (md->type) {

		case EFI_CONVENTIONAL_MEMORY:
		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA: {
			u64 dom_md_start;
			u64 dom_md_end;
			unsigned long left_mem =
				(unsigned long)(d->max_pages - d->tot_pages) <<
				PAGE_SHIFT;

			if (!(md->attribute & EFI_MEMORY_WB))
				break;

			dom_md_start = max(tables->fw_end_paddr, start);
			dom_md_end = dom_md_start;
			do {
				dom_md_end = min(dom_md_end + left_mem, end);
				if (dom_md_end < dom_md_start + PAGE_SIZE)
					break;

				dom_md->type = EFI_CONVENTIONAL_MEMORY;
				dom_md->phys_addr = dom_md_start;
				dom_md->virt_addr = 0;
				dom_md->num_pages =
					(dom_md_end - dom_md_start) >>
					EFI_PAGE_SHIFT;
				dom_md->attribute = EFI_MEMORY_WB;

				assign_new_domain0_range(d, dom_md);
				/*
				 * recalculate left_mem.
				 * we might already allocated memory in
				 * this region because of kernel loader.
				 * So we might consumed less than
				 * (dom_md_end - dom_md_start) above.
				 */
				left_mem = (unsigned long)
					(d->max_pages - d->tot_pages) <<
					PAGE_SHIFT;
			} while (left_mem > 0 && dom_md_end < end);

			if (!(dom_md_end < dom_md_start + PAGE_SIZE))
				tables->num_mds++;
			break;
		}


		default:
			break;
		}
	}

	BUG_ON(tables->fw_tables_size <
	       sizeof(*tables) +
	       sizeof(tables->efi_memmap[0]) * tables->num_mds);

	sort(tables->efi_memmap, tables->num_mds, sizeof(efi_memory_desc_t),
	     efi_mdt_cmp, NULL);

	// Map low-memory holes & unmapped MMIO for legacy drivers
	for (addr = 0; addr < ONE_MB; addr += PAGE_SIZE) {
		if (domain_page_mapped(d, addr))
			continue;

		if (efi_mmio(addr, PAGE_SIZE)) {
			unsigned long flags;
			flags = ASSIGN_writable | ASSIGN_nocache;
			assign_domain_mmio_page(d, addr, addr, PAGE_SIZE,
						flags);
		}
	}
	setup_dom0_memmap_info(d, tables);
	return tables->num_mds;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "linux"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
