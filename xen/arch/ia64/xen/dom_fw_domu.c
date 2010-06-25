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

#ifdef __XEN__
#include <xen/sched.h>
#include <asm/dom_fw_utils.h>
#include <linux/sort.h>
#define xen_ia64_dom_fw_map(d, mpaddr)  domain_mpa_to_imva((d), (mpaddr))
#define xen_ia64_dom_fw_unmap(d, vaddr)  do { } while (0)
#else
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>

#include <xen/xen.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "ia64/xc_dom_ia64_util.h"
#endif

#include <asm/dom_fw.h>
#include <asm/dom_fw_domu.h>

#ifdef __XEN__
void efi_systable_init_domu(struct fw_tables *tables)
#else
void efi_systable_init_domu(xc_interface *xch, struct fw_tables *tables)
#endif
{
	int i = 1;

	printk(XENLOG_GUEST XENLOG_INFO "DomainU EFI build up:");

	tables->efi_tables[i].guid = ACPI_20_TABLE_GUID;
	tables->efi_tables[i].table = FW_ACPI_BASE_PADDR;
	printk(" ACPI 2.0=0x%lx", tables->efi_tables[i].table);
	i++;
	printk("\n");
	BUG_ON(i > NUM_EFI_SYS_TABLES);
}

int
complete_domu_memmap(domain_t * d,
		     struct fw_tables *tables,
		     unsigned long maxmem,
		     unsigned long memmap_info_pfn,
		     unsigned long memmap_info_num_pages)
{
	efi_memory_desc_t *md;
	int create_memmap = 0;
	xen_ia64_memmap_info_t *memmap_info;
	unsigned long memmap_info_size;
	unsigned long paddr_start;
	unsigned long paddr_end;
	void *p;
	void *memmap_start;
	void *memmap_end;
#ifndef __XEN__
	xc_interface *xch = d->xch;
#endif

	if (memmap_info_pfn == 0 || memmap_info_num_pages == 0) {
		/* old domain builder which doesn't setup
		 * memory map. create it for compatibility */
		memmap_info_pfn = (maxmem >> PAGE_SHIFT) - 1;
		memmap_info_num_pages = 1;
		create_memmap = 1;
	}

	memmap_info_size = memmap_info_num_pages << PAGE_SHIFT;
	paddr_start = memmap_info_pfn << PAGE_SHIFT;
	/* 3 = start info page, xenstore page and console page */
	paddr_end = paddr_start + memmap_info_size + 3 * PAGE_SIZE;
	memmap_info = xen_ia64_dom_fw_map(d, paddr_start);

	if (memmap_info->efi_memmap_size == 0) {
		create_memmap = 1;
	} else if (memmap_info->efi_memdesc_size != sizeof(md[0]) ||
		   memmap_info->efi_memdesc_version !=
		   EFI_MEMORY_DESCRIPTOR_VERSION) {
		printk(XENLOG_WARNING
		       "%s: Warning: unknown memory map "
		       "memmap size %" PRIu64 " "
		       "memdesc size %" PRIu64 " "
		       "version %" PRIu32 "\n",
		       __func__,
		       memmap_info->efi_memmap_size,
		       memmap_info->efi_memdesc_size,
		       memmap_info->efi_memdesc_version);
		create_memmap = 1;
	} else if (memmap_info_size < memmap_info->efi_memmap_size) {
		printk(XENLOG_WARNING
		       "%s: Warning: too short memmap info size %" PRIu64 "\n",
		       __func__, memmap_info_size);
		xen_ia64_dom_fw_unmap(d, memmap_info);
		return -EINVAL;
	} else if (memmap_info->efi_memmap_size >
		   PAGE_SIZE - sizeof(*memmap_info)) {
		/*
		 * curently memmap spanning more than single page isn't
		 * supported.
		 */
		printk(XENLOG_WARNING
		       "%s: Warning: too large efi_memmap_size %" PRIu64 "\n",
		       __func__, memmap_info->efi_memmap_size);
		xen_ia64_dom_fw_unmap(d, memmap_info);
		return -ENOSYS;
	}

	if (create_memmap) {
		/*
		 * old domain builder which doesn't setup
		 * memory map. create it for compatibility
		 */
		memmap_info->efi_memdesc_size = sizeof(md[0]);
		memmap_info->efi_memdesc_version =
		    EFI_MEMORY_DESCRIPTOR_VERSION;
		memmap_info->efi_memmap_size = 1 * sizeof(md[0]);

		md = (efi_memory_desc_t *) & memmap_info->memdesc;
		md->type = EFI_CONVENTIONAL_MEMORY;
		md->pad = 0;
		md->phys_addr = 0;
		md->virt_addr = 0;
		md->num_pages = maxmem >> EFI_PAGE_SHIFT;
		md->attribute = EFI_MEMORY_WB;
	}

	memmap_start = &memmap_info->memdesc;
	memmap_end = memmap_start + memmap_info->efi_memmap_size;

	/* XXX Currently the table must be in a single page. */
	if ((unsigned long)memmap_end > (unsigned long)memmap_info + PAGE_SIZE) {
		xen_ia64_dom_fw_unmap(d, memmap_info);
		return -EINVAL;
	}

	/* sort it bofore use
	 * XXX: this is created by user space domain builder so that
	 * we should check its integrity */
	sort(&memmap_info->memdesc,
	     memmap_info->efi_memmap_size / memmap_info->efi_memdesc_size,
	     memmap_info->efi_memdesc_size, efi_mdt_cmp, NULL);

	for (p = memmap_start; p < memmap_end;
	     p += memmap_info->efi_memdesc_size) {
		unsigned long start;
		unsigned long end;

		md = p;
		start = md->phys_addr;
		end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

		if (start < tables->fw_end_paddr)
			start = tables->fw_end_paddr;
		if (end <= start)
			continue;

		/* exclude [paddr_start, paddr_end) */
		if (paddr_end <= start || end <= paddr_start) {
			xen_ia64_efi_make_md(&tables->
					     efi_memmap[tables->num_mds],
					     EFI_CONVENTIONAL_MEMORY,
					     EFI_MEMORY_WB, start, end);
			tables->num_mds++;
		} else if (paddr_start <= start && paddr_end < end) {
			xen_ia64_efi_make_md(&tables->
					     efi_memmap[tables->num_mds],
					     EFI_CONVENTIONAL_MEMORY,
					     EFI_MEMORY_WB, paddr_end, end);
			tables->num_mds++;
		} else if (start < paddr_start && end <= paddr_end) {
			xen_ia64_efi_make_md(&tables->
					     efi_memmap[tables->num_mds],
					     EFI_CONVENTIONAL_MEMORY,
					     EFI_MEMORY_WB, start, paddr_start);
			tables->num_mds++;
		} else {
			xen_ia64_efi_make_md(&tables->
					     efi_memmap[tables->num_mds],
					     EFI_CONVENTIONAL_MEMORY,
					     EFI_MEMORY_WB, start, paddr_start);
			tables->num_mds++;
			xen_ia64_efi_make_md(&tables->
					     efi_memmap[tables->num_mds],
					     EFI_CONVENTIONAL_MEMORY,
					     EFI_MEMORY_WB, paddr_end, end);
			tables->num_mds++;
		}
	}

	/* memmap info page. */
	xen_ia64_efi_make_md(&tables->efi_memmap[tables->num_mds],
			     EFI_RUNTIME_SERVICES_DATA, EFI_MEMORY_WB,
			     paddr_start, paddr_end);
	tables->num_mds++;

	/* Create an entry for IO ports.  */
	xen_ia64_efi_make_md(&tables->efi_memmap[tables->num_mds],
			     EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_MEMORY_UC,
			     IO_PORTS_PADDR, IO_PORTS_PADDR + IO_PORTS_SIZE);
	tables->num_mds++;

	sort(tables->efi_memmap, tables->num_mds, sizeof(efi_memory_desc_t),
	     efi_mdt_cmp, NULL);

	xen_ia64_dom_fw_unmap(d, memmap_info);
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
