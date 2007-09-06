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

#include <xen/types.h>
#include <xen/version.h>
#include <xen/errno.h>
#include <xen/sched.h>

#include <asm/fpswa.h>
#include <asm/dom_fw.h>
#include <asm/dom_fw_common.h>
#include <asm/dom_fw_utils.h>

#include <linux/sort.h>

uint32_t xen_ia64_version(struct domain *unused)
{
	return (xen_major_version() << 16) | xen_minor_version();
}

int xen_ia64_fpswa_revision(struct domain *d, unsigned int *revision)
{
	if (fpswa_interface == NULL)
		return -ENOSYS;

	*revision = fpswa_interface->revision;
	return 0;
}

int xen_ia64_is_vcpu_allocated(struct domain *d, uint32_t vcpu)
{
	return d->vcpu[vcpu] != NULL;
}

int xen_ia64_is_running_on_sim(struct domain *unused)
{
	return running_on_sim;
}

int xen_ia64_is_dom0(struct domain *d)
{
	return d == dom0;
}

void xen_ia64_set_convmem_end(struct domain *d, uint64_t convmem_end)
{
	d->arch.convmem_end = convmem_end;
}

static void dom_fw_domain_init(struct domain *d, struct fw_tables *tables)
{
	/* Initialise for EFI_SET_VIRTUAL_ADDRESS_MAP emulation */
	d->arch.efi_runtime = &tables->efi_runtime;
	d->arch.fpswa_inf = &tables->fpswa_inf;
	d->arch.sal_data = &tables->sal_data;
}

static int dom_fw_set_convmem_end(struct domain *d)
{
	unsigned long gpaddr;
	size_t size;
	xen_ia64_memmap_info_t *memmap_info;
	efi_memory_desc_t *md;
	void *p;
	void *memmap_start;
	void *memmap_end;

	if (d->shared_info->arch.memmap_info_pfn == 0)
		return -EINVAL;

	gpaddr = d->shared_info->arch.memmap_info_pfn << PAGE_SHIFT;
	size = d->shared_info->arch.memmap_info_num_pages << PAGE_SHIFT;
	memmap_info = _xmalloc(size, __alignof__(*memmap_info));
	if (memmap_info == NULL)
		return -ENOMEM;
	dom_fw_copy_from(memmap_info, d, gpaddr, size);
	if (memmap_info->efi_memmap_size == 0 ||
	    memmap_info->efi_memdesc_size != sizeof(*md) ||
	    memmap_info->efi_memdesc_version != EFI_MEMORY_DESCRIPTOR_VERSION ||
	    sizeof(*memmap_info) + memmap_info->efi_memmap_size > size ||
	    memmap_info->efi_memmap_size / memmap_info->efi_memdesc_size == 0) {
		xfree(memmap_info);
		return -EINVAL;
	}

	memmap_start = &memmap_info->memdesc;
	memmap_end = memmap_start + memmap_info->efi_memmap_size;

	/* sort it bofore use
	 * XXX: this is created by user space domain builder so that
	 * we should check its integrity */
	sort(&memmap_info->memdesc,
	     memmap_info->efi_memmap_size / memmap_info->efi_memdesc_size,
	     memmap_info->efi_memdesc_size, efi_mdt_cmp, NULL);

	if (d->arch.convmem_end == 0)
		xen_ia64_set_convmem_end(d, d->max_pages << PAGE_SHIFT);

	for (p = memmap_start; p < memmap_end;
	     p += memmap_info->efi_memdesc_size) {
		unsigned long end;

		md = p;
		end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

		if (md->attribute == EFI_MEMORY_WB &&
		    md->type == EFI_CONVENTIONAL_MEMORY &&
		    md->num_pages > 0 && d->arch.convmem_end < end)
			xen_ia64_set_convmem_end(d, end);
	}

	dom_fw_copy_to(d, gpaddr, memmap_info, size);
	xfree(memmap_info);
	return 0;
}

/* allocate a page for fw
 * guest_setup() @ libxc/xc_linux_build.c does for domU
 */
static inline void
assign_new_domain_page_if_dom0(struct domain *d, unsigned long mpaddr)
{
	if (d == dom0)
		assign_new_domain0_page(d, mpaddr);
}

static void dom_fw_setup_for_domain_restore(domain_t * d, unsigned long maxmem)
{
	assign_new_domain_page(d, FW_HYPERCALL_BASE_PADDR);
	dom_fw_domain_init(d, domain_mpa_to_imva(d, FW_TABLES_BASE_PADDR));
	xen_ia64_set_convmem_end(d, maxmem);
}

/* copy memory range to domain pseudo physical address space */
void
dom_fw_copy_to(struct domain *d, unsigned long dest_gpaddr,
	       void *src, size_t size)
{
	while (size > 0) {
		unsigned long page_offset = dest_gpaddr & ~PAGE_MASK;
		size_t copy_size = size;
		void *dest;

		if (page_offset + copy_size > PAGE_SIZE)
			copy_size = PAGE_SIZE - page_offset;
		dest = domain_mpa_to_imva(d, dest_gpaddr);
		memcpy(dest, src, copy_size);

		src += copy_size;
		dest_gpaddr += copy_size;
		size -= copy_size;
	}
}

/* copy memory range from domain pseudo physical address space */
void
dom_fw_copy_from(void *dest, struct domain *d, unsigned long src_gpaddr,
		 size_t size)
{
	while (size > 0) {
		unsigned long page_offset = src_gpaddr & ~PAGE_MASK;
		size_t copy_size = size;
		void *src;

		if (page_offset + copy_size > PAGE_SIZE)
			copy_size = PAGE_SIZE - page_offset;
		src = domain_mpa_to_imva(d, src_gpaddr);
		memcpy(dest, src, copy_size);

		dest += copy_size;
		src_gpaddr += copy_size;
		size -= copy_size;
	}
}

int dom_fw_setup(domain_t * d, unsigned long bp_mpa, unsigned long maxmem)
{
	int old_domu_builder = 0;
	struct xen_ia64_boot_param *bp;

	BUILD_BUG_ON(sizeof(struct fw_tables) >
		     (FW_TABLES_END_PADDR_MIN - FW_TABLES_BASE_PADDR));

	if (bp_mpa == 0) {
		/* bp_mpa == 0 means this is domain restore case. */
		dom_fw_setup_for_domain_restore(d, maxmem);
		return 0;
	}

	/* Create page for boot_param.  */
	assign_new_domain_page_if_dom0(d, bp_mpa);
	bp = domain_mpa_to_imva(d, bp_mpa);
	if (d != dom0) {
		/*
		 * XXX kludge.
		 * when XEN_DOMCTL_arch_setup is called, shared_info can't
		 * be accessed by libxc so that memmap_info_pfn isn't
		 * initialized. But dom_fw_set_convmem_end() requires it, 
		 * so here we initialize it.
		 * note: domain builder may overwrite memmap_info_num_pages,
		 *       memmap_info_pfns later.
		 */
		if (bp->efi_memmap_size == 0 ||
		    XEN_IA64_MEMMAP_INFO_NUM_PAGES(bp) == 0 ||
		    XEN_IA64_MEMMAP_INFO_PFN(bp) == 0) {
			/* old domain builder compatibility */
			d->shared_info->arch.memmap_info_num_pages = 1;
			d->shared_info->arch.memmap_info_pfn =
			    (maxmem >> PAGE_SHIFT) - 1;
			old_domu_builder = 1;
		} else {
			d->shared_info->arch.memmap_info_num_pages =
			    XEN_IA64_MEMMAP_INFO_NUM_PAGES(bp);
			d->shared_info->arch.memmap_info_pfn =
			    XEN_IA64_MEMMAP_INFO_PFN(bp);
			/* currently multi page memmap isn't supported */
			if (d->shared_info->arch.memmap_info_num_pages != 1)
				return -ENOSYS;
		}
	}

	/* Create page for acpi tables.  */
	if (d != dom0 && old_domu_builder) {
		struct fake_acpi_tables *imva;
		imva = domain_mpa_to_imva(d, FW_ACPI_BASE_PADDR);
		dom_fw_fake_acpi(d, imva);
	}
	if (d == dom0 || old_domu_builder) {
		int ret;
		unsigned long imva_hypercall_base;
		size_t fw_tables_size;
		struct fw_tables *fw_tables;
		unsigned long gpaddr;

		/* Create page for hypercalls.  */
		assign_new_domain_page_if_dom0(d, FW_HYPERCALL_BASE_PADDR);
		imva_hypercall_base = (unsigned long)domain_mpa_to_imva
		    (d, FW_HYPERCALL_BASE_PADDR);

		/*
		 * dom_fw_init()
		 *   - [FW_HYPERCALL_BASE_PADDR, FW_HYPERCALL_END_PADDR)
		 *   - [FW_ACPI_BASE_PADDR, FW_ACPI_END_PADDR)
		 *   - [FW_TABLES_BASE_PADDR, tables->fw_tables_end_paddr)
		 *
		 * complete_dom0_memmap() for dom0
		 *   - real machine memory map
		 *   - memmap_info by setup_dom0_memmap_info()
		 *
		 * complete_domu_memmap() for old domu builder
		 *   - I/O port
		 *   - conventional memory
		 *   - memmap_info
		 */
#define NUM_EXTRA_MEM_DESCS     4

		/* Estimate necessary efi memmap size and allocate memory */
		fw_tables_size = sizeof(*fw_tables) +
			(ia64_boot_param->efi_memmap_size /
			 ia64_boot_param->efi_memdesc_size +
			 NUM_EXTRA_MEM_DESCS) *
			sizeof(fw_tables->efi_memmap[0]);
		if (fw_tables_size <
		    FW_TABLES_END_PADDR_MIN - FW_TABLES_BASE_PADDR)
			fw_tables_size =
			    FW_TABLES_END_PADDR_MIN - FW_TABLES_BASE_PADDR;
		fw_tables_size = (fw_tables_size + ((1UL << EFI_PAGE_SHIFT) - 1))
			& ~((1UL << EFI_PAGE_SHIFT) - 1);
		fw_tables =
		    (struct fw_tables *)_xmalloc(fw_tables_size,
						 __alignof__(*fw_tables));
		if (fw_tables == NULL) {
			dprintk(XENLOG_INFO,
				"can't allocate fw_tables memory size = %ld\n",
				fw_tables_size);
			return -ENOMEM;
		}
		memset(fw_tables, 0, fw_tables_size);
		BUILD_BUG_ON(FW_END_PADDR_MIN != FW_TABLES_END_PADDR_MIN);
		fw_tables->fw_tables_size = fw_tables_size;
		fw_tables->fw_end_paddr = FW_TABLES_BASE_PADDR + fw_tables_size;
		fw_tables->fw_tables_end_paddr =
			FW_TABLES_BASE_PADDR + fw_tables_size;
		fw_tables->num_mds = 0;

		/* It is necessary to allocate pages before dom_fw_init()
		 * dom_fw_init() uses up page to d->max_pages.
		 */
		for (gpaddr = FW_TABLES_BASE_PADDR;
		     gpaddr < fw_tables->fw_end_paddr; gpaddr += PAGE_SIZE)
			assign_new_domain_page_if_dom0(d, gpaddr);

		ret = dom_fw_init(d, d->arch.breakimm, bp,
				  fw_tables, imva_hypercall_base, maxmem);
		if (ret < 0) {
			xfree(fw_tables);
			return ret;
		}

		ret = platform_fw_init(d, bp, fw_tables);
		if (ret < 0) {
			xfree(fw_tables);
			return ret;
		}

		if (sizeof(*fw_tables) +
		    fw_tables->num_mds * sizeof(fw_tables->efi_memmap[0]) >
		    fw_tables_size) {
			panic("EFI memmap too large. "
			      "Increase NUM_EXTRA_MEM_DESCS.\n"
			      "fw_table_size %ld > %ld num_mds %ld "
			      "NUM_EXTRA_MEM_DESCS %d.\n",
			      fw_tables_size, fw_tables->fw_tables_size,
			      fw_tables->num_mds, NUM_EXTRA_MEM_DESCS);
		}
		fw_tables_size = sizeof(*fw_tables) +
			fw_tables->num_mds * sizeof(fw_tables->efi_memmap[0]);

		/* clear domain builder internal use member */
		fw_tables->fw_tables_size = 0;
		fw_tables->fw_end_paddr = 0;
		fw_tables->fw_tables_end_paddr = 0;
		fw_tables->num_mds = 0;

		/* copy fw_tables into domain pseudo physical address space */
		dom_fw_copy_to(d, FW_TABLES_BASE_PADDR, fw_tables,
			       fw_tables_size);
		xfree(fw_tables);
	}

	dom_fw_domain_init(d, domain_mpa_to_imva(d, FW_TABLES_BASE_PADDR));
	return dom_fw_set_convmem_end(d);
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
