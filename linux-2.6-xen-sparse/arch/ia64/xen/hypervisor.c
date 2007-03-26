/******************************************************************************
 * include/asm-ia64/shadow.h
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
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

//#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/efi.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/meminit.h>
#include <asm/hypervisor.h>
#include <asm/hypercall.h>
#include <xen/interface/memory.h>
#include <xen/balloon.h>

shared_info_t *HYPERVISOR_shared_info = (shared_info_t *)XSI_BASE;
EXPORT_SYMBOL(HYPERVISOR_shared_info);

start_info_t *xen_start_info;
EXPORT_SYMBOL(xen_start_info);

int running_on_xen;
EXPORT_SYMBOL(running_on_xen);

#ifdef CONFIG_XEN_IA64_EXPOSE_P2M
static int p2m_expose_init(void);
#else
#define p2m_expose_init() (-ENOSYS)
#endif

EXPORT_SYMBOL(__hypercall);

//XXX same as i386, x86_64 contiguous_bitmap_set(), contiguous_bitmap_clear()
// move those to lib/contiguous_bitmap?
//XXX discontigmem/sparsemem

/*
 * Bitmap is indexed by page number. If bit is set, the page is part of a
 * xen_create_contiguous_region() area of memory.
 */
unsigned long *contiguous_bitmap;

#ifdef CONFIG_VIRTUAL_MEM_MAP
/* Following logic is stolen from create_mem_map_table() for virtual memmap */
static int
create_contiguous_bitmap(u64 start, u64 end, void *arg)
{
	unsigned long address, start_page, end_page;
	unsigned long bitmap_start, bitmap_end;
	unsigned char *bitmap;
	int node;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	bitmap_start = (unsigned long)contiguous_bitmap +
	               ((__pa(start) >> PAGE_SHIFT) >> 3);
	bitmap_end = (unsigned long)contiguous_bitmap +
	             (((__pa(end) >> PAGE_SHIFT) + 2 * BITS_PER_LONG) >> 3);

	start_page = bitmap_start & PAGE_MASK;
	end_page = PAGE_ALIGN(bitmap_end);
	node = paddr_to_nid(__pa(start));

	bitmap = alloc_bootmem_pages_node(NODE_DATA(node),
	                                  end_page - start_page);
	BUG_ON(!bitmap);
	memset(bitmap, 0, end_page - start_page);

	for (address = start_page; address < end_page; address += PAGE_SIZE) {
		pgd = pgd_offset_k(address);
		if (pgd_none(*pgd))
			pgd_populate(&init_mm, pgd,
			             alloc_bootmem_pages_node(NODE_DATA(node),
			                                      PAGE_SIZE));
		pud = pud_offset(pgd, address);

		if (pud_none(*pud))
			pud_populate(&init_mm, pud,
			             alloc_bootmem_pages_node(NODE_DATA(node),
			                                      PAGE_SIZE));
		pmd = pmd_offset(pud, address);

		if (pmd_none(*pmd))
			pmd_populate_kernel(&init_mm, pmd,
			                    alloc_bootmem_pages_node
			                    (NODE_DATA(node), PAGE_SIZE));
		pte = pte_offset_kernel(pmd, address);

		if (pte_none(*pte))
			set_pte(pte,
			        pfn_pte(__pa(bitmap + (address - start_page))
			                >> PAGE_SHIFT, PAGE_KERNEL));
	}
	return 0;
}
#endif

static void
__contiguous_bitmap_init(unsigned long size)
{
	contiguous_bitmap = alloc_bootmem_pages(size);
	BUG_ON(!contiguous_bitmap);
	memset(contiguous_bitmap, 0, size);
}

void
contiguous_bitmap_init(unsigned long end_pfn)
{
	unsigned long size = (end_pfn + 2 * BITS_PER_LONG) >> 3;
#ifndef CONFIG_VIRTUAL_MEM_MAP
	__contiguous_bitmap_init(size);
#else
	unsigned long max_gap = 0;

	efi_memmap_walk(find_largest_hole, (u64*)&max_gap);
	if (max_gap < LARGE_GAP) {
		__contiguous_bitmap_init(size);
	} else {
		unsigned long map_size = PAGE_ALIGN(size);
		vmalloc_end -= map_size;
		contiguous_bitmap = (unsigned long*)vmalloc_end;
		efi_memmap_walk(create_contiguous_bitmap, NULL);
	}
#endif
}

#if 0
int
contiguous_bitmap_test(void* p)
{
	return test_bit(__pa(p) >> PAGE_SHIFT, contiguous_bitmap);
}
#endif

static void contiguous_bitmap_set(
	unsigned long first_page, unsigned long nr_pages)
{
	unsigned long start_off, end_off, curr_idx, end_idx;

	curr_idx  = first_page / BITS_PER_LONG;
	start_off = first_page & (BITS_PER_LONG-1);
	end_idx   = (first_page + nr_pages) / BITS_PER_LONG;
	end_off   = (first_page + nr_pages) & (BITS_PER_LONG-1);

	if (curr_idx == end_idx) {
		contiguous_bitmap[curr_idx] |=
			((1UL<<end_off)-1) & -(1UL<<start_off);
	} else {
		contiguous_bitmap[curr_idx] |= -(1UL<<start_off);
		while ( ++curr_idx < end_idx )
			contiguous_bitmap[curr_idx] = ~0UL;
		contiguous_bitmap[curr_idx] |= (1UL<<end_off)-1;
	}
}

static void contiguous_bitmap_clear(
	unsigned long first_page, unsigned long nr_pages)
{
	unsigned long start_off, end_off, curr_idx, end_idx;

	curr_idx  = first_page / BITS_PER_LONG;
	start_off = first_page & (BITS_PER_LONG-1);
	end_idx   = (first_page + nr_pages) / BITS_PER_LONG;
	end_off   = (first_page + nr_pages) & (BITS_PER_LONG-1);

	if (curr_idx == end_idx) {
		contiguous_bitmap[curr_idx] &=
			-(1UL<<end_off) | ((1UL<<start_off)-1);
	} else {
		contiguous_bitmap[curr_idx] &= (1UL<<start_off)-1;
		while ( ++curr_idx != end_idx )
			contiguous_bitmap[curr_idx] = 0;
		contiguous_bitmap[curr_idx] &= -(1UL<<end_off);
	}
}

// __xen_create_contiguous_region(), __xen_destroy_contiguous_region()
// are based on i386 xen_create_contiguous_region(),
// xen_destroy_contiguous_region()

/* Protected by balloon_lock. */
#define MAX_CONTIG_ORDER 7
static unsigned long discontig_frames[1<<MAX_CONTIG_ORDER];

/* Ensure multi-page extents are contiguous in machine memory. */
int
__xen_create_contiguous_region(unsigned long vstart,
			       unsigned int order, unsigned int address_bits)
{
	unsigned long error = 0;
	unsigned long gphys = __pa(vstart);
	unsigned long start_gpfn = gphys >> PAGE_SHIFT;
	unsigned long num_gpfn = 1 << order;
	unsigned long i;
	unsigned long flags;

	unsigned long *in_frames = discontig_frames, out_frame;
	int success;
	struct xen_memory_exchange exchange = {
		.in = {
			.nr_extents   = num_gpfn,
			.extent_order = 0,
			.domid        = DOMID_SELF
		},
		.out = {
			 .nr_extents   = 1,
			 .extent_order = order,
			 .address_bits = address_bits,
			 .domid        = DOMID_SELF
		 },
		.nr_exchanged = 0
	};

	if (unlikely(order > MAX_CONTIG_ORDER))
		return -ENOMEM;
	
	set_xen_guest_handle(exchange.in.extent_start, in_frames);
	set_xen_guest_handle(exchange.out.extent_start, &out_frame);

	scrub_pages(vstart, num_gpfn);

	balloon_lock(flags);

	/* Get a new contiguous memory extent. */
	for (i = 0; i < num_gpfn; i++) {
		in_frames[i] = start_gpfn + i;
	}
	out_frame = start_gpfn;
	error = HYPERVISOR_memory_op(XENMEM_exchange, &exchange);
	success = (exchange.nr_exchanged == num_gpfn);
	BUG_ON(!success && ((exchange.nr_exchanged != 0) || (error == 0)));
	BUG_ON(success && (error != 0));
	if (unlikely(error == -ENOSYS)) {
		/* Compatibility when XENMEM_exchange is unsupported. */
		error = HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					     &exchange.in);
		BUG_ON(error != num_gpfn);
		error = HYPERVISOR_memory_op(XENMEM_populate_physmap,
					     &exchange.out);
		if (error != 1) {
			/* Couldn't get special memory: fall back to normal. */
			for (i = 0; i < num_gpfn; i++) {
				in_frames[i] = start_gpfn + i;
			}
			error = HYPERVISOR_memory_op(XENMEM_populate_physmap,
						     &exchange.in);
			BUG_ON(error != num_gpfn);
			success = 0;
		} else
			success = 1;
	}
	if (success)
		contiguous_bitmap_set(start_gpfn, num_gpfn);
#if 0
	if (success) {
		unsigned long mfn;
		unsigned long mfn_prev = ~0UL;
		for (i = 0; i < num_gpfn; i++) {
			mfn = pfn_to_mfn_for_dma(start_gpfn + i);
			if (mfn_prev != ~0UL && mfn != mfn_prev + 1) {
				xprintk("\n");
				xprintk("%s:%d order %d "
					"start 0x%lx bus 0x%lx "
					"machine 0x%lx\n",
					__func__, __LINE__, order,
					vstart, virt_to_bus((void*)vstart),
					phys_to_machine_for_dma(gphys));
				xprintk("mfn: ");
				for (i = 0; i < num_gpfn; i++) {
					mfn = pfn_to_mfn_for_dma(
						start_gpfn + i);
					xprintk("0x%lx ", mfn);
				}
				xprintk("\n");
				break;
			}
			mfn_prev = mfn;
		}
	}
#endif
	balloon_unlock(flags);
	return success? 0: -ENOMEM;
}

void
__xen_destroy_contiguous_region(unsigned long vstart, unsigned int order)
{
	unsigned long flags;
	unsigned long error = 0;
	unsigned long start_gpfn = __pa(vstart) >> PAGE_SHIFT;
	unsigned long num_gpfn = 1UL << order;
	unsigned long i;

	unsigned long *out_frames = discontig_frames, in_frame;
	int            success;
	struct xen_memory_exchange exchange = {
		.in = {
			.nr_extents   = 1,
			.extent_order = order,
			.domid        = DOMID_SELF
		},
		.out = {
			 .nr_extents   = num_gpfn,
			 .extent_order = 0,
			 .address_bits = 0,
			 .domid        = DOMID_SELF
		 },
		.nr_exchanged = 0
        };
	

	if (!test_bit(start_gpfn, contiguous_bitmap))
		return;

	if (unlikely(order > MAX_CONTIG_ORDER))
		return;

	set_xen_guest_handle(exchange.in.extent_start, &in_frame);
	set_xen_guest_handle(exchange.out.extent_start, out_frames);

	scrub_pages(vstart, num_gpfn);

	balloon_lock(flags);

	contiguous_bitmap_clear(start_gpfn, num_gpfn);

        /* Do the exchange for non-contiguous MFNs. */
	in_frame = start_gpfn;
	for (i = 0; i < num_gpfn; i++) {
		out_frames[i] = start_gpfn + i;
	}
	error = HYPERVISOR_memory_op(XENMEM_exchange, &exchange);
	success = (exchange.nr_exchanged == 1);
	BUG_ON(!success && ((exchange.nr_exchanged != 0) || (error == 0)));
	BUG_ON(success && (error != 0));
	if (unlikely(error == -ENOSYS)) {
                /* Compatibility when XENMEM_exchange is unsupported. */
		error = HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					     &exchange.in);
		BUG_ON(error != 1);

		error = HYPERVISOR_memory_op(XENMEM_populate_physmap,
					     &exchange.out);
		BUG_ON(error != num_gpfn);
	}
	balloon_unlock(flags);
}


///////////////////////////////////////////////////////////////////////////
// grant table hack
// cmd: GNTTABOP_xxx

#include <linux/mm.h>
#include <xen/interface/xen.h>
#include <xen/gnttab.h>

static void
gnttab_map_grant_ref_pre(struct gnttab_map_grant_ref *uop)
{
	uint32_t flags;

	flags = uop->flags;

	if (flags & GNTMAP_host_map) {
		if (flags & GNTMAP_application_map) {
			xprintd("GNTMAP_application_map is not supported yet: flags 0x%x\n", flags);
			BUG();
		}
		if (flags & GNTMAP_contains_pte) {
			xprintd("GNTMAP_contains_pte is not supported yet flags 0x%x\n", flags);
			BUG();
		}
	} else if (flags & GNTMAP_device_map) {
		xprintd("GNTMAP_device_map is not supported yet 0x%x\n", flags);
		BUG();//XXX not yet. actually this flag is not used.
	} else {
		BUG();
	}
}

int
HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count)
{
	if (cmd == GNTTABOP_map_grant_ref) {
		unsigned int i;
		for (i = 0; i < count; i++) {
			gnttab_map_grant_ref_pre(
				(struct gnttab_map_grant_ref*)uop + i);
		}
	}
	return xencomm_mini_hypercall_grant_table_op(cmd, uop, count);
}
EXPORT_SYMBOL(HYPERVISOR_grant_table_op);

///////////////////////////////////////////////////////////////////////////
// foreign mapping
#include <linux/efi.h>
#include <asm/meminit.h> // for IA64_GRANULE_SIZE, GRANULEROUND{UP,DOWN}()

static unsigned long privcmd_resource_min = 0;
// Xen/ia64 currently can handle pseudo physical address bits up to
// (PAGE_SHIFT * 3)
static unsigned long privcmd_resource_max = GRANULEROUNDDOWN((1UL << (PAGE_SHIFT * 3)) - 1);
static unsigned long privcmd_resource_align = IA64_GRANULE_SIZE;

static unsigned long
md_end_addr(const efi_memory_desc_t *md)
{
	return md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);
}

#define XEN_IA64_PRIVCMD_LEAST_GAP_SIZE	(1024 * 1024 * 1024UL)
static int
xen_ia64_privcmd_check_size(unsigned long start, unsigned long end)
{
	return (start < end &&
		(end - start) > XEN_IA64_PRIVCMD_LEAST_GAP_SIZE);
}

static int __init
xen_ia64_privcmd_init(void)
{
	void *efi_map_start, *efi_map_end, *p;
	u64 efi_desc_size;
	efi_memory_desc_t *md;
	unsigned long tmp_min;
	unsigned long tmp_max;
	unsigned long gap_size;
	unsigned long prev_end;

	if (!is_running_on_xen())
		return -1;

	efi_map_start = __va(ia64_boot_param->efi_memmap);
	efi_map_end   = efi_map_start + ia64_boot_param->efi_memmap_size;
	efi_desc_size = ia64_boot_param->efi_memdesc_size;

	// at first check the used highest address
	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
		// nothing
	}
	md = p - efi_desc_size;
	privcmd_resource_min = GRANULEROUNDUP(md_end_addr(md));
	if (xen_ia64_privcmd_check_size(privcmd_resource_min,
					privcmd_resource_max)) {
		goto out;
	}

	// the used highest address is too large. try to find the largest gap.
	tmp_min = privcmd_resource_max;
	tmp_max = 0;
	gap_size = 0;
	prev_end = 0;
	for (p = efi_map_start;
	     p < efi_map_end - efi_desc_size;
	     p += efi_desc_size) {
		unsigned long end;
		efi_memory_desc_t* next;
		unsigned long next_start;

		md = p;
		end = md_end_addr(md);
		if (end > privcmd_resource_max) {
			break;
		}
		if (end < prev_end) {
			// work around. 
			// Xen may pass incompletely sorted memory
			// descriptors like
			// [x, x + length]
			// [x, x]
			// this order should be reversed.
			continue;
		}
		next = p + efi_desc_size;
		next_start = next->phys_addr;
		if (next_start > privcmd_resource_max) {
			next_start = privcmd_resource_max;
		}
		if (end < next_start && gap_size < (next_start - end)) {
			tmp_min = end;
			tmp_max = next_start;
			gap_size = tmp_max - tmp_min;
		}
		prev_end = end;
	}

	privcmd_resource_min = GRANULEROUNDUP(tmp_min);
	if (xen_ia64_privcmd_check_size(privcmd_resource_min, tmp_max)) {
		privcmd_resource_max = tmp_max;
		goto out;
	}

	privcmd_resource_min = tmp_min;
	privcmd_resource_max = tmp_max;
	if (!xen_ia64_privcmd_check_size(privcmd_resource_min,
					 privcmd_resource_max)) {
		// Any large enough gap isn't found.
		// go ahead anyway with the warning hoping that large region
		// won't be requested.
		printk(KERN_WARNING "xen privcmd: large enough region for privcmd mmap is not found.\n");
	}

out:
	printk(KERN_INFO "xen privcmd uses pseudo physical addr range [0x%lx, 0x%lx] (%ldMB)\n",
	       privcmd_resource_min, privcmd_resource_max, 
	       (privcmd_resource_max - privcmd_resource_min) >> 20);
	BUG_ON(privcmd_resource_min >= privcmd_resource_max);

	// XXX this should be somewhere appropriate
	(void)p2m_expose_init();

	return 0;
}
late_initcall(xen_ia64_privcmd_init);

struct xen_ia64_privcmd_entry {
	atomic_t	map_count;
#define INVALID_GPFN	(~0UL)
	unsigned long	gpfn;
};

struct xen_ia64_privcmd_range {
	atomic_t			ref_count;
	unsigned long			pgoff; // in PAGE_SIZE
	struct resource*		res;

	unsigned long			num_entries;
	struct xen_ia64_privcmd_entry	entries[0];
};

struct xen_ia64_privcmd_vma {
	int				is_privcmd_mmapped;
	struct xen_ia64_privcmd_range*	range;

	unsigned long			num_entries;
	struct xen_ia64_privcmd_entry*	entries;
};

static void
xen_ia64_privcmd_init_entry(struct xen_ia64_privcmd_entry* entry)
{
	atomic_set(&entry->map_count, 0);
	entry->gpfn = INVALID_GPFN;
}

static int
xen_ia64_privcmd_entry_mmap(struct vm_area_struct* vma,
			    unsigned long addr,
			    struct xen_ia64_privcmd_range* privcmd_range,
			    int i,
			    unsigned long gmfn,
			    pgprot_t prot,
			    domid_t domid)
{
	int error = 0;
	struct xen_ia64_privcmd_entry* entry = &privcmd_range->entries[i];
	unsigned long gpfn;
	unsigned long flags;

	if ((addr & ~PAGE_MASK) != 0 || gmfn == INVALID_MFN) {
		error = -EINVAL;
		goto out;
	}

	if (entry->gpfn != INVALID_GPFN) {
		error = -EBUSY;
		goto out;
	}
	gpfn = (privcmd_range->res->start >> PAGE_SHIFT) + i;

	flags = ASSIGN_writable;
	if (pgprot_val(prot) == PROT_READ) {
		flags = ASSIGN_readonly;
	}
	error = HYPERVISOR_add_physmap_with_gmfn(gpfn, gmfn, flags, domid);
	if (error != 0) {
		goto out;
	}

	prot = vma->vm_page_prot;
	error = remap_pfn_range(vma, addr, gpfn, 1 << PAGE_SHIFT, prot);
	if (error != 0) {
		error = HYPERVISOR_zap_physmap(gpfn, 0);
		if (error) {
			BUG();//XXX
		}
	} else {
		atomic_inc(&entry->map_count);
		entry->gpfn = gpfn;
	}

out:
	return error;
}

static void
xen_ia64_privcmd_entry_munmap(struct xen_ia64_privcmd_range* privcmd_range,
			      int i)
{
	struct xen_ia64_privcmd_entry* entry = &privcmd_range->entries[i];
	unsigned long gpfn = entry->gpfn;
	//gpfn = (privcmd_range->res->start >> PAGE_SHIFT) +
	//	(vma->vm_pgoff - privcmd_range->pgoff);
	int error;

	error = HYPERVISOR_zap_physmap(gpfn, 0);
	if (error) {
		BUG();//XXX
	}
	entry->gpfn = INVALID_GPFN;
}

static void
xen_ia64_privcmd_entry_open(struct xen_ia64_privcmd_range* privcmd_range,
			    int i)
{
	struct xen_ia64_privcmd_entry* entry = &privcmd_range->entries[i];
	if (entry->gpfn != INVALID_GPFN) {
		atomic_inc(&entry->map_count);
	} else {
		BUG_ON(atomic_read(&entry->map_count) != 0);
	}
}

static void
xen_ia64_privcmd_entry_close(struct xen_ia64_privcmd_range* privcmd_range,
			     int i)
{
	struct xen_ia64_privcmd_entry* entry = &privcmd_range->entries[i];
	if (entry->gpfn != INVALID_GPFN &&
	    atomic_dec_and_test(&entry->map_count)) {
		xen_ia64_privcmd_entry_munmap(privcmd_range, i);
	}
}

static void xen_ia64_privcmd_vma_open(struct vm_area_struct* vma);
static void xen_ia64_privcmd_vma_close(struct vm_area_struct* vma);

struct vm_operations_struct xen_ia64_privcmd_vm_ops = {
	.open = &xen_ia64_privcmd_vma_open,
	.close = &xen_ia64_privcmd_vma_close,
};

static void
__xen_ia64_privcmd_vma_open(struct vm_area_struct* vma,
			    struct xen_ia64_privcmd_vma* privcmd_vma,
			    struct xen_ia64_privcmd_range* privcmd_range)
{
	unsigned long entry_offset = vma->vm_pgoff - privcmd_range->pgoff;
	unsigned long num_entries = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	unsigned long i;

	BUG_ON(entry_offset < 0);
	BUG_ON(entry_offset + num_entries > privcmd_range->num_entries);

	privcmd_vma->range = privcmd_range;
	privcmd_vma->num_entries = num_entries;
	privcmd_vma->entries = &privcmd_range->entries[entry_offset];
	vma->vm_private_data = privcmd_vma;
	for (i = 0; i < privcmd_vma->num_entries; i++) {
		xen_ia64_privcmd_entry_open(privcmd_range, entry_offset + i);
	}

	vma->vm_private_data = privcmd_vma;
	vma->vm_ops = &xen_ia64_privcmd_vm_ops;
}

static void
xen_ia64_privcmd_vma_open(struct vm_area_struct* vma)
{
	struct xen_ia64_privcmd_vma* old_privcmd_vma = (struct xen_ia64_privcmd_vma*)vma->vm_private_data;
	struct xen_ia64_privcmd_vma* privcmd_vma = (struct xen_ia64_privcmd_vma*)vma->vm_private_data;
	struct xen_ia64_privcmd_range* privcmd_range = privcmd_vma->range;

	atomic_inc(&privcmd_range->ref_count);
	// vm_op->open() can't fail.
	privcmd_vma = kmalloc(sizeof(*privcmd_vma), GFP_KERNEL | __GFP_NOFAIL);
	// copy original value if necessary
	privcmd_vma->is_privcmd_mmapped = old_privcmd_vma->is_privcmd_mmapped;

	__xen_ia64_privcmd_vma_open(vma, privcmd_vma, privcmd_range);
}

static void
xen_ia64_privcmd_vma_close(struct vm_area_struct* vma)
{
	struct xen_ia64_privcmd_vma* privcmd_vma =
		(struct xen_ia64_privcmd_vma*)vma->vm_private_data;
	struct xen_ia64_privcmd_range* privcmd_range = privcmd_vma->range;
	unsigned long entry_offset = vma->vm_pgoff - privcmd_range->pgoff;
	unsigned long i;

	for (i = 0; i < privcmd_vma->num_entries; i++) {
		xen_ia64_privcmd_entry_close(privcmd_range, entry_offset + i);
	}
	vma->vm_private_data = NULL;
	kfree(privcmd_vma);

	if (atomic_dec_and_test(&privcmd_range->ref_count)) {
#if 1
		for (i = 0; i < privcmd_range->num_entries; i++) {
			struct xen_ia64_privcmd_entry* entry =
				&privcmd_range->entries[i];
			BUG_ON(atomic_read(&entry->map_count) != 0);
			BUG_ON(entry->gpfn != INVALID_GPFN);
		}
#endif
		release_resource(privcmd_range->res);
		kfree(privcmd_range->res);
		vfree(privcmd_range);
	}
}

int
privcmd_enforce_singleshot_mapping(struct vm_area_struct *vma)
{
	struct xen_ia64_privcmd_vma* privcmd_vma =
		(struct xen_ia64_privcmd_vma *)vma->vm_private_data;
	return (xchg(&privcmd_vma->is_privcmd_mmapped, 1) == 0);
}

int
privcmd_mmap(struct file * file, struct vm_area_struct * vma)
{
	int error;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long num_entries = size >> PAGE_SHIFT;
	struct xen_ia64_privcmd_range* privcmd_range = NULL;
	struct xen_ia64_privcmd_vma* privcmd_vma = NULL;
	struct resource* res = NULL;
	unsigned long i;
	BUG_ON(!is_running_on_xen());

	BUG_ON(file->private_data != NULL);

	error = -ENOMEM;
	privcmd_range =
		vmalloc(sizeof(*privcmd_range) +
			sizeof(privcmd_range->entries[0]) * num_entries);
	if (privcmd_range == NULL) {
		goto out_enomem0;
	}
	privcmd_vma = kmalloc(sizeof(*privcmd_vma), GFP_KERNEL);
	if (privcmd_vma == NULL) {
		goto out_enomem1;
	}
	privcmd_vma->is_privcmd_mmapped = 0;

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (res == NULL) {
		goto out_enomem1;
	}
	res->name = "Xen privcmd mmap";
	error = allocate_resource(&iomem_resource, res, size,
				  privcmd_resource_min, privcmd_resource_max,
				  privcmd_resource_align, NULL, NULL);
	if (error) {
		goto out_enomem1;
	}
	privcmd_range->res = res;

	/* DONTCOPY is essential for Xen as copy_page_range is broken. */
	vma->vm_flags |= VM_RESERVED | VM_IO | VM_DONTCOPY | VM_PFNMAP;

	atomic_set(&privcmd_range->ref_count, 1);
	privcmd_range->pgoff = vma->vm_pgoff;
	privcmd_range->num_entries = num_entries;
	for (i = 0; i < privcmd_range->num_entries; i++) {
		xen_ia64_privcmd_init_entry(&privcmd_range->entries[i]);
	}

	__xen_ia64_privcmd_vma_open(vma, privcmd_vma, privcmd_range);
	return 0;

out_enomem1:
	kfree(res);
	kfree(privcmd_vma);
out_enomem0:
	vfree(privcmd_range);
	return error;
}

int
direct_remap_pfn_range(struct vm_area_struct *vma,
		       unsigned long address,	// process virtual address
		       unsigned long gmfn,	// gmfn, gmfn + 1, ... gmfn + size/PAGE_SIZE
		       unsigned long size,
		       pgprot_t prot,
		       domid_t  domid)		// target domain
{
	struct xen_ia64_privcmd_vma* privcmd_vma =
		(struct xen_ia64_privcmd_vma*)vma->vm_private_data;
	struct xen_ia64_privcmd_range* privcmd_range = privcmd_vma->range;
	unsigned long entry_offset = vma->vm_pgoff - privcmd_range->pgoff;

	unsigned long i;
	unsigned long offset;
	int error = 0;
	BUG_ON(!is_running_on_xen());

#if 0
	if (prot != vm->vm_page_prot) {
		return -EINVAL;
	}
#endif

	i = (address - vma->vm_start) >> PAGE_SHIFT;
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		error = xen_ia64_privcmd_entry_mmap(vma, (address + offset) & PAGE_MASK, privcmd_range, entry_offset + i, gmfn, prot, domid);
		if (error != 0) {
			break;
		}

		i++;
		gmfn++;
        }

	return error;
}


/* Called after suspend, to resume time.  */
void
time_resume(void)
{
	extern void ia64_cpu_local_tick(void);

	/* Just trigger a tick.  */
	ia64_cpu_local_tick();
}

///////////////////////////////////////////////////////////////////////////
// expose p2m table
#ifdef CONFIG_XEN_IA64_EXPOSE_P2M
#include <linux/cpu.h>
#include <asm/uaccess.h>

int p2m_initialized __read_mostly = 0;

unsigned long p2m_min_low_pfn __read_mostly;
unsigned long p2m_max_low_pfn __read_mostly;
unsigned long p2m_convert_min_pfn __read_mostly;
unsigned long p2m_convert_max_pfn __read_mostly;

static struct resource p2m_resource = {
	.name    = "Xen p2m table",
	.flags   = IORESOURCE_MEM,
};
static unsigned long p2m_assign_start_pfn __read_mostly;
static unsigned long p2m_assign_end_pfn __read_mostly;
volatile const pte_t* p2m_pte __read_mostly;

#define GRNULE_PFN	PTRS_PER_PTE
static unsigned long p2m_granule_pfn __read_mostly = GRNULE_PFN;

#define ROUNDDOWN(x, y)  ((x) & ~((y) - 1))
#define ROUNDUP(x, y)    (((x) + (y) - 1) & ~((y) - 1))

#define P2M_PREFIX	"Xen p2m: "

static int xen_ia64_p2m_expose __read_mostly = 1;
module_param(xen_ia64_p2m_expose, int, 0);
MODULE_PARM_DESC(xen_ia64_p2m_expose,
                 "enable/disable xen/ia64 p2m exposure optimization\n");

#ifdef CONFIG_XEN_IA64_EXPOSE_P2M_USE_DTR
static int xen_ia64_p2m_expose_use_dtr __read_mostly = 1;
module_param(xen_ia64_p2m_expose_use_dtr, int, 0);
MODULE_PARM_DESC(xen_ia64_p2m_expose_use_dtr,
                 "use/unuse dtr to map exposed p2m table\n");

static const int p2m_page_shifts[] = {
	_PAGE_SIZE_4K,
	_PAGE_SIZE_8K,
	_PAGE_SIZE_16K,
	_PAGE_SIZE_64K,
	_PAGE_SIZE_256K,
	_PAGE_SIZE_1M,
	_PAGE_SIZE_4M,
	_PAGE_SIZE_16M,
	_PAGE_SIZE_64M,
	_PAGE_SIZE_256M,
};

struct p2m_itr_arg {
	unsigned long vaddr;
	unsigned long pteval;
	unsigned long log_page_size;
};
static struct p2m_itr_arg p2m_itr_arg __read_mostly;

// This should be in asm-ia64/kregs.h
#define IA64_TR_P2M_TABLE	3

static void
p2m_itr(void* info)
{
	struct p2m_itr_arg* arg = (struct p2m_itr_arg*)info;
	ia64_itr(0x2, IA64_TR_P2M_TABLE,
	         arg->vaddr, arg->pteval, arg->log_page_size);
	ia64_srlz_d();
}

static int
p2m_expose_dtr_call(struct notifier_block *self,
                    unsigned long event, void* ptr)
{
	unsigned int cpu = (unsigned int)(long)ptr;
	if (event != CPU_ONLINE)
		return 0;
	if (!(p2m_initialized && xen_ia64_p2m_expose_use_dtr))
		smp_call_function_single(cpu, &p2m_itr, &p2m_itr_arg, 1, 1);
	return 0;
}

static struct notifier_block p2m_expose_dtr_hotplug_notifier = {
	.notifier_call = p2m_expose_dtr_call,
	.next          = NULL,
	.priority      = 0
};
#endif

static int
p2m_expose_init(void)
{
	unsigned long num_pfn;
	unsigned long size = 0;
	unsigned long p2m_size = 0;
	unsigned long align = ~0UL;
	int error = 0;
#ifdef CONFIG_XEN_IA64_EXPOSE_P2M_USE_DTR
	int i;
	unsigned long page_size;
	unsigned long log_page_size = 0;
#endif

	if (!xen_ia64_p2m_expose)
		return -ENOSYS;
	if (p2m_initialized)
		return 0;

#ifdef CONFIG_XEN_IA64_EXPOSE_P2M_USE_DTR
	error = register_cpu_notifier(&p2m_expose_dtr_hotplug_notifier);
	if (error < 0)
		return error;
#endif

	lock_cpu_hotplug();
	if (p2m_initialized)
		goto out;

#ifdef CONFIG_DISCONTIGMEM
	p2m_min_low_pfn = min_low_pfn;
	p2m_max_low_pfn = max_low_pfn;
#else
	p2m_min_low_pfn = 0;
	p2m_max_low_pfn = max_pfn;
#endif

#ifdef CONFIG_XEN_IA64_EXPOSE_P2M_USE_DTR
	if (xen_ia64_p2m_expose_use_dtr) {
		unsigned long granule_pfn = 0;
		p2m_size = p2m_max_low_pfn - p2m_min_low_pfn;
		for (i = 0;
		     i < sizeof(p2m_page_shifts)/sizeof(p2m_page_shifts[0]);
		     i++) {
			log_page_size = p2m_page_shifts[i];
			page_size = 1UL << log_page_size;
			if (page_size < p2m_size)
				continue;

			granule_pfn = max(page_size >> PAGE_SHIFT,
			                  p2m_granule_pfn);
			p2m_convert_min_pfn = ROUNDDOWN(p2m_min_low_pfn,
			                                granule_pfn);
			p2m_convert_max_pfn = ROUNDUP(p2m_max_low_pfn,
			                              granule_pfn);
			num_pfn = p2m_convert_max_pfn - p2m_convert_min_pfn;
			size = num_pfn << PAGE_SHIFT;
			p2m_size = num_pfn / PTRS_PER_PTE;
			p2m_size = ROUNDUP(p2m_size, granule_pfn << PAGE_SHIFT);
			if (p2m_size == page_size)
				break;
		}
		if (p2m_size != page_size) {
			printk(KERN_ERR "p2m_size != page_size\n");
			error = -EINVAL;
			goto out;
		}
		align = max(privcmd_resource_align, granule_pfn << PAGE_SHIFT);
	} else
#endif
	{
		BUG_ON(p2m_granule_pfn & (p2m_granule_pfn - 1));
		p2m_convert_min_pfn = ROUNDDOWN(p2m_min_low_pfn,
		                                p2m_granule_pfn);
		p2m_convert_max_pfn = ROUNDUP(p2m_max_low_pfn, p2m_granule_pfn);
		num_pfn = p2m_convert_max_pfn - p2m_convert_min_pfn;
		size = num_pfn << PAGE_SHIFT;
		p2m_size = num_pfn / PTRS_PER_PTE;
		p2m_size = ROUNDUP(p2m_size, p2m_granule_pfn << PAGE_SHIFT);
		align = max(privcmd_resource_align,
		            p2m_granule_pfn << PAGE_SHIFT);
	}
	
	// use privcmd region
	error = allocate_resource(&iomem_resource, &p2m_resource, p2m_size,
	                          privcmd_resource_min, privcmd_resource_max,
	                          align, NULL, NULL);
	if (error) {
		printk(KERN_ERR P2M_PREFIX
		       "can't allocate region for p2m exposure "
		       "[0x%016lx, 0x%016lx) 0x%016lx\n",
		       p2m_convert_min_pfn, p2m_convert_max_pfn, p2m_size);
		goto out;
	}

	p2m_assign_start_pfn = p2m_resource.start >> PAGE_SHIFT;
	p2m_assign_end_pfn = p2m_resource.end >> PAGE_SHIFT;
	
	error = HYPERVISOR_expose_p2m(p2m_convert_min_pfn,
	                              p2m_assign_start_pfn,
	                              size, p2m_granule_pfn);
	if (error) {
		printk(KERN_ERR P2M_PREFIX "failed expose p2m hypercall %d\n",
		       error);
		printk(KERN_ERR P2M_PREFIX "conv 0x%016lx assign 0x%016lx "
		       "size 0x%016lx granule 0x%016lx\n",
		       p2m_convert_min_pfn, p2m_assign_start_pfn,
		       size, p2m_granule_pfn);;
		release_resource(&p2m_resource);
		goto out;
	}
	p2m_pte = (volatile const pte_t*)pfn_to_kaddr(p2m_assign_start_pfn);
#ifdef CONFIG_XEN_IA64_EXPOSE_P2M_USE_DTR
	if (xen_ia64_p2m_expose_use_dtr) {
		p2m_itr_arg.vaddr = (unsigned long)__va(p2m_assign_start_pfn
		                                        << PAGE_SHIFT);
		p2m_itr_arg.pteval = pte_val(pfn_pte(p2m_assign_start_pfn,
		                                     PAGE_KERNEL));
		p2m_itr_arg.log_page_size = log_page_size;
		smp_mb();
		smp_call_function(&p2m_itr, &p2m_itr_arg, 1, 1);
		p2m_itr(&p2m_itr_arg);
	}
#endif	
	smp_mb();
	p2m_initialized = 1;
	printk(P2M_PREFIX "assign p2m table of [0x%016lx, 0x%016lx)\n",
	       p2m_convert_min_pfn << PAGE_SHIFT,
	       p2m_convert_max_pfn << PAGE_SHIFT);
	printk(P2M_PREFIX "to [0x%016lx, 0x%016lx) (%ld KBytes)\n",
	       p2m_assign_start_pfn << PAGE_SHIFT,
	       p2m_assign_end_pfn << PAGE_SHIFT,
	       p2m_size / 1024);
out:
	unlock_cpu_hotplug();
	return error;
}

#ifdef notyet
void
p2m_expose_cleanup(void)
{
	BUG_ON(!p2m_initialized);
#ifdef CONFIG_XEN_IA64_EXPOSE_P2M_USE_DTR
	unregister_cpu_notifier(&p2m_expose_dtr_hotplug_notifier);
#endif
	release_resource(&p2m_resource);
}
#endif

//XXX inlinize?
unsigned long
p2m_phystomach(unsigned long gpfn)
{
	volatile const pte_t* pte;
	unsigned long mfn;
	unsigned long pteval;
	
	if (!p2m_initialized ||
	    gpfn < p2m_min_low_pfn || gpfn > p2m_max_low_pfn
	    /* || !pfn_valid(gpfn) */)
		return INVALID_MFN;
	pte = p2m_pte + (gpfn - p2m_convert_min_pfn);

	mfn = INVALID_MFN;
	if (likely(__get_user(pteval, (unsigned long __user *)pte) == 0 &&
	           pte_present(__pte(pteval)) &&
	           pte_pfn(__pte(pteval)) != (INVALID_MFN >> PAGE_SHIFT)))
		mfn = (pteval & _PFN_MASK) >> PAGE_SHIFT;

	return mfn;
}

EXPORT_SYMBOL_GPL(p2m_initialized);
EXPORT_SYMBOL_GPL(p2m_min_low_pfn);
EXPORT_SYMBOL_GPL(p2m_max_low_pfn);
EXPORT_SYMBOL_GPL(p2m_convert_min_pfn);
EXPORT_SYMBOL_GPL(p2m_convert_max_pfn);
EXPORT_SYMBOL_GPL(p2m_pte);
EXPORT_SYMBOL_GPL(p2m_phystomach);
#endif

///////////////////////////////////////////////////////////////////////////
// for xenoprof

struct resource*
xen_ia64_allocate_resource(unsigned long size)
{
	struct resource* res;
	int error;
	
	res = kmalloc(sizeof(*res), GFP_KERNEL);
	if (res == NULL)
		return ERR_PTR(-ENOMEM);

	res->name = "Xen";
	res->flags = IORESOURCE_MEM;
	error = allocate_resource(&iomem_resource, res, PAGE_ALIGN(size),
	                          privcmd_resource_min, privcmd_resource_max,
	                          IA64_GRANULE_SIZE, NULL, NULL);
	if (error) {
		kfree(res);
		return ERR_PTR(error);
	}
	return res;
}
EXPORT_SYMBOL_GPL(xen_ia64_allocate_resource);

void
xen_ia64_release_resource(struct resource* res)
{
	release_resource(res);
	kfree(res);
}
EXPORT_SYMBOL_GPL(xen_ia64_release_resource);

void
xen_ia64_unmap_resource(struct resource* res)
{
	unsigned long gpfn = res->start >> PAGE_SHIFT;
	unsigned long nr_pages = (res->end - res->start) >> PAGE_SHIFT;
	unsigned long i;
	
	for (i = 0; i < nr_pages; i++) {
		int error = HYPERVISOR_zap_physmap(gpfn + i, 0);
		if (error)
			printk(KERN_ERR
			       "%s:%d zap_phsymap failed %d gpfn %lx\n",
			       __func__, __LINE__, error, gpfn + i);
	}
	xen_ia64_release_resource(res);
}
EXPORT_SYMBOL_GPL(xen_ia64_unmap_resource);
