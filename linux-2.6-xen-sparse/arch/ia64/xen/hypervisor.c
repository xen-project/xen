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
#include <asm/page.h>
#include <asm/hypervisor.h>
#include <asm/hypercall.h>

#define XEN_IA64_BALLOON_IS_NOT_YET
#ifndef XEN_IA64_BALLOON_IS_NOT_YET
#include <xen/balloon.h>
#else
#define balloon_lock(flags)	((void)flags)
#define balloon_unlock(flags)	((void)flags)
#endif


//XXX same as i386, x86_64 contiguous_bitmap_set(), contiguous_bitmap_clear()
// move those to lib/contiguous_bitmap?
//XXX discontigmem/sparsemem

/*
 * Bitmap is indexed by page number. If bit is set, the page is part of a
 * xen_create_contiguous_region() area of memory.
 */
unsigned long *contiguous_bitmap;

void
contiguous_bitmap_init(unsigned long end_pfn)
{
	unsigned long size = (end_pfn + 2 * BITS_PER_LONG) >> 3;
	contiguous_bitmap = alloc_bootmem_low_pages(size);
	BUG_ON(!contiguous_bitmap);
	memset(contiguous_bitmap, 0, size);
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

/* Ensure multi-page extents are contiguous in machine memory. */
int
__xen_create_contiguous_region(unsigned long vstart,
			       unsigned int order, unsigned int address_bits)
{
	unsigned long error = 0;
	unsigned long gphys = __pa(vstart);
	unsigned long start_gpfn = gphys >> PAGE_SHIFT;
	unsigned long num_pfn = 1 << order;
	unsigned long i;
	unsigned long flags;

	scrub_pages(vstart, 1 << order);

	balloon_lock(flags);

	//XXX order
	for (i = 0; i < num_pfn; i++) {
		error = HYPERVISOR_zap_physmap(start_gpfn + i, 0);
		if (error) {
			goto out;
		}
	}

	error = HYPERVISOR_populate_physmap(start_gpfn, order, address_bits);
	contiguous_bitmap_set(start_gpfn, 1UL << order);
#if 0
	{
	unsigned long mfn;
	unsigned long mfn_prev = ~0UL;
	for (i = 0; i < 1 << order; i++) {
		mfn = pfn_to_mfn_for_dma(start_gpfn + i);
		if (mfn_prev != ~0UL && mfn != mfn_prev + 1) {
			xprintk("\n");
			xprintk("%s:%d order %d "
				"start 0x%lx bus 0x%lx machine 0x%lx\n",
				__func__, __LINE__, order,
				vstart, virt_to_bus((void*)vstart),
				phys_to_machine_for_dma(gphys));
			xprintk("mfn: ");
			for (i = 0; i < 1 << order; i++) {
				mfn = pfn_to_mfn_for_dma(start_gpfn + i);
				xprintk("0x%lx ", mfn);
			}
			xprintk("\n");
			goto out;
		}
		mfn_prev = mfn;
	}
	}
#endif
out:
	balloon_unlock(flags);
	return error;
}

void
__xen_destroy_contiguous_region(unsigned long vstart, unsigned int order)
{
	unsigned long error = 0;
	unsigned long gphys = __pa(vstart);
	unsigned long start_gpfn = gphys >> PAGE_SHIFT;
	unsigned long num_pfn = 1 << order;
	unsigned long i;
	unsigned long flags;

	scrub_pages(vstart, 1 << order);

	balloon_lock(flags);

	contiguous_bitmap_clear(start_gpfn, 1UL << order);

	//XXX order
	for (i = 0; i < num_pfn; i++) {
		error = HYPERVISOR_zap_physmap(start_gpfn + i, 0);
		if (error) {
			goto out;
		}
	}

	for (i = 0; i < num_pfn; i++) {
		error = HYPERVISOR_populate_physmap(start_gpfn + i, 0, 0);
		if (error) {
			goto out;
		}
	}

out:
	balloon_unlock(flags);
	if (error) {
		//XXX
	}
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
	if (flags & GNTMAP_readonly) {
#if 0
		xprintd("GNTMAP_readonly is not supported yet\n");
#endif
		flags &= ~GNTMAP_readonly;
	}

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

	return ____HYPERVISOR_grant_table_op(cmd, uop, count);
}


///////////////////////////////////////////////////////////////////////////
//XXX taken from balloon.c
//    temporal hack until balloon driver support.
#include <linux/module.h>

struct page *balloon_alloc_empty_page_range(unsigned long nr_pages)
{
	unsigned long vstart;
	unsigned int  order = get_order(nr_pages * PAGE_SIZE);

	vstart = __get_free_pages(GFP_KERNEL, order);
	if (vstart == 0)
		return NULL;

	return virt_to_page(vstart);
}

void balloon_dealloc_empty_page_range(
	struct page *page, unsigned long nr_pages)
{
	__free_pages(page, get_order(nr_pages * PAGE_SIZE));
}

void balloon_update_driver_allowance(long delta)
{
}

EXPORT_SYMBOL(balloon_alloc_empty_page_range);
EXPORT_SYMBOL(balloon_dealloc_empty_page_range);
EXPORT_SYMBOL(balloon_update_driver_allowance);


///////////////////////////////////////////////////////////////////////////
// PageForeign(), SetPageForeign(), ClearPageForeign()

struct address_space xen_ia64_foreign_dummy_mapping;

