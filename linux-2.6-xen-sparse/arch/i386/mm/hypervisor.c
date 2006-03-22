/******************************************************************************
 * mm/hypervisor.c
 * 
 * Update page tables via the hypervisor.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/hypervisor.h>
#include <xen/balloon.h>
#include <xen/features.h>
#include <xen/interface/memory.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_X86_64
#define pmd_val_ma(v) (v).pmd
#else
#ifdef CONFIG_X86_PAE
# define pmd_val_ma(v) ((v).pmd)
# define pud_val_ma(v) ((v).pgd.pgd)
#else
# define pmd_val_ma(v) ((v).pud.pgd.pgd)
#endif
#endif

void xen_l1_entry_update(pte_t *ptr, pte_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = pte_val_ma(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

void xen_l2_entry_update(pmd_t *ptr, pmd_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = pmd_val_ma(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

#ifdef CONFIG_X86_PAE
void xen_l3_entry_update(pud_t *ptr, pud_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = pud_val_ma(val);
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
#endif

#ifdef CONFIG_X86_64
void xen_l3_entry_update(pud_t *ptr, pud_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = val.pud;
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

void xen_l4_entry_update(pgd_t *ptr, pgd_t val)
{
	mmu_update_t u;
	u.ptr = virt_to_machine(ptr);
	u.val = val.pgd;
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}
#endif /* CONFIG_X86_64 */

void xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
	mmu_update_t u;
	if (xen_feature(XENFEAT_auto_translated_physmap)) {
		BUG_ON(pfn != mfn);
		return;
	}
	u.ptr = ((unsigned long long)mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
	u.val = pfn;
	BUG_ON(HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF) < 0);
}

void xen_pt_switch(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_NEW_BASEPTR;
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_new_user_pt(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_NEW_USER_BASEPTR;
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_tlb_flush(void)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_TLB_FLUSH_LOCAL;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_invlpg(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_INVLPG_LOCAL;
	op.arg1.linear_addr = ptr & PAGE_MASK;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

#ifdef CONFIG_SMP

void xen_tlb_flush_all(void)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_TLB_FLUSH_ALL;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_tlb_flush_mask(cpumask_t *mask)
{
	struct mmuext_op op;
	if ( cpus_empty(*mask) )
		return;
	op.cmd = MMUEXT_TLB_FLUSH_MULTI;
	op.arg2.vcpumask = mask->bits;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_invlpg_all(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_INVLPG_ALL;
	op.arg1.linear_addr = ptr & PAGE_MASK;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_invlpg_mask(cpumask_t *mask, unsigned long ptr)
{
	struct mmuext_op op;
	if ( cpus_empty(*mask) )
		return;
	op.cmd = MMUEXT_INVLPG_MULTI;
	op.arg1.linear_addr = ptr & PAGE_MASK;
	op.arg2.vcpumask    = mask->bits;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

#endif /* CONFIG_SMP */

void xen_pgd_pin(unsigned long ptr)
{
	struct mmuext_op op;
#ifdef CONFIG_X86_64
	op.cmd = MMUEXT_PIN_L4_TABLE;
#elif defined(CONFIG_X86_PAE)
	op.cmd = MMUEXT_PIN_L3_TABLE;
#else
	op.cmd = MMUEXT_PIN_L2_TABLE;
#endif
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_pgd_unpin(unsigned long ptr)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_UNPIN_TABLE;
	op.arg1.mfn = pfn_to_mfn(ptr >> PAGE_SHIFT);
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

void xen_set_ldt(unsigned long ptr, unsigned long len)
{
	struct mmuext_op op;
	op.cmd = MMUEXT_SET_LDT;
	op.arg1.linear_addr = ptr;
	op.arg2.nr_ents     = len;
	BUG_ON(HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF) < 0);
}

/*
 * Bitmap is indexed by page number. If bit is set, the page is part of a
 * xen_create_contiguous_region() area of memory.
 */
unsigned long *contiguous_bitmap;

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
int xen_create_contiguous_region(
	unsigned long vstart, unsigned int order, unsigned int address_bits)
{
	pgd_t         *pgd; 
	pud_t         *pud; 
	pmd_t         *pmd;
	pte_t         *pte;
	unsigned long  frame, i, flags;
	struct xen_memory_reservation reservation = {
		.extent_start = &frame,
		.nr_extents   = 1,
		.extent_order = 0,
		.domid        = DOMID_SELF
	};

	/*
	 * Currently an auto-translated guest will not perform I/O, nor will
	 * it require PAE page directories below 4GB. Therefore any calls to
	 * this function are redundant and can be ignored.
	 */
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return 0;

	scrub_pages(vstart, 1 << order);

	balloon_lock(flags);

	/* 1. Zap current PTEs, giving away the underlying pages. */
	for (i = 0; i < (1<<order); i++) {
		pgd = pgd_offset_k(vstart + (i*PAGE_SIZE));
		pud = pud_offset(pgd, (vstart + (i*PAGE_SIZE)));
		pmd = pmd_offset(pud, (vstart + (i*PAGE_SIZE)));
		pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
		frame = pte_mfn(*pte);
		BUG_ON(HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE), __pte_ma(0), 0));
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i,
			INVALID_P2M_ENTRY);
		BUG_ON(HYPERVISOR_memory_op(
			XENMEM_decrease_reservation, &reservation) != 1);
	}

	/* 2. Get a new contiguous memory extent. */
	reservation.extent_order = order;
	reservation.address_bits = address_bits;
	frame = __pa(vstart) >> PAGE_SHIFT;
	if (HYPERVISOR_memory_op(XENMEM_populate_physmap,
				 &reservation) != 1)
		goto fail;

	/* 3. Map the new extent in place of old pages. */
	for (i = 0; i < (1<<order); i++) {
		BUG_ON(HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE),
			pfn_pte_ma(frame+i, PAGE_KERNEL), 0));
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i, frame+i);
	}

	flush_tlb_all();

	contiguous_bitmap_set(__pa(vstart) >> PAGE_SHIFT, 1UL << order);

	balloon_unlock(flags);

	return 0;

 fail:
	reservation.extent_order = 0;
	reservation.address_bits = 0;

	for (i = 0; i < (1<<order); i++) {
		frame = (__pa(vstart) >> PAGE_SHIFT) + i;
		BUG_ON(HYPERVISOR_memory_op(
			XENMEM_populate_physmap, &reservation) != 1);
		BUG_ON(HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE),
			pfn_pte_ma(frame, PAGE_KERNEL), 0));
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i, frame);
	}

	flush_tlb_all();

	balloon_unlock(flags);

	return -ENOMEM;
}

void xen_destroy_contiguous_region(unsigned long vstart, unsigned int order)
{
	pgd_t         *pgd; 
	pud_t         *pud; 
	pmd_t         *pmd;
	pte_t         *pte;
	unsigned long  frame, i, flags;
	struct xen_memory_reservation reservation = {
		.extent_start = &frame,
		.nr_extents   = 1,
		.extent_order = 0,
		.domid        = DOMID_SELF
	};

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return;

	scrub_pages(vstart, 1 << order);

	balloon_lock(flags);

	contiguous_bitmap_clear(__pa(vstart) >> PAGE_SHIFT, 1UL << order);

	/* 1. Zap current PTEs, giving away the underlying pages. */
	for (i = 0; i < (1<<order); i++) {
		pgd = pgd_offset_k(vstart + (i*PAGE_SIZE));
		pud = pud_offset(pgd, (vstart + (i*PAGE_SIZE)));
		pmd = pmd_offset(pud, (vstart + (i*PAGE_SIZE)));
		pte = pte_offset_kernel(pmd, (vstart + (i*PAGE_SIZE)));
		frame = pte_mfn(*pte);
		BUG_ON(HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE), __pte_ma(0), 0));
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i,
			INVALID_P2M_ENTRY);
		BUG_ON(HYPERVISOR_memory_op(
			XENMEM_decrease_reservation, &reservation) != 1);
	}

	/* 2. Map new pages in place of old pages. */
	for (i = 0; i < (1<<order); i++) {
		frame = (__pa(vstart) >> PAGE_SHIFT) + i;
		BUG_ON(HYPERVISOR_memory_op(
			XENMEM_populate_physmap, &reservation) != 1);
		BUG_ON(HYPERVISOR_update_va_mapping(
			vstart + (i*PAGE_SIZE),
			pfn_pte_ma(frame, PAGE_KERNEL), 0));
		set_phys_to_machine((__pa(vstart)>>PAGE_SHIFT)+i, frame);
	}

	flush_tlb_all();

	balloon_unlock(flags);
}

#ifdef __i386__
int write_ldt_entry(void *ldt, int entry, __u32 entry_a, __u32 entry_b)
{
	__u32 *lp = (__u32 *)((char *)ldt + entry * 8);
	maddr_t mach_lp = arbitrary_virt_to_machine(lp);
	return HYPERVISOR_update_descriptor(
		mach_lp, (u64)entry_a | ((u64)entry_b<<32));
}
#endif

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
