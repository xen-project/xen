/*
 *  linux/arch/i386/mm/pgtable.c
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/module.h>

#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>

#include <xen/features.h>
#include <xen/foreign_page.h>
#include <asm/hypervisor.h>

static void pgd_test_and_unpin(pgd_t *pgd);

void show_mem(void)
{
	int total = 0, reserved = 0;
	int shared = 0, cached = 0;
	int highmem = 0;
	struct page *page;
	pg_data_t *pgdat;
	unsigned long i;
	struct page_state ps;
	unsigned long flags;

	printk(KERN_INFO "Mem-info:\n");
	show_free_areas();
	printk(KERN_INFO "Free swap:       %6ldkB\n", nr_swap_pages<<(PAGE_SHIFT-10));
	for_each_pgdat(pgdat) {
		pgdat_resize_lock(pgdat, &flags);
		for (i = 0; i < pgdat->node_spanned_pages; ++i) {
			page = pgdat_page_nr(pgdat, i);
			total++;
			if (PageHighMem(page))
				highmem++;
			if (PageReserved(page))
				reserved++;
			else if (PageSwapCache(page))
				cached++;
			else if (page_count(page))
				shared += page_count(page) - 1;
		}
		pgdat_resize_unlock(pgdat, &flags);
	}
	printk(KERN_INFO "%d pages of RAM\n", total);
	printk(KERN_INFO "%d pages of HIGHMEM\n", highmem);
	printk(KERN_INFO "%d reserved pages\n", reserved);
	printk(KERN_INFO "%d pages shared\n", shared);
	printk(KERN_INFO "%d pages swap cached\n", cached);

	get_page_state(&ps);
	printk(KERN_INFO "%lu pages dirty\n", ps.nr_dirty);
	printk(KERN_INFO "%lu pages writeback\n", ps.nr_writeback);
	printk(KERN_INFO "%lu pages mapped\n", ps.nr_mapped);
	printk(KERN_INFO "%lu pages slab\n", ps.nr_slab);
	printk(KERN_INFO "%lu pages pagetables\n", ps.nr_page_table_pages);
}

/*
 * Associate a virtual page frame with a given physical page frame 
 * and protection flags for that frame.
 */ 
static void set_pte_pfn(unsigned long vaddr, unsigned long pfn, pgprot_t flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = swapper_pg_dir + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		BUG();
		return;
	}
	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud)) {
		BUG();
		return;
	}
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		BUG();
		return;
	}
	pte = pte_offset_kernel(pmd, vaddr);
	/* <pfn,flags> stored as-is, to permit clearing entries */
	set_pte(pte, pfn_pte(pfn, flags));

	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

/*
 * Associate a virtual page frame with a given physical page frame 
 * and protection flags for that frame.
 */ 
static void set_pte_pfn_ma(unsigned long vaddr, unsigned long pfn,
			   pgprot_t flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = swapper_pg_dir + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		BUG();
		return;
	}
	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud)) {
		BUG();
		return;
	}
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		BUG();
		return;
	}
	pte = pte_offset_kernel(pmd, vaddr);
	/* <pfn,flags> stored as-is, to permit clearing entries */
	set_pte(pte, pfn_pte_ma(pfn, flags));

	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

/*
 * Associate a large virtual page frame with a given physical page frame 
 * and protection flags for that frame. pfn is for the base of the page,
 * vaddr is what the page gets mapped to - both must be properly aligned. 
 * The pmd must already be instantiated. Assumes PAE mode.
 */ 
void set_pmd_pfn(unsigned long vaddr, unsigned long pfn, pgprot_t flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	if (vaddr & (PMD_SIZE-1)) {		/* vaddr is misaligned */
		printk(KERN_WARNING "set_pmd_pfn: vaddr misaligned\n");
		return; /* BUG(); */
	}
	if (pfn & (PTRS_PER_PTE-1)) {		/* pfn is misaligned */
		printk(KERN_WARNING "set_pmd_pfn: pfn misaligned\n");
		return; /* BUG(); */
	}
	pgd = swapper_pg_dir + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		printk(KERN_WARNING "set_pmd_pfn: pgd_none\n");
		return; /* BUG(); */
	}
	pud = pud_offset(pgd, vaddr);
	pmd = pmd_offset(pud, vaddr);
	set_pmd(pmd, pfn_pmd(pfn, flags));
	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

static int nr_fixmaps = 0;
unsigned long __FIXADDR_TOP = (HYPERVISOR_VIRT_START - 2 * PAGE_SIZE);
EXPORT_SYMBOL(__FIXADDR_TOP);

void __set_fixmap (enum fixed_addresses idx, maddr_t phys, pgprot_t flags)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}
	switch (idx) {
	case FIX_WP_TEST:
#ifdef CONFIG_X86_F00F_BUG
	case FIX_F00F_IDT:
#endif
		set_pte_pfn(address, phys >> PAGE_SHIFT, flags);
		break;
	default:
		set_pte_pfn_ma(address, phys >> PAGE_SHIFT, flags);
		break;
	}
	nr_fixmaps++;
}

void set_fixaddr_top(unsigned long top)
{
	BUG_ON(nr_fixmaps > 0);
	__FIXADDR_TOP = top - PAGE_SIZE;
}

pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	pte_t *pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
	if (pte)
		make_lowmem_page_readonly(pte, XENFEAT_writable_page_tables);
	return pte;
}

struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

#ifdef CONFIG_HIGHPTE
	pte = alloc_pages(GFP_KERNEL|__GFP_HIGHMEM|__GFP_REPEAT|__GFP_ZERO, 0);
#else
	pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
	if (pte) {
		SetPageForeign(pte, pte_free);
		set_page_count(pte, 1);
	}
#endif
	return pte;
}

void pte_free(struct page *pte)
{
	unsigned long va = (unsigned long)__va(page_to_pfn(pte)<<PAGE_SHIFT);

	if (!pte_write(*virt_to_ptep(va)))
		BUG_ON(HYPERVISOR_update_va_mapping(
			va, pfn_pte(page_to_pfn(pte), PAGE_KERNEL), 0));

	ClearPageForeign(pte);
	set_page_count(pte, 1);

	__free_page(pte);
}

void pmd_ctor(void *pmd, kmem_cache_t *cache, unsigned long flags)
{
	memset(pmd, 0, PTRS_PER_PMD*sizeof(pmd_t));
}

/*
 * List of all pgd's needed for non-PAE so it can invalidate entries
 * in both cached and uncached pgd's; not needed for PAE since the
 * kernel pmd is shared. If PAE were not to share the pmd a similar
 * tactic would be needed. This is essentially codepath-based locking
 * against pageattr.c; it is the unique case in which a valid change
 * of kernel pagetables can't be lazily synchronized by vmalloc faults.
 * vmalloc faults work because attached pagetables are never freed.
 * The locking scheme was chosen on the basis of manfred's
 * recommendations and having no core impact whatsoever.
 * -- wli
 */
DEFINE_SPINLOCK(pgd_lock);
struct page *pgd_list;

static inline void pgd_list_add(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);
	page->index = (unsigned long)pgd_list;
	if (pgd_list)
		set_page_private(pgd_list, (unsigned long)&page->index);
	pgd_list = page;
	set_page_private(page, (unsigned long)&pgd_list);
}

static inline void pgd_list_del(pgd_t *pgd)
{
	struct page *next, **pprev, *page = virt_to_page(pgd);
	next = (struct page *)page->index;
	pprev = (struct page **)page_private(page);
	*pprev = next;
	if (next)
		set_page_private(next, (unsigned long)pprev);
}

void pgd_ctor(void *pgd, kmem_cache_t *cache, unsigned long unused)
{
	unsigned long flags;

	if (PTRS_PER_PMD > 1) {
		if (!xen_feature(XENFEAT_pae_pgdir_above_4gb)) {
			int rc = xen_create_contiguous_region(
				(unsigned long)pgd, 0, 32);
			BUG_ON(rc);
		}
		if (HAVE_SHARED_KERNEL_PMD)
			memcpy((pgd_t *)pgd + USER_PTRS_PER_PGD,
			       swapper_pg_dir + USER_PTRS_PER_PGD,
			       (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
	} else {
		spin_lock_irqsave(&pgd_lock, flags);
		memcpy((pgd_t *)pgd + USER_PTRS_PER_PGD,
		       swapper_pg_dir + USER_PTRS_PER_PGD,
		       (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
		memset(pgd, 0, USER_PTRS_PER_PGD*sizeof(pgd_t));
		pgd_list_add(pgd);
		spin_unlock_irqrestore(&pgd_lock, flags);
	}
}

void pgd_dtor(void *pgd, kmem_cache_t *cache, unsigned long unused)
{
	unsigned long flags; /* can be called from interrupt context */

	if (PTRS_PER_PMD > 1) {
		if (!xen_feature(XENFEAT_pae_pgdir_above_4gb))
			xen_destroy_contiguous_region((unsigned long)pgd, 0);
	} else {
		spin_lock_irqsave(&pgd_lock, flags);
		pgd_list_del(pgd);
		spin_unlock_irqrestore(&pgd_lock, flags);

		pgd_test_and_unpin(pgd);
	}
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	int i;
	pgd_t *pgd = kmem_cache_alloc(pgd_cache, GFP_KERNEL);

	pgd_test_and_unpin(pgd);

	if (PTRS_PER_PMD == 1 || !pgd)
		return pgd;

	for (i = 0; i < USER_PTRS_PER_PGD; ++i) {
		pmd_t *pmd = kmem_cache_alloc(pmd_cache, GFP_KERNEL);
		if (!pmd)
			goto out_oom;
		set_pgd(&pgd[i], __pgd(1 + __pa(pmd)));
	}

	if (!HAVE_SHARED_KERNEL_PMD) {
		unsigned long flags;

		for (i = USER_PTRS_PER_PGD; i < PTRS_PER_PGD; i++) {
			pmd_t *pmd = kmem_cache_alloc(pmd_cache, GFP_KERNEL);
			if (!pmd)
				goto out_oom;
			set_pgd(&pgd[USER_PTRS_PER_PGD], __pgd(1 + __pa(pmd)));
		}

		spin_lock_irqsave(&pgd_lock, flags);
		for (i = USER_PTRS_PER_PGD; i < PTRS_PER_PGD; i++) {
			unsigned long v = (unsigned long)i << PGDIR_SHIFT;
			pgd_t *kpgd = pgd_offset_k(v);
			pud_t *kpud = pud_offset(kpgd, v);
			pmd_t *kpmd = pmd_offset(kpud, v);
			pmd_t *pmd = (void *)__va(pgd_val(pgd[i])-1);
			memcpy(pmd, kpmd, PAGE_SIZE);
			make_lowmem_page_readonly(
				pmd, XENFEAT_writable_page_tables);
		}
		pgd_list_add(pgd);
		spin_unlock_irqrestore(&pgd_lock, flags);
	}

	return pgd;

out_oom:
	for (i--; i >= 0; i--)
		kmem_cache_free(pmd_cache, (void *)__va(pgd_val(pgd[i])-1));
	kmem_cache_free(pgd_cache, pgd);
	return NULL;
}

void pgd_free(pgd_t *pgd)
{
	int i;

	pgd_test_and_unpin(pgd);

	/* in the PAE case user pgd entries are overwritten before usage */
	if (PTRS_PER_PMD > 1) {
		for (i = 0; i < USER_PTRS_PER_PGD; ++i) {
			pmd_t *pmd = (void *)__va(pgd_val(pgd[i])-1);
			kmem_cache_free(pmd_cache, pmd);
		}
		if (!HAVE_SHARED_KERNEL_PMD) {
			unsigned long flags;
			spin_lock_irqsave(&pgd_lock, flags);
			pgd_list_del(pgd);
			spin_unlock_irqrestore(&pgd_lock, flags);
			for (i = USER_PTRS_PER_PGD; i < PTRS_PER_PGD; i++) {
				pmd_t *pmd = (void *)__va(pgd_val(pgd[i])-1);
				make_lowmem_page_writable(
					pmd, XENFEAT_writable_page_tables);
				memset(pmd, 0, PTRS_PER_PMD*sizeof(pmd_t));
				kmem_cache_free(pmd_cache, pmd);
			}
		}
	}
	/* in the non-PAE case, free_pgtables() clears user pgd entries */
	kmem_cache_free(pgd_cache, pgd);
}

void make_lowmem_page_readonly(void *va, unsigned int feature)
{
	pte_t *pte;
	int rc;

	if (xen_feature(feature))
		return;

	pte = virt_to_ptep(va);
	rc = HYPERVISOR_update_va_mapping(
		(unsigned long)va, pte_wrprotect(*pte), 0);
	BUG_ON(rc);
}

void make_lowmem_page_writable(void *va, unsigned int feature)
{
	pte_t *pte;
	int rc;

	if (xen_feature(feature))
		return;

	pte = virt_to_ptep(va);
	rc = HYPERVISOR_update_va_mapping(
		(unsigned long)va, pte_mkwrite(*pte), 0);
	BUG_ON(rc);
}

void make_page_readonly(void *va, unsigned int feature)
{
	pte_t *pte;
	int rc;

	if (xen_feature(feature))
		return;

	pte = virt_to_ptep(va);
	rc = HYPERVISOR_update_va_mapping(
		(unsigned long)va, pte_wrprotect(*pte), 0);
	if (rc) /* fallback? */
		xen_l1_entry_update(pte, pte_wrprotect(*pte));
	if ((unsigned long)va >= (unsigned long)high_memory) {
		unsigned long pfn = pte_pfn(*pte);
#ifdef CONFIG_HIGHMEM
		if (pfn >= highstart_pfn)
			kmap_flush_unused(); /* flush stale writable kmaps */
		else
#endif
			make_lowmem_page_readonly(
				phys_to_virt(pfn << PAGE_SHIFT), feature); 
	}
}

void make_page_writable(void *va, unsigned int feature)
{
	pte_t *pte;
	int rc;

	if (xen_feature(feature))
		return;

	pte = virt_to_ptep(va);
	rc = HYPERVISOR_update_va_mapping(
		(unsigned long)va, pte_mkwrite(*pte), 0);
	if (rc) /* fallback? */
		xen_l1_entry_update(pte, pte_mkwrite(*pte));
	if ((unsigned long)va >= (unsigned long)high_memory) {
		unsigned long pfn = pte_pfn(*pte); 
#ifdef CONFIG_HIGHMEM
		if (pfn < highstart_pfn)
#endif
			make_lowmem_page_writable(
				phys_to_virt(pfn << PAGE_SHIFT), feature);
	}
}

void make_pages_readonly(void *va, unsigned int nr, unsigned int feature)
{
	if (xen_feature(feature))
		return;

	while (nr-- != 0) {
		make_page_readonly(va, feature);
		va = (void *)((unsigned long)va + PAGE_SIZE);
	}
}

void make_pages_writable(void *va, unsigned int nr, unsigned int feature)
{
	if (xen_feature(feature))
		return;

	while (nr-- != 0) {
		make_page_writable(va, feature);
		va = (void *)((unsigned long)va + PAGE_SIZE);
	}
}

static inline void pgd_walk_set_prot(void *pt, pgprot_t flags)
{
	struct page *page = virt_to_page(pt);
	unsigned long pfn = page_to_pfn(page);

	if (PageHighMem(page))
		return;
	BUG_ON(HYPERVISOR_update_va_mapping(
		(unsigned long)__va(pfn << PAGE_SHIFT),
		pfn_pte(pfn, flags), 0));
}

static void pgd_walk(pgd_t *pgd_base, pgprot_t flags)
{
	pgd_t *pgd = pgd_base;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int    g, u, m;

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return;

	for (g = 0; g < USER_PTRS_PER_PGD; g++, pgd++) {
		if (pgd_none(*pgd))
			continue;
		pud = pud_offset(pgd, 0);
		if (PTRS_PER_PUD > 1) /* not folded */
			pgd_walk_set_prot(pud,flags);
		for (u = 0; u < PTRS_PER_PUD; u++, pud++) {
			if (pud_none(*pud))
				continue;
			pmd = pmd_offset(pud, 0);
			if (PTRS_PER_PMD > 1) /* not folded */
				pgd_walk_set_prot(pmd,flags);
			for (m = 0; m < PTRS_PER_PMD; m++, pmd++) {
				if (pmd_none(*pmd))
					continue;
				pte = pte_offset_kernel(pmd,0);
				pgd_walk_set_prot(pte,flags);
			}
		}
	}

	BUG_ON(HYPERVISOR_update_va_mapping(
		(unsigned long)pgd_base,
		pfn_pte(virt_to_phys(pgd_base)>>PAGE_SHIFT, flags),
		UVMF_TLB_FLUSH));
}

static void __pgd_pin(pgd_t *pgd)
{
	pgd_walk(pgd, PAGE_KERNEL_RO);
	xen_pgd_pin(__pa(pgd));
	set_bit(PG_pinned, &virt_to_page(pgd)->flags);
}

static void __pgd_unpin(pgd_t *pgd)
{
	xen_pgd_unpin(__pa(pgd));
	pgd_walk(pgd, PAGE_KERNEL);
	clear_bit(PG_pinned, &virt_to_page(pgd)->flags);
}

static void pgd_test_and_unpin(pgd_t *pgd)
{
	if (test_bit(PG_pinned, &virt_to_page(pgd)->flags))
		__pgd_unpin(pgd);
}

void mm_pin(struct mm_struct *mm)
{
	if (xen_feature(XENFEAT_writable_page_tables))
	    return;
	spin_lock(&mm->page_table_lock);
	__pgd_pin(mm->pgd);
	spin_unlock(&mm->page_table_lock);
}

void mm_unpin(struct mm_struct *mm)
{
	if (xen_feature(XENFEAT_writable_page_tables))
	    return;
	spin_lock(&mm->page_table_lock);
	__pgd_unpin(mm->pgd);
	spin_unlock(&mm->page_table_lock);
}

void mm_pin_all(void)
{
	struct page *page;
	if (xen_feature(XENFEAT_writable_page_tables))
	    return;
	for (page = pgd_list; page; page = (struct page *)page->index) {
		if (!test_bit(PG_pinned, &page->flags))
			__pgd_pin((pgd_t *)page_address(page));
	}
}

void _arch_exit_mmap(struct mm_struct *mm)
{
	struct task_struct *tsk = current;

	task_lock(tsk);

	/*
	 * We aggressively remove defunct pgd from cr3. We execute unmap_vmas()
	 * *much* faster this way, as no tlb flushes means bigger wrpt batches.
	 */
	if (tsk->active_mm == mm) {
		tsk->active_mm = &init_mm;
		atomic_inc(&init_mm.mm_count);

		switch_mm(mm, &init_mm, tsk);

		atomic_dec(&mm->mm_count);
		BUG_ON(atomic_read(&mm->mm_count) == 0);
	}

	task_unlock(tsk);

	if (test_bit(PG_pinned, &virt_to_page(mm->pgd)->flags) &&
	    (atomic_read(&mm->mm_count) == 1))
		mm_unpin(mm);
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
