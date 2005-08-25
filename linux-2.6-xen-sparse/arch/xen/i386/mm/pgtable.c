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

#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>

#include <asm-xen/foreign_page.h>
#include <asm-xen/hypervisor.h>

void show_mem(void)
{
	int total = 0, reserved = 0;
	int shared = 0, cached = 0;
	int highmem = 0;
	struct page *page;
	pg_data_t *pgdat;
	unsigned long i;

	printk("Mem-info:\n");
	show_free_areas();
	printk("Free swap:       %6ldkB\n", nr_swap_pages<<(PAGE_SHIFT-10));
	for_each_pgdat(pgdat) {
		for (i = 0; i < pgdat->node_spanned_pages; ++i) {
			page = pgdat->node_mem_map + i;
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
	}
	printk("%d pages of RAM\n", total);
	printk("%d pages of HIGHMEM\n",highmem);
	printk("%d reserved pages\n",reserved);
	printk("%d pages shared\n",shared);
	printk("%d pages swap cached\n",cached);
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
		printk ("set_pmd_pfn: vaddr misaligned\n");
		return; /* BUG(); */
	}
	if (pfn & (PTRS_PER_PTE-1)) {		/* pfn is misaligned */
		printk ("set_pmd_pfn: pfn misaligned\n");
		return; /* BUG(); */
	}
	pgd = swapper_pg_dir + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		printk ("set_pmd_pfn: pgd_none\n");
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

void __set_fixmap (enum fixed_addresses idx, maddr_t phys, pgprot_t flags)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}
	switch (idx) {
	case FIX_WP_TEST:
	case FIX_VSYSCALL:
#ifdef CONFIG_X86_F00F_BUG
	case FIX_F00F_IDT:
#endif
		set_pte_pfn(address, phys >> PAGE_SHIFT, flags);
		break;
	default:
		set_pte_pfn_ma(address, phys >> PAGE_SHIFT, flags);
		break;
	}
}

pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	pte_t *pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
	if (pte)
		make_page_readonly(pte);
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
		pgd_list->private = (unsigned long)&page->index;
	pgd_list = page;
	page->private = (unsigned long)&pgd_list;
}

static inline void pgd_list_del(pgd_t *pgd)
{
	struct page *next, **pprev, *page = virt_to_page(pgd);
	next = (struct page *)page->index;
	pprev = (struct page **)page->private;
	*pprev = next;
	if (next)
		next->private = (unsigned long)pprev;
}

void pgd_ctor(void *pgd, kmem_cache_t *cache, unsigned long unused)
{
	unsigned long flags;

#ifdef CONFIG_X86_PAE
	/* this gives us a page below 4GB */
	xen_create_contiguous_region((unsigned long)pgd, 0);
#endif

	if (!HAVE_SHARED_KERNEL_PMD)
		spin_lock_irqsave(&pgd_lock, flags);

	memcpy((pgd_t *)pgd + USER_PTRS_PER_PGD,
			swapper_pg_dir + USER_PTRS_PER_PGD,
			(PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));

	if (HAVE_SHARED_KERNEL_PMD)
		return;

	pgd_list_add(pgd);
	spin_unlock_irqrestore(&pgd_lock, flags);
	memset(pgd, 0, USER_PTRS_PER_PGD*sizeof(pgd_t));
}

void pgd_dtor(void *pgd, kmem_cache_t *cache, unsigned long unused)
{
	unsigned long flags; /* can be called from interrupt context */

	if (HAVE_SHARED_KERNEL_PMD)
		return;

	spin_lock_irqsave(&pgd_lock, flags);
	pgd_list_del(pgd);
	spin_unlock_irqrestore(&pgd_lock, flags);
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	int i = 0;
	pgd_t *pgd = kmem_cache_alloc(pgd_cache, GFP_KERNEL);

	if (PTRS_PER_PMD == 1 || !pgd)
		return pgd;

	if (!HAVE_SHARED_KERNEL_PMD) {
		/* alloc and copy kernel pmd */
		unsigned long flags;
		pgd_t *copy_pgd = pgd_offset_k(PAGE_OFFSET);
		pud_t *copy_pud = pud_offset(copy_pgd, PAGE_OFFSET);
		pmd_t *copy_pmd = pmd_offset(copy_pud, PAGE_OFFSET);
		pmd_t *pmd = kmem_cache_alloc(pmd_cache, GFP_KERNEL);
		if (0 == pmd)
			goto out_oom;

		spin_lock_irqsave(&pgd_lock, flags);
		memcpy(pmd, copy_pmd, PAGE_SIZE);
		spin_unlock_irqrestore(&pgd_lock, flags);
		make_page_readonly(pmd);
		set_pgd(&pgd[USER_PTRS_PER_PGD], __pgd(1 + __pa(pmd)));
	}

	/* alloc user pmds */
	for (i = 0; i < USER_PTRS_PER_PGD; ++i) {
		pmd_t *pmd = kmem_cache_alloc(pmd_cache, GFP_KERNEL);
		if (!pmd)
			goto out_oom;
		set_pgd(&pgd[i], __pgd(1 + __pa(pmd)));
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
	pte_t *ptep = virt_to_ptep(pgd);

	if (!pte_write(*ptep)) {
		xen_pgd_unpin(__pa(pgd));
		BUG_ON(HYPERVISOR_update_va_mapping(
			(unsigned long)pgd,
			pfn_pte(virt_to_phys(pgd)>>PAGE_SHIFT, PAGE_KERNEL),
			0));
	}

	/* in the PAE case user pgd entries are overwritten before usage */
	if (PTRS_PER_PMD > 1) {
		for (i = 0; i < USER_PTRS_PER_PGD; ++i) {
			pmd_t *pmd = (void *)__va(pgd_val(pgd[i])-1);
			make_page_writable(pmd);
			kmem_cache_free(pmd_cache, pmd);
		}
		if (!HAVE_SHARED_KERNEL_PMD) {
			pmd_t *pmd = (void *)__va(pgd_val(pgd[USER_PTRS_PER_PGD])-1);
			make_page_writable(pmd);
			memset(pmd, 0, PTRS_PER_PMD*sizeof(pmd_t));
			kmem_cache_free(pmd_cache, pmd);
		}
	}
	/* in the non-PAE case, free_pgtables() clears user pgd entries */
	kmem_cache_free(pgd_cache, pgd);
}

#ifndef CONFIG_XEN_SHADOW_MODE
void make_lowmem_page_readonly(void *va)
{
	pte_t *pte = virt_to_ptep(va);
	set_pte(pte, pte_wrprotect(*pte));
}

void make_lowmem_page_writable(void *va)
{
	pte_t *pte = virt_to_ptep(va);
	set_pte(pte, pte_mkwrite(*pte));
}

void make_page_readonly(void *va)
{
	pte_t *pte = virt_to_ptep(va);
	set_pte(pte, pte_wrprotect(*pte));
	if ( (unsigned long)va >= (unsigned long)high_memory )
	{
		unsigned long phys;
		phys = machine_to_phys(*(unsigned long *)pte & PAGE_MASK);
#ifdef CONFIG_HIGHMEM
		if ( (phys >> PAGE_SHIFT) < highstart_pfn )
#endif
			make_lowmem_page_readonly(phys_to_virt(phys));
	}
}

void make_page_writable(void *va)
{
	pte_t *pte = virt_to_ptep(va);
	set_pte(pte, pte_mkwrite(*pte));
	if ( (unsigned long)va >= (unsigned long)high_memory )
	{
		unsigned long phys;
		phys = machine_to_phys(*(unsigned long *)pte & PAGE_MASK);
#ifdef CONFIG_HIGHMEM
		if ( (phys >> PAGE_SHIFT) < highstart_pfn )
#endif
			make_lowmem_page_writable(phys_to_virt(phys));
	}
}

void make_pages_readonly(void *va, unsigned int nr)
{
	while ( nr-- != 0 )
	{
		make_page_readonly(va);
		va = (void *)((unsigned long)va + PAGE_SIZE);
	}
}

void make_pages_writable(void *va, unsigned int nr)
{
	while ( nr-- != 0 )
	{
		make_page_writable(va);
		va = (void *)((unsigned long)va + PAGE_SIZE);
	}
}
#endif /* CONFIG_XEN_SHADOW_MODE */

LIST_HEAD(mm_unpinned);
DEFINE_SPINLOCK(mm_unpinned_lock);

static inline void mm_walk_set_prot(void *pt, pgprot_t flags)
{
	struct page *page = virt_to_page(pt);
	unsigned long pfn = page_to_pfn(page);

	if (PageHighMem(page))
		return;
	BUG_ON(HYPERVISOR_update_va_mapping(
		(unsigned long)__va(pfn << PAGE_SHIFT),
		pfn_pte(pfn, flags), 0));
}

static void mm_walk(struct mm_struct *mm, pgprot_t flags)
{
	pgd_t       *pgd;
	pud_t       *pud;
	pmd_t       *pmd;
	pte_t       *pte;
	int          g,u,m;

	pgd = mm->pgd;
	for (g = 0; g < USER_PTRS_PER_PGD; g++, pgd++) {
		if (pgd_none(*pgd))
			continue;
		pud = pud_offset(pgd, 0);
		if (PTRS_PER_PUD > 1) /* not folded */
			mm_walk_set_prot(pud,flags);
		for (u = 0; u < PTRS_PER_PUD; u++, pud++) {
			if (pud_none(*pud))
				continue;
			pmd = pmd_offset(pud, 0);
			if (PTRS_PER_PMD > 1) /* not folded */
				mm_walk_set_prot(pmd,flags);
			for (m = 0; m < PTRS_PER_PMD; m++, pmd++) {
				if (pmd_none(*pmd))
					continue;
				pte = pte_offset_kernel(pmd,0);
				mm_walk_set_prot(pte,flags);
			}
		}
	}
}

void mm_pin(struct mm_struct *mm)
{
    spin_lock(&mm->page_table_lock);

    mm_walk(mm, PAGE_KERNEL_RO);
    BUG_ON(HYPERVISOR_update_va_mapping(
        (unsigned long)mm->pgd,
        pfn_pte(virt_to_phys(mm->pgd)>>PAGE_SHIFT, PAGE_KERNEL_RO),
        UVMF_TLB_FLUSH));
    xen_pgd_pin(__pa(mm->pgd));
    mm->context.pinned = 1;
    spin_lock(&mm_unpinned_lock);
    list_del(&mm->context.unpinned);
    spin_unlock(&mm_unpinned_lock);

    spin_unlock(&mm->page_table_lock);
}

void mm_unpin(struct mm_struct *mm)
{
    spin_lock(&mm->page_table_lock);

    xen_pgd_unpin(__pa(mm->pgd));
    BUG_ON(HYPERVISOR_update_va_mapping(
        (unsigned long)mm->pgd,
        pfn_pte(virt_to_phys(mm->pgd)>>PAGE_SHIFT, PAGE_KERNEL), 0));
    mm_walk(mm, PAGE_KERNEL);
    xen_tlb_flush();
    mm->context.pinned = 0;
    spin_lock(&mm_unpinned_lock);
    list_add(&mm->context.unpinned, &mm_unpinned);
    spin_unlock(&mm_unpinned_lock);

    spin_unlock(&mm->page_table_lock);
}

void mm_pin_all(void)
{
    while (!list_empty(&mm_unpinned))	
	mm_pin(list_entry(mm_unpinned.next, struct mm_struct,
			  context.unpinned));
}

void _arch_exit_mmap(struct mm_struct *mm)
{
    struct task_struct *tsk = current;

    task_lock(tsk);

    /*
     * We aggressively remove defunct pgd from cr3. We execute unmap_vmas()
     * *much* faster this way, as no tlb flushes means bigger wrpt batches.
     */
    if ( tsk->active_mm == mm )
    {
        tsk->active_mm = &init_mm;
        atomic_inc(&init_mm.mm_count);

        switch_mm(mm, &init_mm, tsk);

        atomic_dec(&mm->mm_count);
        BUG_ON(atomic_read(&mm->mm_count) == 0);
    }

    task_unlock(tsk);

    if ( mm->context.pinned && (atomic_read(&mm->mm_count) == 1) )
        mm_unpin(mm);
}
