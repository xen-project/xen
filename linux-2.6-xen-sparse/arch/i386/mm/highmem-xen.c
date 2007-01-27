#include <linux/highmem.h>
#include <linux/module.h>

void *kmap(struct page *page)
{
	might_sleep();
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}

void kunmap(struct page *page)
{
	if (in_interrupt())
		BUG();
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}

/*
 * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
 * no global lock is needed and because the kmap code must perform a global TLB
 * invalidation when the kmap pool wraps.
 *
 * However when holding an atomic kmap is is not legal to sleep, so atomic
 * kmaps are appropriate for short, tight code paths only.
 */
static void *__kmap_atomic(struct page *page, enum km_type type, pgprot_t prot)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	/* even !CONFIG_PREEMPT needs this, for in_atomic in do_page_fault */
	inc_preempt_count();
	if (!PageHighMem(page))
		return page_address(page);

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
#ifdef CONFIG_DEBUG_HIGHMEM
	if (!pte_none(*(kmap_pte-idx)))
		BUG();
#endif
	set_pte_at_sync(&init_mm, vaddr, kmap_pte-idx, mk_pte(page, prot));

	return (void*) vaddr;
}

void *kmap_atomic(struct page *page, enum km_type type)
{
	return __kmap_atomic(page, type, kmap_prot);
}

/* Same as kmap_atomic but with PAGE_KERNEL_RO page protection. */
void *kmap_atomic_pte(struct page *page, enum km_type type)
{
	return __kmap_atomic(page, type,
	                     test_bit(PG_pinned, &page->flags)
	                     ? PAGE_KERNEL_RO : kmap_prot);
}

void kunmap_atomic(void *kvaddr, enum km_type type)
{
#if defined(CONFIG_DEBUG_HIGHMEM) || defined(CONFIG_XEN)
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	enum fixed_addresses idx = type + KM_TYPE_NR*smp_processor_id();

	if (vaddr < FIXADDR_START) { // FIXME
		dec_preempt_count();
		preempt_check_resched();
		return;
	}
#endif

#if defined(CONFIG_DEBUG_HIGHMEM)
	if (vaddr != __fix_to_virt(FIX_KMAP_BEGIN+idx))
		BUG();

	/*
	 * force other mappings to Oops if they'll try to access
	 * this pte without first remap it
	 */
	pte_clear(&init_mm, vaddr, kmap_pte-idx);
	__flush_tlb_one(vaddr);
#elif defined(CONFIG_XEN)
	/*
	 * We must ensure there are no dangling pagetable references when
	 * returning memory to Xen (decrease_reservation).
	 * XXX TODO: We could make this faster by only zapping when
	 * kmap_flush_unused is called but that is trickier and more invasive.
	 */
	pte_clear(&init_mm, vaddr, kmap_pte-idx);
#endif

	dec_preempt_count();
	preempt_check_resched();
}

/* This is the same as kmap_atomic() but can map memory that doesn't
 * have a struct page associated with it.
 */
void *kmap_atomic_pfn(unsigned long pfn, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	inc_preempt_count();

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	set_pte(kmap_pte-idx, pfn_pte(pfn, kmap_prot));
	__flush_tlb_one(vaddr);

	return (void*) vaddr;
}

struct page *kmap_atomic_to_page(void *ptr)
{
	unsigned long idx, vaddr = (unsigned long)ptr;
	pte_t *pte;

	if (vaddr < FIXADDR_START)
		return virt_to_page(ptr);

	idx = virt_to_fix(vaddr);
	pte = kmap_pte - (idx - FIX_KMAP_BEGIN);
	return pte_page(*pte);
}

EXPORT_SYMBOL(kmap);
EXPORT_SYMBOL(kunmap);
EXPORT_SYMBOL(kmap_atomic);
EXPORT_SYMBOL(kmap_atomic_pte);
EXPORT_SYMBOL(kunmap_atomic);
EXPORT_SYMBOL(kmap_atomic_to_page);
