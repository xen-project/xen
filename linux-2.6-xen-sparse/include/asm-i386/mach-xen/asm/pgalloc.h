#ifndef _I386_PGALLOC_H
#define _I386_PGALLOC_H

#include <asm/fixmap.h>
#include <linux/threads.h>
#include <linux/mm.h>		/* for struct page */
#include <asm/io.h>		/* for phys_to_virt and page_to_pseudophys */

#define pmd_populate_kernel(mm, pmd, pte) \
		set_pmd(pmd, __pmd(_PAGE_TABLE + __pa(pte)))

#define pmd_populate(mm, pmd, pte) 					\
do {									\
	unsigned long pfn = page_to_pfn(pte);				\
	if (test_bit(PG_pinned, &virt_to_page((mm)->pgd)->flags)) {	\
		if (!PageHighMem(pte))					\
			BUG_ON(HYPERVISOR_update_va_mapping(		\
			  (unsigned long)__va(pfn << PAGE_SHIFT),	\
			  pfn_pte(pfn, PAGE_KERNEL_RO), 0));		\
		else if (!test_and_set_bit(PG_pinned, &pte->flags))	\
			kmap_flush_unused();				\
		set_pmd(pmd,						\
		        __pmd(_PAGE_TABLE + ((paddr_t)pfn << PAGE_SHIFT))); \
	} else							\
		*(pmd) = __pmd(_PAGE_TABLE + ((paddr_t)pfn << PAGE_SHIFT)); \
} while (0)

/*
 * Allocate and free page tables.
 */
extern pgd_t *pgd_alloc(struct mm_struct *);
extern void pgd_free(pgd_t *pgd);

extern pte_t *pte_alloc_one_kernel(struct mm_struct *, unsigned long);
extern struct page *pte_alloc_one(struct mm_struct *, unsigned long);

static inline void pte_free_kernel(pte_t *pte)
{
	free_page((unsigned long)pte);
	make_lowmem_page_writable(pte, XENFEAT_writable_page_tables);
}

extern void pte_free(struct page *pte);

#define __pte_free_tlb(tlb,pte) tlb_remove_page((tlb),(pte))

#ifdef CONFIG_X86_PAE
/*
 * In the PAE case we free the pmds as part of the pgd.
 */
#define pmd_alloc_one(mm, addr)		({ BUG(); ((pmd_t *)2); })
#define pmd_free(x)			do { } while (0)
#define __pmd_free_tlb(tlb,x)		do { } while (0)
#define pud_populate(mm, pmd, pte)	BUG()
#endif

#define check_pgt_cache()	do { } while (0)

#endif /* _I386_PGALLOC_H */
