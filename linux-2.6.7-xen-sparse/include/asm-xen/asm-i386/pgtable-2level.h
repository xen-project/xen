#ifndef _I386_PGTABLE_2LEVEL_H
#define _I386_PGTABLE_2LEVEL_H

/*
 * traditional i386 two-level paging structure:
 */

#define PGDIR_SHIFT	22
#define PTRS_PER_PGD	1024
#define PTRS_PER_PGD_NO_HV	(HYPERVISOR_VIRT_START >> PGDIR_SHIFT)

/*
 * the i386 is two-level, so we don't really have any
 * PMD directory physically.
 */
#define PMD_SHIFT	22
#define PTRS_PER_PMD	1

#define PTRS_PER_PTE	1024

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %08lx.\n", __FILE__, __LINE__, (e).pte_low)
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %08lx.\n", __FILE__, __LINE__, pmd_val(e))
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %08lx.\n", __FILE__, __LINE__, pgd_val(e))

/*
 * The "pgd_xxx()" functions here are trivial for a folded two-level
 * setup: the pgd is never bad, and a pmd always exists (as it's folded
 * into the pgd entry)
 */
static inline int pgd_none(pgd_t pgd)		{ return 0; }
static inline int pgd_bad(pgd_t pgd)		{ return 0; }
static inline int pgd_present(pgd_t pgd)	{ return 1; }
#define pgd_clear(xp)				do { } while (0)

/*
 * Certain architectures need to do special things when PTEs
 * within a page table are directly modified.  Thus, the following
 * hook is made available.
 */
#define set_pte(pteptr, pteval) queue_l1_entry_update(pteptr, (pteval).pte_low)
#define set_pte_atomic(pteptr, pteval) queue_l1_entry_update(pteptr, (pteval).pte_low)
/*
 * (pmds are folded into pgds so this doesn't get actually called,
 * but the define is needed for a generic inline function.)
 */
#define set_pmd(pmdptr, pmdval) queue_l2_entry_update((pmdptr), (pmdval).pmd)
#define set_pgd(pgdptr, pgdval) ((void)0)

#define pgd_page(pgd) \
((unsigned long) __va(pgd_val(pgd) & PAGE_MASK))

static inline pmd_t * pmd_offset(pgd_t * dir, unsigned long address)
{
	return (pmd_t *) dir;
}

/*
 * A note on implementation of this atomic 'get-and-clear' operation.
 * This is actually very simple because Xen Linux can only run on a single
 * processor. Therefore, we cannot race other processors setting the 'accessed'
 * or 'dirty' bits on a page-table entry.
 * Even if pages are shared between domains, that is not a problem because
 * each domain will have separate page tables, with their own versions of
 * accessed & dirty state.
 */
static inline pte_t ptep_get_and_clear(pte_t *xp)
{
	pte_t pte = *xp;
	if (pte.pte_low)
		queue_l1_entry_update(xp, 0);
	return pte;
}

#define pte_same(a, b)		((a).pte_low == (b).pte_low)
#define pte_page(x)		pfn_to_page(pte_pfn(x))
#define pte_none(x)		(!(x).pte_low)
/* XXXcl check valid because msync.c:filemap_sync_pte calls without pte_present check */
#define pte_pfn(x)		((unsigned long)((((x).pte_low & 1 ? machine_to_phys((x).pte_low) : (x).pte_low) >> PAGE_SHIFT)))
#define pfn_pte(pfn, prot)	__pte(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pte_ma(pfn, prot)	__pte_ma(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << PAGE_SHIFT) | pgprot_val(prot))

/*
 * Bits 0, 6 and 7 are taken, split up the 29 bits of offset
 * into this range:
 */
#define PTE_FILE_MAX_BITS	29

#define pte_to_pgoff(pte) \
	((((pte).pte_low >> 1) & 0x1f ) + (((pte).pte_low >> 8) << 5 ))

#define pgoff_to_pte(off) \
	((pte_t) { (((off) & 0x1f) << 1) + (((off) >> 5) << 8) + _PAGE_FILE })

#endif /* _I386_PGTABLE_2LEVEL_H */
