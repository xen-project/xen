#ifndef _I386_PGTABLE_2LEVEL_H
#define _I386_PGTABLE_2LEVEL_H

/*
 * traditional i386 two-level paging structure:
 */

#define PGDIR_SHIFT	22
#define PTRS_PER_PGD	1024

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

#define set_pte(pteptr, pteval) queue_l1_entry_update(pteptr, (pteval).pte_low)
#define set_pte_atomic(pteptr, pteval) queue_l1_entry_update(pteptr, (pteval).pte_low)
#define set_pmd(pmdptr, pmdval) queue_l2_entry_update((pmdptr), (pmdval))
#define set_pgd(pgdptr, pgdval) ((void)0)

#define pgd_page(pgd) \
((unsigned long) __va(pgd_val(pgd) & PAGE_MASK))

static inline pmd_t * pmd_offset(pgd_t * dir, unsigned long address)
{
	return (pmd_t *) dir;
}

#define pte_same(a, b)		((a).pte_low == (b).pte_low)

/*                                 
 * We detect special mappings in one of two ways:
 *  1. If the MFN is an I/O page then Xen will set the m2p entry
 *     to be outside our maximum possible pseudophys range.
 *  2. If the MFN belongs to a different domain then we will certainly
 *     not have MFN in our p2m table. Conversely, if the page is ours,
 *     then we'll have p2m(m2p(MFN))==MFN.
 * If we detect a special mapping then it doesn't have a 'struct page'.
 * We force !VALID_PAGE() by returning an out-of-range pointer.
 *
 * NB. These checks require that, for any MFN that is not in our reservation,
 * there is no PFN such that p2m(PFN) == MFN. Otherwise we can get confused if
 * we are foreign-mapping the MFN, and the other domain as m2p(MFN) == PFN.
 * Yikes! Various places must poke in INVALID_P2M_ENTRY for safety.
 * 
 * NB2. When deliberately mapping foreign pages into the p2m table, you *must*
 *      use FOREIGN_FRAME(). This will cause pte_pfn() to choke on it, as we
 *      require. In all the cases we care about, the high bit gets shifted out
 *      (e.g., phys_to_machine()) so behaviour there is correct.
 */
#define INVALID_P2M_ENTRY (~0U)
#define FOREIGN_FRAME(_m) ((_m) | (1UL<<((sizeof(unsigned long)*8)-1)))
#define pte_page(_pte)                                        \
({                                                            \
    unsigned long mfn = (_pte).pte_low >> PAGE_SHIFT;         \
    unsigned long pfn = mfn_to_pfn(mfn);                      \
    if ( (pfn >= max_mapnr) || (pfn_to_mfn(pfn) != mfn) )     \
        pfn = max_mapnr; /* specia: force !VALID_PAGE() */    \
    &mem_map[pfn];                                            \
})

#define pte_none(x)		(!(x).pte_low)
#define __mk_pte(page_nr,pgprot) __pte(((page_nr) << PAGE_SHIFT) | pgprot_val(pgprot))

/*
 * A note on implementation of this atomic 'get-and-clear' operation.
 * This is actually very simple because XenoLinux can only run on a single
 * processor. Therefore, we cannot race other processors setting the 'accessed'
 * or 'dirty' bits on a page-table entry.
 * Even if pages are shared between domains, that is not a problem because
 * each domain will have separate page tables, with their own versions of
 * accessed & dirty state.
 */
static inline pte_t ptep_get_and_clear(pte_t *xp)
{
    pte_t pte = *xp;
    if ( !pte_none(pte) )
        queue_l1_entry_update(xp, 0);
    return pte;
}

#endif /* _I386_PGTABLE_2LEVEL_H */
