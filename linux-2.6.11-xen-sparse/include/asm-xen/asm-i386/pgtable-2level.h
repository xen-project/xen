#ifndef _I386_PGTABLE_2LEVEL_H
#define _I386_PGTABLE_2LEVEL_H

#include <asm-generic/pgtable-nopmd.h>

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %08lx.\n", __FILE__, __LINE__, (e).pte_low)
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %08lx.\n", __FILE__, __LINE__, pgd_val(e))

/*
 * Certain architectures need to do special things when PTEs
 * within a page table are directly modified.  Thus, the following
 * hook is made available.
 */
#define set_pte_batched(pteptr, pteval) \
	queue_l1_entry_update(pteptr, (pteval).pte_low)
#define set_pte(pteptr, pteval) (*(pteptr) = pteval)
#define set_pte_atomic(pteptr, pteval) set_pte(pteptr,pteval)
#define set_pmd(pmdptr, pmdval) xen_l2_entry_update((pmdptr), (pmdval))

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
		set_pte(xp, __pte_ma(0));
	return pte;
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
 * We force !pfn_valid() by returning an out-of-range pointer.
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
#define INVALID_P2M_ENTRY (~0UL)
#define FOREIGN_FRAME(_m) ((_m) | (1UL<<((sizeof(unsigned long)*8)-1)))
#define pte_pfn(_pte)							\
({									\
	unsigned long mfn = (_pte).pte_low >> PAGE_SHIFT;		\
	unsigned long pfn = mfn_to_pfn(mfn);				\
	if ((pfn >= max_mapnr) || (pfn_to_mfn(pfn) != mfn))		\
		pfn = max_mapnr; /* special: force !pfn_valid() */	\
	pfn;								\
})

#define pte_page(_pte) pfn_to_page(pte_pfn(_pte))

#define pte_none(x)		(!(x).pte_low)
#define pfn_pte(pfn, prot)	__pte(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pte_ma(pfn, prot)	__pte_ma(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << PAGE_SHIFT) | pgprot_val(prot))

#define pmd_page(pmd) (pfn_to_page(pmd_val(pmd) >> PAGE_SHIFT))

#define pmd_page_kernel(pmd) \
((unsigned long) __va(pmd_val(pmd) & PAGE_MASK))

/*
 * All present user pages are user-executable:
 */
static inline int pte_exec(pte_t pte)
{
	return pte_user(pte);
}

/*
 * All present pages are kernel-executable:
 */
static inline int pte_exec_kernel(pte_t pte)
{
	return 1;
}

/*
 * Bits 0, 6 and 7 are taken, split up the 29 bits of offset
 * into this range:
 */
#define PTE_FILE_MAX_BITS	29

#define pte_to_pgoff(pte) \
	((((pte).pte_low >> 1) & 0x1f ) + (((pte).pte_low >> 8) << 5 ))

#define pgoff_to_pte(off) \
	((pte_t) { (((off) & 0x1f) << 1) + (((off) >> 5) << 8) + _PAGE_FILE })

/* Encode and de-code a swap entry */
#define __swp_type(x)			(((x).val >> 1) & 0x1f)
#define __swp_offset(x)			((x).val >> 8)
#define __swp_entry(type, offset)	((swp_entry_t) { ((type) << 1) | ((offset) << 8) })
#define __pte_to_swp_entry(pte)		((swp_entry_t) { (pte).pte_low })
#define __swp_entry_to_pte(x)		((pte_t) { (x).val })

#endif /* _I386_PGTABLE_2LEVEL_H */
