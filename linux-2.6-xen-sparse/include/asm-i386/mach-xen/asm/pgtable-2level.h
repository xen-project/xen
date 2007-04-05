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
#define set_pte(pteptr, pteval) (*(pteptr) = pteval)

#define set_pte_at(_mm,addr,ptep,pteval) do {				\
	if (((_mm) != current->mm && (_mm) != &init_mm) ||		\
	    HYPERVISOR_update_va_mapping((addr), (pteval), 0))		\
		set_pte((ptep), (pteval));				\
} while (0)

#define set_pte_at_sync(_mm,addr,ptep,pteval) do {			\
	if (((_mm) != current->mm && (_mm) != &init_mm) ||		\
	    HYPERVISOR_update_va_mapping((addr), (pteval), UVMF_INVLPG)) { \
		set_pte((ptep), (pteval));				\
		xen_invlpg((addr));					\
	}								\
} while (0)

#define set_pte_atomic(pteptr, pteval) set_pte(pteptr,pteval)

#define set_pmd(pmdptr, pmdval) xen_l2_entry_update((pmdptr), (pmdval))

#define pte_clear(mm,addr,xp)	do { set_pte_at(mm, addr, xp, __pte(0)); } while (0)
#define pmd_clear(xp)	do { set_pmd(xp, __pmd(0)); } while (0)

#define pte_none(x) (!(x).pte_low)

static inline pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;
	if (!pte_none(pte)) {
		if (mm != &init_mm)
			pte = __pte_ma(xchg(&ptep->pte_low, 0));
		else
			HYPERVISOR_update_va_mapping(addr, __pte(0), 0);
	}
	return pte;
}

#define ptep_clear_flush(vma, addr, ptep)			\
({								\
	pte_t *__ptep = (ptep);					\
	pte_t __res = *__ptep;					\
	if (!pte_none(__res) &&					\
	    ((vma)->vm_mm != current->mm ||			\
	     HYPERVISOR_update_va_mapping(addr, __pte(0),	\
			(unsigned long)(vma)->vm_mm->cpu_vm_mask.bits| \
				UVMF_INVLPG|UVMF_MULTI))) {	\
		__ptep->pte_low = 0;				\
		flush_tlb_page(vma, addr);			\
	}							\
	__res;							\
})

#define pte_same(a, b)		((a).pte_low == (b).pte_low)

#define __pte_mfn(_pte) ((_pte).pte_low >> PAGE_SHIFT)
#define pte_mfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	__pte_mfn(_pte) : pfn_to_mfn(__pte_mfn(_pte)))
#define pte_pfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	mfn_to_local_pfn(__pte_mfn(_pte)) : __pte_mfn(_pte))

#define pte_page(_pte) pfn_to_page(pte_pfn(_pte))

#define pfn_pte(pfn, prot)	__pte(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << PAGE_SHIFT) | pgprot_val(prot))

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

void vmalloc_sync_all(void);

#endif /* _I386_PGTABLE_2LEVEL_H */
