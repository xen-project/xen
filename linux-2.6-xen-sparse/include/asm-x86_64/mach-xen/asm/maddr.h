#ifndef _X86_64_MADDR_H
#define _X86_64_MADDR_H

#include <xen/features.h>
#include <xen/interface/xen.h>

/**** MACHINE <-> PHYSICAL CONVERSION MACROS ****/
#define INVALID_P2M_ENTRY	(~0UL)
#define FOREIGN_FRAME_BIT	(1UL<<63)
#define FOREIGN_FRAME(m)	((m) | FOREIGN_FRAME_BIT)

/* Definitions for machine and pseudophysical addresses. */
typedef unsigned long paddr_t;
typedef unsigned long maddr_t;

#ifdef CONFIG_XEN

extern unsigned long *phys_to_machine_mapping;

#undef machine_to_phys_mapping
extern unsigned long *machine_to_phys_mapping;
extern unsigned int   machine_to_phys_order;

static inline unsigned long pfn_to_mfn(unsigned long pfn)
{
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return pfn;
	BUG_ON(end_pfn && pfn >= end_pfn);
	return phys_to_machine_mapping[pfn] & ~FOREIGN_FRAME_BIT;
}

static inline int phys_to_machine_mapping_valid(unsigned long pfn)
{
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return 1;
	BUG_ON(end_pfn && pfn >= end_pfn);
	return (phys_to_machine_mapping[pfn] != INVALID_P2M_ENTRY);
}

static inline unsigned long mfn_to_pfn(unsigned long mfn)
{
	unsigned long pfn;

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return mfn;

	if (unlikely((mfn >> machine_to_phys_order) != 0))
		return end_pfn;

	/* The array access can fail (e.g., device space beyond end of RAM). */
	asm (
		"1:	movq %1,%0\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:	movq %2,%0\n"
		"	jmp  2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 8\n"
		"	.quad 1b,3b\n"
		".previous"
		: "=r" (pfn)
		: "m" (machine_to_phys_mapping[mfn]), "m" (end_pfn) );

	return pfn;
}

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
 *      require. In all the cases we care about, the FOREIGN_FRAME bit is
 *      masked (e.g., pfn_to_mfn()) so behaviour there is correct.
 */
static inline unsigned long mfn_to_local_pfn(unsigned long mfn)
{
	unsigned long pfn = mfn_to_pfn(mfn);
	if ((pfn < end_pfn)
	    && !xen_feature(XENFEAT_auto_translated_physmap)
	    && (phys_to_machine_mapping[pfn] != mfn))
		return end_pfn; /* force !pfn_valid() */
	return pfn;
}

static inline void set_phys_to_machine(unsigned long pfn, unsigned long mfn)
{
	BUG_ON(end_pfn && pfn >= end_pfn);
	if (xen_feature(XENFEAT_auto_translated_physmap)) {
		BUG_ON(pfn != mfn && mfn != INVALID_P2M_ENTRY);
		return;
	}
	phys_to_machine_mapping[pfn] = mfn;
}

static inline maddr_t phys_to_machine(paddr_t phys)
{
	maddr_t machine = pfn_to_mfn(phys >> PAGE_SHIFT);
	machine = (machine << PAGE_SHIFT) | (phys & ~PAGE_MASK);
	return machine;
}

static inline paddr_t machine_to_phys(maddr_t machine)
{
	paddr_t phys = mfn_to_pfn(machine >> PAGE_SHIFT);
	phys = (phys << PAGE_SHIFT) | (machine & ~PAGE_MASK);
	return phys;
}

static inline paddr_t pte_phys_to_machine(paddr_t phys)
{
	maddr_t machine;
	machine = pfn_to_mfn((phys & PHYSICAL_PAGE_MASK) >> PAGE_SHIFT);
	machine = (machine << PAGE_SHIFT) | (phys & ~PHYSICAL_PAGE_MASK);
	return machine;
}

static inline paddr_t pte_machine_to_phys(maddr_t machine)
{
	paddr_t phys;
	phys = mfn_to_pfn((machine & PHYSICAL_PAGE_MASK) >> PAGE_SHIFT);
	phys = (phys << PAGE_SHIFT) | (machine & ~PHYSICAL_PAGE_MASK);
	return phys;
}

#define __pte_ma(x)     ((pte_t) { (x) } )
#define pfn_pte_ma(pfn, prot)	__pte_ma((((pfn) << PAGE_SHIFT) | pgprot_val(prot)) & __supported_pte_mask)

#else /* !CONFIG_XEN */

#define pfn_to_mfn(pfn) (pfn)
#define mfn_to_pfn(mfn) (mfn)
#define mfn_to_local_pfn(mfn) (mfn)
#define set_phys_to_machine(pfn, mfn) ((void)0)
#define phys_to_machine_mapping_valid(pfn) (1)
#define phys_to_machine(phys) ((maddr_t)(phys))
#define machine_to_phys(mach) ((paddr_t)(mach))
#define pfn_pte_ma(pfn, prot) pfn_pte(pfn, prot)
#define __pte_ma(x) __pte(x)

#endif /* !CONFIG_XEN */

/* VIRT <-> MACHINE conversion */
#define virt_to_machine(v)	(phys_to_machine(__pa(v)))
#define virt_to_mfn(v)		(pfn_to_mfn(__pa(v) >> PAGE_SHIFT))
#define mfn_to_virt(m)		(__va(mfn_to_pfn(m) << PAGE_SHIFT))

#endif /* _X86_64_MADDR_H */

