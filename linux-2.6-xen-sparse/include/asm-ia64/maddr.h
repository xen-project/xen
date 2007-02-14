#ifndef _ASM_IA64_MADDR_H
#define _ASM_IA64_MADDR_H

#include <linux/kernel.h>
#include <asm/hypervisor.h>
#include <xen/features.h>
#include <xen/interface/xen.h>

#ifdef CONFIG_XEN

#define INVALID_P2M_ENTRY       (~0UL)

#ifdef CONFIG_XEN_IA64_EXPOSE_P2M
extern int p2m_initialized;
extern unsigned long p2m_min_low_pfn;
extern unsigned long p2m_max_low_pfn;
extern unsigned long p2m_convert_min_pfn;
extern unsigned long p2m_convert_max_pfn;
extern volatile const pte_t* p2m_pte;
unsigned long p2m_phystomach(unsigned long gpfn);
#else
#define p2m_initialized		(0)
#define p2m_phystomach(gpfn)	INVALID_MFN
#endif

/* XXX xen page size != page size */
static inline unsigned long
pfn_to_mfn_for_dma(unsigned long pfn)
{
	unsigned long mfn;
	if (p2m_initialized)
		return p2m_phystomach(pfn);
	mfn = HYPERVISOR_phystomach(pfn);
	BUG_ON(mfn == 0); // XXX
	BUG_ON(mfn == INVALID_P2M_ENTRY); // XXX
	BUG_ON(mfn == INVALID_MFN);
	return mfn;
}

static inline unsigned long
phys_to_machine_for_dma(unsigned long phys)
{
	unsigned long machine =
	              pfn_to_mfn_for_dma(phys >> PAGE_SHIFT) << PAGE_SHIFT;
	machine |= (phys & ~PAGE_MASK);
	return machine;
}

static inline unsigned long
mfn_to_pfn_for_dma(unsigned long mfn)
{
	unsigned long pfn;
	pfn = HYPERVISOR_machtophys(mfn);
	BUG_ON(pfn == 0);
	//BUG_ON(pfn == INVALID_M2P_ENTRY);
	return pfn;
}

static inline unsigned long
machine_to_phys_for_dma(unsigned long machine)
{
	unsigned long phys =
	              mfn_to_pfn_for_dma(machine >> PAGE_SHIFT) << PAGE_SHIFT;
	phys |= (machine & ~PAGE_MASK);
	return phys;
}

static inline unsigned long
mfn_to_local_pfn(unsigned long mfn)
{
	unsigned long pfn = mfn_to_pfn_for_dma(mfn);
	if (!pfn_valid(pfn))
		return INVALID_P2M_ENTRY;
	return pfn;
}

#else /* !CONFIG_XEN */

#define pfn_to_mfn_for_dma(pfn) (pfn)
#define mfn_to_pfn_for_dma(mfn) (mfn)
#define phys_to_machine_for_dma(phys) (phys)
#define machine_to_phys_for_dma(machine) (machine)
#define mfn_to_local_pfn(mfn) (mfn)

#endif /* !CONFIG_XEN */

#define mfn_to_pfn(mfn) (mfn)
#define pfn_to_mfn(pfn) (pfn)

#define mfn_to_virt(mfn) (__va((mfn) << PAGE_SHIFT))
#define virt_to_mfn(virt) (__pa(virt) >> PAGE_SHIFT)
#define virt_to_machine(virt) __pa(virt) // for tpmfront.c

#define set_phys_to_machine(pfn, mfn) do { } while (0)

typedef unsigned long maddr_t;	// to compile netback, netfront

#endif /* _ASM_IA64_MADDR_H */
