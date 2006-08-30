#ifndef _ASM_IA64_MADDR_H
#define _ASM_IA64_MADDR_H

#include <linux/kernel.h>
#include <asm/hypervisor.h>
#include <xen/features.h>
#include <xen/interface/xen.h>

#ifdef CONFIG_XEN

#define INVALID_P2M_ENTRY       (~0UL)

/* XXX xen page size != page size */
static inline unsigned long
pfn_to_mfn_for_dma(unsigned long pfn)
{
	unsigned long mfn;
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
	extern unsigned long max_mapnr;
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

/* XXX to compile set_phys_to_machine(vaddr, FOREIGN_FRAME(m)) */
#define FOREIGN_FRAME(m)        (INVALID_P2M_ENTRY)

#define mfn_to_pfn(mfn) (mfn)
#define pfn_to_mfn(pfn) (pfn)

#define mfn_to_virt(mfn) (__va((mfn) << PAGE_SHIFT))
#define virt_to_mfn(virt) (__pa(virt) >> PAGE_SHIFT)
#define virt_to_machine(virt) __pa(virt) // for tpmfront.c

#define set_phys_to_machine(pfn, mfn) do { } while (0)
#define xen_machphys_update(mfn, pfn) do { } while (0)

typedef unsigned long maddr_t;	// to compile netback, netfront

#endif /* _ASM_IA64_MADDR_H */
