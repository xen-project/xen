/*
 * Initialize MMU support.
 *
 * Copyright (C) 1998-2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <xen/sched.h>
#include <asm/vhpt.h>
#include <asm/xenmca.h>
#include <asm/meminit.h>
#include <asm/page.h>

struct ia64_mca_tlb_info ia64_mca_tlb_list[NR_CPUS];

extern void ia64_tlb_init (void);

#ifdef XEN
cpumask_t percpu_set;
#endif

void __devinit
ia64_mmu_init (void *my_cpu_data)
{
	unsigned long psr, impl_va_bits;
	extern void __devinit tlb_init (void);
	int cpu = smp_processor_id();

	/* Pin mapping for percpu area into TLB */
	psr = ia64_clear_ic();
	ia64_itr(0x2, IA64_TR_PERCPU_DATA, PERCPU_ADDR,
		 pte_val(pfn_pte(__pa(my_cpu_data) >> PAGE_SHIFT, PAGE_KERNEL)),
		 PERCPU_PAGE_SHIFT);

	ia64_set_psr(psr);
	ia64_srlz_i();
#ifdef XEN
	cpumask_set_cpu(cpu, &percpu_set);
#endif

	/*
	 * Check if the virtually mapped linear page table (VMLPT) overlaps with a mapped
	 * address space.  The IA-64 architecture guarantees that at least 50 bits of
	 * virtual address space are implemented but if we pick a large enough page size
	 * (e.g., 64KB), the mapped address space is big enough that it will overlap with
	 * VMLPT.  I assume that once we run on machines big enough to warrant 64KB pages,
	 * IMPL_VA_MSB will be significantly bigger, so this is unlikely to become a
	 * problem in practice.  Alternatively, we could truncate the top of the mapped
	 * address space to not permit mappings that would overlap with the VMLPT.
	 * --davidm 00/12/06
	 */
#	define pte_bits			3
#	define mapped_space_bits	(3*(PAGE_SHIFT - pte_bits) + PAGE_SHIFT)
	/*
	 * The virtual page table has to cover the entire implemented address space within
	 * a region even though not all of this space may be mappable.  The reason for
	 * this is that the Access bit and Dirty bit fault handlers perform
	 * non-speculative accesses to the virtual page table, so the address range of the
	 * virtual page table itself needs to be covered by virtual page table.
	 */
#	define vmlpt_bits		(impl_va_bits - PAGE_SHIFT + pte_bits)
#	define POW2(n)			(1ULL << (n))

	impl_va_bits = ffz(~(local_cpu_data->unimpl_va_mask | (7UL << 61)));

	if (impl_va_bits < 51 || impl_va_bits > 61)
		panic("CPU has bogus IMPL_VA_MSB value of %lu!\n", impl_va_bits - 1);

#ifdef XEN
	vhpt_init();
#endif
	ia64_tlb_init();

#ifdef	CONFIG_HUGETLB_PAGE
	ia64_set_rr(HPAGE_REGION_BASE, HPAGE_SHIFT << 2);
	ia64_srlz_d();
#endif

	/* mca handler uses cr.lid as key to pick the right entry */
	ia64_mca_tlb_list[cpu].cr_lid = ia64_getreg(_IA64_REG_CR_LID);

	/* insert this percpu data information into our list for MCA recovery purposes */
#ifdef XEN
	ia64_mca_tlb_list[cpu].percpu_paddr = __pa(my_cpu_data);
#else
	ia64_mca_tlb_list[cpu].percpu_paddr = pte_val(mk_pte_phys(__pa(my_cpu_data), PAGE_KERNEL));
	/* Also save per-cpu tlb flush recipe for use in physical mode mca handler */
	ia64_mca_tlb_list[cpu].ptce_base = local_cpu_data->ptce_base;
	ia64_mca_tlb_list[cpu].ptce_count[0] = local_cpu_data->ptce_count[0];
	ia64_mca_tlb_list[cpu].ptce_count[1] = local_cpu_data->ptce_count[1];
	ia64_mca_tlb_list[cpu].ptce_stride[0] = local_cpu_data->ptce_stride[0];
	ia64_mca_tlb_list[cpu].ptce_stride[1] = local_cpu_data->ptce_stride[1];
#endif
}

void __init
mem_init (void)
{
#ifdef CONFIG_PCI
	/*
	 * This needs to be called _after_ the command line has been parsed but _before_
	 * any drivers that may need the PCI DMA interface are initialized or bootmem has
	 * been freed.
	 */
	platform_dma_init();
#endif

}
