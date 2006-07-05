/*
 * Initialize VHPT support.
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 */
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/vhpt.h>
#include <asm/vcpu.h>

/* Defined in tlb.c  */
extern void ia64_global_tlb_purge(UINT64 start, UINT64 end, UINT64 nbits);

extern long running_on_sim;

DEFINE_PER_CPU (unsigned long, vhpt_paddr);
DEFINE_PER_CPU (unsigned long, vhpt_pend);

void vhpt_flush(void)
{
	struct vhpt_lf_entry *v = __va(__ia64_per_cpu_var(vhpt_paddr));
	int i;

	for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++)
		v->ti_tag = INVALID_TI_TAG;
}

static void vhpt_erase(void)
{
	struct vhpt_lf_entry *v = (struct vhpt_lf_entry *)VHPT_ADDR;
	int i;

	for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++) {
		v->itir = 0;
		v->CChain = 0;
		v->page_flags = 0;
		v->ti_tag = INVALID_TI_TAG;
	}
	// initialize cache too???
}


static void vhpt_map(unsigned long pte)
{
	unsigned long psr;

	psr = ia64_clear_ic();
	ia64_itr(0x2, IA64_TR_VHPT, VHPT_ADDR, pte, VHPT_SIZE_LOG2);
	ia64_set_psr(psr);
	ia64_srlz_i();
}

void vhpt_insert (unsigned long vadr, unsigned long pte, unsigned long logps)
{
	struct vhpt_lf_entry *vlfe = (struct vhpt_lf_entry *)ia64_thash(vadr);
	unsigned long tag = ia64_ttag (vadr);

	/* No need to first disable the entry, since VHPT is per LP
	   and VHPT is TR mapped.  */
	vlfe->itir = logps;
	vlfe->page_flags = pte | _PAGE_P;
	vlfe->ti_tag = tag;
}

void vhpt_multiple_insert(unsigned long vaddr, unsigned long pte, unsigned long logps)
{
	unsigned long mask = (1L << logps) - 1;
	int i;

	if (logps-PAGE_SHIFT > 10 && !running_on_sim) {
		// if this happens, we may want to revisit this algorithm
		panic("vhpt_multiple_insert:logps-PAGE_SHIFT>10,spinning..\n");
	}
	if (logps-PAGE_SHIFT > 2) {
		// FIXME: Should add counter here to see how often this
		//  happens (e.g. for 16MB pages!) and determine if it
		//  is a performance problem.  On a quick look, it takes
		//  about 39000 instrs for a 16MB page and it seems to occur
		//  only a few times/second, so OK for now.
		//  An alternate solution would be to just insert the one
		//  16KB in the vhpt (but with the full mapping)?
		//printf("vhpt_multiple_insert: logps-PAGE_SHIFT==%d,"
			//"va=%p, pa=%p, pa-masked=%p\n",
			//logps-PAGE_SHIFT,vaddr,pte&_PFN_MASK,
			//(pte&_PFN_MASK)&~mask);
	}
	vaddr &= ~mask;
	pte = ((pte & _PFN_MASK) & ~mask) | (pte & ~_PFN_MASK);
	for (i = 1L << (logps-PAGE_SHIFT); i > 0; i--) {
		vhpt_insert(vaddr,pte,logps<<2);
		vaddr += PAGE_SIZE;
	}
}

void vhpt_init(void)
{
	unsigned long paddr, pte;
	struct page_info *page;
#if !VHPT_ENABLED
	return;
#endif
	/* This allocation only holds true if vhpt table is unique for
	 * all domains. Or else later new vhpt table should be allocated
	 * from domain heap when each domain is created. Assume xen buddy
	 * allocator can provide natural aligned page by order?
	 */
	page = alloc_domheap_pages(NULL, VHPT_SIZE_LOG2 - PAGE_SHIFT, 0);
	if (!page)
		panic("vhpt_init: can't allocate VHPT!\n");
	paddr = page_to_maddr(page);
	if (paddr & ((1 << VHPT_SIZE_LOG2) - 1))
		panic("vhpt_init: bad VHPT alignment!\n");
	__get_cpu_var(vhpt_paddr) = paddr;
	__get_cpu_var(vhpt_pend) = paddr + (1 << VHPT_SIZE_LOG2) - 1;
	printf("vhpt_init: vhpt paddr=0x%lx, end=0x%lx\n",
		paddr, __get_cpu_var(vhpt_pend));
	pte = pte_val(pfn_pte(paddr >> PAGE_SHIFT, PAGE_KERNEL));
	vhpt_map(pte);
	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
		VHPT_ENABLED);
	vhpt_erase();
}


void vcpu_flush_vtlb_all(struct vcpu *v)
{
	/* First VCPU tlb.  */
	vcpu_purge_tr_entry(&PSCBX(v,dtlb));
	vcpu_purge_tr_entry(&PSCBX(v,itlb));

	/* Then VHPT.  */
	vhpt_flush ();

	/* Then mTLB.  */
	local_flush_tlb_all ();

	/* We could clear bit in d->domain_dirty_cpumask only if domain d in
	   not running on this processor.  There is currently no easy way to
	   check this.  */
}

static void __vcpu_flush_vtlb_all(void *vcpu)
{
	vcpu_flush_vtlb_all((struct vcpu*)vcpu);
}

void domain_flush_vtlb_all (void)
{
	int cpu = smp_processor_id ();
	struct vcpu *v;

	for_each_vcpu (current->domain, v) {
		if (!test_bit(_VCPUF_initialised, &v->vcpu_flags))
			continue;

		if (v->processor == cpu)
			vcpu_flush_vtlb_all(v);
		else
			smp_call_function_single(v->processor,
						 __vcpu_flush_vtlb_all,
						 v, 1, 1);
	}
}

static void cpu_flush_vhpt_range (int cpu, u64 vadr, u64 addr_range)
{
	void *vhpt_base = __va(per_cpu(vhpt_paddr, cpu));

	while ((long)addr_range > 0) {
		/* Get the VHPT entry.  */
		unsigned int off = ia64_thash(vadr) - VHPT_ADDR;
		volatile struct vhpt_lf_entry *v;
		v = vhpt_base + off;
		v->ti_tag = INVALID_TI_TAG;
		addr_range -= PAGE_SIZE;
		vadr += PAGE_SIZE;
	}
}

void vcpu_flush_tlb_vhpt_range (u64 vadr, u64 log_range)
{
	cpu_flush_vhpt_range (current->processor, vadr, 1UL << log_range);
	ia64_ptcl(vadr, log_range << 2);
	ia64_srlz_i();
}

void domain_flush_vtlb_range (struct domain *d, u64 vadr, u64 addr_range)
{
	struct vcpu *v;

#if 0
	// this only seems to occur at shutdown, but it does occur
	if ((!addr_range) || addr_range & (addr_range - 1)) {
		printf("vhpt_flush_address: weird range, spinning...\n");
		while(1);
	}
#endif

	for_each_vcpu (d, v) {
		if (!test_bit(_VCPUF_initialised, &v->vcpu_flags))
			continue;

		/* Purge TC entries.
		   FIXME: clear only if match.  */
		vcpu_purge_tr_entry(&PSCBX(v,dtlb));
		vcpu_purge_tr_entry(&PSCBX(v,itlb));
	}
	smp_mb();

	for_each_vcpu (d, v) {
		if (!test_bit(_VCPUF_initialised, &v->vcpu_flags))
			continue;

		/* Invalidate VHPT entries.  */
		cpu_flush_vhpt_range (v->processor, vadr, addr_range);
	}
	// ptc.ga has release semantics.

	/* ptc.ga  */
	ia64_global_tlb_purge(vadr,vadr+addr_range,PAGE_SHIFT);
}

static void flush_tlb_vhpt_all (struct domain *d)
{
	/* First VHPT.  */
	vhpt_flush ();

	/* Then mTLB.  */
	local_flush_tlb_all ();
}

void domain_flush_destroy (struct domain *d)
{
	/* Very heavy...  */
	on_each_cpu ((void (*)(void *))flush_tlb_vhpt_all, d, 1, 1);
	cpus_clear (d->domain_dirty_cpumask);
}

void flush_tlb_mask(cpumask_t mask)
{
    int cpu;

    cpu = smp_processor_id();
    if (cpu_isset (cpu, mask)) {
        cpu_clear(cpu, mask);
        flush_tlb_vhpt_all (NULL);
    }

    if (cpus_empty(mask))
        return;

    for_each_cpu_mask (cpu, mask)
        smp_call_function_single
            (cpu, (void (*)(void *))flush_tlb_vhpt_all, NULL, 1, 1);
}

void zero_vhpt_stats(void)
{
	return;
}

int dump_vhpt_stats(char *buf)
{
	int i, cpu;
	char *s = buf;

	s += sprintf(s,"VHPT usage (%ld entries):\n",
		     (unsigned long) VHPT_NUM_ENTRIES);

	for_each_present_cpu (cpu) {
		struct vhpt_lf_entry *v = __va(per_cpu(vhpt_paddr, cpu));
		unsigned long vhpt_valid = 0;

		for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++)
			if (!(v->ti_tag & INVALID_TI_TAG))
				vhpt_valid++;
		s += sprintf(s,"  cpu %d: %ld\n", cpu, vhpt_valid);
	}

	return s - buf;
}
