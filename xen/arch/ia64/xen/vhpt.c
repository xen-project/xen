/*
 * Initialize VHPT support.
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *                    per vcpu vhpt support
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
#include <asm/vcpumask.h>
#include <asm/vmmu.h>

DEFINE_PER_CPU_READ_MOSTLY(unsigned long, vhpt_paddr);
DEFINE_PER_CPU_READ_MOSTLY(unsigned long, vhpt_pend);
#ifdef CONFIG_XEN_IA64_TLBFLUSH_CLOCK
DEFINE_PER_CPU(volatile u32, vhpt_tlbflush_timestamp);
#endif

static void
__vhpt_flush(unsigned long vhpt_maddr, unsigned long vhpt_size_log2)
{
	struct vhpt_lf_entry *v = (struct vhpt_lf_entry*)__va(vhpt_maddr);
	unsigned long num_entries = 1 << (vhpt_size_log2 - 5);
	int i;

	for (i = 0; i < num_entries; i++, v++)
		v->ti_tag = INVALID_TI_TAG;
}

void
local_vhpt_flush(void)
{
	/* increment flush clock before flush */
	u32 flush_time = tlbflush_clock_inc_and_return();
	__vhpt_flush(__ia64_per_cpu_var(vhpt_paddr), VHPT_SIZE_LOG2);
	/* this must be after flush */
	tlbflush_update_time(&__get_cpu_var(vhpt_tlbflush_timestamp),
	                     flush_time);
	perfc_incr(local_vhpt_flush);
}

void
vcpu_vhpt_flush(struct vcpu* v)
{
	unsigned long vhpt_size_log2 = VHPT_SIZE_LOG2;
#ifdef CONFIG_XEN_IA64_PERVCPU_VHPT
	if (HAS_PERVCPU_VHPT(v->domain))
		vhpt_size_log2 = v->arch.pta.size;
#endif
	__vhpt_flush(vcpu_vhpt_maddr(v), vhpt_size_log2);
	perfc_incr(vcpu_vhpt_flush);
}

static void
vhpt_erase(unsigned long vhpt_maddr, unsigned long vhpt_size_log2)
{
	struct vhpt_lf_entry *v = (struct vhpt_lf_entry*)__va(vhpt_maddr);
	unsigned long num_entries = 1 << (vhpt_size_log2 - 5);
	int i;

	for (i = 0; i < num_entries; i++, v++) {
		v->itir = 0;
		v->CChain = 0;
		v->page_flags = 0;
		v->ti_tag = INVALID_TI_TAG;
	}
	// initialize cache too???
}

void vhpt_insert (unsigned long vadr, unsigned long pte, unsigned long itir)
{
	struct vhpt_lf_entry *vlfe = (struct vhpt_lf_entry *)ia64_thash(vadr);
	unsigned long tag = ia64_ttag (vadr);

	/* Even though VHPT is per VCPU, still need to first disable the entry,
	 * because the processor may support speculative VHPT walk.  */
	vlfe->ti_tag = INVALID_TI_TAG;
	wmb();
	vlfe->itir = itir;
	vlfe->page_flags = pte | _PAGE_P;
	*(volatile unsigned long*)&vlfe->ti_tag = tag;
}

void vhpt_multiple_insert(unsigned long vaddr, unsigned long pte,
			   unsigned long itir)
{
	unsigned char ps = current->arch.vhpt_pg_shift;
	ia64_itir_t _itir = {.itir = itir};
	unsigned long mask = (1L << _itir.ps) - 1;
	int i;

	if (_itir.ps - ps > 10 && !running_on_sim) {
		// if this happens, we may want to revisit this algorithm
		panic("vhpt_multiple_insert:logps-PAGE_SHIFT>10,spinning..\n");
	}
	if (_itir.ps - ps > 2) {
		// FIXME: Should add counter here to see how often this
		//  happens (e.g. for 16MB pages!) and determine if it
		//  is a performance problem.  On a quick look, it takes
		//  about 39000 instrs for a 16MB page and it seems to occur
		//  only a few times/second, so OK for now.
		//  An alternate solution would be to just insert the one
		//  16KB in the vhpt (but with the full mapping)?
		//printk("vhpt_multiple_insert: logps-PAGE_SHIFT==%d,"
			//"va=%p, pa=%p, pa-masked=%p\n",
			//logps-PAGE_SHIFT,vaddr,pte&_PFN_MASK,
			//(pte&_PFN_MASK)&~mask);
	}
	vaddr &= ~mask;
	pte = ((pte & _PFN_MASK) & ~mask) | (pte & ~_PFN_MASK);
	for (i = 1L << (_itir.ps - ps); i > 0; i--) {
		vhpt_insert(vaddr, pte, _itir.itir);
		vaddr += (1L << ps);
	}
}

void __init vhpt_init(void)
{
	unsigned long paddr;
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
	printk(XENLOG_DEBUG "vhpt_init: vhpt paddr=0x%lx, end=0x%lx\n",
	       paddr, __get_cpu_var(vhpt_pend));
	vhpt_erase(paddr, VHPT_SIZE_LOG2);
	// we don't enable VHPT here.
	// context_switch() or schedule_tail() does it.
}

#ifdef CONFIG_XEN_IA64_PERVCPU_VHPT
void
domain_set_vhpt_size(struct domain *d, int8_t vhpt_size_log2)
{
	if (vhpt_size_log2 == -1) {
		d->arch.has_pervcpu_vhpt = 0;
		printk(XENLOG_INFO "XEN_DOMCTL_arch_setup: "
		       "domain %d VHPT is global.\n", d->domain_id);
	} else {
		d->arch.has_pervcpu_vhpt = 1;
		d->arch.vhpt_size_log2 = vhpt_size_log2;
		printk(XENLOG_INFO "XEN_DOMCTL_arch_setup: "
		       "domain %d VHPT is per vcpu. size=2**%d\n",
		       d->domain_id, vhpt_size_log2);
	}
}

int
pervcpu_vhpt_alloc(struct vcpu *v)
{
	unsigned long vhpt_size_log2 = VHPT_SIZE_LOG2;

	if (v->domain->arch.vhpt_size_log2 > 0)
	    vhpt_size_log2 =
		canonicalize_vhpt_size(v->domain->arch.vhpt_size_log2);
	printk(XENLOG_DEBUG "%s vhpt_size_log2=%ld\n",
	       __func__, vhpt_size_log2);
	v->arch.vhpt_entries =
		(1UL << vhpt_size_log2) / sizeof(struct vhpt_lf_entry);
	v->arch.vhpt_page =
		alloc_domheap_pages(NULL, vhpt_size_log2 - PAGE_SHIFT, 0);
	if (!v->arch.vhpt_page)
		return -ENOMEM;
	
	v->arch.vhpt_maddr = page_to_maddr(v->arch.vhpt_page);
	if (v->arch.vhpt_maddr & ((1 << VHPT_SIZE_LOG2) - 1))
		panic("pervcpu_vhpt_init: bad VHPT alignment!\n");

	v->arch.pta.val = 0; // to zero reserved bits
	v->arch.pta.ve = 1; // enable vhpt
	v->arch.pta.size = vhpt_size_log2;
	v->arch.pta.vf = 1; // long format
	v->arch.pta.base = __va_ul(v->arch.vhpt_maddr) >> 15;

	vhpt_erase(v->arch.vhpt_maddr, vhpt_size_log2);
	smp_mb(); // per vcpu vhpt may be used by another physical cpu.
	return 0;
}

void
pervcpu_vhpt_free(struct vcpu *v)
{
	if (likely(v->arch.vhpt_page != NULL))
		free_domheap_pages(v->arch.vhpt_page,
		                   v->arch.pta.size - PAGE_SHIFT);
}
#endif

void
domain_purge_swtc_entries(struct domain *d)
{
	struct vcpu* v;
	for_each_vcpu(d, v) {
		if (!v->is_initialised)
			continue;

		/* Purge TC entries.
		   FIXME: clear only if match.  */
		vcpu_purge_tr_entry(&PSCBX(v,dtlb));
		vcpu_purge_tr_entry(&PSCBX(v,itlb));
	}
}

void
domain_purge_swtc_entries_vcpu_dirty_mask(struct domain* d,
                                          vcpumask_t vcpu_dirty_mask)
{
	int vcpu;

	for_each_vcpu_mask(d, vcpu, vcpu_dirty_mask) {
		struct vcpu* v = d->vcpu[vcpu];
		if (!v->is_initialised)
			continue;

		/* Purge TC entries.
		   FIXME: clear only if match.  */
		vcpu_purge_tr_entry(&PSCBX(v, dtlb));
		vcpu_purge_tr_entry(&PSCBX(v, itlb));
	}
}

// SMP: we can't assume v == current, vcpu might move to another physical cpu.
// So memory barrier is necessary.
// if we can guranttee that vcpu can run on only this physical cpu
// (e.g. vcpu == current), smp_mb() is unnecessary.
void vcpu_flush_vtlb_all(struct vcpu *v)
{
	/* First VCPU tlb.  */
	vcpu_purge_tr_entry(&PSCBX(v,dtlb));
	vcpu_purge_tr_entry(&PSCBX(v,itlb));
	smp_mb();

	/* Then VHPT.  */
	if (HAS_PERVCPU_VHPT(v->domain))
		vcpu_vhpt_flush(v);
	else
		local_vhpt_flush();
	smp_mb();

	/* Then mTLB.  */
	local_flush_tlb_all();

	/* We could clear bit in d->domain_dirty_cpumask only if domain d in
	   not running on this processor.  There is currently no easy way to
	   check this.  */

	perfc_incr(vcpu_flush_vtlb_all);
}

static void __vcpu_flush_vtlb_all(void *vcpu)
{
	vcpu_flush_vtlb_all((struct vcpu*)vcpu);
}

// caller must incremented reference count to d somehow.
void domain_flush_vtlb_all(struct domain* d)
{
	int cpu = smp_processor_id ();
	struct vcpu *v;

	for_each_vcpu(d, v) {
		if (!v->is_initialised)
			continue;

		if (VMX_DOMAIN(v)) {
			// This code may be called for remapping shared_info
			// and grant_table from guest_physmap_remove_page()
			// in arch_memory_op() XENMEM_add_to_physmap to realize
			// PV-on-HVM feature.
			vmx_vcpu_flush_vtlb_all(v);
			continue;
		}

		if (v->processor == cpu)
			vcpu_flush_vtlb_all(v);
		else
			// SMP: it is racy to reference v->processor.
			// vcpu scheduler may move this vcpu to another
			// physicall processor, and change the value
			// using plain store.
			// We may be seeing the old value of it.
			// In such case, flush_vtlb_for_context_switch()
			// takes care of mTLB flush.
			smp_call_function_single(v->processor,
						 __vcpu_flush_vtlb_all,
						 v, 1);
	}
	perfc_incr(domain_flush_vtlb_all);
}

// Callers may need to call smp_mb() before/after calling this.
// Be carefull.
static void
__flush_vhpt_range(unsigned long vhpt_maddr, u64 vadr, u64 addr_range)
{
	void *vhpt_base = __va(vhpt_maddr);
	u64 pgsz = 1L << current->arch.vhpt_pg_shift;
	u64 purge_addr = vadr & PAGE_MASK;

	addr_range += vadr - purge_addr;
	addr_range = PAGE_ALIGN(addr_range);
	while ((long)addr_range > 0) {
		/* Get the VHPT entry.  */
		unsigned int off = ia64_thash(purge_addr) -
			__va_ul(vcpu_vhpt_maddr(current));
		struct vhpt_lf_entry *v = vhpt_base + off;
		v->ti_tag = INVALID_TI_TAG;
		addr_range -= pgsz;
		purge_addr += pgsz;
	}
}

static void
cpu_flush_vhpt_range(int cpu, u64 vadr, u64 addr_range)
{
	__flush_vhpt_range(per_cpu(vhpt_paddr, cpu), vadr, addr_range);
}

static void
vcpu_flush_vhpt_range(struct vcpu* v, u64 vadr, u64 addr_range)
{
	__flush_vhpt_range(vcpu_vhpt_maddr(v), vadr, addr_range);
}

void vcpu_flush_tlb_vhpt_range (u64 vadr, u64 log_range)
{
	if (HAS_PERVCPU_VHPT(current->domain))
		vcpu_flush_vhpt_range(current, vadr, 1UL << log_range);
	else
		cpu_flush_vhpt_range(current->processor,
		                     vadr, 1UL << log_range);
	ia64_ptcl(vadr, log_range << 2);
	ia64_srlz_i();
	perfc_incr(vcpu_flush_tlb_vhpt_range);
}

void domain_flush_vtlb_range (struct domain *d, u64 vadr, u64 addr_range)
{
	struct vcpu *v;

#if 0
	// this only seems to occur at shutdown, but it does occur
	if ((!addr_range) || addr_range & (addr_range - 1)) {
		printk("vhpt_flush_address: weird range, spinning...\n");
		while(1);
	}
#endif

	domain_purge_swtc_entries(d);
	smp_mb();

	for_each_vcpu (d, v) {
		if (!v->is_initialised)
			continue;

		if (HAS_PERVCPU_VHPT(d)) {
			vcpu_flush_vhpt_range(v, vadr, addr_range);
		} else {
			// SMP: it is racy to reference v->processor.
			// vcpu scheduler may move this vcpu to another
			// physicall processor, and change the value
			// using plain store.
			// We may be seeing the old value of it.
			// In such case, flush_vtlb_for_context_switch()
			/* Invalidate VHPT entries.  */
			cpu_flush_vhpt_range(v->processor, vadr, addr_range);
		}
	}
	// ptc.ga has release semantics.

	/* ptc.ga  */
	platform_global_tlb_purge(vadr, vadr + addr_range,
				  current->arch.vhpt_pg_shift);
	perfc_incr(domain_flush_vtlb_range);
}

#ifdef CONFIG_XEN_IA64_TLB_TRACK
#include <asm/tlb_track.h>
#include <asm/vmx_vcpu.h>
void
__domain_flush_vtlb_track_entry(struct domain* d,
                                const struct tlb_track_entry* entry)
{
	unsigned long rr7_rid;
	int swap_rr0 = 0;
	unsigned long old_rid;
	unsigned long vaddr = entry->vaddr;
	struct vcpu* v;
	int cpu;
	int vcpu;
	int local_purge = 1;

	/* tlb inert tracking is done in PAGE_SIZE uint. */
	unsigned char ps = max_t(unsigned char,
				 current->arch.vhpt_pg_shift, PAGE_SHIFT);
	/* This case isn't supported (yet). */
	BUG_ON(current->arch.vhpt_pg_shift > PAGE_SHIFT);
	
	BUG_ON((vaddr >> VRN_SHIFT) != VRN7);
	/*
	 * heuristic:
	 * dom0linux accesses grant mapped pages via the kernel
	 * straight mapped area and it doesn't change rr7 rid. 
	 * So it is likey that rr7 == entry->rid so that
	 * we can avoid rid change.
	 * When blktap is supported, this heuristic should be revised.
	 */
	vcpu_get_rr(current, VRN7 << VRN_SHIFT, &rr7_rid);
	if (likely(rr7_rid == entry->rid)) {
		perfc_incr(tlb_track_use_rr7);
	} else {
		swap_rr0 = 1;
		vaddr = (vaddr << 3) >> 3;// force vrn0
		perfc_incr(tlb_track_swap_rr0);
	}

	// tlb_track_entry_printf(entry);
	if (swap_rr0) {
		vcpu_get_rr(current, 0, &old_rid);
		vcpu_set_rr(current, 0, entry->rid);
	}
    
	if (HAS_PERVCPU_VHPT(d)) {
		for_each_vcpu_mask(d, vcpu, entry->vcpu_dirty_mask) {
			v = d->vcpu[vcpu];
			if (!v->is_initialised)
				continue;

			/* Invalidate VHPT entries.  */
			vcpu_flush_vhpt_range(v, vaddr, 1L << ps);

			/*
			 * current->processor == v->processor
			 * is racy. we may see old v->processor and
			 * a new physical processor of v might see old
			 * vhpt entry and insert tlb.
			 */
			if (v != current)
				local_purge = 0;
		}
	} else {
		for_each_cpu_mask(cpu, entry->pcpu_dirty_mask) {
			/* Invalidate VHPT entries.  */
			cpu_flush_vhpt_range(cpu, vaddr, 1L << ps);

			if (d->vcpu[cpu] != current)
				local_purge = 0;
		}
	}

	/* ptc.ga  */
	if (local_purge) {
		ia64_ptcl(vaddr, ps << 2);
		perfc_incr(domain_flush_vtlb_local);
	} else {
		/* ptc.ga has release semantics. */
		platform_global_tlb_purge(vaddr, vaddr + (1L << ps), ps);
		perfc_incr(domain_flush_vtlb_global);
	}

	if (swap_rr0) {
		vcpu_set_rr(current, 0, old_rid);
	}
	perfc_incr(domain_flush_vtlb_track_entry);
}

void
domain_flush_vtlb_track_entry(struct domain* d,
                              const struct tlb_track_entry* entry)
{
	domain_purge_swtc_entries_vcpu_dirty_mask(d, entry->vcpu_dirty_mask);
	smp_mb();

	__domain_flush_vtlb_track_entry(d, entry);
}

#endif

static void flush_tlb_vhpt_all (struct domain *d)
{
	/* First VHPT.  */
	local_vhpt_flush ();

	/* Then mTLB.  */
	local_flush_tlb_all ();
}

void domain_flush_tlb_vhpt(struct domain *d)
{
	/* Very heavy...  */
	if (HAS_PERVCPU_VHPT(d) || is_hvm_domain(d))
		on_each_cpu((void (*)(void *))local_flush_tlb_all, NULL, 1);
	else
		on_each_cpu((void (*)(void *))flush_tlb_vhpt_all, d, 1);
	cpumask_clear_cpu(d->domain_dirty_cpumask);
}

void flush_tlb_for_log_dirty(struct domain *d)
{
	struct vcpu *v;

	/* NB. There is no race because all vcpus are paused. */
	if (is_hvm_domain(d)) {
		for_each_vcpu (d, v) {
			if (!v->is_initialised)
				continue;
			/* XXX: local_flush_tlb_all is called redundantly */
			thash_purge_all(v);
		}
		smp_call_function((void (*)(void *))local_flush_tlb_all, 
					NULL, 1);
	} else if (HAS_PERVCPU_VHPT(d)) {
		for_each_vcpu (d, v) {
			if (!v->is_initialised)
				continue;
			vcpu_purge_tr_entry(&PSCBX(v,dtlb));
			vcpu_purge_tr_entry(&PSCBX(v,itlb));
			vcpu_vhpt_flush(v);
		}
		on_each_cpu((void (*)(void *))local_flush_tlb_all, NULL, 1);
	} else {
		on_each_cpu((void (*)(void *))flush_tlb_vhpt_all, d, 1);
	}
	cpumask_clear_cpu(d->domain_dirty_cpumask);
}

void flush_tlb_mask(const cpumask_t *mask)
{
    int cpu;

    cpu = smp_processor_id();
    if (cpu_isset(cpu, *mask))
        flush_tlb_vhpt_all (NULL);

    if (cpumask_subset(mask, cpumask_of(cpu)))
        return;

    for_each_cpu_mask (cpu, *mask)
        if (cpu != smp_processor_id())
            smp_call_function_single
                (cpu, (void (*)(void *))flush_tlb_vhpt_all, NULL, 1);
}

#ifdef PERF_COUNTERS
void gather_vhpt_stats(void)
{
	int i, cpu;

	perfc_set(vhpt_nbr_entries, VHPT_NUM_ENTRIES);

	for_each_present_cpu (cpu) {
		struct vhpt_lf_entry *v = __va(per_cpu(vhpt_paddr, cpu));
		unsigned long vhpt_valid = 0;

		for (i = 0; i < VHPT_NUM_ENTRIES; i++, v++)
			if (!(v->ti_tag & INVALID_TI_TAG))
				vhpt_valid++;
		per_cpu(perfcounters, cpu)[PERFC_vhpt_valid_entries] = vhpt_valid;
	}
}
#endif
