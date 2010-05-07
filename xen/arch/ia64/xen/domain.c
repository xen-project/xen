/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 *
 *  Copyright (C) 2005 Intel Co
 *	Kun Tian (Kevin Tian) <kevin.tian@intel.com>
 *
 * 05/04/29 Kun Tian (Kevin Tian) <kevin.tian@intel.com> Add VTI domain support
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *                    dom0 vp model support
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/mm.h>
#include <xen/iocap.h>
#include <asm/asm-xsi-offsets.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/version.h>
#include <xen/libelf.h>
#include <asm/pgalloc.h>
#include <asm/offsets.h>  /* for IA64_THREAD_INFO_SIZE */
#include <asm/vcpu.h>   /* for function declarations */
#include <public/xen.h>
#include <xen/domain.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_vpd.h>
#include <asm/vmx_phy_mode.h>
#include <asm/vmx_vcpu_save.h>
#include <asm/vhpt.h>
#include <asm/vcpu.h>
#include <asm/tlbflush.h>
#include <asm/regionreg.h>
#include <asm/dom_fw.h>
#include <asm/shadow.h>
#include <xen/guest_access.h>
#include <asm/tlb_track.h>
#include <asm/perfmon.h>
#include <asm/sal.h>
#include <public/vcpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <asm/debugger.h>

/* dom0_size: default memory allocation for dom0 (~4GB) */
static unsigned long __initdata dom0_size = 4096UL*1024UL*1024UL;

/* dom0_max_vcpus: maximum number of VCPUs to create for dom0.  */
static unsigned int __initdata dom0_max_vcpus = 4;
integer_param("dom0_max_vcpus", dom0_max_vcpus); 

extern char dom0_command_line[];

/* forward declaration */
static void init_switch_stack(struct vcpu *v);

/* Address of vpsr.i (in fact evtchn_upcall_mask) of current vcpu.
   This is a Xen virtual address.  */
DEFINE_PER_CPU(uint8_t *, current_psr_i_addr);
DEFINE_PER_CPU(int *, current_psr_ic_addr);

DEFINE_PER_CPU(struct vcpu *, fp_owner);

#include <xen/sched-if.h>

static void flush_vtlb_for_context_switch(struct vcpu* prev, struct vcpu* next)
{
	int cpu = smp_processor_id();
	int last_vcpu_id, last_processor;

	if (!is_idle_domain(prev->domain))
		tlbflush_update_time
			(&prev->domain->arch.last_vcpu[cpu].tlbflush_timestamp,
			 tlbflush_current_time());

	if (is_idle_domain(next->domain))
		return;

	last_vcpu_id = next->domain->arch.last_vcpu[cpu].vcpu_id;
	last_processor = next->arch.last_processor;

	next->domain->arch.last_vcpu[cpu].vcpu_id = next->vcpu_id;
	next->arch.last_processor = cpu;

	if ((last_vcpu_id != next->vcpu_id &&
	     last_vcpu_id != INVALID_VCPU_ID) ||
	    (last_vcpu_id == next->vcpu_id &&
	     last_processor != cpu &&
	     last_processor != INVALID_PROCESSOR)) {
#ifdef CONFIG_XEN_IA64_TLBFLUSH_CLOCK
		u32 last_tlbflush_timestamp =
			next->domain->arch.last_vcpu[cpu].tlbflush_timestamp;
#endif
		int vhpt_is_flushed = 0;

		// if the vTLB implementation was changed,
		// the followings must be updated either.
		if (VMX_DOMAIN(next)) {
			// currently vTLB for vt-i domian is per vcpu.
			// so any flushing isn't needed.
		} else if (HAS_PERVCPU_VHPT(next->domain)) {
			// nothing to do
		} else {
			if (NEED_FLUSH(__get_cpu_var(vhpt_tlbflush_timestamp),
			               last_tlbflush_timestamp)) {
				local_vhpt_flush();
				vhpt_is_flushed = 1;
			}
		}
		if (vhpt_is_flushed || NEED_FLUSH(__get_cpu_var(tlbflush_time),
		                                  last_tlbflush_timestamp)) {
			local_flush_tlb_all();
			perfc_incr(tlbflush_clock_cswitch_purge);
		} else {
			perfc_incr(tlbflush_clock_cswitch_skip);
		}
		perfc_incr(flush_vtlb_for_context_switch);
	}
}

static void flush_cache_for_context_switch(struct vcpu *next)
{
	extern cpumask_t cpu_cache_coherent_map;
	int cpu = smp_processor_id();

	if (is_idle_vcpu(next) ||
	    __test_and_clear_bit(cpu, &next->arch.cache_coherent_map)) {
		if (cpu_test_and_clear(cpu, cpu_cache_coherent_map)) {
			unsigned long flags;
			u64 progress = 0;
			s64 status;

			local_irq_save(flags);
			status = ia64_pal_cache_flush(4, 0, &progress, NULL);
			local_irq_restore(flags);
			if (status != 0)
				panic_domain(NULL, "PAL_CACHE_FLUSH ERROR, "
					     "cache_type=4 status %lx", status);
		}
	}
}

static void set_current_psr_i_addr(struct vcpu* v)
{
	__ia64_per_cpu_var(current_psr_i_addr) =
		(uint8_t*)(v->domain->arch.shared_info_va +
			   INT_ENABLE_OFFSET(v));
	__ia64_per_cpu_var(current_psr_ic_addr) = (int *)
		(v->domain->arch.shared_info_va + XSI_PSR_IC_OFS);
}

static void clear_current_psr_i_addr(void)
{
	__ia64_per_cpu_var(current_psr_i_addr) = NULL;
	__ia64_per_cpu_var(current_psr_ic_addr) = NULL;
}

static void lazy_fp_switch(struct vcpu *prev, struct vcpu *next)
{
	/*
	 * Implement eager save, lazy restore
	 */
	if (!is_idle_vcpu(prev)) {
		if (VMX_DOMAIN(prev)) {
			if (FP_PSR(prev) & IA64_PSR_MFH) {
				__ia64_save_fpu(prev->arch._thread.fph);
				__ia64_per_cpu_var(fp_owner) = prev;
			}
		} else {
			if (PSCB(prev, hpsr_mfh)) {
				__ia64_save_fpu(prev->arch._thread.fph);
				__ia64_per_cpu_var(fp_owner) = prev;
			}
		}
	}

	if (!is_idle_vcpu(next)) {
		if (VMX_DOMAIN(next)) {
			FP_PSR(next) = IA64_PSR_DFH;
			vcpu_regs(next)->cr_ipsr |= IA64_PSR_DFH;
		} else {
			PSCB(next, hpsr_dfh) = 1;
			PSCB(next, hpsr_mfh) = 0;
			vcpu_regs(next)->cr_ipsr |= IA64_PSR_DFH;
		}
	}
}

static void load_state(struct vcpu *v)
{
	load_region_regs(v);
	ia64_set_pta(vcpu_pta(v));
	vcpu_load_kernel_regs(v);
	if (vcpu_pkr_in_use(v))
		vcpu_pkr_load_regs(v);
	set_current_psr_i_addr(v);
}

void schedule_tail(struct vcpu *prev)
{
	extern char ia64_ivt;

	context_saved(prev);

	if (VMX_DOMAIN(current))
		vmx_do_resume(current);
	else {
		if (VMX_DOMAIN(prev))
			ia64_set_iva(&ia64_ivt);
		load_state(current);
		migrate_timer(&current->arch.hlt_timer, current->processor);
	}
	flush_vtlb_for_context_switch(prev, current);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    uint64_t spsr;

    local_irq_save(spsr);

    if (VMX_DOMAIN(prev)) {
        vmx_save_state(prev);
        if (!VMX_DOMAIN(next)) {
            /* VMX domains can change the physical cr.dcr.
             * Restore default to prevent leakage. */
            uint64_t dcr = ia64_getreg(_IA64_REG_CR_DCR);
            /* xenoprof:
             * don't change psr.pp.
             * It is manipulated by xenoprof.
             */
            dcr = (IA64_DEFAULT_DCR_BITS & ~IA64_DCR_PP) | (dcr & IA64_DCR_PP);
            ia64_setreg(_IA64_REG_CR_DCR, dcr);
        }
    }

    lazy_fp_switch(prev, current);

    if (prev->arch.dbg_used || next->arch.dbg_used) {
        /*
         * Load debug registers either because they are valid or to clear
         * the previous one.
         */
        ia64_load_debug_regs(next->arch.dbr);
    }
    
    /*
     * disable VHPT walker.
     * ia64_switch_to() might cause VHPT fault because it flushes
     * dtr[IA64_TR_VHPT] and reinsert the mapping with dtr[IA64_TR_STACK].
     * (VHPT_SIZE_LOG2 << 2) is just for avoiding
     * Reserved Register/Field fault.
     */
    ia64_set_pta(VHPT_SIZE_LOG2 << 2);
    prev = ia64_switch_to(next);

    /* Note: ia64_switch_to does not return here at vcpu initialization.  */

    if (VMX_DOMAIN(current)) {
        vmx_load_state(current);
    } else {
        extern char ia64_ivt;

        if (VMX_DOMAIN(prev))
            ia64_set_iva(&ia64_ivt);

        if (!is_idle_vcpu(current)) {
            load_state(current);
            vcpu_set_next_timer(current);
            if (vcpu_timer_expired(current))
                vcpu_pend_timer(current);
            /* steal time accounting */
            if (!guest_handle_is_null(runstate_guest(current)))
                __copy_to_guest(runstate_guest(current), &current->runstate, 1);
        } else {
            /* When switching to idle domain, only need to disable vhpt
             * walker. Then all accesses happen within idle context will
             * be handled by TR mapping and identity mapping.
             */
	     clear_current_psr_i_addr();
        }
    }
    local_irq_restore(spsr);

    /* lazy fp */
    if (current->processor != current->arch.last_processor) {
        unsigned long *addr;
        addr = (unsigned long *)per_cpu_addr(fp_owner,
                                             current->arch.last_processor);
        ia64_cmpxchg(acq, addr, current, 0, 8);
    }
   
    flush_vtlb_for_context_switch(prev, current);
    flush_cache_for_context_switch(current);
    context_saved(prev);
}

void continue_running(struct vcpu *same)
{
	/* nothing to do */
}

#ifdef CONFIG_PERFMON
static int pal_halt        = 1;
static int can_do_pal_halt = 1;

static int __init nohalt_setup(char * str)
{
       pal_halt = can_do_pal_halt = 0;
       return 1;
}
__setup("nohalt", nohalt_setup);

void
update_pal_halt_status(int status)
{
       can_do_pal_halt = pal_halt && status;
}
#else
#define can_do_pal_halt	(1)
#endif

static void default_idle(void)
{
	local_irq_disable();
	if ( cpu_is_haltable(smp_processor_id()) ) {
		if (can_do_pal_halt)
			safe_halt();
		else
			cpu_relax();
	}
	local_irq_enable();
}

extern void play_dead(void);

static void continue_cpu_idle_loop(void)
{
	int cpu = smp_processor_id();

	for ( ; ; )
	{
#ifdef IA64
//        __IRQ_STAT(cpu, idle_timestamp) = jiffies
#else
	    irq_stat[cpu].idle_timestamp = jiffies;
#endif
	    while ( cpu_is_haltable(cpu) )
	        default_idle();
	    raise_softirq(SCHEDULE_SOFTIRQ);
	    do_tasklet();
	    do_softirq();
	    if (!cpu_online(cpu))
	        play_dead();
	}
}

void startup_cpu_idle_loop(void)
{
	/* Just some sanity to ensure that the scheduler is set up okay. */
	ASSERT(current->domain->domain_id == IDLE_DOMAIN_ID);
	raise_softirq(SCHEDULE_SOFTIRQ);

	continue_cpu_idle_loop();
}

/* compile time test for get_order(sizeof(mapped_regs_t)) !=
 * get_order_from_shift(XMAPPEDREGS_SHIFT))
 */
#if !(((1 << (XMAPPEDREGS_SHIFT - 1)) < MAPPED_REGS_T_SIZE) && \
      (MAPPED_REGS_T_SIZE < (1 << (XMAPPEDREGS_SHIFT + 1))))
# error "XMAPPEDREGS_SHIFT doesn't match sizeof(mapped_regs_t)."
#endif

void hlt_timer_fn(void *data)
{
	struct vcpu *v = data;
	vcpu_unblock(v);
}

void relinquish_vcpu_resources(struct vcpu *v)
{
	if (HAS_PERVCPU_VHPT(v->domain))
		pervcpu_vhpt_free(v);
	if (v->arch.privregs != NULL) {
		free_xenheap_pages(v->arch.privregs,
		                   get_order_from_shift(XMAPPEDREGS_SHIFT));
		v->arch.privregs = NULL;
	}
	kill_timer(&v->arch.hlt_timer);
}

struct domain *alloc_domain_struct(void)
{
	struct domain *d;
#ifdef CONFIG_IA64_PICKLE_DOMAIN
	/*
	 * We pack the MFN of the domain structure into a 32-bit field within
	 * the page_info structure. Hence the MEMF_bits() restriction.
	 */
	d = alloc_xenheap_pages(get_order_from_bytes(sizeof(*d)),
				MEMF_bits(32 + PAGE_SHIFT));
#else
	d = xmalloc(struct domain);
#endif

	if ( d != NULL )
		memset(d, 0, sizeof(*d));
	return d;
}

void free_domain_struct(struct domain *d)
{
#ifdef CONFIG_IA64_PICKLE_DOMAIN
	free_xenheap_pages(d, get_order_from_bytes(sizeof(*d)));
#else
	xfree(d);
#endif
}

struct vcpu *alloc_vcpu_struct(void)
{
	struct page_info *page;
	struct vcpu *v;
	struct thread_info *ti;
	static int first_allocation = 1;

	if (first_allocation) {
		first_allocation = 0;
		/* Still keep idle vcpu0 static allocated at compilation, due
		 * to some code from Linux still requires it in early phase.
		 */
		return idle_vcpu[0];
	}

	page = alloc_domheap_pages(NULL, KERNEL_STACK_SIZE_ORDER, 0);
	if (page == NULL)
		return NULL;
	v = page_to_virt(page);
	memset(v, 0, sizeof(*v)); 

	ti = alloc_thread_info(v);
	/* Clear thread_info to clear some important fields, like
	 * preempt_count
	 */
	memset(ti, 0, sizeof(struct thread_info));
	init_switch_stack(v);

	return v;
}

void free_vcpu_struct(struct vcpu *v)
{
	free_domheap_pages(virt_to_page(v), KERNEL_STACK_SIZE_ORDER);
}

int vcpu_initialise(struct vcpu *v)
{
	struct domain *d = v->domain;

	if (!is_idle_domain(d)) {
	    v->arch.metaphysical_rid_dt = d->arch.metaphysical_rid_dt;
	    v->arch.metaphysical_rid_d = d->arch.metaphysical_rid_d;
	    /* Set default values to saved_rr.  */
	    v->arch.metaphysical_saved_rr0 = d->arch.metaphysical_rid_dt;
	    v->arch.metaphysical_saved_rr4 = d->arch.metaphysical_rid_dt;

	    /* Is it correct ?
	       It depends on the domain rid usage.

	       A domain may share rid among its processor (eg having a
	       global VHPT).  In this case, we should also share rid
	       among vcpus and the rid range should be the same.

	       However a domain may have per cpu rid allocation.  In
	       this case we don't want to share rid among vcpus, but we may
	       do it if two vcpus are on the same cpu... */

	    v->arch.starting_rid = d->arch.starting_rid;
	    v->arch.ending_rid = d->arch.ending_rid;
	    v->arch.rid_bits = d->arch.rid_bits;
	    v->arch.breakimm = d->arch.breakimm;
	    v->arch.last_processor = INVALID_PROCESSOR;
	    v->arch.vhpt_pg_shift = PAGE_SHIFT;
	}

	if (!VMX_DOMAIN(v))
		init_timer(&v->arch.hlt_timer, hlt_timer_fn, v,
		           first_cpu(cpu_online_map));

	return 0;
}

static void vcpu_share_privregs_with_guest(struct vcpu *v)
{
	struct domain *d = v->domain;
	int i, order = get_order_from_shift(XMAPPEDREGS_SHIFT); 

	for (i = 0; i < (1 << order); i++)
		share_xen_page_with_guest(virt_to_page(v->arch.privregs) + i,
		                          d, XENSHARE_writable);
	/*
	 * XXX IA64_XMAPPEDREGS_PADDR
	 * assign these pages into guest pseudo physical address
	 * space for dom0 to map this page by gmfn.
	 * this is necessary for domain save, restore and dump-core.
	 */
	for (i = 0; i < XMAPPEDREGS_SIZE; i += PAGE_SIZE)
		assign_domain_page(d, IA64_XMAPPEDREGS_PADDR(v->vcpu_id) + i,
		                   virt_to_maddr(v->arch.privregs + i));
}

int vcpu_late_initialise(struct vcpu *v)
{
	int rc, order;

	if (HAS_PERVCPU_VHPT(v->domain)) {
		rc = pervcpu_vhpt_alloc(v);
		if (rc != 0)
			return rc;
	}

	/* Create privregs page. */
	order = get_order_from_shift(XMAPPEDREGS_SHIFT);
	v->arch.privregs = alloc_xenheap_pages(order, 0);
	if (v->arch.privregs == NULL)
		return -ENOMEM;
	BUG_ON(v->arch.privregs == NULL);
	memset(v->arch.privregs, 0, 1 << XMAPPEDREGS_SHIFT);
	vcpu_share_privregs_with_guest(v);

	return 0;
}

void vcpu_destroy(struct vcpu *v)
{
	if (is_hvm_vcpu(v))
		vmx_relinquish_vcpu_resources(v);
	else
		relinquish_vcpu_resources(v);
}

static unsigned long*
vcpu_to_rbs_bottom(struct vcpu *v)
{
	return (unsigned long*)((char *)v + IA64_RBS_OFFSET);
}

static void init_switch_stack(struct vcpu *v)
{
	struct pt_regs *regs = vcpu_regs (v);
	struct switch_stack *sw = (struct switch_stack *) regs - 1;
	extern void ia64_ret_from_clone;

	memset(sw, 0, sizeof(struct switch_stack) + sizeof(struct pt_regs));
	sw->ar_bspstore = (unsigned long)vcpu_to_rbs_bottom(v);
	sw->b0 = (unsigned long) &ia64_ret_from_clone;
	sw->ar_fpsr = FPSR_DEFAULT;
	v->arch._thread.ksp = (unsigned long) sw - 16;
	// stay on kernel stack because may get interrupts!
	// ia64_ret_from_clone switches to user stack
	v->arch._thread.on_ustack = 0;
	memset(v->arch._thread.fph,0,sizeof(struct ia64_fpreg)*96);
}

#ifdef CONFIG_XEN_IA64_PERVCPU_VHPT
static int opt_pervcpu_vhpt = 1;
integer_param("pervcpu_vhpt", opt_pervcpu_vhpt);
#endif

int arch_domain_create(struct domain *d, unsigned int domcr_flags)
{
	int i;

	// the following will eventually need to be negotiated dynamically
	d->arch.shared_info_va = DEFAULT_SHAREDINFO_ADDR;
	d->arch.breakimm = __IA64_XEN_HYPERCALL_DEFAULT;
	for (i = 0; i < NR_CPUS; i++) {
		d->arch.last_vcpu[i].vcpu_id = INVALID_VCPU_ID;
	}

	if (is_idle_domain(d))
	    return 0;

	INIT_LIST_HEAD(&d->arch.pdev_list);
	foreign_p2m_init(d);
#ifdef CONFIG_XEN_IA64_PERVCPU_VHPT
	d->arch.has_pervcpu_vhpt = opt_pervcpu_vhpt;
	dprintk(XENLOG_INFO, "%s:%d domain %d pervcpu_vhpt %d\n",
	        __func__, __LINE__, d->domain_id, d->arch.has_pervcpu_vhpt);
#endif
	if (tlb_track_create(d) < 0)
		goto fail_nomem1;
	d->shared_info = alloc_xenheap_pages(
		get_order_from_shift(XSI_SHIFT), 0);
	if (d->shared_info == NULL)
		goto fail_nomem;
	BUG_ON(d->shared_info == NULL);
	memset(d->shared_info, 0, XSI_SIZE);
	for (i = 0; i < XSI_SIZE; i += PAGE_SIZE)
	    share_xen_page_with_guest(virt_to_page((char *)d->shared_info + i),
	                              d, XENSHARE_writable);

	/* We may also need emulation rid for region4, though it's unlikely
	 * to see guest issue uncacheable access in metaphysical mode. But
	 * keep such info here may be more sane.
	 */
	if (!allocate_rid_range(d,0))
		goto fail_nomem;

	memset(&d->arch.mm, 0, sizeof(d->arch.mm));
	d->arch.relres = RELRES_not_started;
	d->arch.mm_teardown_offset = 0;
	INIT_PAGE_LIST_HEAD(&d->arch.relmem_list);

	if ((d->arch.mm.pgd = pgd_alloc(&d->arch.mm)) == NULL)
	    goto fail_nomem;

	if(iommu_domain_init(d) != 0)
		goto fail_iommu;

	/*
	 * grant_table_create() can't fully initialize grant table for domain
	 * because it is called before arch_domain_create().
	 * Here we complete the initialization which requires p2m table.
	 */
	spin_lock(&d->grant_table->lock);
	for (i = 0; i < nr_grant_frames(d->grant_table); i++)
		ia64_gnttab_create_shared_page(d, d->grant_table, i);
	spin_unlock(&d->grant_table->lock);

	d->arch.ioport_caps = rangeset_new(d, "I/O Ports",
	                                   RANGESETF_prettyprint_hex);

	dprintk(XENLOG_DEBUG, "arch_domain_create: domain=%p\n", d);
	return 0;

fail_iommu:
	iommu_domain_destroy(d);
fail_nomem:
	tlb_track_destroy(d);
fail_nomem1:
	if (d->arch.mm.pgd != NULL)
	    pgd_free(d->arch.mm.pgd);
	if (d->shared_info != NULL)
	    free_xenheap_pages(d->shared_info,
			       get_order_from_shift(XSI_SHIFT));
	return -ENOMEM;
}

void arch_domain_destroy(struct domain *d)
{
	mm_final_teardown(d);

	if (d->shared_info != NULL)
		free_xenheap_pages(d->shared_info,
				   get_order_from_shift(XSI_SHIFT));

	if ( iommu_enabled && need_iommu(d) )	{
		pci_release_devices(d);
		iommu_domain_destroy(d);
	}

	tlb_track_destroy(d);

	/* Clear vTLB for the next domain.  */
	domain_flush_tlb_vhpt(d);

	deallocate_rid_range(d);
}

void arch_vcpu_reset(struct vcpu *v)
{
	/* FIXME: Stub for now */
}

/* Here it is assumed that all of the CPUs has same RSE.N_STACKED_PHYS */
static unsigned long num_phys_stacked;
static int __init
init_num_phys_stacked(void)
{
	switch (ia64_pal_rse_info(&num_phys_stacked, NULL)) {
	case 0L:
		printk("the number of physical stacked general registers"
		       "(RSE.N_STACKED_PHYS) = %ld\n", num_phys_stacked);
		return 0;
	case -2L:
	case -3L:
	default:
		break;
	}
	printk("WARNING: PAL_RSE_INFO call failed. "
	       "domain save/restore may NOT work!\n");
	return -EINVAL;
}
__initcall(init_num_phys_stacked);

#define COPY_FPREG(dst, src) memcpy(dst, src, sizeof(struct ia64_fpreg))

#define AR_PFS_PEC_SHIFT	51
#define AR_PFS_REC_SIZE		6
#define AR_PFS_PEC_MASK		(((1UL << 6) - 1) << 51)

/*
 * See init_swtich_stack() and ptrace.h
 */
static struct switch_stack*
vcpu_to_switch_stack(struct vcpu* v)
{
	return (struct switch_stack *)(v->arch._thread.ksp + 16);
}

static int
vcpu_has_not_run(struct vcpu* v)
{
	extern void ia64_ret_from_clone;
	struct switch_stack *sw = vcpu_to_switch_stack(v);

	return (sw == (struct switch_stack *)(vcpu_regs(v)) - 1) &&
		(sw->b0 == (unsigned long)&ia64_ret_from_clone);
}

static void
nats_update(unsigned int* nats, unsigned int reg, char nat)
{
	BUG_ON(reg > 31);

	if (nat)
		*nats |= (1UL << reg);
	else
		*nats &= ~(1UL << reg);
}

static unsigned long
__vcpu_get_itc(struct vcpu *v)
{
	unsigned long itc_last;
	unsigned long itc_offset;
	unsigned long itc;

	if (unlikely(v->arch.privregs == NULL))
		return ia64_get_itc();
	
	itc_last = v->arch.privregs->itc_last;
	itc_offset = v->arch.privregs->itc_offset;
	itc = ia64_get_itc();
	itc += itc_offset;
	if (itc_last >= itc)
		itc = itc_last;
	return itc;
}

static void
__vcpu_set_itc(struct vcpu *v, u64 val)
{
	unsigned long itc;
	unsigned long itc_offset;
	unsigned long itc_last;

	BUG_ON(v->arch.privregs == NULL);

	if (v != current)
		vcpu_pause(v);
	
	itc = ia64_get_itc();
	itc_offset = val - itc;
	itc_last = val;
	
	v->arch.privregs->itc_offset = itc_offset;
	v->arch.privregs->itc_last = itc_last;

	if (v != current)
		vcpu_unpause(v);
}

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
	int i;
	struct vcpu_tr_regs *tr = &c.nat->regs.tr;
	struct cpu_user_regs *uregs = vcpu_regs(v);
	struct switch_stack *sw = vcpu_to_switch_stack(v);
	struct unw_frame_info info;
	int is_hvm = VMX_DOMAIN(v);
	unsigned int rbs_size;
	unsigned long *const rbs_bottom = vcpu_to_rbs_bottom(v);
	unsigned long *rbs_top;
	unsigned long *rbs_rnat_addr;
	unsigned int top_slot;
	unsigned int num_regs;

	memset(c.nat, 0, sizeof(*c.nat));
	c.nat->regs.b[6] = uregs->b6;
	c.nat->regs.b[7] = uregs->b7;

	memset(&info, 0, sizeof(info));
	unw_init_from_blocked_task(&info, v);
	if (vcpu_has_not_run(v)) {
		c.nat->regs.ar.lc = sw->ar_lc;
		c.nat->regs.ar.ec =
			(sw->ar_pfs & AR_PFS_PEC_MASK) >> AR_PFS_PEC_SHIFT;
	} else if (unw_unwind_to_user(&info) < 0) {
		/* warn: should panic? */
		gdprintk(XENLOG_ERR, "vcpu=%d unw_unwind_to_user() failed.\n",
			 v->vcpu_id);
		show_stack(v, NULL);

		/* can't return error */
		c.nat->regs.ar.lc = 0;
		c.nat->regs.ar.ec = 0;
	} else {
		unw_get_ar(&info, UNW_AR_LC, &c.nat->regs.ar.lc);
		unw_get_ar(&info, UNW_AR_EC, &c.nat->regs.ar.ec);
	}

	if (!is_hvm)
		c.nat->regs.ar.itc = __vcpu_get_itc(v);

	c.nat->regs.ar.csd = uregs->ar_csd;
	c.nat->regs.ar.ssd = uregs->ar_ssd;

	c.nat->regs.r[8] = uregs->r8;
	c.nat->regs.r[9] = uregs->r9;
	c.nat->regs.r[10] = uregs->r10;
	c.nat->regs.r[11] = uregs->r11;

	if (is_hvm)
		c.nat->regs.psr = vmx_vcpu_get_psr(v);
	else
		c.nat->regs.psr = vcpu_get_psr(v);

	c.nat->regs.ip = uregs->cr_iip;
	c.nat->regs.cfm = uregs->cr_ifs;

	c.nat->regs.ar.unat = uregs->ar_unat;
	c.nat->regs.ar.pfs = uregs->ar_pfs;
	c.nat->regs.ar.rsc = uregs->ar_rsc;
	c.nat->regs.ar.rnat = uregs->ar_rnat;
	c.nat->regs.ar.bspstore = uregs->ar_bspstore;

	c.nat->regs.pr = uregs->pr;
	c.nat->regs.b[0] = uregs->b0;
	rbs_size = uregs->loadrs >> 16;
	num_regs = ia64_rse_num_regs(rbs_bottom,
			(unsigned long*)((char*)rbs_bottom + rbs_size));
	c.nat->regs.ar.bsp = (unsigned long)ia64_rse_skip_regs(
		(unsigned long*)c.nat->regs.ar.bspstore, num_regs);
	BUG_ON(num_regs > num_phys_stacked);

	c.nat->regs.r[1] = uregs->r1;
	c.nat->regs.r[12] = uregs->r12;
	c.nat->regs.r[13] = uregs->r13;
	c.nat->regs.ar.fpsr = uregs->ar_fpsr;
	c.nat->regs.r[15] = uregs->r15;

	c.nat->regs.r[14] = uregs->r14;
	c.nat->regs.r[2] = uregs->r2;
	c.nat->regs.r[3] = uregs->r3;
	c.nat->regs.r[16] = uregs->r16;
	c.nat->regs.r[17] = uregs->r17;
	c.nat->regs.r[18] = uregs->r18;
	c.nat->regs.r[19] = uregs->r19;
	c.nat->regs.r[20] = uregs->r20;
	c.nat->regs.r[21] = uregs->r21;
	c.nat->regs.r[22] = uregs->r22;
	c.nat->regs.r[23] = uregs->r23;
	c.nat->regs.r[24] = uregs->r24;
	c.nat->regs.r[25] = uregs->r25;
	c.nat->regs.r[26] = uregs->r26;
	c.nat->regs.r[27] = uregs->r27;
	c.nat->regs.r[28] = uregs->r28;
	c.nat->regs.r[29] = uregs->r29;
	c.nat->regs.r[30] = uregs->r30;
	c.nat->regs.r[31] = uregs->r31;

	c.nat->regs.ar.ccv = uregs->ar_ccv;

	COPY_FPREG(&c.nat->regs.f[2], &sw->f2);
	COPY_FPREG(&c.nat->regs.f[3], &sw->f3);
	COPY_FPREG(&c.nat->regs.f[4], &sw->f4);
	COPY_FPREG(&c.nat->regs.f[5], &sw->f5);

	COPY_FPREG(&c.nat->regs.f[6], &uregs->f6);
	COPY_FPREG(&c.nat->regs.f[7], &uregs->f7);
	COPY_FPREG(&c.nat->regs.f[8], &uregs->f8);
	COPY_FPREG(&c.nat->regs.f[9], &uregs->f9);
	COPY_FPREG(&c.nat->regs.f[10], &uregs->f10);
	COPY_FPREG(&c.nat->regs.f[11], &uregs->f11);

	COPY_FPREG(&c.nat->regs.f[12], &sw->f12);
	COPY_FPREG(&c.nat->regs.f[13], &sw->f13);
	COPY_FPREG(&c.nat->regs.f[14], &sw->f14);
	COPY_FPREG(&c.nat->regs.f[15], &sw->f15);
	COPY_FPREG(&c.nat->regs.f[16], &sw->f16);
	COPY_FPREG(&c.nat->regs.f[17], &sw->f17);
	COPY_FPREG(&c.nat->regs.f[18], &sw->f18);
	COPY_FPREG(&c.nat->regs.f[19], &sw->f19);
	COPY_FPREG(&c.nat->regs.f[20], &sw->f20);
	COPY_FPREG(&c.nat->regs.f[21], &sw->f21);
	COPY_FPREG(&c.nat->regs.f[22], &sw->f22);
	COPY_FPREG(&c.nat->regs.f[23], &sw->f23);
	COPY_FPREG(&c.nat->regs.f[24], &sw->f24);
	COPY_FPREG(&c.nat->regs.f[25], &sw->f25);
	COPY_FPREG(&c.nat->regs.f[26], &sw->f26);
	COPY_FPREG(&c.nat->regs.f[27], &sw->f27);
	COPY_FPREG(&c.nat->regs.f[28], &sw->f28);
	COPY_FPREG(&c.nat->regs.f[29], &sw->f29);
	COPY_FPREG(&c.nat->regs.f[30], &sw->f30);
	COPY_FPREG(&c.nat->regs.f[31], &sw->f31);

	// f32 - f127
	memcpy(&c.nat->regs.f[32], &v->arch._thread.fph[0],
	       sizeof(v->arch._thread.fph));

#define NATS_UPDATE(reg)						\
	nats_update(&c.nat->regs.nats, (reg),				\
		    !!(uregs->eml_unat &				\
		       (1UL << ia64_unat_pos(&uregs->r ## reg))))

	// corresponding bit in ar.unat is determined by
	// (&uregs->rN){8:3}.
	// r8: the lowest gr member of struct cpu_user_regs.
	// r7: the highest gr member of struct cpu_user_regs.
	BUILD_BUG_ON(offsetof(struct cpu_user_regs, r7) -
		     offsetof(struct cpu_user_regs, r8) >
		     64 * sizeof(unsigned long));

	NATS_UPDATE(1);
	NATS_UPDATE(2);
	NATS_UPDATE(3);

	NATS_UPDATE(8);
	NATS_UPDATE(9);
	NATS_UPDATE(10);
	NATS_UPDATE(11);
	NATS_UPDATE(12);
	NATS_UPDATE(13);
	NATS_UPDATE(14);
	NATS_UPDATE(15);
	NATS_UPDATE(16);
	NATS_UPDATE(17);
	NATS_UPDATE(18);
	NATS_UPDATE(19);
	NATS_UPDATE(20);
	NATS_UPDATE(21);
	NATS_UPDATE(22);
	NATS_UPDATE(23);
	NATS_UPDATE(24);
	NATS_UPDATE(25);
	NATS_UPDATE(26);
	NATS_UPDATE(27);
	NATS_UPDATE(28);
	NATS_UPDATE(29);
	NATS_UPDATE(30);
	NATS_UPDATE(31);
	
	if (!is_hvm) {
		c.nat->regs.r[4] = uregs->r4;
		c.nat->regs.r[5] = uregs->r5;
		c.nat->regs.r[6] = uregs->r6;
		c.nat->regs.r[7] = uregs->r7;

		NATS_UPDATE(4);
		NATS_UPDATE(5);
		NATS_UPDATE(6);
		NATS_UPDATE(7);
#undef NATS_UPDATE
	} else {
		/*
		 * for VTi domain, r[4-7] are saved sometimes both in
		 * uregs->r[4-7] and memory stack or only in memory stack.
		 * So it is ok to get them from memory stack.
		 */
		if (vcpu_has_not_run(v)) {
			c.nat->regs.r[4] = sw->r4;
			c.nat->regs.r[5] = sw->r5;
			c.nat->regs.r[6] = sw->r6;
			c.nat->regs.r[7] = sw->r7;

			nats_update(&c.nat->regs.nats, 4,
				    !!(sw->ar_unat &
				       (1UL << ia64_unat_pos(&sw->r4))));
			nats_update(&c.nat->regs.nats, 5,
				    !!(sw->ar_unat &
				       (1UL << ia64_unat_pos(&sw->r5))));
			nats_update(&c.nat->regs.nats, 6,
				    !!(sw->ar_unat &
				       (1UL << ia64_unat_pos(&sw->r6))));
			nats_update(&c.nat->regs.nats, 7,
				    !!(sw->ar_unat &
				       (1UL << ia64_unat_pos(&sw->r7))));
		} else {
			char nat;

			unw_get_gr(&info, 4, &c.nat->regs.r[4], &nat);
			nats_update(&c.nat->regs.nats, 4, nat);
			unw_get_gr(&info, 5, &c.nat->regs.r[5], &nat);
			nats_update(&c.nat->regs.nats, 5, nat);
			unw_get_gr(&info, 6, &c.nat->regs.r[6], &nat);
			nats_update(&c.nat->regs.nats, 6, nat);
			unw_get_gr(&info, 7, &c.nat->regs.r[7], &nat);
			nats_update(&c.nat->regs.nats, 7, nat);
		}
	}

	c.nat->regs.rbs_voff = (IA64_RBS_OFFSET / 8) % 64;
	if (unlikely(rbs_size > sizeof(c.nat->regs.rbs)))
		gdprintk(XENLOG_INFO,
			 "rbs_size is too large 0x%x > 0x%lx\n",
			 rbs_size, sizeof(c.nat->regs.rbs));
	else
		memcpy(c.nat->regs.rbs, rbs_bottom, rbs_size);

	rbs_top = (unsigned long*)((char *)rbs_bottom + rbs_size) - 1;
	rbs_rnat_addr = ia64_rse_rnat_addr(rbs_top);
	if ((unsigned long)rbs_rnat_addr >= sw->ar_bspstore)
		rbs_rnat_addr = &sw->ar_rnat;

	top_slot = ia64_rse_slot_num(rbs_top);

	c.nat->regs.rbs_rnat = (*rbs_rnat_addr) & ((1UL << top_slot) - 1);
	if (ia64_rse_rnat_addr(rbs_bottom) == ia64_rse_rnat_addr(rbs_top)) {
		unsigned int bottom_slot = ia64_rse_slot_num(rbs_bottom);
		c.nat->regs.rbs_rnat &= ~((1UL << bottom_slot) - 1);
	}

	c.nat->regs.num_phys_stacked = num_phys_stacked;

	if (VMX_DOMAIN(v))
		c.nat->privregs_pfn = VGC_PRIVREGS_HVM;
	else
		c.nat->privregs_pfn = get_gpfn_from_mfn(
			virt_to_maddr(v->arch.privregs) >> PAGE_SHIFT);

	for (i = 0; i < IA64_NUM_DBG_REGS; i++) {
		if (VMX_DOMAIN(v)) {
			vmx_vcpu_get_dbr(v, i, &c.nat->regs.dbr[i]);
			vmx_vcpu_get_ibr(v, i, &c.nat->regs.ibr[i]);
		} else {
			vcpu_get_dbr(v, i, &c.nat->regs.dbr[i]);
			vcpu_get_ibr(v, i, &c.nat->regs.ibr[i]);
		}
	}

	for (i = 0; i < 8; i++)
		vcpu_get_rr(v, (unsigned long)i << 61, &c.nat->regs.rr[i]);

	/* Fill extra regs.  */
	for (i = 0;
	     (i < sizeof(tr->itrs) / sizeof(tr->itrs[0])) && i < NITRS;
	     i++) {
		tr->itrs[i].pte = v->arch.itrs[i].pte.val;
		tr->itrs[i].itir = v->arch.itrs[i].itir;
		tr->itrs[i].vadr = v->arch.itrs[i].vadr;
		tr->itrs[i].rid = v->arch.itrs[i].rid;
	}
	for (i = 0;
	     (i < sizeof(tr->dtrs) / sizeof(tr->dtrs[0])) && i < NDTRS;
	     i++) {
		tr->dtrs[i].pte = v->arch.dtrs[i].pte.val;
		tr->dtrs[i].itir = v->arch.dtrs[i].itir;
		tr->dtrs[i].vadr = v->arch.dtrs[i].vadr;
		tr->dtrs[i].rid = v->arch.dtrs[i].rid;
	}
	c.nat->event_callback_ip = v->arch.event_callback_ip;

	/* If PV and privregs is not set, we can't read mapped registers.  */
 	if (!is_hvm_vcpu(v) && v->arch.privregs == NULL)
		return;

	vcpu_get_dcr(v, &c.nat->regs.cr.dcr);

	c.nat->regs.cr.itm = is_hvm_vcpu(v) ?
		vmx_vcpu_get_itm(v) : PSCBX(v, domain_itm);
	vcpu_get_iva(v, &c.nat->regs.cr.iva);
	vcpu_get_pta(v, &c.nat->regs.cr.pta);

	vcpu_get_ipsr(v, &c.nat->regs.cr.ipsr);
	vcpu_get_isr(v, &c.nat->regs.cr.isr);
	vcpu_get_iip(v, &c.nat->regs.cr.iip);
	vcpu_get_ifa(v, &c.nat->regs.cr.ifa);
	vcpu_get_itir(v, &c.nat->regs.cr.itir);
	vcpu_get_iha(v, &c.nat->regs.cr.iha);

	//XXX change irr[] and arch.insvc[]
	if (is_hvm_vcpu(v))
		/* c.nat->regs.cr.ivr = vmx_vcpu_get_ivr(v)*/;//XXXnot SMP-safe
	else
		vcpu_get_ivr (v, &c.nat->regs.cr.ivr);
	vcpu_get_iim(v, &c.nat->regs.cr.iim);

	vcpu_get_tpr(v, &c.nat->regs.cr.tpr);
	vcpu_get_irr0(v, &c.nat->regs.cr.irr[0]);
	vcpu_get_irr1(v, &c.nat->regs.cr.irr[1]);
	vcpu_get_irr2(v, &c.nat->regs.cr.irr[2]);
	vcpu_get_irr3(v, &c.nat->regs.cr.irr[3]);
	vcpu_get_itv(v, &c.nat->regs.cr.itv);//XXX vlsapic
	vcpu_get_pmv(v, &c.nat->regs.cr.pmv);
	vcpu_get_cmcv(v, &c.nat->regs.cr.cmcv);

	if (is_hvm)
		vmx_arch_get_info_guest(v, c);
}

#if 0
// for debug
static void
__rbs_print(const char* func, int line, const char* name,
	    const unsigned long* rbs, unsigned int rbs_size)
{
	unsigned int i;
	printk("%s:%d %s rbs %p\n", func, line, name, rbs);
	printk("   rbs_size 0x%016x no 0x%lx\n",
	       rbs_size, rbs_size / sizeof(unsigned long));

	for (i = 0; i < rbs_size / sizeof(unsigned long); i++) {
		const char* zero_or_n = "0x";
		if (ia64_rse_is_rnat_slot((unsigned long*)&rbs[i]))
			zero_or_n = "Nx";

		if ((i % 3) == 0)
			printk("0x%02x:", i);
		printk(" %s%016lx", zero_or_n, rbs[i]);
		if ((i % 3) == 2)
			printk("\n");
	}
	printk("\n");		
}

#define rbs_print(rbs, rbs_size)				\
	__rbs_print(__func__, __LINE__, (#rbs), (rbs), (rbs_size))
#endif

static int
copy_rbs(struct vcpu* v, unsigned long* dst_rbs_size,
	 const unsigned long* rbs, unsigned long rbs_size,
	 unsigned long src_rnat, unsigned long rbs_voff)
{
	int rc = -EINVAL;
	struct page_info* page;
	unsigned char* vaddr;
	unsigned long* src_bsp;
	unsigned long* src_bspstore;

	struct switch_stack* sw = vcpu_to_switch_stack(v);
	unsigned long num_regs;
	unsigned long* dst_bsp;
	unsigned long* dst_bspstore;
	unsigned long* dst_rnat;
	unsigned long dst_rnat_tmp;
	unsigned long dst_rnat_mask;
	unsigned long flags;
	extern void ia64_copy_rbs(unsigned long* dst_bspstore,
				  unsigned long* dst_rbs_size,
				  unsigned long* dst_rnat_p,
				  unsigned long* src_bsp,
				  unsigned long src_rbs_size,
				  unsigned long src_rnat);

	dst_bspstore = vcpu_to_rbs_bottom(v);
	*dst_rbs_size = rbs_size;
	if (rbs_size == 0)
		return 0;
	
	// rbs offset depends on sizeof(struct vcpu) so that
	// it's too unstable for hypercall ABI.
	// we need to take rbs offset into acount.
	//memcpy(dst_bspstore, c.nat->regs.rbs, rbs_size);

	// It is assumed that rbs_size is small enough compared
	// to KERNEL_STACK_SIZE.
	page = alloc_domheap_pages(NULL, KERNEL_STACK_SIZE_ORDER, 0);
	if (page == NULL)
		return -ENOMEM;
	vaddr = page_to_virt(page);

	src_bspstore = (unsigned long*)(vaddr + rbs_voff * 8);
	src_bsp = (unsigned long*)((unsigned char*)src_bspstore + rbs_size);
	if ((unsigned long)src_bsp >= (unsigned long)vaddr + PAGE_SIZE)
		goto out;
	memcpy(src_bspstore, rbs, rbs_size);
	
	num_regs = ia64_rse_num_regs(src_bspstore, src_bsp);
	dst_bsp = ia64_rse_skip_regs(dst_bspstore, num_regs);
	*dst_rbs_size = (unsigned long)dst_bsp - (unsigned long)dst_bspstore;

	// rough check.
	if (((unsigned long)dst_bsp & ~PAGE_MASK) > KERNEL_STACK_SIZE / 2)
		goto out;

	// ia64_copy_rbs() uses real cpu's stack register.
	// So it may fault with an Illigal Operation fault resulting
	// in panic if rbs_size is too large to load compared to
	// the number of physical stacked registers, RSE.N_STACKED_PHYS,
	// which is cpu implementatin specific.
	// See SDM vol. 2  Register Stack Engine 6, especially 6.5.5.
	//
	// For safe operation and cpu model independency, 
	// we need to copy them by hand without loadrs and flushrs
	// However even if we implement that, similar issue still occurs
	// when running guest. CPU context restore routine issues loadrs
	// resulting in Illegal Operation fault. And what if the vRSE is in
	// enforced lazy mode? We can't store any dirty stacked registers
	// into RBS without cover or br.call.
	if (num_regs > num_phys_stacked) {
		rc = -ENOSYS;
		gdprintk(XENLOG_WARNING,
			 "%s:%d domain %d: can't load stacked registres\n"
			 "requested size 0x%lx => 0x%lx, num regs %ld"
			 "RSE.N_STACKED_PHYS %ld\n",
			 __func__, __LINE__, v->domain->domain_id, 
			 rbs_size, *dst_rbs_size, num_regs,
			 num_phys_stacked);
		goto out;
	}

	// we mask interrupts to avoid using register backing store.
	local_irq_save(flags);
	ia64_copy_rbs(dst_bspstore, dst_rbs_size, &dst_rnat_tmp,
		      src_bsp, rbs_size, src_rnat);
	local_irq_restore(flags);

	dst_rnat_mask = (1UL << ia64_rse_slot_num(dst_bsp)) - 1;
	dst_rnat = ia64_rse_rnat_addr(dst_bsp);
	if ((unsigned long)dst_rnat > sw->ar_bspstore)
		dst_rnat = &sw->ar_rnat;
	// if ia64_rse_rnat_addr(dst_bsp) ==
	// ia64_rse_rnat_addr(vcpu_to_rbs_bottom(v)), the lsb bit of rnat
	// is just ignored. so we don't have to mask it out.
	*dst_rnat =
		(*dst_rnat & ~dst_rnat_mask) | (dst_rnat_tmp & dst_rnat_mask);
	
	rc = 0;
out:
	free_domheap_pages(page, KERNEL_STACK_SIZE_ORDER);
	return rc;
}

static void
unat_update(unsigned long *unat_eml, unsigned long *spill_addr, char nat)
{
	unsigned int pos = ia64_unat_pos(spill_addr);
	if (nat)
		*unat_eml |= (1UL << pos);
	else
		*unat_eml &= ~(1UL << pos);
}

int arch_set_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
	struct cpu_user_regs *uregs = vcpu_regs(v);
	struct domain *d = v->domain;
	struct switch_stack *sw = vcpu_to_switch_stack(v);
	int was_initialised = v->is_initialised;
	struct unw_frame_info info;
	unsigned int rbs_size;
	unsigned int num_regs;
	unsigned long * const rbs_bottom = vcpu_to_rbs_bottom(v);
	int rc = 0;
	int i;

	/* Finish vcpu initialization.  */
	if (!was_initialised) {
		if (is_hvm_domain(d))
			rc = vmx_final_setup_guest(v);
		else
			rc = vcpu_late_initialise(v);
		if (rc != 0)
			return rc;

		vcpu_init_regs(v);

		v->is_initialised = 1;
		/* Auto-online VCPU0 when it is initialised. */
		if (v->vcpu_id == 0 || (c.nat != NULL && 
					c.nat->flags & VGCF_online))
			clear_bit(_VPF_down, &v->pause_flags);
	}

	if (c.nat == NULL)
		return 0;

	uregs->b6 = c.nat->regs.b[6];
	uregs->b7 = c.nat->regs.b[7];
	
	memset(&info, 0, sizeof(info));
	unw_init_from_blocked_task(&info, v);
	if (vcpu_has_not_run(v)) {
		sw->ar_lc = c.nat->regs.ar.lc;
		sw->ar_pfs =
			(sw->ar_pfs & ~AR_PFS_PEC_MASK) |
			((c.nat->regs.ar.ec << AR_PFS_PEC_SHIFT) &
			 AR_PFS_PEC_MASK);
	} else if (unw_unwind_to_user(&info) < 0) {
		/* warn: should panic? */
		gdprintk(XENLOG_ERR,
			 "vcpu=%d unw_unwind_to_user() failed.\n",
			 v->vcpu_id);
		show_stack(v, NULL);

		//return -ENOSYS;
	} else {
		unw_set_ar(&info, UNW_AR_LC, c.nat->regs.ar.lc);
		unw_set_ar(&info, UNW_AR_EC, c.nat->regs.ar.ec);
	}

	if (!is_hvm_domain(d) && (c.nat->flags & VGCF_SET_AR_ITC))
		__vcpu_set_itc(v, c.nat->regs.ar.itc);

	uregs->ar_csd = c.nat->regs.ar.csd;
	uregs->ar_ssd = c.nat->regs.ar.ssd;
	
	uregs->r8 = c.nat->regs.r[8];
	uregs->r9 = c.nat->regs.r[9];
	uregs->r10 = c.nat->regs.r[10];
	uregs->r11 = c.nat->regs.r[11];

 	if (!is_hvm_domain(d))
		vcpu_set_psr(v, c.nat->regs.psr);
	else
		vmx_vcpu_set_psr(v, c.nat->regs.psr);
	uregs->cr_iip = c.nat->regs.ip;
	uregs->cr_ifs = c.nat->regs.cfm;

	uregs->ar_unat = c.nat->regs.ar.unat;
	uregs->ar_pfs = c.nat->regs.ar.pfs;
	uregs->ar_rsc = c.nat->regs.ar.rsc;
	uregs->ar_rnat = c.nat->regs.ar.rnat;
	uregs->ar_bspstore = c.nat->regs.ar.bspstore;
	
	uregs->pr = c.nat->regs.pr;
	uregs->b0 = c.nat->regs.b[0];
	num_regs = ia64_rse_num_regs((unsigned long*)c.nat->regs.ar.bspstore,
				     (unsigned long*)c.nat->regs.ar.bsp);
	rbs_size = (unsigned long)ia64_rse_skip_regs(rbs_bottom, num_regs) -
		(unsigned long)rbs_bottom;
	if (rbs_size > sizeof (c.nat->regs.rbs)) {
		gdprintk(XENLOG_INFO,
			 "rbs size is too large %x > %lx\n",
			 rbs_size, sizeof (c.nat->regs.rbs));
		return -EINVAL;
	}
	if (rbs_size > 0 &&
	    ((IA64_RBS_OFFSET / 8) % 64) != c.nat->regs.rbs_voff)
		gdprintk(XENLOG_INFO,
			 "rbs stack offset is different! xen 0x%x given 0x%x",
			 (IA64_RBS_OFFSET / 8) % 64, c.nat->regs.rbs_voff);
	
	/* Protection against crazy user code.  */
	if (!was_initialised)
		uregs->loadrs = (rbs_size << 16);
	if (rbs_size == (uregs->loadrs >> 16)) {
		unsigned long dst_rbs_size = 0;
		if (vcpu_has_not_run(v))
			sw->ar_bspstore = (unsigned long)rbs_bottom;
		
		rc = copy_rbs(v, &dst_rbs_size,
			      c.nat->regs.rbs, rbs_size,
			      c.nat->regs.rbs_rnat,
			      c.nat->regs.rbs_voff);
		if (rc < 0)
			return rc;

		/* In case of newly created vcpu, ar_bspstore points to
		 * the bottom of register stack. Move it up.
		 * See also init_switch_stack().
		 */
		if (vcpu_has_not_run(v)) {
			uregs->loadrs = (dst_rbs_size << 16);
			sw->ar_bspstore = (unsigned long)((char*)rbs_bottom +
							  dst_rbs_size);
		}
	}

	// inhibit save/restore between cpus of different RSE.N_STACKED_PHYS.
	// to avoid nasty issues.
	// 
	// The number of physical stacked general register(RSE.N_STACKED_PHYS)
	// isn't virtualized. Guest OS utilizes it via PAL_RSE_INFO call and
	// the value might be exported to user/user process.
	// (Linux does via /proc/cpuinfo)
	// The SDM says only that the number is cpu implementation specific.
	//
	// If the number of restoring cpu is different from one of saving cpu,
	// the following, or something worse, might happen.
	// - Xen VMM itself may panic when issuing loadrs to run guest with
	//   illegal operation fault
	//   When RSE.N_STACKED_PHYS of saving CPU > RSE.N_STACKED_PHYS of
	//   restoring CPU
	//   This case is detected to refuse restore by rbs_copy()
	// - guest kernel may panic with illegal operation fault
	//   When RSE.N_STACKED_PHYS of saving CPU > RSE.N_STACKED_PHYS of
	//   restoring CPU
	// - infomation leak from guest kernel to user process
	//   When RSE.N_STACKED_PHYS of saving CPU < RSE.N_STACKED_PHYS of
	//   restoring CPU
	//   Before returning to user process, kernel should zero clear all
	//   physical stacked resgisters to prevent kernel bits leak.
	//   It would be based on RSE.N_STACKED_PHYS (Linux does.).
	//   On the restored environtment the kernel clears only a part
	//   of the physical stacked registers.
	// - user processes or human operators would be confused.
	//   RSE.N_STACKED_PHYS might be exported to user process or human
	//   operators. Actually on linux it is exported via /proc/cpuinfo.
	//   user processes might use it.
	//   I don't know any concrete example, but it's possible in theory.
	//   e.g. thread libraly may allocate RBS area based on the value.
	//        (Fortunately glibc nptl doesn't)
	if (c.nat->regs.num_phys_stacked != 0 && /* COMPAT */
	    c.nat->regs.num_phys_stacked != num_phys_stacked) {
		gdprintk(XENLOG_WARNING,
			 "num phys stacked is different! "
			 "xen 0x%lx given 0x%lx",
			 num_phys_stacked, c.nat->regs.num_phys_stacked);
		return -EINVAL;
	}

	uregs->r1 = c.nat->regs.r[1];
	uregs->r12 = c.nat->regs.r[12];
	uregs->r13 = c.nat->regs.r[13];
	uregs->ar_fpsr = c.nat->regs.ar.fpsr;
	uregs->r15 = c.nat->regs.r[15];

	uregs->r14 = c.nat->regs.r[14];
	uregs->r2 = c.nat->regs.r[2];
	uregs->r3 = c.nat->regs.r[3];
	uregs->r16 = c.nat->regs.r[16];
	uregs->r17 = c.nat->regs.r[17];
	uregs->r18 = c.nat->regs.r[18];
	uregs->r19 = c.nat->regs.r[19];
	uregs->r20 = c.nat->regs.r[20];
	uregs->r21 = c.nat->regs.r[21];
	uregs->r22 = c.nat->regs.r[22];
	uregs->r23 = c.nat->regs.r[23];
	uregs->r24 = c.nat->regs.r[24];
	uregs->r25 = c.nat->regs.r[25];
	uregs->r26 = c.nat->regs.r[26];
	uregs->r27 = c.nat->regs.r[27];
	uregs->r28 = c.nat->regs.r[28];
	uregs->r29 = c.nat->regs.r[29];
	uregs->r30 = c.nat->regs.r[30];
	uregs->r31 = c.nat->regs.r[31];
	
	uregs->ar_ccv = c.nat->regs.ar.ccv;

	COPY_FPREG(&sw->f2, &c.nat->regs.f[2]);
	COPY_FPREG(&sw->f3, &c.nat->regs.f[3]);
	COPY_FPREG(&sw->f4, &c.nat->regs.f[4]);
	COPY_FPREG(&sw->f5, &c.nat->regs.f[5]);

	COPY_FPREG(&uregs->f6, &c.nat->regs.f[6]);
	COPY_FPREG(&uregs->f7, &c.nat->regs.f[7]);
	COPY_FPREG(&uregs->f8, &c.nat->regs.f[8]);
	COPY_FPREG(&uregs->f9, &c.nat->regs.f[9]);
	COPY_FPREG(&uregs->f10, &c.nat->regs.f[10]);
	COPY_FPREG(&uregs->f11, &c.nat->regs.f[11]);

	COPY_FPREG(&sw->f12, &c.nat->regs.f[12]);
	COPY_FPREG(&sw->f13, &c.nat->regs.f[13]);
	COPY_FPREG(&sw->f14, &c.nat->regs.f[14]);
	COPY_FPREG(&sw->f15, &c.nat->regs.f[15]);
	COPY_FPREG(&sw->f16, &c.nat->regs.f[16]);
	COPY_FPREG(&sw->f17, &c.nat->regs.f[17]);
	COPY_FPREG(&sw->f18, &c.nat->regs.f[18]);
	COPY_FPREG(&sw->f19, &c.nat->regs.f[19]);
	COPY_FPREG(&sw->f20, &c.nat->regs.f[20]);
	COPY_FPREG(&sw->f21, &c.nat->regs.f[21]);
	COPY_FPREG(&sw->f22, &c.nat->regs.f[22]);
	COPY_FPREG(&sw->f23, &c.nat->regs.f[23]);
	COPY_FPREG(&sw->f24, &c.nat->regs.f[24]);
	COPY_FPREG(&sw->f25, &c.nat->regs.f[25]);
	COPY_FPREG(&sw->f26, &c.nat->regs.f[26]);
	COPY_FPREG(&sw->f27, &c.nat->regs.f[27]);
	COPY_FPREG(&sw->f28, &c.nat->regs.f[28]);
	COPY_FPREG(&sw->f29, &c.nat->regs.f[29]);
	COPY_FPREG(&sw->f30, &c.nat->regs.f[30]);
	COPY_FPREG(&sw->f31, &c.nat->regs.f[31]);

	// f32 - f127
	memcpy(&v->arch._thread.fph[0], &c.nat->regs.f[32],
	       sizeof(v->arch._thread.fph));

#define UNAT_UPDATE(reg)					\
	unat_update(&uregs->eml_unat, &uregs->r ## reg,		\
		    !!(c.nat->regs.nats & (1UL << (reg))));

	uregs->eml_unat = 0;
	UNAT_UPDATE(1);
	UNAT_UPDATE(2);
	UNAT_UPDATE(3);

	UNAT_UPDATE(8);
	UNAT_UPDATE(9);
	UNAT_UPDATE(10);
	UNAT_UPDATE(11);
	UNAT_UPDATE(12);
	UNAT_UPDATE(13);
	UNAT_UPDATE(14);
	UNAT_UPDATE(15);
	UNAT_UPDATE(16);
	UNAT_UPDATE(17);
	UNAT_UPDATE(18);
	UNAT_UPDATE(19);
	UNAT_UPDATE(20);
	UNAT_UPDATE(21);
	UNAT_UPDATE(22);
	UNAT_UPDATE(23);
	UNAT_UPDATE(24);
	UNAT_UPDATE(25);
	UNAT_UPDATE(26);
	UNAT_UPDATE(27);
	UNAT_UPDATE(28);
	UNAT_UPDATE(29);
	UNAT_UPDATE(30);
	UNAT_UPDATE(31);
	
	/*
	 * r4-r7 is saved sometimes both in pt_regs->r[4-7] and memory stack or
	 * only in memory stack.
	 * for both cases, both memory stack and pt_regs->r[4-7] are updated.
	 */
	uregs->r4 = c.nat->regs.r[4];
	uregs->r5 = c.nat->regs.r[5];
	uregs->r6 = c.nat->regs.r[6];
	uregs->r7 = c.nat->regs.r[7];

	UNAT_UPDATE(4);
	UNAT_UPDATE(5);
	UNAT_UPDATE(6);
	UNAT_UPDATE(7);
#undef UNAT_UPDATE
	if (vcpu_has_not_run(v)) {
		sw->r4 = c.nat->regs.r[4];
		sw->r5 = c.nat->regs.r[5];
		sw->r6 = c.nat->regs.r[6];
		sw->r7 = c.nat->regs.r[7];

		unat_update(&sw->ar_unat, &sw->r4,
			    !!(c.nat->regs.nats & (1UL << 4)));
		unat_update(&sw->ar_unat, &sw->r5,
			    !!(c.nat->regs.nats & (1UL << 5)));
		unat_update(&sw->ar_unat, &sw->r6,
			    !!(c.nat->regs.nats & (1UL << 6)));
		unat_update(&sw->ar_unat, &sw->r7,
			    !!(c.nat->regs.nats & (1UL << 7)));
	} else {
		unw_set_gr(&info, 4, c.nat->regs.r[4],
			   !!(c.nat->regs.nats & (1UL << 4)));
		unw_set_gr(&info, 5, c.nat->regs.r[5],
			   !!(c.nat->regs.nats & (1UL << 5)));
		unw_set_gr(&info, 6, c.nat->regs.r[6],
			   !!(c.nat->regs.nats & (1UL << 6)));
		unw_set_gr(&info, 7, c.nat->regs.r[7],
			   !!(c.nat->regs.nats & (1UL << 7)));
	}
	
 	if (!is_hvm_domain(d)) {
 		/* domain runs at PL2/3 */
 		uregs->cr_ipsr = vcpu_pl_adjust(uregs->cr_ipsr,
		                                IA64_PSR_CPL0_BIT);
 		uregs->ar_rsc = vcpu_pl_adjust(uregs->ar_rsc, 2);
 	}

	for (i = 0; i < IA64_NUM_DBG_REGS; i++) {
		if (is_hvm_domain(d)) {
			vmx_vcpu_set_dbr(v, i, c.nat->regs.dbr[i]);
			vmx_vcpu_set_ibr(v, i, c.nat->regs.ibr[i]);
		} else {
			vcpu_set_dbr(v, i, c.nat->regs.dbr[i]);
			vcpu_set_ibr(v, i, c.nat->regs.ibr[i]);
		}
	}

	/* rr[] must be set before setting itrs[] dtrs[] */
	for (i = 0; i < 8; i++) {
		unsigned long rrval = c.nat->regs.rr[i];
		unsigned long reg = (unsigned long)i << 61;
		IA64FAULT fault = IA64_NO_FAULT;

		if (rrval == 0)
			continue;
		if (is_hvm_domain(d)) {
			//without VGCF_EXTRA_REGS check,
			//VTi domain doesn't boot.
			if (c.nat->flags & VGCF_EXTRA_REGS)
				fault = vmx_vcpu_set_rr(v, reg, rrval);
		} else
			fault = vcpu_set_rr(v, reg, rrval);
		if (fault != IA64_NO_FAULT)
			return -EINVAL;
	}

	if (c.nat->flags & VGCF_EXTRA_REGS) {
		struct vcpu_tr_regs *tr = &c.nat->regs.tr;

		for (i = 0;
		     (i < sizeof(tr->itrs) / sizeof(tr->itrs[0])) && i < NITRS;
		     i++) {
			if (is_hvm_domain(d))
				vmx_vcpu_itr_i(v, i, tr->itrs[i].pte,
					       tr->itrs[i].itir,
					       tr->itrs[i].vadr);
			else
				vcpu_set_itr(v, i, tr->itrs[i].pte,
					     tr->itrs[i].itir,
					     tr->itrs[i].vadr,
					     tr->itrs[i].rid);
		}
		for (i = 0;
		     (i < sizeof(tr->dtrs) / sizeof(tr->dtrs[0])) && i < NDTRS;
		     i++) {
			if (is_hvm_domain(d))
				vmx_vcpu_itr_d(v, i, tr->dtrs[i].pte,
					       tr->dtrs[i].itir,
					       tr->dtrs[i].vadr);
			else
				vcpu_set_dtr(v, i,
					     tr->dtrs[i].pte,
					     tr->dtrs[i].itir,
					     tr->dtrs[i].vadr,
					     tr->dtrs[i].rid);
		}
		v->arch.event_callback_ip = c.nat->event_callback_ip;
		vcpu_set_iva(v, c.nat->regs.cr.iva);
	}

	if (is_hvm_domain(d))
		rc = vmx_arch_set_info_guest(v, c);

	return rc;
}

static int relinquish_memory(struct domain *d, struct page_list_head *list)
{
    struct page_info *page;
#ifndef __ia64__
    unsigned long     x, y;
#endif
    int               ret = 0;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    while ( (page = page_list_remove_head(list)) )
    {
        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
        {
            /* Couldn't get a reference -- someone is freeing this page. */
            page_list_add_tail(page, &d->arch.relmem_list);
            continue;
        }

        if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
            put_page(page);

#ifndef __ia64__
        /*
         * Forcibly invalidate base page tables at this point to break circular
         * 'linear page table' references. This is okay because MMU structures
         * are not shared across domains and this domain is now dead. Thus base
         * tables are not in use so a non-zero count means circular reference.
         */
        y = page->u.inuse.type_info;
        for ( ; ; )
        {
            x = y;
            if ( likely((x & (PGT_type_mask|PGT_validated)) !=
                        (PGT_base_page_table|PGT_validated)) )
                break;

            y = cmpxchg(&page->u.inuse.type_info, x, x & ~PGT_validated);
            if ( likely(y == x) )
            {
                free_page_type(page, PGT_base_page_table);
                break;
            }
        }
#endif

        /* Follow the list chain and /then/ potentially free the page. */
        BUG_ON(get_gpfn_from_mfn(page_to_mfn(page)) != INVALID_M2P_ENTRY);
        page_list_add_tail(page, &d->arch.relmem_list);
        put_page(page);

        if (hypercall_preempt_check()) {
                ret = -EAGAIN;
                goto out;
        }
    }

    page_list_move(list, &d->arch.relmem_list);

 out:
    spin_unlock_recursive(&d->page_alloc_lock);
    return ret;
}

int domain_relinquish_resources(struct domain *d)
{
	int ret = 0;

	switch (d->arch.relres) {
	case RELRES_not_started:
		/* Relinquish guest resources for VT-i domain. */
		if (is_hvm_domain(d))
			vmx_relinquish_guest_resources(d);
		d->arch.relres = RELRES_mm_teardown;
		/*fallthrough*/

	case RELRES_mm_teardown:
		if (d->arch.pirq_eoi_map != NULL) {
			put_page(virt_to_page(d->arch.pirq_eoi_map));
			d->arch.pirq_eoi_map = NULL;
		}

		/* Tear down shadow mode stuff. */
		ret = mm_teardown(d);
		if (ret != 0)
			return ret;
		d->arch.relres = RELRES_xen;
		/* fallthrough */

	case RELRES_xen:
		/* Relinquish every xen page of memory. */
		ret = relinquish_memory(d, &d->xenpage_list);
		if (ret != 0)
			return ret;
		d->arch.relres = RELRES_dom;
		/* fallthrough */

	case RELRES_dom:
		/* Relinquish every domain page of memory. */
		ret = relinquish_memory(d, &d->page_list);
		if (ret != 0)
			return ret;
		d->arch.relres = RELRES_done;
		/* fallthrough */    

	case RELRES_done:
		break;

	default:
		BUG();
	}

	if (is_hvm_domain(d) && d->arch.sal_data)
		xfree(d->arch.sal_data);

	return 0;
}

unsigned long
domain_set_shared_info_va (unsigned long va)
{
	struct vcpu *v = current;
	struct domain *d = v->domain;
	int rc;

	/* Check virtual address:
	   must belong to region 7,
	   must be 64Kb aligned,
	   must not be within Xen virtual space.  */
	if ((va >> 61) != 7
	    || (va & 0xffffUL) != 0
	    || (va >= HYPERVISOR_VIRT_START && va < HYPERVISOR_VIRT_END))
		panic_domain (NULL, "%s: bad va (0x%016lx)\n", __func__, va);

	/* Note: this doesn't work well if other cpus are already running.
	   However this is part of the spec :-)  */
	gdprintk(XENLOG_DEBUG, "Domain set shared_info_va to 0x%016lx\n", va);
	d->arch.shared_info_va = va;

	VCPU(v, interrupt_mask_addr) = (unsigned char *)va +
	                               INT_ENABLE_OFFSET(v);
	set_current_psr_i_addr(v);

	/* Remap the shared pages.  */
	BUG_ON(VMX_DOMAIN(v));
	rc = !set_one_rr(7UL << 61, PSCB(v,rrs[7]));
	BUG_ON(rc);

	return rc;
}

/* Transfer and clear the shadow bitmap in 1kB chunks for L1 cache. */
#define SHADOW_COPY_CHUNK 1024

int shadow_mode_control(struct domain *d, xen_domctl_shadow_op_t *sc)
{
	unsigned int op = sc->op;
	int          rc = 0;
	int i;
	//struct vcpu *v;

	if (unlikely(d == current->domain)) {
		gdprintk(XENLOG_INFO,
                        "Don't try to do a shadow op on yourself!\n");
		return -EINVAL;
	}   

	domain_pause(d);

	switch (op)
	{
	case XEN_DOMCTL_SHADOW_OP_OFF:
		if (shadow_mode_enabled (d)) {
			u64 *bm = d->arch.shadow_bitmap;
			struct vcpu *v;

			for_each_vcpu(d, v)
				v->arch.shadow_bitmap = NULL;

			/* Flush vhpt and tlb to restore dirty bit usage.  */
			flush_tlb_for_log_dirty(d);

			/* Free bitmap.  */
			d->arch.shadow_bitmap_size = 0;
			d->arch.shadow_bitmap = NULL;
			xfree(bm);
		}
		break;

	case XEN_DOMCTL_SHADOW_OP_ENABLE_TEST:
	case XEN_DOMCTL_SHADOW_OP_ENABLE_TRANSLATE:
		rc = -EINVAL;
		break;

	case XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY:
		if (shadow_mode_enabled(d)) {
			rc = -EINVAL;
			break;
		}

		atomic64_set(&d->arch.shadow_fault_count, 0);
		atomic64_set(&d->arch.shadow_dirty_count, 0);

		d->arch.shadow_bitmap_size =
			(domain_get_maximum_gpfn(d) + BITS_PER_LONG) &
			~(BITS_PER_LONG - 1);
		d->arch.shadow_bitmap = xmalloc_array(unsigned long,
		                   d->arch.shadow_bitmap_size / BITS_PER_LONG);
		if (d->arch.shadow_bitmap == NULL) {
			d->arch.shadow_bitmap_size = 0;
			rc = -ENOMEM;
		}
		else {
			struct vcpu *v;
			memset(d->arch.shadow_bitmap, 0, 
			       d->arch.shadow_bitmap_size / 8);

			for_each_vcpu(d, v)
				v->arch.shadow_bitmap = d->arch.shadow_bitmap;
			/* Flush vhtp and tlb to enable dirty bit
			   virtualization.  */
			flush_tlb_for_log_dirty(d);
		}
		break;

	case XEN_DOMCTL_SHADOW_OP_CLEAN:
	  {
		int nbr_bytes;

		sc->stats.fault_count = atomic64_read(&d->arch.shadow_fault_count);
		sc->stats.dirty_count = atomic64_read(&d->arch.shadow_dirty_count);

		atomic64_set(&d->arch.shadow_fault_count, 0);
		atomic64_set(&d->arch.shadow_dirty_count, 0);
 
		if (guest_handle_is_null(sc->dirty_bitmap) ||
		    (d->arch.shadow_bitmap == NULL)) {
			rc = -EINVAL;
			break;
		}

		if (sc->pages > d->arch.shadow_bitmap_size)
			sc->pages = d->arch.shadow_bitmap_size; 

		nbr_bytes = (sc->pages + 7) / 8;

		for (i = 0; i < nbr_bytes; i += SHADOW_COPY_CHUNK) {
			int size = (nbr_bytes - i) > SHADOW_COPY_CHUNK ?
			           SHADOW_COPY_CHUNK : nbr_bytes - i;
     
			if (copy_to_guest_offset(
                            sc->dirty_bitmap, i,
                            (uint8_t *)d->arch.shadow_bitmap + i,
                            size)) {
				rc = -EFAULT;
				break;
			}

			memset((uint8_t *)d->arch.shadow_bitmap + i, 0, size);
		}
		flush_tlb_for_log_dirty(d);
		
		break;
	  }

	case XEN_DOMCTL_SHADOW_OP_PEEK:
	{
		unsigned long size;

		sc->stats.fault_count = atomic64_read(&d->arch.shadow_fault_count);
		sc->stats.dirty_count = atomic64_read(&d->arch.shadow_dirty_count);

		if (guest_handle_is_null(sc->dirty_bitmap) ||
		    (d->arch.shadow_bitmap == NULL)) {
			rc = -EINVAL;
			break;
		}
 
		if (sc->pages > d->arch.shadow_bitmap_size)
			sc->pages = d->arch.shadow_bitmap_size; 

		size = (sc->pages + 7) / 8;
		if (copy_to_guest(sc->dirty_bitmap,
		                  (uint8_t *)d->arch.shadow_bitmap, size)) {
			rc = -EFAULT;
			break;
		}
		break;
	}
	case XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION:
		sc->mb = 0;
		break;
	case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
		if (sc->mb > 0) {
			BUG();
			rc = -ENOMEM;
		}
		break;
	default:
		rc = -EINVAL;
		break;
	}
	
	domain_unpause(d);
	
	return rc;
}

// remove following line if not privifying in memory
//#define HAVE_PRIVIFY_MEMORY
#ifndef HAVE_PRIVIFY_MEMORY
#define	privify_memory(x,y) do {} while(0)
#endif

static void __init loaddomainelfimage(struct domain *d, struct elf_binary *elf,
				      unsigned long phys_load_offset)
{
	const elf_phdr *phdr;
	int phnum, h, filesz, memsz;
	unsigned long elfaddr, dom_mpaddr, dom_imva;
	struct page_info *p;

	phnum = elf_uval(elf, elf->ehdr, e_phnum);
	for (h = 0; h < phnum; h++) {
		phdr = elf_phdr_by_index(elf, h);
		if (!elf_phdr_is_loadable(elf, phdr))
		    continue;

		filesz = elf_uval(elf, phdr, p_filesz);
		memsz = elf_uval(elf, phdr, p_memsz);
		elfaddr = (unsigned long) elf->image + elf_uval(elf, phdr, p_offset);
		dom_mpaddr = elf_uval(elf, phdr, p_paddr);
		dom_mpaddr += phys_load_offset;

		while (memsz > 0) {
			p = assign_new_domain_page(d,dom_mpaddr);
			BUG_ON (unlikely(p == NULL));
			dom_imva = __va_ul(page_to_maddr(p));
			if (filesz > 0) {
				if (filesz >= PAGE_SIZE)
					copy_page((void *) dom_imva,
					          (void *) elfaddr);
				else {
					// copy partial page
					memcpy((void *) dom_imva,
					       (void *) elfaddr, filesz);
					// zero the rest of page
					memset((void *) dom_imva+filesz, 0,
					       PAGE_SIZE-filesz);
				}
//FIXME: This test for code seems to find a lot more than objdump -x does
				if (elf_uval(elf, phdr, p_flags) & PF_X) {
					privify_memory(dom_imva,PAGE_SIZE);
					flush_icache_range(dom_imva,
							   dom_imva+PAGE_SIZE);
				}
			}
			else if (memsz > 0) {
                                /* always zero out entire page */
				clear_page((void *) dom_imva);
			}
			memsz -= PAGE_SIZE;
			filesz -= PAGE_SIZE;
			elfaddr += PAGE_SIZE;
			dom_mpaddr += PAGE_SIZE;
		}
	}
}

static void __init calc_dom0_size(void)
{
	unsigned long domheap_pages;
	unsigned long p2m_pages;
	unsigned long spare_hv_pages;
	unsigned long max_dom0_size;
	unsigned long iommu_pg_table_pages = 0;

	/* Estimate maximum memory we can safely allocate for dom0
	 * by subtracting the p2m table allocation and a chunk of memory
	 * for DMA and PCI mapping from the available domheap pages. The
	 * chunk for DMA, PCI, etc., is a guestimate, as xen doesn't seem
	 * to have a good idea of what those requirements might be ahead
	 * of time, calculated at 128MB + 1MB per 4GB of system memory */
	domheap_pages = avail_domheap_pages();
	p2m_pages = domheap_pages / PTRS_PER_PTE;
	spare_hv_pages = 8192 + (domheap_pages / 4096);

	if (iommu_enabled)
		iommu_pg_table_pages = domheap_pages * 4 / 512;
		/* There are 512 ptes in one 4K vtd page. */

	max_dom0_size = (domheap_pages - (p2m_pages + spare_hv_pages) -
			iommu_pg_table_pages) * PAGE_SIZE;
	printk("Maximum permitted dom0 size: %luMB\n",
	       max_dom0_size / (1024*1024));

	/* validate proposed dom0_size, fix up as needed */
	if (dom0_size > max_dom0_size) {
		printk("Reducing dom0 memory allocation from %luK to %luK "
		       "to fit available memory\n",
		       dom0_size / 1024, max_dom0_size / 1024);
		dom0_size = max_dom0_size;
	}

	/* dom0_mem=0 can be passed in to give all available mem to dom0 */
	if (dom0_size == 0) {
		printk("Allocating all available memory to dom0\n");
		dom0_size = max_dom0_size;
	}

	/* Check dom0 size.  */
	if (dom0_size < 4 * 1024 * 1024) {
		panic("dom0_mem is too small, boot aborted"
			" (try e.g. dom0_mem=256M or dom0_mem=65536K)\n");
	}

	if (running_on_sim) {
		dom0_size = 128*1024*1024; //FIXME: Should be configurable
	}

	/* no need to allocate pages for now
	 * pages are allocated by map_new_domain_page() via loaddomainelfimage()
	 */
}


/*
 * Domain 0 has direct access to all devices absolutely. However
 * the major point of this stub here, is to allow alloc_dom_mem
 * handled with order > 0 request. Dom0 requires that bit set to
 * allocate memory for other domains.
 */
static void __init physdev_init_dom0(struct domain *d)
{
	if (iomem_permit_access(d, 0UL, ~0UL))
		BUG();
	if (irqs_permit_access(d, 0, NR_IRQS-1))
		BUG();
	if (ioports_permit_access(d, 0, 0, 0xffff))
		BUG();
}

int __init construct_dom0(struct domain *d, 
			  unsigned long image_start, unsigned long image_len, 
			  unsigned long initrd_start, unsigned long initrd_len,
			  char *cmdline)
{
	int i, rc;
	start_info_t *si;
	dom0_vga_console_info_t *ci;
	struct vcpu *v = d->vcpu[0];
	unsigned long max_pages;

	struct elf_binary elf;
	struct elf_dom_parms parms;
	unsigned long p_start;
	unsigned long pkern_start;
	unsigned long pkern_entry;
	unsigned long pkern_end;
	unsigned long pinitrd_start = 0;
	unsigned long pstart_info;
	unsigned long phys_load_offset;
	struct page_info *start_info_page;
	unsigned long bp_mpa;
	struct ia64_boot_param *bp;

//printk("construct_dom0: starting\n");

	/* Sanity! */
	BUG_ON(d != dom0);
	BUG_ON(d->vcpu == NULL);
	BUG_ON(d->vcpu[0] == NULL);
	BUG_ON(v->is_initialised);

	printk("*** LOADING DOMAIN 0 ***\n");

	calc_dom0_size();

	max_pages = dom0_size / PAGE_SIZE;
	d->max_pages = max_pages;
	d->tot_pages = 0;

	rc = elf_init(&elf, (void*)image_start, image_len);
	if ( rc != 0 )
	    return rc;
#ifdef VERBOSE
	elf_set_verbose(&elf);
#endif
	elf_parse_binary(&elf);
	if (0 != (elf_xen_parse(&elf, &parms)))
		return rc;

	/*
	 * We cannot rely on the load address in the ELF headers to
	 * determine the meta physical address at which the image
	 * is loaded.  Patch the address to match the real one, based
	 * on xen_pstart
	 */
	phys_load_offset = xen_pstart - elf.pstart;
	elf.pstart += phys_load_offset;
	elf.pend += phys_load_offset;
	parms.virt_kstart += phys_load_offset;
	parms.virt_kend += phys_load_offset;
	parms.virt_entry += phys_load_offset;

	printk(" Dom0 kernel: %s, %s, paddr 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
	       elf_64bit(&elf) ? "64-bit" : "32-bit",
	       elf_msb(&elf)   ? "msb"    : "lsb",
	       elf.pstart, elf.pend);
        if (!elf_64bit(&elf) ||
	    elf_uval(&elf, elf.ehdr, e_machine) != EM_IA_64) {
		printk("Incompatible kernel binary\n");
		return -1;
	}

	p_start = parms.virt_base;
	pkern_start = parms.virt_kstart;
	pkern_end = parms.virt_kend;
	pkern_entry = parms.virt_entry;

//printk("p_start=%lx, pkern_start=%lx, pkern_end=%lx, pkern_entry=%lx\n",p_start,pkern_start,pkern_end,pkern_entry);

	if ( (p_start & (PAGE_SIZE-1)) != 0 )
	{
	    printk("Initial guest OS must load to a page boundary.\n");
	    return -EINVAL;
	}

	pstart_info = PAGE_ALIGN(pkern_end);
	if(initrd_start && initrd_len){
	    unsigned long offset;

	    /* The next page aligned boundary after the start info.
	       Note: EFI_PAGE_SHIFT = 12 <= PAGE_SHIFT */
	    pinitrd_start = pstart_info + PAGE_SIZE;

	    if ((pinitrd_start + initrd_len - phys_load_offset) >= dom0_size)
		    panic("%s: not enough memory assigned to dom0", __func__);

	    for (offset = 0; offset < initrd_len; offset += PAGE_SIZE) {
		struct page_info *p;
		p = assign_new_domain_page(d, pinitrd_start + offset);
		if (p == NULL)
		    panic("%s: can't allocate page for initrd image", __func__);
		if (initrd_len < offset + PAGE_SIZE)
		    memcpy(page_to_virt(p), (void*)(initrd_start + offset),
		           initrd_len - offset);
		else
		    copy_page(page_to_virt(p), (void*)(initrd_start + offset));
	    }
	}

	printk("METAPHYSICAL MEMORY ARRANGEMENT:\n"
	       " Kernel image:  %lx->%lx\n"
	       " Entry address: %lx\n"
	       " Init. ramdisk: %lx len %lx\n"
	       " Start info.:   %lx->%lx\n",
	       pkern_start, pkern_end, pkern_entry, pinitrd_start, initrd_len,
	       pstart_info, pstart_info + PAGE_SIZE);

	if ( (pkern_end - pkern_start) > (max_pages * PAGE_SIZE) )
	{
	    printk("Initial guest OS requires too much space\n"
	           "(%luMB is greater than %luMB limit)\n",
	           (pkern_end-pkern_start)>>20,
	           (max_pages <<PAGE_SHIFT)>>20);
	    return -ENOMEM;
	}

	// if high 3 bits of pkern start are non-zero, error

	// if pkern end is after end of metaphysical memory, error
	//  (we should be able to deal with this... later)

	/* Mask all upcalls... */
	for ( i = 1; i < XEN_LEGACY_MAX_VCPUS; i++ )
	    d->shared_info->vcpu_info[i].evtchn_upcall_mask = 1;

	printk ("Dom0 max_vcpus=%d\n", dom0_max_vcpus);
	for ( i = 1; i < dom0_max_vcpus; i++ )
	    if (alloc_vcpu(d, i, i) == NULL)
		panic("Cannot allocate dom0 vcpu %d\n", i);

	/* Copy the OS image. */
	loaddomainelfimage(d, &elf, phys_load_offset);

	BUILD_BUG_ON(sizeof(start_info_t) + sizeof(dom0_vga_console_info_t) +
	             sizeof(struct ia64_boot_param) > PAGE_SIZE);

	/* Set up start info area. */
	d->shared_info->arch.start_info_pfn = pstart_info >> PAGE_SHIFT;
	start_info_page = assign_new_domain_page(d, pstart_info);
	if (start_info_page == NULL)
		panic("can't allocate start info page");
	si = page_to_virt(start_info_page);
	clear_page(si);
	snprintf(si->magic, sizeof(si->magic), "xen-3.0-ia64");
	si->nr_pages     = max_pages;
	si->flags = SIF_INITDOMAIN|SIF_PRIVILEGED;
	si->flags |= (xen_processor_pmbits << 8) & SIF_PM_MASK;

	printk("Dom0: 0x%lx\n", (u64)dom0);

	v->is_initialised = 1;
	clear_bit(_VPF_down, &v->pause_flags);

	/* Build firmware.
	   Note: Linux kernel reserve memory used by start_info, so there is
	   no need to remove it from MDT.  */
	bp_mpa = pstart_info + sizeof(struct start_info);
	rc = dom_fw_setup(d, bp_mpa, max_pages * PAGE_SIZE);
	if (rc != 0)
		return rc;

	/* Fill boot param.  */
	strlcpy((char *)si->cmd_line, dom0_command_line, sizeof(si->cmd_line));

	bp = (struct ia64_boot_param *)((unsigned char *)si +
	                                sizeof(start_info_t));
	bp->command_line = pstart_info + offsetof (start_info_t, cmd_line);

	/* We assume console has reached the last line!  */
	bp->console_info.num_cols = ia64_boot_param->console_info.num_cols;
	bp->console_info.num_rows = ia64_boot_param->console_info.num_rows;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = bp->console_info.num_rows == 0 ?
	                          0 : bp->console_info.num_rows - 1;

	bp->initrd_start = pinitrd_start;
	bp->initrd_size = ia64_boot_param->initrd_size;

	ci = (dom0_vga_console_info_t *)((unsigned char *)si +
			                 sizeof(start_info_t) +
	                                 sizeof(struct ia64_boot_param));

	if (fill_console_start_info(ci)) {
		si->console.dom0.info_off = sizeof(start_info_t) +
		                            sizeof(struct ia64_boot_param);
		si->console.dom0.info_size = sizeof(dom0_vga_console_info_t);
	}

	vcpu_init_regs (v);

	vcpu_regs(v)->r28 = bp_mpa;

	vcpu_regs (v)->cr_iip = pkern_entry;

	physdev_init_dom0(d);

	return 0;
}

struct vcpu *__init alloc_dom0_vcpu0(void)
{
       if (dom0_max_vcpus == 0)
           dom0_max_vcpus = MAX_VIRT_CPUS;
       if (dom0_max_vcpus > num_online_cpus())
           dom0_max_vcpus = num_online_cpus();
       if (dom0_max_vcpus > MAX_VIRT_CPUS)
           dom0_max_vcpus = MAX_VIRT_CPUS;

       dom0->vcpu = xmalloc_array(struct vcpu *, dom0_max_vcpus);
       if ( !dom0->vcpu )
               return NULL;
       memset(dom0->vcpu, 0, dom0_max_vcpus * sizeof(*dom0->vcpu));
       dom0->max_vcpus = dom0_max_vcpus;

       return alloc_vcpu(dom0, 0, 0);
}

void machine_restart(unsigned int delay_millisecs)
{
	mdelay(delay_millisecs);
	console_start_sync();
	if (running_on_sim)
		printk ("machine_restart called.  spinning...\n");
	else
		(*efi.reset_system)(EFI_RESET_WARM,0,0,NULL);
	while(1);
}

extern void cpu_halt(void);

void machine_halt(void)
{
	console_start_sync();

#ifdef CONFIG_SMP
	smp_send_stop();
#endif

	printk ("machine_halt called.  spinning...\n");
	while(1);
}

void sync_local_execstate(void)
{
}

void sync_vcpu_execstate(struct vcpu *v)
{
//	__ia64_save_fpu(v->arch._thread.fph);
	// FIXME SMP: Anything else needed here for SMP?
}

/* This function is taken from xen/arch/x86/domain.c */
long
arch_do_vcpu_op(int cmd, struct vcpu *v, XEN_GUEST_HANDLE(void) arg)
{
	long rc = 0;

	switch (cmd) {
	case VCPUOP_register_runstate_memory_area:
	{
		struct vcpu_register_runstate_memory_area area;
		struct vcpu_runstate_info runstate;

		rc = -EFAULT;
		if (copy_from_guest(&area, arg, 1))
			break;

		if (!guest_handle_okay(area.addr.h, 1))
			break;

		rc = 0;
		runstate_guest(v) = area.addr.h;

		if (v == current) {
			__copy_to_guest(runstate_guest(v), &v->runstate, 1);
		} else {
			vcpu_runstate_get(v, &runstate);
			__copy_to_guest(runstate_guest(v), &runstate, 1);
		}

		break;
	}
	default:
		rc = -ENOSYS;
		break;
	}

	return rc;
}

size_param("dom0_mem", dom0_size);

/*
 * Helper function for the optimization stuff handling the identity mapping
 * feature.
 */
static inline unsigned long
optf_identity_mapping_cmd_to_flg(unsigned long cmd)
{
	switch(cmd) {
	case XEN_IA64_OPTF_IDENT_MAP_REG7:
		return XEN_IA64_OPTF_IDENT_MAP_REG7_FLG;
	case XEN_IA64_OPTF_IDENT_MAP_REG4:
		return XEN_IA64_OPTF_IDENT_MAP_REG4_FLG;
	case XEN_IA64_OPTF_IDENT_MAP_REG5:
		return XEN_IA64_OPTF_IDENT_MAP_REG5_FLG;
	default:
		BUG();
		return 0;
	}

	/* NOTREACHED */
}

static inline void
optf_set_identity_mapping(unsigned long* mask, struct identity_mapping* im,
			  struct xen_ia64_opt_feature* f)
{
	unsigned long flag = optf_identity_mapping_cmd_to_flg(f->cmd);

	if (f->on) {
		*mask |= flag;
		im->pgprot = f->pgprot;
		im->key = f->key;
	} else {
		*mask &= ~flag;
		im->pgprot = 0;
		im->key = 0;
	}
}

/*
 * Switch an optimization feature on/off.
 * The vcpu must be paused to avoid racy access to opt_feature.
 */
int
domain_opt_feature(struct domain *d, struct xen_ia64_opt_feature* f)
{
	struct opt_feature* optf = &d->arch.opt_feature;
	struct vcpu *v;
	long rc = 0;

	for_each_vcpu(d, v) {
		if (v != current)
			vcpu_pause(v);
	}

	switch (f->cmd) {
	case XEN_IA64_OPTF_IDENT_MAP_REG4:
		optf_set_identity_mapping(&optf->mask, &optf->im_reg4, f);
		break;
	case XEN_IA64_OPTF_IDENT_MAP_REG5:
		optf_set_identity_mapping(&optf->mask, &optf->im_reg5, f);
		break;
	case XEN_IA64_OPTF_IDENT_MAP_REG7:
		optf_set_identity_mapping(&optf->mask, &optf->im_reg7, f);
		break;
	default:
		printk("%s: unknown opt_feature: %ld\n", __func__, f->cmd);
		rc = -ENOSYS;
		break;
	}

	for_each_vcpu(d, v) {
		if (v != current)
			vcpu_unpause(v);
	}

	return rc;
}

