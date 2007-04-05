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
#include <public/libelf.h>
#include <asm/pgalloc.h>
#include <asm/offsets.h>  /* for IA64_THREAD_INFO_SIZE */
#include <asm/vcpu.h>   /* for function declarations */
#include <public/xen.h>
#include <xen/domain.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_vpd.h>
#include <asm/vmx_phy_mode.h>
#include <asm/vhpt.h>
#include <asm/vcpu.h>
#include <asm/tlbflush.h>
#include <asm/regionreg.h>
#include <asm/dom_fw.h>
#include <asm/shadow.h>
#include <xen/guest_access.h>
#include <asm/tlb_track.h>
#include <asm/perfmon.h>
#include <public/vcpu.h>

unsigned long dom0_size = 512*1024*1024;

/* dom0_max_vcpus: maximum number of VCPUs to create for dom0.  */
static unsigned int dom0_max_vcpus = 1;
integer_param("dom0_max_vcpus", dom0_max_vcpus); 

extern unsigned long running_on_sim;

extern char dom0_command_line[];

/* forward declaration */
static void init_switch_stack(struct vcpu *v);

/* Address of vpsr.i (in fact evtchn_upcall_mask) of current vcpu.
   This is a Xen virtual address.  */
DEFINE_PER_CPU(uint8_t *, current_psr_i_addr);
DEFINE_PER_CPU(int *, current_psr_ic_addr);

DEFINE_PER_CPU(struct vcpu *, fp_owner);

#include <xen/sched-if.h>

static void
ia64_disable_vhpt_walker(void)
{
	// disable VHPT. ia64_new_rr7() might cause VHPT
	// fault without this because it flushes dtr[IA64_TR_VHPT]
	// (VHPT_SIZE_LOG2 << 2) is just for avoid
	// Reserved Register/Field fault.
	ia64_set_pta(VHPT_SIZE_LOG2 << 2);
}

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

void schedule_tail(struct vcpu *prev)
{
	extern char ia64_ivt;

	context_saved(prev);
	ia64_disable_vhpt_walker();

	if (VMX_DOMAIN(current)) {
		vmx_do_launch(current);
		migrate_timer(&current->arch.arch_vmx.vtm.vtm_timer,
		              current->processor);
	} else {
		ia64_set_iva(&ia64_ivt);
		load_region_regs(current);
		ia64_set_pta(vcpu_pta(current));
		vcpu_load_kernel_regs(current);
		__ia64_per_cpu_var(current_psr_i_addr) = &current->domain->
		  shared_info->vcpu_info[current->vcpu_id].evtchn_upcall_mask;
		__ia64_per_cpu_var(current_psr_ic_addr) = (int *)
		  (current->domain->arch.shared_info_va + XSI_PSR_IC_OFS);
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
            ia64_setreg(_IA64_REG_CR_DCR, IA64_DEFAULT_DCR_BITS);
        }
    }
    if (VMX_DOMAIN(next))
        vmx_load_state(next);

    ia64_disable_vhpt_walker();
    lazy_fp_switch(prev, current);

    prev = ia64_switch_to(next);

    /* Note: ia64_switch_to does not return here at vcpu initialization.  */

    if (VMX_DOMAIN(current)) {
        vmx_load_all_rr(current);
        migrate_timer(&current->arch.arch_vmx.vtm.vtm_timer,
                      current->processor);
    } else {
        struct domain *nd;
        extern char ia64_ivt;

        ia64_set_iva(&ia64_ivt);

        nd = current->domain;
        if (!is_idle_domain(nd)) {
            load_region_regs(current);
            ia64_set_pta(vcpu_pta(current));
            vcpu_load_kernel_regs(current);
            vcpu_set_next_timer(current);
            if (vcpu_timer_expired(current))
                vcpu_pend_timer(current);
            __ia64_per_cpu_var(current_psr_i_addr) = &nd->shared_info->
                vcpu_info[current->vcpu_id].evtchn_upcall_mask;
            __ia64_per_cpu_var(current_psr_ic_addr) =
                (int *)(nd->arch.shared_info_va + XSI_PSR_IC_OFS);
            /* steal time accounting */
            if (!guest_handle_is_null(runstate_guest(current)))
                __copy_to_guest(runstate_guest(current), &current->runstate, 1);
        } else {
            /* When switching to idle domain, only need to disable vhpt
             * walker. Then all accesses happen within idle context will
             * be handled by TR mapping and identity mapping.
             */
            __ia64_per_cpu_var(current_psr_i_addr) = NULL;
            __ia64_per_cpu_var(current_psr_ic_addr) = NULL;
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
	if ( !softirq_pending(smp_processor_id()) ) {
		if (can_do_pal_halt)
			safe_halt();
		else
			cpu_relax();
	}
	local_irq_enable();
}

static void continue_cpu_idle_loop(void)
{
	for ( ; ; )
	{
#ifdef IA64
//        __IRQ_STAT(cpu, idle_timestamp) = jiffies
#else
	    irq_stat[cpu].idle_timestamp = jiffies;
#endif
	    page_scrub_schedule_work();
	    while ( !softirq_pending(smp_processor_id()) )
	        default_idle();
	    raise_softirq(SCHEDULE_SOFTIRQ);
	    do_softirq();
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

struct vcpu *alloc_vcpu_struct(void)
{
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

	if ((v = alloc_xenheap_pages(KERNEL_STACK_SIZE_ORDER)) == NULL)
		return NULL;
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
	free_xenheap_pages(v, KERNEL_STACK_SIZE_ORDER);
}

int vcpu_initialise(struct vcpu *v)
{
	struct domain *d = v->domain;

	if (!is_idle_domain(d)) {
	    v->arch.metaphysical_rr0 = d->arch.metaphysical_rr0;
	    v->arch.metaphysical_rr4 = d->arch.metaphysical_rr4;
	    v->arch.metaphysical_saved_rr0 = d->arch.metaphysical_rr0;
	    v->arch.metaphysical_saved_rr4 = d->arch.metaphysical_rr4;

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
	    v->arch.breakimm = d->arch.breakimm;
	    v->arch.last_processor = INVALID_PROCESSOR;
	}

	if (!VMX_DOMAIN(v))
		init_timer(&v->arch.hlt_timer, hlt_timer_fn, v,
		           first_cpu(cpu_online_map));

	return 0;
}

void vcpu_share_privregs_with_guest(struct vcpu *v)
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
	struct domain *d = v->domain;
	int rc, order;

	if (HAS_PERVCPU_VHPT(d)) {
		rc = pervcpu_vhpt_alloc(v);
		if (rc != 0)
			return rc;
	}

	/* Create privregs page. */
	order = get_order_from_shift(XMAPPEDREGS_SHIFT);
	v->arch.privregs = alloc_xenheap_pages(order);
	BUG_ON(v->arch.privregs == NULL);
	memset(v->arch.privregs, 0, 1 << XMAPPEDREGS_SHIFT);
	vcpu_share_privregs_with_guest(v);

	return 0;
}

void vcpu_destroy(struct vcpu *v)
{
	if (v->domain->arch.is_vti)
		vmx_relinquish_vcpu_resources(v);
	else
		relinquish_vcpu_resources(v);
}

static void init_switch_stack(struct vcpu *v)
{
	struct pt_regs *regs = vcpu_regs (v);
	struct switch_stack *sw = (struct switch_stack *) regs - 1;
	extern void ia64_ret_from_clone;

	memset(sw, 0, sizeof(struct switch_stack) + sizeof(struct pt_regs));
	sw->ar_bspstore = (unsigned long)v + IA64_RBS_OFFSET;
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

int arch_domain_create(struct domain *d)
{
	int i;
	
	// the following will eventually need to be negotiated dynamically
	d->arch.shared_info_va = DEFAULT_SHAREDINFO_ADDR;
	d->arch.breakimm = 0x1000;
	for (i = 0; i < NR_CPUS; i++) {
		d->arch.last_vcpu[i].vcpu_id = INVALID_VCPU_ID;
	}

	if (is_idle_domain(d))
	    return 0;

#ifdef CONFIG_XEN_IA64_PERVCPU_VHPT
	d->arch.has_pervcpu_vhpt = opt_pervcpu_vhpt;
	dprintk(XENLOG_INFO, "%s:%d domain %d pervcpu_vhpt %d\n",
	        __func__, __LINE__, d->domain_id, d->arch.has_pervcpu_vhpt);
#endif
	if (tlb_track_create(d) < 0)
		goto fail_nomem1;
	d->shared_info = alloc_xenheap_pages(get_order_from_shift(XSI_SHIFT));
	if (d->shared_info == NULL)
	    goto fail_nomem;
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

	if ((d->arch.mm.pgd = pgd_alloc(&d->arch.mm)) == NULL)
	    goto fail_nomem;

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

fail_nomem:
	tlb_track_destroy(d);
fail_nomem1:
	if (d->arch.mm.pgd != NULL)
	    pgd_free(d->arch.mm.pgd);
	if (d->shared_info != NULL)
	    free_xenheap_pages(d->shared_info, get_order_from_shift(XSI_SHIFT));
	return -ENOMEM;
}

void arch_domain_destroy(struct domain *d)
{
	mm_final_teardown(d);

	if (d->shared_info != NULL)
	    free_xenheap_pages(d->shared_info, get_order_from_shift(XSI_SHIFT));

	tlb_track_destroy(d);

	/* Clear vTLB for the next domain.  */
	domain_flush_tlb_vhpt(d);

	deallocate_rid_range(d);
}

int arch_vcpu_reset(struct vcpu *v)
{
	/* FIXME: Stub for now */
	return 0;
}

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
	int i;
	struct vcpu_extra_regs *er = &c.nat->extra_regs;

	c.nat->user_regs = *vcpu_regs(v);
 	c.nat->privregs_pfn = get_gpfn_from_mfn(virt_to_maddr(v->arch.privregs) >>
                                                PAGE_SHIFT);

	/* Fill extra regs.  */
	for (i = 0; i < 8; i++) {
		er->itrs[i].pte = v->arch.itrs[i].pte.val;
		er->itrs[i].itir = v->arch.itrs[i].itir;
		er->itrs[i].vadr = v->arch.itrs[i].vadr;
		er->itrs[i].rid = v->arch.itrs[i].rid;
	}
	for (i = 0; i < 8; i++) {
		er->dtrs[i].pte = v->arch.dtrs[i].pte.val;
		er->dtrs[i].itir = v->arch.dtrs[i].itir;
		er->dtrs[i].vadr = v->arch.dtrs[i].vadr;
		er->dtrs[i].rid = v->arch.dtrs[i].rid;
	}
	er->event_callback_ip = v->arch.event_callback_ip;
	er->dcr = v->arch.privregs ? PSCB(v,dcr) : 0;
	er->iva = v->arch.iva;
}

int arch_set_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
	struct pt_regs *regs = vcpu_regs (v);
	struct domain *d = v->domain;
	int rc;
	
	*regs = c.nat->user_regs;
 	
 	if (!d->arch.is_vti) {
 		/* domain runs at PL2/3 */
 		regs->cr_ipsr |= 2UL << IA64_PSR_CPL0_BIT;
 		regs->ar_rsc |= (2 << 2); /* force PL2/3 */
 	}

	if (c.nat->flags & VGCF_EXTRA_REGS) {
		int i;
		struct vcpu_extra_regs *er = &c.nat->extra_regs;

		for (i = 0; i < 8; i++) {
			vcpu_set_itr(v, i, er->itrs[i].pte,
			             er->itrs[i].itir,
			             er->itrs[i].vadr,
			             er->itrs[i].rid);
		}
		for (i = 0; i < 8; i++) {
			vcpu_set_dtr(v, i,
			             er->dtrs[i].pte,
			             er->dtrs[i].itir,
			             er->dtrs[i].vadr,
			             er->dtrs[i].rid);
		}
		v->arch.event_callback_ip = er->event_callback_ip;
		v->arch.iva = er->iva;
	}

	if (v->is_initialised)
		return 0;

	if (d->arch.is_vti) {
		rc = vmx_final_setup_guest(v);
		if (rc != 0)
			return rc;
	} else {
		rc = vcpu_late_initialise(v);
		if (rc != 0)
			return rc;
		VCPU(v, interrupt_mask_addr) = 
			(unsigned char *) d->arch.shared_info_va +
			INT_ENABLE_OFFSET(v);
	}

	/* This overrides some registers. */
	vcpu_init_regs(v);

	if (!v->is_initialised) {
		v->is_initialised = 1;
		/* Auto-online VCPU0 when it is initialised. */
		if (v->vcpu_id == 0)
			clear_bit(_VPF_down, &v->pause_flags);
	}

	return 0;
}

static void relinquish_memory(struct domain *d, struct list_head *list)
{
    struct list_head *ent;
    struct page_info *page;
#ifndef __ia64__
    unsigned long     x, y;
#endif

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);
    ent = list->next;
    while ( ent != list )
    {
        page = list_entry(ent, struct page_info, list);
        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
        {
            /* Couldn't get a reference -- someone is freeing this page. */
            ent = ent->next;
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
        ent = ent->next;
        BUG_ON(get_gpfn_from_mfn(page_to_mfn(page)) != INVALID_M2P_ENTRY);
        put_page(page);
    }

    spin_unlock_recursive(&d->page_alloc_lock);
}

void domain_relinquish_resources(struct domain *d)
{
    /* Relinquish guest resources for VT-i domain. */
    if (d->vcpu[0] && VMX_DOMAIN(d->vcpu[0]))
	    vmx_relinquish_guest_resources(d);

    /* Tear down shadow mode stuff. */
    mm_teardown(d);

    /* Relinquish every page of memory. */
    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);

    if (d->arch.is_vti && d->arch.sal_data)
	    xfree(d->arch.sal_data);

    /* Free page used by xen oprofile buffer */
    free_xenoprof_pages(d);
}

unsigned long
domain_set_shared_info_va (unsigned long va)
{
	struct vcpu *v = current;
	struct domain *d = v->domain;

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

	__ia64_per_cpu_var(current_psr_ic_addr) = (int *)(va + XSI_PSR_IC_OFS);

	/* Remap the shared pages.  */
	set_one_rr (7UL << 61, PSCB(v,rrs[7]));

	return 0;
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

			/* Flush vhpt and tlb to restore dirty bit usage.  */
			domain_flush_tlb_vhpt(d);

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
			((d->arch.convmem_end >> PAGE_SHIFT) +
			 BITS_PER_LONG - 1) & ~(BITS_PER_LONG - 1);
		d->arch.shadow_bitmap = xmalloc_array(unsigned long,
		                   d->arch.shadow_bitmap_size / BITS_PER_LONG);
		if (d->arch.shadow_bitmap == NULL) {
			d->arch.shadow_bitmap_size = 0;
			rc = -ENOMEM;
		}
		else {
			memset(d->arch.shadow_bitmap, 0, 
			       d->arch.shadow_bitmap_size / 8);
			
			/* Flush vhtp and tlb to enable dirty bit
			   virtualization.  */
			domain_flush_tlb_vhpt(d);
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

static void loaddomainelfimage(struct domain *d, struct elf_binary *elf)
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

		while (memsz > 0) {
			p = assign_new_domain_page(d,dom_mpaddr);
			BUG_ON (unlikely(p == NULL));
			dom_imva = __va_ul(page_to_maddr(p));
			if (filesz > 0) {
				if (filesz >= PAGE_SIZE)
					memcpy((void *) dom_imva,
					       (void *) elfaddr,
					       PAGE_SIZE);
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
				memset((void *) dom_imva, 0, PAGE_SIZE);
			}
			memsz -= PAGE_SIZE;
			filesz -= PAGE_SIZE;
			elfaddr += PAGE_SIZE;
			dom_mpaddr += PAGE_SIZE;
		}
	}
}

void alloc_dom0(void)
{
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
static void physdev_init_dom0(struct domain *d)
{
	if (iomem_permit_access(d, 0UL, ~0UL))
		BUG();
	if (irqs_permit_access(d, 0, NR_IRQS-1))
		BUG();
	if (ioports_permit_access(d, 0, 0xffff))
		BUG();
}

int construct_dom0(struct domain *d, 
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
	struct page_info *start_info_page;
	unsigned long bp_mpa;
	struct ia64_boot_param *bp;

//printk("construct_dom0: starting\n");

	/* Sanity! */
	BUG_ON(d != dom0);
	BUG_ON(d->vcpu[0] == NULL);
	BUG_ON(v->is_initialised);

	printk("*** LOADING DOMAIN 0 ***\n");

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
	    if (pinitrd_start + initrd_len >= dom0_size)
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
	for ( i = 1; i < MAX_VIRT_CPUS; i++ )
	    d->shared_info->vcpu_info[i].evtchn_upcall_mask = 1;

	if (dom0_max_vcpus == 0)
	    dom0_max_vcpus = MAX_VIRT_CPUS;
	if (dom0_max_vcpus > num_online_cpus())
	    dom0_max_vcpus = num_online_cpus();
	if (dom0_max_vcpus > MAX_VIRT_CPUS)
	    dom0_max_vcpus = MAX_VIRT_CPUS;
	
	printk ("Dom0 max_vcpus=%d\n", dom0_max_vcpus);
	for ( i = 1; i < dom0_max_vcpus; i++ )
	    if (alloc_vcpu(d, i, i) == NULL)
		panic("Cannot allocate dom0 vcpu %d\n", i);

	/* Copy the OS image. */
	loaddomainelfimage(d,&elf);

	BUILD_BUG_ON(sizeof(start_info_t) + sizeof(dom0_vga_console_info_t) +
	             sizeof(struct ia64_boot_param) > PAGE_SIZE);

	/* Set up start info area. */
	d->shared_info->arch.start_info_pfn = pstart_info >> PAGE_SHIFT;
	start_info_page = assign_new_domain_page(d, pstart_info);
	if (start_info_page == NULL)
		panic("can't allocate start info page");
	si = page_to_virt(start_info_page);
	memset(si, 0, PAGE_SIZE);
	snprintf(si->magic, sizeof(si->magic), "xen-%i.%i-ia64",
		xen_major_version(), xen_minor_version());
	si->nr_pages     = max_pages;
	si->flags = SIF_INITDOMAIN|SIF_PRIVILEGED;

	printk("Dom0: 0x%lx\n", (u64)dom0);

	v->is_initialised = 1;
	clear_bit(_VPF_down, &v->pause_flags);

	/* Build firmware.
	   Note: Linux kernel reserve memory used by start_info, so there is
	   no need to remove it from MDT.  */
	bp_mpa = pstart_info + sizeof(struct start_info);
	dom_fw_setup(d, bp_mpa, max_pages * PAGE_SIZE);

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

void machine_restart(char * __unused)
{
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
	if (running_on_sim)
		printk ("machine_halt called.  spinning...\n");
	else
		cpu_halt();
	while(1);
}

void sync_vcpu_execstate(struct vcpu *v)
{
//	__ia64_save_fpu(v->arch._thread.fph);
//	if (VMX_DOMAIN(v))
//		vmx_save_state(v);
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

static void parse_dom0_mem(char *s)
{
	dom0_size = parse_size_and_unit(s, NULL);
}
custom_param("dom0_mem", parse_dom0_mem);
