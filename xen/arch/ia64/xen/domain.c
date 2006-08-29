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
#include <xen/elf.h>
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
#include <asm/tlbflush.h>
#include <asm/regionreg.h>
#include <asm/dom_fw.h>
#include <asm/shadow.h>

unsigned long dom0_size = 512*1024*1024;
unsigned long dom0_align = 64*1024*1024;

/* dom0_max_vcpus: maximum number of VCPUs to create for dom0.  */
static unsigned int dom0_max_vcpus = 1;
integer_param("dom0_max_vcpus", dom0_max_vcpus); 

extern unsigned long running_on_sim;

extern char dom0_command_line[];

/* FIXME: where these declarations should be there ? */
extern void serial_input_init(void);
static void init_switch_stack(struct vcpu *v);
extern void vmx_do_launch(struct vcpu *);

/* this belongs in include/asm, but there doesn't seem to be a suitable place */
extern struct vcpu *ia64_switch_to (struct vcpu *next_task);

/* Address of vpsr.i (in fact evtchn_upcall_mask) of current vcpu.
   This is a Xen virtual address.  */
DEFINE_PER_CPU(uint8_t *, current_psr_i_addr);
DEFINE_PER_CPU(int *, current_psr_ic_addr);

#include <xen/sched-if.h>

static void flush_vtlb_for_context_switch(struct vcpu* vcpu)
{
	int cpu = smp_processor_id();
	int last_vcpu_id = vcpu->domain->arch.last_vcpu[cpu].vcpu_id;
	int last_processor = vcpu->arch.last_processor;

	if (is_idle_domain(vcpu->domain))
		return;
	
	vcpu->domain->arch.last_vcpu[cpu].vcpu_id = vcpu->vcpu_id;
	vcpu->arch.last_processor = cpu;

	if ((last_vcpu_id != vcpu->vcpu_id &&
	     last_vcpu_id != INVALID_VCPU_ID) ||
	    (last_vcpu_id == vcpu->vcpu_id &&
	     last_processor != cpu &&
	     last_processor != INVALID_PROCESSOR)) {

		// if the vTLB implementation was changed,
		// the followings must be updated either.
		if (VMX_DOMAIN(vcpu)) {
			// currently vTLB for vt-i domian is per vcpu.
			// so any flushing isn't needed.
		} else {
			vhpt_flush();
		}
		local_flush_tlb_all();
	}
}

void schedule_tail(struct vcpu *prev)
{
	extern char ia64_ivt;
	context_saved(prev);

	if (VMX_DOMAIN(current)) {
		vmx_do_launch(current);
		migrate_timer(&current->arch.arch_vmx.vtm.vtm_timer,
		              current->processor);
	} else {
		ia64_set_iva(&ia64_ivt);
        	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
		        VHPT_ENABLED);
		load_region_regs(current);
		vcpu_load_kernel_regs(current);
		__ia64_per_cpu_var(current_psr_i_addr) = &current->domain->
		  shared_info->vcpu_info[current->vcpu_id].evtchn_upcall_mask;
		__ia64_per_cpu_var(current_psr_ic_addr) = (int *)
		  (current->domain->arch.shared_info_va + XSI_PSR_IC_OFS);
		migrate_timer(&current->arch.hlt_timer, current->processor);
	}
	flush_vtlb_for_context_switch(current);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    uint64_t spsr;
    uint64_t pta;

    local_irq_save(spsr);

    __ia64_save_fpu(prev->arch._thread.fph);
    __ia64_load_fpu(next->arch._thread.fph);
    if (VMX_DOMAIN(prev)) {
	vmx_save_state(prev);
	if (!VMX_DOMAIN(next)) {
	    /* VMX domains can change the physical cr.dcr.
	     * Restore default to prevent leakage. */
	    ia64_setreg(_IA64_REG_CR_DCR, (IA64_DCR_DP | IA64_DCR_DK
	                   | IA64_DCR_DX | IA64_DCR_DR | IA64_DCR_PP
	                   | IA64_DCR_DA | IA64_DCR_DD | IA64_DCR_LC));
	}
    }
    if (VMX_DOMAIN(next))
	vmx_load_state(next);
    /*ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);*/
    prev = ia64_switch_to(next);

    /* Note: ia64_switch_to does not return here at vcpu initialization.  */

    //cpu_set(smp_processor_id(), current->domain->domain_dirty_cpumask);
 
    if (VMX_DOMAIN(current)){
	vmx_load_all_rr(current);
	migrate_timer(&current->arch.arch_vmx.vtm.vtm_timer,
	              current->processor);
    } else {
	struct domain *nd;
    	extern char ia64_ivt;

    	ia64_set_iva(&ia64_ivt);

	nd = current->domain;
    	if (!is_idle_domain(nd)) {
        	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
			     VHPT_ENABLED);
	    	load_region_regs(current);
	    	vcpu_load_kernel_regs(current);
		vcpu_set_next_timer(current);
		if (vcpu_timer_expired(current))
			vcpu_pend_timer(current);
		__ia64_per_cpu_var(current_psr_i_addr) = &nd->shared_info->
		  vcpu_info[current->vcpu_id].evtchn_upcall_mask;
		__ia64_per_cpu_var(current_psr_ic_addr) =
		  (int *)(nd->arch.shared_info_va + XSI_PSR_IC_OFS);
    	} else {
		/* When switching to idle domain, only need to disable vhpt
		 * walker. Then all accesses happen within idle context will
		 * be handled by TR mapping and identity mapping.
		 */
		pta = ia64_get_pta();
		ia64_set_pta(pta & ~VHPT_ENABLED);
		__ia64_per_cpu_var(current_psr_i_addr) = NULL;
		__ia64_per_cpu_var(current_psr_ic_addr) = NULL;
        }
    }
    flush_vtlb_for_context_switch(current);
    local_irq_restore(spsr);
    context_saved(prev);
}

void continue_running(struct vcpu *same)
{
	/* nothing to do */
}

static void default_idle(void)
{
	local_irq_disable();
	if ( !softirq_pending(smp_processor_id()) )
	        safe_halt();
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

struct vcpu *alloc_vcpu_struct(struct domain *d, unsigned int vcpu_id)
{
	struct vcpu *v;
	struct thread_info *ti;

	/* Still keep idle vcpu0 static allocated at compilation, due
	 * to some code from Linux still requires it in early phase.
	 */
	if (is_idle_domain(d) && !vcpu_id)
	    v = idle_vcpu[0];
	else {
	    if ((v = alloc_xenheap_pages(KERNEL_STACK_SIZE_ORDER)) == NULL)
		return NULL;
	    memset(v, 0, sizeof(*v)); 

	    ti = alloc_thread_info(v);
	    /* Clear thread_info to clear some important fields, like
	     * preempt_count
	     */
	    memset(ti, 0, sizeof(struct thread_info));
	    init_switch_stack(v);
	}

	if (!is_idle_domain(d)) {
	    if (!d->arch.is_vti) {
		int order;
		int i;

		/* Create privregs page only if not VTi. */
		order = get_order_from_shift(XMAPPEDREGS_SHIFT);
		v->arch.privregs = alloc_xenheap_pages(order);
		BUG_ON(v->arch.privregs == NULL);
		memset(v->arch.privregs, 0, 1 << XMAPPEDREGS_SHIFT);
		for (i = 0; i < (1 << order); i++)
		    share_xen_page_with_guest(virt_to_page(v->arch.privregs) +
		                              i, d, XENSHARE_writable);
	    }

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
	if (!VMX_DOMAIN(v)){
		init_timer(&v->arch.hlt_timer, hlt_timer_fn, v,
		           first_cpu(cpu_online_map));
	}

	return v;
}

void relinquish_vcpu_resources(struct vcpu *v)
{
    if (v->arch.privregs != NULL) {
        free_xenheap_pages(v->arch.privregs,
                           get_order_from_shift(XMAPPEDREGS_SHIFT));
        v->arch.privregs = NULL;
    }
    kill_timer(&v->arch.hlt_timer);
}

void free_vcpu_struct(struct vcpu *v)
{
	if (VMX_DOMAIN(v))
		vmx_relinquish_vcpu_resources(v);
	else
		relinquish_vcpu_resources(v);

	free_xenheap_pages(v, KERNEL_STACK_SIZE_ORDER);
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

	d->shared_info = alloc_xenheap_pages(get_order_from_shift(XSI_SHIFT));
	if (d->shared_info == NULL)
	    goto fail_nomem;
	memset(d->shared_info, 0, XSI_SIZE);
	for (i = 0; i < XSI_SIZE; i += PAGE_SIZE)
	    share_xen_page_with_guest(virt_to_page((char *)d->shared_info + i),
	                              d, XENSHARE_writable);

	d->max_pages = (128UL*1024*1024)/PAGE_SIZE; // 128MB default // FIXME
	/* We may also need emulation rid for region4, though it's unlikely
	 * to see guest issue uncacheable access in metaphysical mode. But
	 * keep such info here may be more sane.
	 */
	if (!allocate_rid_range(d,0))
		goto fail_nomem;

	memset(&d->arch.mm, 0, sizeof(d->arch.mm));

	if ((d->arch.mm.pgd = pgd_alloc(&d->arch.mm)) == NULL)
	    goto fail_nomem;

	d->arch.ioport_caps = rangeset_new(d, "I/O Ports",
	                                   RANGESETF_prettyprint_hex);

	printf ("arch_domain_create: domain=%p\n", d);
	return 0;

fail_nomem:
	if (d->arch.mm.pgd != NULL)
	    pgd_free(d->arch.mm.pgd);
	if (d->shared_info != NULL)
	    free_xenheap_pages(d->shared_info, get_order_from_shift(XSI_SHIFT));
	return -ENOMEM;
}

void arch_domain_destroy(struct domain *d)
{
	BUG_ON(d->arch.mm.pgd != NULL);
	if (d->shared_info != NULL) {
		/* If this domain is domVTi, the shared_info page may
		 * be replaced with domheap. Then the shared_info page
		 * frees in relinquish_mm().
		 */
		if (IS_XEN_HEAP_FRAME(virt_to_page(d->shared_info))) {
			free_xenheap_pages(d->shared_info,
			                   get_order_from_shift(XSI_SHIFT));
		}
	}
	if (d->arch.shadow_bitmap != NULL)
		xfree(d->arch.shadow_bitmap);

	/* Clear vTLB for the next domain.  */
	domain_flush_tlb_vhpt(d);

	deallocate_rid_range(d);
}

void arch_getdomaininfo_ctxt(struct vcpu *v, struct vcpu_guest_context *c)
{
	int i;
	struct vcpu_extra_regs *er = &c->extra_regs;

	c->user_regs = *vcpu_regs (v);
 	c->privregs_pfn = virt_to_maddr(v->arch.privregs) >> PAGE_SHIFT;

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
	er->dcr = v->arch.dcr;
	er->iva = v->arch.iva;
}

int arch_set_info_guest(struct vcpu *v, struct vcpu_guest_context *c)
{
	struct pt_regs *regs = vcpu_regs (v);
	struct domain *d = v->domain;
	
	*regs = c->user_regs;
 	
 	if (!d->arch.is_vti) {
 		/* domain runs at PL2/3 */
 		regs->cr_ipsr |= 2UL << IA64_PSR_CPL0_BIT;
 		regs->ar_rsc |= (2 << 2); /* force PL2/3 */
 	}

	if (c->flags & VGCF_EXTRA_REGS) {
		int i;
		struct vcpu_extra_regs *er = &c->extra_regs;

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
		v->arch.dcr = er->dcr;
		v->arch.iva = er->iva;
  	}
	
  	if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
 		return 0;
 	if (d->arch.is_vti)
 		vmx_final_setup_guest(v);
	
 	/* This overrides some registers.  */
  	vcpu_init_regs(v);
  
	/* Don't redo final setup */
	set_bit(_VCPUF_initialised, &v->vcpu_flags);
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
    /* Relinquish every page of memory. */

    // relase page traversing d->arch.mm.
    relinquish_mm(d);

    if (d->vcpu[0] && VMX_DOMAIN(d->vcpu[0]))
	    vmx_relinquish_guest_resources(d);

    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);

    if (d->arch.is_vti && d->arch.sal_data)
	    xfree(d->arch.sal_data);
}

void build_physmap_table(struct domain *d)
{
	struct list_head *list_ent = d->page_list.next;
	unsigned long mfn, i = 0;

	while(list_ent != &d->page_list) {
	    mfn = page_to_mfn(list_entry(
		list_ent, struct page_info, list));
	    assign_domain_page(d, i << PAGE_SHIFT, mfn << PAGE_SHIFT);

	    i++;
	    list_ent = mfn_to_page(mfn)->list.next;
	}
}

unsigned long
domain_set_shared_info_va (unsigned long va)
{
	struct vcpu *v = current;
	struct domain *d = v->domain;
	struct vcpu *v1;

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
	printf ("Domain set shared_info_va to 0x%016lx\n", va);
	d->arch.shared_info_va = va;

	for_each_vcpu (d, v1) {
		VCPU(v1, interrupt_mask_addr) = 
			(unsigned char *)va + INT_ENABLE_OFFSET(v1);
	}

	__ia64_per_cpu_var(current_psr_ic_addr) = (int *)(va + XSI_PSR_IC_OFS);

	/* Remap the shared pages.  */
	set_one_rr (7UL << 61, PSCB(v,rrs[7]));

	return 0;
}

/* Transfer and clear the shadow bitmap in 1kB chunks for L1 cache. */
#define SHADOW_COPY_CHUNK (1024 / sizeof (unsigned long))

int shadow_mode_control(struct domain *d, xen_domctl_shadow_op_t *sc)
{
	unsigned int op = sc->op;
	int          rc = 0;
	int i;
	//struct vcpu *v;

	if (unlikely(d == current->domain)) {
		DPRINTK("Don't try to do a shadow op on yourself!\n");
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

		d->arch.shadow_bitmap_size = (d->max_pages + BITS_PER_LONG-1) &
		                             ~(BITS_PER_LONG-1);
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
		int nbr_longs;

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

		nbr_longs = (sc->pages + BITS_PER_LONG - 1) / BITS_PER_LONG;

		for (i = 0; i < nbr_longs; i += SHADOW_COPY_CHUNK) {
			int size = (nbr_longs - i) > SHADOW_COPY_CHUNK ?
			           SHADOW_COPY_CHUNK : nbr_longs - i;
     
			if (copy_to_guest_offset(sc->dirty_bitmap, i,
			                         d->arch.shadow_bitmap + i,
			                         size)) {
				rc = -EFAULT;
				break;
			}

			memset(d->arch.shadow_bitmap + i,
			       0, size * sizeof(unsigned long));
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

		size = (sc->pages + BITS_PER_LONG - 1) / BITS_PER_LONG;
		if (copy_to_guest(sc->dirty_bitmap, 
		                  d->arch.shadow_bitmap, size)) {
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

// see arch/x86/xxx/domain_build.c
int elf_sanity_check(Elf_Ehdr *ehdr)
{
	if (!(IS_ELF(*ehdr)))
	{
		printk("DOM0 image is not a Xen-compatible Elf image.\n");
		return 0;
	}
	return 1;
}

static void loaddomainelfimage(struct domain *d, unsigned long image_start)
{
	char *elfbase = (char *) image_start;
	Elf_Ehdr ehdr;
	Elf_Phdr phdr;
	int h, filesz, memsz;
	unsigned long elfaddr, dom_mpaddr, dom_imva;
	struct page_info *p;
  
	memcpy(&ehdr, (void *) image_start, sizeof(Elf_Ehdr));
	for ( h = 0; h < ehdr.e_phnum; h++ ) {
		memcpy(&phdr,
		       elfbase + ehdr.e_phoff + (h*ehdr.e_phentsize),
		       sizeof(Elf_Phdr));
		if ((phdr.p_type != PT_LOAD))
		    continue;

		filesz = phdr.p_filesz;
		memsz = phdr.p_memsz;
		elfaddr = (unsigned long) elfbase + phdr.p_offset;
		dom_mpaddr = phdr.p_paddr;

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
				if (phdr.p_flags & PF_X) {
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

	/* Check dom0 align.  */
	if ((dom0_align - 1) & dom0_align) { /* not a power of two */
		panic("dom0_align (%lx) must be power of two, boot aborted"
		      " (try e.g. dom0_align=256M or dom0_align=65536K)\n",
		      dom0_align);
	}
	if (dom0_align < PAGE_SIZE) {
		panic("dom0_align must be >= %ld, boot aborted"
		      " (try e.g. dom0_align=256M or dom0_align=65536K)\n",
		      PAGE_SIZE);
	}
	if (dom0_size % dom0_align) {
		dom0_size = (dom0_size / dom0_align + 1) * dom0_align;
		printf("dom0_size rounded up to %ld, due to dom0_align=%lx\n",
		     dom0_size,dom0_align);
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

	struct domain_setup_info dsi;
	unsigned long p_start;
	unsigned long pkern_start;
	unsigned long pkern_entry;
	unsigned long pkern_end;
	unsigned long pinitrd_start = 0;
	unsigned long pstart_info;
	struct page_info *start_info_page;
	unsigned long bp_mpa;
	struct ia64_boot_param *bp;

#ifdef VALIDATE_VT
	unsigned int vmx_dom0 = 0;
	unsigned long mfn;
	struct page_info *page = NULL;
#endif

//printf("construct_dom0: starting\n");

	/* Sanity! */
	BUG_ON(d != dom0);
	BUG_ON(d->vcpu[0] == NULL);
	BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));

	memset(&dsi, 0, sizeof(struct domain_setup_info));

	printk("*** LOADING DOMAIN 0 ***\n");

	max_pages = dom0_size / PAGE_SIZE;
	d->max_pages = max_pages;
	d->tot_pages = 0;
	dsi.image_addr = (unsigned long)image_start;
	dsi.image_len  = image_len;
	rc = parseelfimage(&dsi);
	if ( rc != 0 )
	    return rc;

#ifdef VALIDATE_VT
	/* Temp workaround */
	if (running_on_sim)
	    dsi.xen_section_string = (char *)1;

	/* Check whether dom0 is vti domain */
	if ((!vmx_enabled) && !dsi.xen_section_string) {
	    printk("Lack of hardware support for unmodified vmx dom0\n");
	    panic("");
	}

	if (vmx_enabled && !dsi.xen_section_string) {
	    printk("Dom0 is vmx domain!\n");
	    vmx_dom0 = 1;
	}
#endif

	p_start = dsi.v_start;
	pkern_start = dsi.v_kernstart;
	pkern_end = dsi.v_kernend;
	pkern_entry = dsi.v_kernentry;

//printk("p_start=%lx, pkern_start=%lx, pkern_end=%lx, pkern_entry=%lx\n",p_start,pkern_start,pkern_end,pkern_entry);

	if ( (p_start & (PAGE_SIZE-1)) != 0 )
	{
	    printk("Initial guest OS must load to a page boundary.\n");
	    return -EINVAL;
	}

	pstart_info = PAGE_ALIGN(pkern_end);
	if(initrd_start && initrd_len){
	    unsigned long offset;

	    pinitrd_start= dom0_size - (PAGE_ALIGN(initrd_len) + 4*1024*1024);
	    if (pinitrd_start <= pstart_info)
		panic("%s:enough memory is not assigned to dom0", __func__);

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
	
	printf ("Dom0 max_vcpus=%d\n", dom0_max_vcpus);
	for ( i = 1; i < dom0_max_vcpus; i++ )
	    if (alloc_vcpu(d, i, i) == NULL)
		printf ("Cannot allocate dom0 vcpu %d\n", i);

	/* Copy the OS image. */
	loaddomainelfimage(d,image_start);

	/* Copy the initial ramdisk. */
	//if ( initrd_len != 0 )
	//    memcpy((void *)vinitrd_start, initrd_start, initrd_len);

	BUILD_BUG_ON(sizeof(start_info_t) + sizeof(dom0_vga_console_info_t) +
	             sizeof(struct ia64_boot_param) > PAGE_SIZE);

	/* Set up start info area. */
	d->shared_info->arch.start_info_pfn = pstart_info >> PAGE_SHIFT;
	start_info_page = assign_new_domain_page(d, pstart_info);
	if (start_info_page == NULL)
		panic("can't allocate start info page");
	si = page_to_virt(start_info_page);
	memset(si, 0, PAGE_SIZE);
	sprintf(si->magic, "xen-%i.%i-ia64",
		xen_major_version(), xen_minor_version());
	si->nr_pages     = max_pages;
	si->flags = SIF_INITDOMAIN|SIF_PRIVILEGED;

	printk("Dom0: 0x%lx\n", (u64)dom0);

#ifdef VALIDATE_VT
	/* VMX specific construction for Dom0, if hardware supports VMX
	 * and Dom0 is unmodified image
	 */
	if (vmx_dom0)
	    vmx_final_setup_guest(v);
#endif

	set_bit(_VCPUF_initialised, &v->vcpu_flags);

	/* Build firmware.
	   Note: Linux kernel reserve memory used by start_info, so there is
	   no need to remove it from MDT.  */
	bp_mpa = pstart_info + sizeof(struct start_info);
	dom_fw_setup(d, bp_mpa, max_pages * PAGE_SIZE);

	/* Fill boot param.  */
	strncpy((char *)si->cmd_line, dom0_command_line, sizeof(si->cmd_line));
	si->cmd_line[sizeof(si->cmd_line)-1] = 0;

	bp = (struct ia64_boot_param *)((unsigned char *)si +
	                                sizeof(start_info_t));
	bp->command_line = pstart_info + offsetof (start_info_t, cmd_line);

	/* We assume console has reached the last line!  */
	bp->console_info.num_cols = ia64_boot_param->console_info.num_cols;
	bp->console_info.num_rows = ia64_boot_param->console_info.num_rows;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = bp->console_info.num_rows == 0 ?
	                          0 : bp->console_info.num_rows - 1;

	bp->initrd_start = dom0_size -
	             (PAGE_ALIGN(ia64_boot_param->initrd_size) + 4*1024*1024);
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

	// FIXME: Hack for keyboard input
	//serial_input_init();

	return 0;
}

void machine_restart(char * __unused)
{
	console_start_sync();
	if (running_on_sim)
		printf ("machine_restart called.  spinning...\n");
	else
		(*efi.reset_system)(EFI_RESET_WARM,0,0,NULL);
	while(1);
}

extern void cpu_halt(void);

void machine_halt(void)
{
	console_start_sync();
	if (running_on_sim)
		printf ("machine_halt called.  spinning...\n");
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

static void parse_dom0_mem(char *s)
{
	dom0_size = parse_size_and_unit(s);
}
custom_param("dom0_mem", parse_dom0_mem);


static void parse_dom0_align(char *s)
{
	dom0_align = parse_size_and_unit(s);
}
custom_param("dom0_align", parse_dom0_align);
