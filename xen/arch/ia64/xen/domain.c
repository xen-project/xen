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
#include <asm/ptrace.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/setup.h>
//#include <asm/mpspec.h>
#include <xen/irq.h>
#include <xen/event.h>
//#include <xen/shadow.h>
#include <xen/console.h>
#include <xen/compile.h>

#include <xen/elf.h>
//#include <asm/page.h>
#include <asm/pgalloc.h>

#include <asm/offsets.h>  /* for IA64_THREAD_INFO_SIZE */

#include <asm/vcpu.h>   /* for function declarations */
#include <public/arch-ia64.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_vpd.h>
#include <asm/vmx_phy_mode.h>
#include <asm/pal.h>
#include <asm/vhpt.h>
#include <public/hvm/ioreq.h>
#include <public/arch-ia64.h>
#include <asm/tlbflush.h>
#include <asm/regionreg.h>
#include <asm/dom_fw.h>

#ifndef CONFIG_XEN_IA64_DOM0_VP
#define CONFIG_DOMAIN0_CONTIGUOUS
#endif
unsigned long dom0_start = -1L;
unsigned long dom0_size = 512*1024*1024;
unsigned long dom0_align = 64*1024*1024;

/* dom0_max_vcpus: maximum number of VCPUs to create for dom0.  */
static unsigned int dom0_max_vcpus = 1;
integer_param("dom0_max_vcpus", dom0_max_vcpus); 

// initialized by arch/ia64/setup.c:find_initrd()
unsigned long initrd_start = 0, initrd_end = 0;
extern unsigned long running_on_sim;

#define IS_XEN_ADDRESS(d,a) ((a >= d->xen_vastart) && (a <= d->xen_vaend))

/* FIXME: where these declarations should be there ? */
extern long platform_is_hp_ski(void);
extern void serial_input_init(void);
static void init_switch_stack(struct vcpu *v);
void build_physmap_table(struct domain *d);

static void try_to_clear_PGC_allocate(struct domain* d,
                                      struct page_info* page);

/* this belongs in include/asm, but there doesn't seem to be a suitable place */
void arch_domain_destroy(struct domain *d)
{
	BUG_ON(d->arch.mm.pgd != NULL);
	if (d->shared_info != NULL)
		free_xenheap_page(d->shared_info);

	domain_flush_destroy (d);

	deallocate_rid_range(d);
}

static void default_idle(void)
{
	int cpu = smp_processor_id();
	local_irq_disable();
	if ( !softirq_pending(cpu))
	        safe_halt();
	local_irq_enable();
}

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
	    while ( !softirq_pending(cpu) )
	        default_idle();
	    add_preempt_count(SOFTIRQ_OFFSET);
	    raise_softirq(SCHEDULE_SOFTIRQ);
	    do_softirq();
	    sub_preempt_count(SOFTIRQ_OFFSET);
	}
}

void startup_cpu_idle_loop(void)
{
	/* Just some sanity to ensure that the scheduler is set up okay. */
	ASSERT(current->domain == IDLE_DOMAIN_ID);
	raise_softirq(SCHEDULE_SOFTIRQ);

	continue_cpu_idle_loop();
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
	    v->arch.privregs = 
		alloc_xenheap_pages(get_order(sizeof(mapped_regs_t)));
	    BUG_ON(v->arch.privregs == NULL);
	    memset(v->arch.privregs, 0, PAGE_SIZE);

	    if (!vcpu_id)
	    	memset(&d->shared_info->evtchn_mask[0], 0xff,
		    sizeof(d->shared_info->evtchn_mask));

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
	}

	return v;
}

void free_vcpu_struct(struct vcpu *v)
{
	if (VMX_DOMAIN(v))
		vmx_relinquish_vcpu_resources(v);
	else {
		if (v->arch.privregs != NULL)
			free_xenheap_pages(v->arch.privregs, get_order(sizeof(mapped_regs_t)));
	}

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
	// ia64_ret_from_clone (which b0 gets in new_thread) switches
	// to user stack
	v->arch._thread.on_ustack = 0;
	memset(v->arch._thread.fph,0,sizeof(struct ia64_fpreg)*96);
}

int arch_domain_create(struct domain *d)
{
	// the following will eventually need to be negotiated dynamically
	d->xen_vastart = XEN_START_ADDR;
	d->xen_vaend = XEN_END_ADDR;
	d->arch.shared_info_va = SHAREDINFO_ADDR;
	d->arch.breakimm = 0x1000;

	if (is_idle_domain(d))
	    return 0;

	if ((d->shared_info = (void *)alloc_xenheap_page()) == NULL)
	    goto fail_nomem;
	memset(d->shared_info, 0, PAGE_SIZE);

	d->max_pages = (128UL*1024*1024)/PAGE_SIZE; // 128MB default // FIXME
	/* We may also need emulation rid for region4, though it's unlikely
	 * to see guest issue uncacheable access in metaphysical mode. But
	 * keep such info here may be more sane.
	 */
	if (!allocate_rid_range(d,0))
		goto fail_nomem;
	d->arch.sys_pgnr = 0;

	memset(&d->arch.mm, 0, sizeof(d->arch.mm));

	d->arch.physmap_built = 0;
	if ((d->arch.mm.pgd = pgd_alloc(&d->arch.mm)) == NULL)
	    goto fail_nomem;

	printf ("arch_domain_create: domain=%p\n", d);
	return 0;

fail_nomem:
	if (d->arch.mm.pgd != NULL)
	    pgd_free(d->arch.mm.pgd);
	if (d->shared_info != NULL)
	    free_xenheap_page(d->shared_info);
	return -ENOMEM;
}

void arch_getdomaininfo_ctxt(struct vcpu *v, struct vcpu_guest_context *c)
{
	c->regs = *vcpu_regs (v);
	c->shared = v->domain->shared_info->arch;
}

int arch_set_info_guest(struct vcpu *v, struct vcpu_guest_context *c)
{
	struct pt_regs *regs = vcpu_regs (v);
	struct domain *d = v->domain;

	if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            return 0;
	if (c->flags & VGCF_VMX_GUEST) {
	    if (!vmx_enabled) {
		printk("No VMX hardware feature for vmx domain.\n");
		return -EINVAL;
	    }

	    if (v == d->vcpu[0])
		vmx_setup_platform(d, c);

	    vmx_final_setup_guest(v);
	} else if (!d->arch.physmap_built)
	    build_physmap_table(d);

	*regs = c->regs;
	if (v == d->vcpu[0]) {
	    /* Only for first vcpu.  */
	    d->arch.sys_pgnr = c->sys_pgnr;
	    d->arch.initrd_start = c->initrd.start;
	    d->arch.initrd_len   = c->initrd.size;
	    d->arch.cmdline      = c->cmdline;
	    d->shared_info->arch = c->shared;

	    /* Cache synchronization seems to be done by the linux kernel
	       during mmap/unmap operation.  However be conservative.  */
	    domain_cache_flush (d, 1);
	}
	new_thread(v, regs->cr_iip, 0, 0);

	if ( c->privregs && copy_from_user(v->arch.privregs,
			   c->privregs, sizeof(mapped_regs_t))) {
	    printk("Bad ctxt address in arch_set_info_guest: %p\n",
		   c->privregs);
	    return -EFAULT;
	}

	v->arch.domain_itm_last = -1L;

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
#ifdef CONFIG_XEN_IA64_DOM0_VP
#if 1
        BUG_ON(get_gpfn_from_mfn(page_to_mfn(page)) != INVALID_M2P_ENTRY);
#else
        //XXX this should be done at traversing the P2M table.
        if (page_get_owner(page) == d)
            set_gpfn_from_mfn(page_to_mfn(page), INVALID_M2P_ENTRY);
#endif
#endif
        put_page(page);
    }

    spin_unlock_recursive(&d->page_alloc_lock);
}

static void
relinquish_pte(struct domain* d, pte_t* pte)
{
    unsigned long mfn = pte_pfn(*pte);
    struct page_info* page;

    // vmx domain use bit[58:56] to distinguish io region from memory.
    // see vmx_build_physmap_table() in vmx_init.c
    if (((mfn << PAGE_SHIFT) & GPFN_IO_MASK) != GPFN_MEM)
        return;

    // domain might map IO space or acpi table pages. check it.
    if (!mfn_valid(mfn))
        return;
    page = mfn_to_page(mfn);
    // struct page_info corresponding to mfn may exist or not depending
    // on CONFIG_VIRTUAL_FRAME_TABLE.
    // This check is too easy.
    // The right way is to check whether this page is of io area or acpi pages
    if (page_get_owner(page) == NULL) {
        BUG_ON(page->count_info != 0);
        return;
    }

#ifdef CONFIG_XEN_IA64_DOM0_VP
    if (page_get_owner(page) == d) {
        BUG_ON(get_gpfn_from_mfn(mfn) == INVALID_M2P_ENTRY);
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
    }
#endif
    try_to_clear_PGC_allocate(d, page);
    put_page(page);
}

static void
relinquish_pmd(struct domain* d, pmd_t* pmd, unsigned long offset)
{
    unsigned long i;
    pte_t* pte = pte_offset_map(pmd, offset);

    for (i = 0; i < PTRS_PER_PTE; i++, pte++) {
        if (!pte_present(*pte))
            continue;
        
        relinquish_pte(d, pte);
    }
    pte_free_kernel(pte_offset_map(pmd, offset));
}

static void
relinquish_pud(struct domain* d, pud_t *pud, unsigned long offset)
{
    unsigned long i;
    pmd_t *pmd = pmd_offset(pud, offset);
    
    for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
        if (!pmd_present(*pmd))
            continue;
        
        relinquish_pmd(d, pmd, offset + (i << PMD_SHIFT));
    }
    pmd_free(pmd_offset(pud, offset));
}

static void
relinquish_pgd(struct domain* d, pgd_t *pgd, unsigned long offset)
{
    unsigned long i;
    pud_t *pud = pud_offset(pgd, offset);

    for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
        if (!pud_present(*pud))
            continue;

        relinquish_pud(d, pud, offset + (i << PUD_SHIFT));
    }
    pud_free(pud_offset(pgd, offset));
}

static void
relinquish_mm(struct domain* d)
{
    struct mm_struct* mm = &d->arch.mm;
    unsigned long i;
    pgd_t* pgd;

    if (mm->pgd == NULL)
        return;

    pgd = pgd_offset(mm, 0);
    for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
        if (!pgd_present(*pgd))
            continue;

        relinquish_pgd(d, pgd, i << PGDIR_SHIFT);
    }
    pgd_free(mm->pgd);
    mm->pgd = NULL;
}

void domain_relinquish_resources(struct domain *d)
{
    /* Relinquish every page of memory. */

    // relase page traversing d->arch.mm.
    relinquish_mm(d);

    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);
}

// heavily leveraged from linux/arch/ia64/kernel/process.c:copy_thread()
// and linux/arch/ia64/kernel/process.c:kernel_thread()
void new_thread(struct vcpu *v,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
	struct domain *d = v->domain;
	struct pt_regs *regs;
	extern char dom0_command_line[];

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0 && v->vcpu_id == 0) start_pc += dom0_start;
#endif

	regs = vcpu_regs (v);
	if (VMX_DOMAIN(v)) {
		/* dt/rt/it:1;i/ic:1, si:1, vm/bn:1, ac:1 */
		regs->cr_ipsr = 0x501008826008; /* Need to be expanded as macro */
	} else {
		regs->cr_ipsr = ia64_getreg(_IA64_REG_PSR)
		  | IA64_PSR_BITS_TO_SET | IA64_PSR_BN;
		regs->cr_ipsr &= ~(IA64_PSR_BITS_TO_CLEAR
				   | IA64_PSR_RI | IA64_PSR_IS);
		regs->cr_ipsr |= 2UL << IA64_PSR_CPL0_BIT; // domain runs at PL2
	}
	regs->cr_iip = start_pc;
	regs->cr_ifs = 1UL << 63; /* or clear? */
	regs->ar_fpsr = FPSR_DEFAULT;

	if (VMX_DOMAIN(v)) {
		vmx_init_all_rr(v);
		if (d == dom0)
		    regs->r28 = dom_fw_setup(d,dom0_command_line,
					     COMMAND_LINE_SIZE);
		/* Virtual processor context setup */
		VCPU(v, vpsr) = IA64_PSR_BN;
		VCPU(v, dcr) = 0;
	} else {
		init_all_rr(v);
		if (v->vcpu_id == 0) {
			/* Build the firmware.  */
			if (d == dom0) 
				regs->r28 = dom_fw_setup(d,dom0_command_line,
							 COMMAND_LINE_SIZE);
			else {
				const char *cmdline = d->arch.cmdline;
				int len;

				if (*cmdline == 0) {
#define DEFAULT_CMDLINE "nomca nosmp xencons=tty0 console=tty0 root=/dev/hda1"
					cmdline = DEFAULT_CMDLINE;
					len = sizeof (DEFAULT_CMDLINE);
					printf("domU command line defaulted to"
					       DEFAULT_CMDLINE "\n");
				}
				else
					len = IA64_COMMAND_LINE_SIZE;

				regs->r28 = dom_fw_setup (d, cmdline, len);
			}
			d->shared_info->arch.flags = (d == dom0) ?
				(SIF_INITDOMAIN|SIF_PRIVILEGED) : 0;
		}
		regs->ar_rsc |= (2 << 2); /* force PL2/3 */
		VCPU(v, banknum) = 1;
		VCPU(v, metaphysical_mode) = 1;
		VCPU(v, interrupt_mask_addr) =
		    (uint64_t)SHAREDINFO_ADDR + INT_ENABLE_OFFSET(v);
		VCPU(v, itv) = (1 << 16); /* timer vector masked */
	}
}

// stolen from share_xen_page_with_guest() in xen/arch/x86/mm.c
void
share_xen_page_with_guest(struct page_info *page,
                          struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

#if 1
    if (readonly) {
        printk("%s:%d readonly is not supported yet\n", __func__, __LINE__);
    }
#endif

    // alloc_xenheap_pages() doesn't initialize page owner.
    //BUG_ON(page_get_owner(page) != NULL);
#if 0
    if (get_gpfn_from_mfn(page_to_mfn(page)) != INVALID_M2P_ENTRY) {
        printk("%s:%d page 0x%p mfn 0x%lx gpfn 0x%lx\n", __func__, __LINE__,
               page, page_to_mfn(page), get_gpfn_from_mfn(page_to_mfn(page)));
    }
#endif
    // grant_table_destroy() release these pages.
    // but it doesn't clear m2p entry. So there might remain stale entry.
    // We clear such a stale entry here.
    set_gpfn_from_mfn(page_to_mfn(page), INVALID_M2P_ENTRY);

    spin_lock(&d->page_alloc_lock);

#ifndef __ia64__
    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;
#endif

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT(page->count_info == 0);
    page->count_info |= PGC_allocated | 1;

    if ( unlikely(d->xenheap_pages++ == 0) )
        get_knownalive_domain(d);
    list_add_tail(&page->list, &d->xenpage_list);

    spin_unlock(&d->page_alloc_lock);
}

//XXX !xxx_present() should be used instread of !xxx_none()?
static pte_t*
lookup_alloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (pgd_none(*pgd)) {
        pgd_populate(mm, pgd, pud_alloc_one(mm,mpaddr));
    }

    pud = pud_offset(pgd, mpaddr);
    if (pud_none(*pud)) {
        pud_populate(mm, pud, pmd_alloc_one(mm,mpaddr));
    }

    pmd = pmd_offset(pud, mpaddr);
    if (pmd_none(*pmd)) {
        pmd_populate_kernel(mm, pmd, pte_alloc_one_kernel(mm, mpaddr));
    }

    return pte_offset_map(pmd, mpaddr);
}

//XXX xxx_none() should be used instread of !xxx_present()?
static pte_t*
lookup_noalloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (!pgd_present(*pgd))
        goto not_present;

    pud = pud_offset(pgd, mpaddr);
    if (!pud_present(*pud))
        goto not_present;

    pmd = pmd_offset(pud, mpaddr);
    if (!pmd_present(*pmd))
        goto not_present;

    return pte_offset_map(pmd, mpaddr);

not_present:
    return NULL;
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
static pte_t*
lookup_noalloc_domain_pte_none(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (pgd_none(*pgd))
        goto not_present;

    pud = pud_offset(pgd, mpaddr);
    if (pud_none(*pud))
        goto not_present;

    pmd = pmd_offset(pud, mpaddr);
    if (pmd_none(*pmd))
        goto not_present;

    return pte_offset_map(pmd, mpaddr);

not_present:
    return NULL;
}
#endif

/* Allocate a new page for domain and map it to the specified metaphysical 
   address.  */
struct page_info *
__assign_new_domain_page(struct domain *d, unsigned long mpaddr, pte_t* pte)
{
    struct page_info *p = NULL;
    unsigned long maddr;
    int ret;

    BUG_ON(!pte_none(*pte));

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
    if (d == dom0) {
#if 0
        if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
            /* FIXME: is it true ?
               dom0 memory is not contiguous!  */
            panic("assign_new_domain_page: bad domain0 "
                  "mpaddr=%lx, start=%lx, end=%lx!\n",
                  mpaddr, dom0_start, dom0_start+dom0_size);
        }
#endif
        p = mfn_to_page((mpaddr >> PAGE_SHIFT));
        return p;
    }
#endif

    p = alloc_domheap_page(d);
    if (unlikely(!p)) {
        printf("assign_new_domain_page: Can't alloc!!!! Aaaargh!\n");
        return(p);
    }

    // zero out pages for security reasons
    clear_page(page_to_virt(p));
    maddr = page_to_maddr (p);
    if (unlikely(maddr > __get_cpu_var(vhpt_paddr)
                 && maddr < __get_cpu_var(vhpt_pend))) {
        /* FIXME: how can this happen ?
           vhpt is allocated by alloc_domheap_page.  */
        printf("assign_new_domain_page: reassigned vhpt page %lx!!\n",
               maddr);
    }

    ret = get_page(p, d);
    BUG_ON(ret == 0);
    set_pte(pte, pfn_pte(maddr >> PAGE_SHIFT,
                         __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));

    //XXX CONFIG_XEN_IA64_DOM0_VP
    //    TODO racy
    set_gpfn_from_mfn(page_to_mfn(p), mpaddr >> PAGE_SHIFT);
    return p;
}

struct page_info *
assign_new_domain_page(struct domain *d, unsigned long mpaddr)
{
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
    pte_t dummy_pte = __pte(0);
    return __assign_new_domain_page(d, mpaddr, &dummy_pte);
#else
    struct page_info *p = NULL;
    pte_t *pte;

    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        p = __assign_new_domain_page(d, mpaddr, pte);
    } else {
        DPRINTK("%s: d 0x%p mpaddr %lx already mapped!\n",
                __func__, d, mpaddr);
    }

    return p;
#endif
}

void
assign_new_domain0_page(struct domain *d, unsigned long mpaddr)
{
#ifndef CONFIG_DOMAIN0_CONTIGUOUS
    pte_t *pte;

    BUG_ON(d != dom0);
    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        struct page_info *p = __assign_new_domain_page(d, mpaddr, pte);
        if (p == NULL) {
            panic("%s: can't allocate page for dom0", __func__);
        }
    }
#endif
}

/* map a physical address to the specified metaphysical addr */
void
__assign_domain_page(struct domain *d,
                     unsigned long mpaddr, unsigned long physaddr)
{
    pte_t *pte;

    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        set_pte(pte,
                pfn_pte(physaddr >> PAGE_SHIFT,
                        __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));
    } else
        printk("%s: mpaddr %lx already mapped!\n", __func__, mpaddr);
}

/* get_page() and map a physical address to the specified metaphysical addr */
void
assign_domain_page(struct domain *d,
                   unsigned long mpaddr, unsigned long physaddr)
{
    struct page_info* page = mfn_to_page(physaddr >> PAGE_SHIFT);
    int ret;

    BUG_ON((physaddr & GPFN_IO_MASK) != GPFN_MEM);
    ret = get_page(page, d);
    BUG_ON(ret == 0);
    __assign_domain_page(d, mpaddr, physaddr);

    //XXX CONFIG_XEN_IA64_DOM0_VP
    //    TODO racy
    set_gpfn_from_mfn(physaddr >> PAGE_SHIFT, mpaddr >> PAGE_SHIFT);
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
static void
assign_domain_same_page(struct domain *d,
                          unsigned long mpaddr, unsigned long size)
{
    //XXX optimization
    unsigned long end = mpaddr + size;
    for (; mpaddr < end; mpaddr += PAGE_SIZE) {
        __assign_domain_page(d, mpaddr, mpaddr);
    }
}

unsigned long
assign_domain_mmio_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size)
{
    if (size == 0) {
        DPRINTK("%s: domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, d, mpaddr, size);
    }
    assign_domain_same_page(d, mpaddr, size);
    return mpaddr;
}

unsigned long
assign_domain_mach_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size)
{
    assign_domain_same_page(d, mpaddr, size);
    return mpaddr;
}

//XXX selege hammer.
//    flush finer range.
void
domain_page_flush(struct domain* d, unsigned long mpaddr,
                  unsigned long old_mfn, unsigned long new_mfn)
{
    domain_flush_vtlb_all();
}
#endif

//XXX heavily depends on the struct page_info layout.
//
// if (page_get_owner(page) == d &&
//     test_and_clear_bit(_PGC_allocated, &page->count_info)) {
//     put_page(page);
// }
static void
try_to_clear_PGC_allocate(struct domain* d, struct page_info* page)
{
    u32 _d, _nd;
    u64 x, nx, y;

    _d = pickle_domptr(d);
    y = *((u64*)&page->count_info);
    do {
        x = y;
        _nd = x >> 32;
        nx = x - 1;
        __clear_bit(_PGC_allocated, &nx);

        if (unlikely(!(x & PGC_allocated)) || unlikely(_nd != _d)) {
            struct domain* nd = unpickle_domptr(_nd);
            if (nd == NULL) {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info "\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, _nd,
                        x,
                        page->u.inuse.type_info);
            }
            break;
        }

        BUG_ON((nx & PGC_count_mask) < 1);
        y = cmpxchg((u64*)&page->count_info, x, nx);
    } while (unlikely(y != x));
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
static void
zap_domain_page_one(struct domain *d, unsigned long mpaddr, int do_put_page)
{
    struct mm_struct *mm = &d->arch.mm;
    pte_t *pte;
    pte_t old_pte;
    unsigned long mfn;
    struct page_info *page;

    pte = lookup_noalloc_domain_pte_none(d, mpaddr);
    if (pte == NULL)
        return;
    if (pte_none(*pte))
        return;

    // update pte
    old_pte = ptep_get_and_clear(mm, mpaddr, pte);
    mfn = pte_pfn(old_pte);
    page = mfn_to_page(mfn);
    BUG_ON((page->count_info & PGC_count_mask) == 0);

    if (page_get_owner(page) == d) {
        BUG_ON(get_gpfn_from_mfn(mfn) != (mpaddr >> PAGE_SHIFT));
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
    }

    domain_page_flush(d, mpaddr, mfn, INVALID_MFN);

    if (do_put_page) {
        try_to_clear_PGC_allocate(d, page);
        put_page(page);
    }
}
#endif

void build_physmap_table(struct domain *d)
{
	struct list_head *list_ent = d->page_list.next;
	unsigned long mfn, i = 0;

	ASSERT(!d->arch.physmap_built);
	while(list_ent != &d->page_list) {
	    mfn = page_to_mfn(list_entry(
		list_ent, struct page_info, list));
	    assign_domain_page(d, i << PAGE_SHIFT, mfn << PAGE_SHIFT);

	    i++;
	    list_ent = mfn_to_page(mfn)->list.next;
	}
	d->arch.physmap_built = 1;
}

void mpafoo(unsigned long mpaddr)
{
	extern unsigned long privop_trace;
	if (mpaddr == 0x3800)
		privop_trace = 1;
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
unsigned long
____lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
    pte_t *pte;

    pte = lookup_noalloc_domain_pte(d, mpaddr);
    if (pte == NULL)
        goto not_present;

    if (pte_present(*pte))
        return (pte->pte & _PFN_MASK);
    else if (VMX_DOMAIN(d->vcpu[0]))
        return GPFN_INV_MASK;

not_present:
    return INVALID_MFN;
}

unsigned long
__lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
    unsigned long machine = ____lookup_domain_mpa(d, mpaddr);
    if (machine != INVALID_MFN)
        return machine;

    printk("%s: d 0x%p id %d current 0x%p id %d\n",
           __func__, d, d->domain_id, current, current->vcpu_id);
    printk("%s: bad mpa 0x%lx (max_pages 0x%lx)\n",
           __func__, mpaddr, (unsigned long)d->max_pages << PAGE_SHIFT);
    return INVALID_MFN;
}
#endif

unsigned long lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
	pte_t *pte;

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0) {
		pte_t pteval;
		if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
			//printk("lookup_domain_mpa: bad dom0 mpaddr 0x%lx!\n",mpaddr);
			//printk("lookup_domain_mpa: start=0x%lx,end=0x%lx!\n",dom0_start,dom0_start+dom0_size);
			mpafoo(mpaddr);
		}
		pteval = pfn_pte(mpaddr >> PAGE_SHIFT,
			__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX));
		pte = &pteval;
		return *(unsigned long *)pte;
	}
#endif
	pte = lookup_noalloc_domain_pte(d, mpaddr);
	if (pte != NULL) {
		if (pte_present(*pte)) {
//printk("lookup_domain_page: found mapping for %lx, pte=%lx\n",mpaddr,pte_val(*pte));
			return *(unsigned long *)pte;
		} else if (VMX_DOMAIN(d->vcpu[0]))
			return GPFN_INV_MASK;
	}

	printk("%s: d 0x%p id %d current 0x%p id %d\n",
	       __func__, d, d->domain_id, current, current->vcpu_id);
	if ((mpaddr >> PAGE_SHIFT) < d->max_pages)
		printk("%s: non-allocated mpa 0x%lx (< 0x%lx)\n", __func__,
		       mpaddr, (unsigned long)d->max_pages << PAGE_SHIFT);
	else
		printk("%s: bad mpa 0x%lx (=> 0x%lx)\n", __func__,
		       mpaddr, (unsigned long)d->max_pages << PAGE_SHIFT);
	mpafoo(mpaddr);
	return 0;
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
//XXX SMP
unsigned long
dom0vp_zap_physmap(struct domain *d, unsigned long gpfn,
                   unsigned int extent_order)
{
    unsigned long ret = 0;
    if (extent_order != 0) {
        //XXX
        ret = -ENOSYS;
        goto out;
    }

    zap_domain_page_one(d, gpfn << PAGE_SHIFT, 1);

out:
    return ret;
}

// caller must get_page(mfn_to_page(mfn)) before
// caller must call set_gpfn_from_mfn().
static void
assign_domain_page_replace(struct domain *d, unsigned long mpaddr,
                           unsigned long mfn, unsigned int flags)
{
    struct mm_struct *mm = &d->arch.mm;
    pte_t* pte;
    pte_t old_pte;

    pte = lookup_alloc_domain_pte(d, mpaddr);

    // update pte
    old_pte = ptep_get_and_clear(mm, mpaddr, pte);
    set_pte(pte, pfn_pte(mfn,
                         __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));
    if (!pte_none(old_pte)) {
        unsigned long old_mfn;
        struct page_info* old_page;

        // XXX should previous underlying page be removed?
        //  or should error be returned because it is a due to a domain?
        old_mfn = pte_pfn(old_pte);//XXX
        old_page = mfn_to_page(old_mfn);

        if (page_get_owner(old_page) == d) {
            BUG_ON(get_gpfn_from_mfn(old_mfn) != (mpaddr >> PAGE_SHIFT));
            set_gpfn_from_mfn(old_mfn, INVALID_M2P_ENTRY);
        }

        domain_page_flush(d, mpaddr, old_mfn, mfn);

        try_to_clear_PGC_allocate(d, old_page);
        put_page(old_page);
    } else {
        BUG_ON(!mfn_valid(mfn));
        BUG_ON(page_get_owner(mfn_to_page(mfn)) == d &&
               get_gpfn_from_mfn(mfn) != INVALID_M2P_ENTRY);
    }
}

unsigned long
dom0vp_add_physmap(struct domain* d, unsigned long gpfn, unsigned long mfn,
                   unsigned int flags, domid_t domid)
{
    int error = 0;

    struct domain* rd;
    rd = find_domain_by_id(domid);
    if (unlikely(rd == NULL)) {
        error = -EINVAL;
        goto out0;
    }
    if (unlikely(rd == d)) {
        error = -EINVAL;
        goto out1;
    }
    if (unlikely(get_page(mfn_to_page(mfn), rd) == 0)) {
        error = -EINVAL;
        goto out1;
    }

    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, 0/* flags:XXX */);
    //don't update p2m table because this page belongs to rd, not d.
out1:
    put_domain(rd);
out0:
    return error;
}

// grant table host mapping
// mpaddr: host_addr: pseudo physical address
// mfn: frame: machine page frame
// flags: GNTMAP_readonly | GNTMAP_application_map | GNTMAP_contains_pte
int
create_grant_host_mapping(unsigned long gpaddr,
			  unsigned long mfn, unsigned int flags)
{
    struct domain* d = current->domain;
    struct page_info* page;
    int ret;

    if (flags & (GNTMAP_application_map | GNTMAP_contains_pte)) {
        DPRINTK("%s: flags 0x%x\n", __func__, flags);
        return GNTST_general_error;
    }
    if (flags & GNTMAP_readonly) {
#if 0
        DPRINTK("%s: GNTMAP_readonly is not implemented yet. flags %x\n",
                __func__, flags);
#endif
        flags &= ~GNTMAP_readonly;
    }

    page = mfn_to_page(mfn);
    ret = get_page(page, page_get_owner(page));
    BUG_ON(ret == 0);
    assign_domain_page_replace(d, gpaddr, mfn, flags);

    return GNTST_okay;
}

// grant table host unmapping
int
destroy_grant_host_mapping(unsigned long gpaddr,
			   unsigned long mfn, unsigned int flags)
{
    struct domain* d = current->domain;
    pte_t* pte;
    pte_t old_pte;
    unsigned long old_mfn = INVALID_MFN;
    struct page_info* old_page;

    if (flags & (GNTMAP_application_map | GNTMAP_contains_pte)) {
        DPRINTK("%s: flags 0x%x\n", __func__, flags);
        return GNTST_general_error;
    }
    if (flags & GNTMAP_readonly) {
#if 0
        DPRINTK("%s: GNTMAP_readonly is not implemented yet. flags %x\n",
                __func__, flags);
#endif
        flags &= ~GNTMAP_readonly;
    }

    pte = lookup_noalloc_domain_pte(d, gpaddr);
    if (pte == NULL || !pte_present(*pte) || pte_pfn(*pte) != mfn)
        return GNTST_general_error;//XXX GNTST_bad_pseudo_phys_addr

    // update pte
    old_pte = ptep_get_and_clear(&d->arch.mm, gpaddr, pte);
    if (pte_present(old_pte)) {
        old_mfn = pte_pfn(old_pte);//XXX
    }
    domain_page_flush(d, gpaddr, old_mfn, INVALID_MFN);

    old_page = mfn_to_page(old_mfn);
    BUG_ON(page_get_owner(old_page) == d);//try_to_clear_PGC_allocate(d, page) is not needed.
    put_page(old_page);

    return GNTST_okay;
}

//XXX needs refcount patch
//XXX heavily depends on the struct page layout.
//XXX SMP
int
steal_page_for_grant_transfer(struct domain *d, struct page_info *page)
{
#if 0 /* if big endian */
# error "implement big endian version of steal_page_for_grant_transfer()"
#endif
    u32 _d, _nd;
    u64 x, nx, y;
    unsigned long mpaddr = get_gpfn_from_mfn(page_to_mfn(page)) << PAGE_SHIFT;
    struct page_info *new;

    zap_domain_page_one(d, mpaddr, 0);
    put_page(page);

    spin_lock(&d->page_alloc_lock);

    /*
     * The tricky bit: atomically release ownership while there is just one
     * benign reference to the page (PGC_allocated). If that reference
     * disappears then the deallocation routine will safely spin.
     */
    _d  = pickle_domptr(d);
    y = *((u64*)&page->count_info);
    do {
        x = y;
        nx = x & 0xffffffff;
        // page->count_info: untouched
        // page->u.inused._domain = 0;
        _nd = x >> 32;

        if (unlikely((x & (PGC_count_mask | PGC_allocated)) !=
                     (1 | PGC_allocated)) ||
            unlikely(_nd != _d)) {
            struct domain* nd = unpickle_domptr(_nd);
            if (nd == NULL) {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info "\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, _nd,
                        x,
                        page->u.inuse.type_info);
            } else {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p(%u) 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info "\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, nd->domain_id, _nd,
                        x,
                        page->u.inuse.type_info);
            }
            spin_unlock(&d->page_alloc_lock);
            return -1;
        }

        y = cmpxchg((u64*)&page->count_info, x, nx);
    } while (unlikely(y != x));

    /*
     * Unlink from 'd'. At least one reference remains (now anonymous), so
     * noone else is spinning to try to delete this page from 'd'.
     */
    d->tot_pages--;
    list_del(&page->list);

    spin_unlock(&d->page_alloc_lock);

#if 1
    //XXX Until net_rx_action() fix
    // assign new page for this mpaddr
    new = assign_new_domain_page(d, mpaddr);
    BUG_ON(new == NULL);//XXX
#endif

    return 0;
}

void
guest_physmap_add_page(struct domain *d, unsigned long gpfn,
                       unsigned long mfn)
{
    int ret;

    ret = get_page(mfn_to_page(mfn), d);
    BUG_ON(ret == 0);
    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, 0/* XXX */);
    set_gpfn_from_mfn(mfn, gpfn);//XXX SMP

    //BUG_ON(mfn != ((lookup_domain_mpa(d, gpfn << PAGE_SHIFT) & _PFN_MASK) >> PAGE_SHIFT));
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gpfn,
                          unsigned long mfn)
{
    BUG_ON(mfn == 0);//XXX
    zap_domain_page_one(d, gpfn << PAGE_SHIFT, 1);
}
#endif

/* Flush cache of domain d.  */
void domain_cache_flush (struct domain *d, int sync_only)
{
	struct mm_struct *mm = &d->arch.mm;
	pgd_t *pgd = mm->pgd;
	unsigned long maddr;
	int i,j,k, l;
	int nbr_page = 0;
	void (*flush_func)(unsigned long start, unsigned long end);
	extern void flush_dcache_range (unsigned long, unsigned long);

	if (sync_only)
		flush_func = &flush_icache_range;
	else
		flush_func = &flush_dcache_range;

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0) {
		/* This is not fully correct (because of hole), but it should
		   be enough for now.  */
		(*flush_func)(__va_ul (dom0_start),
			      __va_ul (dom0_start + dom0_size));
		return;
	}
#endif
	for (i = 0; i < PTRS_PER_PGD; pgd++, i++) {
		pud_t *pud;
		if (!pgd_present(*pgd))
			continue;
		pud = pud_offset(pgd, 0);
		for (j = 0; j < PTRS_PER_PUD; pud++, j++) {
			pmd_t *pmd;
			if (!pud_present(*pud))
				continue;
			pmd = pmd_offset(pud, 0);
			for (k = 0; k < PTRS_PER_PMD; pmd++, k++) {
				pte_t *pte;
				if (!pmd_present(*pmd))
					continue;
				pte = pte_offset_map(pmd, 0);
				for (l = 0; l < PTRS_PER_PTE; pte++, l++) {
					if (!pte_present(*pte))
						continue;
					/* Convert PTE to maddr.  */
					maddr = __va_ul (pte_val(*pte)
							 & _PAGE_PPN_MASK);
					(*flush_func)(maddr, maddr+ PAGE_SIZE);
					nbr_page++;
				}
			}
		}
	}
	//printf ("domain_cache_flush: %d %d pages\n", d->domain_id, nbr_page);
}

// FIXME: ONLY USE FOR DOMAIN PAGE_SIZE == PAGE_SIZE
#if 1
unsigned long domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
	unsigned long pte = lookup_domain_mpa(d,mpaddr);
	unsigned long imva;

	pte &= _PAGE_PPN_MASK;
	imva = (unsigned long) __va(pte);
	imva |= mpaddr & ~PAGE_MASK;
	return(imva);
}
#else
unsigned long domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
    unsigned long imva = __gpa_to_mpa(d, mpaddr);

    return __va(imva);
}
#endif

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

static void copy_memory(void *dst, void *src, int size)
{
	int remain;

	if (IS_XEN_ADDRESS(dom0,(unsigned long) src)) {
		memcpy(dst,src,size);
	}
	else {
		printf("About to call __copy_from_user(%p,%p,%d)\n",
			dst,src,size);
		while ((remain = __copy_from_user(dst,src,size)) != 0) {
			printf("incomplete user copy, %d remain of %d\n",
				remain,size);
			dst += size - remain; src += size - remain;
			size -= remain;
		}
	}
}

static void loaddomainelfimage(struct domain *d, unsigned long image_start)
{
	char *elfbase = (char *) image_start;
	//Elf_Ehdr *ehdr = (Elf_Ehdr *)image_start;
	Elf_Ehdr ehdr;
	Elf_Phdr phdr;
	int h, filesz, memsz;
	unsigned long elfaddr, dom_mpaddr, dom_imva;
	struct page_info *p;
  
	copy_memory(&ehdr, (void *) image_start, sizeof(Elf_Ehdr));
	for ( h = 0; h < ehdr.e_phnum; h++ ) {
		copy_memory(&phdr,
			    elfbase + ehdr.e_phoff + (h*ehdr.e_phentsize),
			    sizeof(Elf_Phdr));
		if ((phdr.p_type != PT_LOAD))
		    continue;

		filesz = phdr.p_filesz;
		memsz = phdr.p_memsz;
		elfaddr = (unsigned long) elfbase + phdr.p_offset;
		dom_mpaddr = phdr.p_paddr;

//printf("p_offset: %x, size=%x\n",elfaddr,filesz);
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
		if (d == dom0) {
			if (dom_mpaddr+memsz>dom0_size)
				panic("Dom0 doesn't fit in memory space!\n");
			dom_imva = __va_ul(dom_mpaddr + dom0_start);
			copy_memory((void *)dom_imva, (void *)elfaddr, filesz);
			if (memsz > filesz)
				memset((void *)dom_imva+filesz, 0,
				       memsz-filesz);
//FIXME: This test for code seems to find a lot more than objdump -x does
			if (phdr.p_flags & PF_X) {
				privify_memory(dom_imva,filesz);
				flush_icache_range (dom_imva, dom_imva+filesz);
			}
		}
		else
#endif
		while (memsz > 0) {
			p = assign_new_domain_page(d,dom_mpaddr);
			BUG_ON (unlikely(p == NULL));
			dom_imva = __va_ul(page_to_maddr(p));
			if (filesz > 0) {
				if (filesz >= PAGE_SIZE)
					copy_memory((void *) dom_imva,
						    (void *) elfaddr,
						    PAGE_SIZE);
				else {
					// copy partial page
					copy_memory((void *) dom_imva,
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
	if (platform_is_hp_ski()) {
		dom0_size = 128*1024*1024; //FIXME: Should be configurable
	}
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	printf("alloc_dom0: starting (initializing %lu MB...)\n",dom0_size/(1024*1024));
 
	/* FIXME: The first trunk (say 256M) should always be assigned to
	 * Dom0, since Dom0's physical == machine address for DMA purpose.
	 * Some old version linux, like 2.4, assumes physical memory existing
	 * in 2nd 64M space.
	 */
	dom0_start = alloc_boot_pages(dom0_size >> PAGE_SHIFT, dom0_align >> PAGE_SHIFT);
	dom0_start <<= PAGE_SHIFT;
	if (!dom0_start) {
	  panic("alloc_dom0: can't allocate contiguous memory size=%lu\n",
		dom0_size);
	}
	printf("alloc_dom0: dom0_start=0x%lx\n", dom0_start);
#else
	// no need to allocate pages for now
	// pages are allocated by map_new_domain_page() via loaddomainelfimage()
	dom0_start = 0;
#endif

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
}

static unsigned int vmx_dom0 = 0;
int construct_dom0(struct domain *d, 
	               unsigned long image_start, unsigned long image_len, 
	               unsigned long initrd_start, unsigned long initrd_len,
	               char *cmdline)
{
	int i, rc;
	unsigned long alloc_start, alloc_end;
	start_info_t *si;
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

#ifdef VALIDATE_VT
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

	alloc_start = dom0_start;
	alloc_end = dom0_start + dom0_size;
	max_pages = dom0_size / PAGE_SIZE;
	d->max_pages = max_pages;
#ifndef CONFIG_XEN_IA64_DOM0_VP
	d->tot_pages = d->max_pages;
#else
	d->tot_pages = 0;
#endif
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

	    pinitrd_start= (dom0_start + dom0_size) -
	                   (PAGE_ALIGN(initrd_len) + 4*1024*1024);
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

#if defined(VALIDATE_VT) && !defined(CONFIG_XEN_IA64_DOM0_VP)
	/* Construct a frame-allocation list for the initial domain, since these
	 * pages are allocated by boot allocator and pfns are not set properly
	 */
	for ( mfn = (alloc_start>>PAGE_SHIFT); 
	      mfn < (alloc_end>>PAGE_SHIFT); 
	      mfn++ )
	{
            page = mfn_to_page(mfn);
            page_set_owner(page, d);
            page->u.inuse.type_info = 0;
            page->count_info        = PGC_allocated | 1;
            list_add_tail(&page->list, &d->page_list);

	    /* Construct 1:1 mapping */
	    set_gpfn_from_mfn(mfn, mfn);
	}
#endif

	/* Copy the OS image. */
	loaddomainelfimage(d,image_start);

	/* Copy the initial ramdisk. */
	//if ( initrd_len != 0 )
	//    memcpy((void *)vinitrd_start, initrd_start, initrd_len);


	/* Set up start info area. */
	d->shared_info->arch.start_info_pfn = pstart_info >> PAGE_SHIFT;
	start_info_page = assign_new_domain_page(d, pstart_info);
	if (start_info_page == NULL)
		panic("can't allocate start info page");
	si = page_to_virt(start_info_page);
	memset(si, 0, PAGE_SIZE);
	sprintf(si->magic, "xen-%i.%i-ia64", XEN_VERSION, XEN_SUBVERSION);
	si->nr_pages     = max_pages;

	/* Give up the VGA console if DOM0 is configured to grab it. */
	if (cmdline != NULL)
	    console_endboot(strstr(cmdline, "tty0") != NULL);

	/* VMX specific construction for Dom0, if hardware supports VMX
	 * and Dom0 is unmodified image
	 */
	printk("Dom0: 0x%lx, domain: 0x%lx\n", (u64)dom0, (u64)d);
	if (vmx_dom0)
	    vmx_final_setup_guest(v);

	set_bit(_VCPUF_initialised, &v->vcpu_flags);

	new_thread(v, pkern_entry, 0, 0);
	physdev_init_dom0(d);

	// dom0 doesn't need build_physmap_table()
	// see arch_set_info_guest()
	// instead we allocate pages manually.
	for (i = 0; i < max_pages; i++) {
		assign_new_domain0_page(d, i << PAGE_SHIFT);
	}
	d->arch.physmap_built = 1;

	// FIXME: Hack for keyboard input
	//serial_input_init();

	return 0;
}

void machine_restart(char * __unused)
{
	if (platform_is_hp_ski()) dummy();
	printf("machine_restart called: spinning....\n");
	while(1);
}

void machine_halt(void)
{
	if (platform_is_hp_ski()) dummy();
	printf("machine_halt called: spinning....\n");
	while(1);
}

void dummy_called(char *function)
{
	if (platform_is_hp_ski()) asm("break 0;;");
	printf("dummy called in %s: spinning....\n", function);
	while(1);
}

void domain_pend_keyboard_interrupt(int irq)
{
	vcpu_pend_interrupt(dom0->vcpu[0],irq);
}

void sync_vcpu_execstate(struct vcpu *v)
{
//	__ia64_save_fpu(v->arch._thread.fph);
//	if (VMX_DOMAIN(v))
//		vmx_save_state(v);
	// FIXME SMP: Anything else needed here for SMP?
}

// FIXME: It would be nice to print out a nice error message for bad
//  values of these boot-time parameters, but it seems we are too early
//  in the boot and attempts to print freeze the system?
#define abort(x...) do {} while(0)
#define warn(x...) do {} while(0)

static void parse_dom0_mem(char *s)
{
	unsigned long bytes = parse_size_and_unit(s);

	if (dom0_size < 4 * 1024 * 1024) {
		abort("parse_dom0_mem: too small, boot aborted"
			" (try e.g. dom0_mem=256M or dom0_mem=65536K)\n");
	}
	if (dom0_size % dom0_align) {
		dom0_size = ((dom0_size / dom0_align) + 1) * dom0_align;
		warn("parse_dom0_mem: dom0_size rounded up from"
			" %lx to %lx bytes, due to dom0_align=%lx\n",
			bytes,dom0_size,dom0_align);
	}
	else dom0_size = bytes;
}
custom_param("dom0_mem", parse_dom0_mem);


static void parse_dom0_align(char *s)
{
	unsigned long bytes = parse_size_and_unit(s);

	if ((bytes - 1) ^ bytes) { /* not a power of two */
		abort("parse_dom0_align: dom0_align must be power of two, "
			"boot aborted"
			" (try e.g. dom0_align=256M or dom0_align=65536K)\n");
	}
	else if (bytes < PAGE_SIZE) {
		abort("parse_dom0_align: dom0_align must be >= %ld, "
			"boot aborted"
			" (try e.g. dom0_align=256M or dom0_align=65536K)\n",
			PAGE_SIZE);
	}
	else dom0_align = bytes;
	if (dom0_size % dom0_align) {
		dom0_size = (dom0_size / dom0_align + 1) * dom0_align;
		warn("parse_dom0_align: dom0_size rounded up from"
			" %ld to %ld bytes, due to dom0_align=%lx\n",
			bytes,dom0_size,dom0_align);
	}
}
custom_param("dom0_align", parse_dom0_align);

