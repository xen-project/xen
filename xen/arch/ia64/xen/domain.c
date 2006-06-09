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

extern char dom0_command_line[];

#define IS_XEN_ADDRESS(d,a) ((a >= d->xen_vastart) && (a <= d->xen_vaend))

/* FIXME: where these declarations should be there ? */
extern void serial_input_init(void);
static void init_switch_stack(struct vcpu *v);
extern void vmx_do_launch(struct vcpu *);
void build_physmap_table(struct domain *d);

/* this belongs in include/asm, but there doesn't seem to be a suitable place */
unsigned long context_switch_count = 0;

extern struct vcpu *ia64_switch_to (struct vcpu *next_task);

#include <xen/sched-if.h>

void schedule_tail(struct vcpu *prev)
{
	extern char ia64_ivt;
	context_saved(prev);

	if (VMX_DOMAIN(current)) {
		vmx_do_launch(current);
	} else {
		ia64_set_iva(&ia64_ivt);
        	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
		        VHPT_ENABLED);
		load_region_regs(current);
		vcpu_load_kernel_regs(current);
	}
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    uint64_t spsr;
    uint64_t pta;

    local_irq_save(spsr);
    context_switch_count++;

    __ia64_save_fpu(prev->arch._thread.fph);
    __ia64_load_fpu(next->arch._thread.fph);
    if (VMX_DOMAIN(prev))
	    vmx_save_state(prev);
    if (VMX_DOMAIN(next))
	    vmx_load_state(next);
    /*ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);*/
    prev = ia64_switch_to(next);

    //cpu_set(smp_processor_id(), current->domain->domain_dirty_cpumask);

    if (!VMX_DOMAIN(current)){
	    vcpu_set_next_timer(current);
    }


// leave this debug for now: it acts as a heartbeat when more than
// one domain is active
{
static long cnt[16] = { 50,50,50,50,50,50,50,50,50,50,50,50,50,50,50,50};
static int i = 100;
int id = ((struct vcpu *)current)->domain->domain_id & 0xf;
if (!cnt[id]--) { cnt[id] = 500000; printk("%x",id); }
if (!i--) { i = 1000000; printk("+"); }
}

    if (VMX_DOMAIN(current)){
		vmx_load_all_rr(current);
    }else{
    	extern char ia64_ivt;
    	ia64_set_iva(&ia64_ivt);
    	if (!is_idle_domain(current->domain)) {
        	ia64_set_pta(VHPT_ADDR | (1 << 8) | (VHPT_SIZE_LOG2 << 2) |
			     VHPT_ENABLED);
	    	load_region_regs(current);
	    	vcpu_load_kernel_regs(current);
		if (vcpu_timer_expired(current))
			vcpu_pend_timer(current);
    	}else {
		/* When switching to idle domain, only need to disable vhpt
		 * walker. Then all accesses happen within idle context will
		 * be handled by TR mapping and identity mapping.
		 */
		pta = ia64_get_pta();
		ia64_set_pta(pta & ~VHPT_ENABLED);
        }
    }
    local_irq_restore(spsr);
    context_saved(prev);
}

void continue_running(struct vcpu *same)
{
	/* nothing to do */
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
	// ia64_ret_from_clone switches to user stack
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
	seqlock_init(&d->arch.vtlb_lock);

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

void arch_domain_destroy(struct domain *d)
{
	BUG_ON(d->arch.mm.pgd != NULL);
	if (d->shared_info != NULL)
		free_xenheap_page(d->shared_info);

	domain_flush_destroy (d);

	deallocate_rid_range(d);
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
	unsigned long cmdline_addr;

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
	cmdline_addr = 0;
	if (v == d->vcpu[0]) {
	    /* Only for first vcpu.  */
	    d->arch.sys_pgnr = c->sys_pgnr;
	    d->arch.initrd_start = c->initrd.start;
	    d->arch.initrd_len   = c->initrd.size;
	    d->arch.cmdline      = c->cmdline;
	    d->shared_info->arch = c->shared;

	    if (!VMX_DOMAIN(v)) {
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
		    cmdline_addr = dom_fw_setup (d, cmdline, len);
	    }

	    /* Cache synchronization seems to be done by the linux kernel
	       during mmap/unmap operation.  However be conservative.  */
	    domain_cache_flush (d, 1);
	}
	vcpu_init_regs (v);
	regs->r28 = cmdline_addr;

	if ( c->privregs && copy_from_user(v->arch.privregs,
			   c->privregs, sizeof(mapped_regs_t))) {
	    printk("Bad ctxt address in arch_set_info_guest: %p\n",
		   c->privregs);
	    return -EFAULT;
	}

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
        BUG_ON(get_gpfn_from_mfn(page_to_mfn(page)) != INVALID_M2P_ENTRY);
#endif
        put_page(page);
    }

    spin_unlock_recursive(&d->page_alloc_lock);
}

void domain_relinquish_resources(struct domain *d)
{
    /* Relinquish every page of memory. */

    // relase page traversing d->arch.mm.
    relinquish_mm(d);

    relinquish_memory(d, &d->xenpage_list);
    relinquish_memory(d, &d->page_list);
}

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
	if (running_on_sim) {
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
	unsigned long cmdline_addr;
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

	d->shared_info->arch.flags = SIF_INITDOMAIN|SIF_PRIVILEGED;

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

	cmdline_addr = dom_fw_setup(d, dom0_command_line, COMMAND_LINE_SIZE);

	vcpu_init_regs (v);

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	pkern_entry += dom0_start;
#endif
	vcpu_regs (v)->cr_iip = pkern_entry;
	vcpu_regs (v)->r28 = cmdline_addr;

	physdev_init_dom0(d);

	// FIXME: Hack for keyboard input
	//serial_input_init();

	return 0;
}

void machine_restart(char * __unused)
{
	if (running_on_sim) dummy();
	printf("machine_restart called: spinning....\n");
	while(1);
}

void machine_halt(void)
{
	if (running_on_sim) dummy();
	printf("machine_halt called: spinning....\n");
	while(1);
}

void dummy_called(char *function)
{
	if (running_on_sim) asm("break 0;;");
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

