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
#include <asm/ptrace.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
//#include <asm/mpspec.h>
#include <xen/irq.h>
#include <xen/event.h>
//#include <xen/shadow.h>
#include <xen/console.h>
#include <xen/compile.h>

#include <xen/elf.h>
//#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/dma.h>	/* for MAX_DMA_ADDRESS */

#include <asm/asm-offsets.h>  /* for IA64_THREAD_INFO_SIZE */

#include <asm/vcpu.h>   /* for function declarations */
#include <public/arch-ia64.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_vpd.h>
#include <asm/pal.h>
#include <public/io/ioreq.h>

#define CONFIG_DOMAIN0_CONTIGUOUS
unsigned long dom0_start = -1L;
unsigned long dom0_size = 512*1024*1024;
unsigned long dom0_align = 64*1024*1024;
#ifdef DOMU_BUILD_STAGING
unsigned long domU_staging_size = 32*1024*1024; //FIXME: Should be configurable
unsigned long domU_staging_start;
unsigned long domU_staging_align = 64*1024;
unsigned long *domU_staging_area;
#endif

// initialized by arch/ia64/setup.c:find_initrd()
unsigned long initrd_start = 0, initrd_end = 0;
extern unsigned long running_on_sim;

#define IS_XEN_ADDRESS(d,a) ((a >= d->xen_vastart) && (a <= d->xen_vaend))

//extern int loadelfimage(char *);
extern int readelfimage_base_and_size(char *, unsigned long,
	              unsigned long *, unsigned long *, unsigned long *);

unsigned long map_domain_page0(struct domain *);
extern unsigned long dom_fw_setup(struct domain *, char *, int);

/* this belongs in include/asm, but there doesn't seem to be a suitable place */
void free_perdomain_pt(struct domain *d)
{
	printf("free_perdomain_pt: not implemented\n");
	//free_page((unsigned long)d->mm.perdomain_pt);
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
	printf ("idle%dD\n", cpu);
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
	int cpu = smp_processor_id ();
	/* Just some sanity to ensure that the scheduler is set up okay. */
	ASSERT(current->domain == IDLE_DOMAIN_ID);
	printf ("idle%dA\n", cpu);
	raise_softirq(SCHEDULE_SOFTIRQ);
#if 0   /* All this work is done within continue_cpu_idle_loop  */
	printf ("idle%dB\n", cpu);
	asm volatile ("mov ar.k2=r0");
	do_softirq();
	printf ("idle%dC\n", cpu);

	/*
	 * Declares CPU setup done to the boot processor.
	 * Therefore memory barrier to ensure state is visible.
	 */
	smp_mb();
#endif
#if 0
//do we have to ensure the idle task has a shared page so that, for example,
//region registers can be loaded from it.  Apparently not...
	idle0_task.shared_info = (void *)alloc_xenheap_page();
	memset(idle0_task.shared_info, 0, PAGE_SIZE);
	/* pin mapping */
	// FIXME: Does this belong here?  Or do only at domain switch time?
	{
		/* WARNING: following must be inlined to avoid nested fault */
		unsigned long psr = ia64_clear_ic();
		ia64_itr(0x2, IA64_TR_SHARED_INFO, SHAREDINFO_ADDR,
		 pte_val(pfn_pte(ia64_tpa(idle0_task.shared_info) >> PAGE_SHIFT, PAGE_KERNEL)),
		 PAGE_SHIFT);
		ia64_set_psr(psr);
		ia64_srlz_i();
	}
#endif

	continue_cpu_idle_loop();
}

struct vcpu *alloc_vcpu_struct(struct domain *d, unsigned int vcpu_id)
{
	struct vcpu *v;

	if ((v = alloc_xenheap_pages(KERNEL_STACK_SIZE_ORDER)) == NULL)
		return NULL;

	memset(v, 0, sizeof(*v)); 
        memcpy(&v->arch, &idle0_vcpu.arch, sizeof(v->arch));
	v->arch.privregs = 
		alloc_xenheap_pages(get_order(sizeof(mapped_regs_t)));
	printf("arch_vcpu_info=%p\n", v->arch.privregs);
	memset(v->arch.privregs, 0, PAGE_SIZE);

	return v;
}

void free_vcpu_struct(struct vcpu *v)
{
	free_xenheap_pages(v, KERNEL_STACK_SIZE_ORDER);
}

static void init_switch_stack(struct vcpu *v)
{
	struct pt_regs *regs = (struct pt_regs *) ((unsigned long) v + IA64_STK_OFFSET) - 1;
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

void arch_do_createdomain(struct vcpu *v)
{
	struct domain *d = v->domain;
	struct thread_info *ti = alloc_thread_info(v);

	/* Clear thread_info to clear some important fields, like preempt_count */
	memset(ti, 0, sizeof(struct thread_info));
	init_switch_stack(v);

	d->shared_info = (void *)alloc_xenheap_page();
	if (!d->shared_info) {
   		printk("ERROR/HALTING: CAN'T ALLOC PAGE\n");
   		while (1);
	}
	memset(d->shared_info, 0, PAGE_SIZE);
	if (v == d->vcpu[0])
	    memset(&d->shared_info->evtchn_mask[0], 0xff,
		sizeof(d->shared_info->evtchn_mask));
#if 0
	d->vcpu[0].arch.privregs = 
			alloc_xenheap_pages(get_order(sizeof(mapped_regs_t)));
	printf("arch_vcpu_info=%p\n", d->vcpu[0].arch.privregs);
	memset(d->vcpu.arch.privregs, 0, PAGE_SIZE);
#endif
	v->vcpu_info = &(d->shared_info->vcpu_data[0]);

	d->max_pages = (128UL*1024*1024)/PAGE_SIZE; // 128MB default // FIXME

	/* We may also need emulation rid for region4, though it's unlikely
	 * to see guest issue uncacheable access in metaphysical mode. But
	 * keep such info here may be more sane.
	 */
	if (((d->arch.metaphysical_rr0 = allocate_metaphysical_rr()) == -1UL)
	 || ((d->arch.metaphysical_rr4 = allocate_metaphysical_rr()) == -1UL))
		BUG();
//	VCPU(v, metaphysical_mode) = 1;
	v->arch.metaphysical_rr0 = d->arch.metaphysical_rr0;
	v->arch.metaphysical_rr4 = d->arch.metaphysical_rr4;
	v->arch.metaphysical_saved_rr0 = d->arch.metaphysical_rr0;
	v->arch.metaphysical_saved_rr4 = d->arch.metaphysical_rr4;
#define DOMAIN_RID_BITS_DEFAULT 18
	if (!allocate_rid_range(d,DOMAIN_RID_BITS_DEFAULT)) // FIXME
		BUG();
	v->arch.starting_rid = d->arch.starting_rid;
	v->arch.ending_rid = d->arch.ending_rid;
	// the following will eventually need to be negotiated dynamically
	d->xen_vastart = XEN_START_ADDR;
	d->xen_vaend = XEN_END_ADDR;
	d->shared_info_va = SHAREDINFO_ADDR;
	d->arch.breakimm = 0x1000;
	v->arch.breakimm = d->arch.breakimm;

	d->arch.sys_pgnr = 0;
	if (d->domain_id != IDLE_DOMAIN_ID) {
		d->arch.mm = xmalloc(struct mm_struct);
		if (unlikely(!d->arch.mm)) {
			printk("Can't allocate mm_struct for domain %d\n",d->domain_id);
			return -ENOMEM;
		}
		memset(d->arch.mm, 0, sizeof(*d->arch.mm));
		d->arch.mm->pgd = pgd_alloc(d->arch.mm);
		if (unlikely(!d->arch.mm->pgd)) {
			printk("Can't allocate pgd for domain %d\n",d->domain_id);
			return -ENOMEM;
		}
	} else
 		d->arch.mm = NULL;
 	printf ("arch_do_create_domain: domain=%p\n", d);
}

void arch_getdomaininfo_ctxt(struct vcpu *v, struct vcpu_guest_context *c)
{
	struct pt_regs *regs = (struct pt_regs *) ((unsigned long) v + IA64_STK_OFFSET) - 1;

	printf("arch_getdomaininfo_ctxt\n");
	c->regs = *regs;
	c->vcpu.evtchn_vector = v->vcpu_info->arch.evtchn_vector;

	c->shared = v->domain->shared_info->arch;
}

int arch_set_info_guest(struct vcpu *v, struct vcpu_guest_context *c)
{
	struct pt_regs *regs = (struct pt_regs *) ((unsigned long) v + IA64_STK_OFFSET) - 1;
	struct domain *d = v->domain;
	int i, rc, ret;
	unsigned long progress = 0;

	printf("arch_set_info_guest\n");
	if ( test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            return 0;

	/* Sync d/i cache conservatively */
	if (!running_on_sim) {
	    ret = ia64_pal_cache_flush(4, 0, &progress, NULL);
	    if (ret != PAL_STATUS_SUCCESS)
	        panic("PAL CACHE FLUSH failed for domain.\n");
	    printk("Sync i/d cache for dom0 image SUCC\n");
	}

	if (c->flags & VGCF_VMX_GUEST) {
	    if (!vmx_enabled) {
		printk("No VMX hardware feature for vmx domain.\n");
		return -EINVAL;
	    }

	    if (v == d->vcpu[0])
		vmx_setup_platform(d, c);

	    vmx_final_setup_guest(v);
	}

	*regs = c->regs;
	d->arch.sys_pgnr = c->sys_pgnr;
	new_thread(v, regs->cr_iip, 0, 0);

 	v->vcpu_info->arch.evtchn_vector = c->vcpu.evtchn_vector;
	if ( c->vcpu.privregs && copy_from_user(v->arch.privregs,
			   c->vcpu.privregs, sizeof(mapped_regs_t))) {
	    printk("Bad ctxt address in arch_set_info_guest: 0x%lx\n", c->vcpu.privregs);
	    return -EFAULT;
	}

	v->arch.domain_itm_last = -1L;
	d->shared_info->arch = c->shared;

	/* Don't redo final setup */
	set_bit(_VCPUF_initialised, &v->vcpu_flags);
	return 0;
}

void domain_relinquish_resources(struct domain *d)
{
	/* FIXME */
	printf("domain_relinquish_resources: not implemented\n");
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
	struct ia64_boot_param *bp;
	extern char saved_command_line[];


#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0) start_pc += dom0_start;
#endif

	regs = (struct pt_regs *) ((unsigned long) v + IA64_STK_OFFSET) - 1;
	if (VMX_DOMAIN(v)) {
		/* dt/rt/it:1;i/ic:1, si:1, vm/bn:1, ac:1 */
		regs->cr_ipsr = 0x501008826008; /* Need to be expanded as macro */
	} else {
		regs->cr_ipsr = ia64_getreg(_IA64_REG_PSR)
			| IA64_PSR_BITS_TO_SET | IA64_PSR_BN
			& ~(IA64_PSR_BITS_TO_CLEAR | IA64_PSR_RI | IA64_PSR_IS);
		regs->cr_ipsr |= 2UL << IA64_PSR_CPL0_BIT; // domain runs at PL2
	}
	regs->cr_iip = start_pc;
	regs->cr_ifs = 1UL << 63; /* or clear? */
	regs->ar_fpsr = FPSR_DEFAULT;

	if (VMX_DOMAIN(v)) {
		vmx_init_all_rr(v);
		if (d == dom0)
//		    VCPU(v,vgr[12]) = dom_fw_setup(d,saved_command_line,256L);
		    regs->r28 = dom_fw_setup(d,saved_command_line,256L);
		/* Virtual processor context setup */
		VCPU(v, vpsr) = IA64_PSR_BN;
		VCPU(v, dcr) = 0;
	} else {
		init_all_rr(v);
		if (d == dom0) 
		    regs->r28 = dom_fw_setup(d,saved_command_line,256L);
		else {
		    regs->ar_rsc |= (2 << 2); /* force PL2/3 */
		    regs->r28 = dom_fw_setup(d,"nomca nosmp xencons=tty0 console=tty0 root=/dev/hda1",256L);  //FIXME
		}
		VCPU(v, banknum) = 1;
		VCPU(v, metaphysical_mode) = 1;
		d->shared_info->arch.flags = (d == dom0) ? (SIF_INITDOMAIN|SIF_PRIVILEGED) : 0;
	}
}

static struct page * map_new_domain0_page(unsigned long mpaddr)
{
	if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
		printk("map_new_domain0_page: bad domain0 mpaddr %p!\n",mpaddr);
printk("map_new_domain0_page: start=%p,end=%p!\n",dom0_start,dom0_start+dom0_size);
		while(1);
	}
	return pfn_to_page((mpaddr >> PAGE_SHIFT));
}

/* allocate new page for domain and map it to the specified metaphysical addr */
struct page * map_new_domain_page(struct domain *d, unsigned long mpaddr)
{
	struct mm_struct *mm = d->arch.mm;
	struct page *p = (struct page *)0;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
extern unsigned long vhpt_paddr, vhpt_pend;

	if (!mm->pgd) {
		printk("map_new_domain_page: domain pgd must exist!\n");
		return(p);
	}
	pgd = pgd_offset(mm,mpaddr);
	if (pgd_none(*pgd))
		pgd_populate(mm, pgd, pud_alloc_one(mm,mpaddr));

	pud = pud_offset(pgd, mpaddr);
	if (pud_none(*pud))
		pud_populate(mm, pud, pmd_alloc_one(mm,mpaddr));

	pmd = pmd_offset(pud, mpaddr);
	if (pmd_none(*pmd))
		pmd_populate_kernel(mm, pmd, pte_alloc_one_kernel(mm,mpaddr));
//		pmd_populate(mm, pmd, pte_alloc_one(mm,mpaddr));

	pte = pte_offset_map(pmd, mpaddr);
	if (pte_none(*pte)) {
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
		if (d == dom0) p = map_new_domain0_page(mpaddr);
		else
#endif
		{
			p = alloc_domheap_page(d);
			// zero out pages for security reasons
			memset(__va(page_to_phys(p)),0,PAGE_SIZE);
		}
		if (unlikely(!p)) {
printf("map_new_domain_page: Can't alloc!!!! Aaaargh!\n");
			return(p);
		}
if (unlikely(page_to_phys(p) > vhpt_paddr && page_to_phys(p) < vhpt_pend)) {
  printf("map_new_domain_page: reassigned vhpt page %p!!\n",page_to_phys(p));
}
		set_pte(pte, pfn_pte(page_to_phys(p) >> PAGE_SHIFT,
			__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));
	}
	else printk("map_new_domain_page: mpaddr %lx already mapped!\n",mpaddr);
	return p;
}

/* map a physical address to the specified metaphysical addr */
void map_domain_page(struct domain *d, unsigned long mpaddr, unsigned long physaddr)
{
	struct mm_struct *mm = d->arch.mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (!mm->pgd) {
		printk("map_domain_page: domain pgd must exist!\n");
		return;
	}
	pgd = pgd_offset(mm,mpaddr);
	if (pgd_none(*pgd))
		pgd_populate(mm, pgd, pud_alloc_one(mm,mpaddr));

	pud = pud_offset(pgd, mpaddr);
	if (pud_none(*pud))
		pud_populate(mm, pud, pmd_alloc_one(mm,mpaddr));

	pmd = pmd_offset(pud, mpaddr);
	if (pmd_none(*pmd))
		pmd_populate_kernel(mm, pmd, pte_alloc_one_kernel(mm,mpaddr));
//		pmd_populate(mm, pmd, pte_alloc_one(mm,mpaddr));

	pte = pte_offset_map(pmd, mpaddr);
	if (pte_none(*pte)) {
		set_pte(pte, pfn_pte(physaddr >> PAGE_SHIFT,
			__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));
	}
	else printk("map_domain_page: mpaddr %lx already mapped!\n",mpaddr);
}
#if 0
/* map a physical address with specified I/O flag */
void map_domain_io_page(struct domain *d, unsigned long mpaddr, unsigned long flags)
{
	struct mm_struct *mm = d->arch.mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t io_pte;

	if (!mm->pgd) {
		printk("map_domain_page: domain pgd must exist!\n");
		return;
	}
	ASSERT(flags & GPFN_IO_MASK);

	pgd = pgd_offset(mm,mpaddr);
	if (pgd_none(*pgd))
		pgd_populate(mm, pgd, pud_alloc_one(mm,mpaddr));

	pud = pud_offset(pgd, mpaddr);
	if (pud_none(*pud))
		pud_populate(mm, pud, pmd_alloc_one(mm,mpaddr));

	pmd = pmd_offset(pud, mpaddr);
	if (pmd_none(*pmd))
		pmd_populate_kernel(mm, pmd, pte_alloc_one_kernel(mm,mpaddr));
//		pmd_populate(mm, pmd, pte_alloc_one(mm,mpaddr));

	pte = pte_offset_map(pmd, mpaddr);
	if (pte_none(*pte)) {
		pte_val(io_pte) = flags;
		set_pte(pte, io_pte);
	}
	else printk("map_domain_page: mpaddr %lx already mapped!\n",mpaddr);
}
#endif
void mpafoo(unsigned long mpaddr)
{
	extern unsigned long privop_trace;
	if (mpaddr == 0x3800)
		privop_trace = 1;
}

unsigned long lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
	struct mm_struct *mm = d->arch.mm;
	pgd_t *pgd = pgd_offset(mm, mpaddr);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0) {
		if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
			//printk("lookup_domain_mpa: bad dom0 mpaddr %p!\n",mpaddr);
//printk("lookup_domain_mpa: start=%p,end=%p!\n",dom0_start,dom0_start+dom0_size);
			mpafoo(mpaddr);
		}
		pte_t pteval = pfn_pte(mpaddr >> PAGE_SHIFT,
			__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX));
		pte = &pteval;
		return *(unsigned long *)pte;
	}
#endif
tryagain:
	if (pgd_present(*pgd)) {
		pud = pud_offset(pgd,mpaddr);
		if (pud_present(*pud)) {
			pmd = pmd_offset(pud,mpaddr);
			if (pmd_present(*pmd)) {
				pte = pte_offset_map(pmd,mpaddr);
				if (pte_present(*pte)) {
//printk("lookup_domain_page: found mapping for %lx, pte=%lx\n",mpaddr,pte_val(*pte));
					return *(unsigned long *)pte;
				} else if (VMX_DOMAIN(d->vcpu[0]))
					return GPFN_INV_MASK;
			}
		}
	}
	/* if lookup fails and mpaddr is "legal", "create" the page */
	if ((mpaddr >> PAGE_SHIFT) < d->max_pages) {
		if (map_new_domain_page(d,mpaddr)) goto tryagain;
	}
	printk("lookup_domain_mpa: bad mpa %p (> %p\n",
		mpaddr,d->max_pages<<PAGE_SHIFT);
	mpafoo(mpaddr);
	return 0;
}

// FIXME: ONLY USE FOR DOMAIN PAGE_SIZE == PAGE_SIZE
#if 1
unsigned long domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
	unsigned long pte = lookup_domain_mpa(d,mpaddr);
	unsigned long imva;

	pte &= _PAGE_PPN_MASK;
	imva = __va(pte);
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
	return (IS_ELF(*ehdr));
}

static void copy_memory(void *dst, void *src, int size)
{
	int remain;

	if (IS_XEN_ADDRESS(dom0,src)) {
		memcpy(dst,src,size);
	}
	else {
		printf("About to call __copy_from_user(%p,%p,%d)\n",
			dst,src,size);
		while (remain = __copy_from_user(dst,src,size)) {
			printf("incomplete user copy, %d remain of %d\n",
				remain,size);
			dst += size - remain; src += size - remain;
			size -= remain;
		}
	}
}

void loaddomainelfimage(struct domain *d, unsigned long image_start)
{
	char *elfbase = image_start;
	//Elf_Ehdr *ehdr = (Elf_Ehdr *)image_start;
	Elf_Ehdr ehdr;
	Elf_Phdr phdr;
	int h, filesz, memsz, paddr;
	unsigned long elfaddr, dom_mpaddr, dom_imva;
	struct page *p;
	unsigned long pteval;
  
	copy_memory(&ehdr,image_start,sizeof(Elf_Ehdr));
	for ( h = 0; h < ehdr.e_phnum; h++ ) {
		copy_memory(&phdr,elfbase + ehdr.e_phoff + (h*ehdr.e_phentsize),
		sizeof(Elf_Phdr));
	    //if ( !is_loadable_phdr(phdr) )
	    if ((phdr.p_type != PT_LOAD)) {
	        continue;
	}
	filesz = phdr.p_filesz; memsz = phdr.p_memsz;
	elfaddr = elfbase + phdr.p_offset;
	dom_mpaddr = phdr.p_paddr;
//printf("p_offset: %x, size=%x\n",elfaddr,filesz);
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0) {
		if (dom_mpaddr+memsz>dom0_size || dom_mpaddr+filesz>dom0_size) {
			printf("Domain0 doesn't fit in allocated space!\n");
			while(1);
		}
		dom_imva = __va(dom_mpaddr + dom0_start);
		copy_memory(dom_imva,elfaddr,filesz);
		if (memsz > filesz) memset(dom_imva+filesz,0,memsz-filesz);
//FIXME: This test for code seems to find a lot more than objdump -x does
		if (phdr.p_flags & PF_X) privify_memory(dom_imva,filesz);
	}
	else
#endif
	while (memsz > 0) {
#ifdef DOMU_AUTO_RESTART
		pteval = lookup_domain_mpa(d,dom_mpaddr);
		if (pteval) dom_imva = __va(pteval & _PFN_MASK);
		else { printf("loaddomainelfimage: BAD!\n"); while(1); }
#else
		p = map_new_domain_page(d,dom_mpaddr);
		if (unlikely(!p)) BUG();
		dom_imva = __va(page_to_phys(p));
#endif
		if (filesz > 0) {
			if (filesz >= PAGE_SIZE)
				copy_memory(dom_imva,elfaddr,PAGE_SIZE);
			else { // copy partial page, zero the rest of page
				copy_memory(dom_imva,elfaddr,filesz);
				memset(dom_imva+filesz,0,PAGE_SIZE-filesz);
			}
//FIXME: This test for code seems to find a lot more than objdump -x does
			if (phdr.p_flags & PF_X)
				privify_memory(dom_imva,PAGE_SIZE);
		}
		else if (memsz > 0) // always zero out entire page
			memset(dom_imva,0,PAGE_SIZE);
		memsz -= PAGE_SIZE; filesz -= PAGE_SIZE;
		elfaddr += PAGE_SIZE; dom_mpaddr += PAGE_SIZE;
	}
	}
}

int
parsedomainelfimage(char *elfbase, unsigned long elfsize, unsigned long *entry)
{
	Elf_Ehdr ehdr;

	copy_memory(&ehdr,elfbase,sizeof(Elf_Ehdr));

	if ( !elf_sanity_check(&ehdr) ) {
	    printk("ELF sanity check failed.\n");
	    return -EINVAL;
	}

	if ( (ehdr.e_phoff + (ehdr.e_phnum * ehdr.e_phentsize)) > elfsize )
	{
	    printk("ELF program headers extend beyond end of image.\n");
	    return -EINVAL;
	}

	if ( (ehdr.e_shoff + (ehdr.e_shnum * ehdr.e_shentsize)) > elfsize )
	{
	    printk("ELF section headers extend beyond end of image.\n");
	    return -EINVAL;
	}

#if 0
	/* Find the section-header strings table. */
	if ( ehdr.e_shstrndx == SHN_UNDEF )
	{
	    printk("ELF image has no section-header strings table (shstrtab).\n");
	    return -EINVAL;
	}
#endif

	*entry = ehdr.e_entry;
printf("parsedomainelfimage: entry point = %p\n",*entry);

	return 0;
}


void alloc_dom0(void)
{
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (platform_is_hp_ski()) {
	dom0_size = 128*1024*1024; //FIXME: Should be configurable
	}
	printf("alloc_dom0: starting (initializing %d MB...)\n",dom0_size/(1024*1024));
 
     /* FIXME: The first trunk (say 256M) should always be assigned to
      * Dom0, since Dom0's physical == machine address for DMA purpose.
      * Some old version linux, like 2.4, assumes physical memory existing
      * in 2nd 64M space.
      */
     dom0_start = alloc_boot_pages(
         dom0_size >> PAGE_SHIFT, dom0_align >> PAGE_SHIFT);
     dom0_start <<= PAGE_SHIFT;
	if (!dom0_start) {
	printf("construct_dom0: can't allocate contiguous memory size=%p\n",
		dom0_size);
	while(1);
	}
	printf("alloc_dom0: dom0_start=%p\n",dom0_start);
#else
	dom0_start = 0;
#endif

}

#ifdef DOMU_BUILD_STAGING
void alloc_domU_staging(void)
{
	domU_staging_size = 32*1024*1024; //FIXME: Should be configurable
	printf("alloc_domU_staging: starting (initializing %d MB...)\n",domU_staging_size/(1024*1024));
	domU_staging_start = alloc_boot_pages(
            domU_staging_size >> PAGE_SHIFT, domU_staging_align >> PAGE_SHIFT);
        domU_staging_start <<= PAGE_SHIFT;
	if (!domU_staging_size) {
		printf("alloc_domU_staging: can't allocate, spinning...\n");
		while(1);
	}
	else domU_staging_area = (unsigned long *)__va(domU_staging_start);
	printf("alloc_domU_staging: domU_staging_area=%p\n",domU_staging_area);

}

unsigned long
domU_staging_read_8(unsigned long at)
{
	// no way to return errors so just do it
	return domU_staging_area[at>>3];
	
}

unsigned long
domU_staging_write_32(unsigned long at, unsigned long a, unsigned long b,
	unsigned long c, unsigned long d)
{
	if (at + 32 > domU_staging_size) return -1;
	if (at & 0x1f) return -1;
	at >>= 3;
	domU_staging_area[at++] = a;
	domU_staging_area[at++] = b;
	domU_staging_area[at++] = c;
	domU_staging_area[at] = d;
	return 0;
	
}
#endif

/*
 * Domain 0 has direct access to all devices absolutely. However
 * the major point of this stub here, is to allow alloc_dom_mem
 * handled with order > 0 request. Dom0 requires that bit set to
 * allocate memory for other domains.
 */
void physdev_init_dom0(struct domain *d)
{
	set_bit(_DOMF_physdev_access, &d->domain_flags);
}

unsigned int vmx_dom0 = 0;
int construct_dom0(struct domain *d, 
	               unsigned long image_start, unsigned long image_len, 
	               unsigned long initrd_start, unsigned long initrd_len,
	               char *cmdline)
{
	char *dst;
	int i, rc;
	unsigned long pfn, mfn;
	unsigned long nr_pt_pages;
	unsigned long count;
	unsigned long alloc_start, alloc_end;
	struct pfn_info *page = NULL;
	start_info_t *si;
	struct vcpu *v = d->vcpu[0];

	struct domain_setup_info dsi;
	unsigned long p_start;
	unsigned long pkern_start;
	unsigned long pkern_entry;
	unsigned long pkern_end;
	unsigned long ret, progress = 0;

//printf("construct_dom0: starting\n");

#ifndef CLONE_DOMAIN0
	/* Sanity! */
	BUG_ON(d != dom0);
	BUG_ON(d->vcpu[0] == NULL);
	BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));
#endif

	memset(&dsi, 0, sizeof(struct domain_setup_info));

	printk("*** LOADING DOMAIN 0 ***\n");

	alloc_start = dom0_start;
	alloc_end = dom0_start + dom0_size;
	d->tot_pages = d->max_pages = dom0_size/PAGE_SIZE;
	image_start = __va(ia64_boot_param->initrd_start);
	image_len = ia64_boot_param->initrd_size;
//printk("image_start=%lx, image_len=%lx\n",image_start,image_len);
//printk("First word of image: %lx\n",*(unsigned long *)image_start);

//printf("construct_dom0: about to call parseelfimage\n");
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

	printk("METAPHYSICAL MEMORY ARRANGEMENT:\n"
	       " Kernel image:  %lx->%lx\n"
	       " Entry address: %lx\n"
	       " Init. ramdisk:   (NOT IMPLEMENTED YET)\n",
	       pkern_start, pkern_end, pkern_entry);

	if ( (pkern_end - pkern_start) > (d->max_pages * PAGE_SIZE) )
	{
	    printk("Initial guest OS requires too much space\n"
	           "(%luMB is greater than %luMB limit)\n",
	           (pkern_end-pkern_start)>>20, (d->max_pages<<PAGE_SHIFT)>>20);
	    return -ENOMEM;
	}

	// if high 3 bits of pkern start are non-zero, error

	// if pkern end is after end of metaphysical memory, error
	//  (we should be able to deal with this... later)


	//

#if 0
	strcpy(d->name,"Domain0");
#endif

	/* Mask all upcalls... */
	for ( i = 1; i < MAX_VIRT_CPUS; i++ )
	    d->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;

#ifdef VALIDATE_VT 
	/* Construct a frame-allocation list for the initial domain, since these
	 * pages are allocated by boot allocator and pfns are not set properly
	 */
	for ( mfn = (alloc_start>>PAGE_SHIFT); 
	      mfn < (alloc_end>>PAGE_SHIFT); 
	      mfn++ )
	{
            page = &frame_table[mfn];
            page_set_owner(page, d);
            page->u.inuse.type_info = 0;
            page->count_info        = PGC_allocated | 1;
            list_add_tail(&page->list, &d->page_list);

	    /* Construct 1:1 mapping */
	    machine_to_phys_mapping[mfn] = mfn;
	}

#endif

	/* Copy the OS image. */
	loaddomainelfimage(d,image_start);

	/* Copy the initial ramdisk. */
	//if ( initrd_len != 0 )
	//    memcpy((void *)vinitrd_start, initrd_start, initrd_len);

	/* Sync d/i cache conservatively */
	if (!running_on_sim) {
	    ret = ia64_pal_cache_flush(4, 0, &progress, NULL);
	    if (ret != PAL_STATUS_SUCCESS)
	        panic("PAL CACHE FLUSH failed for dom0.\n");
	    printk("Sync i/d cache for dom0 image SUCC\n");
	}

	/* Set up start info area. */
	si = (start_info_t *)alloc_xenheap_page();
	memset(si, 0, PAGE_SIZE);
	d->shared_info->arch.start_info_pfn = __pa(si) >> PAGE_SHIFT;
	sprintf(si->magic, "Xen-%i.%i", XEN_VERSION, XEN_SUBVERSION);

#if 0
	si->nr_pages     = d->tot_pages;
	si->shared_info  = virt_to_phys(d->shared_info);
	si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
	//si->pt_base      = vpt_start;
	//si->nr_pt_frames = nr_pt_pages;
	//si->mfn_list     = vphysmap_start;

	if ( initrd_len != 0 )
	{
	    //si->mod_start = vinitrd_start;
	    si->mod_len   = initrd_len;
	    printk("Initrd len 0x%lx, start at 0x%08lx\n",
	           si->mod_len, si->mod_start);
	}

	dst = si->cmd_line;
	if ( cmdline != NULL )
	{
	    for ( i = 0; i < 255; i++ )
	    {
	        if ( cmdline[i] == '\0' )
	            break;
	        *dst++ = cmdline[i];
	    }
	}
	*dst = '\0';

	zap_low_mappings(); /* Do the same for the idle page tables. */
#endif
	
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

	// FIXME: Hack for keyboard input
#ifdef CLONE_DOMAIN0
if (d == dom0)
#endif
	serial_input_init();
	if (d == dom0) {
		VCPU(v, delivery_mask[0]) = -1L;
		VCPU(v, delivery_mask[1]) = -1L;
		VCPU(v, delivery_mask[2]) = -1L;
		VCPU(v, delivery_mask[3]) = -1L;
	}
	else __set_bit(0x30, VCPU(v, delivery_mask));

	return 0;
}

// FIXME: When dom0 can construct domains, this goes away (or is rewritten)
int construct_domU(struct domain *d,
		   unsigned long image_start, unsigned long image_len,
	           unsigned long initrd_start, unsigned long initrd_len,
	           char *cmdline)
{
	int i, rc;
	struct vcpu *v = d->vcpu[0];
	unsigned long pkern_entry;

#ifndef DOMU_AUTO_RESTART
	BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));
#endif

	printk("*** LOADING DOMAIN %d ***\n",d->domain_id);

	d->max_pages = dom0_size/PAGE_SIZE;	// FIXME: use dom0 size
	// FIXME: use domain0 command line
	rc = parsedomainelfimage(image_start, image_len, &pkern_entry);
	printk("parsedomainelfimage returns %d\n",rc);
	if ( rc != 0 ) return rc;

	/* Mask all upcalls... */
	for ( i = 0; i < MAX_VIRT_CPUS; i++ )
		d->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;

	/* Copy the OS image. */
	printk("calling loaddomainelfimage(%p,%p)\n",d,image_start);
	loaddomainelfimage(d,image_start);
	printk("loaddomainelfimage returns\n");

	set_bit(_VCPUF_initialised, &v->vcpu_flags);

	printk("calling new_thread, entry=%p\n",pkern_entry);
#ifdef DOMU_AUTO_RESTART
	v->domain->arch.image_start = image_start;
	v->domain->arch.image_len = image_len;
	v->domain->arch.entry = pkern_entry;
#endif
	new_thread(v, pkern_entry, 0, 0);
	printk("new_thread returns\n");
	__set_bit(0x30, VCPU(v, delivery_mask));

	return 0;
}

#ifdef DOMU_AUTO_RESTART
void reconstruct_domU(struct vcpu *v)
{
	/* re-copy the OS image to reset data values to original */
	printk("reconstruct_domU: restarting domain %d...\n",
		v->domain->domain_id);
	loaddomainelfimage(v->domain,v->domain->arch.image_start);
	new_thread(v, v->domain->arch.entry, 0, 0);
}
#endif

// FIXME: When dom0 can construct domains, this goes away (or is rewritten)
int launch_domainU(unsigned long size)
{
#ifdef CLONE_DOMAIN0
	static int next = CLONE_DOMAIN0+1;
#else
	static int next = 1;
#endif	

	struct domain *d = do_createdomain(next,0);
	if (!d) {
		printf("launch_domainU: couldn't create\n");
		return 1;
	}
	else next++;
	if (construct_domU(d, (unsigned long)domU_staging_area, size,0,0,0)) {
		printf("launch_domainU: couldn't construct(id=%d,%lx,%lx)\n",
			d->domain_id,domU_staging_area,size);
		return 2;
	}
	domain_unpause_by_systemcontroller(d);
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


#if 0
void switch_to(struct vcpu *prev, struct vcpu *next)
{
 	struct vcpu *last;

	__switch_to(prev,next,last);
	//set_current(next);
}
#endif

void domain_pend_keyboard_interrupt(int irq)
{
	vcpu_pend_interrupt(dom0->vcpu[0],irq);
}

void vcpu_migrate_cpu(struct vcpu *v, int newcpu)
{
	if ( v->processor == newcpu )
		return;

	set_bit(_VCPUF_cpu_migrated, &v->vcpu_flags);
	v->processor = newcpu;
}

void sync_vcpu_execstate(struct vcpu *v)
{
	ia64_save_fpu(v->arch._thread.fph);
	if (VMX_DOMAIN(v))
		vmx_save_state(v);
	else {
		if (IA64_HAS_EXTRA_STATE(v))
			ia64_save_extra(v);
	}
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

