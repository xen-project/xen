/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
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
//#include <asm/mpspec.h>
#include <xen/irq.h>
#include <xen/event.h>
//#include <xen/shadow.h>
#include <xen/console.h>

#include <xen/elf.h>
//#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/dma.h>	/* for MAX_DMA_ADDRESS */

#include <asm/asm-offsets.h>  /* for IA64_THREAD_INFO_SIZE */

#include <asm/vcpu.h>   /* for function declarations */

#define CONFIG_DOMAIN0_CONTIGUOUS
unsigned long dom0_start = -1L;
unsigned long dom0_size = 512*1024*1024; //FIXME: Should be configurable
//FIXME: alignment should be 256MB, lest Linux use a 256MB page size
unsigned long dom0_align = 64*1024*1024;
#ifdef DOMU_BUILD_STAGING
unsigned long domU_staging_size = 32*1024*1024; //FIXME: Should be configurable
unsigned long domU_staging_start;
unsigned long domU_staging_align = 64*1024;
unsigned long *domU_staging_area;
#endif

// initialized by arch/ia64/setup.c:find_initrd()
unsigned long initrd_start = 0, initrd_end = 0;

#define IS_XEN_ADDRESS(d,a) ((a >= d->xen_vastart) && (a <= d->xen_vaend))

//extern int loadelfimage(char *);
extern int readelfimage_base_and_size(char *, unsigned long,
	              unsigned long *, unsigned long *, unsigned long *);

unsigned long map_domain_page0(struct domain *);
extern unsigned long dom_fw_setup(struct domain *, char *, int);

/* this belongs in include/asm, but there doesn't seem to be a suitable place */
void free_perdomain_pt(struct domain *d)
{
	dummy();
	//free_page((unsigned long)d->mm.perdomain_pt);
}

int hlt_counter;

void disable_hlt(void)
{
	hlt_counter++;
}

void enable_hlt(void)
{
	hlt_counter--;
}

static void default_idle(void)
{
	if ( hlt_counter == 0 )
	{
	local_irq_disable();
	    if ( !softirq_pending(smp_processor_id()) )
	        safe_halt();
	    //else
		local_irq_enable();
	}
}

void continue_cpu_idle_loop(void)
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
	    do_softirq();
	}
}

void startup_cpu_idle_loop(void)
{
	/* Just some sanity to ensure that the scheduler is set up okay. */
	ASSERT(current->domain == IDLE_DOMAIN_ID);
	domain_unpause_by_systemcontroller(current->domain);
	raise_softirq(SCHEDULE_SOFTIRQ);
	do_softirq();

	/*
	 * Declares CPU setup done to the boot processor.
	 * Therefore memory barrier to ensure state is visible.
	 */
	smp_mb();
	init_idle();
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

struct exec_domain *arch_alloc_exec_domain_struct(void)
{
	/* Per-vp stack is used here. So we need keep exec_domain
	 * same page as per-vp stack */
	return alloc_xenheap_pages(KERNEL_STACK_SIZE_ORDER);
}

void arch_free_exec_domain_struct(struct exec_domain *ed)
{
	free_xenheap_pages(ed, KERNEL_STACK_SIZE_ORDER);
}

void arch_do_createdomain(struct exec_domain *ed)
{
	struct domain *d = ed->domain;

	d->shared_info = (void *)alloc_xenheap_page();
	ed->vcpu_info = (void *)alloc_xenheap_page();
	if (!ed->vcpu_info) {
   		printk("ERROR/HALTING: CAN'T ALLOC PAGE\n");
   		while (1);
	}
	memset(ed->vcpu_info, 0, PAGE_SIZE);
	/* pin mapping */
	// FIXME: Does this belong here?  Or do only at domain switch time?
#if 0
	// this is now done in ia64_new_rr7
	{
		/* WARNING: following must be inlined to avoid nested fault */
		unsigned long psr = ia64_clear_ic();
		ia64_itr(0x2, IA64_TR_SHARED_INFO, SHAREDINFO_ADDR,
		 pte_val(pfn_pte(ia64_tpa(d->shared_info) >> PAGE_SHIFT, PAGE_KERNEL)),
		 PAGE_SHIFT);
		ia64_set_psr(psr);
		ia64_srlz_i();
	}
#endif
	d->max_pages = (128*1024*1024)/PAGE_SIZE; // 128MB default // FIXME
	if ((d->metaphysical_rid = allocate_metaphysical_rid()) == -1UL)
		BUG();
	ed->vcpu_info->arch.metaphysical_mode = 1;
#define DOMAIN_RID_BITS_DEFAULT 18
	if (!allocate_rid_range(d,DOMAIN_RID_BITS_DEFAULT)) // FIXME
		BUG();
	// the following will eventually need to be negotiated dynamically
	d->xen_vastart = 0xf000000000000000;
	d->xen_vaend = 0xf300000000000000;
	d->shared_info_va = 0xf100000000000000;
	d->breakimm = 0x1000;
	// stay on kernel stack because may get interrupts!
	// ia64_ret_from_clone (which b0 gets in new_thread) switches
	// to user stack
	ed->thread.on_ustack = 0;
}

void arch_do_boot_vcpu(struct exec_domain *p)
{
	return;
}

int arch_set_info_guest(struct exec_domain *p, full_execution_context_t *c)
{
	dummy();
	return 1;
}

int arch_final_setup_guest(struct exec_domain *p, full_execution_context_t *c)
{
	dummy();
	return 1;
}

void domain_relinquish_resources(struct domain *d)
{
	dummy();
}

// heavily leveraged from linux/arch/ia64/kernel/process.c:copy_thread()
// and linux/arch/ia64/kernel/process.c:kernel_thread()
void new_thread(struct exec_domain *ed,
	            unsigned long start_pc,
	            unsigned long start_stack,
	            unsigned long start_info)
{
	struct domain *d = ed->domain;
	struct switch_stack *sw;
	struct pt_regs *regs;
	unsigned long new_rbs;
	struct ia64_boot_param *bp;
	extern char ia64_ret_from_clone;
	extern char saved_command_line[];

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
	if (d == dom0) start_pc += dom0_start;
#endif
	regs = (struct pt_regs *) ((unsigned long) ed + IA64_STK_OFFSET) - 1;
	sw = (struct switch_stack *) regs - 1;
	memset(sw,0,sizeof(struct switch_stack)+sizeof(struct pt_regs));
	new_rbs = (unsigned long) ed + IA64_RBS_OFFSET;
	regs->cr_ipsr = ia64_getreg(_IA64_REG_PSR)
		| IA64_PSR_BITS_TO_SET | IA64_PSR_BN
		& ~(IA64_PSR_BITS_TO_CLEAR | IA64_PSR_RI | IA64_PSR_IS);
	regs->cr_ipsr |= 2UL << IA64_PSR_CPL0_BIT; // domain runs at PL2
	regs->cr_iip = start_pc;
	regs->ar_rsc = 0;		/* lazy mode */
	regs->ar_rnat = 0;
	regs->ar_fpsr = sw->ar_fpsr = FPSR_DEFAULT;
	regs->loadrs = 0;
	//regs->r8 = current->mm->dumpable; /* set "don't zap registers" flag */
	//regs->r8 = 0x01234567890abcdef; // FIXME: temp marker
	//regs->r12 = ((unsigned long) regs - 16);	/* 16 byte scratch */
	regs->cr_ifs = 1UL << 63;
	regs->pr = 0;
	sw->pr = 0;
	regs->ar_pfs = 0;
	sw->caller_unat = 0;
	sw->ar_pfs = 0;
	sw->ar_bspstore = new_rbs;
	//regs->r13 = (unsigned long) ed;
printf("new_thread: ed=%p, start_pc=%p, regs=%p, sw=%p, new_rbs=%p, IA64_STK_OFFSET=%p, &r8=%p\n",
ed,start_pc,regs,sw,new_rbs,IA64_STK_OFFSET,&regs->r8);
	sw->b0 = (unsigned long) &ia64_ret_from_clone;
	ed->thread.ksp = (unsigned long) sw - 16;
	//ed->thread_info->flags = 0;
printk("new_thread, about to call init_all_rr\n");
	init_all_rr(ed);
	// set up boot parameters (and fake firmware)
printk("new_thread, about to call dom_fw_setup\n");
	regs->r28 = dom_fw_setup(d,saved_command_line,256L);  //FIXME
printk("new_thread, done with dom_fw_setup\n");
	// don't forget to set this!
	ed->vcpu_info->arch.banknum = 1;
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
	pmd_t *pmd;
	pte_t *pte;
extern unsigned long vhpt_paddr, vhpt_pend;

	if (!mm->pgd) {
		printk("map_new_domain_page: domain pgd must exist!\n");
		return(p);
	}
	pgd = pgd_offset(mm,mpaddr);
	if (pgd_none(*pgd))
		pgd_populate(mm, pgd, pmd_alloc_one(mm,mpaddr));

	pmd = pmd_offset(pgd, mpaddr);
	if (pmd_none(*pmd))
		pmd_populate_kernel(mm, pmd, pte_alloc_one_kernel(mm,mpaddr));
//		pmd_populate(mm, pmd, pte_alloc_one(mm,mpaddr));

	pte = pte_offset_map(pmd, mpaddr);
	if (pte_none(*pte)) {
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
		if (d == dom0) p = map_new_domain0_page(mpaddr);
		else
#endif
			p = alloc_domheap_page(d);
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
	else printk("map_new_domain_page: page %p already mapped!\n",p);
	return p;
}

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
		pmd = pmd_offset(pgd,mpaddr);
		if (pmd_present(*pmd)) {
			pte = pte_offset_map(pmd,mpaddr);
			if (pte_present(*pte)) {
//printk("lookup_domain_page: found mapping for %lx, pte=%lx\n",mpaddr,pte_val(*pte));
				return *(unsigned long *)pte;
			}
		}	
	}
	/* if lookup fails and mpaddr is "legal", "create" the page */
	if ((mpaddr >> PAGE_SHIFT) < d->max_pages) {
		// FIXME: should zero out pages for security reasons
		if (map_new_domain_page(d,mpaddr)) goto tryagain;
	}
	printk("lookup_domain_mpa: bad mpa %p (> %p\n",
		mpaddr,d->max_pages<<PAGE_SHIFT);
	mpafoo(mpaddr);
	return 0;
}

// FIXME: ONLY USE FOR DOMAIN PAGE_SIZE == PAGE_SIZE
unsigned long domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
	unsigned long pte = lookup_domain_mpa(d,mpaddr);
	unsigned long imva;

	pte &= _PAGE_PPN_MASK;
	imva = __va(pte);
	imva |= mpaddr & ~PAGE_MASK;
	return(imva);
}

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
     dom0_start = alloc_boot_pages(dom0_size,dom0_align);
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
	domU_staging_start= alloc_boot_pages(domU_staging_size,domU_staging_align);
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
	//l2_pgentry_t *l2tab, *l2start;
	//l1_pgentry_t *l1tab = NULL, *l1start = NULL;
	struct pfn_info *page = NULL;
	start_info_t *si;
	struct exec_domain *ed = d->exec_domain[0];

	struct domain_setup_info dsi;
	unsigned long p_start;
	unsigned long pkern_start;
	unsigned long pkern_entry;
	unsigned long pkern_end;

	extern void physdev_init_dom0(struct domain *);

//printf("construct_dom0: starting\n");
	/* Sanity! */
#ifndef CLONE_DOMAIN0
	if ( d != dom0 ) 
	    BUG();
	if ( test_bit(DF_CONSTRUCTED, &d->d_flags) ) 
	    BUG();
#endif

	memset(&dsi, 0, sizeof(struct domain_setup_info));

	printk("*** LOADING DOMAIN 0 ***\n");

	d->max_pages = dom0_size/PAGE_SIZE;
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

	// prepare domain0 pagetable (maps METAphysical to physical)
	// following is roughly mm_init() in linux/kernel/fork.c
	d->arch.mm = xmalloc(struct mm_struct);
	if (unlikely(!d->arch.mm)) {
	    	printk("Can't allocate mm_struct for domain0\n");
	    	return -ENOMEM;
	}
	memset(d->arch.mm, 0, sizeof(*d->arch.mm));
	d->arch.mm->pgd = pgd_alloc(d->arch.mm);
	if (unlikely(!d->arch.mm->pgd)) {
	    	printk("Can't allocate pgd for domain0\n");
	    	return -ENOMEM;
	}


	/* Mask all upcalls... */
	for ( i = 0; i < MAX_VIRT_CPUS; i++ )
	    d->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;

	/* Copy the OS image. */
	//(void)loadelfimage(image_start);
	loaddomainelfimage(d,image_start);

	/* Copy the initial ramdisk. */
	//if ( initrd_len != 0 )
	//    memcpy((void *)vinitrd_start, initrd_start, initrd_len);

#if 0
	/* Set up start info area. */
	//si = (start_info_t *)vstartinfo_start;
	memset(si, 0, PAGE_SIZE);
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
#ifdef IA64
	if (cmdline != NULL)
#endif
	console_endboot(strstr(cmdline, "tty0") != NULL);

	/* DOM0 gets access to everything. */
#ifdef CLONE_DOMAIN0
if (d == dom0)
#endif
	physdev_init_dom0(d);

	set_bit(DF_CONSTRUCTED, &d->d_flags);

	new_thread(ed, pkern_entry, 0, 0);
	// FIXME: Hack for keyboard input
#ifdef CLONE_DOMAIN0
if (d == dom0)
#endif
	serial_input_init();
	if (d == dom0) {
		ed->vcpu_info->arch.delivery_mask[0] = -1L;
		ed->vcpu_info->arch.delivery_mask[1] = -1L;
		ed->vcpu_info->arch.delivery_mask[2] = -1L;
		ed->vcpu_info->arch.delivery_mask[3] = -1L;
	}
	else __set_bit(0x30,ed->vcpu_info->arch.delivery_mask);

	return 0;
}

// FIXME: When dom0 can construct domains, this goes away (or is rewritten)
int construct_domU(struct domain *d,
		   unsigned long image_start, unsigned long image_len,
	           unsigned long initrd_start, unsigned long initrd_len,
	           char *cmdline)
{
	int i, rc;
	struct exec_domain *ed = d->exec_domain[0];
	unsigned long pkern_entry;

#ifndef DOMU_AUTO_RESTART
	if ( test_bit(DF_CONSTRUCTED, &d->d_flags) ) BUG();
#endif

	printk("*** LOADING DOMAIN %d ***\n",d->id);

	d->max_pages = dom0_size/PAGE_SIZE;	// FIXME: use dom0 size
	// FIXME: use domain0 command line
	rc = parsedomainelfimage(image_start, image_len, &pkern_entry);
	printk("parsedomainelfimage returns %d\n",rc);
	if ( rc != 0 ) return rc;

	d->arch.mm = xmalloc(struct mm_struct);
	if (unlikely(!d->arch.mm)) {
	    	printk("Can't allocate mm_struct for domain %d\n",d->id);
	    	return -ENOMEM;
	}
	memset(d->arch.mm, 0, sizeof(*d->arch.mm));
	d->arch.mm->pgd = pgd_alloc(d->arch.mm);
	if (unlikely(!d->arch.mm->pgd)) {
	    	printk("Can't allocate pgd for domain %d\n",d->id);
	    	return -ENOMEM;
	}


	/* Mask all upcalls... */
	for ( i = 0; i < MAX_VIRT_CPUS; i++ )
		d->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;

	/* Copy the OS image. */
	printk("calling loaddomainelfimage(%p,%p)\n",d,image_start);
	loaddomainelfimage(d,image_start);
	printk("loaddomainelfimage returns\n");

	set_bit(DF_CONSTRUCTED, &d->d_flags);

	printk("calling new_thread, entry=%p\n",pkern_entry);
#ifdef DOMU_AUTO_RESTART
	ed->domain->arch.image_start = image_start;
	ed->domain->arch.image_len = image_len;
	ed->domain->arch.entry = pkern_entry;
#endif
	new_thread(ed, pkern_entry, 0, 0);
	printk("new_thread returns\n");
	__set_bit(0x30,ed->vcpu_info->arch.delivery_mask);

	return 0;
}

#ifdef DOMU_AUTO_RESTART
void reconstruct_domU(struct exec_domain *ed)
{
	/* re-copy the OS image to reset data values to original */
	printk("reconstruct_domU: restarting domain %d...\n",
		ed->domain->id);
	loaddomainelfimage(ed->domain,ed->domain->arch.image_start);
	new_thread(ed, ed->domain->arch.entry, 0, 0);
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
			d->id,domU_staging_area,size);
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

void dummy(void)
{
	if (platform_is_hp_ski()) asm("break 0;;");
	printf("dummy called: spinning....\n");
	while(1);
}


#if 0
void switch_to(struct exec_domain *prev, struct exec_domain *next)
{
 	struct exec_domain *last;

	__switch_to(prev,next,last);
	//set_current(next);
}
#endif

void domain_pend_keyboard_interrupt(int irq)
{
	vcpu_pend_interrupt(dom0->exec_domain[0],irq);
}

/////////////////////////////////
// added 01Apr2005, to accomodate change in xen/sched.h, not clear
//  yet if this functionality is needed on ia64
#if 0
static void __synchronise_lazy_execstate(void *unused)
{
    if ( percpu_ctxt[smp_processor_id()].curr_ed != current )
    {
        __context_switch();
        load_LDT(current);
        clear_segments();
    }
}
#endif

void synchronise_lazy_execstate(unsigned long cpuset)
{
    //smp_subset_call_function(__synchronise_lazy_execstate, NULL, 1, cpuset);
}
/////////////////////////////////
