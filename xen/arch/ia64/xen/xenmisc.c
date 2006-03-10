/*
 * Xen misc
 * 
 * Functions/decls that are/may be needed to link with Xen because
 * of x86 dependencies
 *
 * Copyright (C) 2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <linux/config.h>
#include <xen/sched.h>
#include <linux/efi.h>
#include <asm/processor.h>
#include <xen/serial.h>
#include <asm/io.h>
#include <xen/softirq.h>
#include <public/sched.h>
#include <asm/vhpt.h>
#include <asm/debugger.h>
#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>

efi_memory_desc_t ia64_efi_io_md;
EXPORT_SYMBOL(ia64_efi_io_md);
unsigned long wait_init_idle;
int phys_proc_id[NR_CPUS];
unsigned long loops_per_jiffy = (1<<12);	// from linux/init/main.c

/* FIXME: where these declarations should be there ? */
extern void load_region_regs(struct vcpu *);
extern void show_registers(struct pt_regs *regs);

void ia64_mca_init(void) { printf("ia64_mca_init() skipped (Machine check abort handling)\n"); }
void ia64_mca_cpu_init(void *x) { }
void ia64_patch_mckinley_e9(unsigned long a, unsigned long b) { }
void ia64_patch_vtop(unsigned long a, unsigned long b) { }
void hpsim_setup(char **x)
{
#ifdef CONFIG_SMP
	init_smp_config();
#endif
}

// called from mem_init... don't think s/w I/O tlb is needed in Xen
//void swiotlb_init(void) { }  ...looks like it IS needed

long
is_platform_hp_ski(void)
{
	int i;
	long cpuid[6];

	for (i = 0; i < 5; ++i)
		cpuid[i] = ia64_get_cpuid(i);
	if ((cpuid[0] & 0xff) != 'H') return 0;
	if ((cpuid[3] & 0xff) != 0x4) return 0;
	if (((cpuid[3] >> 8) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 16) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 24) & 0x7) != 0x7) return 0;
	return 1;
}

long
platform_is_hp_ski(void)
{
	extern long running_on_sim;
	return running_on_sim;
}

/* calls in xen/common code that are unused on ia64 */

void sync_lazy_execstate_cpu(unsigned int cpu) {}

#if 0
int grant_table_create(struct domain *d) { return 0; }
void grant_table_destroy(struct domain *d) { return; }
#endif

struct pt_regs *guest_cpu_user_regs(void) { return vcpu_regs(current); }

void raise_actimer_softirq(void)
{
	raise_softirq(TIMER_SOFTIRQ);
}

unsigned long
gmfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
{
	if (d == dom0)
		return(gpfn);
	else {
		unsigned long pte = lookup_domain_mpa(d,gpfn << PAGE_SHIFT);
		if (!pte) {
printk("gmfn_to_mfn_foreign: bad gpfn. spinning...\n");
while(1);
			return 0;
		}
		return ((pte & _PFN_MASK) >> PAGE_SHIFT);
	}
}
#if 0
u32
mfn_to_gmfn(struct domain *d, unsigned long frame)
{
	// FIXME: is this right?
if ((frame << PAGE_SHIFT) & _PAGE_PPN_MASK) {
printk("mfn_to_gmfn: bad frame. spinning...\n");
while(1);
}
	return frame;
}
#endif

///////////////////////////////
// from arch/ia64/page_alloc.c
///////////////////////////////
DEFINE_PER_CPU(struct page_state, page_states) = {0};
unsigned long totalram_pages;

void __mod_page_state(unsigned long offset, unsigned long delta)
{
	unsigned long flags;
	void* ptr;

	local_irq_save(flags);
	ptr = &__get_cpu_var(page_states);
	*(unsigned long*)(ptr + offset) += delta;
	local_irq_restore(flags);
}

///////////////////////////////
// from arch/x86/flushtlb.c
///////////////////////////////

u32 tlbflush_clock;
u32 tlbflush_time[NR_CPUS];

///////////////////////////////
// from arch/x86/memory.c
///////////////////////////////

void init_percpu_info(void)
{
	dummy();
    //memset(percpu_info, 0, sizeof(percpu_info));
}

void free_page_type(struct page_info *page, u32 type)
{
//	dummy();
	return;
}

int alloc_page_type(struct page_info *page, u32 type)
{
//	dummy();
	return 1;
}

///////////////////////////////
//// misc memory stuff
///////////////////////////////

unsigned long __get_free_pages(unsigned int mask, unsigned int order)
{
	void *p = alloc_xenheap_pages(order);

	memset(p,0,PAGE_SIZE<<order);
	return (unsigned long)p;
}

void __free_pages(struct page *page, unsigned int order)
{
	if (order) BUG();
	free_xenheap_page(page);
}

void *pgtable_quicklist_alloc(void)
{
    void *p;
    p = alloc_xenheap_pages(0);
    if (p) 
        clear_page(p);
    return p;
}

void pgtable_quicklist_free(void *pgtable_entry)
{
	free_xenheap_page(pgtable_entry);
}

///////////////////////////////
// from arch/ia64/traps.c
///////////////////////////////

int is_kernel_text(unsigned long addr)
{
	extern char _stext[], _etext[];
	if (addr >= (unsigned long) _stext &&
	    addr <= (unsigned long) _etext)
	    return 1;

	return 0;
}

unsigned long kernel_text_end(void)
{
	extern char _etext[];
	return (unsigned long) _etext;
}

///////////////////////////////
// from common/keyhandler.c
///////////////////////////////
void dump_pageframe_info(struct domain *d)
{
	printk("dump_pageframe_info not implemented\n");
}

int nmi_count(int x) { return x; }

///////////////////////////////
// called from arch/ia64/head.S
///////////////////////////////

void console_print(char *msg)
{
	printk("console_print called, how did start_kernel return???\n");
}

void kernel_thread_helper(void)
{
	printk("kernel_thread_helper not implemented\n");
	dummy();
}

void sys_exit(void)
{
	printk("sys_exit not implemented\n");
	dummy();
}

////////////////////////////////////
// called from unaligned.c
////////////////////////////////////

void die_if_kernel(char *str, struct pt_regs *regs, long err) /* __attribute__ ((noreturn)) */
{
	if (user_mode(regs))
		return;

	printk("%s: %s %ld\n", __func__, str, err);
	debugtrace_dump();
	show_registers(regs);
	domain_crash_synchronous();
}

long
ia64_peek (struct task_struct *child, struct switch_stack *child_stack,
	   unsigned long user_rbs_end, unsigned long addr, long *val)
{
	printk("ia64_peek: called, not implemented\n");
	return 1;
}

long
ia64_poke (struct task_struct *child, struct switch_stack *child_stack,
	   unsigned long user_rbs_end, unsigned long addr, long val)
{
	printk("ia64_poke: called, not implemented\n");
	return 1;
}

void
ia64_sync_fph (struct task_struct *task)
{
	printk("ia64_sync_fph: called, not implemented\n");
}

void
ia64_flush_fph (struct task_struct *task)
{
	printk("ia64_flush_fph: called, not implemented\n");
}

////////////////////////////////////
// called from irq_ia64.c:init_IRQ()
//   (because CONFIG_IA64_HP_SIM is specified)
////////////////////////////////////
void hpsim_irq_init(void) { }


// accomodate linux extable.c
//const struct exception_table_entry *
void *search_module_extables(unsigned long addr) { return NULL; }
void *__module_text_address(unsigned long addr) { return NULL; }
void *module_text_address(unsigned long addr) { return NULL; }

void cs10foo(void) {}
void cs01foo(void) {}

unsigned long context_switch_count = 0;

#include <asm/vcpu.h>

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    uint64_t spsr;
    uint64_t pta;

    local_irq_save(spsr);
//    if(VMX_DOMAIN(prev)){
//    	vtm_domain_out(prev);
//    }
	context_switch_count++;
	switch_to(prev,next,prev);
//    if(VMX_DOMAIN(current)){
//        vtm_domain_in(current);
//    }

// leave this debug for now: it acts as a heartbeat when more than
// one domain is active
{
static long cnt[16] = { 50,50,50,50,50,50,50,50,50,50,50,50,50,50,50,50};
static int i = 100;
int id = ((struct vcpu *)current)->domain->domain_id & 0xf;
if (!cnt[id]--) { printk("%x",id); cnt[id] = 500000; }
if (!i--) { printk("+"); i = 1000000; }
}

    if (VMX_DOMAIN(current)){
//        vtm_domain_in(current);
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

void arch_dump_domain_info(struct domain *d)
{
}

void panic_domain(struct pt_regs *regs, const char *fmt, ...)
{
	va_list args;
	char buf[128];
	struct vcpu *v = current;
//	static volatile int test = 1;	// so can continue easily in debug
//	extern spinlock_t console_lock;
//	unsigned long flags;
    
loop:
	printf("$$$$$ PANIC in domain %d (k6=0x%lx): ",
		v->domain->domain_id, 
		__get_cpu_var(cpu_kr)._kr[IA64_KR_CURRENT]);
	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printf(buf);
	if (regs) show_registers(regs);
	if (regs) {
		debugger_trap_fatal(0 /* don't care */, regs);
	} else {
		debugger_trap_immediate();
	}
	domain_pause_by_systemcontroller(current->domain);
	v->domain->shutdown_code = SHUTDOWN_crash;
	set_bit(_DOMF_shutdown, &v->domain->domain_flags);
	if (v->domain->domain_id == 0) {
		int i = 1000000000L;
		// if domain0 crashes, just periodically print out panic
		// message to make post-mortem easier
		while(i--);
		goto loop;
	}
}

/* FIXME: for the forseeable future, all cpu's that enable VTi have split
 *  caches and all cpu's that have split caches enable VTi.  This may
 *  eventually be untrue though. */
#define cpu_has_split_cache	vmx_enabled
extern unsigned int vmx_enabled;

void sync_split_caches(void)
{
	unsigned long ret, progress = 0;

	if (cpu_has_split_cache) {
		/* Sync d/i cache conservatively */
		ret = ia64_pal_cache_flush(4, 0, &progress, NULL);
		if ((ret!=PAL_STATUS_SUCCESS)&& (ret!=PAL_STATUS_UNIMPLEMENTED))
			printk("PAL CACHE FLUSH failed\n");
		else printk("Sync i/d cache for guest SUCC\n");
	}
	else printk("sync_split_caches ignored for CPU with no split cache\n");
}

///////////////////////////////
// from arch/x86/mm.c
///////////////////////////////

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                           \
  printk("DOM%u: (file=mm.c, line=%d) " _f "\n", \
         current->domain->domain_id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

void cleanup_writable_pagetable(struct domain *d)
{
  return;
}

void put_page_type(struct page_info *page)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        /*
         * The page should always be validated while a reference is held. The 
         * exception is during domain destruction, when we forcibly invalidate 
         * page-table pages if we detect a referential loop.
         * See domain.c:relinquish_list().
         */
        ASSERT((x & PGT_validated) || 
               test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags));

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            /* Record TLB information for flush later. Races are harmless. */
            page->tlbflush_timestamp = tlbflush_current_time();
            
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & PGT_validated) )
            {
                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and validated
                 * bit is clear => other ops will spin or fail.
                 */
                if ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, 
                                           x & ~PGT_validated)) != x) )
                    goto again;
                /* We cleared the 'valid bit' so we do the clean up. */
                free_page_type(page, x);
                /* Carry on, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
            }
        }
        else if ( unlikely(((nx & (PGT_pinned | PGT_count_mask)) == 
                            (PGT_pinned | 1)) &&
                           ((nx & PGT_type_mask) != PGT_writable_page)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct page_info *page, u32 type)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %lx", page_to_mfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                if ( (x & PGT_type_mask) != (type & PGT_type_mask) )
                {
                    /*
                     * On type change we check to flush stale TLB
                     * entries. This may be unnecessary (e.g., page
                     * was GDT/LDT) but those circumstances should be
                     * very rare.
                     */
                    cpumask_t mask =
                        page_get_owner(page)->domain_dirty_cpumask;
                    tlbflush_filter(mask, page->tlbflush_timestamp);

                    if ( unlikely(!cpus_empty(mask)) )
                    {
                        perfc_incrc(need_flush_tlb_flush);
                        flush_tlb_mask(mask);
                    }
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_va_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else
        {
            if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
            {
                if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
                {
                    if ( current->domain == page_get_owner(page) )
                    {
                        /*
                         * This ensures functions like set_gdt() see up-to-date
                         * type info without needing to clean up writable p.t.
                         * state on the fast path.
                         */
                        LOCK_BIGLOCK(current->domain);
                        cleanup_writable_pagetable(current->domain);
                        y = page->u.inuse.type_info;
                        UNLOCK_BIGLOCK(current->domain);
                        /* Can we make progress now? */
                        if ( ((y & PGT_type_mask) == (type & PGT_type_mask)) ||
                             ((y & PGT_count_mask) == 0) )
                            goto again;
                    }
                    if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                         ((type & PGT_type_mask) != PGT_l1_page_table) )
                        MEM_LOG("Bad type (saw %" PRtype_info
                                " != exp %" PRtype_info ") "
                                "for mfn %lx (pfn %lx)",
                                x, type, page_to_mfn(page),
                                get_gpfn_from_mfn(page_to_mfn(page)));
                    return 0;
                }
                else if ( (x & PGT_va_mask) == PGT_va_mutable )
                {
                    /* The va backpointer is mutable, hence we update it. */
                    nx &= ~PGT_va_mask;
                    nx |= type; /* we know the actual type is correct */
                }
                else if ( ((type & PGT_va_mask) != PGT_va_mutable) &&
                          ((type & PGT_va_mask) != (x & PGT_va_mask)) )
                {
#ifdef CONFIG_X86_PAE
                    /* We use backptr as extra typing. Cannot be unknown. */
                    if ( (type & PGT_type_mask) == PGT_l2_page_table )
                        return 0;
#endif
                    /* This table is possibly mapped at multiple locations. */
                    nx &= ~PGT_va_mask;
                    nx |= PGT_va_unknown;
                }
            }
            if ( unlikely(!(x & PGT_validated)) )
            {
                /* Someone else is updating validation of this page. Wait... */
                while ( (y = page->u.inuse.type_info) == x )
                    cpu_relax();
                goto again;
            }
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type)) )
        {
            MEM_LOG("Error while validating mfn %lx (pfn %lx) for type %"
                    PRtype_info ": caf=%08x taf=%" PRtype_info,
                    page_to_mfn(page), get_gpfn_from_mfn(page_to_mfn(page)),
                    type, page->count_info, page->u.inuse.type_info);
            /* Noone else can get a reference. We hold the only ref. */
            page->u.inuse.type_info = 0;
            return 0;
        }

        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}
