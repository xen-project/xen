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

efi_memory_desc_t ia64_efi_io_md;
EXPORT_SYMBOL(ia64_efi_io_md);
unsigned long wait_init_idle;
int phys_proc_id[NR_CPUS];
unsigned long loops_per_jiffy = (1<<12);	// from linux/init/main.c

void unw_init(void) { printf("unw_init() skipped (NEED FOR KERNEL UNWIND)\n"); }
void ia64_mca_init(void) { printf("ia64_mca_init() skipped (Machine check abort handling)\n"); }
void ia64_mca_cpu_init(void *x) { }
void ia64_patch_mckinley_e9(unsigned long a, unsigned long b) { }
void ia64_patch_vtop(unsigned long a, unsigned long b) { }
void hpsim_setup(char **x) { }

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

void sync_vcpu_execstate(struct vcpu *v) {}

#ifdef CONFIG_VTI
int grant_table_create(struct domain *d) { return 0; }
void grant_table_destroy(struct domain *d) { return; }
#endif

struct pt_regs *guest_cpu_user_regs(void) { return ia64_task_regs(current); }

void raise_actimer_softirq(void)
{
	raise_softirq(AC_TIMER_SOFTIRQ);
}

#ifndef CONFIG_VTI
unsigned long
__gpfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
{
	if (d == dom0)
		return(gpfn);
	else {
		unsigned long pte = lookup_domain_mpa(d,gpfn << PAGE_SHIFT);
		if (!pte) {
printk("__gpfn_to_mfn_foreign: bad gpfn. spinning...\n");
while(1);
			return 0;
		}
		return ((pte & _PFN_MASK) >> PAGE_SHIFT);
	}
}

u32
__mfn_to_gpfn(struct domain *d, unsigned long frame)
{
	// FIXME: is this right?
if ((frame << PAGE_SHIFT) & _PAGE_PPN_MASK) {
printk("__mfn_to_gpfn: bad frame. spinning...\n");
while(1);
}
	return frame;
}
#endif

#ifndef CONFIG_VTI
unsigned long __hypercall_create_continuation(
	unsigned int op, unsigned int nr_args, ...)
{
	printf("__hypercall_create_continuation: not implemented!!!\n");
}
#endif

///////////////////////////////

///////////////////////////////
// from arch/x86/apic.c
///////////////////////////////

extern unsigned long domain0_ready;

int reprogram_ac_timer(s_time_t timeout)
{
	struct vcpu *v = current;

#ifdef CONFIG_VTI
//	if(VMX_DOMAIN(v))
		return 1;
#endif // CONFIG_VTI
	if (!domain0_ready) return 1;
	local_cpu_data->itm_next = timeout;
	if (is_idle_task(v->domain)) vcpu_safe_set_itm(timeout);
	else vcpu_set_next_timer(current);
	return 1;
}

///////////////////////////////
// from arch/ia64/page_alloc.c
///////////////////////////////
DEFINE_PER_CPU(struct page_state, page_states) = {0};
unsigned long totalram_pages;

void __mod_page_state(unsigned offset, unsigned long delta)
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

void free_page_type(struct pfn_info *page, unsigned int type)
{
	dummy();
}

///////////////////////////////
// from arch/ia64/traps.c
///////////////////////////////

void show_registers(struct pt_regs *regs)
{
	printf("*** ADD REGISTER DUMP HERE FOR DEBUGGING\n");
}

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
	printk("die_if_kernel: called, not implemented\n");
}

long
ia64_peek (struct task_struct *child, struct switch_stack *child_stack,
	   unsigned long user_rbs_end, unsigned long addr, long *val)
{
	printk("ia64_peek: called, not implemented\n");
}

long
ia64_poke (struct task_struct *child, struct switch_stack *child_stack,
	   unsigned long user_rbs_end, unsigned long addr, long val)
{
	printk("ia64_poke: called, not implemented\n");
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

void context_switch(struct vcpu *prev, struct vcpu *next)
{
//printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
//printk("@@@@@@ context switch from domain %d (%x) to domain %d (%x)\n",
//prev->domain->domain_id,(long)prev&0xffffff,next->domain->domain_id,(long)next&0xffffff);
//if (prev->domain->domain_id == 1 && next->domain->domain_id == 0) cs10foo();
//if (prev->domain->domain_id == 0 && next->domain->domain_id == 1) cs01foo();
//printk("@@sw %d->%d\n",prev->domain->domain_id,next->domain->domain_id);
#ifdef CONFIG_VTI
	vtm_domain_out(prev);
#endif
	context_switch_count++;
	switch_to(prev,next,prev);
#ifdef CONFIG_VTI
	 vtm_domain_in(current);
#endif

// leave this debug for now: it acts as a heartbeat when more than
// one domain is active
{
static long cnt[16] = { 50,50,50,50,50,50,50,50,50,50,50,50,50,50,50,50};
static int i = 100;
int id = ((struct vcpu *)current)->domain->domain_id & 0xf;
if (!cnt[id]--) { printk("%x",id); cnt[id] = 500000; }
if (!i--) { printk("+",id); i = 1000000; }
}

#ifdef CONFIG_VTI
	if (VMX_DOMAIN(current))
		vmx_load_all_rr(current);
#else
	if (!is_idle_task(current->domain)) {
		load_region_regs(current);
		if (vcpu_timer_expired(current)) vcpu_pend_timer(current);
	}
	if (vcpu_timer_expired(current)) vcpu_pend_timer(current);
#endif
}

void context_switch_finalise(struct vcpu *next)
{
	/* nothing to do */
}

void continue_running(struct vcpu *same)
{
	/* nothing to do */
}

void panic_domain(struct pt_regs *regs, const char *fmt, ...)
{
	va_list args;
	char buf[128];
	struct vcpu *v = current;
	static volatile int test = 1;	// so can continue easily in debug
	extern spinlock_t console_lock;
	unsigned long flags;
    
loop:
	printf("$$$$$ PANIC in domain %d (k6=%p): ",
		v->domain->domain_id, 
		__get_cpu_var(cpu_kr)._kr[IA64_KR_CURRENT]);
	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printf(buf);
	if (regs) show_registers(regs);
	domain_pause_by_systemcontroller(current->domain);
	v->domain->shutdown_code = SHUTDOWN_crash;
	set_bit(_DOMF_shutdown, v->domain->domain_flags);
	if (v->domain->domain_id == 0) {
		int i = 1000000000L;
		// if domain0 crashes, just periodically print out panic
		// message to make post-mortem easier
		while(i--);
		goto loop;
	}
}
