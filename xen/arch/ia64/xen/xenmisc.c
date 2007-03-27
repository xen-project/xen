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
#include <asm/vcpu.h>

unsigned long loops_per_jiffy = (1<<12);	// from linux/init/main.c

/* FIXME: where these declarations should be there ? */
extern void show_registers(struct pt_regs *regs);

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

struct pt_regs *guest_cpu_user_regs(void) { return vcpu_regs(current); }

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

////////////////////////////////////
// called from unaligned.c
////////////////////////////////////

void die_if_kernel(char *str, struct pt_regs *regs, long err)
{
	if (user_mode(regs))
		return;

	printk("%s: %s %ld\n", __func__, str, err);
	debugtrace_dump();
	show_registers(regs);
	domain_crash_synchronous();
}

void vmx_die_if_kernel(char *str, struct pt_regs *regs, long err)
{
	if (vmx_user_mode(regs))
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


void arch_dump_domain_info(struct domain *d)
{
}

void arch_dump_vcpu_info(struct vcpu *v)
{
}

void audit_domains_key(unsigned char key)
{
}

void panic_domain(struct pt_regs *regs, const char *fmt, ...)
{
	va_list args;
	char buf[256];
	struct vcpu *v = current;

	printk("$$$$$ PANIC in domain %d (k6=0x%lx): ",
		v->domain->domain_id,
		__get_cpu_var(cpu_kr)._kr[IA64_KR_CURRENT]);
	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(buf);
	if (regs)
		show_registers(regs);
	domain_crash_synchronous ();
}
