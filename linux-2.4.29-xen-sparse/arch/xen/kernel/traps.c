/*
 *  linux/arch/i386/traps.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * 'Traps.c' handles hardware traps and faults after we have saved some
 * state in 'asm.s'.
 */
#include <linux/config.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/highmem.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/i387.h>

#include <asm/smp.h>
#include <asm/pgalloc.h>

#include <asm/hypervisor.h>

#include <linux/irq.h>
#include <linux/module.h>

asmlinkage int system_call(void);
asmlinkage void lcall7(void);
asmlinkage void lcall27(void);

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void double_fault(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
asmlinkage void fixup_4gb_segment(void);
asmlinkage void machine_check(void);

int kstack_depth_to_print = 24;


/*
 * If the address is either in the .text section of the
 * kernel, or in the vmalloc'ed module regions, it *may* 
 * be the address of a calling routine
 */

#ifdef CONFIG_MODULES

extern struct module *module_list;
extern struct module kernel_module;

static inline int kernel_text_address(unsigned long addr)
{
	int retval = 0;
	struct module *mod;

	if (addr >= (unsigned long) &_stext &&
	    addr <= (unsigned long) &_etext)
		return 1;

	for (mod = module_list; mod != &kernel_module; mod = mod->next) {
		/* mod_bound tests for addr being inside the vmalloc'ed
		 * module area. Of course it'd be better to test only
		 * for the .text subset... */
		if (mod_bound(addr, 0, mod)) {
			retval = 1;
			break;
		}
	}

	return retval;
}

#else

static inline int kernel_text_address(unsigned long addr)
{
	return (addr >= (unsigned long) &_stext &&
		addr <= (unsigned long) &_etext);
}

#endif

void show_trace(unsigned long * stack)
{
	int i;
	unsigned long addr;

	if (!stack)
		stack = (unsigned long*)&stack;

	printk("Call Trace: ");
	i = 1;
	while (((long) stack & (THREAD_SIZE-1)) != 0) {
		addr = *stack++;
		if (kernel_text_address(addr)) {
			if (i && ((i % 6) == 0))
				printk("\n   ");
			printk("[<%08lx>] ", addr);
			i++;
		}
	}
	printk("\n");
}

void show_trace_task(struct task_struct *tsk)
{
	unsigned long esp = tsk->thread.esp;

	/* User space on another CPU? */
	if ((esp ^ (unsigned long)tsk) & (PAGE_MASK<<1))
		return;
	show_trace((unsigned long *)esp);
}

void show_stack(unsigned long * esp)
{
	unsigned long *stack;
	int i;

	// debugging aid: "show_stack(NULL);" prints the
	// back trace for this cpu.

	if(esp==NULL)
		esp=(unsigned long*)&esp;

	stack = esp;
	for(i=0; i < kstack_depth_to_print; i++) {
		if (((long) stack & (THREAD_SIZE-1)) == 0)
			break;
		if (i && ((i % 8) == 0))
			printk("\n       ");
		printk("%08lx ", *stack++);
	}
	printk("\n");
	show_trace(esp);
}

void show_registers(struct pt_regs *regs)
{
	int in_kernel = 1;
	unsigned long esp;
	unsigned short ss;

	esp = (unsigned long) (&regs->esp);
	ss = __KERNEL_DS;
	if (regs->xcs & 2) {
		in_kernel = 0;
		esp = regs->esp;
		ss = regs->xss & 0xffff;
	}
	printk(KERN_ALERT "CPU:    %d\n", smp_processor_id() );
	printk(KERN_ALERT "EIP:    %04x:[<%08lx>]    %s\n",
	       0xffff & regs->xcs, regs->eip, print_tainted());
	printk(KERN_ALERT "EFLAGS: %08lx\n",regs->eflags);
	printk(KERN_ALERT "eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	printk(KERN_ALERT "esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
		regs->esi, regs->edi, regs->ebp, esp);
	printk(KERN_ALERT "ds: %04x   es: %04x   ss: %04x\n",
		regs->xds & 0xffff, regs->xes & 0xffff, ss);
	printk(KERN_ALERT "Process %s (pid: %d, stackpage=%08lx)",
		current->comm, current->pid, 4096+(unsigned long)current);
	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (in_kernel) {

		printk(KERN_ALERT "\nStack: ");
		show_stack((unsigned long*)esp);

#if 0
                {
                        int i;
			printk(KERN_ALERT "\nCode: ");
			if(regs->eip < PAGE_OFFSET)
			        goto bad;

			for(i=0;i<20;i++)
			{
			        unsigned char c;
			        if(__get_user(c, &((unsigned char*)regs->eip)[i])) {
bad:
				        printk(KERN_ALERT " Bad EIP value.");
					break;
				}
				printk("%02x ", c);
			}
		}
#endif
	}
	printk(KERN_ALERT "\n");
}	

spinlock_t die_lock = SPIN_LOCK_UNLOCKED;

void die(const char * str, struct pt_regs * regs, long err)
{
	console_verbose();
	spin_lock_irq(&die_lock);
	bust_spinlocks(1);
	printk("%s: %04lx\n", str, err & 0xffff);
	show_registers(regs);
	bust_spinlocks(0);
	spin_unlock_irq(&die_lock);
	do_exit(SIGSEGV);
}

static inline void die_if_kernel(const char * str, struct pt_regs * regs, long err)
{
	if (!(2 & regs->xcs))
		die(str, regs, err);
}


static void inline do_trap(int trapnr, int signr, char *str,
			   struct pt_regs * regs, long error_code,
                           siginfo_t *info)
{
	if (!(regs->xcs & 2))
		goto kernel_trap;

	/*trap_signal:*/ {
		struct task_struct *tsk = current;
		tsk->thread.error_code = error_code;
		tsk->thread.trap_no = trapnr;
		if (info)
			force_sig_info(signr, info, tsk);
		else
			force_sig(signr, tsk);
		return;
	}

	kernel_trap: {
		unsigned long fixup = search_exception_table(regs->eip);
		if (fixup)
			regs->eip = fixup;
		else	
			die(str, regs, error_code);
		return;
	}
}

#define DO_ERROR(trapnr, signr, str, name) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	do_trap(trapnr, signr, str, regs, error_code, NULL); \
}

#define DO_ERROR_INFO(trapnr, signr, str, name, sicode, siaddr) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	siginfo_t info; \
	info.si_signo = signr; \
	info.si_errno = 0; \
	info.si_code = sicode; \
	info.si_addr = (void *)siaddr; \
	do_trap(trapnr, signr, str, regs, error_code, &info); \
}

DO_ERROR_INFO( 0, SIGFPE,  "divide error", divide_error, FPE_INTDIV, regs->eip)
DO_ERROR( 3, SIGTRAP, "int3", int3)
DO_ERROR( 4, SIGSEGV, "overflow", overflow)
DO_ERROR( 5, SIGSEGV, "bounds", bounds)
DO_ERROR_INFO( 6, SIGILL,  "invalid operand", invalid_op, ILL_ILLOPN, regs->eip)
DO_ERROR( 7, SIGSEGV, "device not available", device_not_available)
DO_ERROR( 8, SIGSEGV, "double fault", double_fault)
DO_ERROR( 9, SIGFPE,  "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS)
DO_ERROR(11, SIGBUS,  "segment not present", segment_not_present)
DO_ERROR(12, SIGBUS,  "stack segment", stack_segment)
DO_ERROR_INFO(17, SIGBUS, "alignment check", alignment_check, BUS_ADRALN, 0)
DO_ERROR(18, SIGBUS, "machine check", machine_check)

asmlinkage void do_general_protection(struct pt_regs * regs, long error_code)
{
	/*
	 * If we trapped on an LDT access then ensure that the default_ldt is
	 * loaded, if nothing else. We load default_ldt lazily because LDT
	 * switching costs time and many applications don't need it.
	 */
	if ( unlikely((error_code & 6) == 4) )
	{
		unsigned long ldt;
		__asm__ __volatile__ ( "sldt %0" : "=r" (ldt) );
		if ( ldt == 0 )
		{
                    xen_set_ldt((unsigned long)&default_ldt[0], 5);
		    return;
		}
	}

	if (!(regs->xcs & 2))
		goto gp_in_kernel;

	current->thread.error_code = error_code;
	current->thread.trap_no = 13;
	force_sig(SIGSEGV, current);
	return;

gp_in_kernel:
	{
		unsigned long fixup;
		fixup = search_exception_table(regs->eip);
		if (fixup) {
			regs->eip = fixup;
			return;
		}
		die("general protection fault", regs, error_code);
	}
}


asmlinkage void do_debug(struct pt_regs * regs, long error_code)
{
    unsigned int condition;
    struct task_struct *tsk = current;
    siginfo_t info;

    condition = HYPERVISOR_get_debugreg(6);

    /* Mask out spurious debug traps due to lazy DR7 setting */
    if (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) {
        if (!tsk->thread.debugreg[7])
            goto clear_dr7;
    }

    /* Save debug status register where ptrace can see it */
    tsk->thread.debugreg[6] = condition;

    /* Mask out spurious TF errors due to lazy TF clearing */
    if (condition & DR_STEP) {
        /*
         * The TF error should be masked out only if the current
         * process is not traced and if the TRAP flag has been set
         * previously by a tracing process (condition detected by
         * the PT_DTRACE flag); remember that the i386 TRAP flag
         * can be modified by the process itself in user mode,
         * allowing programs to debug themselves without the ptrace()
         * interface.
         */
        if ((tsk->ptrace & (PT_DTRACE|PT_PTRACED)) == PT_DTRACE)
            goto clear_TF;
    }

    /* Ok, finally something we can handle */
    tsk->thread.trap_no = 1;
    tsk->thread.error_code = error_code;
    info.si_signo = SIGTRAP;
    info.si_errno = 0;
    info.si_code = TRAP_BRKPT;
        
    /* If this is a kernel mode trap, save the user PC on entry to 
     * the kernel, that's what the debugger can make sense of.
     */
    info.si_addr = ((regs->xcs & 2) == 0) ? (void *)tsk->thread.eip : 
                                            (void *)regs->eip;
    force_sig_info(SIGTRAP, &info, tsk);

    /* Disable additional traps. They'll be re-enabled when
     * the signal is delivered.
     */
 clear_dr7:
    HYPERVISOR_set_debugreg(7, 0);
    return;

 clear_TF:
    regs->eflags &= ~TF_MASK;
    return;
}


/*
 * Note that we play around with the 'TS' bit in an attempt to get
 * the correct behaviour even in the presence of the asynchronous
 * IRQ13 behaviour
 */
void math_error(void *eip)
{
	struct task_struct * task;
	siginfo_t info;
	unsigned short cwd, swd;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	save_init_fpu(task);
	task->thread.trap_no = 16;
	task->thread.error_code = 0;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = __SI_FAULT;
	info.si_addr = eip;
	/*
	 * (~cwd & swd) will mask out exceptions that are not set to unmasked
	 * status.  0x3f is the exception bits in these regs, 0x200 is the
	 * C1 reg you need in case of a stack fault, 0x040 is the stack
	 * fault bit.  We should only be taking one exception at a time,
	 * so if this combination doesn't produce any single exception,
	 * then we have a bad program that isn't syncronizing its FPU usage
	 * and it will suffer the consequences since we won't be able to
	 * fully reproduce the context of the exception
	 */
	cwd = get_fpu_cwd(task);
	swd = get_fpu_swd(task);
	switch (((~cwd) & swd & 0x3f) | (swd & 0x240)) {
		case 0x000:
		default:
			break;
		case 0x001: /* Invalid Op */
		case 0x041: /* Stack Fault */
		case 0x241: /* Stack Fault | Direction */
			info.si_code = FPE_FLTINV;
			break;
		case 0x002: /* Denormalize */
		case 0x010: /* Underflow */
			info.si_code = FPE_FLTUND;
			break;
		case 0x004: /* Zero Divide */
			info.si_code = FPE_FLTDIV;
			break;
		case 0x008: /* Overflow */
			info.si_code = FPE_FLTOVF;
			break;
		case 0x020: /* Precision */
			info.si_code = FPE_FLTRES;
			break;
	}
	force_sig_info(SIGFPE, &info, task);
}

asmlinkage void do_coprocessor_error(struct pt_regs * regs, long error_code)
{
	ignore_irq13 = 1;
	math_error((void *)regs->eip);
}

void simd_math_error(void *eip)
{
	struct task_struct * task;
	siginfo_t info;
	unsigned short mxcsr;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	save_init_fpu(task);
	task->thread.trap_no = 19;
	task->thread.error_code = 0;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = __SI_FAULT;
	info.si_addr = eip;
	/*
	 * The SIMD FPU exceptions are handled a little differently, as there
	 * is only a single status/control register.  Thus, to determine which
	 * unmasked exception was caught we must mask the exception mask bits
	 * at 0x1f80, and then use these to mask the exception bits at 0x3f.
	 */
	mxcsr = get_fpu_mxcsr(task);
	switch (~((mxcsr & 0x1f80) >> 7) & (mxcsr & 0x3f)) {
		case 0x000:
		default:
			break;
		case 0x001: /* Invalid Op */
			info.si_code = FPE_FLTINV;
			break;
		case 0x002: /* Denormalize */
		case 0x010: /* Underflow */
			info.si_code = FPE_FLTUND;
			break;
		case 0x004: /* Zero Divide */
			info.si_code = FPE_FLTDIV;
			break;
		case 0x008: /* Overflow */
			info.si_code = FPE_FLTOVF;
			break;
		case 0x020: /* Precision */
			info.si_code = FPE_FLTRES;
			break;
	}
	force_sig_info(SIGFPE, &info, task);
}

asmlinkage void do_simd_coprocessor_error(struct pt_regs * regs,
					  long error_code)
{
	if (cpu_has_xmm) {
		/* Handle SIMD FPU exceptions on PIII+ processors. */
		ignore_irq13 = 1;
		simd_math_error((void *)regs->eip);
	} else {
		die_if_kernel("cache flush denied", regs, error_code);
		current->thread.trap_no = 19;
		current->thread.error_code = error_code;
		force_sig(SIGSEGV, current);
	}
}

/*
 *  'math_state_restore()' saves the current math information in the
 * old math state array, and gets the new ones from the current task
 *
 * Careful.. There are problems with IBM-designed IRQ13 behaviour.
 * Don't touch unless you *really* know how it works.
 */
asmlinkage void math_state_restore(struct pt_regs regs)
{
	/*
	 * A trap in kernel mode can be ignored. It'll be the fast XOR or
	 * copying libraries, which will correctly save/restore state and
	 * reset the TS bit in CR0.
	 */
	if ( (regs.xcs & 2) == 0 )
		return;

	if (current->used_math) {
		restore_fpu(current);
	} else {
		init_fpu();
	}
	current->flags |= PF_USEDFPU;	/* So we fnsave on switch_to() */
}


#define _set_gate(gate_addr,type,dpl,addr) \
do { \
  int __d0, __d1; \
  __asm__ __volatile__ ("movw %%dx,%%ax\n\t" \
	"movw %4,%%dx\n\t" \
	"movl %%eax,%0\n\t" \
	"movl %%edx,%1" \
	:"=m" (*((long *) (gate_addr))), \
	 "=m" (*(1+(long *) (gate_addr))), "=&a" (__d0), "=&d" (__d1) \
	:"i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
	 "3" ((char *) (addr)),"2" (__KERNEL_CS << 16)); \
} while (0)

static void __init set_call_gate(void *a, void *addr)
{
	_set_gate(a,12,3,addr);
}


/* NB. All these are "trap gates" (i.e. events_mask isn't cleared). */
static trap_info_t trap_table[] = {
    {  0, 0, __KERNEL_CS, (unsigned long)divide_error                },
    {  1, 0, __KERNEL_CS, (unsigned long)debug                       },
    {  3, 3, __KERNEL_CS, (unsigned long)int3                        },
    {  4, 3, __KERNEL_CS, (unsigned long)overflow                    },
    {  5, 3, __KERNEL_CS, (unsigned long)bounds                      },
    {  6, 0, __KERNEL_CS, (unsigned long)invalid_op                  },
    {  7, 0, __KERNEL_CS, (unsigned long)device_not_available        },
    {  8, 0, __KERNEL_CS, (unsigned long)double_fault                },
    {  9, 0, __KERNEL_CS, (unsigned long)coprocessor_segment_overrun },
    { 10, 0, __KERNEL_CS, (unsigned long)invalid_TSS                 },
    { 11, 0, __KERNEL_CS, (unsigned long)segment_not_present         },
    { 12, 0, __KERNEL_CS, (unsigned long)stack_segment               },
    { 13, 0, __KERNEL_CS, (unsigned long)general_protection          },
    { 14, 0, __KERNEL_CS, (unsigned long)page_fault                  },
    { 15, 0, __KERNEL_CS, (unsigned long)fixup_4gb_segment           },
    { 16, 0, __KERNEL_CS, (unsigned long)coprocessor_error           },
    { 17, 0, __KERNEL_CS, (unsigned long)alignment_check             },
    { 18, 0, __KERNEL_CS, (unsigned long)machine_check               },
    { 19, 0, __KERNEL_CS, (unsigned long)simd_coprocessor_error      },
    { SYSCALL_VECTOR, 
          3, __KERNEL_CS, (unsigned long)system_call                 },
    {  0, 0,           0, 0                           }
};


void __init trap_init(void)
{
    HYPERVISOR_set_trap_table(trap_table);    
    HYPERVISOR_set_fast_trap(SYSCALL_VECTOR);

    /*
     * The default LDT is a single-entry callgate to lcall7 for iBCS and a
     * callgate to lcall27 for Solaris/x86 binaries.
     */
    clear_page(&default_ldt[0]);
    set_call_gate(&default_ldt[0],lcall7);
    set_call_gate(&default_ldt[4],lcall27);
    __make_page_readonly(&default_ldt[0]);

    cpu_init();
}
