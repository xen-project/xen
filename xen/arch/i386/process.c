/*
 *  linux/arch/i386/kernel/process.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#define __KERNEL_SYSCALLS__
#include <xeno/config.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/smp.h>
#include <asm/ptrace.h>
#include <xeno/delay.h>
#include <xeno/interrupt.h>
#include <asm/mc146818rtc.h>

#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>

#include <xeno/irq.h>
#include <xeno/event.h>

int hlt_counter;

void disable_hlt(void)
{
    hlt_counter++;
}

void enable_hlt(void)
{
    hlt_counter--;
}

/*
 * We use this if we don't have any better
 * idle routine..
 */
static void default_idle(void)
{
    if (!hlt_counter) {
        __cli();
        if (!current->hyp_events && !softirq_pending(smp_processor_id()))
            safe_halt();
        else
            __sti();
    }
}

void continue_cpu_idle_loop(void)
{
    int cpu = smp_processor_id();
    for ( ; ; )
    {
        irq_stat[cpu].idle_timestamp = jiffies;
        while (!current->hyp_events && !softirq_pending(cpu))
            default_idle();
        do_hyp_events();
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    /* Just some sanity to ensure that the scheduler is set up okay. */
    ASSERT(current->domain == IDLE_DOMAIN_ID);
    (void)wake_up(current);
    __enter_scheduler();

    /*
     * Declares CPU setup done to the boot processor.
     * Therefore memory barrier to ensure state is visible.
     */
    smp_mb();
    init_idle();

    continue_cpu_idle_loop();
}

static long no_idt[2];
static int reboot_mode;
int reboot_thru_bios = 0;

#ifdef CONFIG_SMP
int reboot_smp = 0;
static int reboot_cpu = -1;
/* shamelessly grabbed from lib/vsprintf.c for readability */
#define is_digit(c)	((c) >= '0' && (c) <= '9')
#endif


static inline void kb_wait(void)
{
    int i;

    for (i=0; i<0x10000; i++)
        if ((inb_p(0x64) & 0x02) == 0)
            break;
}


void machine_restart(char * __unused)
{
#if CONFIG_SMP
    int cpuid;
	
    cpuid = GET_APIC_ID(apic_read(APIC_ID));

    if (reboot_smp) {

        /* check to see if reboot_cpu is valid 
           if its not, default to the BSP */
        if ((reboot_cpu == -1) ||  
            (reboot_cpu > (NR_CPUS -1))  || 
            !(phys_cpu_present_map & (1<<cpuid))) 
            reboot_cpu = boot_cpu_physical_apicid;

        reboot_smp = 0;  /* use this as a flag to only go through this once*/
        /* re-run this function on the other CPUs
           it will fall though this section since we have 
           cleared reboot_smp, and do the reboot if it is the
           correct CPU, otherwise it halts. */
        if (reboot_cpu != cpuid)
            smp_call_function((void *)machine_restart , NULL, 1, 0);
    }

    /* if reboot_cpu is still -1, then we want a tradional reboot, 
       and if we are not running on the reboot_cpu,, halt */
    if ((reboot_cpu != -1) && (cpuid != reboot_cpu)) {
        for (;;)
            __asm__ __volatile__ ("hlt");
    }
    /*
     * Stop all CPUs and turn off local APICs and the IO-APIC, so
     * other OSs see a clean IRQ state.
     */
    smp_send_stop();
    disable_IO_APIC();
#endif

    if(!reboot_thru_bios) {
        /* rebooting needs to touch the page at absolute addr 0 */
        *((unsigned short *)__va(0x472)) = reboot_mode;
        for (;;) {
            int i;
            for (i=0; i<100; i++) {
                kb_wait();
                udelay(50);
                outb(0xfe,0x64);         /* pulse reset low */
                udelay(50);
            }
            /* That didn't work - force a triple fault.. */
            __asm__ __volatile__("lidt %0": :"m" (no_idt));
            __asm__ __volatile__("int3");
        }
    }

    panic("Need to reinclude BIOS reboot code\n");
}

void machine_halt(void)
{
    machine_restart(0);
}

void machine_power_off(void)
{
    machine_restart(0);
}

void exit_thread(void)
{
    /* nothing to do ... */
}

void flush_thread(void)
{
    struct task_struct *tsk = current;

    memset(tsk->thread.debugreg, 0, sizeof(unsigned long)*8);
    /*
     * Forget coprocessor state..
     */
    clear_fpu(tsk);
    tsk->flags &= ~PF_DONEFPUINIT;
}

void release_thread(struct task_struct *dead_task)
{
}

void new_thread(struct task_struct *p,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
    execution_context_t *ec = &p->shared_info->execution_context;

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_RING1_DS
     *       CS:EIP = FLAT_RING1_CS:start_pc
     *       SS:ESP = FLAT_RING1_DS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     */
    ec->ds = ec->es = ec->fs = ec->gs = ec->ss = FLAT_RING1_DS;
    ec->cs = FLAT_RING1_CS;
    ec->eip = start_pc;
    ec->esp = start_stack;
    ec->esi = start_info;

    __save_flags(ec->eflags);
    ec->eflags |= X86_EFLAGS_IF;

    /* No fast trap at start of day. */
    SET_DEFAULT_FAST_TRAP(&p->thread);
}


/*
 * This special macro can be used to load a debugging register
 */
#define loaddebug(thread,register) \
		__asm__("movl %0,%%db" #register  \
			: /* no output */ \
			:"r" (thread->debugreg[register]))

void switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
    struct thread_struct *next = &next_p->thread;
    struct tss_struct *tss = init_tss + smp_processor_id();
    execution_context_t *stack_ec = get_execution_context();

    __cli();

    /* Switch guest general-register state. */
    memcpy(&prev_p->shared_info->execution_context, 
           stack_ec, 
           sizeof(*stack_ec));
    memcpy(stack_ec,
           &next_p->shared_info->execution_context,
           sizeof(*stack_ec));

    /*
     * This is sufficient! If the descriptor DPL differs from CS RPL
     * then we'll #GP. If DS, ES, FS, GS are DPL 0 then they'll be
     * cleared automatically. If SS RPL or DPL differs from CS RPL
     * then we'll #GP.
     */
    if ( (stack_ec->cs & 3) == 0 )
        stack_ec->cs = 0;

    unlazy_fpu(prev_p);

    /* Switch the fast-trap handler. */
    CLEAR_FAST_TRAP(&prev_p->thread);
    SET_FAST_TRAP(&next_p->thread);

    /* Switch the guest OS ring-1 stack. */
    tss->esp1 = next->esp1;
    tss->ss1  = next->ss1;

    /* Switch page tables.  */
    __write_cr3_counted(pagetable_val(next_p->mm.pagetable));

    set_current(next_p);

    /* Switch GDT and LDT. */
    __asm__ __volatile__ ("lgdt %0" : "=m" (*next_p->mm.gdt));
    load_LDT();

    /* Maybe switch the debug registers. */
    if ( next->debugreg[7] )
    {
        loaddebug(next, 0);
        loaddebug(next, 1);
        loaddebug(next, 2);
        loaddebug(next, 3);
        /* no 4 and 5 */
        loaddebug(next, 6);
        loaddebug(next, 7);
    }

    __sti();
}


/* XXX Currently the 'domain' field is ignored! XXX */
long do_iopl(unsigned int domain, unsigned int new_io_pl)
{
    execution_context_t *ec = get_execution_context();
    ec->eflags = (ec->eflags & 0xffffcfff) | ((new_io_pl&3) << 12);
    return 0;
}
