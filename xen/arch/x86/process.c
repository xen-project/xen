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
#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <asm/ptrace.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/mpspec.h>
#include <asm/ldt.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/shadow.h>

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
    if ( hlt_counter == 0 )
    {
        __cli();
        if ( !softirq_pending(smp_processor_id()) )
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
        while ( !softirq_pending(cpu) )
            default_idle();
        do_softirq();
    }
}

void startup_cpu_idle_loop(void)
{
    /* Just some sanity to ensure that the scheduler is set up okay. */
    ASSERT(current->domain == IDLE_DOMAIN_ID);
    domain_unpause_by_systemcontroller(current);
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
    extern int opt_noreboot;
#ifdef CONFIG_SMP
    int cpuid;
#endif
	
    if ( opt_noreboot )
    {
        printk("Reboot disabled on cmdline: require manual reset\n");
        for ( ; ; ) __asm__ __volatile__ ("hlt");
    }

#ifdef CONFIG_SMP
    cpuid = GET_APIC_ID(apic_read(APIC_ID));

    /* KAF: Need interrupts enabled for safe IPI. */
    __sti();

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
            __asm__ __volatile__("lidt %0": "=m" (no_idt));
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

void new_thread(struct domain *p,
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


void switch_to(struct domain *prev_p, struct domain *next_p)
{
    struct thread_struct *next = &next_p->thread;
    struct tss_struct *tss = init_tss + smp_processor_id();
    execution_context_t *stack_ec = get_execution_context();
    int i;
    
    __cli();

    /* Switch guest general-register state. */
    if ( !is_idle_task(prev_p) )
    {
        memcpy(&prev_p->shared_info->execution_context, 
               stack_ec, 
               sizeof(*stack_ec));
        unlazy_fpu(prev_p);
        CLEAR_FAST_TRAP(&prev_p->thread);
    }

    if ( !is_idle_task(next_p) )
    {
        memcpy(stack_ec,
               &next_p->shared_info->execution_context,
               sizeof(*stack_ec));

        /*
         * This is sufficient! If the descriptor DPL differs from CS RPL then 
         * we'll #GP. If DS, ES, FS, GS are DPL 0 then they'll be cleared 
         * automatically. If SS RPL or DPL differs from CS RPL then we'll #GP.
         */
        if ( (stack_ec->cs & 3) == 0 )
            stack_ec->cs = FLAT_RING1_CS;
        if ( (stack_ec->ss & 3) == 0 )
            stack_ec->ss = FLAT_RING1_DS;

        SET_FAST_TRAP(&next_p->thread);

        /* Switch the guest OS ring-1 stack. */
        tss->esp1 = next->guestos_sp;
        tss->ss1  = next->guestos_ss;

        /* Maybe switch the debug registers. */
        if ( unlikely(next->debugreg[7]) )
        {
            loaddebug(next, 0);
            loaddebug(next, 1);
            loaddebug(next, 2);
            loaddebug(next, 3);
            /* no 4 and 5 */
            loaddebug(next, 6);
            loaddebug(next, 7);
        }

        /* Switch page tables. */
        write_ptbase(&next_p->mm);
        tlb_clocktick();
    }

    if ( unlikely(prev_p->io_bitmap != NULL) || 
         unlikely(next_p->io_bitmap != NULL) )
    {
        if ( next_p->io_bitmap != NULL )
        {
            /* Copy in the appropriate parts of the IO bitmap.  We use the
             * selector to copy only the interesting parts of the bitmap. */

            u64 old_sel = ~0ULL; /* IO bitmap selector for previous task. */

            if ( prev_p->io_bitmap != NULL)
            {
                old_sel = prev_p->io_bitmap_sel;

                /* Replace any areas of the IO bitmap that had bits cleared. */
                for ( i = 0; i < sizeof(prev_p->io_bitmap_sel) * 8; i++ )
                    if ( !test_bit(i, &prev_p->io_bitmap_sel) )
                        memcpy(&tss->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                               &next_p->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                               IOBMP_SELBIT_LWORDS * sizeof(unsigned long));
            }

            /* Copy in any regions of the new task's bitmap that have bits
             * clear and we haven't already dealt with. */
            for ( i = 0; i < sizeof(prev_p->io_bitmap_sel) * 8; i++ )
            {
                if ( test_bit(i, &old_sel)
                     && !test_bit(i, &next_p->io_bitmap_sel) )
                    memcpy(&tss->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                           &next_p->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                           IOBMP_SELBIT_LWORDS * sizeof(unsigned long));
            }

            tss->bitmap = IO_BITMAP_OFFSET;

	}
        else
        {
            /* In this case, we're switching FROM a task with IO port access,
             * to a task that doesn't use the IO bitmap.  We set any TSS bits
             * that might have been cleared, ready for future use. */
            for ( i = 0; i < sizeof(prev_p->io_bitmap_sel) * 8; i++ )
                if ( !test_bit(i, &prev_p->io_bitmap_sel) )
                    memset(&tss->io_bitmap[i * IOBMP_SELBIT_LWORDS],
                           0xFF, IOBMP_SELBIT_LWORDS * sizeof(unsigned long));

            /*
             * a bitmap offset pointing outside of the TSS limit
             * causes a nicely controllable SIGSEGV if a process
             * tries to use a port IO instruction. The first
             * sys_ioperm() call sets up the bitmap properly.
             */
            tss->bitmap = INVALID_IO_BITMAP_OFFSET;
	}
    }

    set_current(next_p);

    /* Switch GDT and LDT. */
    __asm__ __volatile__ ("lgdt %0" : "=m" (*next_p->mm.gdt));
    load_LDT(next_p);

    __sti();
}


/* XXX Currently the 'domain' field is ignored! XXX */
long do_iopl(domid_t domain, unsigned int new_io_pl)
{
    execution_context_t *ec = get_execution_context();
    ec->eflags = (ec->eflags & 0xffffcfff) | ((new_io_pl&3) << 12);
    return 0;
}
