/*
 *	Local APIC handling, local APIC timers
 *
 *	(c) 1999, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	Fixes
 *	Maciej W. Rozycki	:	Bits for genuine 82489DX APICs;
 *					thanks to Eric Gilmore
 *					and Rolf G. Tews
 *					for testing these extensively.
 *	Maciej W. Rozycki	:	Various updates and fixes.
 *	Mikael Pettersson	:	Power Management for UP-APIC.
 *	Pavel Machek and
 *	Mikael Pettersson	:	PM converted to driver model.
 */

#include <linux/config.h>
#include <linux/init.h>

#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/mc146818rtc.h>
#include <linux/kernel_stat.h>
#include <linux/sysdev.h>

#include <asm/atomic.h>
#include <asm/smp.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>
#include <asm/hpet.h>

#include "io_ports.h"

/*
 * Debug level
 */
int apic_verbosity;
int disable_apic;

void smp_local_timer_interrupt(struct pt_regs *regs)
{

	profile_tick(CPU_PROFILING, regs);
#ifndef CONFIG_XEN
	int cpu = smp_processor_id();

	if (--per_cpu(prof_counter, cpu) <= 0) {
		/*
		 * The multiplier may have changed since the last time we got
		 * to this point as a result of the user writing to
		 * /proc/profile. In this case we need to adjust the APIC
		 * timer accordingly.
		 *
		 * Interrupts are already masked off at this point.
		 */
		per_cpu(prof_counter, cpu) = per_cpu(prof_multiplier, cpu);
		if (per_cpu(prof_counter, cpu) != 
		    per_cpu(prof_old_multiplier, cpu)) {
			__setup_APIC_LVTT(calibration_result/
					per_cpu(prof_counter, cpu));
			per_cpu(prof_old_multiplier, cpu) =
				per_cpu(prof_counter, cpu);
		}

#ifdef CONFIG_SMP
		update_process_times(user_mode(regs));
#endif
	}
#endif

	/*
	 * We take the 'long' return path, and there every subsystem
	 * grabs the appropriate locks (kernel lock/ irq lock).
	 *
	 * we might want to decouple profiling from the 'long path',
	 * and do the profiling totally in assembly.
	 *
	 * Currently this isn't too much of an issue (performance wise),
	 * we can take more than 100K local irqs per second on a 100 MHz P5.
	 */
}

/*
 * Local APIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesn't support APIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */
void smp_apic_timer_interrupt(struct pt_regs *regs)
{
	/*
	 * the NMI deadlock-detector uses this.
	 */
	add_pda(apic_timer_irqs, 1);

	/*
	 * NOTE! We'd better ACK the irq immediately,
	 * because timer handling can be slow.
	 */
	ack_APIC_irq();
	/*
	 * update_process_times() expects us to have done irq_enter().
	 * Besides, if we don't timer interrupts ignore the global
	 * interrupt lock, which is the WrongThing (tm) to do.
	 */
	irq_enter();
	smp_local_timer_interrupt(regs);
	irq_exit();
}

/*
 * This interrupt should _never_ happen with our APIC/SMP architecture
 */
asmlinkage void smp_spurious_interrupt(void)
{
	unsigned int v;
	irq_enter();
	/*
	 * Check if this really is a spurious interrupt and ACK it
	 * if it is a vectored one.  Just in case...
	 * Spurious interrupts should not be ACKed.
	 */
	v = apic_read(APIC_ISR + ((SPURIOUS_APIC_VECTOR & ~0x1f) >> 1));
	if (v & (1 << (SPURIOUS_APIC_VECTOR & 0x1f)))
		ack_APIC_irq();

#if 0
	static unsigned long last_warning; 
	static unsigned long skipped; 

	/* see sw-dev-man vol 3, chapter 7.4.13.5 */
	if (time_before(last_warning+30*HZ,jiffies)) { 
		printk(KERN_INFO "spurious APIC interrupt on CPU#%d, %ld skipped.\n",
		       smp_processor_id(), skipped);
		last_warning = jiffies; 
		skipped = 0;
	} else { 
		skipped++; 
	} 
#endif 
	irq_exit();
}

/*
 * This interrupt should never happen with our APIC/SMP architecture
 */

asmlinkage void smp_error_interrupt(void)
{
	unsigned int v, v1;

	irq_enter();
	/* First tickle the hardware, only then report what went on. -- REW */
	v = apic_read(APIC_ESR);
	apic_write(APIC_ESR, 0);
	v1 = apic_read(APIC_ESR);
	ack_APIC_irq();
	atomic_inc(&irq_err_count);

	/* Here is what the APIC error bits mean:
	   0: Send CS error
	   1: Receive CS error
	   2: Send accept error
	   3: Receive accept error
	   4: Reserved
	   5: Send illegal vector
	   6: Received illegal vector
	   7: Illegal register address
	*/
	printk (KERN_DEBUG "APIC error on CPU%d: %02x(%02x)\n",
	        smp_processor_id(), v , v1);
	irq_exit();
}

int get_physical_broadcast(void)
{
        return 0xff;
}

/*
 * This initializes the IO-APIC and APIC hardware if this is
 * a UP kernel.
 */
int __init APIC_init_uniprocessor (void)
{
#ifdef CONFIG_X86_IO_APIC
	if (smp_found_config)
		if (!skip_ioapic_setup && nr_ioapics)
			setup_IO_APIC();
#endif

	return 0;
}
