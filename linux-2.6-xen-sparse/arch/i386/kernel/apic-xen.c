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

#include <linux/init.h>

#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/mc146818rtc.h>
#include <linux/kernel_stat.h>
#include <linux/sysdev.h>
#include <linux/cpu.h>
#include <linux/module.h>

#include <asm/atomic.h>
#include <asm/smp.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>
#include <asm/hpet.h>
#include <asm/i8253.h>
#include <asm/nmi.h>

#include <mach_apic.h>
#include <mach_apicdef.h>
#include <mach_ipi.h>

#include "io_ports.h"

#ifndef CONFIG_XEN
/*
 * cpu_mask that denotes the CPUs that needs timer interrupt coming in as
 * IPIs in place of local APIC timers
 */
static cpumask_t timer_bcast_ipi;
#endif

/*
 * Knob to control our willingness to enable the local APIC.
 */
int enable_local_apic __initdata = 0; /* -1=force-disable, +1=force-enable */

/*
 * Debug level
 */
int apic_verbosity;

#ifndef CONFIG_XEN
static int modern_apic(void)
{
	unsigned int lvr, version;
	/* AMD systems use old APIC versions, so check the CPU */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		boot_cpu_data.x86 >= 0xf)
		return 1;
	lvr = apic_read(APIC_LVR);
	version = GET_APIC_VERSION(lvr);
	return version >= 0x14;
}
#endif /* !CONFIG_XEN */

/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
	printk("unexpected IRQ trap at vector %02x\n", irq);
	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 * But only ack when the APIC is enabled -AK
	 */
	if (cpu_has_apic)
		ack_APIC_irq();
}

int get_physical_broadcast(void)
{
        return 0xff;
}

#ifndef CONFIG_XEN
#ifndef CONFIG_SMP
static void up_apic_timer_interrupt_call(struct pt_regs *regs)
{
	int cpu = smp_processor_id();

	/*
	 * the NMI deadlock-detector uses this.
	 */
	per_cpu(irq_stat, cpu).apic_timer_irqs++;

	smp_local_timer_interrupt(regs);
}
#endif

void smp_send_timer_broadcast_ipi(struct pt_regs *regs)
{
	cpumask_t mask;

	cpus_and(mask, cpu_online_map, timer_bcast_ipi);
	if (!cpus_empty(mask)) {
#ifdef CONFIG_SMP
		send_IPI_mask(mask, LOCAL_TIMER_VECTOR);
#else
		/*
		 * We can directly call the apic timer interrupt handler
		 * in UP case. Minus all irq related functions
		 */
		up_apic_timer_interrupt_call(regs);
#endif
	}
}
#endif

int setup_profiling_timer(unsigned int multiplier)
{
	return -EINVAL;
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
