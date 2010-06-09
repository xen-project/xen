/*
 * Athlon/Hammer specific Machine Check Exception Reporting
 * (C) Copyright 2002 Dave Jones <davej@codemonkey.org.uk>
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/config.h>
#include <xen/smp.h>

#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"
#include "x86_mca.h"

/* Machine Check Handler For AMD Athlon/Duron */
static fastcall void k7_machine_check(struct cpu_user_regs * regs, long error_code)
{
	int recover=1;
	u32 alow, ahigh, high, low;
	u32 mcgstl, mcgsth;
	int i;

	rdmsr (MSR_IA32_MCG_STATUS, mcgstl, mcgsth);
	if (mcgstl & (1<<0))	/* Recoverable ? */
		recover=0;

	printk (KERN_EMERG "CPU %d: Machine Check Exception: %08x%08x\n",
		smp_processor_id(), mcgsth, mcgstl);

	for (i=1; i<nr_mce_banks; i++) {
		rdmsr (MSR_IA32_MCx_STATUS(i),low, high);
		if (high&(1<<31)) {
			if (high & (1<<29))
				recover |= 1;
			if (high & (1<<25))
				recover |= 2;
			printk (KERN_EMERG "Bank %d: %08x%08x", i, high, low);
			high &= ~(1<<31);
			if (high & (1<<27)) {
				rdmsr (MSR_IA32_MCx_MISC(i), alow, ahigh);
				printk ("[%08x%08x]", ahigh, alow);
			}
			if (high & (1<<26)) {
				rdmsr (MSR_IA32_MCx_ADDR(i), alow, ahigh);
				printk (" at %08x%08x", ahigh, alow);
			}
			printk ("\n");
			/* Clear it */
			wrmsr (MSR_IA32_MCx_STATUS(i), 0UL, 0UL);
			/* Serialize */
			wmb();
			add_taint(TAINT_MACHINE_CHECK);
		}
	}

	if (recover&2)
		mc_panic ("CPU context corrupt");
	if (recover&1)
		mc_panic ("Unable to continue");
	printk (KERN_EMERG "Attempting to continue.\n");
	mcgstl &= ~(1<<2);
	wrmsr (MSR_IA32_MCG_STATUS,mcgstl, mcgsth);
}


/* AMD K7 machine check */
enum mcheck_type amd_k7_mcheck_init(struct cpuinfo_x86 *c)
{
	int i;

	x86_mce_vector_register(k7_machine_check);

	/* Clear status for MC index 0 separately, we don't touch CTL,
	 * as some Athlons cause spurious MCEs when its enabled. */
	wrmsr (MSR_IA32_MC0_STATUS, 0x0, 0x0);
	for (i=1; i<nr_mce_banks; i++) {
		wrmsr (MSR_IA32_MCx_CTL(i), 0xffffffff, 0xffffffff);
		wrmsr (MSR_IA32_MCx_STATUS(i), 0x0, 0x0);
	}

	return mcheck_amd_k7;
}
