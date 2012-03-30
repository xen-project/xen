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
static void k7_machine_check(struct cpu_user_regs * regs, long error_code)
{
	int recover = 1;
	uint64_t msr_content, mcgst;
	int i;

	rdmsrl(MSR_IA32_MCG_STATUS, mcgst);
	if (mcgst & MCG_STATUS_RIPV)	/* Recoverable ? */
		recover = 0;

	printk(KERN_EMERG "CPU %d: Machine Check Exception: 0x%016"PRIx64"\n",
		smp_processor_id(), mcgst);

	for (i = 1; i < nr_mce_banks; i++) {
		uint64_t value;

		rdmsrl(MSR_IA32_MCx_STATUS(i), msr_content);
		if (msr_content & MCi_STATUS_VAL) {
			if (msr_content & MCi_STATUS_UC)
				recover |= 1;
			if (msr_content & MCi_STATUS_PCC)
				recover |= 2;
			printk(KERN_EMERG "Bank %d: 0x%16"PRIx64,
				i, msr_content);
			msr_content &= ~MCi_STATUS_VAL;
			if (msr_content & MCi_STATUS_MISCV) {
				rdmsrl(MSR_IA32_MCx_MISC(i), value);
				printk("[0x%016"PRIx64"]", value);
			}
			if (msr_content & MCi_STATUS_ADDRV) {
				rdmsrl(MSR_IA32_MCx_ADDR(i), value);
				printk(" at 0x%016"PRIx64, value);
			}
			printk("\n");
			/* Clear it */
			wrmsrl(MSR_IA32_MCx_STATUS(i), 0x0ULL);
			/* Serialize */
			wmb();
			add_taint(TAINT_MACHINE_CHECK);
		}
	}

	if (recover & 2)
		mc_panic("CPU context corrupt");
	if (recover & 1)
		mc_panic("Unable to continue");
	printk(KERN_EMERG "Attempting to continue.\n");
	mcgst &= ~MCG_STATUS_MCIP;
	wrmsrl(MSR_IA32_MCG_STATUS, mcgst);
}


/* AMD K7 machine check */
enum mcheck_type amd_k7_mcheck_init(struct cpuinfo_x86 *c)
{
	int i;

	x86_mce_vector_register(k7_machine_check);

	/* Clear status for MC index 0 separately, we don't touch CTL,
	 * as some Athlons cause spurious MCEs when its enabled. */
	wrmsrl(MSR_IA32_MC0_STATUS, 0x0ULL);
	for (i = 1; i < nr_mce_banks; i++) {
		wrmsrl(MSR_IA32_MCx_CTL(i), 0xffffffffffffffffULL);
		wrmsrl(MSR_IA32_MCx_STATUS(i), 0x0ULL);
	}

	return mcheck_amd_k7;
}
