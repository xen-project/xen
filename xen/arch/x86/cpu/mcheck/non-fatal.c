/*
 * Non Fatal Machine Check Exception Reporting
 *
 * (C) Copyright 2002 Dave Jones. <davej@codemonkey.org.uk>
 *
 * This file contains routines to check for non-fatal MCEs every 15s
 *
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/timer.h>
#include <xen/errno.h>
#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"
#include "x86_mca.h"
int firstbank = 0;
static struct timer mce_timer;

#define MCE_PERIOD MILLISECS(15000)

static void mce_checkregs (void *info)
{
	u32 low, high;
	int i;

	for (i=firstbank; i<nr_mce_banks; i++) {
		rdmsr (MSR_IA32_MC0_STATUS+i*4, low, high);

		if (high & (1<<31)) {
			printk(KERN_INFO "MCE: The hardware reports a non "
				"fatal, correctable incident occurred on "
				"CPU %d.\n",
				smp_processor_id());
			printk (KERN_INFO "Bank %d: %08x%08x\n", i, high, low);

			/* Scrub the error so we don't pick it up in MCE_RATE seconds time. */
			wrmsr (MSR_IA32_MC0_STATUS+i*4, 0UL, 0UL);

			/* Serialize */
			wmb();
			add_taint(TAINT_MACHINE_CHECK);
		}
	}
}

static void mce_work_fn(void *data)
{ 
	on_each_cpu(mce_checkregs, NULL, 1, 1);
	set_timer(&mce_timer, NOW() + MCE_PERIOD);
}

static int __init init_nonfatal_mce_checker(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	/* Check for MCE support */
	if (!mce_available(c))
		return -ENODEV;
	/*
	 * Check for non-fatal errors every MCE_RATE s
	 */
	switch (c->x86_vendor) {
	case X86_VENDOR_AMD:
		if (c->x86 == 6) { /* K7 */
			firstbank = 1;
			init_timer(&mce_timer, mce_work_fn, NULL, 0);
			set_timer(&mce_timer, NOW() + MCE_PERIOD);
			break;
		}

		/* Assume we are on K8 or newer AMD CPU here */
		amd_nonfatal_mcheck_init(c);
		break;

	case X86_VENDOR_INTEL:
		/* p5 family is different. P4/P6 and latest CPUs shares the
		 * same polling methods
		*/
		if ( c->x86 != 5 )
		{
			/* some CPUs or banks don't support cmci, we need to 
			 * enable this feature anyway
			 */
			intel_mcheck_timer(c);
		}
		break;
	}

	printk(KERN_INFO "mcheck_poll: Machine check polling timer started.\n");
	return 0;
}
__initcall(init_nonfatal_mce_checker);
