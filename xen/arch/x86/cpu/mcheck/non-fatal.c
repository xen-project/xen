/*
 * Non Fatal Machine Check Exception Reporting
 *
 * (C) Copyright 2002 Dave Jones. <davej@codemonkey.org.uk>
 *
 * This file contains routines to check for non-fatal MCEs every 15s
 *
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/timer.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"
#include "vmce.h"

static struct timer mce_timer;

#define MCE_PERIOD MILLISECS(8000)
#define MCE_PERIOD_MIN MILLISECS(2000)
#define MCE_PERIOD_MAX MILLISECS(16000)

static uint64_t period = MCE_PERIOD;
static int adjust = 0;
static int variable_period = 1;

static void mce_checkregs (void *info)
{
	mctelem_cookie_t mctc;
	struct mca_summary bs;
	static uint64_t dumpcount = 0;

	mctc = mcheck_mca_logout(MCA_POLLER, __get_cpu_var(poll_bankmask), &bs, NULL);

	if (bs.errcnt && mctc != NULL) {
		adjust++;

		/* If Dom0 enabled the VIRQ_MCA event, then notify it.
		 * Otherwise, if dom0 has had plenty of time to register
		 * the virq handler but still hasn't then dump telemetry
		 * to the Xen console.  The call count may be incremented
		 * on multiple cpus at once and is indicative only - just
		 * a simple-minded attempt to avoid spamming the console
		 * for corrected errors in early startup.
		 */

		if (dom0_vmce_enabled()) {
			mctelem_commit(mctc);
			send_global_virq(VIRQ_MCA);
		} else if (++dumpcount >= 10) {
			x86_mcinfo_dump((struct mc_info *)mctelem_dataptr(mctc));
			mctelem_dismiss(mctc);
		} else {
			mctelem_dismiss(mctc);
		}
	} else if (mctc != NULL) {
		mctelem_dismiss(mctc);
	}
}

static void mce_work_fn(void *data)
{ 
	on_each_cpu(mce_checkregs, NULL, 1);

	if (variable_period) {
		if (adjust)
			period /= (adjust + 1);
		else
			period *= 2;
		if (period > MCE_PERIOD_MAX)
			period = MCE_PERIOD_MAX;
		if (period < MCE_PERIOD_MIN)
			period = MCE_PERIOD_MIN;
	}

	set_timer(&mce_timer, NOW() + period);
	adjust = 0;
}

static int __init init_nonfatal_mce_checker(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	/* Check for MCE support */
	if (!opt_mce || !mce_available(c))
		return -ENODEV;

	if (__get_cpu_var(poll_bankmask) == NULL)
		return -EINVAL;

	/*
	 * Check for non-fatal errors every MCE_RATE s
	 */
	switch (c->x86_vendor) {
	case X86_VENDOR_AMD:
		/* Assume we are on K8 or newer AMD CPU here */
		amd_nonfatal_mcheck_init(c);
		break;

	case X86_VENDOR_INTEL:
		init_timer(&mce_timer, mce_work_fn, NULL, 0);
		set_timer(&mce_timer, NOW() + MCE_PERIOD);
		break;
	}

	printk(KERN_INFO "mcheck_poll: Machine check polling timer started.\n");
	return 0;
}
__initcall(init_nonfatal_mce_checker);
