/*
 * Non Fatal Machine Check Exception Reporting
 *
 * (C) Copyright 2002 Dave Jones. <davej@codemonkey.org.uk>
 *
 * This file contains routines to check for non-fatal MCEs every 15s
 *
 */

#include "mce.h"

static int __init cf_check init_nonfatal_mce_checker(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	/* Check for MCE support */
	if (!opt_mce || !mce_available(c))
		return -ENODEV;

	if (!this_cpu(poll_bankmask))
		return -EINVAL;

	/*
	 * Check for non-fatal errors every MCE_RATE s
	 */
	switch (c->x86_vendor) {
#ifdef CONFIG_AMD
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		/* Assume we are on K8 or newer AMD or Hygon CPU here */
		amd_nonfatal_mcheck_init(c);
		break;
#endif

#ifdef CONFIG_INTEL
	case X86_VENDOR_INTEL:
		intel_nonfatal_mcheck_init(c);
		break;
#endif

	default:
		/* unhandled vendor isn't really an error */
		return 0;
	}
	printk(KERN_INFO "mcheck_poll: Machine check polling timer started.\n");
	return 0;
}
__initcall(init_nonfatal_mce_checker);
