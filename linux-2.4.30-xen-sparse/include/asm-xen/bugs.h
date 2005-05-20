/*
 *  include/asm-i386/bugs.h
 *
 *  Copyright (C) 1994  Linus Torvalds
 *
 *  Cyrix stuff, June 1998 by:
 *	- Rafael R. Reilova (moved everything from head.S),
 *        <rreilova@ececs.uc.edu>
 *	- Channing Corn (tests & fixes),
 *	- Andrew D. Balsa (code cleanup).
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * This is included by init/main.c to check for architecture-dependent bugs.
 *
 * Needs:
 *	void check_bugs(void);
 */

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/msr.h>


static void __init check_fpu(void)
{
    boot_cpu_data.fdiv_bug = 0;
}

static void __init check_hlt(void)
{
    boot_cpu_data.hlt_works_ok = 1;
}

static void __init check_bugs(void)
{
	extern void __init boot_init_fpu(void);

	identify_cpu(&boot_cpu_data);
	boot_init_fpu();
#ifndef CONFIG_SMP
	printk("CPU: ");
	print_cpu_info(&boot_cpu_data);
#endif
	check_fpu();
	check_hlt();
    system_utsname.machine[1] = '0' + 
        (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
}
