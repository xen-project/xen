/*
 * Xen irq routines
 *
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <asm/ptrace.h>
#include <asm/hw_irq.h>
#include <asm/delay.h>

void
xen_debug_irq(ia64_vector vector, struct pt_regs *regs)
{
//FIXME: For debug only, can be removed
	static char firstirq = 1;
	static char firsttime[256];
	static char firstpend[256];
	if (firstirq) {
		int i;
		for (i=0;i<256;i++) firsttime[i] = 1;
		for (i=0;i<256;i++) firstpend[i] = 1;
		firstirq = 0;
	}
	if (firsttime[vector]) {
		printf("**** (entry) First received int on vector=%lu,itc=%lx\n",
			(unsigned long) vector, ia64_get_itc());
		firsttime[vector] = 0;
	}
}

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	sub_preempt_count(IRQ_EXIT_OFFSET);
}

/*
 * ONLY gets called from ia64_leave_kernel
 * ONLY call with interrupts enabled
 */
void process_soft_irq(void)
{
	if (!in_interrupt() && local_softirq_pending()) {
		add_preempt_count(SOFTIRQ_OFFSET);
		do_softirq();
		sub_preempt_count(SOFTIRQ_OFFSET);
	}
}

/* end from linux/kernel/softirq.c */
