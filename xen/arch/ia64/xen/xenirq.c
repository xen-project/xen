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
		printf("**** (entry) First received int on vector=%d,itc=%lx\n",
			(unsigned long) vector, ia64_get_itc());
		firsttime[vector] = 0;
	}
}


int
xen_do_IRQ(ia64_vector vector)
{
	if (vector != IA64_TIMER_VECTOR && vector != IA64_IPI_VECTOR) {
		extern void vcpu_pend_interrupt(void *, int);
#if 0
		if (firsttime[vector]) {
			printf("**** (iterate) First received int on vector=%d,itc=%lx\n",
			(unsigned long) vector, ia64_get_itc());
			firsttime[vector] = 0;
		}
		if (firstpend[vector]) {
			printf("**** First pended int on vector=%d,itc=%lx\n",
				(unsigned long) vector,ia64_get_itc());
			firstpend[vector] = 0;
		}
#endif
		//FIXME: TEMPORARY HACK!!!!
		vcpu_pend_interrupt(dom0->vcpu[0],vector);
		vcpu_wake(dom0->vcpu[0]);
		return(1);
	}
	return(0);
}

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void xen_irq_exit(struct pt_regs *regs)
{
	sub_preempt_count(IRQ_EXIT_OFFSET);
}

/*
 * ONLY gets called from ia64_leave_kernel
 * ONLY call with interrupts enabled
 */
void process_soft_irq()
{
	if (!in_interrupt() && local_softirq_pending()) {
		add_preempt_count(SOFTIRQ_OFFSET);
		do_softirq();
		sub_preempt_count(SOFTIRQ_OFFSET);
	}
}

/* end from linux/kernel/softirq.c */
