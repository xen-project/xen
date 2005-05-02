/*
 * Xen irq routines
 *
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <asm/ptrace.h>
#include <asm/hw_irq.h>


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
	if (vector != 0xef) {
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
		vcpu_pend_interrupt(dom0->exec_domain[0],vector);
		domain_wake(dom0->exec_domain[0]);
		return(1);
	}
	return(0);
}

/* From linux/kernel/softirq.c */
#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
# define invoke_softirq()	__do_softirq()
#else
# define invoke_softirq()	do_softirq()
#endif

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	//account_system_vtime(current);
	//sub_preempt_count(IRQ_EXIT_OFFSET);
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();
	//preempt_enable_no_resched();
}
/* end from linux/kernel/softirq.c */
