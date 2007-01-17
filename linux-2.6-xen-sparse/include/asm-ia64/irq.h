#ifndef _ASM_IA64_IRQ_H
#define _ASM_IA64_IRQ_H

/*
 * Copyright (C) 1999-2000, 2002 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 *
 * 11/24/98	S.Eranian 	updated TIMER_IRQ and irq_canonicalize
 * 01/20/99	S.Eranian	added keyboard interrupt
 * 02/29/00     D.Mosberger	moved most things into hw_irq.h
 */

#ifndef CONFIG_XEN
#define NR_IRQS		256
#define NR_IRQ_VECTORS	NR_IRQS
#else
/*
 * The flat IRQ space is divided into two regions:
 *  1. A one-to-one mapping of real physical IRQs. This space is only used
 *     if we have physical device-access privilege. This region is at the 
 *     start of the IRQ space so that existing device drivers do not need
 *     to be modified to translate physical IRQ numbers into our IRQ space.
 *  3. A dynamic mapping of inter-domain and Xen-sourced virtual IRQs. These
 *     are bound using the provided bind/unbind functions.
 */

#define PIRQ_BASE		0
#define NR_PIRQS		256

#define DYNIRQ_BASE		(PIRQ_BASE + NR_PIRQS)
#define NR_DYNIRQS		256

#define NR_IRQS			(NR_PIRQS + NR_DYNIRQS)
#define NR_IRQ_VECTORS		NR_IRQS

#define pirq_to_irq(_x)		((_x) + PIRQ_BASE)
#define irq_to_pirq(_x)		((_x) - PIRQ_BASE)

#define dynirq_to_irq(_x)	((_x) + DYNIRQ_BASE)
#define irq_to_dynirq(_x)	((_x) - DYNIRQ_BASE)

#define RESCHEDULE_VECTOR	0
#define IPI_VECTOR		1
#define CMCP_VECTOR		2
#define CPEP_VECTOR		3
#define NR_IPIS			4
#endif /* CONFIG_XEN */

static __inline__ int
irq_canonicalize (int irq)
{
	/*
	 * We do the legacy thing here of pretending that irqs < 16
	 * are 8259 irqs.  This really shouldn't be necessary at all,
	 * but we keep it here as serial.c still uses it...
	 */
	return ((irq == 2) ? 9 : irq);
}

extern void disable_irq (unsigned int);
extern void disable_irq_nosync (unsigned int);
extern void enable_irq (unsigned int);
extern void set_irq_affinity_info (unsigned int irq, int dest, int redir);

#endif /* _ASM_IA64_IRQ_H */
