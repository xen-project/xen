#ifndef _ASM_IRQ_H
#define _ASM_IRQ_H

/*
 *	linux/include/asm/irq.h
 *
 *	(C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar
 *
 *	IRQ/IPI changes taken from work by Thomas Radke
 *	<tomsoft@informatik.tu-chemnitz.de>
 */

#include <linux/config.h>
#include <asm/hypervisor.h>
#include <asm/ptrace.h>

/*
 * The flat IRQ space is divided into two regions:
 *  1. A one-to-one mapping of real physical IRQs. This space is only used
 *     if we have physical device-access privilege. This region is at the 
 *     start of the IRQ space so that existing device drivers do not need
 *     to be modified to translate physical IRQ numbers into our IRQ space.
 *  3. A dynamic mapping of inter-domain and Xen-sourced virtual IRQs. These
 *     are bound using the provided bind/unbind functions.
 */

#define PIRQ_BASE   0
#define NR_PIRQS  128

#define DYNIRQ_BASE (PIRQ_BASE + NR_PIRQS)
#define NR_DYNIRQS  128

#define NR_IRQS   (NR_PIRQS + NR_DYNIRQS)

extern void physirq_init(void);

/* Dynamic binding of event channels and VIRQ sources to Linux IRQ space. */
extern int  bind_virq_to_irq(int virq);
extern void unbind_virq_from_irq(int virq);
extern int  bind_evtchn_to_irq(int evtchn);
extern void unbind_evtchn_from_irq(int evtchn);

#define irq_cannonicalize(_irq) (_irq)

extern void disable_irq(unsigned int);
extern void disable_irq_nosync(unsigned int);
extern void enable_irq(unsigned int);

#ifdef CONFIG_X86_LOCAL_APIC
#define ARCH_HAS_NMI_WATCHDOG		/* See include/linux/nmi.h */
#endif

#endif /* _ASM_IRQ_H */
