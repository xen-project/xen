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

#define NR_IRQS             256

#define PHYS_IRQ_BASE         0
#define NR_PHYS_IRQS        128

#define HYPEREVENT_IRQ_BASE 128
#define NR_HYPEREVENT_IRQS  128

#define HYPEREVENT_IRQ(_ev)       ((_ev)  + HYPEREVENT_IRQ_BASE)
#define HYPEREVENT_FROM_IRQ(_irq) ((_irq) - HYPEREVENT_IRQ_BASE)

extern void physirq_init(void);

#define irq_cannonicalize(_irq) (_irq)

extern void disable_irq(unsigned int);
extern void disable_irq_nosync(unsigned int);
extern void enable_irq(unsigned int);

#ifdef CONFIG_X86_LOCAL_APIC
#define ARCH_HAS_NMI_WATCHDOG		/* See include/linux/nmi.h */
#endif

#endif /* _ASM_IRQ_H */
