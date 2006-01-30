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
#include <linux/sched.h>
/* include comes from machine specific directory */
#include "irq_vectors.h"
#include <asm/thread_info.h>

static __inline__ int irq_canonicalize(int irq)
{
	return ((irq == 2) ? 9 : irq);
}

#ifdef CONFIG_X86_LOCAL_APIC
#define ARCH_HAS_NMI_WATCHDOG		/* See include/linux/nmi.h */
#endif

#define KDB_VECTOR	0xf9

# define irq_ctx_init(cpu) do { } while (0)

struct irqaction;
struct pt_regs;
int handle_IRQ_event(unsigned int, struct pt_regs *, struct irqaction *);

#endif /* _ASM_IRQ_H */
