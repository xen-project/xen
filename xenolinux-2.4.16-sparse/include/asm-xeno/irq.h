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

#define NET_TX_IRQ  _EVENT_NET_TX
#define NET_RX_IRQ  _EVENT_NET_RX
#define NET2_TX_IRQ  _EVENT_NET2_TX
#define NET2_RX_IRQ  _EVENT_NET2_RX
#define TIMER_IRQ   _EVENT_TIMER

#define NR_IRQS (sizeof(HYPERVISOR_shared_info->events) * 8)

#define irq_cannonicalize(_irq) (_irq)

extern void disable_irq(unsigned int);
extern void disable_irq_nosync(unsigned int);
extern void enable_irq(unsigned int);
extern unsigned int do_IRQ(int, struct pt_regs *);

#endif /* _ASM_IRQ_H */
