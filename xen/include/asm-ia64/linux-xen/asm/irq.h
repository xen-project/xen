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

#define NR_VECTORS	256
#define NR_IRQS		256

#ifdef XEN
#include <xen/hvm/irq.h>

struct arch_irq_desc {
        int  vector;
	unsigned int depth;
        cpumask_var_t cpu_mask;
};

struct arch_pirq {
	struct hvm_pirq_dpci dpci;
};

int init_irq_data(void);
#endif

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

#ifdef CONFIG_SMP
extern void move_irq(int irq);
#else
#define move_irq(irq)
#endif

struct irqaction;
struct pt_regs;
int handle_IRQ_event(unsigned int, struct pt_regs *, struct irqaction *);

extern fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs);

#ifdef XEN
static inline unsigned int irq_to_vector(int);
extern int setup_irq_vector(unsigned int, struct irqaction *);
extern void release_irq_vector(unsigned int);
extern int request_irq_vector(unsigned int vector,
               void (*handler)(int, void *, struct cpu_user_regs *),
               unsigned long irqflags, const char * devname, void *dev_id);

#define create_irq(x) assign_irq_vector(AUTO_ASSIGN_IRQ)
#define destroy_irq(x) free_irq_vector(x)

#define irq_complete_move(x) do {} \
    while(!x)

#define domain_pirq_to_irq(d, irq) (irq) /* domain_irq_to_vector(d, irq) */

#define hvm_domain_use_pirq(d, info) 0
#endif

#endif /* _ASM_IA64_IRQ_H */
