#ifndef __XEN_IRQ_H__
#define __XEN_IRQ_H__

#include <xen/config.h>
#include <xen/cpumask.h>
#include <xen/spinlock.h>
#include <asm/regs.h>
#include <asm/hardirq.h>

struct irqaction
{
    void (*handler)(int, void *, struct cpu_user_regs *);
    const char *name;
    void *dev_id;
};

/*
 * IRQ line status.
 */
#define IRQ_INPROGRESS	1	/* IRQ handler active - do not enter! */
#define IRQ_DISABLED	2	/* IRQ disabled - do not enter! */
#define IRQ_PENDING	4	/* IRQ pending - replay on enable */
#define IRQ_REPLAY	8	/* IRQ has been replayed but not acked yet */
#define IRQ_GUEST       16      /* IRQ is handled by guest OS(es) */
#define IRQ_GUEST_EOI_PENDING 32 /* IRQ was disabled, pending a guest EOI */
#define IRQ_PER_CPU     256     /* IRQ is per CPU */

/* Special IRQ numbers. */
#define AUTO_ASSIGN_IRQ         (-1)
#define NEVER_ASSIGN_IRQ        (-2)
#define FREE_TO_ASSIGN_IRQ      (-3)

/*
 * Interrupt controller descriptor. This is all we need
 * to describe about the low-level hardware. 
 */
struct hw_interrupt_type {
    const char *typename;
    unsigned int (*startup)(unsigned int irq);
    void (*shutdown)(unsigned int irq);
    void (*enable)(unsigned int irq);
    void (*disable)(unsigned int irq);
    void (*ack)(unsigned int irq);
    void (*end)(unsigned int irq);
    void (*set_affinity)(unsigned int irq, cpumask_t mask);
};

typedef struct hw_interrupt_type hw_irq_controller;

#include <asm/irq.h>

#ifdef NR_IRQS
# define nr_irqs_gsi NR_IRQS
#else
extern unsigned int nr_irqs_gsi;
#endif

struct msi_desc;
/*
 * This is the "IRQ descriptor", which contains various information
 * about the irq, including what kind of hardware handling it has,
 * whether it is disabled etc etc.
 *
 * Pad this out to 32 bytes for cache and indexing reasons.
 */
typedef struct {
    unsigned int status;		/* IRQ status */
    hw_irq_controller *handler;
    struct msi_desc   *msi_desc;
    struct irqaction *action;	/* IRQ action list */
    unsigned int depth;		/* nested irq disables */
    spinlock_t lock;
    cpumask_t affinity;
} __cacheline_aligned irq_desc_t;

extern irq_desc_t irq_desc[NR_VECTORS];

extern int setup_irq_vector(unsigned int, struct irqaction *);
extern void release_irq_vector(unsigned int);
extern int request_irq_vector(unsigned int vector,
               void (*handler)(int, void *, struct cpu_user_regs *),
               unsigned long irqflags, const char * devname, void *dev_id);

#define setup_irq(irq, action) \
    setup_irq_vector(irq_to_vector(irq), action)

#define release_irq(irq) \
    release_irq_vector(irq_to_vector(irq))

#define request_irq(irq, handler, irqflags, devname, devid) \
    request_irq_vector(irq_to_vector(irq), handler, irqflags, devname, devid)

extern hw_irq_controller no_irq_type;
extern void no_action(int cpl, void *dev_id, struct cpu_user_regs *regs);

struct domain;
struct vcpu;
extern int pirq_guest_eoi(struct domain *d, int irq);
extern int pirq_guest_unmask(struct domain *d);
extern int pirq_guest_bind(struct vcpu *v, int irq, int will_share);
extern void pirq_guest_unbind(struct domain *d, int irq);
extern irq_desc_t *domain_spin_lock_irq_desc(
    struct domain *d, int irq, unsigned long *pflags);

static inline void set_native_irq_info(unsigned int vector, cpumask_t mask)
{
    irq_desc[vector].affinity = mask;
}

#ifdef irq_to_vector
static inline void set_irq_info(int irq, cpumask_t mask)
{
    set_native_irq_info(irq_to_vector(irq), mask);
}
#endif

#endif /* __XEN_IRQ_H__ */
