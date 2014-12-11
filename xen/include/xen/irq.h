#ifndef __XEN_IRQ_H__
#define __XEN_IRQ_H__

#include <xen/cpumask.h>
#include <xen/rcupdate.h>
#include <xen/spinlock.h>
#include <xen/time.h>
#include <xen/list.h>
#include <asm/regs.h>
#include <asm/hardirq.h>

struct irqaction {
    void (*handler)(int, void *, struct cpu_user_regs *);
    const char *name;
    void *dev_id;
    bool_t free_on_release;
#ifdef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    struct irqaction *next;
#endif
};

/*
 * IRQ line status.
 */
#define _IRQ_INPROGRESS         0 /* IRQ handler active - do not enter! */
#define _IRQ_DISABLED           1 /* IRQ disabled - do not enter! */
#define _IRQ_PENDING            2 /* IRQ pending - replay on enable */
#define _IRQ_REPLAY             3 /* IRQ has been replayed but not acked yet */
#define _IRQ_GUEST              4 /* IRQ is handled by guest OS(es) */
#define _IRQ_MOVE_PENDING       5 /* IRQ is migrating to another CPUs */
#define _IRQ_PER_CPU            6 /* IRQ is per CPU */
#define _IRQ_GUEST_EOI_PENDING  7 /* IRQ was disabled, pending a guest EOI */
#define _IRQF_SHARED            8 /* IRQ is shared */
#define IRQ_INPROGRESS          (1u<<_IRQ_INPROGRESS)
#define IRQ_DISABLED            (1u<<_IRQ_DISABLED)
#define IRQ_PENDING             (1u<<_IRQ_PENDING)
#define IRQ_REPLAY              (1u<<_IRQ_REPLAY)
#define IRQ_GUEST               (1u<<_IRQ_GUEST)
#define IRQ_MOVE_PENDING        (1u<<_IRQ_MOVE_PENDING)
#define IRQ_PER_CPU             (1u<<_IRQ_PER_CPU)
#define IRQ_GUEST_EOI_PENDING   (1u<<_IRQ_GUEST_EOI_PENDING)
#define IRQF_SHARED             (1u<<_IRQF_SHARED)

/* Special IRQ numbers. */
#define AUTO_ASSIGN_IRQ         (-1)
#define NEVER_ASSIGN_IRQ        (-2)
#define FREE_TO_ASSIGN_IRQ      (-3)

struct irq_desc;

/*
 * Interrupt controller descriptor. This is all we need
 * to describe about the low-level hardware. 
 */
struct hw_interrupt_type {
    const char *typename;
    unsigned int (*startup)(struct irq_desc *);
    void (*shutdown)(struct irq_desc *);
    void (*enable)(struct irq_desc *);
    void (*disable)(struct irq_desc *);
    void (*ack)(struct irq_desc *);
#ifdef CONFIG_X86
    void (*end)(struct irq_desc *, u8 vector);
#else
    void (*end)(struct irq_desc *);
#endif
    void (*set_affinity)(struct irq_desc *, const cpumask_t *);
};

typedef const struct hw_interrupt_type hw_irq_controller;

#include <asm/irq.h>

struct msi_desc;
/*
 * This is the "IRQ descriptor", which contains various information
 * about the irq, including what kind of hardware handling it has,
 * whether it is disabled etc etc.
 *
 * Note: on ARMv8 we can use normal bit manipulation functions to access
 * the status field because struct irq_desc contains pointers, therefore
 * the alignment of the struct is at least 8 bytes and status is the
 * first field.
 */
typedef struct irq_desc {
    unsigned int status;        /* IRQ status */
    hw_irq_controller *handler;
    struct msi_desc   *msi_desc;
    struct irqaction *action;   /* IRQ action list */
    int irq;
    spinlock_t lock;
    struct arch_irq_desc arch;
    cpumask_var_t affinity;

    /* irq ratelimit */
    s_time_t rl_quantum_start;
    unsigned int rl_cnt;
    struct list_head rl_link;
} __cacheline_aligned irq_desc_t;

#ifndef irq_to_desc
#define irq_to_desc(irq)    (&irq_desc[irq])
#endif

int init_one_irq_desc(struct irq_desc *);
int arch_init_one_irq_desc(struct irq_desc *);

#define irq_desc_initialized(desc) ((desc)->handler != NULL)

extern int setup_irq(unsigned int irq, unsigned int irqflags,
                     struct irqaction *);
extern void release_irq(unsigned int irq, const void *dev_id);
extern int request_irq(unsigned int irq, unsigned int irqflags,
               void (*handler)(int, void *, struct cpu_user_regs *),
               const char * devname, void *dev_id);

extern hw_irq_controller no_irq_type;
extern void no_action(int cpl, void *dev_id, struct cpu_user_regs *regs);
extern unsigned int irq_startup_none(struct irq_desc *);
extern void irq_actor_none(struct irq_desc *);
#define irq_shutdown_none irq_actor_none
#define irq_disable_none irq_actor_none
#define irq_enable_none irq_actor_none

struct domain;
struct vcpu;

struct pirq {
    int pirq;
    u16 evtchn;
    bool_t masked;
    struct rcu_head rcu_head;
    struct arch_pirq arch;
};

#define pirq_info(d, p) ((struct pirq *)radix_tree_lookup(&(d)->pirq_tree, p))

/* Use this instead of pirq_info() if the structure may need allocating. */
extern struct pirq *pirq_get_info(struct domain *, int pirq);

#define pirq_field(d, p, f, def) ({ \
    const struct pirq *__pi = pirq_info(d, p); \
    __pi ? __pi->f : def; \
})
#define pirq_to_evtchn(d, pirq) pirq_field(d, pirq, evtchn, 0)
#define pirq_masked(d, pirq) pirq_field(d, pirq, masked, 0)

void pirq_cleanup_check(struct pirq *, struct domain *);

#define pirq_cleanup_check(pirq, d) \
    ((pirq)->evtchn ? pirq_cleanup_check(pirq, d) : (void)0)

extern void pirq_guest_eoi(struct pirq *);
extern void desc_guest_eoi(struct irq_desc *, struct pirq *);
extern int pirq_guest_unmask(struct domain *d);
extern int pirq_guest_bind(struct vcpu *, struct pirq *, int will_share);
extern void pirq_guest_unbind(struct domain *d, struct pirq *);
extern void pirq_set_affinity(struct domain *d, int irq, const cpumask_t *);
extern irq_desc_t *domain_spin_lock_irq_desc(
    struct domain *d, int irq, unsigned long *pflags);
extern irq_desc_t *pirq_spin_lock_irq_desc(
    const struct pirq *, unsigned long *pflags);

static inline void set_native_irq_info(unsigned int irq, const cpumask_t *mask)
{
    cpumask_copy(irq_to_desc(irq)->affinity, mask);
}

unsigned int set_desc_affinity(struct irq_desc *, const cpumask_t *);

#ifndef arch_hwdom_irqs
unsigned int arch_hwdom_irqs(domid_t);
#endif

#endif /* __XEN_IRQ_H__ */
