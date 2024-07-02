#ifndef __XEN_IRQ_H__
#define __XEN_IRQ_H__

#include <xen/cpumask.h>
#include <xen/rcupdate.h>
#include <xen/spinlock.h>
#include <xen/time.h>
#include <xen/list.h>
#include <asm/regs.h>
#include <asm/hardirq.h>
#include <public/event_channel.h>

/*
 * Heap allocations may need TLB flushes which may require IRQs to be
 * enabled (except when only 1 PCPU is online).
 */
#define ASSERT_ALLOC_CONTEXT() \
    ASSERT(!in_irq() && (local_irq_is_enabled() || num_online_cpus() <= 1))

struct irqaction {
    void (*handler)(int irq, void *dev_id);
    const char *name;
    void *dev_id;
    bool free_on_release;
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
    unsigned int (*startup)(struct irq_desc *desc);
    void (*shutdown)(struct irq_desc *desc);
    void (*enable)(struct irq_desc *desc);
    void (*disable)(struct irq_desc *desc);
    void (*ack)(struct irq_desc *desc);
#ifdef CONFIG_X86
    void (*end)(struct irq_desc *desc, u8 vector);
#else
    void (*end)(struct irq_desc *desc);
#endif
    void (*set_affinity)(struct irq_desc *desc, const cpumask_t *mask);
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

int init_one_irq_desc(struct irq_desc *desc);
int arch_init_one_irq_desc(struct irq_desc *desc);

#define irq_desc_initialized(desc) ((desc)->handler != NULL)

extern int setup_irq(unsigned int irq, unsigned int irqflags,
                     struct irqaction *new);
extern void release_irq(unsigned int irq, const void *dev_id);
extern int request_irq(unsigned int irq, unsigned int irqflags,
               void (*handler)(int irq, void *dev_id),
               const char *devname, void *dev_id);

extern const hw_irq_controller no_irq_type;
void cf_check no_action(int cpl, void *dev_id);
unsigned int cf_check irq_startup_none(struct irq_desc *desc);
void cf_check irq_actor_none(struct irq_desc *desc);
#define irq_shutdown_none irq_actor_none
#define irq_disable_none irq_actor_none
#define irq_enable_none irq_actor_none

/*
 * irq_ack_none() must be provided by the architecture.
 * irq_end_none() is optional, and opted into using a define.
 */
void cf_check irq_ack_none(struct irq_desc *desc);

/*
 * Per-cpu interrupted context register state - the inner-most interrupt frame
 * on the stack.
 */
DECLARE_PER_CPU(const struct cpu_user_regs *, irq_regs);

static inline const struct cpu_user_regs *get_irq_regs(void)
{
    return this_cpu(irq_regs);
}

static inline const struct cpu_user_regs *set_irq_regs(
    const struct cpu_user_regs *new_regs)
{
    const struct cpu_user_regs *old_regs, **pp_regs = &this_cpu(irq_regs);

    old_regs = *pp_regs;
    *pp_regs = new_regs;

    return old_regs;
}

struct domain;
struct vcpu;

struct pirq {
    int pirq;
    evtchn_port_t evtchn;
    struct rcu_head rcu_head;
    bool masked;
    /* Architectures may require this field to be last. */
    struct arch_pirq arch;
};

#define INVALID_PIRQ (-1)
#define pirq_info(d, p) ((struct pirq *)radix_tree_lookup(&(d)->pirq_tree, p))

/* Use this instead of pirq_info() if the structure may need allocating. */
extern struct pirq *pirq_get_info(struct domain *d, int pirq);

#define pirq_field(d, p, f, def) ({ \
    const struct pirq *__pi = pirq_info(d, p); \
    __pi ? __pi->f : (def); \
})
#define pirq_to_evtchn(d, pirq) pirq_field(d, pirq, evtchn, 0)
#define pirq_masked(d, pirq) pirq_field(d, pirq, masked, 0)

void pirq_cleanup_check(struct pirq *pirq, struct domain *d);

#define pirq_cleanup_check(pirq, d) \
    (!(pirq)->evtchn ? pirq_cleanup_check(pirq, d) : (void)0)

extern void pirq_guest_eoi(struct pirq *pirq);
extern void desc_guest_eoi(struct irq_desc *desc, struct pirq *pirq);
extern int pirq_guest_unmask(struct domain *d);
extern int pirq_guest_bind(struct vcpu *v, struct pirq *pirq, int will_share);
extern void pirq_guest_unbind(struct domain *d, struct pirq *pirq);
extern void pirq_set_affinity(struct domain *d, int pirq,
                              const cpumask_t *mask);
extern struct irq_desc *domain_spin_lock_irq_desc(
    struct domain *d, int pirq, unsigned long *pflags);
extern struct irq_desc *pirq_spin_lock_irq_desc(
    const struct pirq *pirq, unsigned long *pflags);

unsigned int set_desc_affinity(struct irq_desc *desc, const cpumask_t *mask);

/* When passed a system domain, this returns the maximum permissible value. */
#ifndef arch_hwdom_irqs
unsigned int arch_hwdom_irqs(const struct domain *d);
#endif

#ifndef arch_evtchn_bind_pirq
void arch_evtchn_bind_pirq(struct domain *d, int pirq);
#endif

#endif /* __XEN_IRQ_H__ */
