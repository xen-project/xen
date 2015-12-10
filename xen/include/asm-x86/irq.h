#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/* (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar */

#include <xen/config.h>
#include <asm/atomic.h>
#include <asm/numa.h>
#include <xen/cpumask.h>
#include <xen/smp.h>
#include <xen/hvm/irq.h>
#include <irq_vectors.h>
#include <asm/percpu.h>

extern unsigned int nr_irqs_gsi;
extern unsigned int nr_irqs;
#define nr_static_irqs nr_irqs_gsi

#define IO_APIC_IRQ(irq)    (platform_legacy_irq(irq) ?    \
			     (1 << (irq)) & io_apic_irqs : \
			     (irq) < nr_irqs_gsi)

#define MSI_IRQ(irq)       ((irq) >= nr_irqs_gsi && (irq) < nr_irqs)

#define LEGACY_VECTOR(irq)          ((irq) + FIRST_LEGACY_VECTOR)

typedef struct {
    DECLARE_BITMAP(_bits,NR_VECTORS);
} vmask_t;

struct irq_desc;

struct arch_irq_desc {
        s16 vector;                  /* vector itself is only 8 bits, */
        s16 old_vector;              /* but we use -1 for unassigned  */
        cpumask_var_t cpu_mask;
        cpumask_var_t old_cpu_mask;
        cpumask_var_t pending_mask;
        unsigned move_cleanup_count;
        vmask_t *used_vectors;
        u8 move_in_progress : 1;
        s8 used;
};

/* For use with irq_desc.arch.used */
#define IRQ_UNUSED      (0)
#define IRQ_USED        (1)
#define IRQ_RESERVED    (-1)

#define IRQ_VECTOR_UNASSIGNED (-1)

typedef int vector_irq_t[NR_VECTORS];
DECLARE_PER_CPU(vector_irq_t, vector_irq);

extern bool_t opt_noirqbalance;

#define OPT_IRQ_VECTOR_MAP_DEFAULT 0 /* Do the default thing  */
#define OPT_IRQ_VECTOR_MAP_NONE    1 /* None */ 
#define OPT_IRQ_VECTOR_MAP_GLOBAL  2 /* One global vector map (no vector sharing) */ 
#define OPT_IRQ_VECTOR_MAP_PERDEV  3 /* Per-device vetor map (no vector sharing w/in a device) */

extern int opt_irq_vector_map;

/*
 * Per-cpu current frame pointer - the location of the last exception frame on
 * the stack
 */
DECLARE_PER_CPU(struct cpu_user_regs *, __irq_regs);

static inline struct cpu_user_regs *get_irq_regs(void)
{
	return __get_cpu_var(__irq_regs);
}

static inline struct cpu_user_regs *set_irq_regs(struct cpu_user_regs *new_regs)
{
	struct cpu_user_regs *old_regs, **pp_regs = &__get_cpu_var(__irq_regs);

	old_regs = *pp_regs;
	*pp_regs = new_regs;
	return old_regs;
}


#define platform_legacy_irq(irq)	((irq) < 16)

void event_check_interrupt(struct cpu_user_regs *regs);
void invalidate_interrupt(struct cpu_user_regs *regs);
void call_function_interrupt(struct cpu_user_regs *regs);
void apic_timer_interrupt(struct cpu_user_regs *regs);
void error_interrupt(struct cpu_user_regs *regs);
void pmu_apic_interrupt(struct cpu_user_regs *regs);
void spurious_interrupt(struct cpu_user_regs *regs);
void irq_move_cleanup_interrupt(struct cpu_user_regs *regs);

uint8_t alloc_hipriority_vector(void);

void set_direct_apic_vector(
    uint8_t vector, void (*handler)(struct cpu_user_regs *));
void alloc_direct_apic_vector(
    uint8_t *vector, void (*handler)(struct cpu_user_regs *));

void do_IRQ(struct cpu_user_regs *regs);

void disable_8259A_irq(struct irq_desc *);
void enable_8259A_irq(struct irq_desc *);
int i8259A_irq_pending(unsigned int irq);
void mask_8259A(void);
void unmask_8259A(void);
void init_8259A(int aeoi);
void make_8259A_irq(unsigned int irq);
bool_t bogus_8259A_irq(unsigned int irq);
int i8259A_suspend(void);
int i8259A_resume(void);

void setup_IO_APIC(void);
void disable_IO_APIC(void);
void setup_ioapic_dest(void);
vmask_t *io_apic_get_used_vector_map(unsigned int irq);

extern unsigned int io_apic_irqs;

DECLARE_PER_CPU(unsigned int, irq_count);

struct pirq;
struct arch_pirq {
    int irq;
    union {
        struct hvm_pirq {
            int emuirq;
            struct hvm_pirq_dpci dpci;
        } hvm;
    };
};

#define pirq_dpci(pirq) ((pirq) ? &(pirq)->arch.hvm.dpci : NULL)
#define dpci_pirq(pd) container_of(pd, struct pirq, arch.hvm.dpci)

int pirq_shared(struct domain *d , int irq);

int map_domain_pirq(struct domain *d, int pirq, int irq, int type,
                           void *data);
int unmap_domain_pirq(struct domain *d, int pirq);
int get_free_pirq(struct domain *d, int type);
int get_free_pirqs(struct domain *, unsigned int nr);
void free_domain_pirqs(struct domain *d);
int map_domain_emuirq_pirq(struct domain *d, int pirq, int irq);
int unmap_domain_pirq_emuirq(struct domain *d, int pirq);
bool_t hvm_domain_use_pirq(const struct domain *, const struct pirq *);

/* Reset irq affinities to match the given CPU mask. */
void fixup_irqs(const cpumask_t *mask, bool_t verbose);
void fixup_eoi(void);

int  init_irq_data(void);

void clear_irq_vector(int irq);

int irq_to_vector(int irq);
int create_irq(nodeid_t node);
void destroy_irq(unsigned int irq);
int assign_irq_vector(int irq, const cpumask_t *);

extern void irq_complete_move(struct irq_desc *);

extern struct irq_desc *irq_desc;

void lock_vector_lock(void);
void unlock_vector_lock(void);

void setup_vector_irq(unsigned int cpu);

void move_native_irq(struct irq_desc *);
void move_masked_irq(struct irq_desc *);

int bind_irq_vector(int irq, int vector, const cpumask_t *);

void irq_set_affinity(struct irq_desc *, const cpumask_t *mask);

int init_domain_irq_mapping(struct domain *);
void cleanup_domain_irq_mapping(struct domain *);

#define domain_pirq_to_irq(d, pirq) pirq_field(d, pirq, arch.irq, 0)
#define domain_irq_to_pirq(d, irq) ({                           \
    void *__ret = radix_tree_lookup(&(d)->arch.irq_pirq, irq);  \
    __ret ? radix_tree_ptr_to_int(__ret) : 0;                   \
})
#define PIRQ_ALLOCATED -1
#define domain_pirq_to_emuirq(d, pirq) pirq_field(d, pirq,              \
    arch.hvm.emuirq, IRQ_UNBOUND)
#define domain_emuirq_to_pirq(d, emuirq) ({                             \
    void *__ret = radix_tree_lookup(&(d)->arch.hvm_domain.emuirq_pirq,  \
                                    emuirq);                            \
    __ret ? radix_tree_ptr_to_int(__ret) : IRQ_UNBOUND;                 \
})
#define IRQ_UNBOUND -1
#define IRQ_PT -2
#define IRQ_MSI_EMU -3

bool_t cpu_has_pending_apic_eoi(void);

static inline void arch_move_irqs(struct vcpu *v) { }

#endif /* _ASM_HW_IRQ_H */
