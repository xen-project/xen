#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/* (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar */

#include <xen/config.h>
#include <asm/atomic.h>
#include <xen/cpumask.h>
#include <xen/smp.h>
#include <xen/hvm/irq.h>
#include <irq_vectors.h>
#include <asm/percpu.h>

#define IO_APIC_IRQ(irq)    (platform_legacy_irq(irq) ?    \
			     (1 << (irq)) & io_apic_irqs : \
			     (irq) < nr_irqs_gsi)
#define IO_APIC_VECTOR(irq) (irq_vector[irq])

#define MSI_IRQ(irq)       ((irq) >= nr_irqs_gsi && (irq) < nr_irqs)

#define LEGACY_VECTOR(irq)          ((irq) + FIRST_LEGACY_VECTOR)

#define irq_to_desc(irq)    (&irq_desc[irq])
#define irq_cfg(irq)        (&irq_cfg[irq])

typedef struct {
    DECLARE_BITMAP(_bits,NR_VECTORS);
} vmask_t;

struct irq_cfg {
        int  vector;
        cpumask_t cpu_mask;
        cpumask_t old_cpu_mask;
        unsigned move_cleanup_count;
        vmask_t *used_vectors;
        u8 move_in_progress : 1;
};

extern struct irq_cfg *irq_cfg;

typedef int vector_irq_t[NR_VECTORS];
DECLARE_PER_CPU(vector_irq_t, vector_irq);

extern u8 *irq_vector;

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

fastcall void event_check_interrupt(void);
fastcall void invalidate_interrupt(void);
fastcall void call_function_interrupt(void);
fastcall void apic_timer_interrupt(void);
fastcall void error_interrupt(void);
fastcall void pmu_apic_interrupt(void);
fastcall void spurious_interrupt(void);
fastcall void thermal_interrupt(void);
fastcall void cmci_interrupt(void);
fastcall void irq_move_cleanup_interrupt(void);

fastcall void smp_event_check_interrupt(struct cpu_user_regs *regs);
fastcall void smp_invalidate_interrupt(void);
fastcall void smp_call_function_interrupt(struct cpu_user_regs *regs);
fastcall void smp_apic_timer_interrupt(struct cpu_user_regs *regs);
fastcall void smp_error_interrupt(struct cpu_user_regs *regs);
fastcall void smp_pmu_apic_interrupt(struct cpu_user_regs *regs);
fastcall void smp_spurious_interrupt(struct cpu_user_regs *regs);
fastcall void smp_thermal_interrupt(struct cpu_user_regs *regs);
fastcall void smp_cmci_interrupt(struct cpu_user_regs *regs);
fastcall void smp_irq_move_cleanup_interrupt(struct cpu_user_regs *regs);

asmlinkage void do_IRQ(struct cpu_user_regs *regs);

void disable_8259A_irq(unsigned int irq);
void enable_8259A_irq(unsigned int irq);
int i8259A_irq_pending(unsigned int irq);
void mask_8259A(void);
void unmask_8259A(void);
void init_8259A(int aeoi);
void make_8259A_irq(unsigned int irq);
int i8259A_suspend(void);
int i8259A_resume(void);

void setup_IO_APIC(void);
void disable_IO_APIC(void);
void setup_ioapic_dest(void);

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
int get_free_pirq(struct domain *d, int type, int index);
void free_domain_pirqs(struct domain *d);
int map_domain_emuirq_pirq(struct domain *d, int pirq, int irq);
int unmap_domain_pirq_emuirq(struct domain *d, int pirq);
bool_t hvm_domain_use_pirq(const struct domain *, const struct pirq *);

/* A cpu has been removed from cpu_online_mask.  Re-set irq affinities. */
void fixup_irqs(void);

int  init_irq_data(void);

void clear_irq_vector(int irq);

int irq_to_vector(int irq);
int create_irq(void);
void destroy_irq(unsigned int irq);

struct irq_desc;
extern void irq_complete_move(struct irq_desc **descp);

extern struct irq_desc *irq_desc;

void lock_vector_lock(void);
void unlock_vector_lock(void);

void __setup_vector_irq(int cpu);

void move_native_irq(int irq);
void move_masked_irq(int irq);

int __assign_irq_vector(int irq, struct irq_cfg *, const cpumask_t *);

int bind_irq_vector(int irq, int vector, cpumask_t domain);

void irq_set_affinity(struct irq_desc *, const cpumask_t *mask);

int init_domain_irq_mapping(struct domain *);
void cleanup_domain_irq_mapping(struct domain *);

#define domain_pirq_to_irq(d, pirq) pirq_field(d, pirq, arch.irq)
#define domain_irq_to_pirq(d, irq) ({                           \
    void *__ret = radix_tree_lookup(&(d)->arch.irq_pirq, irq);  \
    __ret ? radix_tree_ptr_to_int(__ret) : 0;                   \
})
#define PIRQ_ALLOCATED -1
#define domain_pirq_to_emuirq(d, pirq) pirq_field(d, pirq, arch.hvm.emuirq)
#define domain_emuirq_to_pirq(d, emuirq) ({                             \
    void *__ret = radix_tree_lookup(&(d)->arch.hvm_domain.emuirq_pirq,  \
                                    emuirq);                            \
    __ret ? radix_tree_ptr_to_int(__ret) : IRQ_UNBOUND;                 \
})
#define IRQ_UNBOUND -1
#define IRQ_PT -2

bool_t cpu_has_pending_apic_eoi(void);

#endif /* _ASM_HW_IRQ_H */
