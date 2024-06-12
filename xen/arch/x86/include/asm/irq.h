#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/* (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar */

#include <asm/atomic.h>
#include <asm/numa.h>
#include <xen/cpumask.h>
#include <xen/percpu.h>
#include <xen/smp.h>
#include <asm/hvm/irq.h>

extern unsigned int nr_irqs_gsi;
extern unsigned int nr_irqs;
#define nr_static_irqs nr_irqs_gsi

#define IO_APIC_IRQ(irq)    (platform_legacy_irq(irq) ?    \
			     (1 << (irq)) & io_apic_irqs : \
			     (irq) < nr_irqs_gsi)

#define MSI_IRQ(irq)       ((irq) >= nr_irqs_gsi && (irq) < nr_irqs)

#define LEGACY_VECTOR(irq)          ((irq) + FIRST_LEGACY_VECTOR)

typedef struct {
    DECLARE_BITMAP(_bits, X86_NR_VECTORS);
} vmask_t;

struct irq_desc;

/*
 * Xen logic for moving interrupts around CPUs allows manipulating interrupts
 * that target remote CPUs.  The logic to move an interrupt from CPU(s) is as
 * follows:
 *
 * 1. irq_set_affinity() is called with the new destination mask, such mask is
 *    copied into pending_mask and IRQ_MOVE_PENDING is set in status to notice
 *    an affinity change has been requested.
 * 2. An interrupt acked with the IRQ_MOVE_PENDING will trigger the logic to
 *    migrate it to a destination in pending_mask as long as the mask contains
 *    any online CPUs.
 * 3. cpu_mask and vector is copied to old_cpu_mask and old_vector.
 * 4. New cpu_mask and vector are set, vector is setup at the new destination.
 * 5. move_in_progress is set.
 * 6. Interrupt source is updated to target new CPU and vector.
 * 7. Interrupts arriving at old_cpu_mask are processed normally.
 * 8. When the first interrupt is delivered at the new destination (cpu_mask) as
 *    part of acking the interrupt the cleanup of the old destination(s) is
 *    engaged.  move_in_progress is cleared and old_cpu_mask is
 *    reduced to the online CPUs.  If the result is empty the old vector is
 *    released.  Otherwise move_cleanup_count is set to the weight of online
 *    CPUs in old_cpu_mask and IRQ_MOVE_CLEANUP_VECTOR is sent to them.
 * 9. When receiving IRQ_MOVE_CLEANUP_VECTOR CPUs in old_cpu_mask clean the
 *    vector entry and decrease the count in move_cleanup_count.  The CPU that
 *    sets move_cleanup_count to 0 releases the vector.
 *
 * Note that when interrupt movement (either move_in_progress or
 * move_cleanup_count set) is in progress it's not possible to move the
 * interrupt to yet a different CPU.
 *
 * Interrupt movements done by fixup_irqs() skip setting IRQ_MOVE_PENDING and
 * pending_mask as the movement must be performed right away, and so start
 * directly from step 3.
 *
 * By keeping the vector in the old CPU(s) configured until the interrupt is
 * acked on the new destination Xen allows draining any pending interrupts at
 * the old destinations.
 */
struct arch_irq_desc {
        s16 vector;                  /* vector itself is only 8 bits, */
        s16 old_vector;              /* but we use -1 for unassigned  */
        /*
         * Except for high priority interrupts @cpu_mask may have bits set for
         * offline CPUs.  Consumers need to be careful to mask this down to
         * online ones as necessary.  There is supposed to always be a non-
         * empty intersection with cpu_online_map.
         */
        cpumask_var_t cpu_mask;
        cpumask_var_t old_cpu_mask;
        cpumask_var_t pending_mask;
        vmask_t *used_vectors;
        unsigned move_cleanup_count;
        u8 move_in_progress : 1;
        s8 used;
        /*
         * Weak reference to domain having permission over this IRQ (which can
         * be different from the domain actually having the IRQ assigned)
         */
        domid_t creator_domid;
};

/* For use with irq_desc.arch.used */
#define IRQ_UNUSED      (0)
#define IRQ_USED        (1)
#define IRQ_RESERVED    (-1)

#define IRQ_VECTOR_UNASSIGNED (-1)

typedef int vector_irq_t[X86_NR_VECTORS];
DECLARE_PER_CPU(vector_irq_t, vector_irq);

extern bool opt_noirqbalance;

#define OPT_IRQ_VECTOR_MAP_DEFAULT 0 /* Do the default thing  */
#define OPT_IRQ_VECTOR_MAP_NONE    1 /* None */ 
#define OPT_IRQ_VECTOR_MAP_GLOBAL  2 /* One global vector map (no vector sharing) */ 
#define OPT_IRQ_VECTOR_MAP_PERDEV  3 /* Per-device vetor map (no vector sharing w/in a device) */

extern int opt_irq_vector_map;

#define platform_legacy_irq(irq)	((irq) < 16)

void cf_check event_check_interrupt(void);
void cf_check invalidate_interrupt(void);
void cf_check call_function_interrupt(void);
void cf_check irq_move_cleanup_interrupt(void);

uint8_t alloc_hipriority_vector(void);

void set_direct_apic_vector(uint8_t vector, void (*handler)(void));
void alloc_direct_apic_vector(uint8_t *vector, void (*handler)(void));

void do_IRQ(struct cpu_user_regs *regs);

void cf_check disable_8259A_irq(struct irq_desc *desc);
void cf_check enable_8259A_irq(struct irq_desc *desc);
int i8259A_irq_pending(unsigned int irq);
void mask_8259A(void);
void unmask_8259A(void);
void init_8259A(int auto_eoi);
void make_8259A_irq(unsigned int irq);
bool bogus_8259A_irq(unsigned int irq);
int i8259A_suspend(void);
int i8259A_resume(void);

void enable_IO_APIC(void);
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

int pirq_shared(struct domain *d , int pirq);

int map_domain_pirq(struct domain *d, int pirq, int irq, int type,
                           void *data);
int unmap_domain_pirq(struct domain *d, int pirq);
int get_free_pirq(struct domain *d, int type);
int get_free_pirqs(struct domain *d, unsigned int nr);
void free_domain_pirqs(struct domain *d);
int map_domain_emuirq_pirq(struct domain *d, int pirq, int emuirq);
int unmap_domain_pirq_emuirq(struct domain *d, int pirq);

/* Reset irq affinities to match the given CPU mask. */
void fixup_irqs(const cpumask_t *mask, bool verbose);
void fixup_eoi(void);

int  init_irq_data(void);

void clear_irq_vector(int irq);

int irq_to_vector(int irq);
/*
 * If grant_access is set the current domain is given permissions over
 * the created IRQ.
 */
int create_irq(nodeid_t node, bool grant_access);
void destroy_irq(unsigned int irq);
int assign_irq_vector(int irq, const cpumask_t *mask);

void cf_check irq_complete_move(struct irq_desc *desc);

extern struct irq_desc *irq_desc;

/* Not speculation safe, only used for AP bringup. */
void lock_vector_lock(void);
void unlock_vector_lock(void);

void setup_vector_irq(unsigned int cpu);

void move_native_irq(struct irq_desc *desc);
void move_masked_irq(struct irq_desc *desc);

int bind_irq_vector(int irq, int vector, const cpumask_t *mask);

void cf_check end_nonmaskable_irq(struct irq_desc *desc, uint8_t vector);
void irq_set_affinity(struct irq_desc *desc, const cpumask_t *mask);

int init_domain_irq_mapping(struct domain *d);
void cleanup_domain_irq_mapping(struct domain *d);

#define domain_pirq_to_irq(d, pirq) pirq_field(d, pirq, arch.irq, 0)
#define domain_irq_to_pirq(d, irq) ({                           \
    void *__ret = radix_tree_lookup(&(d)->arch.irq_pirq, irq);  \
    __ret ? radix_tree_ptr_to_int(__ret) : 0;                   \
})
#define PIRQ_ALLOCATED (-1)
#define domain_pirq_to_emuirq(d, pirq) pirq_field(d, pirq,              \
    arch.hvm.emuirq, IRQ_UNBOUND)
#define domain_emuirq_to_pirq(d, emuirq) ({                             \
    void *__ret = radix_tree_lookup(&(d)->arch.hvm.emuirq_pirq, emuirq);\
    __ret ? radix_tree_ptr_to_int(__ret) : IRQ_UNBOUND;                 \
})
#define IRQ_UNBOUND (-1)
#define IRQ_PT      (-2)
#define IRQ_MSI_EMU (-3)

bool cpu_has_pending_apic_eoi(void);

static inline void arch_move_irqs(struct vcpu *v) { }

struct msi_info;
int allocate_and_map_gsi_pirq(struct domain *d, int index, int *pirq_p);
int allocate_and_map_msi_pirq(struct domain *d, int index, int *pirq_p,
                              int type, struct msi_info *msi);

#endif /* _ASM_HW_IRQ_H */
