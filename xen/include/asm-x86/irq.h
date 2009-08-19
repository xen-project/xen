#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

/* (C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar */

#include <xen/config.h>
#include <asm/atomic.h>
#include <irq_vectors.h>

#define IO_APIC_IRQ(irq)    (((irq) >= 16 && (irq) < nr_irqs_gsi) \
        || (((irq) < 16) && (1<<(irq)) & io_apic_irqs))
#define IO_APIC_VECTOR(irq) (irq_vector[irq])

#define MSI_IRQ(irq)       ((irq) >= nr_irqs_gsi && (irq) < nr_irqs)

#define LEGACY_VECTOR(irq)          ((irq) + FIRST_LEGACY_VECTOR)
#define LEGACY_IRQ_FROM_VECTOR(vec) ((vec) - FIRST_LEGACY_VECTOR)

#define vector_to_irq(vec)  (vector_irq[vec])
#define irq_to_desc(irq)    &irq_desc[(irq)]

#define MAX_GSI_IRQS PAGE_SIZE * 8
#define MAX_NR_IRQS (2 * MAX_GSI_IRQS)

extern int vector_irq[NR_VECTORS];
extern u8 *irq_vector;

extern int irq_to_vector(int irq);
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

void disable_8259A_irq(unsigned int irq);
void enable_8259A_irq(unsigned int irq);
int i8259A_irq_pending(unsigned int irq);
void init_8259A(int aeoi);
int i8259A_suspend(void);
int i8259A_resume(void);

void setup_IO_APIC(void);
void disable_IO_APIC(void);
void print_IO_APIC(void);
void setup_ioapic_dest(void);

extern unsigned long io_apic_irqs;

extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

int pirq_shared(struct domain *d , int irq);

int map_domain_pirq(struct domain *d, int pirq, int irq, int type,
                           void *data);
int unmap_domain_pirq(struct domain *d, int pirq);
int get_free_pirq(struct domain *d, int type, int index);
void free_domain_pirqs(struct domain *d);

int  init_irq_data(void);

void clear_irq_vector(int irq);
int __assign_irq_vector(int irq);

int create_irq(void);
void destroy_irq(unsigned int irq);

#define domain_pirq_to_irq(d, pirq) ((d)->arch.pirq_irq[pirq])
#define domain_irq_to_pirq(d, irq) ((d)->arch.irq_pirq[irq])

#endif /* _ASM_HW_IRQ_H */
