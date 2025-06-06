#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

#include <xen/device_tree.h>
#include <public/device_tree_defs.h>

#include <asm/irq-dt.h>

#define NR_VECTORS 256 /* XXX */

typedef struct {
    DECLARE_BITMAP(_bits,NR_VECTORS);
} vmask_t;

struct arch_pirq
{
};

struct arch_irq_desc {
    unsigned int type;
};

#define NR_LOCAL_IRQS	32

/*
 * This only covers the interrupts that Xen cares about, so SGIs, PPIs and
 * SPIs. LPIs are too numerous, also only propagated to guests, so they are
 * not included in this number.
 */
#define NR_IRQS		1024

#define LPI_OFFSET      8192

/* LPIs are always numbered starting at 8192, so 0 is a good invalid case. */
#define INVALID_LPI     0

/* This is a spurious interrupt ID which never makes it into the GIC code. */
#define INVALID_IRQ     1023

extern const unsigned int nr_irqs;
#define nr_static_irqs NR_IRQS

struct irq_desc;
struct irqaction;

struct irq_desc *__irq_to_desc(unsigned int irq);

#define irq_to_desc(irq)    __irq_to_desc(irq)

void do_IRQ(struct cpu_user_regs *regs, unsigned int irq, int is_fiq);

static inline bool is_lpi(unsigned int irq)
{
    return irq >= LPI_OFFSET;
}

#define domain_pirq_to_irq(d, pirq) (pirq)

bool is_assignable_irq(unsigned int irq);

void init_IRQ(void);

int route_irq_to_guest(struct domain *d, unsigned int virq,
                       unsigned int irq, const char *devname);
int release_guest_irq(struct domain *d, unsigned int virq);

void arch_move_irqs(struct vcpu *v);

#define arch_evtchn_bind_pirq(d, pirq) ((void)((d) + (pirq)))

/* Set IRQ type for an SPI */
int irq_set_spi_type(unsigned int spi, unsigned int type);

int irq_set_type(unsigned int irq, unsigned int type);

int platform_get_irq(const struct dt_device_node *device, int index);

int platform_get_irq_byname(const struct dt_device_node *np, const char *name);

void irq_set_affinity(struct irq_desc *desc, const cpumask_t *mask);

/*
 * Use this helper in places that need to know whether the IRQ type is
 * set by the domain.
 */
bool irq_type_set_by_domain(const struct domain *d);

void irq_end_none(struct irq_desc *irq);
#define irq_end_none irq_end_none

#endif /* _ASM_HW_IRQ_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
