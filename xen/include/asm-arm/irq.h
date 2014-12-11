#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

#include <xen/config.h>
#include <xen/device_tree.h>

#define NR_VECTORS 256 /* XXX */

typedef struct {
    DECLARE_BITMAP(_bits,NR_VECTORS);
} vmask_t;

struct arch_pirq
{
};

struct arch_irq_desc {
    int eoi_cpu;
    unsigned int type;
};

#define NR_LOCAL_IRQS	32
#define NR_IRQS		1024

#define nr_irqs NR_IRQS
#define nr_static_irqs NR_IRQS
#define arch_hwdom_irqs(domid) NR_IRQS

struct irq_desc;
struct irqaction;

struct irq_desc *__irq_to_desc(int irq);

#define irq_to_desc(irq)    __irq_to_desc(irq)

void do_IRQ(struct cpu_user_regs *regs, unsigned int irq, int is_fiq);

#define domain_pirq_to_irq(d, pirq) (pirq)

void init_IRQ(void);
void init_secondary_IRQ(void);

int route_irq_to_guest(struct domain *d, unsigned int irq,
                       const char *devname);
void arch_move_irqs(struct vcpu *v);

/* Set IRQ type for an SPI */
int irq_set_spi_type(unsigned int spi, unsigned int type);

int platform_get_irq(const struct dt_device_node *device, int index);

void irq_set_affinity(struct irq_desc *desc, const cpumask_t *cpu_mask);

#endif /* _ASM_HW_IRQ_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
