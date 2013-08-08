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

struct irq_cfg {
#define arch_irq_desc irq_cfg
    int eoi_cpu;
};

#define NR_LOCAL_IRQS	32
#define NR_IRQS		1024
#define nr_irqs NR_IRQS

#define nr_irqs NR_IRQS
#define nr_static_irqs NR_IRQS

struct irq_desc;
struct irqaction;

struct irq_desc *__irq_to_desc(int irq);

#define irq_to_desc(irq)    __irq_to_desc(irq)

void do_IRQ(struct cpu_user_regs *regs, unsigned int irq, int is_fiq);

#define domain_pirq_to_irq(d, pirq) (pirq)

void init_IRQ(void);
void init_secondary_IRQ(void);

int __init request_dt_irq(const struct dt_irq *irq,
                          void (*handler)(int, void *, struct cpu_user_regs *),
                          const char *devname, void *dev_id);
int __init setup_dt_irq(const struct dt_irq *irq, struct irqaction *new);

#endif /* _ASM_HW_IRQ_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
