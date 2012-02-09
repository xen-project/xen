#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

#include <xen/config.h>

#define NR_VECTORS 256 /* XXX */

typedef struct {
    DECLARE_BITMAP(_bits,NR_VECTORS);
} vmask_t;

struct arch_pirq
{
};

struct irq_cfg {
#define arch_irq_desc irq_cfg
};

void do_IRQ(struct cpu_user_regs *regs, unsigned int irq, int is_fiq);

#define domain_pirq_to_irq(d, pirq) (pirq)

#endif /* _ASM_HW_IRQ_H */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
