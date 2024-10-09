/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__IRQ_H
#define ASM__RISCV__IRQ_H

#include <xen/bug.h>

/* TODO */
#define nr_irqs 0U
#define nr_static_irqs 0
#define arch_hwdom_irqs(domid) 0U

#define domain_pirq_to_irq(d, pirq) (pirq)

#define arch_evtchn_bind_pirq(d, pirq) ((void)((d) + (pirq)))

struct arch_pirq {
};

struct arch_irq_desc {
    unsigned int type;
};

static inline void arch_move_irqs(struct vcpu *v)
{
    BUG_ON("unimplemented");
}

#endif /* ASM__RISCV__IRQ_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
