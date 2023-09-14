/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_IRQ_H__
#define __ASM_PPC_IRQ_H__

#include <xen/lib.h>
#include <xen/device_tree.h>
#include <public/device_tree_defs.h>

/* TODO */
#define nr_irqs 0U
#define nr_static_irqs 0
#define arch_hwdom_irqs(domid) 0U

#define domain_pirq_to_irq(d, pirq) (pirq)

struct arch_pirq {
};

struct arch_irq_desc {
    unsigned int type;
};

static inline void arch_move_irqs(struct vcpu *v)
{
    BUG_ON("unimplemented");
}

static inline int platform_get_irq(const struct dt_device_node *device, int index)
{
    BUG_ON("unimplemented");
}

#endif /* __ASM_PPC_IRQ_H__ */
