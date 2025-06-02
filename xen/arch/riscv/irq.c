/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RISC-V Interrupt support
 *
 * Copyright (c) Vates
 */

#include <xen/bug.h>
#include <xen/init.h>
#include <xen/irq.h>

static irq_desc_t irq_desc[NR_IRQS];

int arch_init_one_irq_desc(struct irq_desc *desc)
{
    desc->arch.type = IRQ_TYPE_INVALID;

    return 0;
}

static int __init init_irq_data(void)
{
    unsigned int irq;

    for ( irq = 0; irq < NR_IRQS; irq++ )
    {
        struct irq_desc *desc = irq_to_desc(irq);
        int rc;

        desc->irq = irq;

        rc = init_one_irq_desc(desc);
        if ( rc )
            return rc;
    }

    return 0;
}

void __init init_IRQ(void)
{
    if ( init_irq_data() < 0 )
        panic("initialization of IRQ data failed\n");
}
