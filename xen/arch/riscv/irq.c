/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RISC-V Interrupt support
 *
 * Copyright (c) Vates
 */

#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>

static irq_desc_t irq_desc[NR_IRQS];

static bool irq_validate_new_type(unsigned int curr, unsigned int new)
{
    return curr == IRQ_TYPE_INVALID || curr == new;
}

static int irq_set_type(unsigned int irq, unsigned int type)
{
    unsigned long flags;
    struct irq_desc *desc = irq_to_desc(irq);
    int ret = -EBUSY;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !irq_validate_new_type(desc->arch.type, type) )
        goto err;

    desc->arch.type = type;

    ret = 0;

 err:
    spin_unlock_irqrestore(&desc->lock, flags);

    return ret;
}

int platform_get_irq(const struct dt_device_node *device, int index)
{
    struct dt_irq dt_irq;
    int ret;

    if ( (ret = dt_device_get_irq(device, index, &dt_irq)) != 0 )
        return ret;

    BUILD_BUG_ON(NR_IRQS > INT_MAX);

    if ( dt_irq.irq >= NR_IRQS )
        panic("irq%d is bigger then NR_IRQS(%d)\n", dt_irq.irq, NR_IRQS);

    if ( (ret = irq_set_type(dt_irq.irq, dt_irq.type)) != 0 )
        return ret;

    return dt_irq.irq;
}

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
