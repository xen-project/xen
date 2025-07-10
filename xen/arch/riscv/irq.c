/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RISC-V Interrupt support
 *
 * Copyright (c) Vates
 */

#include <xen/bug.h>
#include <xen/cpumask.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/spinlock.h>

#include <asm/hardirq.h>
#include <asm/intc.h>

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

static int _setup_irq(struct irq_desc *desc, unsigned int irqflags,
                      struct irqaction *new)
{
    bool shared = irqflags & IRQF_SHARED;

    ASSERT(new != NULL);

    /*
     * Sanity checks:
     *  - if the IRQ is marked as shared
     *  - dev_id is not NULL when IRQF_SHARED is set
     */
    if ( desc->action != NULL && (!(desc->status & IRQF_SHARED) || !shared) )
        return -EINVAL;
    if ( shared && new->dev_id == NULL )
        return -EINVAL;

    if ( shared )
        desc->status |= IRQF_SHARED;

#ifdef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    new->next = desc->action;
#endif

    desc->action = new;
    smp_wmb();

    return 0;
}

int setup_irq(unsigned int irq, unsigned int irqflags, struct irqaction *new)
{
    int rc;
    unsigned long flags;
    struct irq_desc *desc = irq_to_desc(irq);
    bool disabled;

    spin_lock_irqsave(&desc->lock, flags);

    disabled = (desc->action == NULL);

    if ( desc->status & IRQ_GUEST )
    {
        spin_unlock_irqrestore(&desc->lock, flags);
        /*
         * TODO: would be nice to have functionality to print which domain owns
         *       an IRQ.
         */
        printk(XENLOG_ERR "ERROR: IRQ %u is already in use by a domain\n", irq);
        return -EBUSY;
    }

    rc = _setup_irq(desc, irqflags, new);
    if ( rc )
        goto err;

    /* First time the IRQ is setup */
    if ( disabled )
    {
        /* Route interrupt to xen */
        intc_route_irq_to_xen(desc, IRQ_NO_PRIORITY);

        /*
         * We don't care for now which CPU will receive the
         * interrupt.
         *
         * TODO: Handle case where IRQ is setup on different CPU than
         *       the targeted CPU and the priority.
         */
        desc->handler->set_affinity(desc, cpumask_of(smp_processor_id()));

        desc->handler->startup(desc);

        /* Enable irq */
        desc->status &= ~IRQ_DISABLED;
    }

 err:
    spin_unlock_irqrestore(&desc->lock, flags);

    return rc;
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

/* Dispatch an interrupt */
void do_IRQ(struct cpu_user_regs *regs, unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action;

    irq_enter();

    spin_lock(&desc->lock);

    if ( desc->handler->ack )
        desc->handler->ack(desc);

    if ( desc->status & IRQ_DISABLED )
        goto out;

    desc->status |= IRQ_INPROGRESS;

    action = desc->action;

    spin_unlock_irq(&desc->lock);

#ifndef CONFIG_IRQ_HAS_MULTIPLE_ACTION
    action->handler(irq, action->dev_id);
#else
    do {
        action->handler(irq, action->dev_id);
        action = action->next;
    } while ( action );
#endif /* CONFIG_IRQ_HAS_MULTIPLE_ACTION */

    spin_lock_irq(&desc->lock);

    desc->status &= ~IRQ_INPROGRESS;

 out:
    if ( desc->handler->end )
        desc->handler->end(desc);

    spin_unlock(&desc->lock);
    irq_exit();
}
