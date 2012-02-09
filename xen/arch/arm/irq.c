/*
 * xen/arch/arm/irq.c
 *
 * ARM Interrupt support
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/spinlock.h>
#include <xen/irq.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/sched.h>

#include "gic.h"

static void enable_none(struct irq_desc *irq) { }
static unsigned int startup_none(struct irq_desc *irq) { return 0; }
static void disable_none(struct irq_desc *irq) { }
static void ack_none(struct irq_desc *irq)
{
    printk("unexpected IRQ trap at irq %02x\n", irq->irq);
}

#define shutdown_none   disable_none
#define end_none        enable_none

hw_irq_controller no_irq_type = {
    .typename = "none",
    .startup = startup_none,
    .shutdown = shutdown_none,
    .enable = enable_none,
    .disable = disable_none,
    .ack = ack_none,
    .end = end_none
};

int __init arch_init_one_irq_desc(struct irq_desc *desc)
{
    return 0;
}


static int __init init_irq_data(void)
{
    int irq;

    for (irq = 0; irq < NR_IRQS; irq++) {
        struct irq_desc *desc = irq_to_desc(irq);
        init_one_irq_desc(desc);
        desc->irq = irq;
        desc->action  = NULL;
    }
    return 0;
}

void __init init_IRQ(void)
{
    BUG_ON(init_irq_data() < 0);
}

int __init request_irq(unsigned int irq,
        void (*handler)(int, void *, struct cpu_user_regs *),
        unsigned long irqflags, const char * devname, void *dev_id)
{
    struct irqaction *action;
    int retval;

    /*
     * Sanity-check: shared interrupts must pass in a real dev-ID,
     * otherwise we'll have trouble later trying to figure out
     * which interrupt is which (messes up the interrupt freeing
     * logic etc).
     */
    if (irq >= nr_irqs)
        return -EINVAL;
    if (!handler)
        return -EINVAL;

    action = xmalloc(struct irqaction);
    if (!action)
        return -ENOMEM;

    action->handler = handler;
    action->name = devname;
    action->dev_id = dev_id;
    action->free_on_release = 1;

    retval = setup_irq(irq, action);
    if (retval)
        xfree(action);

    return retval;
}

/* Dispatch an interrupt */
void do_IRQ(struct cpu_user_regs *regs, unsigned int irq, int is_fiq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action = desc->action;

    /* TODO: perfc_incr(irqs); */

    /* TODO: this_cpu(irq_count)++; */

    irq_enter();

    spin_lock(&desc->lock);
    desc->handler->ack(desc);

    if ( action == NULL )
    {
        printk("Unknown %s %#3.3x\n",
               is_fiq ? "FIQ" : "IRQ", irq);
        goto out;
    }

    if ( desc->status & IRQ_GUEST )
    {
        struct domain *d = action->dev_id;

        desc->handler->end(desc);

        desc->status |= IRQ_INPROGRESS;

        /* XXX: inject irq into the guest */
        goto out_no_end;
    }

    desc->status |= IRQ_PENDING;

    /*
     * Since we set PENDING, if another processor is handling a different
     * instance of this same irq, the other processor will take care of it.
     */
    if ( desc->status & (IRQ_DISABLED | IRQ_INPROGRESS) )
        goto out;

    desc->status |= IRQ_INPROGRESS;

    action = desc->action;
    while ( desc->status & IRQ_PENDING )
    {
        desc->status &= ~IRQ_PENDING;
        spin_unlock_irq(&desc->lock);
        action->handler(irq, action->dev_id, regs);
        spin_lock_irq(&desc->lock);
    }

    desc->status &= ~IRQ_INPROGRESS;

out:
    desc->handler->end(desc);
out_no_end:
    spin_unlock(&desc->lock);
    irq_exit();
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
