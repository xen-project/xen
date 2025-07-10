/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/acpi.h>
#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/spinlock.h>

#include <asm/intc.h>

static const struct intc_hw_operations *__ro_after_init intc_hw_ops;

void __init register_intc_ops(const struct intc_hw_operations *ops)
{
    intc_hw_ops = ops;
}

void __init intc_preinit(void)
{
    if ( acpi_disabled )
        intc_dt_preinit();
    else
        panic("ACPI interrupt controller preinit() isn't implemented\n");
}

void __init intc_init(void)
{
    if ( intc_hw_ops->init() )
        panic("Failed to initialize the interrupt controller drivers\n");
}

/* desc->irq needs to be disabled before calling this function */
static void intc_set_irq_type(struct irq_desc *desc, unsigned int type)
{
    ASSERT(desc->status & IRQ_DISABLED);
    ASSERT(spin_is_locked(&desc->lock));
    ASSERT(type != IRQ_TYPE_INVALID);

    if ( intc_hw_ops->set_irq_type )
        intc_hw_ops->set_irq_type(desc, type);
}

static void intc_set_irq_priority(struct irq_desc *desc, unsigned int priority)
{
    ASSERT(spin_is_locked(&desc->lock));

    if ( intc_hw_ops->set_irq_priority )
        intc_hw_ops->set_irq_priority(desc, priority);
}

void intc_route_irq_to_xen(struct irq_desc *desc, unsigned int priority)
{
    ASSERT(desc->status & IRQ_DISABLED);
    ASSERT(spin_is_locked(&desc->lock));
    /* Can't route interrupts that don't exist */
    ASSERT(intc_hw_ops && desc->irq < intc_hw_ops->info->num_irqs);

    desc->handler = intc_hw_ops->host_irq_type;

    intc_set_irq_type(desc, desc->arch.type);
    intc_set_irq_priority(desc, priority);
}
