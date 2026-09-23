/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/acpi.h>
#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/dt-overlay.h>
#include <xen/errno.h>
#include <xen/fdt-kernel.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/xvmalloc.h>

#include <asm/aia.h>
#include <asm/intc.h>
#include <asm/vaplic.h>

static const struct intc_hw_operations *__ro_after_init intc_hw_ops;

static const struct intc_hw_init_ops *__initdata intc_hw_init_ops;

void __init register_intc_ops(const struct intc_hw_init_ops *init_ops)
{
    intc_hw_ops = init_ops->ops;
    intc_hw_init_ops = init_ops;
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
    ASSERT(intc_hw_init_ops && intc_hw_init_ops->init);

    aia_init();

    if ( intc_hw_init_ops->init() )
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

void intc_handle_external_irqs(struct cpu_user_regs *regs)
{
    intc_hw_ops->handle_interrupt(regs);
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

int intc_route_irq_to_guest(struct irq_desc *desc,
                            unsigned int priority)
{
    ASSERT(spin_is_locked(&desc->lock));

    ASSERT(intc_hw_ops->guest_irq_type);

    desc->handler = intc_hw_ops->guest_irq_type;
    desc->status |= IRQ_GUEST;

    intc_set_irq_type(desc, desc->arch.type);
    intc_set_irq_priority(desc, priority);

    return 0;
}

int __init make_intc_domU_node(struct kernel_info *kinfo)
{
    const struct vintc *vintc = kinfo->bd.d->arch.vintc;

    return vintc->init_ops->make_domu_dt_node(kinfo);
}

int domain_vintc_init(struct domain *d)
{
    int ret = -EOPNOTSUPP;
    const enum intc_variant variant = intc_hw_ops->info->hw_variant;

    switch ( variant )
    {
    case INTC_APLIC:
        ret = domain_vaplic_init(d);
        break;

    default:
        printk_once("vintc (variant:%d) isn't implemented\n", variant);
        break;
    }

    if ( !ret )
    {
        d->arch.vintc->used_irqs =
            xvzalloc_array(unsigned long,
                           BITS_TO_LONGS(d->arch.vintc->nr_virqs));
        if ( !d->arch.vintc->used_irqs )
            ret = -ENOMEM;
    }

    return ret;
}

void domain_vintc_deinit(struct domain *d)
{
    const enum intc_variant variant = intc_hw_ops->info->hw_variant;

    if ( !d->arch.vintc )
        return;

    if ( d->arch.vintc->used_irqs )
    {
        unsigned int virq;

        for ( virq = 0; virq < d->arch.vintc->nr_virqs; virq++ )
            if ( test_bit(virq, d->arch.vintc->used_irqs) )
                release_guest_irq(d, virq);

        XVFREE(d->arch.vintc->used_irqs);
    }

    switch ( variant )
    {
    case INTC_APLIC:
        domain_vaplic_deinit(d);
        break;

    default:
        break;
    }
}

/*
 * Mark @virq as used by @d so that domain_vintc_deinit() knows that it has to
 * be released.
 *
 * Returns 0 on success, -EEXIST if @virq has already been reserved, which
 * legitimately happens when an IRQ is shared between devices, and -ERANGE if
 * @virq is outside the range of the interrupt sources the vINTC provides.
 */
int __overlay_init vintc_reserve_virq(const struct domain *d,
                                      unsigned int virq)
{
    if ( virq >= d->arch.vintc->nr_virqs )
        return -ERANGE;

    return test_and_set_bit(virq, d->arch.vintc->used_irqs) ? -EEXIST : 0;
}
