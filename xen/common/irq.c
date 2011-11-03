#include <xen/config.h>
#include <xen/irq.h>

int init_one_irq_desc(struct irq_desc *desc)
{
    int err;

    if (irq_desc_initialized(desc))
        return 0;

    if ( !alloc_cpumask_var(&desc->affinity) )
        return -ENOMEM;

    desc->status = IRQ_DISABLED;
    desc->handler = &no_irq_type;
    spin_lock_init(&desc->lock);
    cpumask_setall(desc->affinity);
    INIT_LIST_HEAD(&desc->rl_link);

    err = arch_init_one_irq_desc(desc);
    if ( err )
    {
        free_cpumask_var(desc->affinity);
        desc->handler = NULL;
    }

    return err;
}
