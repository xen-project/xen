#include <xen/irq.h>
#include <xen/errno.h>

DEFINE_PER_CPU(struct cpu_user_regs *, irq_regs);

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

void cf_check no_action(int cpl, void *dev_id)
{
}

void cf_check irq_actor_none(struct irq_desc *desc)
{
}

unsigned int cf_check irq_startup_none(struct irq_desc *desc)
{
    return 0;
}
