#include <xen/config.h>
#include <xen/irq.h>
#include <xen/errno.h>

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

void no_action(int cpl, void *dev_id, struct cpu_user_regs *regs)
{
}

void irq_actor_none(struct irq_desc *desc)
{
}

unsigned int irq_startup_none(struct irq_desc *desc)
{
    return 0;
}
