/******************************************************************************
 * common/softirq.c
 * 
 * Softirqs in Xen are only executed in an outermost activation (e.g., never 
 * within an interrupt activation). This simplifies some things and generally 
 * seems a good thing.
 * 
 * Copyright (c) 2003, K A Fraser
 * Copyright (c) 1992, Linus Torvalds
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/rcupdate.h>
#include <xen/softirq.h>

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS];
#endif

static softirq_handler softirq_handlers[NR_SOFTIRQS];

asmlinkage void do_softirq(void)
{
    unsigned int i, cpu;
    unsigned long pending;

    for ( ; ; )
    {
        /*
         * Initialise @cpu on every iteration: SCHEDULE_SOFTIRQ may move
         * us to another processor.
         */
        cpu = smp_processor_id();

        if ( rcu_pending(cpu) )
            rcu_check_callbacks(cpu);

        if ( (pending = softirq_pending(cpu)) == 0 )
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &softirq_pending(cpu));
        (*softirq_handlers[i])();
    }
}

void open_softirq(int nr, softirq_handler handler)
{
    softirq_handlers[nr] = handler;
}

static DEFINE_PER_CPU(struct tasklet *, tasklet_list);

void tasklet_schedule(struct tasklet *t)
{
    unsigned long flags;

    if ( test_and_set_bool(t->is_scheduled) )
        return;

    local_irq_save(flags);
    t->next = this_cpu(tasklet_list);
    this_cpu(tasklet_list) = t;
    local_irq_restore(flags);

    raise_softirq(TASKLET_SOFTIRQ);
}

static void tasklet_action(void)
{
    struct tasklet *list, *t;

    local_irq_disable();
    list = this_cpu(tasklet_list);
    this_cpu(tasklet_list) = NULL;
    local_irq_enable();

    while ( (t = list) != NULL )
    {
        list = list->next;

        BUG_ON(t->is_running);
        t->is_running = 1;
        smp_wmb();

        BUG_ON(!t->is_scheduled);
        t->is_scheduled = 0;

        smp_mb();
        t->func(t->data);
        smp_mb();

        t->is_running = 0;
    }
}

void tasklet_kill(struct tasklet *t)
{
    /* Prevent tasklet from re-scheduling itself. */
    while ( t->is_scheduled || test_and_set_bool(t->is_scheduled) )
        cpu_relax();
    smp_mb();

    /* Wait for tasklet to complete. */
    while ( t->is_running )
        cpu_relax();
    smp_mb();

    /* Clean up and we're done. */
    t->is_scheduled = 0;
}

void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    memset(t, 0, sizeof(*t));
    t->func = func;
    t->data = data;
}

void __init softirq_init(void)
{
    open_softirq(TASKLET_SOFTIRQ, tasklet_action);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
