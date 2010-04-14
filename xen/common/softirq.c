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

static void __do_softirq(unsigned long ignore_mask)
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

        if ( (pending = (softirq_pending(cpu) & ~ignore_mask)) == 0 )
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &softirq_pending(cpu));
        (*softirq_handlers[i])();
    }
}

void process_pending_softirqs(void)
{
    ASSERT(!in_irq() && local_irq_is_enabled());
    /* Do not enter scheduler as it can preempt the calling context. */
    __do_softirq(1ul<<SCHEDULE_SOFTIRQ);
}

asmlinkage void do_softirq(void)
{
    __do_softirq(0);
}

void open_softirq(int nr, softirq_handler handler)
{
    ASSERT(nr < NR_SOFTIRQS);
    softirq_handlers[nr] = handler;
}

void cpumask_raise_softirq(cpumask_t mask, unsigned int nr)
{
    int cpu;

    for_each_cpu_mask(cpu, mask)
        if ( test_and_set_bit(nr, &softirq_pending(cpu)) )
            cpu_clear(cpu, mask);

    smp_send_event_check_mask(&mask);
}

void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    if ( !test_and_set_bit(nr, &softirq_pending(cpu))
         && (cpu != smp_processor_id()) )
        smp_send_event_check_cpu(cpu);
}

void raise_softirq(unsigned int nr)
{
    set_bit(nr, &softirq_pending(smp_processor_id()));
}

static bool_t tasklets_initialised;
static DEFINE_PER_CPU(struct list_head, tasklet_list);
static DEFINE_SPINLOCK(tasklet_lock);

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( tasklets_initialised && !t->is_dead )
    {
        t->scheduled_on = cpu;
        if ( !t->is_running )
        {
            list_del(&t->list);
            list_add_tail(&t->list, &per_cpu(tasklet_list, cpu));
            cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
        }
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_schedule(struct tasklet *t)
{
    tasklet_schedule_on_cpu(t, smp_processor_id());
}

static void tasklet_action(void)
{
    unsigned int cpu = smp_processor_id();
    struct list_head *list = &per_cpu(tasklet_list, cpu);
    struct tasklet *t;

    spin_lock_irq(&tasklet_lock);

    if ( list_empty(list) )
    {
        spin_unlock_irq(&tasklet_lock);
        return;
    }

    t = list_entry(list->next, struct tasklet, list);
    list_del_init(&t->list);

    BUG_ON(t->is_dead || t->is_running || (t->scheduled_on != cpu));
    t->scheduled_on = -1;
    t->is_running = 1;

    spin_unlock_irq(&tasklet_lock);
    t->func(t->data);
    spin_lock_irq(&tasklet_lock);

    t->is_running = 0;

    if ( t->scheduled_on >= 0 )
    {
        BUG_ON(t->is_dead || !list_empty(&t->list));
        list_add_tail(&t->list, &per_cpu(tasklet_list, t->scheduled_on));
        if ( t->scheduled_on != cpu )
            cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
    }

    /*
     * If there is more work to do then reschedule. We don't grab more work
     * immediately as we want to allow other softirq work to happen first.
     */
    if ( !list_empty(list) )
        raise_softirq(TASKLET_SOFTIRQ);

    spin_unlock_irq(&tasklet_lock);
}

void tasklet_kill(struct tasklet *t)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( !list_empty(&t->list) )
    {
        BUG_ON(t->is_dead || t->is_running || (t->scheduled_on < 0));
        list_del_init(&t->list);
    }
    t->scheduled_on = -1;
    t->is_dead = 1;

    while ( t->is_running )
    {
        spin_unlock_irqrestore(&tasklet_lock, flags);
        cpu_relax();
        spin_lock_irqsave(&tasklet_lock, flags);
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void migrate_tasklets_from_cpu(unsigned int cpu)
{
    struct list_head *list = &per_cpu(tasklet_list, cpu);
    unsigned long flags;
    struct tasklet *t;

    spin_lock_irqsave(&tasklet_lock, flags);

    while ( !list_empty(list) )
    {
        t = list_entry(list->next, struct tasklet, list);
        BUG_ON(t->scheduled_on != cpu);
        t->scheduled_on = smp_processor_id();
        list_del(&t->list);
        list_add_tail(&t->list, &this_cpu(tasklet_list));
    }

    raise_softirq(TASKLET_SOFTIRQ);

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    memset(t, 0, sizeof(*t));
    INIT_LIST_HEAD(&t->list);
    t->scheduled_on = -1;
    t->func = func;
    t->data = data;
}

void __init softirq_init(void)
{
    unsigned int cpu;

    for_each_possible_cpu ( cpu )
        INIT_LIST_HEAD(&per_cpu(tasklet_list, cpu));

    open_softirq(TASKLET_SOFTIRQ, tasklet_action);

    tasklets_initialised = 1;
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
