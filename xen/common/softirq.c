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
    if ( !test_and_set_bit(nr, &softirq_pending(cpu)) )
        smp_send_event_check_cpu(cpu);
}

void raise_softirq(unsigned int nr)
{
    set_bit(nr, &softirq_pending(smp_processor_id()));
}

static LIST_HEAD(tasklet_list);
static DEFINE_SPINLOCK(tasklet_lock);

void tasklet_schedule(struct tasklet *t)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( !t->is_dead )
    {
        if ( !t->is_scheduled && !t->is_running )
        {
            BUG_ON(!list_empty(&t->list));
            list_add_tail(&t->list, &tasklet_list);
        }
        t->is_scheduled = 1;
        raise_softirq(TASKLET_SOFTIRQ);
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

static void tasklet_action(void)
{
    struct tasklet *t;

    spin_lock_irq(&tasklet_lock);

    if ( list_empty(&tasklet_list) )
    {
        spin_unlock_irq(&tasklet_lock);
        return;
    }

    t = list_entry(tasklet_list.next, struct tasklet, list);
    list_del_init(&t->list);

    BUG_ON(t->is_dead || t->is_running || !t->is_scheduled);
    t->is_scheduled = 0;
    t->is_running = 1;

    spin_unlock_irq(&tasklet_lock);
    t->func(t->data);
    spin_lock_irq(&tasklet_lock);

    t->is_running = 0;

    if ( t->is_scheduled )
    {
        BUG_ON(t->is_dead || !list_empty(&t->list));
        list_add_tail(&t->list, &tasklet_list);
    }

    /*
     * If there is more work to do then reschedule. We don't grab more work
     * immediately as we want to allow other softirq work to happen first.
     */
    if ( !list_empty(&tasklet_list) )
        raise_softirq(TASKLET_SOFTIRQ);

    spin_unlock_irq(&tasklet_lock);
}

void tasklet_kill(struct tasklet *t)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( !list_empty(&t->list) )
    {
        BUG_ON(t->is_dead || t->is_running || !t->is_scheduled);
        list_del_init(&t->list);
    }
    t->is_scheduled = 0;
    t->is_dead = 1;

    while ( t->is_running )
    {
        spin_unlock_irqrestore(&tasklet_lock, flags);
        cpu_relax();
        spin_lock_irqsave(&tasklet_lock, flags);
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    memset(t, 0, sizeof(*t));
    INIT_LIST_HEAD(&t->list);
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
