/******************************************************************************
 * tasklet.c
 * 
 * Tasklets are dynamically-allocatable tasks run in either VCPU context
 * (specifically, the idle VCPU's context) or in softirq context, on at most
 * one CPU at a time. Softirq versus VCPU context execution is specified
 * during per-tasklet initialisation.
 * 
 * Copyright (c) 2010, Citrix Systems, Inc.
 * Copyright (c) 1992, Linus Torvalds
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/cpu.h>

/* Some subsystems call into us before we are initialised. We ignore them. */
static bool_t tasklets_initialised;

DEFINE_PER_CPU(unsigned long, tasklet_work_to_do);

static DEFINE_PER_CPU(struct list_head, tasklet_list);
static DEFINE_PER_CPU(struct list_head, softirq_tasklet_list);

/* Protects all lists and tasklet structures. */
static DEFINE_SPINLOCK(tasklet_lock);

static void tasklet_enqueue(struct tasklet *t)
{
    unsigned int cpu = t->scheduled_on;

    if ( t->is_softirq )
    {
        struct list_head *list = &per_cpu(softirq_tasklet_list, cpu);
        bool_t was_empty = list_empty(list);
        list_add_tail(&t->list, list);
        if ( was_empty )
            cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
    }
    else
    {
        unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);
        list_add_tail(&t->list, &per_cpu(tasklet_list, cpu));
        if ( !test_and_set_bit(_TASKLET_enqueued, work_to_do) )
            cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    }
}

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
            tasklet_enqueue(t);
        }
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_schedule(struct tasklet *t)
{
    tasklet_schedule_on_cpu(t, smp_processor_id());
}

static void do_tasklet_work(unsigned int cpu, struct list_head *list)
{
    struct tasklet *t;

    if ( unlikely(list_empty(list) || cpu_is_offline(cpu)) )
        return;

    t = list_entry(list->next, struct tasklet, list);
    list_del_init(&t->list);

    BUG_ON(t->is_dead || t->is_running || (t->scheduled_on != cpu));
    t->scheduled_on = -1;
    t->is_running = 1;

    spin_unlock_irq(&tasklet_lock);
    sync_local_execstate();
    t->func(t->data);
    spin_lock_irq(&tasklet_lock);

    t->is_running = 0;

    if ( t->scheduled_on >= 0 )
    {
        BUG_ON(t->is_dead || !list_empty(&t->list));
        tasklet_enqueue(t);
    }
}

/* VCPU context work */
void do_tasklet(void)
{
    unsigned int cpu = smp_processor_id();
    unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);
    struct list_head *list = &per_cpu(tasklet_list, cpu);

    /*
     * We want to be sure any caller has checked that a tasklet is both
     * enqueued and scheduled, before calling this. And, if the caller has
     * actually checked, it's not an issue that we are outside of the
     * critical region, in fact:
     * - TASKLET_enqueued is cleared only here,
     * - TASKLET_scheduled is only cleared when schedule() find it set,
     *   without TASKLET_enqueued being set as well.
     */
    ASSERT(tasklet_work_to_do(cpu));

    spin_lock_irq(&tasklet_lock);

    do_tasklet_work(cpu, list);

    if ( list_empty(list) )
    {
        clear_bit(_TASKLET_enqueued, work_to_do);        
        raise_softirq(SCHEDULE_SOFTIRQ);
    }

    spin_unlock_irq(&tasklet_lock);
}

/* Softirq context work */
static void tasklet_softirq_action(void)
{
    unsigned int cpu = smp_processor_id();
    struct list_head *list = &per_cpu(softirq_tasklet_list, cpu);

    spin_lock_irq(&tasklet_lock);

    do_tasklet_work(cpu, list);

    if ( !list_empty(list) && !cpu_is_offline(cpu) )
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

static void migrate_tasklets_from_cpu(unsigned int cpu, struct list_head *list)
{
    unsigned long flags;
    struct tasklet *t;

    spin_lock_irqsave(&tasklet_lock, flags);

    while ( !list_empty(list) )
    {
        t = list_entry(list->next, struct tasklet, list);
        BUG_ON(t->scheduled_on != cpu);
        t->scheduled_on = smp_processor_id();
        list_del(&t->list);
        tasklet_enqueue(t);
    }

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

void softirq_tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    tasklet_init(t, func, data);
    t->is_softirq = 1;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        INIT_LIST_HEAD(&per_cpu(tasklet_list, cpu));
        INIT_LIST_HEAD(&per_cpu(softirq_tasklet_list, cpu));
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        migrate_tasklets_from_cpu(cpu, &per_cpu(tasklet_list, cpu));
        migrate_tasklets_from_cpu(cpu, &per_cpu(softirq_tasklet_list, cpu));
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
    .priority = 99
};

void __init tasklet_subsys_init(void)
{
    void *hcpu = (void *)(long)smp_processor_id();
    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, hcpu);
    register_cpu_notifier(&cpu_nfb);
    open_softirq(TASKLET_SOFTIRQ, tasklet_softirq_action);
    tasklets_initialised = 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
