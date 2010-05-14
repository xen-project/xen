/******************************************************************************
 * tasklet.c
 * 
 * Tasklets are dynamically-allocatable tasks run in VCPU context
 * (specifically, the idle VCPU's context) on at most one CPU at a time.
 * 
 * Copyright (c) 2010, Citrix Systems, Inc.
 * Copyright (c) 1992, Linus Torvalds
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/cpu.h>

/* Some subsystems call into us before we are initialised. We ignore them. */
static cpumask_t tasklets_initialised;

DEFINE_PER_CPU(unsigned long, tasklet_work_to_do);

static DEFINE_PER_CPU(struct list_head, tasklet_list);

/* Protects all lists and tasklet structures. */
static DEFINE_SPINLOCK(tasklet_lock);

static void tasklet_enqueue(struct tasklet *t)
{
    unsigned int cpu = t->scheduled_on;
    unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);

    list_add_tail(&t->list, &per_cpu(tasklet_list, cpu));
    if ( !test_and_set_bit(_TASKLET_enqueued, work_to_do) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
}

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( cpu_isset(cpu, tasklets_initialised) && !t->is_dead )
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

void do_tasklet(void)
{
    unsigned int cpu = smp_processor_id();
    unsigned long *work_to_do = &per_cpu(tasklet_work_to_do, cpu);
    struct list_head *list = &per_cpu(tasklet_list, cpu);
    struct tasklet *t;

    /*
     * Work must be enqueued *and* scheduled. Otherwise there is no work to
     * do, and/or scheduler needs to run to update idle vcpu priority.
     */
    if ( likely(*work_to_do != (TASKLET_enqueued|TASKLET_scheduled)) )
        return;

    spin_lock_irq(&tasklet_lock);

    if ( unlikely(list_empty(list)) )
        goto out;

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

 out:
    if ( list_empty(list) )
    {
        clear_bit(_TASKLET_enqueued, work_to_do);        
        raise_softirq(SCHEDULE_SOFTIRQ);
    }

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

static void migrate_tasklets_from_cpu(unsigned int cpu)
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

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        if ( !cpu_test_and_set(cpu, tasklets_initialised) )
            INIT_LIST_HEAD(&per_cpu(tasklet_list, cpu));
        break;
    case CPU_DEAD:
        migrate_tasklets_from_cpu(cpu);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

void __init tasklet_subsys_init(void)
{
    void *hcpu = (void *)(long)smp_processor_id();
    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, hcpu);
    register_cpu_notifier(&cpu_nfb);
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
