/******************************************************************************
 * common/softirq.c
 * 
 * Modified from the Linux original. Softirqs in Xen are only executed in
 * an outermost activation (e.g., never within an interrupt activation).
 * This simplifies some things and generally seems a good thing.
 * 
 * Copyright (c) 2003, K A Fraser
 * 
 * Copyright (C) 1992 Linus Torvalds
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/interrupt.h>
#include <xen/init.h>
#include <xen/tqueue.h>

irq_cpustat_t irq_stat[NR_CPUS];

static struct softirq_action softirq_vec[32] __cacheline_aligned;

asmlinkage void do_softirq()
{
    unsigned int pending, cpu = smp_processor_id();
    struct softirq_action *h;

    if ( unlikely(in_interrupt()) )
        BUG();

    /*
     * XEN: This isn't real mutual-exclusion: it just ensures that in_softirq()
     * and in_interrupt() are both TRUE, allowing checks for erroneous reentry.
     */
    cpu_bh_disable(cpu);

    while ( (pending = xchg(&softirq_pending(cpu), 0)) != 0 )
    {
        h = softirq_vec;
        while ( pending )
        {
            if ( pending & 1 )
                h->action(h);
            h++;
            pending >>= 1;
        }
    }

    cpu_bh_enable(cpu);
}

inline void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    __cpu_raise_softirq(cpu, nr);
#ifdef CONFIG_SMP
    if ( cpu != smp_processor_id() )
        smp_send_event_check_cpu(cpu);
#endif
}

void raise_softirq(unsigned int nr)
{
    cpu_raise_softirq(smp_processor_id(), nr);
}

void open_softirq(int nr, void (*action)(struct softirq_action*), void *data)
{
    softirq_vec[nr].data = data;
    softirq_vec[nr].action = action;
}


/* Tasklets */

struct tasklet_head tasklet_vec[NR_CPUS] __cacheline_aligned;
struct tasklet_head tasklet_hi_vec[NR_CPUS] __cacheline_aligned;

void __tasklet_schedule(struct tasklet_struct *t)
{
    int cpu = smp_processor_id();
    unsigned long flags;

    local_irq_save(flags);
    t->next = tasklet_vec[cpu].list;
    tasklet_vec[cpu].list = t;
    cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
    local_irq_restore(flags);
}

void __tasklet_hi_schedule(struct tasklet_struct *t)
{
    int cpu = smp_processor_id();
    unsigned long flags;

    local_irq_save(flags);
    t->next = tasklet_hi_vec[cpu].list;
    tasklet_hi_vec[cpu].list = t;
    cpu_raise_softirq(cpu, HI_SOFTIRQ);
    local_irq_restore(flags);
}

static void tasklet_action(struct softirq_action *a)
{
    int cpu = smp_processor_id();
    struct tasklet_struct *list;

    local_irq_disable();
    list = tasklet_vec[cpu].list;
    tasklet_vec[cpu].list = NULL;
    local_irq_enable();

    while ( list != NULL )
    {
        struct tasklet_struct *t = list;

        list = list->next;

        if ( likely(tasklet_trylock(t)) )
        {
            if ( likely(!atomic_read(&t->count)) )
            {
                if ( unlikely(!test_and_clear_bit(TASKLET_STATE_SCHED, 
                                                  &t->state)) )
                    BUG();
                t->func(t->data);
            }
            tasklet_unlock(t);
            continue;
        }

        local_irq_disable();
        t->next = tasklet_vec[cpu].list;
        tasklet_vec[cpu].list = t;
        __cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
        local_irq_enable();
    }
}

static void tasklet_hi_action(struct softirq_action *a)
{
    int cpu = smp_processor_id();
    struct tasklet_struct *list;

    local_irq_disable();
    list = tasklet_hi_vec[cpu].list;
    tasklet_hi_vec[cpu].list = NULL;
    local_irq_enable();

    while ( list != NULL )
    {
        struct tasklet_struct *t = list;

        list = list->next;

        if ( likely(tasklet_trylock(t)) )
        {
            if ( likely(!atomic_read(&t->count)) )
            {
                if ( unlikely(!test_and_clear_bit(TASKLET_STATE_SCHED, 
                                                  &t->state)) )
                    BUG();
                t->func(t->data);
            }
            tasklet_unlock(t);
            continue;
        }

        local_irq_disable();
        t->next = tasklet_hi_vec[cpu].list;
        tasklet_hi_vec[cpu].list = t;
        __cpu_raise_softirq(cpu, HI_SOFTIRQ);
        local_irq_enable();
    }
}


void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
    t->next = NULL;
    t->state = 0;
    atomic_set(&t->count, 0);
    t->func = func;
    t->data = data;
}

void tasklet_kill(struct tasklet_struct *t)
{
    if ( in_interrupt() )
        BUG();
    while ( test_and_set_bit(TASKLET_STATE_SCHED, &t->state) )
        while ( test_bit(TASKLET_STATE_SCHED, &t->state) )
            do_softirq();
    tasklet_unlock_wait(t);
    clear_bit(TASKLET_STATE_SCHED, &t->state);
}



/* Old style BHs */

static void (*bh_base[32])(void);
struct tasklet_struct bh_task_vec[32];

spinlock_t global_bh_lock = SPIN_LOCK_UNLOCKED;

static void bh_action(unsigned long nr)
{
    int cpu = smp_processor_id();

    if ( !spin_trylock(&global_bh_lock) )
        goto resched;

    if ( !hardirq_trylock(cpu) )
        goto resched_unlock;

    if ( likely(bh_base[nr] != NULL) )
        bh_base[nr]();

    hardirq_endlock(cpu);
    spin_unlock(&global_bh_lock);
    return;

 resched_unlock:
    spin_unlock(&global_bh_lock);
 resched:
    mark_bh(nr);
}

void init_bh(int nr, void (*routine)(void))
{
    bh_base[nr] = routine;
    mb();
}

void remove_bh(int nr)
{
    tasklet_kill(bh_task_vec+nr);
    bh_base[nr] = NULL;
}

void __init softirq_init()
{
    int i;

    for ( i = 0; i < 32; i++)
        tasklet_init(bh_task_vec+i, bh_action, i);

    open_softirq(TASKLET_SOFTIRQ, tasklet_action, NULL);
    open_softirq(HI_SOFTIRQ, tasklet_hi_action, NULL);
}

void __run_task_queue(task_queue *list)
{
    struct list_head  head, *next;
    unsigned long     flags;
    void              (*f) (void *);
    struct tq_struct *p;
    void             *data;

    spin_lock_irqsave(&tqueue_lock, flags);
    list_add(&head, list);
    list_del_init(list);
    spin_unlock_irqrestore(&tqueue_lock, flags);

    next = head.next;
    while ( next != &head )
    {
        p = list_entry(next, struct tq_struct, list);
        next = next->next;
        f = p->routine;
        data = p->data;
        wmb();
        p->sync = 0;
        if ( likely(f != NULL) )
            f(data);
    }
}

