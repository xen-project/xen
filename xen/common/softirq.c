/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 * Fixed a disable_bh()/enable_bh() race (was causing a console lockup)
 * due bh_mask_count not atomic handling. Copyright (C) 1998  Andrea Arcangeli
 *
 * Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/sched.h>
//#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
//#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/tqueue.h>

/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.
   - These softirqs are not masked by global cli() and start_bh_atomic()
     (by clear reasons). Hence, old parts of code still using global locks
     MUST NOT use softirqs, but insert interfacing routines acquiring
     global locks. F.e. look at BHs implementation.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
   - Bottom halves: globally serialized, grr...
 */

irq_cpustat_t irq_stat[NR_CPUS];

static struct softirq_action softirq_vec[32] __cacheline_aligned;


asmlinkage void do_softirq()
{
    int cpu = smp_processor_id();
    struct softirq_action *h;
    __u32 pending;
    long flags;

    if (in_interrupt())
        return;

    local_irq_save(flags);

    pending = xchg(&softirq_pending(cpu), 0);
    if ( !pending ) goto out;

    local_bh_disable();

    do {
        local_irq_enable();
        
        h = softirq_vec;
        
        do {
            if (pending & 1)
                h->action(h);
            h++;
            pending >>= 1;
        } while (pending);
        
        local_irq_disable();
        
        pending = xchg(&softirq_pending(cpu), 0);
    } while ( pending );

    __local_bh_enable();

out:
    local_irq_restore(flags);
}

/*
 * This function must run with irq disabled!
 */
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
    long flags;

    local_irq_save(flags);
    cpu_raise_softirq(smp_processor_id(), nr);
    local_irq_restore(flags);
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

    while (list) {
        struct tasklet_struct *t = list;

        list = list->next;

        if (tasklet_trylock(t)) {
            if (!atomic_read(&t->count)) {
                if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
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

    while (list) {
        struct tasklet_struct *t = list;

        list = list->next;

        if (tasklet_trylock(t)) {
            if (!atomic_read(&t->count)) {
                if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
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
    if (in_interrupt())
        printk("Attempt to kill tasklet from interrupt\n");

    while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
        set_current_state(TASK_RUNNING);
        do {
            current->policy |= SCHED_YIELD;
            schedule();
        } while (test_bit(TASKLET_STATE_SCHED, &t->state));
    }
    tasklet_unlock_wait(t);
    clear_bit(TASKLET_STATE_SCHED, &t->state);
}



/* Old style BHs */

static void (*bh_base[32])(void);
struct tasklet_struct bh_task_vec[32];

/* BHs are serialized by spinlock global_bh_lock.

   It is still possible to make synchronize_bh() as
   spin_unlock_wait(&global_bh_lock). This operation is not used
   by kernel now, so that this lock is not made private only
   due to wait_on_irq().

   It can be removed only after auditing all the BHs.
 */
spinlock_t global_bh_lock = SPIN_LOCK_UNLOCKED;

static void bh_action(unsigned long nr)
{
    int cpu = smp_processor_id();

    if (!spin_trylock(&global_bh_lock))
        goto resched;

    if (!hardirq_trylock(cpu))
        goto resched_unlock;

    if (bh_base[nr])
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

    for (i=0; i<32; i++)
        tasklet_init(bh_task_vec+i, bh_action, i);

    open_softirq(TASKLET_SOFTIRQ, tasklet_action, NULL);
    open_softirq(HI_SOFTIRQ, tasklet_hi_action, NULL);
}

void __run_task_queue(task_queue *list)
{
    struct list_head head, *next;
    unsigned long flags;

    spin_lock_irqsave(&tqueue_lock, flags);
    list_add(&head, list);
    list_del_init(list);
    spin_unlock_irqrestore(&tqueue_lock, flags);

    next = head.next;
    while (next != &head) {
        void (*f) (void *);
        struct tq_struct *p;
        void *data;

        p = list_entry(next, struct tq_struct, list);
        next = next->next;
        f = p->routine;
        data = p->data;
        wmb();
        p->sync = 0;
        if (f)
            f(data);
    }
}

