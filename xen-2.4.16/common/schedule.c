/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: schedule.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: CPU scheduling
 *				partially moved from domain.c
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/sched.h>
#include <xeno/delay.h>
#include <xeno/event.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>

#undef SCHEDULER_TRACE
#ifdef SCHEDULER_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

/*
 * per CPU data for the scheduler.
 */
typedef struct schedule_data_st
{
    spinlock_t lock;
    struct list_head runqueue;
    struct task_struct *prev, *curr;
} __cacheline_aligned schedule_data_t;
schedule_data_t schedule_data[NR_CPUS];

static __cacheline_aligned struct ac_timer s_timer[NR_CPUS];

/*
 * Some convenience functions
 */

static inline void __add_to_runqueue(struct task_struct * p)
{
    list_add(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __move_last_runqueue(struct task_struct * p)
{
    list_del(&p->run_list);
    list_add_tail(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __move_first_runqueue(struct task_struct * p)
{
    list_del(&p->run_list);
    list_add(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __del_from_runqueue(struct task_struct * p)
{
    list_del(&p->run_list);
    p->run_list.next = NULL;
}

static inline int __task_on_runqueue(struct task_struct *p)
{
    return (p->run_list.next != NULL);
}


/*
 * Add a new domain to the scheduler
 */
void sched_add_domain(struct task_struct *p) 
{
    p->state      = TASK_UNINTERRUPTIBLE;
}

/*
 * Remove domain to the scheduler
 */
void sched_rem_domain(struct task_struct *p) 
{
	p->state = TASK_DYING;
}


/*
 * wake up a domain which had been sleeping
 */
int wake_up(struct task_struct *p)
{
    unsigned long flags;
    int ret = 0;
    spin_lock_irqsave(&schedule_data[p->processor].lock, flags);
    if ( __task_on_runqueue(p) ) goto out;
    p->state = TASK_RUNNING;
    __add_to_runqueue(p);
    ret = 1;

 out:
    spin_unlock_irqrestore(&schedule_data[p->processor].lock, flags);
    return ret;
}

static void process_timeout(unsigned long __data)
{
    struct task_struct * p = (struct task_struct *) __data;
    wake_up(p);
}

long schedule_timeout(long timeout)
{
    struct timer_list timer;
    unsigned long expire;
    
    switch (timeout)
    {
    case MAX_SCHEDULE_TIMEOUT:
        /*
         * These two special cases are useful to be comfortable in the caller.
         * Nothing more. We could take MAX_SCHEDULE_TIMEOUT from one of the
         * negative value but I' d like to return a valid offset (>=0) to allow
         * the caller to do everything it want with the retval.
         */
        schedule();
        goto out;
    default:
        /*
         * Another bit of PARANOID. Note that the retval will be 0 since no
         * piece of kernel is supposed to do a check for a negative retval of
         * schedule_timeout() (since it should never happens anyway). You just
         * have the printk() that will tell you if something is gone wrong and
         * where.
         */
        if (timeout < 0)
        {
            printk(KERN_ERR "schedule_timeout: wrong timeout "
                   "value %lx from %p\n", timeout,
                   __builtin_return_address(0));
            current->state = TASK_RUNNING;
            goto out;
        }
    }
    
    expire = timeout + jiffies;
    
    init_timer(&timer);
    timer.expires = expire;
    timer.data = (unsigned long) current;
    timer.function = process_timeout;
    
    add_timer(&timer);
    schedule();
    del_timer_sync(&timer);
    
    timeout = expire - jiffies;
    
 out:
    return timeout < 0 ? 0 : timeout;
}

/* RN: XXX turn this into do_halt() */
/*
 * yield the current process
 */
long do_sched_op(void)
{
    current->state = TASK_INTERRUPTIBLE;
    schedule();
    return 0;
}

/*
 * 
 */
void reschedule(struct task_struct *p)
{
    int cpu = p->processor;
    struct task_struct *curr;
    unsigned long flags;

    if (p->has_cpu)
		return;

    spin_lock_irqsave(&schedule_data[cpu].lock, flags);
    curr = schedule_data[cpu].curr;
    if (is_idle_task(curr)) {
        set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);
        spin_unlock_irqrestore(&schedule_data[cpu].lock, flags);
#ifdef CONFIG_SMP
        if (cpu != smp_processor_id())
			smp_send_event_check_cpu(cpu);
#endif
    } else {
        spin_unlock_irqrestore(&schedule_data[cpu].lock, flags);
    }
}


/*
 * Pick the next domain to run
 */

asmlinkage void schedule(void)
{
    struct task_struct *prev, *next, *p;
    struct list_head *tmp;
    int this_cpu;

 need_resched_back:
    prev = current;
    this_cpu = prev->processor;

    spin_lock_irq(&schedule_data[this_cpu].lock);

    //ASSERT(!in_interrupt());
    ASSERT(__task_on_runqueue(prev));

	__move_last_runqueue(prev);

    switch ( prev->state )
    {
    case TASK_INTERRUPTIBLE:
        if ( signal_pending(prev) )
        {
            prev->state = TASK_RUNNING;
            break;
        }
    default:
        __del_from_runqueue(prev);
    case TASK_RUNNING:;
    }
    clear_bit(_HYP_EVENT_NEED_RESCHED, &prev->hyp_events);

    next = NULL;
    list_for_each(tmp, &schedule_data[smp_processor_id()].runqueue) {
        p = list_entry(tmp, struct task_struct, run_list);
        next = p;
        break;
    }

    prev->has_cpu = 0;
    next->has_cpu = 1;

    schedule_data[this_cpu].prev = prev;
    schedule_data[this_cpu].curr = next;

    spin_unlock_irq(&schedule_data[this_cpu].lock);

    if ( unlikely(prev == next) )
    {
        /* We won't go through the normal tail, so do this by hand */
        prev->policy &= ~SCHED_YIELD;
        goto same_process;
    }

    prepare_to_switch();
    switch_to(prev, next);
    prev = schedule_data[this_cpu].prev;
    
    prev->policy &= ~SCHED_YIELD;
    if ( prev->state == TASK_DYING ) release_task(prev);

 same_process:

	update_dom_time(next->shared_info);

    if ( test_bit(_HYP_EVENT_NEED_RESCHED, &current->hyp_events) )
        goto need_resched_back;
    return;
}

static __cacheline_aligned int count[NR_CPUS];
static void sched_timer(unsigned long foo)
{
	int 				cpu  = smp_processor_id();
    struct task_struct *curr = schedule_data[cpu].curr;
	s_time_t			now;
	int 				res;

	if (count[cpu] >= 5) {
		set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);
		count[cpu] = 0;
	}
	count[cpu]++;

 again:
	now = NOW();
	s_timer[cpu].expires  = now + MILLISECS(10);

 	TRC(printk("SCHED[%02d] timer(): now=0x%08X%08X timo=0x%08X%08X\n",
 			   cpu, (u32)(now>>32), (u32)now,
 			   (u32)(s_timer[cpu].expires>>32), (u32)s_timer[cpu].expires));
	res=add_ac_timer(&s_timer[cpu]);
	if (res==1) {
		goto again;
	}
}
/*
 * Initialise the data structures
 */
void __init scheduler_init(void)
{
    int i;

	printk("Initialising schedulers\n");

    for ( i = 0; i < NR_CPUS; i++ )
    {
        INIT_LIST_HEAD(&schedule_data[i].runqueue);
        spin_lock_init(&schedule_data[i].lock);
        schedule_data[i].prev = &idle0_task;
        schedule_data[i].curr = &idle0_task;
		
		/* a timer for each CPU  */
		init_ac_timer(&s_timer[i]);
		s_timer[i].function = &sched_timer;
    }
}

/*
 * Start a scheduler for each CPU
 * This has to be done *after* the timers, e.g., APICs, have been initialised
 */
void schedulers_start(void) {
	
	printk("Start schedulers\n");
	__cli();
	sched_timer(0);
	smp_call_function(sched_timer, (void*)0, 1, 1);
	__sti();
}
