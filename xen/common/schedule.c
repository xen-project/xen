/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 ****************************************************************************
 *
 *        File: common/schedule.c
 *      Author: Rolf Neugebar & Keir Fraser
 * 
 * Description: CPU scheduling
 *              implements A Borrowed Virtual Time scheduler.
 *              (see Duda & Cheriton SOSP'99)
 */

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/sched.h>
#include <xeno/delay.h>
#include <xeno/event.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>
#include <xeno/interrupt.h>
#include <xeno/timer.h>
#include <xeno/perfc.h>


#undef SCHEDULER_TRACE
#ifdef SCHEDULER_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

/*#define SCHED_HISTO*/
#ifdef SCHED_HISTO
#define BUCKETS 31
#endif

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */

typedef struct schedule_data_st
{
    spinlock_t          lock;           /* lock for protecting this */
    struct list_head    runqueue;       /* runqueue */
    struct task_struct *prev, *curr;    /* previous and current task */
    struct task_struct *idle;           /* idle task for this cpu */
    u32                 svt;            /* system virtual time. per CPU??? */
    struct ac_timer     s_timer;        /* scheduling timer  */
#ifdef SCHED_HISTO
    u32                 hist[BUCKETS];  /* for scheduler latency histogram */
#endif
} __cacheline_aligned schedule_data_t;
schedule_data_t schedule_data[NR_CPUS];

struct ac_timer v_timer;        /* scheduling timer  */
static void virt_timer(unsigned long foo);
static void dump_rqueue(struct list_head *queue, char *name);


static inline void __add_to_runqueue_head(struct task_struct * p)
{    
    list_add(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __add_to_runqueue_tail(struct task_struct * p)
{
    list_add_tail(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __del_from_runqueue(struct task_struct * p)
{
    list_del(&p->run_list);
    p->run_list.next = NULL;
}

static inline int __task_on_runqueue(struct task_struct *p)
{
    return p->run_list.next != NULL;
}

#define next_domain(p) \\
        list_entry((p)->run_list.next, struct task_struct, run_list)

static void __calc_evt(struct task_struct *p)
{
    s_time_t now = NOW();
    if ( p->warpback ) 
    {
        if ( ((now - p->warped) < p->warpl) &&
             ((now - p->uwarped) > p->warpu) )
        {
            /* allowed to warp */
            p->evt = p->avt - p->warp;
        } 
        else 
        {
            /* warped for too long -> unwarp */
            p->evt      = p->avt;
            p->uwarped  = now;
            p->warpback = 0;
        }
    } 
    else 
    {
        p->evt = p->avt;
    }
}


/******************************************************************************
* Add and remove a domain
******************************************************************************/
void sched_add_domain(struct task_struct *p) 
{
    p->state       = TASK_SUSPENDED;
    p->mcu_advance = MCU_ADVANCE;

    if ( p->domain == IDLE_DOMAIN_ID )
    {
        p->avt = 0xffffffff;
        p->evt = 0xffffffff;
        schedule_data[p->processor].idle = p;
    } 
    else 
    {
        /* set avt end evt to system virtual time */
        p->avt         = schedule_data[p->processor].svt;
        p->evt         = schedule_data[p->processor].svt;
        /* set some default values here */
        p->warpback    = 0;
        p->warp        = 0;
        p->warpl       = 0;
        p->warpu       = 0;
    }
}

void sched_rem_domain(struct task_struct *p) 
{
    p->state = TASK_DYING;
}


void init_idle_task(void)
{
    unsigned long flags;
    struct task_struct *p = current;
    spin_lock_irqsave(&schedule_data[p->processor].lock, flags);
    p->has_cpu = 1;
    p->state = TASK_RUNNING;
    if ( !__task_on_runqueue(p) )
        __add_to_runqueue_head(p);
    spin_unlock_irqrestore(&schedule_data[p->processor].lock, flags);
}


/****************************************************************************
 * wake up a domain which had been sleeping
 ****************************************************************************/
int wake_up(struct task_struct *p)
{
    unsigned long flags;
    int ret = 0;

    spin_lock_irqsave(&schedule_data[p->processor].lock, flags);

    /* XXX RN: should we warp here? Might be a good idea to also boost a 
     * domain which currently is unwarped and on run queue and 
     * the receives an event. */
    if ( __task_on_runqueue(p) ) goto out;

    p->state = TASK_RUNNING;
    __add_to_runqueue_head(p);

    /* set the BVT parameters */
    if (p->avt < schedule_data[p->processor].svt)
        p->avt = schedule_data[p->processor].svt;

    /* deal with warping here */
    p->warpback  = 1;
    p->warped    = NOW();
    __calc_evt(p);

#ifdef SCHED_HISTO
    p->wokenup = NOW();
#endif

    ret = 1;
 out:
    spin_unlock_irqrestore(&schedule_data[p->processor].lock, flags);
    return ret;
}

/****************************************************************************
 * Voluntarily yield the processor to another domain, until an event occurs.
 ****************************************************************************/
long do_yield(void)
{
    current->state = TASK_INTERRUPTIBLE;
    current->warpback = 0; /* XXX should only do this when blocking */
    schedule();
    return 0;
}

/****************************************************************************
 * Control the scheduler
 ****************************************************************************/
long sched_bvtctl(unsigned long c_allow)
{
    ctx_allow = c_allow;
    return 0;
}

/****************************************************************************
 * Adjust scheduling parameter for a given domain
 ****************************************************************************/
long sched_adjdom(int dom, unsigned long mcu_adv, unsigned long warp, 
                 unsigned long warpl, unsigned long warpu)
{
    struct task_struct *p;

    /* Sanity -- this can avoid divide-by-zero. */
    if ( mcu_adv == 0 )
        return -EINVAL;

    p = find_domain_by_id(dom);
    if ( p == NULL ) 
        return -ESRCH;

    spin_lock_irq(&schedule_data[p->processor].lock);   
    p->mcu_advance = mcu_adv;
    spin_unlock_irq(&schedule_data[p->processor].lock); 

    put_task_struct(p);

    return 0;
}

/****************************************************************************
 * cause a run through the scheduler when appropriate
 * Appropriate is:
 * - current task is idle task
 * - the current task already ran for it's context switch allowance
 * Otherwise we do a run through the scheduler after the current tasks 
 * context switch allowance is over.
 ****************************************************************************/
void reschedule(struct task_struct *p)
{
    int cpu = p->processor;
    struct task_struct *curr;
    unsigned long flags;
    s_time_t now, min_time;

    if (p->has_cpu)
        return;

    spin_lock_irqsave(&schedule_data[cpu].lock, flags);
    
    now = NOW();
    curr = schedule_data[cpu].curr;
    /* domain should run at least for ctx_allow */
    min_time = curr->lastschd + ctx_allow;

    if ( is_idle_task(curr) || (min_time <= now) ) {
        /* reschedule */
        set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);

        spin_unlock_irqrestore(&schedule_data[cpu].lock, flags);

        if (cpu != smp_processor_id())
            smp_send_event_check_cpu(cpu);
        return;
    }

    /* current hasn't been running for long enough -> reprogram timer.
     * but don't bother if timer would go off soon anyway */
    if (schedule_data[cpu].s_timer.expires > min_time + TIME_SLOP) {
        mod_ac_timer(&schedule_data[cpu].s_timer, min_time);
    }
    
    spin_unlock_irqrestore(&schedule_data[cpu].lock, flags);
    return;
}


/**************************************************************************** 
 * The main function
 * - deschedule the current domain.
 * - pick a new domain.
 *   i.e., the domain with lowest EVT.
 *   The runqueue should be ordered by EVT so that is easy.
 ****************************************************************************/
asmlinkage void schedule(void)
{
    struct task_struct *prev, *next, *next_prime, *p;
    struct list_head   *tmp;
    int                 this_cpu;
    s_time_t            now;
    s32                 r_time;     /* time for new dom to run */
    s32                 ranfor;     /* assume we never run longer than 2.1s! */
    s32                 mcus;
    u32                 next_evt, next_prime_evt, min_avt;

    perfc_incrc(sched_run1);
 need_resched_back:
    perfc_incrc(sched_run2);

    prev = current;
    next = NULL;

    this_cpu = prev->processor;

    spin_lock_irq(&schedule_data[this_cpu].lock);

    now = NOW();

    /* remove timer, if still on list  */
    rem_ac_timer(&schedule_data[this_cpu].s_timer);

    /* deschedule the current domain */

    ASSERT(!in_interrupt());
    ASSERT(__task_on_runqueue(prev));

    if (is_idle_task(prev)) 
        goto deschedule_done;

    /* do some accounting */
    ranfor = (s32)(now - prev->lastschd);
    ASSERT((ranfor>0));
    prev->cpu_time += ranfor;
    
    /* calculate mcu and update avt */
    mcus = ranfor/MCU;
    if (ranfor % MCU) mcus ++;  /* always round up */
    prev->avt += mcus * prev->mcu_advance;

    /* recalculate evt */
    __calc_evt(prev);

    /* dequeue */
    __del_from_runqueue(prev);
    switch (prev->state) {
    case TASK_INTERRUPTIBLE:
        if (signal_pending(prev)) {
            prev->state = TASK_RUNNING; /* but has events pending */
            break;
        }
    case TASK_UNINTERRUPTIBLE:
    case TASK_WAIT:
    case TASK_DYING:
    case TASK_SUSPENDED:
    default:
        /* done if not running. Else, continue */
        goto deschedule_done;
    case TASK_RUNNING:;
    }

    /* requeue */
    __add_to_runqueue_tail(prev);
    

 deschedule_done:
    clear_bit(_HYP_EVENT_NEED_RESCHED, &prev->hyp_events);

    /*
     * Pick a new domain
     */

    /* we should at least have the idle task */
    ASSERT(!list_empty(&schedule_data[this_cpu].runqueue));

    /*
     * scan through the run queue and pick the task with the lowest evt
     * *and* the task the second lowest evt.
     * this code is O(n) but we expect n to be small.
     */
    next       = schedule_data[this_cpu].idle;
    next_prime = NULL;

    next_evt       = 0xffffffff;
    next_prime_evt = 0xffffffff;
    min_avt        = 0xffffffff;    /* to calculate svt */

    list_for_each(tmp, &schedule_data[this_cpu].runqueue) {
        p = list_entry(tmp, struct task_struct, run_list);
        if (p->evt < next_evt) {
            next_prime     = next;
            next_prime_evt = next_evt;
            next = p;
            next_evt = p->evt;
        } else if (next_prime_evt == 0xffffffff) {
            next_prime_evt = p->evt;
            next_prime     = p;
        } else if (p->evt < next_prime_evt) {
            next_prime_evt = p->evt;
            next_prime     = p;
        }
        /* determine system virtual time */
        if (p->avt < min_avt)
            min_avt = p->avt;
    }
    ASSERT(next != NULL);   /* we should have at least the idle task */

    /* update system virtual time  */
    if (min_avt != 0xffffffff) schedule_data[this_cpu].svt = min_avt;

    /* check for virtual time overrun on this cpu */
    if (schedule_data[this_cpu].svt >= 0xf0000000) {
        u_long t_flags; 
        write_lock_irqsave(&tasklist_lock, t_flags); 
        p = &idle0_task;
        do {
            if (p->processor == this_cpu && !is_idle_task(p)) {
                p->evt -= 0xe0000000;
                p->avt -= 0xe0000000;
            }
        } while ( (p = p->next_task) != &idle0_task );
        write_unlock_irqrestore(&tasklist_lock, t_flags); 
        schedule_data[this_cpu].svt -= 0xe0000000;
    }

    /* work out time for next run through scheduler */
    if (is_idle_task(next)) {
        r_time = ctx_allow;
        goto sched_done;
    }

    if (next_prime == NULL || is_idle_task(next_prime)) {
        /* we have only one runable task besides the idle task */
        r_time = 10 * ctx_allow;     /* RN: random constant */
        goto sched_done;
    }

    /*
     * if we are here we have two runable tasks.
     * work out how long 'next' can run till its evt is greater than
     * 'next_prime's evt. Taking context switch allowance into account.
     */
    ASSERT(next_prime->evt >= next->evt);
    r_time = ((next_prime->evt - next->evt)/next->mcu_advance) + ctx_allow;

 sched_done:
    ASSERT(r_time >= ctx_allow);

#ifndef NDEBUG
    if (r_time < ctx_allow) {
        printk("[%02d]: %lx\n", this_cpu, (unsigned long)r_time);
        dump_rqueue(&schedule_data[this_cpu].runqueue, "foo");
    }
#endif

    prev->has_cpu = 0;
    next->has_cpu = 1;

    schedule_data[this_cpu].prev = prev;
    schedule_data[this_cpu].curr = next;

    next->lastschd = now;

    /* reprogramm the timer */
    schedule_data[this_cpu].s_timer.expires  = now + r_time;
    add_ac_timer(&schedule_data[this_cpu].s_timer);

    spin_unlock_irq(&schedule_data[this_cpu].lock);

    /* done, switch tasks */
    if ( unlikely(prev == next) )
    {
        /* We won't go through the normal tail, so do this by hand */
        prev->policy &= ~SCHED_YIELD;
        goto same_process;
    }

    perfc_incrc(sched_ctx);
#ifdef SCHED_HISTO
    {
        ulong diff; /* should fit in 32bits */
        if (!is_idle_task(next) && next->wokenup) {
            diff = (ulong)(now - next->wokenup);
            diff /= (ulong)MILLISECS(1);
            if (diff <= BUCKETS-2)  schedule_data[this_cpu].hist[diff]++;
            else                    schedule_data[this_cpu].hist[BUCKETS-1]++;
        }
        next->wokenup = (s_time_t)0;
    }
#endif


    prepare_to_switch();
    switch_to(prev, next);
    prev = schedule_data[this_cpu].prev;
    
    prev->policy &= ~SCHED_YIELD;
    if ( prev->state == TASK_DYING ) 
        put_task_struct(prev);

 same_process:
    /* update the domains notion of time  */
    update_dom_time(current->shared_info);

    if ( test_bit(_HYP_EVENT_NEED_RESCHED, &current->hyp_events) ) {
        goto need_resched_back;
    }
    return;
}

/* No locking needed -- pointer comparison is safe :-) */
int idle_cpu(int cpu)
{
    struct task_struct *p = schedule_data[cpu].curr;
    return p == idle_task[cpu];
}


/*
 * The scheduler timer.
 */
static void sched_timer(unsigned long foo)
{
    int                 cpu  = smp_processor_id();
    struct task_struct *curr = schedule_data[cpu].curr;
    /* cause a reschedule */
    set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);
    perfc_incrc(sched_irq);
}

/*
 * The Domain virtual time timer
 */
static void virt_timer(unsigned long foo)
{
    unsigned long cpu_mask = 0;
    struct task_struct *p;
    s_time_t now;

    /* send virtual timer interrupt */
    read_lock(&tasklist_lock);
    p = &idle0_task;
    do {
        if ( is_idle_task(p) ) continue;
        cpu_mask |= mark_guest_event(p, _EVENT_TIMER);
    }
    while ( (p = p->next_task) != &idle0_task );
    read_unlock(&tasklist_lock);
    guest_event_notify(cpu_mask);

    now = NOW();
    v_timer.expires  = now + MILLISECS(20);
    add_ac_timer(&v_timer);
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
        init_ac_timer(&schedule_data[i].s_timer, i);
        schedule_data[i].s_timer.data = 2;
        schedule_data[i].s_timer.function = &sched_timer;

    }
    schedule_data[0].idle = &idle0_task; /* idle on CPU 0 is special */
    init_ac_timer(&v_timer, 0);
    v_timer.data = 3;
    v_timer.function = &virt_timer;
}

/*
 * Start a scheduler for each CPU
 * This has to be done *after* the timers, e.g., APICs, have been initialised
 */
void schedulers_start(void) 
{   
    printk("Start schedulers\n");
    sched_timer(0);
    virt_timer(0);
    smp_call_function((void *)sched_timer, NULL, 1, 1);
}


/****************************************************************************
 * Functions for legacy support. 
 * Schedule timeout is used at a number of places and is a bit meaningless 
 * in the context of Xen, as Domains are not able to call these and all 
 * there entry points into Xen should be asynchronous. If a domain wishes
 * to block for a while it should use Xen's sched_op/yield entry point.
 ****************************************************************************/

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
        /* Sanity! This just wouldn't make sense. */
        if ( is_idle_task(current) )
            panic("Arbitrary sleep in idle task!");
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
    
    if ( is_idle_task(current) )
    {
        /*
         * If the idle task is calling in then it shouldn't ever sleep. We 
         * therefore force it to TASK_RUNNING here and busy-wait. We spin on 
         * schedule to give other domains a chance meanwhile.
         */
        set_current_state(TASK_RUNNING);
        do { 
            schedule();
            timeout = expire - jiffies;
        } 
        while ( (timeout > 0) && is_idle_task(current) );
    }
    else
    {
        init_timer(&timer);
        timer.expires = expire;
        timer.data = (unsigned long) current;
        timer.function = process_timeout;
        
        add_timer(&timer);
        schedule();
        del_timer_sync(&timer);
        
        timeout = expire - jiffies;
    }

 out:
    return timeout < 0 ? 0 : timeout;
}

/****************************************************************************
 * debug function
 ****************************************************************************/

static void dump_rqueue(struct list_head *queue, char *name)
{
    struct list_head *list;
    int loop = 0;
    struct task_struct  *p;

    printk ("QUEUE %s %lx   n: %lx, p: %lx\n", name,  (unsigned long)queue,
            (unsigned long) queue->next, (unsigned long) queue->prev);
    list_for_each (list, queue) {
        p = list_entry(list, struct task_struct, run_list);
        printk("%3d: %3d has=%c mcua=0x%04lX ev=0x%08X av=0x%08X c=0x%X%08X\n",
               loop++, p->domain,
               p->has_cpu ? 'T':'F',
               p->mcu_advance, p->evt, p->avt,
               (u32)(p->cpu_time>>32), (u32)p->cpu_time);
        printk("         l: %lx n: %lx  p: %lx\n",
               (unsigned long)list, (unsigned long)list->next,
               (unsigned long)list->prev);
    }
    return; 
}

void dump_runq(u_char key, void *dev_id, struct pt_regs *regs)
{
    u_long   flags; 
    s_time_t now = NOW();
    int i;

    printk("BVT: mcu=0x%08Xns ctx_allow=0x%08Xns NOW=0x%08X%08X\n",
           (u32)MCU, (u32)ctx_allow, (u32)(now>>32), (u32)now); 
    for (i = 0; i < smp_num_cpus; i++) {
        spin_lock_irqsave(&schedule_data[i].lock, flags);
        printk("CPU[%02d] svt=0x%08X ", i, (s32)schedule_data[i].svt);
        dump_rqueue(&schedule_data[i].runqueue, "rq"); 
        spin_unlock_irqrestore(&schedule_data[i].lock, flags);
    }
    return; 
}

#ifdef SCHED_HISTO
void print_sched_histo(u_char key, void *dev_id, struct pt_regs *regs)
{
    int loop, i, j;
    for (loop = 0; loop < smp_num_cpus; loop++) {
        j = 0;
        printf ("CPU[%02d]: scheduler latency histogram (ms:[count])\n", loop);
        for (i=0; i<BUCKETS; i++) {
            if (schedule_data[loop].hist[i]) {
                if (i < BUCKETS-1)
                    printk("%2d:[%7u]    ", i, schedule_data[loop].hist[i]);
                else
                    printk(" >:[%7u]    ", schedule_data[loop].hist[i]);
                j++;
                if (!(j % 5)) printk("\n");
            }
        }
        printk("\n");
    }
      
}
void reset_sched_histo(u_char key, void *dev_id, struct pt_regs *regs)
{
    int loop, i;
    for (loop = 0; loop < smp_num_cpus; loop++)
        for (i=0; i<BUCKETS; i++) 
            schedule_data[loop].hist[i]=0;
}
#else
void print_sched_histo(u_char key, void *dev_id, struct pt_regs *regs)
{
}
void reset_sched_histo(u_char key, void *dev_id, struct pt_regs *regs)
{
}
#endif
