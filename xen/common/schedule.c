/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 ****************************************************************************
 *
 *        File: common/schedule.c
 *      Author: Rolf Neugebauer & Keir Fraser
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

/*#define WAKEUP_HISTO*/
/*#define BLOCKTIME_HISTO*/

#if defined(WAKEUP_HISTO)
#define BUCKETS 31
#elif defined(BLOCKTIME_HISTO)
#define BUCKETS 200
#endif

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */

typedef struct schedule_data_st
{
    struct list_head    runqueue;       /* runqueue */
    struct task_struct *curr;           /* current task */
    struct task_struct *idle;           /* idle task for this cpu */
    u32                 svt;            /* system virtual time. per CPU??? */
    struct ac_timer     s_timer;        /* scheduling timer  */
#ifdef BUCKETS
    u32                 hist[BUCKETS];  /* for scheduler latency histogram */
#endif
} __cacheline_aligned schedule_data_t;
static schedule_data_t schedule_data[NR_CPUS];

spinlock_t schedule_lock[NR_CPUS] __cacheline_aligned;

/* Per-CPU periodic timer sends an event to the currently-executing domain. */
static struct ac_timer t_timer[NR_CPUS]; 

/*
 * Per-CPU timer which ensures that even guests with very long quantums get
 * their time-of-day state updated often enough to avoid wrapping.
 */
static struct ac_timer fallback_timer[NR_CPUS];

/* Various timer handlers. */
static void s_timer_fn(unsigned long unused);
static void t_timer_fn(unsigned long unused);
static void dom_timer_fn(unsigned long data);
static void fallback_timer_fn(unsigned long unused);

/*
 * Wrappers for run-queue management. Must be called with the schedule_lock
 * held.
 */
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

/*
 * Calculate the effective virtual time for a domain. Take into account 
 * warping limits
 */
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


/*
 * Add and remove a domain
 */
void sched_add_domain(struct task_struct *p) 
{
    p->state       = TASK_STOPPED;
    p->mcu_advance = MCU_ADVANCE;

    if ( p->domain == IDLE_DOMAIN_ID )
    {
        p->avt = p->evt = ~0U;
        schedule_data[p->processor].idle = p;
    } 
    else 
    {
        /* Set avt end evt to system virtual time. */
        p->avt         = schedule_data[p->processor].svt;
        p->evt         = schedule_data[p->processor].svt;
        /* Set some default values here. */
        p->warpback    = 0;
        p->warp        = 0;
        p->warpl       = 0;
        p->warpu       = 0;

        /* Initialise the per-domain timer. */
        init_ac_timer(&p->timer);
        p->timer.cpu      =  p->processor;
        p->timer.data     = (unsigned long)p;
        p->timer.function = &dom_timer_fn;

    }
}

int sched_rem_domain(struct task_struct *p) 
{
    int x, y = p->state;
    do {
        if ( (x = y) == TASK_DYING ) return 0;
    } while ( (y = cmpxchg(&p->state, x, TASK_DYING)) != x );
    return 1;
}


void init_idle_task(void)
{
    unsigned long flags;
    struct task_struct *p = current;
    spin_lock_irqsave(&schedule_lock[p->processor], flags);
    p->has_cpu = 1;
    p->state = TASK_RUNNING;
    if ( !__task_on_runqueue(p) )
        __add_to_runqueue_head(p);
    spin_unlock_irqrestore(&schedule_lock[p->processor], flags);
}


void __wake_up(struct task_struct *p)
{
    ASSERT(p->state != TASK_DYING);

    if ( unlikely(__task_on_runqueue(p)) )
        return;

    p->state = TASK_RUNNING;
    __add_to_runqueue_head(p);

    /* set the BVT parameters */
    if (p->avt < schedule_data[p->processor].svt)
        p->avt = schedule_data[p->processor].svt;

    /* deal with warping here */
    p->warpback  = 1;
    p->warped    = NOW();
    __calc_evt(p);

#ifdef WAKEUP_HISTO
    p->wokenup = NOW();
#endif
}

void wake_up(struct task_struct *p)
{
    unsigned long flags;
    spin_lock_irqsave(&schedule_lock[p->processor], flags);
    __wake_up(p);
    spin_unlock_irqrestore(&schedule_lock[p->processor], flags);
}

/* 
 * Block the currently-executing domain until a pertinent event occurs.
 */
static long do_block(void)
{
    set_bit(EVENTS_MASTER_ENABLE_BIT, &current->shared_info->events_mask);
    current->state = TASK_INTERRUPTIBLE;
    current->warpback = 0; 
    __enter_scheduler();
    return 0;
}

/*
 * Voluntarily yield the processor for this allocation.
 */
static long do_yield(void)
{
    __enter_scheduler();
    return 0;
}


/*
 * Demultiplex scheduler-related hypercalls.
 */
long do_sched_op(unsigned long op)
{
    long ret = 0;

    switch( op ) 
    {

    case SCHEDOP_yield:
    {
        ret = do_yield();
        break;
    }

    case SCHEDOP_block:
    {
        ret = do_block();
        break;
    }

    case SCHEDOP_exit:
    {
        DPRINTK("DOM%llu killed itself!\n", current->domain);
        DPRINTK(" EIP == %08lx\n", get_execution_context()->eip);
        kill_domain();
        break;
    }

    case SCHEDOP_stop:
    {
        DPRINTK("DOM%llu stopped itself!\n", current->domain);
        DPRINTK(" EIP == %08lx\n", get_execution_context()->eip);
        stop_domain();
        break;
    }

    default:
        ret = -ENOSYS;
    }

    return ret;
}

/* Per-domain one-shot-timer hypercall. */
long do_set_timer_op(unsigned long timeout_hi, unsigned long timeout_lo)
{
    struct task_struct *p = current;

    rem_ac_timer(&p->timer);
    
    if ( (timeout_hi != 0) || (timeout_lo != 0) )
    {
        p->timer.expires = ((s_time_t)timeout_hi<<32) | ((s_time_t)timeout_lo);
        add_ac_timer(&p->timer);
    }

    return 0;
}


/* Control the scheduler. */
long sched_bvtctl(unsigned long c_allow)
{
    ctx_allow = c_allow;
    return 0;
}

/* Adjust scheduling parameter for a given domain. */
long sched_adjdom(domid_t dom, unsigned long mcu_adv, unsigned long warp, 
                 unsigned long warpl, unsigned long warpu)
{
    struct task_struct *p;

    /* Sanity -- this can avoid divide-by-zero. */
    if ( mcu_adv == 0 )
        return -EINVAL;

    p = find_domain_by_id(dom);
    if ( p == NULL ) 
        return -ESRCH;

    spin_lock_irq(&schedule_lock[p->processor]);   
    p->mcu_advance = mcu_adv;
    spin_unlock_irq(&schedule_lock[p->processor]); 

    put_task_struct(p);

    return 0;
}

/*
 * cause a run through the scheduler when appropriate
 * Appropriate is:
 * - current task is idle task
 * - the current task already ran for it's context switch allowance
 * Otherwise we do a run through the scheduler after the current tasks 
 * context switch allowance is over.
 */
unsigned long __reschedule(struct task_struct *p)
{
    int cpu = p->processor;
    struct task_struct *curr;
    s_time_t now, min_time;

    if ( unlikely(p->has_cpu || !__task_on_runqueue(p)) )
        return 0;

    now = NOW();
    curr = schedule_data[cpu].curr;
    /* domain should run at least for ctx_allow */
    min_time = curr->lastschd + ctx_allow;

    if ( is_idle_task(curr) || (min_time <= now) )
    {
        set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);
        return (1 << p->processor);
    }

    /* current hasn't been running for long enough -> reprogram timer.
     * but don't bother if timer would go off soon anyway */
    if ( schedule_data[cpu].s_timer.expires > min_time + TIME_SLOP )
        mod_ac_timer(&schedule_data[cpu].s_timer, min_time);

    return 0;
}


void reschedule(struct task_struct *p)
{
    unsigned long flags, cpu_mask;
    spin_lock_irqsave(&schedule_lock[p->processor], flags);
    cpu_mask = __reschedule(p);
    spin_unlock_irqrestore(&schedule_lock[p->processor], flags);
    hyp_event_notify(cpu_mask);
}


/* 
 * The main function
 * - deschedule the current domain.
 * - pick a new domain.
 *   i.e., the domain with lowest EVT.
 *   The runqueue should be ordered by EVT so that is easy.
 */
asmlinkage void __enter_scheduler(void)
{
    struct task_struct *prev = current, *next = NULL, *next_prime, *p;
    struct list_head   *tmp;
    int                 cpu = prev->processor;
    s_time_t            now;
    s32                 r_time;     /* time for new dom to run */
    s32                 ranfor;     /* assume we never run longer than 2.1s! */
    s32                 mcus;
    u32                 next_evt, next_prime_evt, min_avt;

    perfc_incrc(sched_run);

    spin_lock_irq(&schedule_lock[cpu]);

    now = NOW();

    rem_ac_timer(&schedule_data[cpu].s_timer);

    ASSERT(!in_interrupt());
    ASSERT(__task_on_runqueue(prev));
    ASSERT(prev->state != TASK_UNINTERRUPTIBLE);

    if ( likely(!is_idle_task(prev)) ) 
    {
        ranfor = (s32)(now - prev->lastschd);
        prev->cpu_time += ranfor;
    
        /* Calculate mcu and update avt. */
        mcus = (ranfor + MCU - 1) / MCU;
        prev->avt += mcus * prev->mcu_advance;
        
        __calc_evt(prev);
        
        __del_from_runqueue(prev);
        
        if ( likely(prev->state == TASK_RUNNING) ||
             unlikely((prev->state == TASK_INTERRUPTIBLE) && 
                      signal_pending(prev)) )
        {
            prev->state = TASK_RUNNING;
            __add_to_runqueue_tail(prev);
        }
    }

    clear_bit(_HYP_EVENT_NEED_RESCHED, &prev->hyp_events);

    /* We should at least have the idle task */
    ASSERT(!list_empty(&schedule_data[cpu].runqueue));

    /*
     * scan through the run queue and pick the task with the lowest evt
     * *and* the task the second lowest evt.
     * this code is O(n) but we expect n to be small.
     */
    next       = schedule_data[cpu].idle;
    next_prime = NULL;

    next_evt       = ~0U;
    next_prime_evt = ~0U;
    min_avt        = ~0U;

    list_for_each ( tmp, &schedule_data[cpu].runqueue )
    {
        p = list_entry(tmp, struct task_struct, run_list);
        if ( p->evt < next_evt )
        {
            next_prime     = next;
            next_prime_evt = next_evt;
            next = p;
            next_evt = p->evt;
        } 
        else if ( next_prime_evt == ~0U )
        {
            next_prime_evt = p->evt;
            next_prime     = p;
        } 
        else if ( p->evt < next_prime_evt )
        {
            next_prime_evt = p->evt;
            next_prime     = p;
        }

        /* Determine system virtual time. */
        if ( p->avt < min_avt )
            min_avt = p->avt;
    }

    /* Update system virtual time. */
    if ( min_avt != ~0U )
        schedule_data[cpu].svt = min_avt;

    /* check for virtual time overrun on this cpu */
    if ( schedule_data[cpu].svt >= 0xf0000000 )
    {
        u_long t_flags; 
        write_lock_irqsave(&tasklist_lock, t_flags); 
        p = &idle0_task;
        do {
            if ( (p->processor == cpu) && !is_idle_task(p) )
            {
                p->evt -= 0xe0000000;
                p->avt -= 0xe0000000;
            }
        } 
        while ( (p = p->next_task) != &idle0_task );
        write_unlock_irqrestore(&tasklist_lock, t_flags); 
        schedule_data[cpu].svt -= 0xe0000000;
    }

    /* work out time for next run through scheduler */
    if ( is_idle_task(next) ) 
    {
        r_time = ctx_allow;
        goto sched_done;
    }

    if ( (next_prime == NULL) || is_idle_task(next_prime) )
    {
        /* We have only one runnable task besides the idle task. */
        r_time = 10 * ctx_allow;     /* RN: random constant */
        goto sched_done;
    }

    /*
     * If we are here then we have two runnable tasks.
     * Work out how long 'next' can run till its evt is greater than
     * 'next_prime's evt. Take context switch allowance into account.
     */
    ASSERT(next_prime->evt >= next->evt);
    
    r_time = ((next_prime->evt - next->evt)/next->mcu_advance) + ctx_allow;

 sched_done:
    ASSERT(r_time >= ctx_allow);

    prev->has_cpu = 0;
    next->has_cpu = 1;

    schedule_data[cpu].curr = next;

    next->lastschd = now;

    /* reprogramm the timer */
    schedule_data[cpu].s_timer.expires  = now + r_time;
    add_ac_timer(&schedule_data[cpu].s_timer);

    spin_unlock_irq(&schedule_lock[cpu]);

    /* Ensure that the domain has an up-to-date time base. */
    if ( !is_idle_task(next) )
        update_dom_time(next->shared_info);

    if ( unlikely(prev == next) )
        return;

    perfc_incrc(sched_ctx);

#if defined(WAKEUP_HISTO)
    if ( !is_idle_task(next) && next->wokenup ) {
        ulong diff = (ulong)(now - next->wokenup);
        diff /= (ulong)MILLISECS(1);
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
    next->wokenup = (s_time_t)0;
#elif defined(BLOCKTIME_HISTO)
    prev->lastdeschd = now;
    if ( !is_idle_task(next) )
    {
        ulong diff = (ulong)((now - next->lastdeschd) / MILLISECS(10));
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
#endif

    switch_to(prev, next);
    
    if ( unlikely(prev->state == TASK_DYING) ) 
        put_task_struct(prev);

    /* Mark a timer event for the newly-scheduled domain. */
    if ( !is_idle_task(next) )
        set_bit(_EVENT_TIMER, &next->shared_info->events);
    
    schedule_tail(next);

    BUG();
}

/* No locking needed -- pointer comparison is safe :-) */
int idle_cpu(int cpu)
{
    struct task_struct *p = schedule_data[cpu].curr;
    return p == idle_task[cpu];
}


/****************************************************************************
 * Timers: the scheduler utilises a number of timers
 * - s_timer: per CPU timer for preemption and scheduling decisions
 * - t_timer: per CPU periodic timer to send timer interrupt to current dom
 * - dom_timer: per domain timer to specifiy timeout values
 * - fallback_timer: safeguard to ensure time is up to date
 ****************************************************************************/

/* The scheduler timer: force a run through the scheduler*/
static void s_timer_fn(unsigned long unused)
{
    set_bit(_HYP_EVENT_NEED_RESCHED, &current->hyp_events);
    perfc_incrc(sched_irq);
}

/* Periodic tick timer: send timer event to current domain*/
static void t_timer_fn(unsigned long unused)
{
    struct task_struct *p = current;

    if ( !is_idle_task(p) ) 
        set_bit(_EVENT_TIMER, &p->shared_info->events);

    t_timer[p->processor].expires = NOW() + MILLISECS(10);
    add_ac_timer(&t_timer[p->processor]);
}

/* Domain timer function, sends a virtual timer interrupt to domain */
static void dom_timer_fn(unsigned long data)
{
    unsigned long cpu_mask = 0;
    struct task_struct *p = (struct task_struct *)data;

    cpu_mask |= mark_guest_event(p, _EVENT_TIMER);
    guest_event_notify(cpu_mask);
}


/* Fallback timer to ensure guests get time updated 'often enough'. */
static void fallback_timer_fn(unsigned long unused)
{
    struct task_struct *p = current;

    if ( !is_idle_task(p) )
        update_dom_time(p->shared_info);

    fallback_timer[p->processor].expires = NOW() + MILLISECS(500);
    add_ac_timer(&fallback_timer[p->processor]);
}

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    int i;

    printk("Initialising schedulers\n");

    for ( i = 0; i < NR_CPUS; i++ )
    {
        INIT_LIST_HEAD(&schedule_data[i].runqueue);
        spin_lock_init(&schedule_lock[i]);
        schedule_data[i].curr = &idle0_task;
        
        init_ac_timer(&schedule_data[i].s_timer);
        schedule_data[i].s_timer.cpu      = i;
        schedule_data[i].s_timer.data     = 2;
        schedule_data[i].s_timer.function = &s_timer_fn;

        init_ac_timer(&t_timer[i]);
        t_timer[i].cpu      = i;
        t_timer[i].data     = 3;
        t_timer[i].function = &t_timer_fn;

        init_ac_timer(&fallback_timer[i]);
        fallback_timer[i].cpu      = i;
        fallback_timer[i].data     = 4;
        fallback_timer[i].function = &fallback_timer_fn;
    }

    schedule_data[0].idle = &idle0_task;
}

/*
 * Start a scheduler for each CPU
 * This has to be done *after* the timers, e.g., APICs, have been initialised
 */
void schedulers_start(void) 
{   
    printk("Start schedulers\n");

    s_timer_fn(0);
    smp_call_function((void *)s_timer_fn, NULL, 1, 1);

    t_timer_fn(0);
    smp_call_function((void *)t_timer_fn, NULL, 1, 1);

    fallback_timer_fn(0);
    smp_call_function((void *)fallback_timer_fn, NULL, 1, 1);
}


static void process_timeout(unsigned long __data)
{
    struct task_struct * p = (struct task_struct *) __data;
    wake_up(p);
}


static void dump_rqueue(struct list_head *queue, char *name)
{
    struct list_head *list;
    int loop = 0;
    struct task_struct  *p;

    printk ("QUEUE %s %lx   n: %lx, p: %lx\n", name,  (unsigned long)queue,
            (unsigned long) queue->next, (unsigned long) queue->prev);
    list_for_each (list, queue) {
        p = list_entry(list, struct task_struct, run_list);
        printk("%3d: %llu has=%c mcua=0x%04lX"
               " ev=0x%08X av=0x%08X c=0x%X%08X\n",
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
        spin_lock_irqsave(&schedule_lock[i], flags);
        printk("CPU[%02d] svt=0x%08X ", i, (s32)schedule_data[i].svt);
        dump_rqueue(&schedule_data[i].runqueue, "rq"); 
        spin_unlock_irqrestore(&schedule_lock[i], flags);
    }
    return; 
}

#if defined(WAKEUP_HISTO) || defined(BLOCKTIME_HISTO)
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
