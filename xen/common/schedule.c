/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 * (C) 2004      - Mark Williamson - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: common/schedule.c
 *      Author: Rolf Neugebauer & Keir Fraser
 *              Updated for generic API by Mark Williamson
 * 
 * Description: Generic CPU scheduling code
 *              implements support functionality for the Xen scheduler API.
 *
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/ac_timer.h>
#include <xen/interrupt.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <hypervisor-ifs/sched_ctl.h>
#include <xen/trace.h>

/*#define WAKEUP_HISTO*/
/*#define BLOCKTIME_HISTO*/

#if defined(WAKEUP_HISTO)
#define BUCKETS 31
#elif defined(BLOCKTIME_HISTO)
#define BUCKETS 200
#endif

#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */

/*
 * TODO MAW pull trace-related #defines out of here and into an auto-generated
 * header file later on!
 */
#define TRC_SCHED_DOM_ADD             0x00010000
#define TRC_SCHED_DOM_REM             0x00010001
#define TRC_SCHED_WAKE                0x00010002
#define TRC_SCHED_BLOCK               0x00010003
#define TRC_SCHED_YIELD               0x00010004
#define TRC_SCHED_SET_TIMER           0x00010005
#define TRC_SCHED_CTL                 0x00010006
#define TRC_SCHED_ADJDOM              0x00010007
#define TRC_SCHED_RESCHED             0x00010008
#define TRC_SCHED_SWITCH              0x00010009
#define TRC_SCHED_S_TIMER_FN          0x0001000A
#define TRC_SCHED_T_TIMER_FN          0x0001000B
#define TRC_SCHED_DOM_TIMER_FN        0x0001000C
#define TRC_SCHED_FALLBACK_TIMER_FN   0x0001000D

#define _HIGH32(_x) (_x >> 32)
#define _LOW32(_x)  ((u32)_x )

/* Various timer handlers. */
static void s_timer_fn(unsigned long unused);
static void t_timer_fn(unsigned long unused);
static void dom_timer_fn(unsigned long data);
static void fallback_timer_fn(unsigned long unused);

/* This is global for now so that private implementations can reach it */
schedule_data_t schedule_data[NR_CPUS];

/*
 * TODO: It would be nice if the schedulers array could get populated
 * automagically without having to hack the code in here.
 */
extern struct scheduler sched_bvt_def, sched_rrobin_def, sched_atropos_def;
static struct scheduler *schedulers[] = { &sched_bvt_def,
                                          &sched_rrobin_def,
                                          &sched_atropos_def,
                                          NULL};

/* Operations for the current scheduler. */
static struct scheduler ops;

#define SCHED_OP(fn, ...)                                 \
         (( ops.fn != NULL ) ? ops.fn( __VA_ARGS__ )      \
          : (typeof(ops.fn(__VA_ARGS__)))0 )

spinlock_t schedule_lock[NR_CPUS] __cacheline_aligned;

/* Per-CPU periodic timer sends an event to the currently-executing domain. */
static struct ac_timer t_timer[NR_CPUS]; 

/*
 * Per-CPU timer which ensures that even guests with very long quantums get
 * their time-of-day state updated often enough to avoid wrapping.
 */
static struct ac_timer fallback_timer[NR_CPUS];

extern kmem_cache_t *task_struct_cachep;

void free_task_struct(struct task_struct *p)
{
    SCHED_OP(free_task, p);
    kmem_cache_free(task_struct_cachep, p);
}

/**
 * alloc_task_struct - allocate a new task_struct and sched private structures
 */
struct task_struct *alloc_task_struct(void)
{
    struct task_struct *p;

    if ( (p = kmem_cache_alloc(task_struct_cachep,GFP_KERNEL)) == NULL )
        return NULL;
    
    memset(p, 0, sizeof(*p));

    if ( SCHED_OP(alloc_task, p) < 0 )
    {
        kmem_cache_free(task_struct_cachep,p);
        return NULL;
    }

    return p;
}

/*
 * Add and remove a domain
 */
void sched_add_domain(struct task_struct *p) 
{
    p->state = TASK_STOPPED;

    if ( p->domain != IDLE_DOMAIN_ID )
    {
        /* Initialise the per-domain timer. */
        init_ac_timer(&p->timer);
        p->timer.cpu      =  p->processor;
        p->timer.data     = (unsigned long)p;
        p->timer.function = &dom_timer_fn;
    }
    else
    {
        schedule_data[p->processor].idle = p;
    }

    SCHED_OP(add_task, p);

    TRACE_3D(TRC_SCHED_DOM_ADD, _HIGH32(p->domain), _LOW32(p->domain), p);
}

int sched_rem_domain(struct task_struct *p) 
{
    int x, y = p->state;
    do {
        if ( (x = y) == TASK_DYING ) return 0;
    } while ( (y = cmpxchg(&p->state, x, TASK_DYING)) != x );

    rem_ac_timer(&p->timer);

    SCHED_OP(rem_task, p);

    TRACE_3D(TRC_SCHED_DOM_REM, _HIGH32(p->domain), _LOW32(p->domain), p);

    return 1;
}

void init_idle_task(void)
{
    unsigned long flags;
    struct task_struct *p = current;

    if ( SCHED_OP(alloc_task, p) < 0)
        panic("Failed to allocate scheduler private data for idle task");
    SCHED_OP(add_task, p);

    spin_lock_irqsave(&schedule_lock[p->processor], flags);
    p->has_cpu = 1;
    p->state = TASK_RUNNING;
    if ( !__task_on_runqueue(p) )
        __add_to_runqueue_head(p);
    spin_unlock_irqrestore(&schedule_lock[p->processor], flags);
}

void __wake_up(struct task_struct *p)
{
    TRACE_3D(TRC_SCHED_WAKE, _HIGH32(p->domain), _LOW32(p->domain), p);

    ASSERT(p->state != TASK_DYING);

    if ( unlikely(__task_on_runqueue(p)) )        
        return;

    p->state = TASK_RUNNING;

    SCHED_OP(wake_up, p);

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
long do_block(void)
{
    ASSERT(current->domain != IDLE_DOMAIN_ID);
    current->shared_info->vcpu_data[0].evtchn_upcall_mask = 0;
    current->state = TASK_INTERRUPTIBLE;
    TRACE_2D(TRC_SCHED_BLOCK, current->domain, current);
    __enter_scheduler();
    return 0;
}

/*
 * Voluntarily yield the processor for this allocation.
 */
static long do_yield(void)
{
    TRACE_2D(TRC_SCHED_YIELD, current->domain, current);
    __enter_scheduler();
    return 0;
}


/*
 * Demultiplex scheduler-related hypercalls.
 */
long do_sched_op(unsigned long op)
{
    long ret = 0;

    switch ( op & SCHEDOP_cmdmask ) 
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

    case SCHEDOP_stop:
    {
        stop_domain((u8)(op >> SCHEDOP_reasonshift));
        break;
    }

    default:
        ret = -ENOSYS;
    }

    return ret;
}


/*
 * sched_pause_sync - synchronously pause a domain's execution.
 * XXXX This is horribly broken -- here just as a place holder at present,
 *                                 do not use.
 */
void sched_pause_sync(struct task_struct *p)
{
    unsigned long flags;
    int cpu = p->processor;

    spin_lock_irqsave(&schedule_lock[cpu], flags);

    /* If not the current task, we can remove it from scheduling now. */
    if ( schedule_data[cpu].curr != p )
        SCHED_OP(pause, p);

    p->state = TASK_PAUSED;
    
    spin_unlock_irqrestore(&schedule_lock[cpu], flags);

    /* Spin until domain is descheduled by its local scheduler. */
    while ( schedule_data[cpu].curr == p )
    {
        send_hyp_event(p, _HYP_EVENT_NEED_RESCHED );
        do_yield();
    }
        
    /* The domain will not be scheduled again until we do a wake_up(). */
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

    TRACE_5D(TRC_SCHED_SET_TIMER, _HIGH32(p->domain), _LOW32(p->domain),
             p, timeout_hi, timeout_lo);

    return 0;
}

/** sched_id - fetch ID of current scheduler */
int sched_id()
{
    return ops.sched_id;
}

long sched_ctl(struct sched_ctl_cmd *cmd)
{
    TRACE_0D(TRC_SCHED_CTL);

    if ( cmd->sched_id != ops.sched_id )
        return -EINVAL;

    return SCHED_OP(control, cmd);
}


/* Adjust scheduling parameter for a given domain. */
long sched_adjdom(struct sched_adjdom_cmd *cmd)
{
    struct task_struct *p;    
    
    if ( cmd->sched_id != ops.sched_id )
        return -EINVAL;

    if ( cmd->direction != SCHED_INFO_PUT && cmd->direction != SCHED_INFO_GET )
        return -EINVAL;

    p = find_domain_by_id(cmd->domain);

    if( p == NULL )
        return -ESRCH;

    TRACE_2D(TRC_SCHED_ADJDOM, _HIGH32(p->domain), _LOW32(p->domain));

    SCHED_OP(adjdom, p, cmd);

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

    TRACE_3D(TRC_SCHED_RESCHED, _HIGH32(p->domain), _LOW32(p->domain), p);

    if ( unlikely(p->has_cpu || !__task_on_runqueue(p)) )
        return 0;

    now = NOW();
    curr = schedule_data[cpu].curr;
    /* domain should run at least for ctx_allow */
    min_time = curr->lastschd + curr->min_slice;

    if ( is_idle_task(curr) || (min_time <= now) )
    {
        set_bit(_HYP_EVENT_NEED_RESCHED, &curr->hyp_events);
        return (1 << p->processor);
    }

    /* current hasn't been running for long enough -> reprogram timer.
     * but don't bother if timer would go off soon anyway */
    if ( schedule_data[cpu].s_timer.expires > min_time + TIME_SLOP )
        mod_ac_timer(&schedule_data[cpu].s_timer, min_time);

    return SCHED_OP(reschedule, p);
}

void reschedule(struct task_struct *p)
{
    unsigned long flags, cpu_mask;

    spin_lock_irqsave(&schedule_lock[p->processor], flags);
    cpu_mask = __reschedule(p);

    spin_unlock_irqrestore(&schedule_lock[p->processor], flags);

#ifdef CONFIG_SMP
    cpu_mask &= ~(1 << smp_processor_id());
    if ( cpu_mask != 0 )
        smp_send_event_check_mask(cpu_mask);
#endif
}

/* 
 * The main function
 * - deschedule the current domain (scheduler independent).
 * - pick a new domain (scheduler dependent).
 */
asmlinkage void __enter_scheduler(void)
{
    struct task_struct *prev = current, *next = NULL;
    int                 cpu = prev->processor;
    s_time_t            now;
    task_slice_t        next_slice;
    s32                 r_time;     /* time for new dom to run */

    perfc_incrc(sched_run);

    clear_bit(_HYP_EVENT_NEED_RESCHED, &prev->hyp_events);

    spin_lock_irq(&schedule_lock[cpu]);

    now = NOW();

    rem_ac_timer(&schedule_data[cpu].s_timer);
    
    ASSERT(!in_interrupt());
    ASSERT(__task_on_runqueue(prev));
    ASSERT(prev->state != TASK_UNINTERRUPTIBLE);

    if ( prev->state == TASK_INTERRUPTIBLE )
    {
        /* this check is needed to avoid a race condition */
        if ( signal_pending(prev) )
            prev->state = TASK_RUNNING;
        else
            SCHED_OP(do_block, prev);
    }

    prev->cpu_time += now - prev->lastschd;

    /* get policy-specific decision on scheduling... */
    next_slice = ops.do_schedule(now);

    r_time = next_slice.time;
    next = next_slice.task;

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

    TRACE_2D(TRC_SCHED_SWITCH, next->domain, next);

    switch_to(prev, next);
    
    if ( unlikely(prev->state == TASK_DYING) ) 
        put_task_struct(prev);

    /* Mark a timer event for the newly-scheduled domain. */
    if ( !is_idle_task(next) )
        send_guest_virq(next, VIRQ_TIMER);
    
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
    TRACE_0D(TRC_SCHED_S_TIMER_FN);
    set_bit(_HYP_EVENT_NEED_RESCHED, &current->hyp_events);
    perfc_incrc(sched_irq);
}

/* Periodic tick timer: send timer event to current domain*/
static void t_timer_fn(unsigned long unused)
{
    struct task_struct *p = current;

    TRACE_0D(TRC_SCHED_T_TIMER_FN);

    if ( !is_idle_task(p) )
        send_guest_virq(p, VIRQ_TIMER);

    t_timer[p->processor].expires = NOW() + MILLISECS(10);
    add_ac_timer(&t_timer[p->processor]);
}

/* Domain timer function, sends a virtual timer interrupt to domain */
static void dom_timer_fn(unsigned long data)
{
    struct task_struct *p = (struct task_struct *)data;
    TRACE_0D(TRC_SCHED_DOM_TIMER_FN);
    send_guest_virq(p, VIRQ_TIMER);
}


/* Fallback timer to ensure guests get time updated 'often enough'. */
static void fallback_timer_fn(unsigned long unused)
{
    struct task_struct *p = current;

    TRACE_0D(TRC_SCHED_FALLBACK_TIMER_FN);

    if ( !is_idle_task(p) )
        update_dom_time(p->shared_info);

    fallback_timer[p->processor].expires = NOW() + MILLISECS(500);
    add_ac_timer(&fallback_timer[p->processor]);
}

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    int i;

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

    extern char opt_sched[];

    for ( i = 0; schedulers[i] != NULL; i++ )
    {
        ops = *schedulers[i];
        if ( strcmp(ops.opt_name, opt_sched) == 0 )
            break;
    }
    
    if ( schedulers[i] == NULL )
        printk("Could not find scheduler: %s\n", opt_sched);

    printk("Using scheduler: %s (%s)\n", ops.name, ops.opt_name);

    if ( SCHED_OP(init_scheduler) < 0 )
        panic("Initialising scheduler failed!");
}

/*
 * Start a scheduler for each CPU
 * This has to be done *after* the timers, e.g., APICs, have been initialised
 */
void schedulers_start(void) 
{   
    s_timer_fn(0);
    smp_call_function((void *)s_timer_fn, NULL, 1, 1);

    t_timer_fn(0);
    smp_call_function((void *)t_timer_fn, NULL, 1, 1);

    fallback_timer_fn(0);
    smp_call_function((void *)fallback_timer_fn, NULL, 1, 1);
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
        printk("%3d: %u has=%c ", loop++, p->domain, p->has_cpu ? 'T':'F');
        SCHED_OP(dump_runq_el, p);
        printk("c=0x%X%08X\n", (u32)(p->cpu_time>>32), (u32)p->cpu_time);
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

    printk("Scheduler: %s (%s)\n", ops.name, ops.opt_name);
    SCHED_OP(dump_settings);
    printk("NOW=0x%08X%08X\n",  (u32)(now>>32), (u32)now); 
    for (i = 0; i < smp_num_cpus; i++) {
        spin_lock_irqsave(&schedule_lock[i], flags);
        printk("CPU[%02d] ", i);
        SCHED_OP(dump_cpu_state,i);
        dump_rqueue(&schedule_data[i].runqueue, "rq"); 
        spin_unlock_irqrestore(&schedule_lock[i], flags);
    }
    return; 
}

/* print human-readable "state", given the numeric code for that state */
void sched_prn_state(int state)
{
    int ret = 0;
    
    switch(state)
    {
    case TASK_RUNNING:
        printk("Running");
        break;
    case TASK_INTERRUPTIBLE:
        printk("Int sleep");
        break;
    case TASK_UNINTERRUPTIBLE:
        printk("UInt sleep");
        break;
    case TASK_STOPPED:
        printk("Stopped");
        break;
    case TASK_DYING:
        printk("Dying");
        break;
    default:
        ret = SCHED_OP(prn_state, state);
    }

    if ( ret != 0 )
        printk("Unknown");
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
