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
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <public/sched_ctl.h>

/*#define WAKE_HISTO*/
/*#define BLOCKTIME_HISTO*/

#if defined(WAKE_HISTO)
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

/* Various timer handlers. */
static void s_timer_fn(unsigned long unused);
static void t_timer_fn(unsigned long unused);
static void dom_timer_fn(unsigned long data);
static void fallback_timer_fn(unsigned long unused);

/* This is global for now so that private implementations can reach it */
schedule_data_t schedule_data[NR_CPUS];

extern struct scheduler sched_bvt_def;
extern struct scheduler sched_rrobin_def;
extern struct scheduler sched_atropos_def;
static struct scheduler *schedulers[] = { 
    &sched_bvt_def,
    &sched_rrobin_def,
    &sched_atropos_def,
    NULL
};

/* Operations for the current scheduler. */
static struct scheduler ops;

#define SCHED_OP(fn, ...)                                 \
         (( ops.fn != NULL ) ? ops.fn( __VA_ARGS__ )      \
          : (typeof(ops.fn(__VA_ARGS__)))0 )

/* Per-CPU periodic timer sends an event to the currently-executing domain. */
static struct ac_timer t_timer[NR_CPUS]; 

/*
 * Per-CPU timer which ensures that even guests with very long quantums get
 * their time-of-day state updated often enough to avoid wrapping.
 */
static struct ac_timer fallback_timer[NR_CPUS];

extern xmem_cache_t *domain_struct_cachep;

void free_domain_struct(struct domain *d)
{
    SCHED_OP(free_task, d);
    xmem_cache_free(domain_struct_cachep, d);
}

struct domain *alloc_domain_struct(void)
{
    struct domain *d;

    if ( (d = xmem_cache_alloc(domain_struct_cachep)) == NULL )
        return NULL;
    
    memset(d, 0, sizeof(*d));

    if ( SCHED_OP(alloc_task, d) < 0 )
    {
        xmem_cache_free(domain_struct_cachep, d);
        return NULL;
    }

    return d;
}

/*
 * Add and remove a domain
 */
void sched_add_domain(struct domain *d) 
{
    /* Must be unpaused by control software to start execution. */
    set_bit(DF_CTRLPAUSE, &d->flags);

    if ( d->id != IDLE_DOMAIN_ID )
    {
        /* Initialise the per-domain timer. */
        init_ac_timer(&d->timer);
        d->timer.cpu      = d->processor;
        d->timer.data     = (unsigned long)d;
        d->timer.function = &dom_timer_fn;
    }
    else
    {
        schedule_data[d->processor].idle = d;
    }

    SCHED_OP(add_task, d);

    TRACE_2D(TRC_SCHED_DOM_ADD, d->id, d);
}

void sched_rem_domain(struct domain *d) 
{
    rem_ac_timer(&d->timer);
    SCHED_OP(rem_task, d);
    TRACE_2D(TRC_SCHED_DOM_REM, d->id, d);
}

void init_idle_task(void)
{
    if ( SCHED_OP(init_idle_task, current) < 0 )
        BUG();
}

void domain_sleep(struct domain *d)
{
    unsigned long flags;

    spin_lock_irqsave(&schedule_data[d->processor].schedule_lock, flags);

    if ( likely(!domain_runnable(d)) )
        SCHED_OP(sleep, d);

    spin_unlock_irqrestore(&schedule_data[d->processor].schedule_lock, flags);
 
    /* Synchronous. */
    while ( test_bit(DF_RUNNING, &d->flags) && !domain_runnable(d) )
    {
        smp_mb();
        cpu_relax();
    }
}

void domain_wake(struct domain *d)
{
    unsigned long flags;

    spin_lock_irqsave(&schedule_data[d->processor].schedule_lock, flags);

    if ( likely(domain_runnable(d)) )
    {
        TRACE_2D(TRC_SCHED_WAKE, d->id, d);
        SCHED_OP(wake, d);
#ifdef WAKE_HISTO
        d->wokenup = NOW();
#endif
    }
    
    clear_bit(DF_MIGRATED, &d->flags);
    
    spin_unlock_irqrestore(&schedule_data[d->processor].schedule_lock, flags);
}

/* Block the currently-executing domain until a pertinent event occurs. */
long do_block(void)
{
    ASSERT(current->id != IDLE_DOMAIN_ID);
    current->shared_info->vcpu_data[0].evtchn_upcall_mask = 0;
    set_bit(DF_BLOCKED, &current->flags);
    TRACE_2D(TRC_SCHED_BLOCK, current->id, current);
    __enter_scheduler();
    return 0;
}

/* Voluntarily yield the processor for this allocation. */
static long do_yield(void)
{
    TRACE_2D(TRC_SCHED_YIELD, current->id, current);
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

    case SCHEDOP_shutdown:
    {
        domain_shutdown((u8)(op >> SCHEDOP_reasonshift));
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
    struct domain *p = current;

    rem_ac_timer(&p->timer);
    
    if ( (timeout_hi != 0) || (timeout_lo != 0) )
    {
        p->timer.expires = ((s_time_t)timeout_hi<<32) | ((s_time_t)timeout_lo);
        add_ac_timer(&p->timer);
    }

    TRACE_4D(TRC_SCHED_SET_TIMER, p->id, p, timeout_hi, timeout_lo);

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
    struct domain *d;

    if ( cmd->sched_id != ops.sched_id )
        return -EINVAL;

    if ( cmd->direction != SCHED_INFO_PUT && cmd->direction != SCHED_INFO_GET )
        return -EINVAL;

    d = find_domain_by_id(cmd->domain);
    if ( d == NULL )
        return -ESRCH;

    TRACE_1D(TRC_SCHED_ADJDOM, d->id);

    spin_lock_irq(&schedule_data[d->processor].schedule_lock);
    SCHED_OP(adjdom, d, cmd);
    spin_unlock_irq(&schedule_data[d->processor].schedule_lock);

    put_domain(d);
    return 0;
}

/* 
 * The main function
 * - deschedule the current domain (scheduler independent).
 * - pick a new domain (scheduler dependent).
 */
void __enter_scheduler(void)
{
    struct domain *prev = current, *next = NULL;
    int                 cpu = prev->processor;
    s_time_t            now;
    task_slice_t        next_slice;
    s32                 r_time;     /* time for new dom to run */

    cleanup_writable_pagetable(
        prev, PTWR_CLEANUP_ACTIVE | PTWR_CLEANUP_INACTIVE);

    perfc_incrc(sched_run);
    
    spin_lock_irq(&schedule_data[cpu].schedule_lock);
 
    now = NOW();

    rem_ac_timer(&schedule_data[cpu].s_timer);
    
    ASSERT(!in_irq());

    if ( test_bit(DF_BLOCKED, &prev->flags) )
    {
        /* This check is needed to avoid a race condition. */
        if ( event_pending(prev) )
            clear_bit(DF_BLOCKED, &prev->flags);
        else
            SCHED_OP(do_block, prev);
    }

    prev->cpu_time += now - prev->lastschd;

    /* get policy-specific decision on scheduling... */
    next_slice = ops.do_schedule(now);

    r_time = next_slice.time;
    next = next_slice.task;
    
    schedule_data[cpu].curr = next;
    
    next->lastschd = now;

    /* reprogramm the timer */
    schedule_data[cpu].s_timer.expires  = now + r_time;
    add_ac_timer(&schedule_data[cpu].s_timer);

    /* Must be protected by the schedule_lock! */
    set_bit(DF_RUNNING, &next->flags);

    spin_unlock_irq(&schedule_data[cpu].schedule_lock);

    /* Ensure that the domain has an up-to-date time base. */
    if ( !is_idle_task(next) )
        update_dom_time(next->shared_info);

    if ( unlikely(prev == next) )
        return;
    
    perfc_incrc(sched_ctx);

#if defined(WAKE_HISTO)
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

    TRACE_2D(TRC_SCHED_SWITCH, next->id, next);

    switch_to(prev, next);

    /*
     * We do this late on because it doesn't need to be protected by the
     * schedule_lock, and because we want this to be the very last use of
     * 'prev' (after this point, a dying domain's info structure may be freed
     * without warning). 
     */
    clear_bit(DF_RUNNING, &prev->flags);

    /* Mark a timer event for the newly-scheduled domain. */
    if ( !is_idle_task(next) )
        send_guest_virq(next, VIRQ_TIMER);
    
    schedule_tail(next);

    BUG();
}

/* No locking needed -- pointer comparison is safe :-) */
int idle_cpu(int cpu)
{
    struct domain *p = schedule_data[cpu].curr;
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
    raise_softirq(SCHEDULE_SOFTIRQ);
    perfc_incrc(sched_irq);
}

/* Periodic tick timer: send timer event to current domain*/
static void t_timer_fn(unsigned long unused)
{
    struct domain *p = current;

    TRACE_0D(TRC_SCHED_T_TIMER_FN);

    if ( !is_idle_task(p) ) {
        update_dom_time(p->shared_info);
        send_guest_virq(p, VIRQ_TIMER);
    }

    t_timer[p->processor].expires = NOW() + MILLISECS(10);
    add_ac_timer(&t_timer[p->processor]);
}

/* Domain timer function, sends a virtual timer interrupt to domain */
static void dom_timer_fn(unsigned long data)
{
    struct domain *p = (struct domain *)data;
    TRACE_0D(TRC_SCHED_DOM_TIMER_FN);
    update_dom_time(p->shared_info);
    send_guest_virq(p, VIRQ_TIMER);
}


/* Fallback timer to ensure guests get time updated 'often enough'. */
static void fallback_timer_fn(unsigned long unused)
{
    struct domain *p = current;

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

    open_softirq(SCHEDULE_SOFTIRQ, __enter_scheduler);

    for ( i = 0; i < NR_CPUS; i++ )
    {
        spin_lock_init(&schedule_data[i].schedule_lock);
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


void dump_runq(u_char key, void *dev_id, struct xen_regs *regs)
{
    s_time_t      now = NOW();
    int           i;
    unsigned long flags;

    local_irq_save(flags);

    printk("Scheduler: %s (%s)\n", ops.name, ops.opt_name);
    SCHED_OP(dump_settings);
    printk("NOW=0x%08X%08X\n",  (u32)(now>>32), (u32)now); 

    for ( i = 0; i < smp_num_cpus; i++ )
    {
        spin_lock(&schedule_data[i].schedule_lock);
        printk("CPU[%02d] ", i);
        SCHED_OP(dump_cpu_state,i);
        spin_unlock(&schedule_data[i].schedule_lock);
    }

    local_irq_restore(flags);
}

#if defined(WAKE_HISTO) || defined(BLOCKTIME_HISTO)
void print_sched_histo(u_char key, void *dev_id, struct xen_regs *regs)
{
    int i, j, k;
    for ( k = 0; k < smp_num_cpus; k++ )
    {
        j = 0;
        printf ("CPU[%02d]: scheduler latency histogram (ms:[count])\n", k);
        for ( i = 0; i < BUCKETS; i++ )
        {
            if ( schedule_data[k].hist[i] != 0 )
            {
                if ( i < BUCKETS-1 )
                    printk("%2d:[%7u]    ", i, schedule_data[k].hist[i]);
                else
                    printk(" >:[%7u]    ", schedule_data[k].hist[i]);
                if ( !(++j % 5) )
                    printk("\n");
            }
        }
        printk("\n");
    }
      
}
void reset_sched_histo(u_char key, void *dev_id, struct xen_regs *regs)
{
    int i, j;
    for ( j = 0; j < smp_num_cpus; j++ )
        for ( i=0; i < BUCKETS; i++ ) 
            schedule_data[j].hist[i] = 0;
}
#else
void print_sched_histo(u_char key, void *dev_id, struct xen_regs *regs)
{
}
void reset_sched_histo(u_char key, void *dev_id, struct xen_regs *regs)
{
}
#endif
