/****************************************************************************
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

/*#define WAKE_HISTO*/
/*#define BLOCKTIME_HISTO*/

#if defined(WAKE_HISTO)
#define BUCKETS 31
#elif defined(BLOCKTIME_HISTO)
#define BUCKETS 200
#endif

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

/* opt_sched: scheduler - default to Borrowed Virtual Time */
static char opt_sched[10] = "bvt";
string_param("sched", opt_sched);

#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */

/* Various timer handlers. */
static void s_timer_fn(unsigned long unused);
static void t_timer_fn(unsigned long unused);
static void dom_timer_fn(unsigned long data);

/* This is global for now so that private implementations can reach it */
struct schedule_data schedule_data[NR_CPUS];

extern struct scheduler sched_bvt_def;
static struct scheduler *schedulers[] = { 
    &sched_bvt_def,
    NULL
};

static void __enter_scheduler(void);

static struct scheduler ops;

#define SCHED_OP(fn, ...)                                 \
         (( ops.fn != NULL ) ? ops.fn( __VA_ARGS__ )      \
          : (typeof(ops.fn(__VA_ARGS__)))0 )

/* Per-CPU periodic timer sends an event to the currently-executing domain. */
static struct ac_timer t_timer[NR_CPUS]; 

void free_domain_struct(struct domain *d)
{
    int i;

    SCHED_OP(free_task, d);
    for (i = 0; i < MAX_VIRT_CPUS; i++)
        if ( d->exec_domain[i] )
            arch_free_exec_domain_struct(d->exec_domain[i]);

    xfree(d);
}

struct exec_domain *alloc_exec_domain_struct(struct domain *d,
                                             unsigned long vcpu)
{
    struct exec_domain *ed, *edc;

    ASSERT( d->exec_domain[vcpu] == NULL );

    if ( (ed = arch_alloc_exec_domain_struct()) == NULL )
        return NULL;

    memset(ed, 0, sizeof(*ed));

    d->exec_domain[vcpu] = ed;
    ed->domain = d;
    ed->eid = vcpu;

    if ( SCHED_OP(alloc_task, ed) < 0 )
        goto out;

    if (vcpu != 0) {
        ed->vcpu_info = &d->shared_info->vcpu_data[ed->eid];

        for_each_exec_domain(d, edc) {
            if (edc->ed_next_list == NULL || edc->ed_next_list->eid > vcpu)
                break;
        }
        ed->ed_next_list = edc->ed_next_list;
        edc->ed_next_list = ed;

        if (test_bit(EDF_CPUPINNED, &edc->ed_flags)) {
            ed->processor = (edc->processor + 1) % smp_num_cpus;
            set_bit(EDF_CPUPINNED, &ed->ed_flags);
        } else {
            ed->processor = (edc->processor + 1) % smp_num_cpus;  /* XXX */
        }
    }

    return ed;

 out:
    d->exec_domain[vcpu] = NULL;
    arch_free_exec_domain_struct(ed);

    return NULL;
}

struct domain *alloc_domain_struct(void)
{
    struct domain *d;

    if ( (d = xmalloc(struct domain)) == NULL )
        return NULL;
    
    memset(d, 0, sizeof(*d));

    if ( alloc_exec_domain_struct(d, 0) == NULL )
        goto out;

    return d;

 out:
    xfree(d);
    return NULL;
}

/*
 * Add and remove a domain
 */
void sched_add_domain(struct exec_domain *ed) 
{
    struct domain *d = ed->domain;

    /* Must be unpaused by control software to start execution. */
    set_bit(EDF_CTRLPAUSE, &ed->ed_flags);

    if ( d->id != IDLE_DOMAIN_ID )
    {
        /* Initialise the per-domain timer. */
        init_ac_timer(&ed->timer);
        ed->timer.cpu      = ed->processor;
        ed->timer.data     = (unsigned long)ed;
        ed->timer.function = &dom_timer_fn;
    }
    else
    {
        schedule_data[ed->processor].idle = ed;
    }

    SCHED_OP(add_task, ed);
    TRACE_2D(TRC_SCHED_DOM_ADD, d->id, ed->eid);
}

void sched_rem_domain(struct exec_domain *ed) 
{
    rem_ac_timer(&ed->timer);
    SCHED_OP(rem_task, ed);
    TRACE_2D(TRC_SCHED_DOM_REM, ed->domain->id, ed->eid);
}

void init_idle_task(void)
{
    if ( SCHED_OP(init_idle_task, current) < 0 )
        BUG();
}

void domain_sleep(struct exec_domain *ed)
{
    unsigned long flags;

    spin_lock_irqsave(&schedule_data[ed->processor].schedule_lock, flags);
    if ( likely(!domain_runnable(ed)) )
        SCHED_OP(sleep, ed);
    spin_unlock_irqrestore(&schedule_data[ed->processor].schedule_lock, flags);

    TRACE_2D(TRC_SCHED_SLEEP, ed->domain->id, ed->eid);
 
    /* Synchronous. */
    while ( test_bit(EDF_RUNNING, &ed->ed_flags) && !domain_runnable(ed) )
        cpu_relax();
}

void domain_wake(struct exec_domain *ed)
{
    unsigned long flags;

    spin_lock_irqsave(&schedule_data[ed->processor].schedule_lock, flags);
    if ( likely(domain_runnable(ed)) )
    {
        SCHED_OP(wake, ed);
#ifdef WAKE_HISTO
        ed->wokenup = NOW();
#endif
    }
    clear_bit(EDF_MIGRATED, &ed->ed_flags);
    spin_unlock_irqrestore(&schedule_data[ed->processor].schedule_lock, flags);

    TRACE_2D(TRC_SCHED_WAKE, ed->domain->id, ed->eid);
}

/* Block the currently-executing domain until a pertinent event occurs. */
long do_block(void)
{
    struct exec_domain *ed = current;

    ed->vcpu_info->evtchn_upcall_mask = 0;
    set_bit(EDF_BLOCKED, &ed->ed_flags);

    /* Check for events /after/ blocking: avoids wakeup waiting race. */
    if ( event_pending(ed) )
        clear_bit(EDF_BLOCKED, &ed->ed_flags);
    else
    {
        TRACE_2D(TRC_SCHED_BLOCK, ed->domain->id, ed->eid);
        __enter_scheduler();
    }

    return 0;
}

/* Voluntarily yield the processor for this allocation. */
static long do_yield(void)
{
    TRACE_2D(TRC_SCHED_YIELD, current->domain->id, current->eid);
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
        TRACE_3D(TRC_SCHED_SHUTDOWN, current->domain->id, current->eid,
                 (op >> SCHEDOP_reasonshift));
        domain_shutdown((u8)(op >> SCHEDOP_reasonshift));
        break;
    }

    default:
        ret = -ENOSYS;
    }

    return ret;
}

/* Per-domain one-shot-timer hypercall. */
long do_set_timer_op(s_time_t timeout)
{
    struct exec_domain *ed = current;

    rem_ac_timer(&ed->timer);
    
    if ( (ed->timer.expires = timeout) != 0 )
        add_ac_timer(&ed->timer);

    return 0;
}

/** sched_id - fetch ID of current scheduler */
int sched_id()
{
    return ops.sched_id;
}

long sched_ctl(struct sched_ctl_cmd *cmd)
{
    if ( cmd->sched_id != ops.sched_id )
        return -EINVAL;

    SCHED_OP(control, cmd);
    TRACE_0D(TRC_SCHED_CTL);
    return 0;
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

    spin_lock_irq(&schedule_data[d->exec_domain[0]->processor].schedule_lock);
    SCHED_OP(adjdom, d, cmd);
    spin_unlock_irq(&schedule_data[d->exec_domain[0]->processor].schedule_lock);

    TRACE_1D(TRC_SCHED_ADJDOM, d->id);
    put_domain(d);
    return 0;
}

/* 
 * The main function
 * - deschedule the current domain (scheduler independent).
 * - pick a new domain (scheduler dependent).
 */
static void __enter_scheduler(void)
{
    struct exec_domain *prev = current, *next = NULL;
    int                 cpu = prev->processor;
    s_time_t            now;
    struct task_slice   next_slice;
    s32                 r_time;     /* time for new dom to run */

    perfc_incrc(sched_run);
    
    spin_lock_irq(&schedule_data[cpu].schedule_lock);
 
    now = NOW();

    rem_ac_timer(&schedule_data[cpu].s_timer);
    
    ASSERT(!in_irq());

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
    set_bit(EDF_RUNNING, &next->ed_flags);

    spin_unlock_irq(&schedule_data[cpu].schedule_lock);

    if ( unlikely(prev == next) )
        return;
    
    perfc_incrc(sched_ctx);

#if defined(WAKE_HISTO)
    if ( !is_idle_task(next->domain) && next->wokenup ) {
        ulong diff = (ulong)(now - next->wokenup);
        diff /= (ulong)MILLISECS(1);
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
    next->wokenup = (s_time_t)0;
#elif defined(BLOCKTIME_HISTO)
    prev->lastdeschd = now;
    if ( !is_idle_task(next->domain) )
    {
        ulong diff = (ulong)((now - next->lastdeschd) / MILLISECS(10));
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
#endif

    prev->sleep_tick = schedule_data[cpu].tick;

    /* Ensure that the domain has an up-to-date time base. */
    if ( !is_idle_task(next->domain) )
    {
        update_dom_time(next);
        if ( next->sleep_tick != schedule_data[cpu].tick )
            send_guest_virq(next, VIRQ_TIMER);
    }

    TRACE_4D(TRC_SCHED_SWITCH,
             prev->domain->id, prev->eid,
             next->domain->id, next->eid);

    context_switch(prev, next);
}

/* No locking needed -- pointer comparison is safe :-) */
int idle_cpu(int cpu)
{
    struct exec_domain *p = schedule_data[cpu].curr;
    return p == idle_task[cpu];
}


/****************************************************************************
 * Timers: the scheduler utilises a number of timers
 * - s_timer: per CPU timer for preemption and scheduling decisions
 * - t_timer: per CPU periodic timer to send timer interrupt to current dom
 * - dom_timer: per domain timer to specifiy timeout values
 ****************************************************************************/

/* The scheduler timer: force a run through the scheduler */
static void s_timer_fn(unsigned long unused)
{
    raise_softirq(SCHEDULE_SOFTIRQ);
    perfc_incrc(sched_irq);
}

/* Periodic tick timer: send timer event to current domain */
static void t_timer_fn(unsigned long unused)
{
    struct exec_domain *ed  = current;
    unsigned int        cpu = ed->processor;

    schedule_data[cpu].tick++;

    if ( !is_idle_task(ed->domain) )
    {
        update_dom_time(ed);
        send_guest_virq(ed, VIRQ_TIMER);
    }

    page_scrub_schedule_work();

    t_timer[cpu].expires = NOW() + MILLISECS(10);
    add_ac_timer(&t_timer[cpu]);
}

/* Domain timer function, sends a virtual timer interrupt to domain */
static void dom_timer_fn(unsigned long data)
{
    struct exec_domain *ed = (struct exec_domain *)data;

    update_dom_time(ed);
    send_guest_virq(ed, VIRQ_TIMER);
}

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    int i;

    open_softirq(SCHEDULE_SOFTIRQ, __enter_scheduler);

    for ( i = 0; i < NR_CPUS; i++ )
    {
        spin_lock_init(&schedule_data[i].schedule_lock);
        schedule_data[i].curr = &idle0_exec_domain;
        
        init_ac_timer(&schedule_data[i].s_timer);
        schedule_data[i].s_timer.cpu      = i;
        schedule_data[i].s_timer.data     = 2;
        schedule_data[i].s_timer.function = &s_timer_fn;

        init_ac_timer(&t_timer[i]);
        t_timer[i].cpu      = i;
        t_timer[i].data     = 3;
        t_timer[i].function = &t_timer_fn;
    }

    schedule_data[0].idle = &idle0_exec_domain;

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
}


void dump_runq(unsigned char key)
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
void print_sched_histo(unsigned char key)
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
void reset_sched_histo(unsigned char key)
{
    int i, j;
    for ( j = 0; j < smp_num_cpus; j++ )
        for ( i=0; i < BUCKETS; i++ ) 
            schedule_data[j].hist[i] = 0;
}
#else
void print_sched_histo(unsigned char key) { }
void reset_sched_histo(unsigned char key) { }
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
