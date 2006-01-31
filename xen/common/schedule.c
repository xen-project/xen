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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <xen/mm.h>
#include <public/sched.h>
#include <public/sched_ctl.h>

extern void arch_getdomaininfo_ctxt(struct vcpu *,
                                    struct vcpu_guest_context *);
/* opt_sched: scheduler - default to SEDF */
static char opt_sched[10] = "sedf";
string_param("sched", opt_sched);

/*#define WAKE_HISTO*/
/*#define BLOCKTIME_HISTO*/
#if defined(WAKE_HISTO)
#define BUCKETS 31
#elif defined(BLOCKTIME_HISTO)
#define BUCKETS 200
#endif

#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */

/* Various timer handlers. */
static void s_timer_fn(void *unused);
static void t_timer_fn(void *unused);
static void dom_timer_fn(void *data);

/* This is global for now so that private implementations can reach it */
struct schedule_data schedule_data[NR_CPUS];

extern struct scheduler sched_bvt_def;
extern struct scheduler sched_sedf_def;
static struct scheduler *schedulers[] = { 
    &sched_bvt_def,
    &sched_sedf_def,
    NULL
};

static void __enter_scheduler(void);

static struct scheduler ops;

#define SCHED_OP(fn, ...)                                 \
         (( ops.fn != NULL ) ? ops.fn( __VA_ARGS__ )      \
          : (typeof(ops.fn(__VA_ARGS__)))0 )

/* Per-CPU periodic timer sends an event to the currently-executing domain. */
static struct timer t_timer[NR_CPUS]; 

struct domain *alloc_domain(void)
{
    struct domain *d;

    if ( (d = xmalloc(struct domain)) != NULL )
        memset(d, 0, sizeof(*d));

    return d;
}

void free_domain(struct domain *d)
{
    struct vcpu *v;
    int i;

    for_each_vcpu ( d, v )
        sched_rem_domain(v);

    SCHED_OP(free_task, d);

    for ( i = MAX_VIRT_CPUS-1; i >= 0; i-- )
        if ( (v = d->vcpu[i]) != NULL )
            free_vcpu_struct(v);

    xfree(d);
}

struct vcpu *alloc_vcpu(
    struct domain *d, unsigned int vcpu_id, unsigned int cpu_id)
{
    struct vcpu *v;

    BUG_ON(d->vcpu[vcpu_id] != NULL);

    if ( (v = alloc_vcpu_struct(d, vcpu_id)) == NULL )
        return NULL;

    v->domain = d;
    v->vcpu_id = vcpu_id;
    v->processor = cpu_id;
    atomic_set(&v->pausecnt, 0);
    v->vcpu_info = &d->shared_info->vcpu_info[vcpu_id];

    v->cpu_affinity = is_idle_domain(d) ?
        cpumask_of_cpu(cpu_id) : CPU_MASK_ALL;

    if ( (vcpu_id != 0) && !is_idle_domain(d) )
        set_bit(_VCPUF_down, &v->vcpu_flags);

    if ( SCHED_OP(alloc_task, v) < 0 )
    {
        free_vcpu_struct(v);
        return NULL;
    }

    d->vcpu[vcpu_id] = v;
    if ( vcpu_id != 0 )
        d->vcpu[v->vcpu_id-1]->next_in_list = v;

    sched_add_domain(v);

    return v;
}

void sched_add_domain(struct vcpu *v) 
{
    /* Initialise the per-domain timer. */
    init_timer(&v->timer, dom_timer_fn, v, v->processor);

    if ( is_idle_vcpu(v) )
    {
        schedule_data[v->processor].curr = v;
        schedule_data[v->processor].idle = v;
        set_bit(_VCPUF_running, &v->vcpu_flags);
    }

    SCHED_OP(add_task, v);
    TRACE_2D(TRC_SCHED_DOM_ADD, v->domain->domain_id, v->vcpu_id);
}

void sched_rem_domain(struct vcpu *v) 
{
    kill_timer(&v->timer);
    SCHED_OP(rem_task, v);
    TRACE_2D(TRC_SCHED_DOM_REM, v->domain->domain_id, v->vcpu_id);
}

void vcpu_sleep_nosync(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);
    if ( likely(!vcpu_runnable(v)) )
        SCHED_OP(sleep, v);
    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_SLEEP, v->domain->domain_id, v->vcpu_id);
}

void vcpu_sleep_sync(struct vcpu *v)
{
    vcpu_sleep_nosync(v);

    while ( !vcpu_runnable(v) && test_bit(_VCPUF_running, &v->vcpu_flags) )
        cpu_relax();

    sync_vcpu_execstate(v);
}

void vcpu_wake(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);
    if ( likely(vcpu_runnable(v)) )
    {
        SCHED_OP(wake, v);
        v->wokenup = NOW();
    }
    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_WAKE, v->domain->domain_id, v->vcpu_id);
}

int vcpu_set_affinity(struct vcpu *v, cpumask_t *affinity)
{
    cpumask_t online_affinity;

    cpus_and(online_affinity, *affinity, cpu_online_map);
    if ( cpus_empty(online_affinity) )
        return -EINVAL;

    return SCHED_OP(set_affinity, v, affinity);
}

/* Block the currently-executing domain until a pertinent event occurs. */
static long do_block(void)
{
    struct vcpu *v = current;

    v->vcpu_info->evtchn_upcall_mask = 0;
    set_bit(_VCPUF_blocked, &v->vcpu_flags);

    /* Check for events /after/ blocking: avoids wakeup waiting race. */
    if ( event_pending(v) )
    {
        clear_bit(_VCPUF_blocked, &v->vcpu_flags);
    }
    else
    {
        TRACE_2D(TRC_SCHED_BLOCK, v->domain->domain_id, v->vcpu_id);
        __enter_scheduler();
    }

    return 0;
}

/* Voluntarily yield the processor for this allocation. */
static long do_yield(void)
{
    TRACE_2D(TRC_SCHED_YIELD, current->domain->domain_id, current->vcpu_id);
    __enter_scheduler();
    return 0;
}

long do_sched_op(int cmd, unsigned long arg)
{
    long ret = 0;

    switch ( cmd )
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
        TRACE_3D(TRC_SCHED_SHUTDOWN,
                 current->domain->domain_id, current->vcpu_id, arg);
        domain_shutdown(current->domain, (u8)arg);
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
    struct vcpu *v = current;

    if ( timeout == 0 )
        stop_timer(&v->timer);
    else
        set_timer(&v->timer, timeout);

    return 0;
}

/* sched_id - fetch ID of current scheduler */
int sched_id(void)
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
    struct vcpu *v, *vme;
    
    if ( (cmd->sched_id != ops.sched_id) ||
         ((cmd->direction != SCHED_INFO_PUT) &&
          (cmd->direction != SCHED_INFO_GET)) )
        return -EINVAL;

    d = find_domain_by_id(cmd->domain);
    if ( d == NULL )
        return -ESRCH;

    /*
     * Most VCPUs we can simply pause. If we are adjusting this VCPU then
     * we acquire the local schedule_lock to guard against concurrent updates.
     *
     * We only acquire the local schedule lock after we have paused all other
     * VCPUs in this domain. There are two reasons for this:
     * 1- We don't want to hold up interrupts as pausing a VCPU can
     *    trigger a tlb shootdown.
     * 2- Pausing other VCPUs involves briefly locking the schedule
     *    lock of the CPU they are running on. This CPU could be the
     *    same as ours.
     */
    vme = NULL;

    for_each_vcpu ( d, v )
    {
        if ( v == current )
            vme = current;
        else
            vcpu_pause(v);
    }

    if (vme)
            vcpu_schedule_lock_irq(vme);

    SCHED_OP(adjdom, d, cmd);
    TRACE_1D(TRC_SCHED_ADJDOM, d->domain_id);

    if (vme)
            vcpu_schedule_unlock_irq(vme);

    for_each_vcpu ( d, v )
    {
        if ( v != vme )
            vcpu_unpause(v);
    }

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
    struct vcpu        *prev = current, *next = NULL;
    int                 cpu = smp_processor_id();
    s_time_t            now = NOW();
    struct task_slice   next_slice;
    s32                 r_time;     /* time for new dom to run */

    ASSERT(!in_irq());

    perfc_incrc(sched_run);

    spin_lock_irq(&schedule_data[cpu].schedule_lock);

    stop_timer(&schedule_data[cpu].s_timer);
    
    prev->cpu_time += now - prev->lastschd;

    /* get policy-specific decision on scheduling... */
    next_slice = ops.do_schedule(now);

    r_time = next_slice.time;
    next = next_slice.task;

    schedule_data[cpu].curr = next;
    
    next->lastschd = now;

    set_timer(&schedule_data[cpu].s_timer, now + r_time);

    if ( unlikely(prev == next) )
    {
        spin_unlock_irq(&schedule_data[cpu].schedule_lock);
        return continue_running(prev);
    }

    TRACE_2D(TRC_SCHED_SWITCH_INFPREV,
             prev->domain->domain_id, now - prev->lastschd);
    TRACE_3D(TRC_SCHED_SWITCH_INFNEXT,
             next->domain->domain_id, now - next->wokenup, r_time);

    /*
     * Logic of wokenup field in domain struct:
     * Used to calculate "waiting time", which is the time that a domain
     * spends being "runnable", but not actually running. wokenup is set
     * set whenever a domain wakes from sleeping. However, if wokenup is not
     * also set here then a preempted runnable domain will get a screwed up
     * "waiting time" value next time it is scheduled.
     */
    prev->wokenup = now;

#if defined(WAKE_HISTO)
    if ( !is_idle_vcpu(next) && next->wokenup )
    {
        ulong diff = (ulong)(now - next->wokenup);
        diff /= (ulong)MILLISECS(1);
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
    next->wokenup = (s_time_t)0;
#elif defined(BLOCKTIME_HISTO)
    prev->lastdeschd = now;
    if ( !is_idle_vcpu(next) )
    {
        ulong diff = (ulong)((now - next->lastdeschd) / MILLISECS(10));
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
#endif

    ASSERT(!test_bit(_VCPUF_running, &next->vcpu_flags));
    set_bit(_VCPUF_running, &next->vcpu_flags);

    spin_unlock_irq(&schedule_data[cpu].schedule_lock);

    perfc_incrc(sched_ctx);

    prev->sleep_tick = schedule_data[cpu].tick;

    /* Ensure that the domain has an up-to-date time base. */
    if ( !is_idle_vcpu(next) )
    {
        update_dom_time(next);
        if ( next->sleep_tick != schedule_data[cpu].tick )
            send_guest_virq(next, VIRQ_TIMER);
    }

    TRACE_4D(TRC_SCHED_SWITCH,
             prev->domain->domain_id, prev->vcpu_id,
             next->domain->domain_id, next->vcpu_id);

    context_switch(prev, next);
}


/****************************************************************************
 * Timers: the scheduler utilises a number of timers
 * - s_timer: per CPU timer for preemption and scheduling decisions
 * - t_timer: per CPU periodic timer to send timer interrupt to current dom
 * - dom_timer: per domain timer to specifiy timeout values
 ****************************************************************************/

/* The scheduler timer: force a run through the scheduler */
static void s_timer_fn(void *unused)
{
    raise_softirq(SCHEDULE_SOFTIRQ);
    perfc_incrc(sched_irq);
}

/* Periodic tick timer: send timer event to current domain */
static void t_timer_fn(void *unused)
{
    struct vcpu  *v   = current;
    unsigned int  cpu = smp_processor_id();

    schedule_data[cpu].tick++;

    if ( !is_idle_vcpu(v) )
    {
        update_dom_time(v);
        send_guest_virq(v, VIRQ_TIMER);
    }

    page_scrub_schedule_work();

    set_timer(&t_timer[cpu], NOW() + MILLISECS(10));
}

/* Domain timer function, sends a virtual timer interrupt to domain */
static void dom_timer_fn(void *data)
{
    struct vcpu *v = data;

    update_dom_time(v);
    send_guest_virq(v, VIRQ_TIMER);
}

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    int i, rc;

    open_softirq(SCHEDULE_SOFTIRQ, __enter_scheduler);

    for ( i = 0; i < NR_CPUS; i++ )
    {
        spin_lock_init(&schedule_data[i].schedule_lock);
        init_timer(&schedule_data[i].s_timer, s_timer_fn, NULL, i);
        init_timer(&t_timer[i], t_timer_fn, NULL, i);
    }

    for ( i = 0; schedulers[i] != NULL; i++ )
    {
        ops = *schedulers[i];
        if ( strcmp(ops.opt_name, opt_sched) == 0 )
            break;
    }
    
    if ( schedulers[i] == NULL )
        printk("Could not find scheduler: %s\n", opt_sched);

    printk("Using scheduler: %s (%s)\n", ops.name, ops.opt_name);

    if ( idle_vcpu[0] != NULL )
    {
        schedule_data[0].curr = idle_vcpu[0];
        schedule_data[0].idle = idle_vcpu[0];

        rc = SCHED_OP(alloc_task, idle_vcpu[0]);
        BUG_ON(rc < 0);

        sched_add_domain(idle_vcpu[0]);
    }
}

/*
 * Start a scheduler for each CPU
 * This has to be done *after* the timers, e.g., APICs, have been initialised
 */
void schedulers_start(void) 
{   
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

    for_each_online_cpu ( i )
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
    for_each_online_cpu ( k )
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
    for ( j = 0; j < NR_CPUS; j++ )
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
