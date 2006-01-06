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
#include <xen/ac_timer.h>
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
static struct ac_timer t_timer[NR_CPUS]; 

void free_domain(struct domain *d)
{
    int i;

    SCHED_OP(free_task, d);

    for ( i = MAX_VIRT_CPUS-1; i >= 0; i-- )
        if ( d->vcpu[i] != NULL )
            free_vcpu_struct(d->vcpu[i]);

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

    v->cpu_affinity = is_idle_domain(d) ?
        cpumask_of_cpu(cpu_id) : CPU_MASK_ALL;

    d->vcpu[vcpu_id] = v;

    if ( SCHED_OP(alloc_task, v) < 0 )
    {
        d->vcpu[vcpu_id] = NULL;
        free_vcpu_struct(v);
        return NULL;
    }

    sched_add_domain(v);

    if ( vcpu_id != 0 )
    {
        v->vcpu_info = &d->shared_info->vcpu_info[vcpu_id];
        d->vcpu[v->vcpu_id-1]->next_in_list = v;
        set_bit(_VCPUF_down, &v->vcpu_flags);
    }

    return v;
}

struct domain *alloc_domain(void)
{
    struct domain *d;

    if ( (d = xmalloc(struct domain)) != NULL )
        memset(d, 0, sizeof(*d));

    return d;
}

/*
 * Add and remove a domain
 */
void sched_add_domain(struct vcpu *v) 
{
    struct domain *d = v->domain;

    /* Initialise the per-domain timer. */
    init_ac_timer(&v->timer, dom_timer_fn, v, v->processor);

    if ( is_idle_domain(d) )
    {
        schedule_data[v->processor].curr = v;
        schedule_data[v->processor].idle = v;
        set_bit(_VCPUF_running, &v->vcpu_flags);
    }

    SCHED_OP(add_task, v);
    TRACE_2D(TRC_SCHED_DOM_ADD, d->domain_id, v->vcpu_id);
}

void sched_rem_domain(struct vcpu *v) 
{
    rem_ac_timer(&v->timer);
    SCHED_OP(rem_task, v);
    TRACE_2D(TRC_SCHED_DOM_REM, v->domain->domain_id, v->vcpu_id);
}

void vcpu_sleep_nosync(struct vcpu *v)
{
    unsigned long flags;

    spin_lock_irqsave(&schedule_data[v->processor].schedule_lock, flags);
    if ( likely(!domain_runnable(v)) )
        SCHED_OP(sleep, v);
    spin_unlock_irqrestore(&schedule_data[v->processor].schedule_lock, flags);

    TRACE_2D(TRC_SCHED_SLEEP, v->domain->domain_id, v->vcpu_id);
} 

void vcpu_sleep_sync(struct vcpu *v)
{
    vcpu_sleep_nosync(v);

    /*
     * We can be sure that the VCPU is finally descheduled after the running
     * flag is cleared and the scheduler lock is released. We also check that
     * the domain continues to be unrunnable, in case someone else wakes it.
     */
    while ( !domain_runnable(v) &&
            (test_bit(_VCPUF_running, &v->vcpu_flags) ||
             spin_is_locked(&schedule_data[v->processor].schedule_lock)) )
        cpu_relax();

    sync_vcpu_execstate(v);
}

void vcpu_wake(struct vcpu *v)
{
    unsigned long flags;

    spin_lock_irqsave(&schedule_data[v->processor].schedule_lock, flags);
    if ( likely(domain_runnable(v)) )
    {
        SCHED_OP(wake, v);
        v->wokenup = NOW();
    }
    clear_bit(_VCPUF_cpu_migrated, &v->vcpu_flags);
    spin_unlock_irqrestore(&schedule_data[v->processor].schedule_lock, flags);

    TRACE_2D(TRC_SCHED_WAKE, v->domain->domain_id, v->vcpu_id);
}

/* Block the currently-executing domain until a pertinent event occurs. */
long do_block(void)
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
        rem_ac_timer(&v->timer);
    else
        set_ac_timer(&v->timer, timeout);

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
    struct vcpu *v;
    int cpu;
#if NR_CPUS <=32
    unsigned long have_lock;
 #else
    unsigned long long have_lock;
#endif
    int succ;

    #define __set_cpu_bit(cpu, data) data |= ((typeof(data))1)<<cpu
    #define __get_cpu_bit(cpu, data) (data & ((typeof(data))1)<<cpu)
    #define __clear_cpu_bits(data) data = ((typeof(data))0)
    
    if ( cmd->sched_id != ops.sched_id )
        return -EINVAL;
    
    if ( cmd->direction != SCHED_INFO_PUT && cmd->direction != SCHED_INFO_GET )
        return -EINVAL;

    d = find_domain_by_id(cmd->domain);
    if ( d == NULL )
        return -ESRCH;

    /* acquire locks on all CPUs on which vcpus of this domain run */
    do {
        succ = 0;
        __clear_cpu_bits(have_lock);
        for_each_vcpu(d, v) {
            cpu = v->processor;
            if (!__get_cpu_bit(cpu, have_lock)) {
                /* if we don't have a lock on this CPU: acquire it*/
                if (spin_trylock(&schedule_data[cpu].schedule_lock)) {
                    /*we have this lock!*/
                    __set_cpu_bit(cpu, have_lock);
                    succ = 1;
                } else {
                    /*we didn,t get this lock -> free all other locks too!*/
                    for (cpu = 0; cpu < NR_CPUS; cpu++)
                        if (__get_cpu_bit(cpu, have_lock))
                            spin_unlock(&schedule_data[cpu].schedule_lock);
                    /* and start from the beginning! */
                    succ = 0;
                    /* leave the "for_each_domain_loop" */
                    break;
                }
            }
        }
    } while ( !succ );

    SCHED_OP(adjdom, d, cmd);

    for (cpu = 0; cpu < NR_CPUS; cpu++)
        if (__get_cpu_bit(cpu, have_lock))
            spin_unlock(&schedule_data[cpu].schedule_lock);
    __clear_cpu_bits(have_lock);

    TRACE_1D(TRC_SCHED_ADJDOM, d->domain_id);
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
    struct vcpu *prev = current, *next = NULL;
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

    set_ac_timer(&schedule_data[cpu].s_timer, now + r_time);

    if ( unlikely(prev == next) )
    {
        spin_unlock_irq(&schedule_data[cpu].schedule_lock);
        return continue_running(prev);
    }

    TRACE_2D(TRC_SCHED_SWITCH_INFPREV,
             prev->domain->domain_id, now - prev->lastschd);
    TRACE_3D(TRC_SCHED_SWITCH_INFNEXT,
             next->domain->domain_id, now - next->wokenup, r_time);

    clear_bit(_VCPUF_running, &prev->vcpu_flags);
    set_bit(_VCPUF_running, &next->vcpu_flags);

    perfc_incrc(sched_ctx);

    /*
     * Logic of wokenup field in domain struct:
     * Used to calculate "waiting time", which is the time that a domain
     * spends being "runnable", but not actually running. wokenup is set
     * set whenever a domain wakes from sleeping. However, if wokenup is not
     * also set here then a preempted runnable domain will get a screwed up
     * "waiting time" value next time it is scheduled.
     */
    prev->wokenup = NOW();

#if defined(WAKE_HISTO)
    if ( !is_idle_domain(next->domain) && next->wokenup )
    {
        ulong diff = (ulong)(now - next->wokenup);
        diff /= (ulong)MILLISECS(1);
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
    next->wokenup = (s_time_t)0;
#elif defined(BLOCKTIME_HISTO)
    prev->lastdeschd = now;
    if ( !is_idle_domain(next->domain) )
    {
        ulong diff = (ulong)((now - next->lastdeschd) / MILLISECS(10));
        if (diff <= BUCKETS-2)  schedule_data[cpu].hist[diff]++;
        else                    schedule_data[cpu].hist[BUCKETS-1]++;
    }
#endif

    prev->sleep_tick = schedule_data[cpu].tick;

    /* Ensure that the domain has an up-to-date time base. */
    if ( !is_idle_domain(next->domain) )
    {
        update_dom_time(next);
        if ( next->sleep_tick != schedule_data[cpu].tick )
            send_guest_virq(next, VIRQ_TIMER);
    }

    TRACE_4D(TRC_SCHED_SWITCH,
             prev->domain->domain_id, prev->vcpu_id,
             next->domain->domain_id, next->vcpu_id);

    context_switch(prev, next);

    spin_unlock_irq(&schedule_data[cpu].schedule_lock);

    context_switch_finalise(next);
}

/* No locking needed -- pointer comparison is safe :-) */
int idle_cpu(int cpu)
{
    struct vcpu *p = schedule_data[cpu].curr;
    return p == idle_domain[cpu];
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
    struct vcpu  *v  = current;
    unsigned int  cpu = v->processor;

    schedule_data[cpu].tick++;

    if ( !is_idle_domain(v->domain) )
    {
        update_dom_time(v);
        send_guest_virq(v, VIRQ_TIMER);
    }

    page_scrub_schedule_work();

    set_ac_timer(&t_timer[cpu], NOW() + MILLISECS(10));
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
        init_ac_timer(&schedule_data[i].s_timer, s_timer_fn, NULL, i);
        init_ac_timer(&t_timer[i], t_timer_fn, NULL, i);
    }

    schedule_data[0].curr = idle_domain[0];
    schedule_data[0].idle = idle_domain[0];

    for ( i = 0; schedulers[i] != NULL; i++ )
    {
        ops = *schedulers[i];
        if ( strcmp(ops.opt_name, opt_sched) == 0 )
            break;
    }
    
    if ( schedulers[i] == NULL )
        printk("Could not find scheduler: %s\n", opt_sched);

    printk("Using scheduler: %s (%s)\n", ops.name, ops.opt_name);

    rc = SCHED_OP(alloc_task, idle_domain[0]);
    BUG_ON(rc < 0);

    sched_add_domain(idle_domain[0]);
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
