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

#ifndef COMPAT
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
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/multicall.h>
#include <public/sched.h>

/* opt_sched: scheduler - default to credit */
static char opt_sched[10] = "credit";
string_param("sched", opt_sched);

/* opt_dom0_vcpus_pin: If true, dom0 VCPUs are pinned. */
static unsigned int opt_dom0_vcpus_pin;
boolean_param("dom0_vcpus_pin", opt_dom0_vcpus_pin);

#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */

/* Various timer handlers. */
static void s_timer_fn(void *unused);
static void vcpu_periodic_timer_fn(void *data);
static void vcpu_singleshot_timer_fn(void *data);
static void poll_timer_fn(void *data);

/* This is global for now so that private implementations can reach it */
DEFINE_PER_CPU(struct schedule_data, schedule_data);

extern struct scheduler sched_sedf_def;
extern struct scheduler sched_credit_def;
static struct scheduler *schedulers[] = { 
    &sched_sedf_def,
    &sched_credit_def,
    NULL
};

static struct scheduler ops;

#define SCHED_OP(fn, ...)                                 \
         (( ops.fn != NULL ) ? ops.fn( __VA_ARGS__ )      \
          : (typeof(ops.fn(__VA_ARGS__)))0 )

static inline void vcpu_runstate_change(
    struct vcpu *v, int new_state, s_time_t new_entry_time)
{
    ASSERT(v->runstate.state != new_state);
    ASSERT(spin_is_locked(&per_cpu(schedule_data,v->processor).schedule_lock));

    v->runstate.time[v->runstate.state] +=
        new_entry_time - v->runstate.state_entry_time;
    v->runstate.state_entry_time = new_entry_time;
    v->runstate.state = new_state;
}

void vcpu_runstate_get(struct vcpu *v, struct vcpu_runstate_info *runstate)
{
    if ( likely(v == current) )
    {
        /* Fast lock-free path. */
        memcpy(runstate, &v->runstate, sizeof(*runstate));
        ASSERT(runstate->state == RUNSTATE_running);
        runstate->time[RUNSTATE_running] += NOW() - runstate->state_entry_time;
    }
    else
    {
        vcpu_schedule_lock_irq(v);
        memcpy(runstate, &v->runstate, sizeof(*runstate));
        runstate->time[runstate->state] += NOW() - runstate->state_entry_time;
        vcpu_schedule_unlock_irq(v);
    }
}

int sched_init_vcpu(struct vcpu *v, unsigned int processor) 
{
    struct domain *d = v->domain;

    /*
     * Initialize processor and affinity settings. The idler, and potentially
     * domain-0 VCPUs, are pinned onto their respective physical CPUs.
     */
    v->processor = processor;
    if ( is_idle_domain(d) || ((d->domain_id == 0) && opt_dom0_vcpus_pin) )
        v->cpu_affinity = cpumask_of_cpu(processor);
    else
        cpus_setall(v->cpu_affinity);

    /* Initialise the per-vcpu timers. */
    init_timer(&v->periodic_timer, vcpu_periodic_timer_fn,
               v, v->processor);
    init_timer(&v->singleshot_timer, vcpu_singleshot_timer_fn,
               v, v->processor);
    init_timer(&v->poll_timer, poll_timer_fn,
               v, v->processor);

    /* Idle VCPUs are scheduled immediately. */
    if ( is_idle_domain(d) )
    {
        per_cpu(schedule_data, v->processor).curr = v;
        per_cpu(schedule_data, v->processor).idle = v;
        v->is_running = 1;
    }

    TRACE_2D(TRC_SCHED_DOM_ADD, v->domain->domain_id, v->vcpu_id);

    return SCHED_OP(init_vcpu, v);
}

void sched_destroy_vcpu(struct vcpu *v)
{
    kill_timer(&v->periodic_timer);
    kill_timer(&v->singleshot_timer);
    kill_timer(&v->poll_timer);
    SCHED_OP(destroy_vcpu, v);
}

int sched_init_domain(struct domain *d)
{
    return SCHED_OP(init_domain, d);
}

void sched_destroy_domain(struct domain *d)
{
    SCHED_OP(destroy_domain, d);
}

void vcpu_sleep_nosync(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);

    if ( likely(!vcpu_runnable(v)) )
    {
        if ( v->runstate.state == RUNSTATE_runnable )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());

        SCHED_OP(sleep, v);
    }

    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_SLEEP, v->domain->domain_id, v->vcpu_id);
}

void vcpu_sleep_sync(struct vcpu *v)
{
    vcpu_sleep_nosync(v);

    while ( !vcpu_runnable(v) && v->is_running )
        cpu_relax();

    sync_vcpu_execstate(v);
}

void vcpu_wake(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);

    if ( likely(vcpu_runnable(v)) )
    {
        if ( v->runstate.state >= RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_runnable, NOW());
        SCHED_OP(wake, v);
    }
    else if ( !test_bit(_VPF_blocked, &v->pause_flags) )
    {
        if ( v->runstate.state == RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());
    }

    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_WAKE, v->domain->domain_id, v->vcpu_id);
}

static void vcpu_migrate(struct vcpu *v)
{
    unsigned long flags;
    int old_cpu;

    vcpu_schedule_lock_irqsave(v, flags);

    /*
     * NB. Check of v->running happens /after/ setting migration flag
     * because they both happen in (different) spinlock regions, and those
     * regions are strictly serialised.
     */
    if ( v->is_running ||
         !test_and_clear_bit(_VPF_migrating, &v->pause_flags) )
    {
        vcpu_schedule_unlock_irqrestore(v, flags);
        return;
    }

    /* Switch to new CPU, then unlock old CPU. */
    old_cpu = v->processor;
    v->processor = SCHED_OP(pick_cpu, v);
    spin_unlock_irqrestore(
        &per_cpu(schedule_data, old_cpu).schedule_lock, flags);

    /* Wake on new CPU. */
    vcpu_wake(v);
}

/*
 * Force a VCPU through a deschedule/reschedule path.
 * For example, using this when setting the periodic timer period means that
 * most periodic-timer state need only be touched from within the scheduler
 * which can thus be done without need for synchronisation.
 */
void vcpu_force_reschedule(struct vcpu *v)
{
    vcpu_schedule_lock_irq(v);
    if ( v->is_running )
        set_bit(_VPF_migrating, &v->pause_flags);
    vcpu_schedule_unlock_irq(v);

    if ( test_bit(_VPF_migrating, &v->pause_flags) )
    {
        vcpu_sleep_nosync(v);
        vcpu_migrate(v);
    }
}

int vcpu_set_affinity(struct vcpu *v, cpumask_t *affinity)
{
    cpumask_t online_affinity;

    if ( (v->domain->domain_id == 0) && opt_dom0_vcpus_pin )
        return -EINVAL;

    cpus_and(online_affinity, *affinity, cpu_online_map);
    if ( cpus_empty(online_affinity) )
        return -EINVAL;

    vcpu_schedule_lock_irq(v);

    v->cpu_affinity = *affinity;
    if ( !cpu_isset(v->processor, v->cpu_affinity) )
        set_bit(_VPF_migrating, &v->pause_flags);

    vcpu_schedule_unlock_irq(v);

    if ( test_bit(_VPF_migrating, &v->pause_flags) )
    {
        vcpu_sleep_nosync(v);
        vcpu_migrate(v);
    }

    return 0;
}

/* Block the currently-executing domain until a pertinent event occurs. */
static long do_block(void)
{
    struct vcpu *v = current;

    local_event_delivery_enable();
    set_bit(_VPF_blocked, &v->pause_flags);

    /* Check for events /after/ blocking: avoids wakeup waiting race. */
    if ( local_events_need_delivery() )
    {
        clear_bit(_VPF_blocked, &v->pause_flags);
    }
    else
    {
        TRACE_2D(TRC_SCHED_BLOCK, v->domain->domain_id, v->vcpu_id);
        raise_softirq(SCHEDULE_SOFTIRQ);
    }

    return 0;
}

static long do_poll(struct sched_poll *sched_poll)
{
    struct vcpu   *v = current;
    struct domain *d = v->domain;
    evtchn_port_t  port;
    long           rc = 0;
    unsigned int   i;

    /* Fairly arbitrary limit. */
    if ( sched_poll->nr_ports > 128 )
        return -EINVAL;

    if ( !guest_handle_okay(sched_poll->ports, sched_poll->nr_ports) )
        return -EFAULT;

    set_bit(_VPF_blocked, &v->pause_flags);
    v->is_polling = 1;
    d->is_polling = 1;

    /* Check for events /after/ setting flags: avoids wakeup waiting race. */
    smp_wmb();

    for ( i = 0; i < sched_poll->nr_ports; i++ )
    {
        rc = -EFAULT;
        if ( __copy_from_guest_offset(&port, sched_poll->ports, i, 1) )
            goto out;

        rc = -EINVAL;
        if ( port >= MAX_EVTCHNS(d) )
            goto out;

        rc = 0;
        if ( test_bit(port, shared_info_addr(d, evtchn_pending)) )
            goto out;
    }

    if ( sched_poll->timeout != 0 )
        set_timer(&v->poll_timer, sched_poll->timeout);

    TRACE_2D(TRC_SCHED_BLOCK, d->domain_id, v->vcpu_id);
    raise_softirq(SCHEDULE_SOFTIRQ);

    return 0;

 out:
    v->is_polling = 0;
    clear_bit(_VPF_blocked, &v->pause_flags);
    return rc;
}

/* Voluntarily yield the processor for this allocation. */
static long do_yield(void)
{
    TRACE_2D(TRC_SCHED_YIELD, current->domain->domain_id, current->vcpu_id);
    raise_softirq(SCHEDULE_SOFTIRQ);
    return 0;
}

long do_sched_op_compat(int cmd, unsigned long arg)
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

typedef long ret_t;

#endif /* !COMPAT */

ret_t do_sched_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    ret_t ret = 0;

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
        struct sched_shutdown sched_shutdown;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_shutdown, arg, 1) )
            break;

        ret = 0;
        TRACE_3D(TRC_SCHED_SHUTDOWN,
                 current->domain->domain_id, current->vcpu_id,
                 sched_shutdown.reason);
        domain_shutdown(current->domain, (u8)sched_shutdown.reason);

        break;
    }

    case SCHEDOP_poll:
    {
        struct sched_poll sched_poll;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_poll, arg, 1) )
            break;

        ret = do_poll(&sched_poll);

        break;
    }

    case SCHEDOP_remote_shutdown:
    {
        struct domain *d;
        struct sched_remote_shutdown sched_remote_shutdown;

        if ( !IS_PRIV(current->domain) )
            return -EPERM;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_remote_shutdown, arg, 1) )
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(sched_remote_shutdown.domain_id);
        if ( d == NULL )
            break;

        domain_shutdown(d, (u8)sched_remote_shutdown.reason);
        rcu_unlock_domain(d);
        ret = 0;

        break;
    }

    default:
        ret = -ENOSYS;
    }

    return ret;
}

#ifndef COMPAT

/* Per-vcpu oneshot-timer hypercall. */
long do_set_timer_op(s_time_t timeout)
{
    struct vcpu *v = current;
    s_time_t offset = timeout - NOW();

    if ( timeout == 0 )
    {
        stop_timer(&v->singleshot_timer);
    }
    else if ( unlikely(timeout < 0) || /* overflow into 64th bit? */
              unlikely((offset > 0) && ((uint32_t)(offset >> 50) != 0)) )
    {
        /*
         * Linux workaround: occasionally we will see timeouts a long way in 
         * the future due to wrapping in Linux's jiffy time handling. We check 
         * for timeouts wrapped negative, and for positive timeouts more than 
         * about 13 days in the future (2^50ns). The correct fix is to trigger 
         * an interrupt immediately (since Linux in fact has pending work to 
         * do in this situation). However, older guests also set a long timeout
         * when they have *no* pending timers at all: setting an immediate
         * timeout in this case can burn a lot of CPU. We therefore go for a
         * reasonable middleground of triggering a timer event in 100ms.
         */
        gdprintk(XENLOG_INFO, "Warning: huge timeout set by domain %d "
                "(vcpu %d): %"PRIx64"\n",
                v->domain->domain_id, v->vcpu_id, (uint64_t)timeout);
        set_timer(&v->singleshot_timer, NOW() + MILLISECS(100));
    }
    else
    {
        if ( v->singleshot_timer.cpu != smp_processor_id() )
        {
            stop_timer(&v->singleshot_timer);
            v->singleshot_timer.cpu = smp_processor_id();
        }

        set_timer(&v->singleshot_timer, timeout);
    }

    return 0;
}

/* sched_id - fetch ID of current scheduler */
int sched_id(void)
{
    return ops.sched_id;
}

/* Adjust scheduling parameter for a given domain. */
long sched_adjust(struct domain *d, struct xen_domctl_scheduler_op *op)
{
    struct vcpu *v;
    long ret;
    
    if ( (op->sched_id != ops.sched_id) ||
         ((op->cmd != XEN_DOMCTL_SCHEDOP_putinfo) &&
          (op->cmd != XEN_DOMCTL_SCHEDOP_getinfo)) )
        return -EINVAL;

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

    for_each_vcpu ( d, v )
    {
        if ( v != current )
            vcpu_pause(v);
    }

    if ( d == current->domain )
        vcpu_schedule_lock_irq(current);

    if ( (ret = SCHED_OP(adjust, d, op)) == 0 )
        TRACE_1D(TRC_SCHED_ADJDOM, d->domain_id);

    if ( d == current->domain )
        vcpu_schedule_unlock_irq(current);

    for_each_vcpu ( d, v )
    {
        if ( v != current )
            vcpu_unpause(v);
    }

    return ret;
}

static void vcpu_periodic_timer_work(struct vcpu *v)
{
    s_time_t now = NOW();
    uint64_t periodic_next_event;

    ASSERT(!active_timer(&v->periodic_timer));

    if ( v->periodic_period == 0 )
        return;

    periodic_next_event = v->periodic_last_event + v->periodic_period;
    if ( now > periodic_next_event )
    {
        send_timer_event(v);
        v->periodic_last_event = now;
        periodic_next_event = now + v->periodic_period;
    }

    v->periodic_timer.cpu = smp_processor_id();
    set_timer(&v->periodic_timer, periodic_next_event);
}

/* 
 * The main function
 * - deschedule the current domain (scheduler independent).
 * - pick a new domain (scheduler dependent).
 */
static void schedule(void)
{
    struct vcpu          *prev = current, *next = NULL;
    s_time_t              now = NOW();
    struct schedule_data *sd;
    struct task_slice     next_slice;
    s32                   r_time;     /* time for new dom to run */

    ASSERT(!in_irq());
    ASSERT(this_cpu(mc_state).flags == 0);

    perfc_incr(sched_run);

    sd = &this_cpu(schedule_data);

    spin_lock_irq(&sd->schedule_lock);

    stop_timer(&sd->s_timer);
    
    /* get policy-specific decision on scheduling... */
    next_slice = ops.do_schedule(now);

    r_time = next_slice.time;
    next = next_slice.task;

    sd->curr = next;
    
    set_timer(&sd->s_timer, now + r_time);

    if ( unlikely(prev == next) )
    {
        spin_unlock_irq(&sd->schedule_lock);
        return continue_running(prev);
    }

    TRACE_2D(TRC_SCHED_SWITCH_INFPREV,
             prev->domain->domain_id,
             now - prev->runstate.state_entry_time);
    TRACE_3D(TRC_SCHED_SWITCH_INFNEXT,
             next->domain->domain_id,
             (next->runstate.state == RUNSTATE_runnable) ?
             (now - next->runstate.state_entry_time) : 0,
             r_time);

    ASSERT(prev->runstate.state == RUNSTATE_running);
    vcpu_runstate_change(
        prev,
        (test_bit(_VPF_blocked, &prev->pause_flags) ? RUNSTATE_blocked :
         (vcpu_runnable(prev) ? RUNSTATE_runnable : RUNSTATE_offline)),
        now);

    ASSERT(next->runstate.state != RUNSTATE_running);
    vcpu_runstate_change(next, RUNSTATE_running, now);

    ASSERT(!next->is_running);
    next->is_running = 1;

    spin_unlock_irq(&sd->schedule_lock);

    perfc_incr(sched_ctx);

    stop_timer(&prev->periodic_timer);

    /* Ensure that the domain has an up-to-date time base. */
    update_vcpu_system_time(next);
    vcpu_periodic_timer_work(next);

    TRACE_4D(TRC_SCHED_SWITCH,
             prev->domain->domain_id, prev->vcpu_id,
             next->domain->domain_id, next->vcpu_id);

    context_switch(prev, next);
}

void context_saved(struct vcpu *prev)
{
    /* Clear running flag /after/ writing context to memory. */
    smp_wmb();

    prev->is_running = 0;

    /* Check for migration request /after/ clearing running flag. */
    smp_mb();

    if ( unlikely(test_bit(_VPF_migrating, &prev->pause_flags)) )
        vcpu_migrate(prev);
}

/* The scheduler timer: force a run through the scheduler */
static void s_timer_fn(void *unused)
{
    raise_softirq(SCHEDULE_SOFTIRQ);
    perfc_incr(sched_irq);
}

/* Per-VCPU periodic timer function: sends a virtual timer interrupt. */
static void vcpu_periodic_timer_fn(void *data)
{
    struct vcpu *v = data;
    vcpu_periodic_timer_work(v);
}

/* Per-VCPU single-shot timer function: sends a virtual timer interrupt. */
static void vcpu_singleshot_timer_fn(void *data)
{
    struct vcpu *v = data;
    send_timer_event(v);
}

/* SCHEDOP_poll timeout callback. */
static void poll_timer_fn(void *data)
{
    struct vcpu *v = data;

    if ( !v->is_polling )
        return;

    v->is_polling = 0;
    vcpu_unblock(v);
}

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    int i;

    open_softirq(SCHEDULE_SOFTIRQ, schedule);

    for_each_cpu ( i )
    {
        spin_lock_init(&per_cpu(schedule_data, i).schedule_lock);
        init_timer(&per_cpu(schedule_data, i).s_timer, s_timer_fn, NULL, i);
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
    SCHED_OP(init);
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
        spin_lock(&per_cpu(schedule_data, i).schedule_lock);
        printk("CPU[%02d] ", i);
        SCHED_OP(dump_cpu_state, i);
        spin_unlock(&per_cpu(schedule_data, i).schedule_lock);
    }

    local_irq_restore(flags);
}

#ifdef CONFIG_COMPAT
#include "compat/schedule.c"
#endif

#endif /* !COMPAT */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
