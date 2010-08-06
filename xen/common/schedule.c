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
#include <xen/cpu.h>
#include <public/sched.h>
#include <xsm/xsm.h>

/* opt_sched: scheduler - default to credit */
static char __initdata opt_sched[10] = "credit";
string_param("sched", opt_sched);

/* if sched_smt_power_savings is set,
 * scheduler will give preferrence to partially idle package compared to
 * the full idle package, when picking pCPU to schedule vCPU.
 */
int sched_smt_power_savings = 0;
boolean_param("sched_smt_power_savings", sched_smt_power_savings);

/* Various timer handlers. */
static void s_timer_fn(void *unused);
static void vcpu_periodic_timer_fn(void *data);
static void vcpu_singleshot_timer_fn(void *data);
static void poll_timer_fn(void *data);

/* This is global for now so that private implementations can reach it */
DEFINE_PER_CPU(struct schedule_data, schedule_data);
DEFINE_PER_CPU(struct scheduler *, scheduler);

extern const struct scheduler sched_sedf_def;
extern const struct scheduler sched_credit_def;
extern const struct scheduler sched_credit2_def;
static const struct scheduler *schedulers[] = {
    &sched_sedf_def,
    &sched_credit_def,
    &sched_credit2_def,
    NULL
};

static struct scheduler __read_mostly ops;

#define SCHED_OP(opsptr, fn, ...)                                          \
         (( (opsptr)->fn != NULL ) ? (opsptr)->fn(opsptr, ##__VA_ARGS__ )  \
          : (typeof((opsptr)->fn(opsptr, ##__VA_ARGS__)))0 )

#define DOM2OP(_d)    (((_d)->cpupool == NULL) ? &ops : ((_d)->cpupool->sched))
#define VCPU2OP(_v)   (DOM2OP((_v)->domain))
#define VCPU2ONLINE(_v)                                                    \
         (((_v)->domain->cpupool == NULL) ? &cpu_online_map                \
         : &(_v)->domain->cpupool->cpu_valid)

static inline void trace_runstate_change(struct vcpu *v, int new_state)
{
    struct { uint32_t vcpu:16, domain:16; } d;
    uint32_t event;

    if ( likely(!tb_init_done) )
        return;

    d.vcpu = v->vcpu_id;
    d.domain = v->domain->domain_id;

    event = TRC_SCHED_RUNSTATE_CHANGE;
    event |= ( v->runstate.state & 0x3 ) << 8;
    event |= ( new_state & 0x3 ) << 4;

    __trace_var(event, 1/*tsc*/, sizeof(d), (unsigned char *)&d);
}

static inline void trace_continue_running(struct vcpu *v)
{
    struct { uint32_t vcpu:16, domain:16; } d;

    if ( likely(!tb_init_done) )
        return;

    d.vcpu = v->vcpu_id;
    d.domain = v->domain->domain_id;

    __trace_var(TRC_SCHED_CONTINUE_RUNNING, 1/*tsc*/, sizeof(d),
                (unsigned char *)&d);
}

static inline void vcpu_urgent_count_update(struct vcpu *v)
{
    if ( is_idle_vcpu(v) )
        return;

    if ( unlikely(v->is_urgent) )
    {
        if ( !test_bit(_VPF_blocked, &v->pause_flags) ||
             !test_bit(v->vcpu_id, v->domain->poll_mask) )
        {
            v->is_urgent = 0;
            atomic_dec(&per_cpu(schedule_data,v->processor).urgent_count);
        }
    }
    else
    {
        if ( unlikely(test_bit(_VPF_blocked, &v->pause_flags) &&
                      test_bit(v->vcpu_id, v->domain->poll_mask)) )
        {
            v->is_urgent = 1;
            atomic_inc(&per_cpu(schedule_data,v->processor).urgent_count);
        }
    }
}

static inline void vcpu_runstate_change(
    struct vcpu *v, int new_state, s_time_t new_entry_time)
{
    s_time_t delta;

    ASSERT(v->runstate.state != new_state);
    ASSERT(spin_is_locked(per_cpu(schedule_data,v->processor).schedule_lock));

    vcpu_urgent_count_update(v);

    trace_runstate_change(v, new_state);

    delta = new_entry_time - v->runstate.state_entry_time;
    if ( delta > 0 )
    {
        v->runstate.time[v->runstate.state] += delta;
        v->runstate.state_entry_time = new_entry_time;
    }

    v->runstate.state = new_state;
}

void vcpu_runstate_get(struct vcpu *v, struct vcpu_runstate_info *runstate)
{
    s_time_t delta;

    if ( unlikely(v != current) )
        vcpu_schedule_lock_irq(v);

    memcpy(runstate, &v->runstate, sizeof(*runstate));
    delta = NOW() - runstate->state_entry_time;
    if ( delta > 0 )
        runstate->time[runstate->state] += delta;

    if ( unlikely(v != current) )
        vcpu_schedule_unlock_irq(v);
}

uint64_t get_cpu_idle_time(unsigned int cpu)
{
    struct vcpu_runstate_info state;
    struct vcpu *v;

    if ( (v = idle_vcpu[cpu]) == NULL )
        return 0;

    vcpu_runstate_get(v, &state);
    return state.time[RUNSTATE_running];
}

int sched_init_vcpu(struct vcpu *v, unsigned int processor) 
{
    struct domain *d = v->domain;

    /*
     * Initialize processor and affinity settings. The idler, and potentially
     * domain-0 VCPUs, are pinned onto their respective physical CPUs.
     */
    v->processor = processor;
    if ( is_idle_domain(d) || d->is_pinned )
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
        v->is_running = 1;
    }

    TRACE_2D(TRC_SCHED_DOM_ADD, v->domain->domain_id, v->vcpu_id);

    v->sched_priv = SCHED_OP(DOM2OP(d), alloc_vdata, v, d->sched_priv);
    if ( v->sched_priv == NULL )
        return 1;

    return 0;
}

int sched_move_domain(struct domain *d, struct cpupool *c)
{
    struct vcpu *v;
    unsigned int new_p;
    void **vcpu_priv;
    void *domdata;

    domdata = SCHED_OP(c->sched, alloc_domdata, d);
    if ( domdata == NULL )
        return -ENOMEM;

    vcpu_priv = xmalloc_array(void *, d->max_vcpus);
    if ( vcpu_priv == NULL )
    {
        SCHED_OP(c->sched, free_domdata, domdata);
        return -ENOMEM;
    }

    memset(vcpu_priv, 0, d->max_vcpus * sizeof(void *));
    for_each_vcpu ( d, v )
    {
        vcpu_priv[v->vcpu_id] = SCHED_OP(c->sched, alloc_vdata, v, domdata);
        if ( vcpu_priv[v->vcpu_id] == NULL )
        {
            for_each_vcpu ( d, v )
            {
                if ( vcpu_priv[v->vcpu_id] != NULL )
                    xfree(vcpu_priv[v->vcpu_id]);
            }
            xfree(vcpu_priv);
            SCHED_OP(c->sched, free_domdata, domdata);
            return -ENOMEM;
        }
    }

    domain_pause(d);

    new_p = first_cpu(c->cpu_valid);
    for_each_vcpu ( d, v )
    {
        migrate_timer(&v->periodic_timer, new_p);
        migrate_timer(&v->singleshot_timer, new_p);
        migrate_timer(&v->poll_timer, new_p);

        SCHED_OP(VCPU2OP(v), destroy_vcpu, v);

        cpus_setall(v->cpu_affinity);
        v->processor = new_p;
        v->sched_priv = vcpu_priv[v->vcpu_id];
        evtchn_move_pirqs(v);

        new_p = cycle_cpu(new_p, c->cpu_valid);
    }
    domain_update_node_affinity(d);

    d->cpupool = c;
    SCHED_OP(DOM2OP(d), free_domdata, d->sched_priv);
    d->sched_priv = domdata;

    domain_unpause(d);

    xfree(vcpu_priv);

    return 0;
}

void sched_destroy_vcpu(struct vcpu *v)
{
    kill_timer(&v->periodic_timer);
    kill_timer(&v->singleshot_timer);
    kill_timer(&v->poll_timer);
    if ( test_and_clear_bool(v->is_urgent) )
        atomic_dec(&per_cpu(schedule_data, v->processor).urgent_count);
    SCHED_OP(VCPU2OP(v), destroy_vcpu, v);
}

int sched_init_domain(struct domain *d)
{
    return SCHED_OP(DOM2OP(d), init_domain, d);
}

void sched_destroy_domain(struct domain *d)
{
    SCHED_OP(DOM2OP(d), destroy_domain, d);
}

void vcpu_sleep_nosync(struct vcpu *v)
{
    unsigned long flags;

    vcpu_schedule_lock_irqsave(v, flags);

    if ( likely(!vcpu_runnable(v)) )
    {
        if ( v->runstate.state == RUNSTATE_runnable )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());

        SCHED_OP(VCPU2OP(v), sleep, v);
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
        SCHED_OP(VCPU2OP(v), wake, v);
    }
    else if ( !test_bit(_VPF_blocked, &v->pause_flags) )
    {
        if ( v->runstate.state == RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());
    }

    vcpu_schedule_unlock_irqrestore(v, flags);

    TRACE_2D(TRC_SCHED_WAKE, v->domain->domain_id, v->vcpu_id);
}

void vcpu_unblock(struct vcpu *v)
{
    if ( !test_and_clear_bit(_VPF_blocked, &v->pause_flags) )
        return;

    /* Polling period ends when a VCPU is unblocked. */
    if ( unlikely(v->poll_evtchn != 0) )
    {
        v->poll_evtchn = 0;
        /*
         * We *must* re-clear _VPF_blocked to avoid racing other wakeups of
         * this VCPU (and it then going back to sleep on poll_mask).
         * Test-and-clear is idiomatic and ensures clear_bit not reordered.
         */
        if ( test_and_clear_bit(v->vcpu_id, v->domain->poll_mask) )
            clear_bit(_VPF_blocked, &v->pause_flags);
    }

    vcpu_wake(v);
}

static void vcpu_migrate(struct vcpu *v)
{
    unsigned long flags;
    int old_cpu, new_cpu;

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

    /* Select new CPU. */
    old_cpu = v->processor;
    new_cpu = SCHED_OP(VCPU2OP(v), pick_cpu, v);

    /*
     * Transfer urgency status to new CPU before switching CPUs, as once
     * the switch occurs, v->is_urgent is no longer protected by the per-CPU
     * scheduler lock we are holding.
     */
    if ( unlikely(v->is_urgent) && (old_cpu != new_cpu) )
    {
        atomic_inc(&per_cpu(schedule_data, new_cpu).urgent_count);
        atomic_dec(&per_cpu(schedule_data, old_cpu).urgent_count);
    }

    /* Switch to new CPU, then unlock old CPU. */
    v->processor = new_cpu;
    spin_unlock_irqrestore(
        per_cpu(schedule_data, old_cpu).schedule_lock, flags);

    if ( old_cpu != new_cpu )
        evtchn_move_pirqs(v);

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

/*
 * This function is used by cpu_hotplug code from stop_machine context
 * and from cpupools to switch schedulers on a cpu.
 */
int cpu_disable_scheduler(unsigned int cpu)
{
    struct domain *d;
    struct vcpu *v;
    struct cpupool *c;
    int    ret = 0;
    bool_t affinity_broken;

    c = per_cpu(cpupool, cpu);
    if ( c == NULL )
        return ret;

    for_each_domain ( d )
    {
        if ( d->cpupool != c )
            continue;

        affinity_broken = 0;

        for_each_vcpu ( d, v )
        {
            vcpu_schedule_lock_irq(v);

            if ( (cpus_weight(v->cpu_affinity) == 1) &&
                 cpu_isset(cpu, v->cpu_affinity) )
            {
                printk("Breaking vcpu affinity for domain %d vcpu %d\n",
                        v->domain->domain_id, v->vcpu_id);
                cpus_setall(v->cpu_affinity);
                affinity_broken = 1;
            }

            if ( v->processor == cpu )
            {
                set_bit(_VPF_migrating, &v->pause_flags);
                vcpu_schedule_unlock_irq(v);
                vcpu_sleep_nosync(v);
                vcpu_migrate(v);
            }
            else
            {
                vcpu_schedule_unlock_irq(v);
            }

            /*
             * A vcpu active in the hypervisor will not be migratable.
             * The caller should try again after releasing and reaquiring
             * all locks.
             */
            if ( v->processor == cpu )
                ret = -EAGAIN;
        }

        if ( affinity_broken )
            domain_update_node_affinity(d);
    }

    return ret;
}

int vcpu_set_affinity(struct vcpu *v, cpumask_t *affinity)
{
    cpumask_t online_affinity, old_affinity;
    cpumask_t *online;

    if ( v->domain->is_pinned )
        return -EINVAL;
    online = VCPU2ONLINE(v);
    cpus_and(online_affinity, *affinity, *online);
    if ( cpus_empty(online_affinity) )
        return -EINVAL;

    vcpu_schedule_lock_irq(v);

    old_affinity = v->cpu_affinity;
    v->cpu_affinity = *affinity;
    *affinity = old_affinity;
    if ( !cpu_isset(v->processor, v->cpu_affinity) )
        set_bit(_VPF_migrating, &v->pause_flags);

    vcpu_schedule_unlock_irq(v);

    domain_update_node_affinity(v->domain);

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
    long           rc;
    unsigned int   i;

    /* Fairly arbitrary limit. */
    if ( sched_poll->nr_ports > 128 )
        return -EINVAL;

    if ( !guest_handle_okay(sched_poll->ports, sched_poll->nr_ports) )
        return -EFAULT;

    set_bit(_VPF_blocked, &v->pause_flags);
    v->poll_evtchn = -1;
    set_bit(v->vcpu_id, d->poll_mask);

#ifndef CONFIG_X86 /* set_bit() implies mb() on x86 */
    /* Check for events /after/ setting flags: avoids wakeup waiting race. */
    smp_mb();

    /*
     * Someone may have seen we are blocked but not that we are polling, or
     * vice versa. We are certainly being woken, so clean up and bail. Beyond
     * this point others can be guaranteed to clean up for us if they wake us.
     */
    rc = 0;
    if ( (v->poll_evtchn == 0) ||
         !test_bit(_VPF_blocked, &v->pause_flags) ||
         !test_bit(v->vcpu_id, d->poll_mask) )
        goto out;
#endif

    rc = 0;
    if ( local_events_need_delivery() )
        goto out;

    for ( i = 0; i < sched_poll->nr_ports; i++ )
    {
        rc = -EFAULT;
        if ( __copy_from_guest_offset(&port, sched_poll->ports, i, 1) )
            goto out;

        rc = -EINVAL;
        if ( port >= MAX_EVTCHNS(d) )
            goto out;

        rc = 0;
        if ( test_bit(port, &shared_info(d, evtchn_pending)) )
            goto out;
    }

    if ( sched_poll->nr_ports == 1 )
        v->poll_evtchn = port;

    if ( sched_poll->timeout != 0 )
        set_timer(&v->poll_timer, sched_poll->timeout);

    TRACE_2D(TRC_SCHED_BLOCK, d->domain_id, v->vcpu_id);
    raise_softirq(SCHEDULE_SOFTIRQ);

    return 0;

 out:
    v->poll_evtchn = 0;
    clear_bit(v->vcpu_id, d->poll_mask);
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

static void domain_watchdog_timeout(void *data)
{
    struct domain *d = data;

    if ( d->is_shutting_down || d->is_dying )
        return;

    printk("Watchdog timer fired for domain %u\n", d->domain_id);
    domain_shutdown(d, SHUTDOWN_watchdog);
}

static long domain_watchdog(struct domain *d, uint32_t id, uint32_t timeout)
{
    if ( id > NR_DOMAIN_WATCHDOG_TIMERS )
        return -EINVAL;

    spin_lock(&d->watchdog_lock);

    if ( id == 0 )
    {
        for ( id = 0; id < NR_DOMAIN_WATCHDOG_TIMERS; id++ )
        {
            if ( test_and_set_bit(id, &d->watchdog_inuse_map) )
                continue;
            set_timer(&d->watchdog_timer[id], NOW() + SECONDS(timeout));
            break;
        }
        spin_unlock(&d->watchdog_lock);
        return id == NR_DOMAIN_WATCHDOG_TIMERS ? -EEXIST : id + 1;
    }

    id -= 1;
    if ( !test_bit(id, &d->watchdog_inuse_map) )
    {
        spin_unlock(&d->watchdog_lock);
        return -EEXIST;
    }

    if ( timeout == 0 )
    {
        stop_timer(&d->watchdog_timer[id]);
        clear_bit(id, &d->watchdog_inuse_map);
    }
    else
    {
        set_timer(&d->watchdog_timer[id], NOW() + SECONDS(timeout));
    }

    spin_unlock(&d->watchdog_lock);
    return 0;
}

void watchdog_domain_init(struct domain *d)
{
    unsigned int i;

    spin_lock_init(&d->watchdog_lock);

    d->watchdog_inuse_map = 0;

    for ( i = 0; i < NR_DOMAIN_WATCHDOG_TIMERS; i++ )
        init_timer(&d->watchdog_timer[i], domain_watchdog_timeout, d, 0);
}

void watchdog_domain_destroy(struct domain *d)
{
    unsigned int i;

    for ( i = 0; i < NR_DOMAIN_WATCHDOG_TIMERS; i++ )
        kill_timer(&d->watchdog_timer[i]);
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

    case SCHEDOP_shutdown_code:
    {
        struct sched_shutdown sched_shutdown;
        struct domain *d = current->domain;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_shutdown, arg, 1) )
            break;

        TRACE_3D(TRC_SCHED_SHUTDOWN_CODE,
                 d->domain_id, current->vcpu_id, sched_shutdown.reason);

        spin_lock(&d->shutdown_lock);
        if ( d->shutdown_code == -1 )
            d->shutdown_code = (u8)sched_shutdown.reason;
        spin_unlock(&d->shutdown_lock);

        ret = 0;
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

        ret = -EFAULT;
        if ( copy_from_guest(&sched_remote_shutdown, arg, 1) )
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(sched_remote_shutdown.domain_id);
        if ( d == NULL )
            break;

        if ( !IS_PRIV_FOR(current->domain, d) )
        {
            rcu_unlock_domain(d);
            return -EPERM;
        }

        ret = xsm_schedop_shutdown(current->domain, d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            return ret;
        }

        domain_shutdown(d, (u8)sched_remote_shutdown.reason);

        rcu_unlock_domain(d);
        ret = 0;

        break;
    }

    case SCHEDOP_watchdog:
    {
        struct sched_watchdog sched_watchdog;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_watchdog, arg, 1) )
            break;

        ret = domain_watchdog(
            current->domain, sched_watchdog.id, sched_watchdog.timeout);
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
        gdprintk(XENLOG_INFO,
                 "Warning: huge timeout set by vcpu %d: %"PRIx64"\n",
                 v->vcpu_id, (uint64_t)timeout);
        set_timer(&v->singleshot_timer, NOW() + MILLISECS(100));
    }
    else
    {
        migrate_timer(&v->singleshot_timer, smp_processor_id());
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
    
    if ( (op->sched_id != DOM2OP(d)->sched_id) ||
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

    if ( (ret = SCHED_OP(DOM2OP(d), adjust, d, op)) == 0 )
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

long sched_adjust_global(struct xen_sysctl_scheduler_op *op)
{
    struct cpupool *pool;
    int rc;

    if ( (op->cmd != XEN_DOMCTL_SCHEDOP_putinfo) &&
         (op->cmd != XEN_DOMCTL_SCHEDOP_getinfo) )
        return -EINVAL;

    pool = cpupool_get_by_id(op->cpupool_id);
    if ( pool == NULL )
        return -ESRCH;

    if ( op->sched_id != pool->sched->sched_id )
    {
        cpupool_put(pool);
        return -EINVAL;
    }

    rc = SCHED_OP(pool->sched, adjust_global, op);

    cpupool_put(pool);

    return rc;
}

static void vcpu_periodic_timer_work(struct vcpu *v)
{
    s_time_t now = NOW();
    s_time_t periodic_next_event;

    if ( v->periodic_period == 0 )
        return;

    periodic_next_event = v->periodic_last_event + v->periodic_period;

    if ( now >= periodic_next_event )
    {
        send_timer_event(v);
        v->periodic_last_event = now;
        periodic_next_event = now + v->periodic_period;
    }

    migrate_timer(&v->periodic_timer, smp_processor_id());
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
    struct scheduler     *sched = this_cpu(scheduler);
    unsigned long        *tasklet_work = &this_cpu(tasklet_work_to_do);
    bool_t                tasklet_work_scheduled = 0;
    struct schedule_data *sd;
    struct task_slice     next_slice;

    ASSERT(!in_irq());
    ASSERT(this_cpu(mc_state).flags == 0);

    perfc_incr(sched_run);

    sd = &this_cpu(schedule_data);

    /* Update tasklet scheduling status. */
    switch ( *tasklet_work )
    {
    case TASKLET_enqueued:
        set_bit(_TASKLET_scheduled, tasklet_work);
    case TASKLET_enqueued|TASKLET_scheduled:
        tasklet_work_scheduled = 1;
        break;
    case TASKLET_scheduled:
        clear_bit(_TASKLET_scheduled, tasklet_work);
    case 0:
        /*tasklet_work_scheduled = 0;*/
        break;
    default:
        BUG();
    }

    spin_lock_irq(sd->schedule_lock);

    stop_timer(&sd->s_timer);
    
    /* get policy-specific decision on scheduling... */
    next_slice = sched->do_schedule(sched, now, tasklet_work_scheduled);

    next = next_slice.task;

    sd->curr = next;

    if ( next_slice.time >= 0 ) /* -ve means no limit */
        set_timer(&sd->s_timer, now + next_slice.time);

    if ( unlikely(prev == next) )
    {
        spin_unlock_irq(sd->schedule_lock);
        trace_continue_running(next);
        return continue_running(prev);
    }

    TRACE_2D(TRC_SCHED_SWITCH_INFPREV,
             prev->domain->domain_id,
             now - prev->runstate.state_entry_time);
    TRACE_3D(TRC_SCHED_SWITCH_INFNEXT,
             next->domain->domain_id,
             (next->runstate.state == RUNSTATE_runnable) ?
             (now - next->runstate.state_entry_time) : 0,
             next_slice.time);

    ASSERT(prev->runstate.state == RUNSTATE_running);

    TRACE_4D(TRC_SCHED_SWITCH,
             prev->domain->domain_id, prev->vcpu_id,
             next->domain->domain_id, next->vcpu_id);

    vcpu_runstate_change(
        prev,
        (test_bit(_VPF_blocked, &prev->pause_flags) ? RUNSTATE_blocked :
         (vcpu_runnable(prev) ? RUNSTATE_runnable : RUNSTATE_offline)),
        now);
    prev->last_run_time = now;

    ASSERT(next->runstate.state != RUNSTATE_running);
    vcpu_runstate_change(next, RUNSTATE_running, now);

    /*
     * NB. Don't add any trace records from here until the actual context
     * switch, else lost_records resume will not work properly.
     */

    ASSERT(!next->is_running);
    next->is_running = 1;

    spin_unlock_irq(sd->schedule_lock);

    perfc_incr(sched_ctx);

    stop_timer(&prev->periodic_timer);

    if ( next_slice.migrated )
        evtchn_move_pirqs(next);

    /* Ensure that the domain has an up-to-date time base. */
    update_vcpu_system_time(next);
    vcpu_periodic_timer_work(next);

    context_switch(prev, next);
}

void context_saved(struct vcpu *prev)
{
    /* Clear running flag /after/ writing context to memory. */
    smp_wmb();

    prev->is_running = 0;

    /* Check for migration request /after/ clearing running flag. */
    smp_mb();

    SCHED_OP(VCPU2OP(prev), context_saved, prev);

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

    if ( test_and_clear_bit(v->vcpu_id, v->domain->poll_mask) )
        vcpu_unblock(v);
}

static int cpu_schedule_up(unsigned int cpu)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);

    per_cpu(scheduler, cpu) = &ops;
    spin_lock_init(&sd->_lock);
    sd->schedule_lock = &sd->_lock;
    sd->curr = idle_vcpu[cpu];
    init_timer(&sd->s_timer, s_timer_fn, NULL, cpu);
    atomic_set(&sd->urgent_count, 0);

    /* Boot CPU is dealt with later in schedule_init(). */
    if ( cpu == 0 )
        return 0;

    if ( idle_vcpu[cpu] == NULL )
        alloc_vcpu(idle_vcpu[0]->domain, cpu, cpu);
    if ( idle_vcpu[cpu] == NULL )
        return -ENOMEM;

    if ( (ops.alloc_pdata != NULL) &&
         ((sd->sched_priv = ops.alloc_pdata(&ops, cpu)) == NULL) )
        return -ENOMEM;

    return 0;
}

static void cpu_schedule_down(unsigned int cpu)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);

    if ( sd->sched_priv != NULL )
        SCHED_OP(&ops, free_pdata, sd->sched_priv, cpu);

    kill_timer(&sd->s_timer);
}

static int cpu_schedule_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = cpu_schedule_up(cpu);
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        cpu_schedule_down(cpu);
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_schedule_nfb = {
    .notifier_call = cpu_schedule_callback
};

/* Initialise the data structures. */
void __init scheduler_init(void)
{
    struct domain *idle_domain;
    int i;

    open_softirq(SCHEDULE_SOFTIRQ, schedule);

    for ( i = 0; schedulers[i] != NULL; i++ )
    {
        ops = *schedulers[i];
        if ( strcmp(ops.opt_name, opt_sched) == 0 )
            break;
    }

    if ( schedulers[i] == NULL )
    {
        printk("Could not find scheduler: %s\n", opt_sched);
        ops = *schedulers[0];
    }

    if ( cpu_schedule_up(0) )
        BUG();
    register_cpu_notifier(&cpu_schedule_nfb);

    printk("Using scheduler: %s (%s)\n", ops.name, ops.opt_name);
    if ( SCHED_OP(&ops, init) )
        panic("scheduler returned error on init\n");

    idle_domain = domain_create(IDLE_DOMAIN_ID, 0, 0);
    BUG_ON(idle_domain == NULL);
    idle_domain->vcpu = idle_vcpu;
    idle_domain->max_vcpus = NR_CPUS;
    if ( alloc_vcpu(idle_domain, 0, 0) == NULL )
        BUG();
    if ( ops.alloc_pdata &&
         !(this_cpu(schedule_data).sched_priv = ops.alloc_pdata(&ops, 0)) )
        BUG();
}

void schedule_cpu_switch(unsigned int cpu, struct cpupool *c)
{
    unsigned long flags;
    struct vcpu *idle;
    void *ppriv, *ppriv_old, *vpriv, *vpriv_old;
    struct scheduler *old_ops = per_cpu(scheduler, cpu);
    struct scheduler *new_ops = (c == NULL) ? &ops : c->sched;

    if ( old_ops == new_ops )
        return;

    idle = idle_vcpu[cpu];
    ppriv = SCHED_OP(new_ops, alloc_pdata, cpu);
    vpriv = SCHED_OP(new_ops, alloc_vdata, idle, idle->domain->sched_priv);

    spin_lock_irqsave(per_cpu(schedule_data, cpu).schedule_lock, flags);

    SCHED_OP(old_ops, tick_suspend, cpu);
    vpriv_old = idle->sched_priv;
    idle->sched_priv = vpriv;
    per_cpu(scheduler, cpu) = new_ops;
    ppriv_old = per_cpu(schedule_data, cpu).sched_priv;
    per_cpu(schedule_data, cpu).sched_priv = ppriv;
    SCHED_OP(new_ops, tick_resume, cpu);
    SCHED_OP(new_ops, insert_vcpu, idle);

    spin_unlock_irqrestore(per_cpu(schedule_data, cpu).schedule_lock, flags);

    SCHED_OP(old_ops, free_vdata, vpriv);
    SCHED_OP(old_ops, free_pdata, ppriv_old, cpu);
}

struct scheduler *scheduler_get_default(void)
{
    return &ops;
}

struct scheduler *scheduler_alloc(unsigned int sched_id, int *perr)
{
    int i;
    struct scheduler *sched;

    for ( i = 0; schedulers[i] != NULL; i++ )
        if ( schedulers[i]->sched_id == sched_id )
            goto found;
    *perr = -ENOENT;
    return NULL;

 found:
    *perr = -ENOMEM;
    if ( (sched = xmalloc(struct scheduler)) == NULL )
        return NULL;
    memcpy(sched, schedulers[i], sizeof(*sched));
    if ( (*perr = SCHED_OP(sched, init)) != 0 )
    {
        xfree(sched);
        sched = NULL;
    }

    return sched;
}

void scheduler_free(struct scheduler *sched)
{
    BUG_ON(sched == &ops);
    SCHED_OP(sched, deinit);
    xfree(sched);
}

void schedule_dump(struct cpupool *c)
{
    int               i;
    struct scheduler *sched;
    cpumask_t        *cpus;

    sched = (c == NULL) ? &ops : c->sched;
    cpus = (c == NULL) ? &cpupool_free_cpus : &c->cpu_valid;
    printk("Scheduler: %s (%s)\n", sched->name, sched->opt_name);
    SCHED_OP(sched, dump_settings);

    for_each_cpu_mask (i, *cpus)
    {
        spin_lock(per_cpu(schedule_data, i).schedule_lock);
        printk("CPU[%02d] ", i);
        SCHED_OP(sched, dump_cpu_state, i);
        spin_unlock(per_cpu(schedule_data, i).schedule_lock);
    }
}

void sched_tick_suspend(void)
{
    struct scheduler *sched;
    unsigned int cpu = smp_processor_id();

    sched = per_cpu(scheduler, cpu);
    SCHED_OP(sched, tick_suspend, cpu);
}

void sched_tick_resume(void)
{
    struct scheduler *sched;
    unsigned int cpu = smp_processor_id();

    sched = per_cpu(scheduler, cpu);
    SCHED_OP(sched, tick_resume, cpu);
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
