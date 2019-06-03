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
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/multicall.h>
#include <xen/cpu.h>
#include <xen/preempt.h>
#include <xen/event.h>
#include <public/sched.h>
#include <xsm/xsm.h>
#include <xen/err.h>

/* opt_sched: scheduler - default to configured value */
static char __initdata opt_sched[10] = CONFIG_SCHED_DEFAULT;
string_param("sched", opt_sched);

/* if sched_smt_power_savings is set,
 * scheduler will give preferrence to partially idle package compared to
 * the full idle package, when picking pCPU to schedule vCPU.
 */
bool_t sched_smt_power_savings = 0;
boolean_param("sched_smt_power_savings", sched_smt_power_savings);

/* Default scheduling rate limit: 1ms
 * The behavior when sched_ratelimit_us is greater than sched_credit_tslice_ms is undefined
 * */
int sched_ratelimit_us = SCHED_DEFAULT_RATELIMIT_US;
integer_param("sched_ratelimit_us", sched_ratelimit_us);
/* Various timer handlers. */
static void s_timer_fn(void *unused);
static void vcpu_periodic_timer_fn(void *data);
static void vcpu_singleshot_timer_fn(void *data);
static void poll_timer_fn(void *data);

/* This is global for now so that private implementations can reach it */
DEFINE_PER_CPU(struct schedule_data, schedule_data);
DEFINE_PER_CPU(struct scheduler *, scheduler);

/* Scratch space for cpumasks. */
DEFINE_PER_CPU(cpumask_t, cpumask_scratch);

extern const struct scheduler *__start_schedulers_array[], *__end_schedulers_array[];
#define NUM_SCHEDULERS (__end_schedulers_array - __start_schedulers_array)
#define schedulers __start_schedulers_array

static struct scheduler __read_mostly ops;

#define SCHED_OP(opsptr, fn, ...)                                          \
         (( (opsptr)->fn != NULL ) ? (opsptr)->fn(opsptr, ##__VA_ARGS__ )  \
          : (typeof((opsptr)->fn(opsptr, ##__VA_ARGS__)))0 )

static inline struct scheduler *dom_scheduler(const struct domain *d)
{
    if ( likely(d->cpupool != NULL) )
        return d->cpupool->sched;

    /*
     * If d->cpupool is NULL, this is the idle domain. This is special
     * because the idle domain does not really belong to any cpupool, and,
     * hence, does not really have a scheduler.
     *
     * This is (should be!) only called like this for allocating the idle
     * vCPUs for the first time, during boot, in which case what we want
     * is the default scheduler that has been, choosen at boot.
     */
    ASSERT(is_idle_domain(d));
    return &ops;
}

static inline struct scheduler *vcpu_scheduler(const struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( likely(d->cpupool != NULL) )
        return d->cpupool->sched;

    /*
     * If d->cpupool is NULL, this is a vCPU of the idle domain. And this
     * case is special because the idle domain does not really belong to
     * a cpupool and, hence, doesn't really have a scheduler). In fact, its
     * vCPUs (may) run on pCPUs which are in different pools, with different
     * schedulers.
     *
     * What we want, in this case, is the scheduler of the pCPU where this
     * particular idle vCPU is running. And, since v->processor never changes
     * for idle vCPUs, it is safe to use it, with no locks, to figure that out.
     */
    ASSERT(is_idle_domain(d));
    return per_cpu(scheduler, v->processor);
}
#define VCPU2ONLINE(_v) cpupool_domain_cpumask((_v)->domain)

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

    __trace_var(event, 1/*tsc*/, sizeof(d), &d);
}

static inline void trace_continue_running(struct vcpu *v)
{
    struct { uint32_t vcpu:16, domain:16; } d;

    if ( likely(!tb_init_done) )
        return;

    d.vcpu = v->vcpu_id;
    d.domain = v->domain->domain_id;

    __trace_var(TRC_SCHED_CONTINUE_RUNNING, 1/*tsc*/, sizeof(d), &d);
}

static inline void vcpu_urgent_count_update(struct vcpu *v)
{
    if ( is_idle_vcpu(v) )
        return;

    if ( unlikely(v->is_urgent) )
    {
        if ( !(v->pause_flags & VPF_blocked) ||
             !test_bit(v->vcpu_id, v->domain->poll_mask) )
        {
            v->is_urgent = 0;
            atomic_dec(&per_cpu(schedule_data,v->processor).urgent_count);
        }
    }
    else
    {
        if ( unlikely(v->pause_flags & VPF_blocked) &&
             unlikely(test_bit(v->vcpu_id, v->domain->poll_mask)) )
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
    spinlock_t *lock = likely(v == current) ? NULL : vcpu_schedule_lock_irq(v);
    s_time_t delta;

    memcpy(runstate, &v->runstate, sizeof(*runstate));
    delta = NOW() - runstate->state_entry_time;
    if ( delta > 0 )
        runstate->time[runstate->state] += delta;

    if ( unlikely(lock != NULL) )
        vcpu_schedule_unlock_irq(lock, v);
}

uint64_t get_cpu_idle_time(unsigned int cpu)
{
    struct vcpu_runstate_info state = { 0 };
    struct vcpu *v = idle_vcpu[cpu];

    if ( cpu_online(cpu) && v )
        vcpu_runstate_get(v, &state);

    return state.time[RUNSTATE_running];
}

/*
 * If locks are different, take the one with the lower address first.
 * This avoids dead- or live-locks when this code is running on both
 * cpus at the same time.
 */
static void sched_spin_lock_double(spinlock_t *lock1, spinlock_t *lock2,
                                   unsigned long *flags)
{
    if ( lock1 == lock2 )
    {
        spin_lock_irqsave(lock1, *flags);
    }
    else if ( lock1 < lock2 )
    {
        spin_lock_irqsave(lock1, *flags);
        spin_lock(lock2);
    }
    else
    {
        spin_lock_irqsave(lock2, *flags);
        spin_lock(lock1);
    }
}

static void sched_spin_unlock_double(spinlock_t *lock1, spinlock_t *lock2,
                                     unsigned long flags)
{
    if ( lock1 != lock2 )
        spin_unlock(lock2);
    spin_unlock_irqrestore(lock1, flags);
}

int sched_init_vcpu(struct vcpu *v, unsigned int processor)
{
    struct domain *d = v->domain;

    v->processor = processor;

    /* Initialise the per-vcpu timers. */
    init_timer(&v->periodic_timer, vcpu_periodic_timer_fn,
               v, v->processor);
    init_timer(&v->singleshot_timer, vcpu_singleshot_timer_fn,
               v, v->processor);
    init_timer(&v->poll_timer, poll_timer_fn,
               v, v->processor);

    v->sched_priv = SCHED_OP(dom_scheduler(d), alloc_vdata, v,
                     d->sched_priv);
    if ( v->sched_priv == NULL )
        return 1;

    /*
     * Initialize affinity settings. The idler, and potentially
     * domain-0 VCPUs, are pinned onto their respective physical CPUs.
     */
    if ( is_idle_domain(d) || (is_hardware_domain(d) && opt_dom0_vcpus_pin) )
        sched_set_affinity(v, cpumask_of(processor), &cpumask_all);
    else
        sched_set_affinity(v, &cpumask_all, &cpumask_all);

    /* Idle VCPUs are scheduled immediately, so don't put them in runqueue. */
    if ( is_idle_domain(d) )
    {
        per_cpu(schedule_data, v->processor).curr = v;
        v->is_running = 1;
    }
    else
    {
        SCHED_OP(dom_scheduler(d), insert_vcpu, v);
    }

    return 0;
}

static void sched_move_irqs(struct vcpu *v)
{
    arch_move_irqs(v);
    evtchn_move_pirqs(v);
}

int sched_move_domain(struct domain *d, struct cpupool *c)
{
    struct vcpu *v;
    unsigned int new_p;
    void **vcpu_priv;
    void *domdata;
    void *vcpudata;
    struct scheduler *old_ops;
    void *old_domdata;

    for_each_vcpu ( d, v )
    {
        if ( v->affinity_broken )
            return -EBUSY;
    }

    domdata = sched_alloc_domdata(c->sched, d);
    if ( IS_ERR(domdata) )
        return PTR_ERR(domdata);

    vcpu_priv = xzalloc_array(void *, d->max_vcpus);
    if ( vcpu_priv == NULL )
    {
        sched_free_domdata(c->sched, domdata);
        return -ENOMEM;
    }

    for_each_vcpu ( d, v )
    {
        vcpu_priv[v->vcpu_id] = SCHED_OP(c->sched, alloc_vdata, v, domdata);
        if ( vcpu_priv[v->vcpu_id] == NULL )
        {
            for_each_vcpu ( d, v )
                xfree(vcpu_priv[v->vcpu_id]);
            xfree(vcpu_priv);
            sched_free_domdata(c->sched, domdata);
            return -ENOMEM;
        }
    }

    domain_pause(d);

    old_ops = dom_scheduler(d);
    old_domdata = d->sched_priv;

    for_each_vcpu ( d, v )
    {
        SCHED_OP(old_ops, remove_vcpu, v);
    }

    d->cpupool = c;
    d->sched_priv = domdata;

    new_p = cpumask_first(c->cpu_valid);
    for_each_vcpu ( d, v )
    {
        spinlock_t *lock;

        vcpudata = v->sched_priv;

        migrate_timer(&v->periodic_timer, new_p);
        migrate_timer(&v->singleshot_timer, new_p);
        migrate_timer(&v->poll_timer, new_p);

        lock = vcpu_schedule_lock_irq(v);

        sched_set_affinity(v, &cpumask_all, &cpumask_all);

        v->processor = new_p;
        /*
         * With v->processor modified we must not
         * - make any further changes assuming we hold the scheduler lock,
         * - use vcpu_schedule_unlock_irq().
         */
        spin_unlock_irq(lock);

        v->sched_priv = vcpu_priv[v->vcpu_id];
        if ( !d->is_dying )
            sched_move_irqs(v);

        new_p = cpumask_cycle(new_p, c->cpu_valid);

        SCHED_OP(c->sched, insert_vcpu, v);

        SCHED_OP(old_ops, free_vdata, vcpudata);
    }

    domain_update_node_affinity(d);

    domain_unpause(d);

    sched_free_domdata(old_ops, old_domdata);

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
    SCHED_OP(vcpu_scheduler(v), remove_vcpu, v);
    SCHED_OP(vcpu_scheduler(v), free_vdata, v->sched_priv);
}

int sched_init_domain(struct domain *d, int poolid)
{
    void *sdom;
    int ret;

    ASSERT(d->cpupool == NULL);
    ASSERT(d->domain_id < DOMID_FIRST_RESERVED);

    if ( (ret = cpupool_add_domain(d, poolid)) )
        return ret;

    SCHED_STAT_CRANK(dom_init);
    TRACE_1D(TRC_SCHED_DOM_ADD, d->domain_id);

    sdom = sched_alloc_domdata(dom_scheduler(d), d);
    if ( IS_ERR(sdom) )
        return PTR_ERR(sdom);

    d->sched_priv = sdom;

    return 0;
}

void sched_destroy_domain(struct domain *d)
{
    ASSERT(d->domain_id < DOMID_FIRST_RESERVED);

    if ( d->cpupool )
    {
        SCHED_STAT_CRANK(dom_destroy);
        TRACE_1D(TRC_SCHED_DOM_REM, d->domain_id);

        sched_free_domdata(dom_scheduler(d), d->sched_priv);
        d->sched_priv = NULL;

        cpupool_rm_domain(d);
    }
}

void vcpu_sleep_nosync_locked(struct vcpu *v)
{
    ASSERT(spin_is_locked(per_cpu(schedule_data,v->processor).schedule_lock));

    if ( likely(!vcpu_runnable(v)) )
    {
        if ( v->runstate.state == RUNSTATE_runnable )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());

        SCHED_OP(vcpu_scheduler(v), sleep, v);
    }
}

void vcpu_sleep_nosync(struct vcpu *v)
{
    unsigned long flags;
    spinlock_t *lock;

    TRACE_2D(TRC_SCHED_SLEEP, v->domain->domain_id, v->vcpu_id);

    lock = vcpu_schedule_lock_irqsave(v, &flags);

    vcpu_sleep_nosync_locked(v);

    vcpu_schedule_unlock_irqrestore(lock, flags, v);
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
    spinlock_t *lock;

    TRACE_2D(TRC_SCHED_WAKE, v->domain->domain_id, v->vcpu_id);

    lock = vcpu_schedule_lock_irqsave(v, &flags);

    if ( likely(vcpu_runnable(v)) )
    {
        if ( v->runstate.state >= RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_runnable, NOW());
        SCHED_OP(vcpu_scheduler(v), wake, v);
    }
    else if ( !(v->pause_flags & VPF_blocked) )
    {
        if ( v->runstate.state == RUNSTATE_blocked )
            vcpu_runstate_change(v, RUNSTATE_offline, NOW());
    }

    vcpu_schedule_unlock_irqrestore(lock, flags, v);
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

/*
 * Do the actual movement of a vcpu from old to new CPU. Locks for *both*
 * CPUs needs to have been taken already when calling this!
 */
static void vcpu_move_locked(struct vcpu *v, unsigned int new_cpu)
{
    unsigned int old_cpu = v->processor;

    /*
     * Transfer urgency status to new CPU before switching CPUs, as
     * once the switch occurs, v->is_urgent is no longer protected by
     * the per-CPU scheduler lock we are holding.
     */
    if ( unlikely(v->is_urgent) && (old_cpu != new_cpu) )
    {
        atomic_inc(&per_cpu(schedule_data, new_cpu).urgent_count);
        atomic_dec(&per_cpu(schedule_data, old_cpu).urgent_count);
    }

    /*
     * Actual CPU switch to new CPU.  This is safe because the lock
     * pointer cant' change while the current lock is held.
     */
    if ( vcpu_scheduler(v)->migrate )
        SCHED_OP(vcpu_scheduler(v), migrate, v, new_cpu);
    else
        v->processor = new_cpu;
}

/*
 * Initiating migration
 *
 * In order to migrate, we need the vcpu in question to have stopped
 * running and had SCHED_OP(sleep) called (to take it off any
 * runqueues, for instance); and if it is currently running, it needs
 * to be scheduled out.  Finally, we need to hold the scheduling locks
 * for both the processor we're migrating from, and the processor
 * we're migrating to.
 *
 * In order to avoid deadlock while satisfying the final requirement,
 * we must release any scheduling lock we hold, then try to grab both
 * locks we want, then double-check to make sure that what we started
 * to do hasn't been changed in the mean time.
 *
 * These steps are encapsulated in the following two functions; they
 * should be called like this:
 *
 *     lock = vcpu_schedule_lock_irq(v);
 *     vcpu_migrate_start(v);
 *     vcpu_schedule_unlock_irq(lock, v)
 *     vcpu_migrate_finish(v);
 *
 * vcpu_migrate_finish() will do the work now if it can, or simply
 * return if it can't (because v is still running); in that case
 * vcpu_migrate_finish() will be called by context_saved().
 */
static void vcpu_migrate_start(struct vcpu *v)
{
    set_bit(_VPF_migrating, &v->pause_flags);
    vcpu_sleep_nosync_locked(v);
}

static void vcpu_migrate_finish(struct vcpu *v)
{
    unsigned long flags;
    unsigned int old_cpu, new_cpu;
    spinlock_t *old_lock, *new_lock;
    bool_t pick_called = 0;

    /*
     * If the vcpu is currently running, this will be handled by
     * context_saved(); and in any case, if the bit is cleared, then
     * someone else has already done the work so we don't need to.
     */
    if ( v->is_running || !test_bit(_VPF_migrating, &v->pause_flags) )
        return;

    old_cpu = new_cpu = v->processor;
    for ( ; ; )
    {
        /*
         * We need another iteration if the pre-calculated lock addresses
         * are not correct any longer after evaluating old and new cpu holding
         * the locks.
         */
        old_lock = per_cpu(schedule_data, old_cpu).schedule_lock;
        new_lock = per_cpu(schedule_data, new_cpu).schedule_lock;

        sched_spin_lock_double(old_lock, new_lock, &flags);

        old_cpu = v->processor;
        if ( old_lock == per_cpu(schedule_data, old_cpu).schedule_lock )
        {
            /*
             * If we selected a CPU on the previosu iteration, check if it
             * remains suitable for running this vCPU.
             */
            if ( pick_called &&
                 (new_lock == per_cpu(schedule_data, new_cpu).schedule_lock) &&
                 cpumask_test_cpu(new_cpu, v->cpu_hard_affinity) &&
                 cpumask_test_cpu(new_cpu, v->domain->cpupool->cpu_valid) )
                break;

            /* Select a new CPU. */
            new_cpu = SCHED_OP(vcpu_scheduler(v), pick_cpu, v);
            if ( (new_lock == per_cpu(schedule_data, new_cpu).schedule_lock) &&
                 cpumask_test_cpu(new_cpu, v->domain->cpupool->cpu_valid) )
                break;
            pick_called = 1;
        }
        else
        {
            /*
             * We do not hold the scheduler lock appropriate for this vCPU.
             * Thus we cannot select a new CPU on this iteration. Try again.
             */
            pick_called = 0;
        }

        sched_spin_unlock_double(old_lock, new_lock, flags);
    }

    /*
     * NB. Check of v->running happens /after/ setting migration flag
     * because they both happen in (different) spinlock regions, and those
     * regions are strictly serialised.
     */
    if ( v->is_running ||
         !test_and_clear_bit(_VPF_migrating, &v->pause_flags) )
    {
        sched_spin_unlock_double(old_lock, new_lock, flags);
        return;
    }

    vcpu_move_locked(v, new_cpu);

    sched_spin_unlock_double(old_lock, new_lock, flags);

    if ( old_cpu != new_cpu )
        sched_move_irqs(v);

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
    spinlock_t *lock = vcpu_schedule_lock_irq(v);

    if ( v->is_running )
        vcpu_migrate_start(v);

    vcpu_schedule_unlock_irq(lock, v);

    vcpu_migrate_finish(v);
}

void restore_vcpu_affinity(struct domain *d)
{
    unsigned int cpu = smp_processor_id();
    struct vcpu *v;

    ASSERT(system_state == SYS_STATE_resume);

    for_each_vcpu ( d, v )
    {
        spinlock_t *lock;
        unsigned int old_cpu = v->processor;

        ASSERT(!vcpu_runnable(v));

        /*
         * Re-assign the initial processor as after resume we have no
         * guarantee the old processor has come back to life again.
         *
         * Therefore, here, before actually unpausing the domains, we should
         * set v->processor of each of their vCPUs to something that will
         * make sense for the scheduler of the cpupool in which they are in.
         */
        cpumask_and(cpumask_scratch_cpu(cpu), v->cpu_hard_affinity,
                    cpupool_domain_cpumask(d));
        if ( cpumask_empty(cpumask_scratch_cpu(cpu)) )
        {
            if ( v->affinity_broken )
            {
                sched_set_affinity(v, v->cpu_hard_affinity_saved, NULL);
                v->affinity_broken = 0;
                cpumask_and(cpumask_scratch_cpu(cpu), v->cpu_hard_affinity,
                            cpupool_domain_cpumask(d));
            }

            if ( cpumask_empty(cpumask_scratch_cpu(cpu)) )
            {
                printk(XENLOG_DEBUG "Breaking affinity for %pv\n", v);
                sched_set_affinity(v, &cpumask_all, NULL);
                cpumask_and(cpumask_scratch_cpu(cpu), v->cpu_hard_affinity,
                            cpupool_domain_cpumask(d));
            }
        }

        v->processor = cpumask_any(cpumask_scratch_cpu(cpu));

        lock = vcpu_schedule_lock_irq(v);
        v->processor = SCHED_OP(vcpu_scheduler(v), pick_cpu, v);
        spin_unlock_irq(lock);

        if ( old_cpu != v->processor )
            sched_move_irqs(v);
    }

    domain_update_node_affinity(d);
}

/*
 * This function is used by cpu_hotplug code via cpu notifier chain
 * and from cpupools to switch schedulers on a cpu.
 * Caller must get domlist_read_lock.
 */
int cpu_disable_scheduler(unsigned int cpu)
{
    struct domain *d;
    struct vcpu *v;
    struct cpupool *c;
    cpumask_t online_affinity;
    int ret = 0;

    c = per_cpu(cpupool, cpu);
    if ( c == NULL )
        return ret;

    for_each_domain_in_cpupool ( d, c )
    {
        for_each_vcpu ( d, v )
        {
            unsigned long flags;
            spinlock_t *lock = vcpu_schedule_lock_irqsave(v, &flags);

            cpumask_and(&online_affinity, v->cpu_hard_affinity, c->cpu_valid);
            if ( cpumask_empty(&online_affinity) &&
                 cpumask_test_cpu(cpu, v->cpu_hard_affinity) )
            {
                if ( v->affinity_broken )
                {
                    /* The vcpu is temporarily pinned, can't move it. */
                    vcpu_schedule_unlock_irqrestore(lock, flags, v);
                    ret = -EADDRINUSE;
                    break;
                }

                printk(XENLOG_DEBUG "Breaking affinity for %pv\n", v);

                sched_set_affinity(v, &cpumask_all, NULL);
            }

            if ( v->processor != cpu )
            {
                /* The vcpu is not on this cpu, so we can move on. */
                vcpu_schedule_unlock_irqrestore(lock, flags, v);
                continue;
            }

            /* If it is on this cpu, we must send it away.
             * We are doing some cpupool manipulations:
             *  * we want to call the scheduler, and let it re-evaluation
             *    the placement of the vcpu, taking into account the new
             *    cpupool configuration;
             *  * the scheduler will always find a suitable solution, or
             *    things would have failed before getting in here.
             */
            vcpu_migrate_start(v);
            vcpu_schedule_unlock_irqrestore(lock, flags, v);

            vcpu_migrate_finish(v);

            /*
             * The only caveat, in this case, is that if a vcpu active in
             * the hypervisor isn't migratable. In this case, the caller
             * should try again after releasing and reaquiring all locks.
             */
            if ( v->processor == cpu )
                ret = -EAGAIN;
        }
    }

    return ret;
}

static int cpu_disable_scheduler_check(unsigned int cpu)
{
    struct domain *d;
    struct vcpu *v;
    struct cpupool *c;

    c = per_cpu(cpupool, cpu);
    if ( c == NULL )
        return 0;

    for_each_domain_in_cpupool ( d, c )
        for_each_vcpu ( d, v )
            if ( v->affinity_broken )
                return -EADDRINUSE;

    return 0;
}

/*
 * In general, this must be called with the scheduler lock held, because the
 * adjust_affinity hook may want to modify the vCPU state. However, when the
 * vCPU is being initialized (either for dom0 or domU) there is no risk of
 * races, and it's fine to not take the look (we're talking about
 * dom0_setup_vcpu() an sched_init_vcpu()).
 */
void sched_set_affinity(
    struct vcpu *v, const cpumask_t *hard, const cpumask_t *soft)
{
    SCHED_OP(dom_scheduler(v->domain), adjust_affinity, v, hard, soft);

    if ( hard )
        cpumask_copy(v->cpu_hard_affinity, hard);
    if ( soft )
        cpumask_copy(v->cpu_soft_affinity, soft);

    v->soft_aff_effective = !cpumask_subset(v->cpu_hard_affinity,
                                            v->cpu_soft_affinity) &&
                            cpumask_intersects(v->cpu_soft_affinity,
                                               v->cpu_hard_affinity);
}

static int vcpu_set_affinity(
    struct vcpu *v, const cpumask_t *affinity, const cpumask_t *which)
{
    spinlock_t *lock;
    int ret = 0;

    lock = vcpu_schedule_lock_irq(v);

    if ( v->affinity_broken )
        ret = -EBUSY;
    else
    {
        /*
         * Tell the scheduler we changes something about affinity,
         * and ask to re-evaluate vcpu placement.
         */
        if ( which == v->cpu_hard_affinity )
        {
            sched_set_affinity(v, affinity, NULL);
        }
        else
        {
            ASSERT(which == v->cpu_soft_affinity);
            sched_set_affinity(v, NULL, affinity);
        }
        vcpu_migrate_start(v);
    }

    vcpu_schedule_unlock_irq(lock, v);

    domain_update_node_affinity(v->domain);

    vcpu_migrate_finish(v);

    return ret;
}

int vcpu_set_hard_affinity(struct vcpu *v, const cpumask_t *affinity)
{
    cpumask_t online_affinity;
    cpumask_t *online;

    online = VCPU2ONLINE(v);
    cpumask_and(&online_affinity, affinity, online);
    if ( cpumask_empty(&online_affinity) )
        return -EINVAL;

    return vcpu_set_affinity(v, affinity, v->cpu_hard_affinity);
}

int vcpu_set_soft_affinity(struct vcpu *v, const cpumask_t *affinity)
{
    return vcpu_set_affinity(v, affinity, v->cpu_soft_affinity);
}

/* Block the currently-executing domain until a pertinent event occurs. */
void vcpu_block(void)
{
    struct vcpu *v = current;

    set_bit(_VPF_blocked, &v->pause_flags);

    arch_vcpu_block(v);

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
}

static void vcpu_block_enable_events(void)
{
    local_event_delivery_enable();
    vcpu_block();
}

static long do_poll(struct sched_poll *sched_poll)
{
    struct vcpu   *v = current;
    struct domain *d = v->domain;
    evtchn_port_t  port = 0;
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

    arch_vcpu_block(v);

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
        if ( port >= d->max_evtchns )
            goto out;

        rc = 0;
        if ( evtchn_port_is_pending(d, port) )
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
long vcpu_yield(void)
{
    struct vcpu * v=current;
    spinlock_t *lock = vcpu_schedule_lock_irq(v);

    SCHED_OP(vcpu_scheduler(v), yield, v);
    vcpu_schedule_unlock_irq(lock, v);

    SCHED_STAT_CRANK(vcpu_yield);

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
        return id == NR_DOMAIN_WATCHDOG_TIMERS ? -ENOSPC : id + 1;
    }

    id -= 1;
    if ( !test_bit(id, &d->watchdog_inuse_map) )
    {
        spin_unlock(&d->watchdog_lock);
        return -EINVAL;
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

int vcpu_pin_override(struct vcpu *v, int cpu)
{
    spinlock_t *lock;
    int ret = -EINVAL;

    lock = vcpu_schedule_lock_irq(v);

    if ( cpu < 0 )
    {
        if ( v->affinity_broken )
        {
            sched_set_affinity(v, v->cpu_hard_affinity_saved, NULL);
            v->affinity_broken = 0;
            ret = 0;
        }
    }
    else if ( cpu < nr_cpu_ids )
    {
        if ( v->affinity_broken )
            ret = -EBUSY;
        else if ( cpumask_test_cpu(cpu, VCPU2ONLINE(v)) )
        {
            cpumask_copy(v->cpu_hard_affinity_saved, v->cpu_hard_affinity);
            v->affinity_broken = 1;
            sched_set_affinity(v, cpumask_of(cpu), NULL);
            ret = 0;
        }
    }

    if ( ret == 0 )
        vcpu_migrate_start(v);

    vcpu_schedule_unlock_irq(lock, v);

    domain_update_node_affinity(v->domain);

    vcpu_migrate_finish(v);

    return ret;
}

typedef long ret_t;

#endif /* !COMPAT */

ret_t do_sched_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    ret_t ret = 0;

    switch ( cmd )
    {
    case SCHEDOP_yield:
    {
        ret = vcpu_yield();
        break;
    }

    case SCHEDOP_block:
    {
        vcpu_block_enable_events();
        break;
    }

    case SCHEDOP_shutdown:
    {
        struct sched_shutdown sched_shutdown;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_shutdown, arg, 1) )
            break;

        TRACE_3D(TRC_SCHED_SHUTDOWN,
                 current->domain->domain_id, current->vcpu_id,
                 sched_shutdown.reason);
        ret = domain_shutdown(current->domain, (u8)sched_shutdown.reason);

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
        if ( d->shutdown_code == SHUTDOWN_CODE_INVALID )
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

        ret = xsm_schedop_shutdown(XSM_DM_PRIV, current->domain, d);
        if ( likely(!ret) )
            domain_shutdown(d, sched_remote_shutdown.reason);

        rcu_unlock_domain(d);

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

    case SCHEDOP_pin_override:
    {
        struct sched_pin_override sched_pin_override;

        ret = -EPERM;
        if ( !is_hardware_domain(current->domain) )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&sched_pin_override, arg, 1) )
            break;

        ret = vcpu_pin_override(current, sched_pin_override.pcpu);

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
        gdprintk(XENLOG_INFO, "Warning: huge timeout set: %"PRIx64"\n",
                 timeout);
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
    long ret;

    ret = xsm_domctl_scheduler_op(XSM_HOOK, d, op->cmd);
    if ( ret )
        return ret;

    if ( op->sched_id != dom_scheduler(d)->sched_id )
        return -EINVAL;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_SCHEDOP_putinfo:
    case XEN_DOMCTL_SCHEDOP_getinfo:
    case XEN_DOMCTL_SCHEDOP_putvcpuinfo:
    case XEN_DOMCTL_SCHEDOP_getvcpuinfo:
        break;
    default:
        return -EINVAL;
    }

    /* NB: the pluggable scheduler code needs to take care
     * of locking by itself. */
    if ( (ret = SCHED_OP(dom_scheduler(d), adjust, d, op)) == 0 )
        TRACE_1D(TRC_SCHED_ADJDOM, d->domain_id);

    return ret;
}

long sched_adjust_global(struct xen_sysctl_scheduler_op *op)
{
    struct cpupool *pool;
    int rc;

    rc = xsm_sysctl_scheduler_op(XSM_HOOK, op->cmd);
    if ( rc )
        return rc;

    if ( (op->cmd != XEN_SYSCTL_SCHEDOP_putinfo) &&
         (op->cmd != XEN_SYSCTL_SCHEDOP_getinfo) )
        return -EINVAL;

    pool = cpupool_get_by_id(op->cpupool_id);
    if ( pool == NULL )
        return -ESRCH;

    rc = ((op->sched_id == pool->sched->sched_id)
          ? SCHED_OP(pool->sched, adjust_global, op) : -EINVAL);

    cpupool_put(pool);

    return rc;
}

static void vcpu_periodic_timer_work(struct vcpu *v)
{
    s_time_t now;
    s_time_t periodic_next_event;

    if ( v->periodic_period == 0 )
        return;

    now = NOW();
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
    s_time_t              now;
    struct scheduler     *sched;
    unsigned long        *tasklet_work = &this_cpu(tasklet_work_to_do);
    bool_t                tasklet_work_scheduled = 0;
    struct schedule_data *sd;
    spinlock_t           *lock;
    struct task_slice     next_slice;
    int cpu = smp_processor_id();

    ASSERT_NOT_IN_ATOMIC();

    SCHED_STAT_CRANK(sched_run);

    sd = &this_cpu(schedule_data);

    /* Update tasklet scheduling status. */
    switch ( *tasklet_work )
    {
    case TASKLET_enqueued:
        set_bit(_TASKLET_scheduled, tasklet_work);
        /* fallthrough */
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

    lock = pcpu_schedule_lock_irq(cpu);

    now = NOW();

    stop_timer(&sd->s_timer);

    /* get policy-specific decision on scheduling... */
    sched = this_cpu(scheduler);
    next_slice = sched->do_schedule(sched, now, tasklet_work_scheduled);

    next = next_slice.task;

    sd->curr = next;

    if ( next_slice.time >= 0 ) /* -ve means no limit */
        set_timer(&sd->s_timer, now + next_slice.time);

    if ( unlikely(prev == next) )
    {
        pcpu_schedule_unlock_irq(lock, cpu);
        TRACE_4D(TRC_SCHED_SWITCH_INFCONT,
                 next->domain->domain_id, next->vcpu_id,
                 now - prev->runstate.state_entry_time,
                 next_slice.time);
        trace_continue_running(next);
        return continue_running(prev);
    }

    TRACE_3D(TRC_SCHED_SWITCH_INFPREV,
             prev->domain->domain_id, prev->vcpu_id,
             now - prev->runstate.state_entry_time);
    TRACE_4D(TRC_SCHED_SWITCH_INFNEXT,
             next->domain->domain_id, next->vcpu_id,
             (next->runstate.state == RUNSTATE_runnable) ?
             (now - next->runstate.state_entry_time) : 0,
             next_slice.time);

    ASSERT(prev->runstate.state == RUNSTATE_running);

    TRACE_4D(TRC_SCHED_SWITCH,
             prev->domain->domain_id, prev->vcpu_id,
             next->domain->domain_id, next->vcpu_id);

    vcpu_runstate_change(
        prev,
        ((prev->pause_flags & VPF_blocked) ? RUNSTATE_blocked :
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

    pcpu_schedule_unlock_irq(lock, cpu);

    SCHED_STAT_CRANK(sched_ctx);

    stop_timer(&prev->periodic_timer);

    if ( next_slice.migrated )
        sched_move_irqs(next);

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

    SCHED_OP(vcpu_scheduler(prev), context_saved, prev);

    vcpu_migrate_finish(prev);
}

/* The scheduler timer: force a run through the scheduler */
static void s_timer_fn(void *unused)
{
    raise_softirq(SCHEDULE_SOFTIRQ);
    SCHED_STAT_CRANK(sched_irq);
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
    void *sched_priv;

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
        vcpu_create(idle_vcpu[0]->domain, cpu, cpu);
    else
    {
        struct vcpu *idle = idle_vcpu[cpu];

        /*
         * During (ACPI?) suspend the idle vCPU for this pCPU is not freed,
         * while its scheduler specific data (what is pointed by sched_priv)
         * is. Also, at this stage of the resume path, we attach the pCPU
         * to the default scheduler, no matter in what cpupool it was before
         * suspend. To avoid inconsistency, let's allocate default scheduler
         * data for the idle vCPU here. If the pCPU was in a different pool
         * with a different scheduler, it is schedule_cpu_switch(), invoked
         * later, that will set things up as appropriate.
         */
        ASSERT(idle->sched_priv == NULL);

        idle->sched_priv = SCHED_OP(&ops, alloc_vdata, idle,
                                    idle->domain->sched_priv);
        if ( idle->sched_priv == NULL )
            return -ENOMEM;
    }
    if ( idle_vcpu[cpu] == NULL )
        return -ENOMEM;

    /*
     * We don't want to risk calling xfree() on an sd->sched_priv
     * (e.g., inside free_pdata, from cpu_schedule_down() called
     * during CPU_UP_CANCELLED) that contains an IS_ERR value.
     */
    sched_priv = SCHED_OP(&ops, alloc_pdata, cpu);
    if ( IS_ERR(sched_priv) )
        return PTR_ERR(sched_priv);

    sd->sched_priv = sched_priv;

    return 0;
}

static void cpu_schedule_down(unsigned int cpu)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    struct scheduler *sched = per_cpu(scheduler, cpu);

    SCHED_OP(sched, free_pdata, sd->sched_priv, cpu);
    SCHED_OP(sched, free_vdata, idle_vcpu[cpu]->sched_priv);

    idle_vcpu[cpu]->sched_priv = NULL;
    sd->sched_priv = NULL;

    kill_timer(&sd->s_timer);
}

static int cpu_schedule_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    struct scheduler *sched = per_cpu(scheduler, cpu);
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    int rc = 0;

    /*
     * From the scheduler perspective, bringing up a pCPU requires
     * allocating and initializing the per-pCPU scheduler specific data,
     * as well as "registering" this pCPU to the scheduler (which may
     * involve modifying some scheduler wide data structures).
     * This happens by calling the alloc_pdata and init_pdata hooks, in
     * this order. A scheduler that does not need to allocate any per-pCPU
     * data can avoid implementing alloc_pdata. init_pdata may, however, be
     * necessary/useful in this case too (e.g., it can contain the "register
     * the pCPU to the scheduler" part). alloc_pdata (if present) is called
     * during CPU_UP_PREPARE. init_pdata (if present) is called during
     * CPU_STARTING.
     *
     * On the other hand, at teardown, we need to reverse what has been done
     * during initialization, and then free the per-pCPU specific data. This
     * happens by calling the deinit_pdata and free_pdata hooks, in this
     * order. If no per-pCPU memory was allocated, there is no need to
     * provide an implementation of free_pdata. deinit_pdata may, however,
     * be necessary/useful in this case too (e.g., it can undo something done
     * on scheduler wide data structure during init_pdata). Both deinit_pdata
     * and free_pdata are called during CPU_DEAD.
     *
     * If someting goes wrong during bringup, we go to CPU_UP_CANCELLED
     * *before* having called init_pdata. In this case, as there is no
     * initialization needing undoing, only free_pdata should be called.
     * This means it is possible to call free_pdata just after alloc_pdata,
     * without a init_pdata/deinit_pdata "cycle" in between the two.
     *
     * So, in summary, the usage pattern should look either
     *  - alloc_pdata-->init_pdata-->deinit_pdata-->free_pdata, or
     *  - alloc_pdata-->free_pdata.
     */
    switch ( action )
    {
    case CPU_STARTING:
        if ( system_state != SYS_STATE_resume )
            SCHED_OP(sched, init_pdata, sd->sched_priv, cpu);
        break;
    case CPU_UP_PREPARE:
        if ( system_state != SYS_STATE_resume )
            rc = cpu_schedule_up(cpu);
        break;
    case CPU_DOWN_PREPARE:
        rcu_read_lock(&domlist_read_lock);
        rc = cpu_disable_scheduler_check(cpu);
        rcu_read_unlock(&domlist_read_lock);
        break;
    case CPU_RESUME_FAILED:
    case CPU_DEAD:
        if ( system_state == SYS_STATE_suspend )
            break;
        rcu_read_lock(&domlist_read_lock);
        rc = cpu_disable_scheduler(cpu);
        BUG_ON(rc);
        rcu_read_unlock(&domlist_read_lock);
        SCHED_OP(sched, deinit_pdata, sd->sched_priv, cpu);
        cpu_schedule_down(cpu);
        break;
    case CPU_UP_CANCELED:
        if ( system_state != SYS_STATE_resume )
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

    for ( i = 0; i < NUM_SCHEDULERS; i++)
    {
        if ( schedulers[i]->global_init && schedulers[i]->global_init() < 0 )
            schedulers[i] = NULL;
        else if ( !ops.name && !strcmp(schedulers[i]->opt_name, opt_sched) )
            ops = *schedulers[i];
    }

    if ( !ops.name )
    {
        printk("Could not find scheduler: %s\n", opt_sched);
        for ( i = 0; i < NUM_SCHEDULERS; i++ )
            if ( schedulers[i] &&
                 !strcmp(schedulers[i]->opt_name, CONFIG_SCHED_DEFAULT) )
            {
                ops = *schedulers[i];
                break;
            }
        BUG_ON(!ops.name);
        printk("Using '%s' (%s)\n", ops.name, ops.opt_name);
    }

    if ( cpu_schedule_up(0) )
        BUG();
    register_cpu_notifier(&cpu_schedule_nfb);

    printk("Using scheduler: %s (%s)\n", ops.name, ops.opt_name);
    if ( SCHED_OP(&ops, init) )
        panic("scheduler returned error on init\n");

    if ( sched_ratelimit_us &&
         (sched_ratelimit_us > XEN_SYSCTL_SCHED_RATELIMIT_MAX
          || sched_ratelimit_us < XEN_SYSCTL_SCHED_RATELIMIT_MIN) )
    {
        printk("WARNING: sched_ratelimit_us outside of valid range [%d,%d].\n"
               " Resetting to default %u\n",
               XEN_SYSCTL_SCHED_RATELIMIT_MIN,
               XEN_SYSCTL_SCHED_RATELIMIT_MAX,
               SCHED_DEFAULT_RATELIMIT_US);
        sched_ratelimit_us = SCHED_DEFAULT_RATELIMIT_US;
    }

    idle_domain = domain_create(DOMID_IDLE, NULL, false);
    BUG_ON(IS_ERR(idle_domain));
    BUG_ON(nr_cpu_ids > ARRAY_SIZE(idle_vcpu));
    idle_domain->vcpu = idle_vcpu;
    idle_domain->max_vcpus = nr_cpu_ids;
    if ( vcpu_create(idle_domain, 0, 0) == NULL )
        BUG();
    this_cpu(schedule_data).sched_priv = SCHED_OP(&ops, alloc_pdata, 0);
    BUG_ON(IS_ERR(this_cpu(schedule_data).sched_priv));
    SCHED_OP(&ops, init_pdata, this_cpu(schedule_data).sched_priv, 0);
}

/*
 * Move a pCPU outside of the influence of the scheduler of its current
 * cpupool, or subject it to the scheduler of a new cpupool.
 *
 * For the pCPUs that are removed from their cpupool, their scheduler becomes
 * &ops (the default scheduler, selected at boot, which also services the
 * default cpupool). However, as these pCPUs are not really part of any pool,
 * there won't be any scheduling event on them, not even from the default
 * scheduler. Basically, they will just sit idle until they are explicitly
 * added back to a cpupool.
 */
int schedule_cpu_switch(unsigned int cpu, struct cpupool *c)
{
    struct vcpu *idle;
    void *ppriv, *ppriv_old, *vpriv, *vpriv_old;
    struct scheduler *old_ops = per_cpu(scheduler, cpu);
    struct scheduler *new_ops = (c == NULL) ? &ops : c->sched;
    struct cpupool *old_pool = per_cpu(cpupool, cpu);
    spinlock_t * old_lock;

    /*
     * pCPUs only move from a valid cpupool to free (i.e., out of any pool),
     * or from free to a valid cpupool. In the former case (which happens when
     * c is NULL), we want the CPU to have been marked as free already, as
     * well as to not be valid for the source pool any longer, when we get to
     * here. In the latter case (which happens when c is a valid cpupool), we
     * want the CPU to still be marked as free, as well as to not yet be valid
     * for the destination pool.
     */
    ASSERT(c != old_pool && (c != NULL || old_pool != NULL));
    ASSERT(cpumask_test_cpu(cpu, &cpupool_free_cpus));
    ASSERT((c == NULL && !cpumask_test_cpu(cpu, old_pool->cpu_valid)) ||
           (c != NULL && !cpumask_test_cpu(cpu, c->cpu_valid)));

    if ( old_ops == new_ops )
        goto out;

    /*
     * To setup the cpu for the new scheduler we need:
     *  - a valid instance of per-CPU scheduler specific data, as it is
     *    allocated by SCHED_OP(alloc_pdata). Note that we do not want to
     *    initialize it yet (i.e., we are not calling SCHED_OP(init_pdata)).
     *    That will be done by the target scheduler, in SCHED_OP(switch_sched),
     *    in proper ordering and with locking.
     *  - a valid instance of per-vCPU scheduler specific data, for the idle
     *    vCPU of cpu. That is what the target scheduler will use for the
     *    sched_priv field of the per-vCPU info of the idle domain.
     */
    idle = idle_vcpu[cpu];
    ppriv = SCHED_OP(new_ops, alloc_pdata, cpu);
    if ( IS_ERR(ppriv) )
        return PTR_ERR(ppriv);
    vpriv = SCHED_OP(new_ops, alloc_vdata, idle, idle->domain->sched_priv);
    if ( vpriv == NULL )
    {
        SCHED_OP(new_ops, free_pdata, ppriv, cpu);
        return -ENOMEM;
    }

    SCHED_OP(old_ops, tick_suspend, cpu);

    /*
     * The actual switch, including (if necessary) the rerouting of the
     * scheduler lock to whatever new_ops prefers,  needs to happen in one
     * critical section, protected by old_ops' lock, or races are possible.
     * It is, in fact, the lock of another scheduler that we are taking (the
     * scheduler of the cpupool that cpu still belongs to). But that is ok
     * as, anyone trying to schedule on this cpu will spin until when we
     * release that lock (bottom of this function). When he'll get the lock
     * --thanks to the loop inside *_schedule_lock() functions-- he'll notice
     * that the lock itself changed, and retry acquiring the new one (which
     * will be the correct, remapped one, at that point).
     */
    old_lock = pcpu_schedule_lock_irq(cpu);

    vpriv_old = idle->sched_priv;
    ppriv_old = per_cpu(schedule_data, cpu).sched_priv;
    SCHED_OP(new_ops, switch_sched, cpu, ppriv, vpriv);

    /* _Not_ pcpu_schedule_unlock(): schedule_lock may have changed! */
    spin_unlock_irq(old_lock);

    SCHED_OP(new_ops, tick_resume, cpu);

    SCHED_OP(old_ops, deinit_pdata, ppriv_old, cpu);

    SCHED_OP(old_ops, free_vdata, vpriv_old);
    SCHED_OP(old_ops, free_pdata, ppriv_old, cpu);

 out:
    per_cpu(cpupool, cpu) = c;
    /* When a cpu is added to a pool, trigger it to go pick up some work */
    if ( c != NULL )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);

    return 0;
}

struct scheduler *scheduler_get_default(void)
{
    return &ops;
}

struct scheduler *scheduler_alloc(unsigned int sched_id, int *perr)
{
    int i;
    struct scheduler *sched;

    for ( i = 0; i < NUM_SCHEDULERS; i++ )
        if ( schedulers[i] && schedulers[i]->sched_id == sched_id )
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
    unsigned int      i;
    struct scheduler *sched;
    cpumask_t        *cpus;

    /* Locking, if necessary, must be handled withing each scheduler */

    if ( c != NULL )
    {
        sched = c->sched;
        cpus = c->cpu_valid;
        printk("Scheduler: %s (%s)\n", sched->name, sched->opt_name);
        SCHED_OP(sched, dump_settings);
    }
    else
    {
        sched = &ops;
        cpus = &cpupool_free_cpus;
    }

    if ( sched->dump_cpu_state != NULL )
    {
        printk("CPUs info:\n");
        for_each_cpu (i, cpus)
            SCHED_OP(sched, dump_cpu_state, i);
    }
}

void sched_tick_suspend(void)
{
    struct scheduler *sched;
    unsigned int cpu = smp_processor_id();

    sched = per_cpu(scheduler, cpu);
    SCHED_OP(sched, tick_suspend, cpu);
    rcu_idle_enter(cpu);
    rcu_idle_timer_start();
}

void sched_tick_resume(void)
{
    struct scheduler *sched;
    unsigned int cpu = smp_processor_id();

    rcu_idle_timer_stop();
    rcu_idle_exit(cpu);
    sched = per_cpu(scheduler, cpu);
    SCHED_OP(sched, tick_resume, cpu);
}

void wait(void)
{
    schedule();
}

#ifdef CONFIG_COMPAT
#include "compat/schedule.c"
#endif

#endif /* !COMPAT */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
