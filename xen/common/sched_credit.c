/****************************************************************************
 * (C) 2005-2006 - Emmanuel Ackaouy - XenSource Inc.
 ****************************************************************************
 *
 *        File: common/csched_credit.c
 *      Author: Emmanuel Ackaouy
 *
 * Description: Credit-based SMP CPU scheduler
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/atomic.h>
#include <asm/div64.h>
#include <xen/errno.h>
#include <xen/keyhandler.h>
#include <xen/trace.h>


/*
 * Locking:
 * - Scheduler-lock (a.k.a. runqueue lock):
 *  + is per-runqueue, and there is one runqueue per-cpu;
 *  + serializes all runqueue manipulation operations;
 * - Private data lock (a.k.a. private scheduler lock):
 *  + serializes accesses to the scheduler global state (weight,
 *    credit, balance_credit, etc);
 *  + serializes updates to the domains' scheduling parameters.
 *
 * Ordering is "private lock always comes first":
 *  + if we need both locks, we must acquire the private
 *    scheduler lock for first;
 *  + if we already own a runqueue lock, we must never acquire
 *    the private scheduler lock.
 */

/*
 * Basic constants
 */
#define CSCHED_DEFAULT_WEIGHT       256
#define CSCHED_TICKS_PER_TSLICE     3
/* Default timeslice: 30ms */
#define CSCHED_DEFAULT_TSLICE_MS    30
#define CSCHED_CREDITS_PER_MSEC     10


/*
 * Priorities
 */
#define CSCHED_PRI_TS_BOOST      0      /* time-share waking up */
#define CSCHED_PRI_TS_UNDER     -1      /* time-share w/ credits */
#define CSCHED_PRI_TS_OVER      -2      /* time-share w/o credits */
#define CSCHED_PRI_IDLE         -64     /* idle */


/*
 * Flags
 */
#define CSCHED_FLAG_VCPU_PARKED    0x0  /* VCPU over capped credits */
#define CSCHED_FLAG_VCPU_YIELD     0x1  /* VCPU yielding */


/*
 * Useful macros
 */
#define CSCHED_PRIV(_ops)   \
    ((struct csched_private *)((_ops)->sched_data))
#define CSCHED_PCPU(_c)     \
    ((struct csched_pcpu *)per_cpu(schedule_data, _c).sched_priv)
#define CSCHED_VCPU(_vcpu)  ((struct csched_vcpu *) (_vcpu)->sched_priv)
#define CSCHED_DOM(_dom)    ((struct csched_dom *) (_dom)->sched_priv)
#define RUNQ(_cpu)          (&(CSCHED_PCPU(_cpu)->runq))
/* Is the first element of _cpu's runq its idle vcpu? */
#define IS_RUNQ_IDLE(_cpu)  (list_empty(RUNQ(_cpu)) || \
                             is_idle_vcpu(__runq_elem(RUNQ(_cpu)->next)->vcpu))


/*
 * CSCHED_STATS
 *
 * Manage very basic per-vCPU counters and stats.
 *
 * Useful for debugging live systems. The stats are displayed
 * with runq dumps ('r' on the Xen console).
 */
#ifdef SCHED_STATS

#define CSCHED_STATS

#define SCHED_VCPU_STATS_RESET(_V)                      \
    do                                                  \
    {                                                   \
        memset(&(_V)->stats, 0, sizeof((_V)->stats));   \
    } while ( 0 )

#define SCHED_VCPU_STAT_CRANK(_V, _X)       (((_V)->stats._X)++)

#define SCHED_VCPU_STAT_SET(_V, _X, _Y)     (((_V)->stats._X) = (_Y))

#else /* !SCHED_STATS */

#undef CSCHED_STATS

#define SCHED_VCPU_STATS_RESET(_V)         do {} while ( 0 )
#define SCHED_VCPU_STAT_CRANK(_V, _X)      do {} while ( 0 )
#define SCHED_VCPU_STAT_SET(_V, _X, _Y)    do {} while ( 0 )

#endif /* SCHED_STATS */


/*
 * Credit tracing events ("only" 512 available!). Check
 * include/public/trace.h for more details.
 */
#define TRC_CSCHED_SCHED_TASKLET TRC_SCHED_CLASS_EVT(CSCHED, 1)
#define TRC_CSCHED_ACCOUNT_START TRC_SCHED_CLASS_EVT(CSCHED, 2)
#define TRC_CSCHED_ACCOUNT_STOP  TRC_SCHED_CLASS_EVT(CSCHED, 3)
#define TRC_CSCHED_STOLEN_VCPU   TRC_SCHED_CLASS_EVT(CSCHED, 4)
#define TRC_CSCHED_PICKED_CPU    TRC_SCHED_CLASS_EVT(CSCHED, 5)
#define TRC_CSCHED_TICKLE        TRC_SCHED_CLASS_EVT(CSCHED, 6)


/*
 * Hard and soft affinity load balancing.
 *
 * Idea is each vcpu has some pcpus that it prefers, some that it does not
 * prefer but is OK with, and some that it cannot run on at all. The first
 * set of pcpus are the ones that are both in the soft affinity *and* in the
 * hard affinity; the second set of pcpus are the ones that are in the hard
 * affinity but *not* in the soft affinity; the third set of pcpus are the
 * ones that are not in the hard affinity.
 *
 * We implement a two step balancing logic. Basically, every time there is
 * the need to decide where to run a vcpu, we first check the soft affinity
 * (well, actually, the && between soft and hard affinity), to see if we can
 * send it where it prefers to (and can) run on. However, if the first step
 * does not find any suitable and free pcpu, we fall back checking the hard
 * affinity.
 */
#define CSCHED_BALANCE_SOFT_AFFINITY    0
#define CSCHED_BALANCE_HARD_AFFINITY    1

/*
 * Boot parameters
 */
static int __read_mostly sched_credit_tslice_ms = CSCHED_DEFAULT_TSLICE_MS;
integer_param("sched_credit_tslice_ms", sched_credit_tslice_ms);

/*
 * Physical CPU
 */
struct csched_pcpu {
    struct list_head runq;
    uint32_t runq_sort_last;
    struct timer ticker;
    unsigned int tick;
    unsigned int idle_bias;
    /* Store this here to avoid having too many cpumask_var_t-s on stack */
    cpumask_var_t balance_mask;
};

/*
 * Convenience macro for accessing the per-PCPU cpumask we need for
 * implementing the two steps (soft and hard affinity) balancing logic.
 * It is stored in csched_pcpu so that serialization is not an issue,
 * as there is a csched_pcpu for each PCPU, and we always hold the
 * runqueue lock for the proper PCPU when using this.
 */
#define csched_balance_mask(c) (CSCHED_PCPU(c)->balance_mask)

/*
 * Virtual CPU
 */
struct csched_vcpu {
    struct list_head runq_elem;
    struct list_head active_vcpu_elem;
    struct csched_dom *sdom;
    struct vcpu *vcpu;
    atomic_t credit;
    unsigned int residual;
    s_time_t start_time;   /* When we were scheduled (used for credit) */
    unsigned flags;
    int16_t pri;
#ifdef CSCHED_STATS
    struct {
        int credit_last;
        uint32_t credit_incr;
        uint32_t state_active;
        uint32_t state_idle;
        uint32_t migrate_q;
        uint32_t migrate_r;
        uint32_t kicked_away;
    } stats;
#endif
};

/*
 * Domain
 */
struct csched_dom {
    struct list_head active_vcpu;
    struct list_head active_sdom_elem;
    struct domain *dom;
    uint16_t active_vcpu_count;
    uint16_t weight;
    uint16_t cap;
};

/*
 * System-wide private data
 */
struct csched_private {
    /* lock for the whole pluggable scheduler, nests inside cpupool_lock */
    spinlock_t lock;
    struct list_head active_sdom;
    uint32_t ncpus;
    struct timer  master_ticker;
    unsigned int master;
    cpumask_var_t idlers;
    cpumask_var_t cpus;
    uint32_t weight;
    uint32_t credit;
    int credit_balance;
    uint32_t runq_sort;
    unsigned ratelimit_us;
    /* Period of master and tick in milliseconds */
    unsigned tslice_ms, tick_period_us, ticks_per_tslice;
    unsigned credits_per_tslice;
};

static void csched_tick(void *_cpu);
static void csched_acct(void *dummy);

static inline int
__vcpu_on_runq(struct csched_vcpu *svc)
{
    return !list_empty(&svc->runq_elem);
}

static inline struct csched_vcpu *
__runq_elem(struct list_head *elem)
{
    return list_entry(elem, struct csched_vcpu, runq_elem);
}

static inline void
__runq_insert(unsigned int cpu, struct csched_vcpu *svc)
{
    const struct list_head * const runq = RUNQ(cpu);
    struct list_head *iter;

    BUG_ON( __vcpu_on_runq(svc) );
    BUG_ON( cpu != svc->vcpu->processor );

    list_for_each( iter, runq )
    {
        const struct csched_vcpu * const iter_svc = __runq_elem(iter);
        if ( svc->pri > iter_svc->pri )
            break;
    }

    /* If the vcpu yielded, try to put it behind one lower-priority
     * runnable vcpu if we can.  The next runq_sort will bring it forward
     * within 30ms if the queue too long. */
    if ( test_bit(CSCHED_FLAG_VCPU_YIELD, &svc->flags)
         && __runq_elem(iter)->pri > CSCHED_PRI_IDLE )
    {
        iter=iter->next;

        /* Some sanity checks */
        BUG_ON(iter == runq);
    }

    list_add_tail(&svc->runq_elem, iter);
}

static inline void
__runq_remove(struct csched_vcpu *svc)
{
    BUG_ON( !__vcpu_on_runq(svc) );
    list_del_init(&svc->runq_elem);
}


#define for_each_csched_balance_step(step) \
    for ( (step) = 0; (step) <= CSCHED_BALANCE_HARD_AFFINITY; (step)++ )


/*
 * Hard affinity balancing is always necessary and must never be skipped.
 * But soft affinity need only be considered when it has a functionally
 * different effect than other constraints (such as hard affinity, cpus
 * online, or cpupools).
 *
 * Soft affinity only needs to be considered if:
 * * The cpus in the cpupool are not a subset of soft affinity
 * * The hard affinity is not a subset of soft affinity
 * * There is an overlap between the soft affinity and the mask which is
 *   currently being considered.
 */
static inline int __vcpu_has_soft_affinity(const struct vcpu *vc,
                                           const cpumask_t *mask)
{
    return !cpumask_subset(cpupool_online_cpumask(vc->domain->cpupool),
                           vc->cpu_soft_affinity) &&
           !cpumask_subset(vc->cpu_hard_affinity, vc->cpu_soft_affinity) &&
           cpumask_intersects(vc->cpu_soft_affinity, mask);
}

/*
 * Each csched-balance step uses its own cpumask. This function determines
 * which one (given the step) and copies it in mask. For the soft affinity
 * balancing step, the pcpus that are not part of vc's hard affinity are
 * filtered out from the result, to avoid running a vcpu where it would
 * like, but is not allowed to!
 */
static void
csched_balance_cpumask(const struct vcpu *vc, int step, cpumask_t *mask)
{
    if ( step == CSCHED_BALANCE_SOFT_AFFINITY )
    {
        cpumask_and(mask, vc->cpu_soft_affinity, vc->cpu_hard_affinity);

        if ( unlikely(cpumask_empty(mask)) )
            cpumask_copy(mask, vc->cpu_hard_affinity);
    }
    else /* step == CSCHED_BALANCE_HARD_AFFINITY */
        cpumask_copy(mask, vc->cpu_hard_affinity);
}

static void burn_credits(struct csched_vcpu *svc, s_time_t now)
{
    s_time_t delta;
    uint64_t val;
    unsigned int credits;

    /* Assert svc is current */
    ASSERT( svc == CSCHED_VCPU(curr_on_cpu(svc->vcpu->processor)) );

    if ( (delta = now - svc->start_time) <= 0 )
        return;

    val = delta * CSCHED_CREDITS_PER_MSEC + svc->residual;
    svc->residual = do_div(val, MILLISECS(1));
    credits = val;
    ASSERT(credits == val); /* make sure we haven't truncated val */
    atomic_sub(credits, &svc->credit);
    svc->start_time += (credits * MILLISECS(1)) / CSCHED_CREDITS_PER_MSEC;
}

static bool_t __read_mostly opt_tickle_one_idle = 1;
boolean_param("tickle_one_idle_cpu", opt_tickle_one_idle);

DEFINE_PER_CPU(unsigned int, last_tickle_cpu);

static inline void
__runq_tickle(unsigned int cpu, struct csched_vcpu *new)
{
    struct csched_vcpu * const cur = CSCHED_VCPU(curr_on_cpu(cpu));
    struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));
    cpumask_t mask, idle_mask, *online;
    int balance_step, idlers_empty;

    ASSERT(cur);
    cpumask_clear(&mask);

    /* cpu is vc->processor, so it must be in a cpupool. */
    ASSERT(per_cpu(cpupool, cpu) != NULL);
    online = cpupool_online_cpumask(per_cpu(cpupool, cpu));
    cpumask_and(&idle_mask, prv->idlers, online);
    idlers_empty = cpumask_empty(&idle_mask);


    /*
     * If the pcpu is idle, or there are no idlers and the new
     * vcpu is a higher priority than the old vcpu, run it here.
     *
     * If there are idle cpus, first try to find one suitable to run
     * new, so we can avoid preempting cur.  If we cannot find a
     * suitable idler on which to run new, run it here, but try to
     * find a suitable idler on which to run cur instead.
     */
    if ( cur->pri == CSCHED_PRI_IDLE
         || (idlers_empty && new->pri > cur->pri) )
    {
        if ( cur->pri != CSCHED_PRI_IDLE )
            SCHED_STAT_CRANK(tickle_idlers_none);
        __cpumask_set_cpu(cpu, &mask);
    }
    else if ( !idlers_empty )
    {
        /*
         * Soft and hard affinity balancing loop. For vcpus without
         * a useful soft affinity, consider hard affinity only.
         */
        for_each_csched_balance_step( balance_step )
        {
            int new_idlers_empty;

            if ( balance_step == CSCHED_BALANCE_SOFT_AFFINITY
                 && !__vcpu_has_soft_affinity(new->vcpu,
                                              new->vcpu->cpu_hard_affinity) )
                continue;

            /* Are there idlers suitable for new (for this balance step)? */
            csched_balance_cpumask(new->vcpu, balance_step,
                                   csched_balance_mask(cpu));
            cpumask_and(csched_balance_mask(cpu),
                        csched_balance_mask(cpu), &idle_mask);
            new_idlers_empty = cpumask_empty(csched_balance_mask(cpu));

            /*
             * Let's not be too harsh! If there aren't idlers suitable
             * for new in its soft affinity mask, make sure we check its
             * hard affinity as well, before taking final decisions.
             */
            if ( new_idlers_empty
                 && balance_step == CSCHED_BALANCE_SOFT_AFFINITY )
                continue;

            /*
             * If there are no suitable idlers for new, and it's higher
             * priority than cur, ask the scheduler to migrate cur away.
             * We have to act like this (instead of just waking some of
             * the idlers suitable for cur) because cur is running.
             *
             * If there are suitable idlers for new, no matter priorities,
             * leave cur alone (as it is running and is, likely, cache-hot)
             * and wake some of them (which is waking up and so is, likely,
             * cache cold anyway).
             */
            if ( new_idlers_empty && new->pri > cur->pri )
            {
                SCHED_STAT_CRANK(tickle_idlers_none);
                SCHED_VCPU_STAT_CRANK(cur, kicked_away);
                SCHED_VCPU_STAT_CRANK(cur, migrate_r);
                SCHED_STAT_CRANK(migrate_kicked_away);
                set_bit(_VPF_migrating, &cur->vcpu->pause_flags);
                __cpumask_set_cpu(cpu, &mask);
            }
            else if ( !new_idlers_empty )
            {
                /* Which of the idlers suitable for new shall we wake up? */
                SCHED_STAT_CRANK(tickle_idlers_some);
                if ( opt_tickle_one_idle )
                {
                    this_cpu(last_tickle_cpu) =
                        cpumask_cycle(this_cpu(last_tickle_cpu), &idle_mask);
                    __cpumask_set_cpu(this_cpu(last_tickle_cpu), &mask);
                }
                else
                    cpumask_or(&mask, &mask, &idle_mask);
            }

            /* Did we find anyone? */
            if ( !cpumask_empty(&mask) )
                break;
        }
    }

    if ( !cpumask_empty(&mask) )
    {
        if ( unlikely(tb_init_done) )
        {
            /* Avoid TRACE_*: saves checking !tb_init_done each step */
            for_each_cpu(cpu, &mask)
                __trace_var(TRC_CSCHED_TICKLE, 0, sizeof(cpu), &cpu);
        }

        /* Send scheduler interrupts to designated CPUs */
        cpumask_raise_softirq(&mask, SCHEDULE_SOFTIRQ);
    }
}

static void
csched_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_pcpu *spc = pcpu;
    unsigned long flags;

    if ( spc == NULL )
        return;

    spin_lock_irqsave(&prv->lock, flags);

    prv->credit -= prv->credits_per_tslice;
    prv->ncpus--;
    cpumask_clear_cpu(cpu, prv->idlers);
    cpumask_clear_cpu(cpu, prv->cpus);
    if ( (prv->master == cpu) && (prv->ncpus > 0) )
    {
        prv->master = cpumask_first(prv->cpus);
        migrate_timer(&prv->master_ticker, prv->master);
    }
    kill_timer(&spc->ticker);
    if ( prv->ncpus == 0 )
        kill_timer(&prv->master_ticker);

    spin_unlock_irqrestore(&prv->lock, flags);

    free_cpumask_var(spc->balance_mask);
    xfree(spc);
}

static void *
csched_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct csched_pcpu *spc;
    struct csched_private *prv = CSCHED_PRIV(ops);
    unsigned long flags;

    /* Allocate per-PCPU info */
    spc = xzalloc(struct csched_pcpu);
    if ( spc == NULL )
        return NULL;

    if ( !alloc_cpumask_var(&spc->balance_mask) )
    {
        xfree(spc);
        return NULL;
    }

    spin_lock_irqsave(&prv->lock, flags);

    /* Initialize/update system-wide config */
    prv->credit += prv->credits_per_tslice;
    prv->ncpus++;
    cpumask_set_cpu(cpu, prv->cpus);
    if ( prv->ncpus == 1 )
    {
        prv->master = cpu;
        init_timer(&prv->master_ticker, csched_acct, prv, cpu);
        set_timer(&prv->master_ticker,
                  NOW() + MILLISECS(prv->tslice_ms));
    }

    init_timer(&spc->ticker, csched_tick, (void *)(unsigned long)cpu, cpu);
    set_timer(&spc->ticker, NOW() + MICROSECS(prv->tick_period_us) );

    INIT_LIST_HEAD(&spc->runq);
    spc->runq_sort_last = prv->runq_sort;
    spc->idle_bias = nr_cpu_ids - 1;
    if ( per_cpu(schedule_data, cpu).sched_priv == NULL )
        per_cpu(schedule_data, cpu).sched_priv = spc;

    /* Start off idling... */
    BUG_ON(!is_idle_vcpu(curr_on_cpu(cpu)));
    cpumask_set_cpu(cpu, prv->idlers);

    spin_unlock_irqrestore(&prv->lock, flags);

    return spc;
}

#ifndef NDEBUG
static inline void
__csched_vcpu_check(struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    struct csched_dom * const sdom = svc->sdom;

    BUG_ON( svc->vcpu != vc );
    BUG_ON( sdom != CSCHED_DOM(vc->domain) );
    if ( sdom )
    {
        BUG_ON( is_idle_vcpu(vc) );
        BUG_ON( sdom->dom != vc->domain );
    }
    else
    {
        BUG_ON( !is_idle_vcpu(vc) );
    }

    SCHED_STAT_CRANK(vcpu_check);
}
#define CSCHED_VCPU_CHECK(_vc)  (__csched_vcpu_check(_vc))
#else
#define CSCHED_VCPU_CHECK(_vc)
#endif

/*
 * Delay, in microseconds, between migrations of a VCPU between PCPUs.
 * This prevents rapid fluttering of a VCPU between CPUs, and reduces the
 * implicit overheads such as cache-warming. 1ms (1000) has been measured
 * as a good value.
 */
static unsigned int vcpu_migration_delay;
integer_param("vcpu_migration_delay", vcpu_migration_delay);

void set_vcpu_migration_delay(unsigned int delay)
{
    vcpu_migration_delay = delay;
}

unsigned int get_vcpu_migration_delay(void)
{
    return vcpu_migration_delay;
}

static inline int
__csched_vcpu_is_cache_hot(struct vcpu *v)
{
    int hot = ((NOW() - v->last_run_time) <
               ((uint64_t)vcpu_migration_delay * 1000u));

    if ( hot )
        SCHED_STAT_CRANK(vcpu_hot);

    return hot;
}

static inline int
__csched_vcpu_is_migrateable(struct vcpu *vc, int dest_cpu, cpumask_t *mask)
{
    /*
     * Don't pick up work that's in the peer's scheduling tail or hot on
     * peer PCPU. Only pick up work that prefers and/or is allowed to run
     * on our CPU.
     */
    return !vc->is_running &&
           !__csched_vcpu_is_cache_hot(vc) &&
           cpumask_test_cpu(dest_cpu, mask);
}

static int
_csched_cpu_pick(const struct scheduler *ops, struct vcpu *vc, bool_t commit)
{
    cpumask_t cpus;
    cpumask_t idlers;
    cpumask_t *online;
    struct csched_pcpu *spc = NULL;
    int cpu = vc->processor;
    int balance_step;

    /* Store in cpus the mask of online cpus on which the domain can run */
    online = cpupool_scheduler_cpumask(vc->domain->cpupool);
    cpumask_and(&cpus, vc->cpu_hard_affinity, online);

    for_each_csched_balance_step( balance_step )
    {
        /*
         * We want to pick up a pcpu among the ones that are online and
         * can accommodate vc, which is basically what we computed above
         * and stored in cpus. As far as hard affinity is concerned,
         * there always will be at least one of these pcpus, hence cpus
         * is never empty and the calls to cpumask_cycle() and
         * cpumask_test_cpu() below are ok.
         *
         * On the other hand, when considering soft affinity too, it
         * is possible for the mask to become empty (for instance, if the
         * domain has been put in a cpupool that does not contain any of the
         * pcpus in its soft affinity), which would result in the ASSERT()-s
         * inside cpumask_*() operations triggering (in debug builds).
         *
         * Therefore, in this case, we filter the soft affinity mask against
         * cpus and, if the result is empty, we just skip the soft affinity
         * balancing step all together.
         */
        if ( balance_step == CSCHED_BALANCE_SOFT_AFFINITY
             && !__vcpu_has_soft_affinity(vc, &cpus) )
            continue;

        /* Pick an online CPU from the proper affinity mask */
        csched_balance_cpumask(vc, balance_step, &cpus);
        cpumask_and(&cpus, &cpus, online);

        /* If present, prefer vc's current processor */
        cpu = cpumask_test_cpu(vc->processor, &cpus)
                ? vc->processor
                : cpumask_cycle(vc->processor, &cpus);
        ASSERT(cpumask_test_cpu(cpu, &cpus));

        /*
         * Try to find an idle processor within the above constraints.
         *
         * In multi-core and multi-threaded CPUs, not all idle execution
         * vehicles are equal!
         *
         * We give preference to the idle execution vehicle with the most
         * idling neighbours in its grouping. This distributes work across
         * distinct cores first and guarantees we don't do something stupid
         * like run two VCPUs on co-hyperthreads while there are idle cores
         * or sockets.
         *
         * Notice that, when computing the "idleness" of cpu, we may want to
         * discount vc. That is, iff vc is the currently running and the only
         * runnable vcpu on cpu, we add cpu to the idlers.
         */
        cpumask_and(&idlers, &cpu_online_map, CSCHED_PRIV(ops)->idlers);
        if ( vc->processor == cpu && IS_RUNQ_IDLE(cpu) )
            __cpumask_set_cpu(cpu, &idlers);
        cpumask_and(&cpus, &cpus, &idlers);

        /*
         * It is important that cpu points to an idle processor, if a suitable
         * one exists (and we can use cpus to check and, possibly, choose a new
         * CPU, as we just &&-ed it with idlers). In fact, if we are on SMT, and
         * cpu points to a busy thread with an idle sibling, both the threads
         * will be considered the same, from the "idleness" calculation point
         * of view", preventing vcpu from being moved to the thread that is
         * actually idle.
         *
         * Notice that cpumask_test_cpu() is quicker than cpumask_empty(), so
         * we check for it first.
         */
        if ( !cpumask_test_cpu(cpu, &cpus) && !cpumask_empty(&cpus) )
            cpu = cpumask_cycle(cpu, &cpus);
        __cpumask_clear_cpu(cpu, &cpus);

        while ( !cpumask_empty(&cpus) )
        {
            cpumask_t cpu_idlers;
            cpumask_t nxt_idlers;
            int nxt, weight_cpu, weight_nxt;
            int migrate_factor;

            nxt = cpumask_cycle(cpu, &cpus);

            if ( cpumask_test_cpu(cpu, per_cpu(cpu_core_mask, nxt)) )
            {
                /* We're on the same socket, so check the busy-ness of threads.
                 * Migrate if # of idlers is less at all */
                ASSERT( cpumask_test_cpu(nxt, per_cpu(cpu_core_mask, cpu)) );
                migrate_factor = 1;
                cpumask_and(&cpu_idlers, &idlers, per_cpu(cpu_sibling_mask,
                            cpu));
                cpumask_and(&nxt_idlers, &idlers, per_cpu(cpu_sibling_mask,
                            nxt));
            }
            else
            {
                /* We're on different sockets, so check the busy-ness of cores.
                 * Migrate only if the other core is twice as idle */
                ASSERT( !cpumask_test_cpu(nxt, per_cpu(cpu_core_mask, cpu)) );
                migrate_factor = 2;
                cpumask_and(&cpu_idlers, &idlers, per_cpu(cpu_core_mask, cpu));
                cpumask_and(&nxt_idlers, &idlers, per_cpu(cpu_core_mask, nxt));
            }

            weight_cpu = cpumask_weight(&cpu_idlers);
            weight_nxt = cpumask_weight(&nxt_idlers);
            /* smt_power_savings: consolidate work rather than spreading it */
            if ( sched_smt_power_savings ?
                 weight_cpu > weight_nxt :
                 weight_cpu * migrate_factor < weight_nxt )
            {
                cpumask_and(&nxt_idlers, &cpus, &nxt_idlers);
                spc = CSCHED_PCPU(nxt);
                cpu = cpumask_cycle(spc->idle_bias, &nxt_idlers);
                cpumask_andnot(&cpus, &cpus, per_cpu(cpu_sibling_mask, cpu));
            }
            else
            {
                cpumask_andnot(&cpus, &cpus, &nxt_idlers);
            }
        }

        /* Stop if cpu is idle */
        if ( cpumask_test_cpu(cpu, &idlers) )
            break;
    }

    if ( commit && spc )
       spc->idle_bias = cpu;

    TRACE_3D(TRC_CSCHED_PICKED_CPU, vc->domain->domain_id, vc->vcpu_id, cpu);

    return cpu;
}

static int
csched_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    return _csched_cpu_pick(ops, vc, 1);
}

static inline void
__csched_vcpu_acct_start(struct csched_private *prv, struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);

    if ( list_empty(&svc->active_vcpu_elem) )
    {
        SCHED_VCPU_STAT_CRANK(svc, state_active);
        SCHED_STAT_CRANK(acct_vcpu_active);

        sdom->active_vcpu_count++;
        list_add(&svc->active_vcpu_elem, &sdom->active_vcpu);
        /* Make weight per-vcpu */
        prv->weight += sdom->weight;
        if ( list_empty(&sdom->active_sdom_elem) )
        {
            list_add(&sdom->active_sdom_elem, &prv->active_sdom);
        }
    }

    TRACE_3D(TRC_CSCHED_ACCOUNT_START, sdom->dom->domain_id,
             svc->vcpu->vcpu_id, sdom->active_vcpu_count);

    spin_unlock_irqrestore(&prv->lock, flags);
}

static inline void
__csched_vcpu_acct_stop_locked(struct csched_private *prv,
    struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;

    BUG_ON( list_empty(&svc->active_vcpu_elem) );

    SCHED_VCPU_STAT_CRANK(svc, state_idle);
    SCHED_STAT_CRANK(acct_vcpu_idle);

    BUG_ON( prv->weight < sdom->weight );
    sdom->active_vcpu_count--;
    list_del_init(&svc->active_vcpu_elem);
    prv->weight -= sdom->weight;
    if ( list_empty(&sdom->active_vcpu) )
    {
        list_del_init(&sdom->active_sdom_elem);
    }

    TRACE_3D(TRC_CSCHED_ACCOUNT_STOP, sdom->dom->domain_id,
             svc->vcpu->vcpu_id, sdom->active_vcpu_count);
}

static void
csched_vcpu_acct(struct csched_private *prv, unsigned int cpu)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(current);
    const struct scheduler *ops = per_cpu(scheduler, cpu);

    ASSERT( current->processor == cpu );
    ASSERT( svc->sdom != NULL );

    /*
     * If this VCPU's priority was boosted when it last awoke, reset it.
     * If the VCPU is found here, then it's consuming a non-negligeable
     * amount of CPU resources and should no longer be boosted.
     */
    if ( svc->pri == CSCHED_PRI_TS_BOOST )
        svc->pri = CSCHED_PRI_TS_UNDER;

    /*
     * Update credits
     */
    if ( !is_idle_vcpu(svc->vcpu) )
        burn_credits(svc, NOW());

    /*
     * Put this VCPU and domain back on the active list if it was
     * idling.
     *
     * If it's been active a while, check if we'd be better off
     * migrating it to run elsewhere (see multi-core and multi-thread
     * support in csched_cpu_pick()).
     */
    if ( list_empty(&svc->active_vcpu_elem) )
    {
        __csched_vcpu_acct_start(prv, svc);
    }
    else if ( _csched_cpu_pick(ops, current, 0) != cpu )
    {
        SCHED_VCPU_STAT_CRANK(svc, migrate_r);
        SCHED_STAT_CRANK(migrate_running);
        set_bit(_VPF_migrating, &current->pause_flags);
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    }
}

static void *
csched_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct csched_vcpu *svc;

    /* Allocate per-VCPU info */
    svc = xzalloc(struct csched_vcpu);
    if ( svc == NULL )
        return NULL;

    INIT_LIST_HEAD(&svc->runq_elem);
    INIT_LIST_HEAD(&svc->active_vcpu_elem);
    svc->sdom = dd;
    svc->vcpu = vc;
    svc->pri = is_idle_domain(vc->domain) ?
        CSCHED_PRI_IDLE : CSCHED_PRI_TS_UNDER;
    SCHED_VCPU_STATS_RESET(svc);
    SCHED_STAT_CRANK(vcpu_init);
    return svc;
}

static void
csched_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu *svc = vc->sched_priv;

    if ( !__vcpu_on_runq(svc) && vcpu_runnable(vc) && !vc->is_running )
        __runq_insert(vc->processor, svc);
}

static void
csched_free_vdata(const struct scheduler *ops, void *priv)
{
    struct csched_vcpu *svc = priv;

    BUG_ON( !list_empty(&svc->runq_elem) );

    xfree(svc);
}

static void
csched_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    struct csched_dom * const sdom = svc->sdom;
    unsigned long flags;

    SCHED_STAT_CRANK(vcpu_destroy);

    if ( test_and_clear_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
    {
        SCHED_STAT_CRANK(vcpu_unpark);
        vcpu_unpause(svc->vcpu);
    }

    if ( __vcpu_on_runq(svc) )
        __runq_remove(svc);

    spin_lock_irqsave(&(prv->lock), flags);

    if ( !list_empty(&svc->active_vcpu_elem) )
        __csched_vcpu_acct_stop_locked(prv, svc);

    spin_unlock_irqrestore(&(prv->lock), flags);

    BUG_ON( sdom == NULL );
    BUG_ON( !list_empty(&svc->runq_elem) );
}

static void
csched_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);

    SCHED_STAT_CRANK(vcpu_sleep);

    BUG_ON( is_idle_vcpu(vc) );

    if ( curr_on_cpu(vc->processor) == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
    else if ( __vcpu_on_runq(svc) )
        __runq_remove(svc);
}

static void
csched_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    const unsigned int cpu = vc->processor;

    BUG_ON( is_idle_vcpu(vc) );

    if ( unlikely(curr_on_cpu(cpu) == vc) )
    {
        SCHED_STAT_CRANK(vcpu_wake_running);
        return;
    }
    if ( unlikely(__vcpu_on_runq(svc)) )
    {
        SCHED_STAT_CRANK(vcpu_wake_onrunq);
        return;
    }

    if ( likely(vcpu_runnable(vc)) )
        SCHED_STAT_CRANK(vcpu_wake_runnable);
    else
        SCHED_STAT_CRANK(vcpu_wake_not_runnable);

    /*
     * We temporarly boost the priority of awaking VCPUs!
     *
     * If this VCPU consumes a non negligeable amount of CPU, it
     * will eventually find itself in the credit accounting code
     * path where its priority will be reset to normal.
     *
     * If on the other hand the VCPU consumes little CPU and is
     * blocking and awoken a lot (doing I/O for example), its
     * priority will remain boosted, optimizing it's wake-to-run
     * latencies.
     *
     * This allows wake-to-run latency sensitive VCPUs to preempt
     * more CPU resource intensive VCPUs without impacting overall 
     * system fairness.
     *
     * The one exception is for VCPUs of capped domains unpausing
     * after earning credits they had overspent. We don't boost
     * those.
     */
    if ( svc->pri == CSCHED_PRI_TS_UNDER &&
         !test_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
    {
        svc->pri = CSCHED_PRI_TS_BOOST;
    }

    /* Put the VCPU on the runq and tickle CPUs */
    __runq_insert(cpu, svc);
    __runq_tickle(cpu, svc);
}

static void
csched_vcpu_yield(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);

    /* Let the scheduler know that this vcpu is trying to yield */
    set_bit(CSCHED_FLAG_VCPU_YIELD, &svc->flags);
}

static int
csched_dom_cntl(
    const struct scheduler *ops,
    struct domain *d,
    struct xen_domctl_scheduler_op *op)
{
    struct csched_dom * const sdom = CSCHED_DOM(d);
    struct csched_private *prv = CSCHED_PRIV(ops);
    unsigned long flags;

    /* Protect both get and put branches with the pluggable scheduler
     * lock. Runq lock not needed anywhere in here. */
    spin_lock_irqsave(&prv->lock, flags);

    if ( op->cmd == XEN_DOMCTL_SCHEDOP_getinfo )
    {
        op->u.credit.weight = sdom->weight;
        op->u.credit.cap = sdom->cap;
    }
    else
    {
        ASSERT(op->cmd == XEN_DOMCTL_SCHEDOP_putinfo);

        if ( op->u.credit.weight != 0 )
        {
            if ( !list_empty(&sdom->active_sdom_elem) )
            {
                prv->weight -= sdom->weight * sdom->active_vcpu_count;
                prv->weight += op->u.credit.weight * sdom->active_vcpu_count;
            }
            sdom->weight = op->u.credit.weight;
        }

        if ( op->u.credit.cap != (uint16_t)~0U )
            sdom->cap = op->u.credit.cap;

    }

    spin_unlock_irqrestore(&prv->lock, flags);

    return 0;
}

static inline void
__csched_set_tslice(struct csched_private *prv, unsigned timeslice)
{
    prv->tslice_ms = timeslice;
    prv->ticks_per_tslice = CSCHED_TICKS_PER_TSLICE;
    if ( prv->tslice_ms < prv->ticks_per_tslice )
        prv->ticks_per_tslice = 1;
    prv->tick_period_us = prv->tslice_ms * 1000 / prv->ticks_per_tslice;
    prv->credits_per_tslice = CSCHED_CREDITS_PER_MSEC * prv->tslice_ms;
}

static int
csched_sys_cntl(const struct scheduler *ops,
                        struct xen_sysctl_scheduler_op *sc)
{
    int rc = -EINVAL;
    xen_sysctl_credit_schedule_t *params = &sc->u.sched_credit;
    struct csched_private *prv = CSCHED_PRIV(ops);

    switch ( sc->cmd )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
        if (params->tslice_ms > XEN_SYSCTL_CSCHED_TSLICE_MAX
            || params->tslice_ms < XEN_SYSCTL_CSCHED_TSLICE_MIN 
            || (params->ratelimit_us
                && (params->ratelimit_us > XEN_SYSCTL_SCHED_RATELIMIT_MAX
                    || params->ratelimit_us < XEN_SYSCTL_SCHED_RATELIMIT_MIN))
            || MICROSECS(params->ratelimit_us) > MILLISECS(params->tslice_ms) )
                goto out;
        __csched_set_tslice(prv, params->tslice_ms);
        prv->ratelimit_us = params->ratelimit_us;
        /* FALLTHRU */
    case XEN_SYSCTL_SCHEDOP_getinfo:
        params->tslice_ms = prv->tslice_ms;
        params->ratelimit_us = prv->ratelimit_us;
        rc = 0;
        break;
    }
    out:
    return rc;
}

static void *
csched_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom;

    sdom = xzalloc(struct csched_dom);
    if ( sdom == NULL )
        return NULL;

    /* Initialize credit and weight */
    INIT_LIST_HEAD(&sdom->active_vcpu);
    INIT_LIST_HEAD(&sdom->active_sdom_elem);
    sdom->dom = dom;
    sdom->weight = CSCHED_DEFAULT_WEIGHT;

    return (void *)sdom;
}

static int
csched_dom_init(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom;

    if ( is_idle_domain(dom) )
        return 0;

    sdom = csched_alloc_domdata(ops, dom);
    if ( sdom == NULL )
        return -ENOMEM;

    dom->sched_priv = sdom;

    return 0;
}

static void
csched_free_domdata(const struct scheduler *ops, void *data)
{
    xfree(data);
}

static void
csched_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    csched_free_domdata(ops, CSCHED_DOM(dom));
}

/*
 * This is a O(n) optimized sort of the runq.
 *
 * Time-share VCPUs can only be one of two priorities, UNDER or OVER. We walk
 * through the runq and move up any UNDERs that are preceded by OVERS. We
 * remember the last UNDER to make the move up operation O(1).
 */
static void
csched_runq_sort(struct csched_private *prv, unsigned int cpu)
{
    struct csched_pcpu * const spc = CSCHED_PCPU(cpu);
    struct list_head *runq, *elem, *next, *last_under;
    struct csched_vcpu *svc_elem;
    spinlock_t *lock;
    unsigned long flags;
    int sort_epoch;

    sort_epoch = prv->runq_sort;
    if ( sort_epoch == spc->runq_sort_last )
        return;

    spc->runq_sort_last = sort_epoch;

    lock = pcpu_schedule_lock_irqsave(cpu, &flags);

    runq = &spc->runq;
    elem = runq->next;
    last_under = runq;

    while ( elem != runq )
    {
        next = elem->next;
        svc_elem = __runq_elem(elem);

        if ( svc_elem->pri >= CSCHED_PRI_TS_UNDER )
        {
            /* does elem need to move up the runq? */
            if ( elem->prev != last_under )
            {
                list_del(elem);
                list_add(elem, last_under);
            }
            last_under = elem;
        }

        elem = next;
    }

    pcpu_schedule_unlock_irqrestore(lock, flags, cpu);
}

static void
csched_acct(void* dummy)
{
    struct csched_private *prv = dummy;
    unsigned long flags;
    struct list_head *iter_vcpu, *next_vcpu;
    struct list_head *iter_sdom, *next_sdom;
    struct csched_vcpu *svc;
    struct csched_dom *sdom;
    uint32_t credit_total;
    uint32_t weight_total;
    uint32_t weight_left;
    uint32_t credit_fair;
    uint32_t credit_peak;
    uint32_t credit_cap;
    int credit_balance;
    int credit_xtra;
    int credit;


    spin_lock_irqsave(&prv->lock, flags);

    weight_total = prv->weight;
    credit_total = prv->credit;

    /* Converge balance towards 0 when it drops negative */
    if ( prv->credit_balance < 0 )
    {
        credit_total -= prv->credit_balance;
        SCHED_STAT_CRANK(acct_balance);
    }

    if ( unlikely(weight_total == 0) )
    {
        prv->credit_balance = 0;
        spin_unlock_irqrestore(&prv->lock, flags);
        SCHED_STAT_CRANK(acct_no_work);
        goto out;
    }

    SCHED_STAT_CRANK(acct_run);

    weight_left = weight_total;
    credit_balance = 0;
    credit_xtra = 0;
    credit_cap = 0U;

    list_for_each_safe( iter_sdom, next_sdom, &prv->active_sdom )
    {
        sdom = list_entry(iter_sdom, struct csched_dom, active_sdom_elem);

        BUG_ON( is_idle_domain(sdom->dom) );
        BUG_ON( sdom->active_vcpu_count == 0 );
        BUG_ON( sdom->weight == 0 );
        BUG_ON( (sdom->weight * sdom->active_vcpu_count) > weight_left );

        weight_left -= ( sdom->weight * sdom->active_vcpu_count );

        /*
         * A domain's fair share is computed using its weight in competition
         * with that of all other active domains.
         *
         * At most, a domain can use credits to run all its active VCPUs
         * for one full accounting period. We allow a domain to earn more
         * only when the system-wide credit balance is negative.
         */
        credit_peak = sdom->active_vcpu_count * prv->credits_per_tslice;
        if ( prv->credit_balance < 0 )
        {
            credit_peak += ( ( -prv->credit_balance
                               * sdom->weight
                               * sdom->active_vcpu_count) +
                             (weight_total - 1)
                           ) / weight_total;
        }

        if ( sdom->cap != 0U )
        {
            credit_cap = ((sdom->cap * prv->credits_per_tslice) + 99) / 100;
            if ( credit_cap < credit_peak )
                credit_peak = credit_cap;

            /* FIXME -- set cap per-vcpu as well...? */
            credit_cap = ( credit_cap + ( sdom->active_vcpu_count - 1 )
                         ) / sdom->active_vcpu_count;
        }

        credit_fair = ( ( credit_total
                          * sdom->weight
                          * sdom->active_vcpu_count )
                        + (weight_total - 1)
                      ) / weight_total;

        if ( credit_fair < credit_peak )
        {
            credit_xtra = 1;
        }
        else
        {
            if ( weight_left != 0U )
            {
                /* Give other domains a chance at unused credits */
                credit_total += ( ( ( credit_fair - credit_peak
                                    ) * weight_total
                                  ) + ( weight_left - 1 )
                                ) / weight_left;
            }

            if ( credit_xtra )
            {
                /*
                 * Lazily keep domains with extra credits at the head of
                 * the queue to give others a chance at them in future
                 * accounting periods.
                 */
                SCHED_STAT_CRANK(acct_reorder);
                list_del(&sdom->active_sdom_elem);
                list_add(&sdom->active_sdom_elem, &prv->active_sdom);
            }

            credit_fair = credit_peak;
        }

        /* Compute fair share per VCPU */
        credit_fair = ( credit_fair + ( sdom->active_vcpu_count - 1 )
                      ) / sdom->active_vcpu_count;


        list_for_each_safe( iter_vcpu, next_vcpu, &sdom->active_vcpu )
        {
            svc = list_entry(iter_vcpu, struct csched_vcpu, active_vcpu_elem);
            BUG_ON( sdom != svc->sdom );

            /* Increment credit */
            atomic_add(credit_fair, &svc->credit);
            credit = atomic_read(&svc->credit);

            /*
             * Recompute priority or, if VCPU is idling, remove it from
             * the active list.
             */
            if ( credit < 0 )
            {
                svc->pri = CSCHED_PRI_TS_OVER;

                /* Park running VCPUs of capped-out domains */
                if ( sdom->cap != 0U &&
                     credit < -credit_cap &&
                     !test_and_set_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
                {
                    SCHED_STAT_CRANK(vcpu_park);
                    vcpu_pause_nosync(svc->vcpu);
                }

                /* Lower bound on credits */
                if ( credit < -prv->credits_per_tslice )
                {
                    SCHED_STAT_CRANK(acct_min_credit);
                    credit = -prv->credits_per_tslice;
                    atomic_set(&svc->credit, credit);
                }
            }
            else
            {
                svc->pri = CSCHED_PRI_TS_UNDER;

                /* Unpark any capped domains whose credits go positive */
                if ( test_and_clear_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
                {
                    /*
                     * It's important to unset the flag AFTER the unpause()
                     * call to make sure the VCPU's priority is not boosted
                     * if it is woken up here.
                     */
                    SCHED_STAT_CRANK(vcpu_unpark);
                    vcpu_unpause(svc->vcpu);
                }

                /* Upper bound on credits means VCPU stops earning */
                if ( credit > prv->credits_per_tslice )
                {
                    __csched_vcpu_acct_stop_locked(prv, svc);
                    /* Divide credits in half, so that when it starts
                     * accounting again, it starts a little bit "ahead" */
                    credit /= 2;
                    atomic_set(&svc->credit, credit);
                }
            }

            SCHED_VCPU_STAT_SET(svc, credit_last, credit);
            SCHED_VCPU_STAT_SET(svc, credit_incr, credit_fair);
            credit_balance += credit;
        }
    }

    prv->credit_balance = credit_balance;

    spin_unlock_irqrestore(&prv->lock, flags);

    /* Inform each CPU that its runq needs to be sorted */
    prv->runq_sort++;

out:
    set_timer( &prv->master_ticker,
               NOW() + MILLISECS(prv->tslice_ms));
}

static void
csched_tick(void *_cpu)
{
    unsigned int cpu = (unsigned long)_cpu;
    struct csched_pcpu *spc = CSCHED_PCPU(cpu);
    struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));

    spc->tick++;

    /*
     * Accounting for running VCPU
     */
    if ( !is_idle_vcpu(current) )
        csched_vcpu_acct(prv, cpu);

    /*
     * Check if runq needs to be sorted
     *
     * Every physical CPU resorts the runq after the accounting master has
     * modified priorities. This is a special O(n) sort and runs at most
     * once per accounting period (currently 30 milliseconds).
     */
    csched_runq_sort(prv, cpu);

    set_timer(&spc->ticker, NOW() + MICROSECS(prv->tick_period_us) );
}

static struct csched_vcpu *
csched_runq_steal(int peer_cpu, int cpu, int pri, int balance_step)
{
    const struct csched_pcpu * const peer_pcpu = CSCHED_PCPU(peer_cpu);
    const struct vcpu * const peer_vcpu = curr_on_cpu(peer_cpu);
    struct csched_vcpu *speer;
    struct list_head *iter;
    struct vcpu *vc;

    /*
     * Don't steal from an idle CPU's runq because it's about to
     * pick up work from it itself.
     */
    if ( peer_pcpu != NULL && !is_idle_vcpu(peer_vcpu) )
    {
        list_for_each( iter, &peer_pcpu->runq )
        {
            speer = __runq_elem(iter);

            /*
             * If next available VCPU here is not of strictly higher
             * priority than ours, this PCPU is useless to us.
             */
            if ( speer->pri <= pri )
                break;

            /* Is this VCPU runnable on our PCPU? */
            vc = speer->vcpu;
            BUG_ON( is_idle_vcpu(vc) );

            /*
             * If the vcpu has no useful soft affinity, skip this vcpu.
             * In fact, what we want is to check if we have any "soft-affine
             * work" to steal, before starting to look at "hard-affine work".
             *
             * Notice that, if not even one vCPU on this runq has a useful
             * soft affinity, we could have avoid considering this runq for
             * a soft balancing step in the first place. This, for instance,
             * can be implemented by taking note of on what runq there are
             * vCPUs with useful soft affinities in some sort of bitmap
             * or counter.
             */
            if ( balance_step == CSCHED_BALANCE_SOFT_AFFINITY
                 && !__vcpu_has_soft_affinity(vc, vc->cpu_hard_affinity) )
                continue;

            csched_balance_cpumask(vc, balance_step, csched_balance_mask(cpu));
            if ( __csched_vcpu_is_migrateable(vc, cpu,
                                              csched_balance_mask(cpu)) )
            {
                /* We got a candidate. Grab it! */
                TRACE_3D(TRC_CSCHED_STOLEN_VCPU, peer_cpu,
                         vc->domain->domain_id, vc->vcpu_id);
                SCHED_VCPU_STAT_CRANK(speer, migrate_q);
                SCHED_STAT_CRANK(migrate_queued);
                WARN_ON(vc->is_urgent);
                __runq_remove(speer);
                vc->processor = cpu;
                return speer;
            }
        }
    }

    SCHED_STAT_CRANK(steal_peer_idle);
    return NULL;
}

static struct csched_vcpu *
csched_load_balance(struct csched_private *prv, int cpu,
    struct csched_vcpu *snext, bool_t *stolen)
{
    struct cpupool *c = per_cpu(cpupool, cpu);
    struct csched_vcpu *speer;
    cpumask_t workers;
    cpumask_t *online;
    int peer_cpu, peer_node, bstep;
    int node = cpu_to_node(cpu);

    BUG_ON( cpu != snext->vcpu->processor );
    online = cpupool_online_cpumask(c);

    /*
     * If this CPU is going offline, or is not (yet) part of any cpupool
     * (as it happens, e.g., during cpu bringup), we shouldn't steal work.
     */
    if ( unlikely(!cpumask_test_cpu(cpu, online) || c == NULL) )
        goto out;

    if ( snext->pri == CSCHED_PRI_IDLE )
        SCHED_STAT_CRANK(load_balance_idle);
    else if ( snext->pri == CSCHED_PRI_TS_OVER )
        SCHED_STAT_CRANK(load_balance_over);
    else
        SCHED_STAT_CRANK(load_balance_other);

    /*
     * Let's look around for work to steal, taking both hard affinity
     * and soft affinity into account. More specifically, we check all
     * the non-idle CPUs' runq, looking for:
     *  1. any "soft-affine work" to steal first,
     *  2. if not finding anything, any "hard-affine work" to steal.
     */
    for_each_csched_balance_step( bstep )
    {
        /*
         * We peek at the non-idling CPUs in a node-wise fashion. In fact,
         * it is more likely that we find some affine work on our same
         * node, not to mention that migrating vcpus within the same node
         * could well expected to be cheaper than across-nodes (memory
         * stays local, there might be some node-wide cache[s], etc.).
         */
        peer_node = node;
        do
        {
            /* Find out what the !idle are in this node */
            cpumask_andnot(&workers, online, prv->idlers);
            cpumask_and(&workers, &workers, &node_to_cpumask(peer_node));
            __cpumask_clear_cpu(cpu, &workers);

            peer_cpu = cpumask_first(&workers);
            if ( peer_cpu >= nr_cpu_ids )
                goto next_node;
            do
            {
                /*
                 * Get ahold of the scheduler lock for this peer CPU.
                 *
                 * Note: We don't spin on this lock but simply try it. Spinning
                 * could cause a deadlock if the peer CPU is also load
                 * balancing and trying to lock this CPU.
                 */
                spinlock_t *lock = pcpu_schedule_trylock(peer_cpu);

                if ( !lock )
                {
                    SCHED_STAT_CRANK(steal_trylock_failed);
                    peer_cpu = cpumask_cycle(peer_cpu, &workers);
                    continue;
                }

                /* Any work over there to steal? */
                speer = cpumask_test_cpu(peer_cpu, online) ?
                    csched_runq_steal(peer_cpu, cpu, snext->pri, bstep) : NULL;
                pcpu_schedule_unlock(lock, peer_cpu);

                /* As soon as one vcpu is found, balancing ends */
                if ( speer != NULL )
                {
                    *stolen = 1;
                    return speer;
                }

                peer_cpu = cpumask_cycle(peer_cpu, &workers);

            } while( peer_cpu != cpumask_first(&workers) );

 next_node:
            peer_node = cycle_node(peer_node, node_online_map);
        } while( peer_node != node );
    }

 out:
    /* Failed to find more important work elsewhere... */
    __runq_remove(snext);
    return snext;
}

/*
 * This function is in the critical path. It is designed to be simple and
 * fast for the common case.
 */
static struct task_slice
csched_schedule(
    const struct scheduler *ops, s_time_t now, bool_t tasklet_work_scheduled)
{
    const int cpu = smp_processor_id();
    struct list_head * const runq = RUNQ(cpu);
    struct csched_vcpu * const scurr = CSCHED_VCPU(current);
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_vcpu *snext;
    struct task_slice ret;
    s_time_t runtime, tslice;

    SCHED_STAT_CRANK(schedule);
    CSCHED_VCPU_CHECK(current);

    runtime = now - current->runstate.state_entry_time;
    if ( runtime < 0 ) /* Does this ever happen? */
        runtime = 0;

    if ( !is_idle_vcpu(scurr->vcpu) )
    {
        /* Update credits of a non-idle VCPU. */
        burn_credits(scurr, now);
        scurr->start_time -= now;
    }
    else
    {
        /* Re-instate a boosted idle VCPU as normal-idle. */
        scurr->pri = CSCHED_PRI_IDLE;
    }

    /* Choices, choices:
     * - If we have a tasklet, we need to run the idle vcpu no matter what.
     * - If sched rate limiting is in effect, and the current vcpu has
     *   run for less than that amount of time, continue the current one,
     *   but with a shorter timeslice and return it immediately
     * - Otherwise, chose the one with the highest priority (which may
     *   be the one currently running)
     * - If the currently running one is TS_OVER, see if there
     *   is a higher priority one waiting on the runqueue of another
     *   cpu and steal it.
     */

    /* If we have schedule rate limiting enabled, check to see
     * how long we've run for. */
    if ( !tasklet_work_scheduled
         && prv->ratelimit_us
         && vcpu_runnable(current)
         && !is_idle_vcpu(current)
         && runtime < MICROSECS(prv->ratelimit_us) )
    {
        snext = scurr;
        snext->start_time += now;
        perfc_incr(delay_ms);
        tslice = MICROSECS(prv->ratelimit_us);
        ret.migrated = 0;
        goto out;
    }
    tslice = MILLISECS(prv->tslice_ms);

    /*
     * Select next runnable local VCPU (ie top of local runq)
     */
    if ( vcpu_runnable(current) )
        __runq_insert(cpu, scurr);
    else
        BUG_ON( is_idle_vcpu(current) || list_empty(runq) );

    snext = __runq_elem(runq->next);
    ret.migrated = 0;

    /* Tasklet work (which runs in idle VCPU context) overrides all else. */
    if ( tasklet_work_scheduled )
    {
        TRACE_0D(TRC_CSCHED_SCHED_TASKLET);
        snext = CSCHED_VCPU(idle_vcpu[cpu]);
        snext->pri = CSCHED_PRI_TS_BOOST;
    }

    /*
     * Clear YIELD flag before scheduling out
     */
    clear_bit(CSCHED_FLAG_VCPU_YIELD, &scurr->flags);

    /*
     * SMP Load balance:
     *
     * If the next highest priority local runnable VCPU has already eaten
     * through its credits, look on other PCPUs to see if we have more
     * urgent work... If not, csched_load_balance() will return snext, but
     * already removed from the runq.
     */
    if ( snext->pri > CSCHED_PRI_TS_OVER )
        __runq_remove(snext);
    else
        snext = csched_load_balance(prv, cpu, snext, &ret.migrated);

    /*
     * Update idlers mask if necessary. When we're idling, other CPUs
     * will tickle us when they get extra work.
     */
    if ( snext->pri == CSCHED_PRI_IDLE )
    {
        if ( !cpumask_test_cpu(cpu, prv->idlers) )
            cpumask_set_cpu(cpu, prv->idlers);
    }
    else if ( cpumask_test_cpu(cpu, prv->idlers) )
    {
        cpumask_clear_cpu(cpu, prv->idlers);
    }

    if ( !is_idle_vcpu(snext->vcpu) )
        snext->start_time += now;

out:
    /*
     * Return task to run next...
     */
    ret.time = (is_idle_vcpu(snext->vcpu) ?
                -1 : tslice);
    ret.task = snext->vcpu;

    CSCHED_VCPU_CHECK(ret.task);
    return ret;
}

static void
csched_dump_vcpu(struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;

    printk("[%i.%i] pri=%i flags=%x cpu=%i",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id,
            svc->pri,
            svc->flags,
            svc->vcpu->processor);

    if ( sdom )
    {
        printk(" credit=%i [w=%u,cap=%u]", atomic_read(&svc->credit),
                sdom->weight, sdom->cap);
#ifdef CSCHED_STATS
        printk(" (%d+%u) {a/i=%u/%u m=%u+%u (k=%u)}",
                svc->stats.credit_last,
                svc->stats.credit_incr,
                svc->stats.state_active,
                svc->stats.state_idle,
                svc->stats.migrate_q,
                svc->stats.migrate_r,
                svc->stats.kicked_away);
#endif
    }

    printk("\n");
}

static void
csched_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct list_head *runq, *iter;
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_pcpu *spc;
    struct csched_vcpu *svc;
    spinlock_t *lock = lock;
    unsigned long flags;
    int loop;
#define cpustr keyhandler_scratch

    /*
     * We need both locks:
     * - csched_dump_vcpu() wants to access domains' scheduling
     *   parameters, which are protected by the private scheduler lock;
     * - we scan through the runqueue, so we need the proper runqueue
     *   lock (the one of the runqueue of this cpu).
     */
    spin_lock_irqsave(&prv->lock, flags);
    lock = pcpu_schedule_lock(cpu);

    spc = CSCHED_PCPU(cpu);
    runq = &spc->runq;

    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_sibling_mask, cpu));
    printk(" sort=%d, sibling=%s, ", spc->runq_sort_last, cpustr);
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_core_mask, cpu));
    printk("core=%s\n", cpustr);

    /* current VCPU */
    svc = CSCHED_VCPU(curr_on_cpu(cpu));
    if ( svc )
    {
        printk("\trun: ");
        csched_dump_vcpu(svc);
    }

    loop = 0;
    list_for_each( iter, runq )
    {
        svc = __runq_elem(iter);
        if ( svc )
        {
            printk("\t%3d: ", ++loop);
            csched_dump_vcpu(svc);
        }
    }

    pcpu_schedule_unlock(lock, cpu);
    spin_unlock_irqrestore(&prv->lock, flags);
#undef cpustr
}

static void
csched_dump(const struct scheduler *ops)
{
    struct list_head *iter_sdom, *iter_svc;
    struct csched_private *prv = CSCHED_PRIV(ops);
    int loop;
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);

#define idlers_buf keyhandler_scratch

    printk("info:\n"
           "\tncpus              = %u\n"
           "\tmaster             = %u\n"
           "\tcredit             = %u\n"
           "\tcredit balance     = %d\n"
           "\tweight             = %u\n"
           "\trunq_sort          = %u\n"
           "\tdefault-weight     = %d\n"
           "\ttslice             = %dms\n"
           "\tratelimit          = %dus\n"
           "\tcredits per msec   = %d\n"
           "\tticks per tslice   = %d\n"
           "\tmigration delay    = %uus\n",
           prv->ncpus,
           prv->master,
           prv->credit,
           prv->credit_balance,
           prv->weight,
           prv->runq_sort,
           CSCHED_DEFAULT_WEIGHT,
           prv->tslice_ms,
           prv->ratelimit_us,
           CSCHED_CREDITS_PER_MSEC,
           prv->ticks_per_tslice,
           vcpu_migration_delay);

    cpumask_scnprintf(idlers_buf, sizeof(idlers_buf), prv->idlers);
    printk("idlers: %s\n", idlers_buf);

    printk("active vcpus:\n");
    loop = 0;
    list_for_each( iter_sdom, &prv->active_sdom )
    {
        struct csched_dom *sdom;
        sdom = list_entry(iter_sdom, struct csched_dom, active_sdom_elem);

        list_for_each( iter_svc, &sdom->active_vcpu )
        {
            struct csched_vcpu *svc;
            spinlock_t *lock;

            svc = list_entry(iter_svc, struct csched_vcpu, active_vcpu_elem);
            lock = vcpu_schedule_lock(svc->vcpu);

            printk("\t%3d: ", ++loop);
            csched_dump_vcpu(svc);

            vcpu_schedule_unlock(lock, svc->vcpu);
        }
    }
#undef idlers_buf

    spin_unlock_irqrestore(&prv->lock, flags);
}

static int
csched_init(struct scheduler *ops)
{
    struct csched_private *prv;

    prv = xzalloc(struct csched_private);
    if ( prv == NULL )
        return -ENOMEM;
    if ( !zalloc_cpumask_var(&prv->cpus) ||
         !zalloc_cpumask_var(&prv->idlers) )
    {
        free_cpumask_var(prv->cpus);
        xfree(prv);
        return -ENOMEM;
    }

    ops->sched_data = prv;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->active_sdom);
    prv->master = UINT_MAX;

    if ( sched_credit_tslice_ms > XEN_SYSCTL_CSCHED_TSLICE_MAX
         || sched_credit_tslice_ms < XEN_SYSCTL_CSCHED_TSLICE_MIN )
    {
        printk("WARNING: sched_credit_tslice_ms outside of valid range [%d,%d].\n"
               " Resetting to default %u\n",
               XEN_SYSCTL_CSCHED_TSLICE_MIN,
               XEN_SYSCTL_CSCHED_TSLICE_MAX,
               CSCHED_DEFAULT_TSLICE_MS);
        sched_credit_tslice_ms = CSCHED_DEFAULT_TSLICE_MS;
    }

    __csched_set_tslice(prv, sched_credit_tslice_ms);

    if ( MICROSECS(sched_ratelimit_us) > MILLISECS(sched_credit_tslice_ms) )
    {
        printk("WARNING: sched_ratelimit_us >" 
               "sched_credit_tslice_ms is undefined\n"
               "Setting ratelimit_us to 1000 * tslice_ms\n");
        prv->ratelimit_us = 1000 * prv->tslice_ms;
    }
    else
        prv->ratelimit_us = sched_ratelimit_us;
    return 0;
}

static void
csched_deinit(const struct scheduler *ops)
{
    struct csched_private *prv;

    prv = CSCHED_PRIV(ops);
    if ( prv != NULL )
    {
        free_cpumask_var(prv->cpus);
        free_cpumask_var(prv->idlers);
        xfree(prv);
    }
}

static void csched_tick_suspend(const struct scheduler *ops, unsigned int cpu)
{
    struct csched_pcpu *spc;

    spc = CSCHED_PCPU(cpu);

    stop_timer(&spc->ticker);
}

static void csched_tick_resume(const struct scheduler *ops, unsigned int cpu)
{
    struct csched_private *prv;
    struct csched_pcpu *spc;
    uint64_t now = NOW();

    spc = CSCHED_PCPU(cpu);

    prv = CSCHED_PRIV(ops);

    set_timer(&spc->ticker, now + MICROSECS(prv->tick_period_us)
            - now % MICROSECS(prv->tick_period_us) );
}

static struct csched_private _csched_priv;

const struct scheduler sched_credit_def = {
    .name           = "SMP Credit Scheduler",
    .opt_name       = "credit",
    .sched_id       = XEN_SCHEDULER_CREDIT,
    .sched_data     = &_csched_priv,

    .init_domain    = csched_dom_init,
    .destroy_domain = csched_dom_destroy,

    .insert_vcpu    = csched_vcpu_insert,
    .remove_vcpu    = csched_vcpu_remove,

    .sleep          = csched_vcpu_sleep,
    .wake           = csched_vcpu_wake,
    .yield          = csched_vcpu_yield,

    .adjust         = csched_dom_cntl,
    .adjust_global  = csched_sys_cntl,

    .pick_cpu       = csched_cpu_pick,
    .do_schedule    = csched_schedule,

    .dump_cpu_state = csched_dump_pcpu,
    .dump_settings  = csched_dump,
    .init           = csched_init,
    .deinit         = csched_deinit,
    .alloc_vdata    = csched_alloc_vdata,
    .free_vdata     = csched_free_vdata,
    .alloc_pdata    = csched_alloc_pdata,
    .free_pdata     = csched_free_pdata,
    .alloc_domdata  = csched_alloc_domdata,
    .free_domdata   = csched_free_domdata,

    .tick_suspend   = csched_tick_suspend,
    .tick_resume    = csched_tick_resume,
};
