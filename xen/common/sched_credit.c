/****************************************************************************
 * (C) 2005-2006 - Emmanuel Ackaouy - XenSource Inc.
 ****************************************************************************
 *
 *        File: common/csched_credit.c
 *      Author: Emmanuel Ackaouy
 *
 * Description: Credit-based SMP CPU scheduler
 */

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
#include <xen/err.h>


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
/* Never set a timer shorter than this value. */
#define CSCHED_MIN_TIMER            XEN_SYSCTL_SCHED_RATELIMIT_MIN


/*
 * Priorities
 */
#define CSCHED_PRI_TS_BOOST      0      /* time-share waking up */
#define CSCHED_PRI_TS_UNDER     -1      /* time-share w/ credits */
#define CSCHED_PRI_TS_OVER      -2      /* time-share w/o credits */
#define CSCHED_PRI_IDLE         -64     /* idle */


/*
 * Flags
 *
 * Note that svc->flags (where these flags live) is protected by an
 * inconsistent set of locks. Therefore atomic-safe bit operations must
 * be used for accessing it.
 */
#define CSCHED_FLAG_VCPU_PARKED    0x0  /* VCPU over capped credits */
#define CSCHED_FLAG_VCPU_YIELD     0x1  /* VCPU yielding */
#define CSCHED_FLAG_VCPU_MIGRATING 0x2  /* VCPU may have moved to a new pcpu */
#define CSCHED_FLAG_VCPU_PINNED    0x4  /* VCPU can run only on 1 pcpu */


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
#define TRC_CSCHED_BOOST_START   TRC_SCHED_CLASS_EVT(CSCHED, 7)
#define TRC_CSCHED_BOOST_END     TRC_SCHED_CLASS_EVT(CSCHED, 8)
#define TRC_CSCHED_SCHEDULE      TRC_SCHED_CLASS_EVT(CSCHED, 9)
#define TRC_CSCHED_RATELIMIT     TRC_SCHED_CLASS_EVT(CSCHED, 10)
#define TRC_CSCHED_STEAL_CHECK   TRC_SCHED_CLASS_EVT(CSCHED, 11)

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

    unsigned int idle_bias;
    unsigned int nr_runnable;

    unsigned int tick;
    struct timer ticker;
};

/*
 * Virtual CPU
 */
struct csched_vcpu {
    struct list_head runq_elem;
    struct list_head active_vcpu_elem;

    /* Up-pointers */
    struct csched_dom *sdom;
    struct vcpu *vcpu;

    s_time_t start_time;   /* When we were scheduled (used for credit) */
    unsigned flags;
    int pri;

    atomic_t credit;
    unsigned int residual;

    s_time_t last_sched_time;

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

    cpumask_var_t idlers;
    cpumask_var_t cpus;
    uint32_t *balance_bias;
    uint32_t runq_sort;
    uint32_t ncpus;

    /* Period of master and tick in milliseconds */
    unsigned int tick_period_us, ticks_per_tslice;
    s_time_t ratelimit, tslice, vcpu_migr_delay;

    struct list_head active_sdom;
    uint32_t weight;
    uint32_t credit;
    int credit_balance;
    unsigned int credits_per_tslice;

    unsigned int master;
    struct timer master_ticker;
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

/* Is the first element of cpu's runq (if any) cpu's idle vcpu? */
static inline bool_t is_runq_idle(unsigned int cpu)
{
    /*
     * We're peeking at cpu's runq, we must hold the proper lock.
     */
    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    return list_empty(RUNQ(cpu)) ||
           is_idle_vcpu(__runq_elem(RUNQ(cpu)->next)->vcpu);
}

static inline void
inc_nr_runnable(unsigned int cpu)
{
    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));
    CSCHED_PCPU(cpu)->nr_runnable++;

}

static inline void
dec_nr_runnable(unsigned int cpu)
{
    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));
    ASSERT(CSCHED_PCPU(cpu)->nr_runnable >= 1);
    CSCHED_PCPU(cpu)->nr_runnable--;
}

static inline void
__runq_insert(struct csched_vcpu *svc)
{
    unsigned int cpu = svc->vcpu->processor;
    const struct list_head * const runq = RUNQ(cpu);
    struct list_head *iter;

    BUG_ON( __vcpu_on_runq(svc) );

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
runq_insert(struct csched_vcpu *svc)
{
    __runq_insert(svc);
    inc_nr_runnable(svc->vcpu->processor);
}

static inline void
__runq_remove(struct csched_vcpu *svc)
{
    BUG_ON( !__vcpu_on_runq(svc) );
    list_del_init(&svc->runq_elem);
}

static inline void
runq_remove(struct csched_vcpu *svc)
{
    dec_nr_runnable(svc->vcpu->processor);
    __runq_remove(svc);
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

static inline void __runq_tickle(struct csched_vcpu *new)
{
    unsigned int cpu = new->vcpu->processor;
    struct csched_vcpu * const cur = CSCHED_VCPU(curr_on_cpu(cpu));
    struct csched_private *prv = CSCHED_PRIV(per_cpu(scheduler, cpu));
    cpumask_t mask, idle_mask, *online;
    int balance_step, idlers_empty;

    ASSERT(cur);
    cpumask_clear(&mask);

    online = cpupool_domain_cpumask(new->sdom->dom);
    cpumask_and(&idle_mask, prv->idlers, online);
    idlers_empty = cpumask_empty(&idle_mask);

    /*
     * Exclusive pinning is when a vcpu has hard-affinity with only one
     * cpu, and there is no other vcpu that has hard-affinity with that
     * same cpu. This is infrequent, but if it happens, is for achieving
     * the most possible determinism, and least possible overhead for
     * the vcpus in question.
     *
     * Try to identify the vast majority of these situations, and deal
     * with them quickly.
     */
    if ( unlikely(test_bit(CSCHED_FLAG_VCPU_PINNED, &new->flags) &&
                  cpumask_test_cpu(cpu, &idle_mask)) )
    {
        ASSERT(cpumask_cycle(cpu, new->vcpu->cpu_hard_affinity) == cpu);
        SCHED_STAT_CRANK(tickled_idle_cpu_excl);
        __cpumask_set_cpu(cpu, &mask);
        goto tickle;
    }

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
            SCHED_STAT_CRANK(tickled_busy_cpu);
        else
            SCHED_STAT_CRANK(tickled_idle_cpu);
        __cpumask_set_cpu(cpu, &mask);
    }
    else if ( !idlers_empty )
    {
        /*
         * Soft and hard affinity balancing loop. For vcpus without
         * a useful soft affinity, consider hard affinity only.
         */
        for_each_affinity_balance_step( balance_step )
        {
            int new_idlers_empty;

            if ( balance_step == BALANCE_SOFT_AFFINITY
                 && !has_soft_affinity(new->vcpu) )
                continue;

            /* Are there idlers suitable for new (for this balance step)? */
            affinity_balance_cpumask(new->vcpu, balance_step,
                                     cpumask_scratch_cpu(cpu));
            cpumask_and(cpumask_scratch_cpu(cpu),
                        cpumask_scratch_cpu(cpu), &idle_mask);
            new_idlers_empty = cpumask_empty(cpumask_scratch_cpu(cpu));

            /*
             * Let's not be too harsh! If there aren't idlers suitable
             * for new in its soft affinity mask, make sure we check its
             * hard affinity as well, before taking final decisions.
             */
            if ( new_idlers_empty
                 && balance_step == BALANCE_SOFT_AFFINITY )
                continue;

            /*
             * If there are no suitable idlers for new, and it's higher
             * priority than cur, check whether we can migrate cur away.
             * We have to do it indirectly, via _VPF_migrating (instead
             * of just tickling any idler suitable for cur) because cur
             * is running.
             *
             * If there are suitable idlers for new, no matter priorities,
             * leave cur alone (as it is running and is, likely, cache-hot)
             * and wake some of them (which is waking up and so is, likely,
             * cache cold anyway).
             */
            if ( new_idlers_empty && new->pri > cur->pri )
            {
                if ( cpumask_intersects(cur->vcpu->cpu_hard_affinity,
                                        &idle_mask) )
                {
                    SCHED_VCPU_STAT_CRANK(cur, kicked_away);
                    SCHED_VCPU_STAT_CRANK(cur, migrate_r);
                    SCHED_STAT_CRANK(migrate_kicked_away);
                    set_bit(_VPF_migrating, &cur->vcpu->pause_flags);
                }
                /* Tickle cpu anyway, to let new preempt cur. */
                SCHED_STAT_CRANK(tickled_busy_cpu);
                __cpumask_set_cpu(cpu, &mask);
            }
            else if ( !new_idlers_empty )
            {
                /* Which of the idlers suitable for new shall we wake up? */
                SCHED_STAT_CRANK(tickled_idle_cpu);
                if ( opt_tickle_one_idle )
                {
                    this_cpu(last_tickle_cpu) =
                        cpumask_cycle(this_cpu(last_tickle_cpu),
                                      cpumask_scratch_cpu(cpu));
                    __cpumask_set_cpu(this_cpu(last_tickle_cpu), &mask);
                }
                else
                    cpumask_or(&mask, &mask, cpumask_scratch_cpu(cpu));
            }

            /* Did we find anyone? */
            if ( !cpumask_empty(&mask) )
                break;
        }
    }

 tickle:
    if ( !cpumask_empty(&mask) )
    {
        if ( unlikely(tb_init_done) )
        {
            /* Avoid TRACE_*: saves checking !tb_init_done each step */
            for_each_cpu(cpu, &mask)
                __trace_var(TRC_CSCHED_TICKLE, 1, sizeof(cpu), &cpu);
        }

        /*
         * Mark the designated CPUs as busy and send them all the scheduler
         * interrupt. We need the for_each_cpu for dealing with the
         * !opt_tickle_one_idle case. We must use cpumask_clear_cpu() and
         * can't use cpumask_andnot(), because prv->idlers needs atomic access.
         *
         * In the default (and most common) case, when opt_rickle_one_idle is
         * true, the loop does only one step, and only one bit is cleared.
         */
        for_each_cpu(cpu, &mask)
            cpumask_clear_cpu(cpu, prv->idlers);
        cpumask_raise_softirq(&mask, SCHEDULE_SOFTIRQ);
    }
    else
        SCHED_STAT_CRANK(tickled_no_cpu);
}

static void
csched_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct csched_private *prv = CSCHED_PRIV(ops);

    /*
     * pcpu either points to a valid struct csched_pcpu, or is NULL, if we're
     * beeing called from CPU_UP_CANCELLED, because bringing up a pCPU failed
     * very early. xfree() does not really mind, but we want to be sure that,
     * when we get here, either init_pdata has never been called, or
     * deinit_pdata has been called already.
     */
    ASSERT(!cpumask_test_cpu(cpu, prv->cpus));

    xfree(pcpu);
}

static void
csched_deinit_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct csched_private *prv = CSCHED_PRIV(ops);
    struct csched_pcpu *spc = pcpu;
    unsigned int node = cpu_to_node(cpu);
    unsigned long flags;

    /*
     * Scheduler specific data for this pCPU must still be there and and be
     * valid. In fact, if we are here:
     *  1. alloc_pdata must have been called for this cpu, and free_pdata
     *     must not have been called on it before us,
     *  2. init_pdata must have been called on this cpu, and deinit_pdata
     *     (us!) must not have been called on it already.
     */
    ASSERT(spc && cpumask_test_cpu(cpu, prv->cpus));

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
    if ( prv->balance_bias[node] == cpu )
    {
        cpumask_and(cpumask_scratch, prv->cpus, &node_to_cpumask(node));
        if ( !cpumask_empty(cpumask_scratch) )
            prv->balance_bias[node] =  cpumask_first(cpumask_scratch);
    }
    kill_timer(&spc->ticker);
    if ( prv->ncpus == 0 )
        kill_timer(&prv->master_ticker);

    spin_unlock_irqrestore(&prv->lock, flags);
}

static void *
csched_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct csched_pcpu *spc;

    /* Allocate per-PCPU info */
    spc = xzalloc(struct csched_pcpu);
    if ( spc == NULL )
        return ERR_PTR(-ENOMEM);

    return spc;
}

static void
init_pdata(struct csched_private *prv, struct csched_pcpu *spc, int cpu)
{
    ASSERT(spin_is_locked(&prv->lock));
    /* cpu data needs to be allocated, but STILL uninitialized. */
    ASSERT(spc && spc->runq.next == NULL && spc->runq.prev == NULL);

    /* Initialize/update system-wide config */
    prv->credit += prv->credits_per_tslice;
    prv->ncpus++;
    cpumask_set_cpu(cpu, prv->cpus);
    if ( prv->ncpus == 1 )
    {
        prv->master = cpu;
        init_timer(&prv->master_ticker, csched_acct, prv, cpu);
        set_timer(&prv->master_ticker, NOW() + prv->tslice);
    }

    cpumask_and(cpumask_scratch, prv->cpus, &node_to_cpumask(cpu_to_node(cpu)));
    if ( cpumask_weight(cpumask_scratch) == 1 )
        prv->balance_bias[cpu_to_node(cpu)] = cpu;

    init_timer(&spc->ticker, csched_tick, (void *)(unsigned long)cpu, cpu);
    set_timer(&spc->ticker, NOW() + MICROSECS(prv->tick_period_us) );

    INIT_LIST_HEAD(&spc->runq);
    spc->runq_sort_last = prv->runq_sort;
    spc->idle_bias = nr_cpu_ids - 1;

    /* Start off idling... */
    BUG_ON(!is_idle_vcpu(curr_on_cpu(cpu)));
    cpumask_set_cpu(cpu, prv->idlers);
    spc->nr_runnable = 0;
}

static void
csched_init_pdata(const struct scheduler *ops, void *pdata, int cpu)
{
    unsigned long flags;
    struct csched_private *prv = CSCHED_PRIV(ops);

    spin_lock_irqsave(&prv->lock, flags);
    init_pdata(prv, pdata, cpu);
    spin_unlock_irqrestore(&prv->lock, flags);
}

/* Change the scheduler of cpu to us (Credit). */
static spinlock_t *
csched_switch_sched(struct scheduler *new_ops, unsigned int cpu,
                    void *pdata, void *vdata)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    struct csched_private *prv = CSCHED_PRIV(new_ops);
    struct csched_vcpu *svc = vdata;

    ASSERT(svc && is_idle_vcpu(svc->vcpu));

    idle_vcpu[cpu]->sched_priv = vdata;

    /*
     * We are holding the runqueue lock already (it's been taken in
     * schedule_cpu_switch()). It actually may or may not be the 'right'
     * one for this cpu, but that is ok for preventing races.
     */
    ASSERT(!local_irq_is_enabled());
    spin_lock(&prv->lock);
    init_pdata(prv, pdata, cpu);
    spin_unlock(&prv->lock);

    return &sd->_lock;
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
static unsigned int vcpu_migration_delay_us;
integer_param("vcpu_migration_delay", vcpu_migration_delay_us);

static inline bool
__csched_vcpu_is_cache_hot(const struct csched_private *prv,
                           const struct csched_vcpu *svc)
{
    bool hot = prv->vcpu_migr_delay &&
               (NOW() - svc->last_sched_time) < prv->vcpu_migr_delay;

    if ( hot )
        SCHED_STAT_CRANK(vcpu_hot);

    return hot;
}

static inline int
__csched_vcpu_is_migrateable(const struct csched_private *prv, struct vcpu *vc,
                             int dest_cpu, cpumask_t *mask)
{
    const struct csched_vcpu *svc = CSCHED_VCPU(vc);
    /*
     * Don't pick up work that's hot on peer PCPU, or that can't (or
     * would prefer not to) run on cpu.
     *
     * The caller is supposed to have already checked that vc is also
     * not running.
     */
    ASSERT(!vc->is_running);

    return !__csched_vcpu_is_cache_hot(prv, svc) &&
           cpumask_test_cpu(dest_cpu, mask);
}

static int
_csched_cpu_pick(const struct scheduler *ops, struct vcpu *vc, bool_t commit)
{
    /* We must always use vc->procssor's scratch space */
    cpumask_t *cpus = cpumask_scratch_cpu(vc->processor);
    cpumask_t idlers;
    cpumask_t *online = cpupool_domain_cpumask(vc->domain);
    struct csched_pcpu *spc = NULL;
    int cpu = vc->processor;
    int balance_step;

    for_each_affinity_balance_step( balance_step )
    {
        affinity_balance_cpumask(vc, balance_step, cpus);
        cpumask_and(cpus, online, cpus);
        /*
         * We want to pick up a pcpu among the ones that are online and
         * can accommodate vc. As far as hard affinity is concerned, there
         * always will be at least one of these pcpus in the scratch cpumask,
         * hence, the calls to cpumask_cycle() and cpumask_test_cpu() below
         * are ok.
         *
         * On the other hand, when considering soft affinity, it is possible
         * that the mask is empty (for instance, if the domain has been put
         * in a cpupool that does not contain any of the pcpus in its soft
         * affinity), which would result in the ASSERT()-s inside cpumask_*()
         * operations triggering (in debug builds).
         *
         * Therefore, if that is the case, we just skip the soft affinity
         * balancing step all together.
         */
        if ( balance_step == BALANCE_SOFT_AFFINITY &&
             (!has_soft_affinity(vc) || cpumask_empty(cpus)) )
            continue;

        /* If present, prefer vc's current processor */
        cpu = cpumask_test_cpu(vc->processor, cpus)
                ? vc->processor : cpumask_cycle(vc->processor, cpus);
        ASSERT(cpumask_test_cpu(cpu, cpus));

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
        if ( vc->processor == cpu && is_runq_idle(cpu) )
            __cpumask_set_cpu(cpu, &idlers);
        cpumask_and(cpus, &idlers, cpus);

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
        if ( !cpumask_test_cpu(cpu, cpus) && !cpumask_empty(cpus) )
            cpu = cpumask_cycle(cpu, cpus);
        __cpumask_clear_cpu(cpu, cpus);

        while ( !cpumask_empty(cpus) )
        {
            cpumask_t cpu_idlers;
            cpumask_t nxt_idlers;
            int nxt, weight_cpu, weight_nxt;
            int migrate_factor;

            nxt = cpumask_cycle(cpu, cpus);

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
                cpumask_and(&nxt_idlers, &nxt_idlers, cpus);
                spc = CSCHED_PCPU(nxt);
                cpu = cpumask_cycle(spc->idle_bias, &nxt_idlers);
                cpumask_andnot(cpus, cpus, per_cpu(cpu_sibling_mask, cpu));
            }
            else
            {
                cpumask_andnot(cpus, cpus, &nxt_idlers);
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
    struct csched_vcpu *svc = CSCHED_VCPU(vc);

    /*
     * We have been called by vcpu_migrate() (in schedule.c), as part
     * of the process of seeing if vc can be migrated to another pcpu.
     * We make a note about this in svc->flags so that later, in
     * csched_vcpu_wake() (still called from vcpu_migrate()) we won't
     * get boosted, which we don't deserve as we are "only" migrating.
     */
    set_bit(CSCHED_FLAG_VCPU_MIGRATING, &svc->flags);
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
    ASSERT( !is_idle_vcpu(svc->vcpu) );

    /*
     * If this VCPU's priority was boosted when it last awoke, reset it.
     * If the VCPU is found here, then it's consuming a non-negligeable
     * amount of CPU resources and should no longer be boosted.
     */
    if ( svc->pri == CSCHED_PRI_TS_BOOST )
    {
        svc->pri = CSCHED_PRI_TS_UNDER;
        TRACE_2D(TRC_CSCHED_BOOST_END, svc->sdom->dom->domain_id,
                 svc->vcpu->vcpu_id);
    }

    /*
     * Update credits
     */
    burn_credits(svc, NOW());

    /*
     * Put this VCPU and domain back on the active list if it was
     * idling.
     */
    if ( list_empty(&svc->active_vcpu_elem) )
    {
        __csched_vcpu_acct_start(prv, svc);
    }
    else
    {
        unsigned int new_cpu;
        unsigned long flags;
        spinlock_t *lock = vcpu_schedule_lock_irqsave(current, &flags);

        /*
         * If it's been active a while, check if we'd be better off
         * migrating it to run elsewhere (see multi-core and multi-thread
         * support in csched_cpu_pick()).
         */
        new_cpu = _csched_cpu_pick(ops, current, 0);

        vcpu_schedule_unlock_irqrestore(lock, flags, current);

        if ( new_cpu != cpu )
        {
            SCHED_VCPU_STAT_CRANK(svc, migrate_r);
            SCHED_STAT_CRANK(migrate_running);
            set_bit(_VPF_migrating, &current->pause_flags);
            /*
             * As we are about to tickle cpu, we should clear its bit in
             * idlers. But, if we are here, it means there is someone running
             * on it, and hence the bit must be zero already.
             */
            ASSERT(!cpumask_test_cpu(cpu,
                                     CSCHED_PRIV(per_cpu(scheduler, cpu))->idlers));
            cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
        }
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
    SCHED_STAT_CRANK(vcpu_alloc);
    return svc;
}

static void
csched_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu *svc = vc->sched_priv;
    spinlock_t *lock;

    BUG_ON( is_idle_vcpu(vc) );

    /* csched_cpu_pick() looks in vc->processor's runq, so we need the lock. */
    lock = vcpu_schedule_lock_irq(vc);

    vc->processor = csched_cpu_pick(ops, vc);

    spin_unlock_irq(lock);

    lock = vcpu_schedule_lock_irq(vc);

    if ( !__vcpu_on_runq(svc) && vcpu_runnable(vc) && !vc->is_running )
        runq_insert(svc);

    vcpu_schedule_unlock_irq(lock, vc);

    SCHED_STAT_CRANK(vcpu_insert);
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

    SCHED_STAT_CRANK(vcpu_remove);

    ASSERT(!__vcpu_on_runq(svc));

    if ( test_and_clear_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
    {
        SCHED_STAT_CRANK(vcpu_unpark);
        vcpu_unpause(svc->vcpu);
    }

    spin_lock_irq(&prv->lock);

    if ( !list_empty(&svc->active_vcpu_elem) )
        __csched_vcpu_acct_stop_locked(prv, svc);

    spin_unlock_irq(&prv->lock);

    BUG_ON( sdom == NULL );
}

static void
csched_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    unsigned int cpu = vc->processor;

    SCHED_STAT_CRANK(vcpu_sleep);

    BUG_ON( is_idle_vcpu(vc) );

    if ( curr_on_cpu(cpu) == vc )
    {
        /*
         * We are about to tickle cpu, so we should clear its bit in idlers.
         * But, we are here because vc is going to sleep while running on cpu,
         * so the bit must be zero already.
         */
        ASSERT(!cpumask_test_cpu(cpu, CSCHED_PRIV(per_cpu(scheduler, cpu))->idlers));
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    }
    else if ( __vcpu_on_runq(svc) )
        runq_remove(svc);
}

static void
csched_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    bool_t migrating;

    BUG_ON( is_idle_vcpu(vc) );

    if ( unlikely(curr_on_cpu(vc->processor) == vc) )
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
     * There are two cases, when we don't want to boost:
     *  - VCPUs that are waking up after a migration, rather than
     *    after having block;
     *  - VCPUs of capped domains unpausing after earning credits
     *    they had overspent.
     */
    migrating = test_and_clear_bit(CSCHED_FLAG_VCPU_MIGRATING, &svc->flags);

    if ( !migrating && svc->pri == CSCHED_PRI_TS_UNDER &&
         !test_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
    {
        TRACE_2D(TRC_CSCHED_BOOST_START, vc->domain->domain_id, vc->vcpu_id);
        SCHED_STAT_CRANK(vcpu_boost);
        svc->pri = CSCHED_PRI_TS_BOOST;
    }

    /* Put the VCPU on the runq and tickle CPUs */
    runq_insert(svc);
    __runq_tickle(svc);
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
    int rc = 0;

    /* Protect both get and put branches with the pluggable scheduler
     * lock. Runq lock not needed anywhere in here. */
    spin_lock_irqsave(&prv->lock, flags);

    switch ( op->cmd )
    {
    case XEN_DOMCTL_SCHEDOP_getinfo:
        op->u.credit.weight = sdom->weight;
        op->u.credit.cap = sdom->cap;
        break;
    case XEN_DOMCTL_SCHEDOP_putinfo:
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
        break;
    default:
        rc = -EINVAL;
        break;
    }

    spin_unlock_irqrestore(&prv->lock, flags);

    return rc;
}

static void
csched_aff_cntl(const struct scheduler *ops, struct vcpu *v,
                const cpumask_t *hard, const cpumask_t *soft)
{
    struct csched_vcpu *svc = CSCHED_VCPU(v);

    if ( !hard )
        return;

    /* Are we becoming exclusively pinned? */
    if ( cpumask_weight(hard) == 1 )
        set_bit(CSCHED_FLAG_VCPU_PINNED, &svc->flags);
    else
        clear_bit(CSCHED_FLAG_VCPU_PINNED, &svc->flags);
}

static inline void
__csched_set_tslice(struct csched_private *prv, unsigned int timeslice_ms)
{
    prv->tslice = MILLISECS(timeslice_ms);
    prv->ticks_per_tslice = CSCHED_TICKS_PER_TSLICE;
    if ( timeslice_ms < prv->ticks_per_tslice )
        prv->ticks_per_tslice = 1;
    prv->tick_period_us = timeslice_ms * 1000 / prv->ticks_per_tslice;
    prv->credits_per_tslice = CSCHED_CREDITS_PER_MSEC * timeslice_ms;
    prv->credit = prv->credits_per_tslice * prv->ncpus;
}

static int
csched_sys_cntl(const struct scheduler *ops,
                        struct xen_sysctl_scheduler_op *sc)
{
    int rc = -EINVAL;
    struct xen_sysctl_credit_schedule *params = &sc->u.sched_credit;
    struct csched_private *prv = CSCHED_PRIV(ops);
    unsigned long flags;

    switch ( sc->cmd )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
        if ( params->tslice_ms > XEN_SYSCTL_CSCHED_TSLICE_MAX
             || params->tslice_ms < XEN_SYSCTL_CSCHED_TSLICE_MIN
             || (params->ratelimit_us
                 && (params->ratelimit_us > XEN_SYSCTL_SCHED_RATELIMIT_MAX
                     || params->ratelimit_us < XEN_SYSCTL_SCHED_RATELIMIT_MIN))
             || MICROSECS(params->ratelimit_us) > MILLISECS(params->tslice_ms)
             || params->vcpu_migr_delay_us > XEN_SYSCTL_CSCHED_MGR_DLY_MAX_US )
                goto out;

        spin_lock_irqsave(&prv->lock, flags);
        __csched_set_tslice(prv, params->tslice_ms);
        if ( !prv->ratelimit && params->ratelimit_us )
            printk(XENLOG_INFO "Enabling context switch rate limiting\n");
        else if ( prv->ratelimit && !params->ratelimit_us )
            printk(XENLOG_INFO "Disabling context switch rate limiting\n");
        prv->ratelimit = MICROSECS(params->ratelimit_us);
        prv->vcpu_migr_delay = MICROSECS(params->vcpu_migr_delay_us);
        spin_unlock_irqrestore(&prv->lock, flags);

        /* FALLTHRU */
    case XEN_SYSCTL_SCHEDOP_getinfo:
        params->tslice_ms = prv->tslice / MILLISECS(1);
        params->ratelimit_us = prv->ratelimit / MICROSECS(1);
        params->vcpu_migr_delay_us = prv->vcpu_migr_delay / MICROSECS(1);
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
        return ERR_PTR(-ENOMEM);

    /* Initialize credit and weight */
    INIT_LIST_HEAD(&sdom->active_vcpu);
    INIT_LIST_HEAD(&sdom->active_sdom_elem);
    sdom->dom = dom;
    sdom->weight = CSCHED_DEFAULT_WEIGHT;

    return sdom;
}

static void
csched_free_domdata(const struct scheduler *ops, void *data)
{
    xfree(data);
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
                if ( test_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags) )
                {
                    /*
                     * It's important to unset the flag AFTER the unpause()
                     * call to make sure the VCPU's priority is not boosted
                     * if it is woken up here.
                     */
                    SCHED_STAT_CRANK(vcpu_unpark);
                    vcpu_unpause(svc->vcpu);
                    clear_bit(CSCHED_FLAG_VCPU_PARKED, &svc->flags);
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
    set_timer( &prv->master_ticker, NOW() + prv->tslice);
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
    const struct csched_private * const prv = CSCHED_PRIV(per_cpu(scheduler, cpu));
    const struct csched_pcpu * const peer_pcpu = CSCHED_PCPU(peer_cpu);
    struct csched_vcpu *speer;
    struct list_head *iter;
    struct vcpu *vc;

    ASSERT(peer_pcpu != NULL);

    /*
     * Don't steal from an idle CPU's runq because it's about to
     * pick up work from it itself.
     */
    if ( unlikely(is_idle_vcpu(curr_on_cpu(peer_cpu))) )
        goto out;

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
         * If the vcpu is still in peer_cpu's scheduling tail, or if it
         * has no useful soft affinity, skip it.
         *
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
        if ( vc->is_running || (balance_step == BALANCE_SOFT_AFFINITY &&
                                !has_soft_affinity(vc)) )
            continue;

        affinity_balance_cpumask(vc, balance_step, cpumask_scratch);
        if ( __csched_vcpu_is_migrateable(prv, vc, cpu, cpumask_scratch) )
        {
            /* We got a candidate. Grab it! */
            TRACE_3D(TRC_CSCHED_STOLEN_VCPU, peer_cpu,
                     vc->domain->domain_id, vc->vcpu_id);
            SCHED_VCPU_STAT_CRANK(speer, migrate_q);
            SCHED_STAT_CRANK(migrate_queued);
            WARN_ON(vc->is_urgent);
            runq_remove(speer);
            vc->processor = cpu;
            /*
             * speer will start executing directly on cpu, without having to
             * go through runq_insert(). So we must update the runnable count
             * for cpu here.
             */
            inc_nr_runnable(cpu);
            return speer;
        }
    }
 out:
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
    int peer_cpu, first_cpu, peer_node, bstep;
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
    for_each_affinity_balance_step( bstep )
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
            /* Select the pCPUs in this node that have work we can steal. */
            cpumask_andnot(&workers, online, prv->idlers);
            cpumask_and(&workers, &workers, &node_to_cpumask(peer_node));
            __cpumask_clear_cpu(cpu, &workers);

            first_cpu = cpumask_cycle(prv->balance_bias[peer_node], &workers);
            if ( first_cpu >= nr_cpu_ids )
                goto next_node;
            peer_cpu = first_cpu;
            do
            {
                spinlock_t *lock;

                /*
                 * If there is only one runnable vCPU on peer_cpu, it means
                 * there's no one to be stolen in its runqueue, so skip it.
                 *
                 * Checking this without holding the lock is racy... But that's
                 * the whole point of this optimization!
                 *
                 * In more details:
                 * - if we race with dec_nr_runnable(), we may try to take the
                 *   lock and call csched_runq_steal() for no reason. This is
                 *   not a functional issue, and should be infrequent enough.
                 *   And we can avoid that by re-checking nr_runnable after
                 *   having grabbed the lock, if we want;
                 * - if we race with inc_nr_runnable(), we skip a pCPU that may
                 *   have runnable vCPUs in its runqueue, but that's not a
                 *   problem because:
                 *   + if racing with csched_vcpu_insert() or csched_vcpu_wake(),
                 *     __runq_tickle() will be called afterwords, so the vCPU
                 *     won't get stuck in the runqueue for too long;
                 *   + if racing with csched_runq_steal(), it may be that a
                 *     vCPU that we could have picked up, stays in a runqueue
                 *     until someone else tries to steal it again. But this is
                 *     no worse than what can happen already (without this
                 *     optimization), it the pCPU would schedule right after we
                 *     have taken the lock, and hence block on it.
                 */
                if ( CSCHED_PCPU(peer_cpu)->nr_runnable <= 1 )
                {
                    TRACE_2D(TRC_CSCHED_STEAL_CHECK, peer_cpu, /* skipp'n */ 0);
                    goto next_cpu;
                }

                /*
                 * Get ahold of the scheduler lock for this peer CPU.
                 *
                 * Note: We don't spin on this lock but simply try it. Spinning
                 * could cause a deadlock if the peer CPU is also load
                 * balancing and trying to lock this CPU.
                 */
                lock = pcpu_schedule_trylock(peer_cpu);
                SCHED_STAT_CRANK(steal_trylock);
                if ( !lock )
                {
                    SCHED_STAT_CRANK(steal_trylock_failed);
                    TRACE_2D(TRC_CSCHED_STEAL_CHECK, peer_cpu, /* skip */ 0);
                    goto next_cpu;
                }

                TRACE_2D(TRC_CSCHED_STEAL_CHECK, peer_cpu, /* checked */ 1);

                /* Any work over there to steal? */
                speer = cpumask_test_cpu(peer_cpu, online) ?
                    csched_runq_steal(peer_cpu, cpu, snext->pri, bstep) : NULL;
                pcpu_schedule_unlock(lock, peer_cpu);

                /* As soon as one vcpu is found, balancing ends */
                if ( speer != NULL )
                {
                    *stolen = 1;
                    /*
                     * Next time we'll look for work to steal on this node, we
                     * will start from the next pCPU, with respect to this one,
                     * so we don't risk stealing always from the same ones.
                     */
                    prv->balance_bias[peer_node] = peer_cpu;
                    return speer;
                }

 next_cpu:
                peer_cpu = cpumask_cycle(peer_cpu, &workers);

            } while( peer_cpu != first_cpu );

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

    /*
     * Here in Credit1 code, we usually just call TRACE_nD() helpers, and
     * don't care about packing. But scheduling happens very often, so it
     * actually is important that the record is as small as possible.
     */
    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned cpu:16, tasklet:8, idle:8;
        } d;
        d.cpu = cpu;
        d.tasklet = tasklet_work_scheduled;
        d.idle = is_idle_vcpu(current);
        __trace_var(TRC_CSCHED_SCHEDULE, 1, sizeof(d),
                    (unsigned char *)&d);
    }

    runtime = now - current->runstate.state_entry_time;
    if ( runtime < 0 ) /* Does this ever happen? */
        runtime = 0;

    if ( !is_idle_vcpu(scurr->vcpu) )
    {
        /* Update credits of a non-idle VCPU. */
        burn_credits(scurr, now);
        scurr->start_time -= now;
        scurr->last_sched_time = now;
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

    /*
     * If we have schedule rate limiting enabled, check to see
     * how long we've run for.
     *
     * If scurr is yielding, however, we don't let rate limiting kick in.
     * In fact, it may be the case that scurr is about to spin, and there's
     * no point forcing it to do so until rate limiting expires.
     */
    if ( !test_bit(CSCHED_FLAG_VCPU_YIELD, &scurr->flags)
         && !tasklet_work_scheduled
         && prv->ratelimit
         && vcpu_runnable(current)
         && !is_idle_vcpu(current)
         && runtime < prv->ratelimit )
    {
        snext = scurr;
        snext->start_time += now;
        perfc_incr(delay_ms);
        /*
         * Next timeslice must last just until we'll have executed for
         * ratelimit. However, to avoid setting a really short timer, which
         * will most likely be inaccurate and counterproductive, we never go
         * below CSCHED_MIN_TIMER.
         */
        tslice = prv->ratelimit - runtime;
        if ( unlikely(runtime < CSCHED_MIN_TIMER) )
            tslice = CSCHED_MIN_TIMER;
        if ( unlikely(tb_init_done) )
        {
            struct {
                unsigned vcpu:16, dom:16;
                unsigned runtime;
            } d;
            d.dom = scurr->vcpu->domain->domain_id;
            d.vcpu = scurr->vcpu->vcpu_id;
            d.runtime = runtime;
            __trace_var(TRC_CSCHED_RATELIMIT, 1, sizeof(d),
                        (unsigned char *)&d);
        }

        ret.migrated = 0;
        goto out;
    }
    tslice = prv->tslice;

    /*
     * Select next runnable local VCPU (ie top of local runq)
     */
    if ( vcpu_runnable(current) )
        __runq_insert(scurr);
    else
    {
        BUG_ON( is_idle_vcpu(current) || list_empty(runq) );
        /* Current has blocked. Update the runnable counter for this cpu. */
        dec_nr_runnable(cpu);
    }

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
    if ( !tasklet_work_scheduled && snext->pri == CSCHED_PRI_IDLE )
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
    spinlock_t *lock;
    unsigned long flags;
    int loop;

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

    printk("CPU[%02d] nr_run=%d, sort=%d, sibling=%*pb, core=%*pb\n",
           cpu, spc->nr_runnable, spc->runq_sort_last,
           CPUMASK_PR(per_cpu(cpu_sibling_mask, cpu)),
           CPUMASK_PR(per_cpu(cpu_core_mask, cpu)));

    /* current VCPU (nothing to say if that's the idle vcpu). */
    svc = CSCHED_VCPU(curr_on_cpu(cpu));
    if ( svc && !is_idle_vcpu(svc->vcpu) )
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
}

static void
csched_dump(const struct scheduler *ops)
{
    struct list_head *iter_sdom, *iter_svc;
    struct csched_private *prv = CSCHED_PRIV(ops);
    int loop;
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);

    printk("info:\n"
           "\tncpus              = %u\n"
           "\tmaster             = %u\n"
           "\tcredit             = %u\n"
           "\tcredit balance     = %d\n"
           "\tweight             = %u\n"
           "\trunq_sort          = %u\n"
           "\tdefault-weight     = %d\n"
           "\ttslice             = %"PRI_stime"ms\n"
           "\tratelimit          = %"PRI_stime"us\n"
           "\tcredits per msec   = %d\n"
           "\tticks per tslice   = %d\n"
           "\tmigration delay    = %"PRI_stime"us\n",
           prv->ncpus,
           prv->master,
           prv->credit,
           prv->credit_balance,
           prv->weight,
           prv->runq_sort,
           CSCHED_DEFAULT_WEIGHT,
           prv->tslice / MILLISECS(1),
           prv->ratelimit / MICROSECS(1),
           CSCHED_CREDITS_PER_MSEC,
           prv->ticks_per_tslice,
           prv->vcpu_migr_delay/ MICROSECS(1));

    printk("idlers: %*pb\n", CPUMASK_PR(prv->idlers));

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

    spin_unlock_irqrestore(&prv->lock, flags);
}

static int __init
csched_global_init(void)
{
    if ( sched_credit_tslice_ms > XEN_SYSCTL_CSCHED_TSLICE_MAX ||
         sched_credit_tslice_ms < XEN_SYSCTL_CSCHED_TSLICE_MIN )
    {
        printk("WARNING: sched_credit_tslice_ms outside of valid range [%d,%d].\n"
               " Resetting to default %u\n",
               XEN_SYSCTL_CSCHED_TSLICE_MIN,
               XEN_SYSCTL_CSCHED_TSLICE_MAX,
               CSCHED_DEFAULT_TSLICE_MS);
        sched_credit_tslice_ms = CSCHED_DEFAULT_TSLICE_MS;
    }

    if ( MICROSECS(sched_ratelimit_us) > MILLISECS(sched_credit_tslice_ms) )
        printk("WARNING: sched_ratelimit_us >"
               "sched_credit_tslice_ms is undefined\n"
               "Setting ratelimit to tslice\n");

    if ( vcpu_migration_delay_us > XEN_SYSCTL_CSCHED_MGR_DLY_MAX_US )
    {
        vcpu_migration_delay_us = 0;
        printk("WARNING: vcpu_migration_delay outside of valid range [0,%d]us.\n"
               "Resetting to default: %u\n",
               XEN_SYSCTL_CSCHED_MGR_DLY_MAX_US, vcpu_migration_delay_us);
    }

    return 0;
}

static int
csched_init(struct scheduler *ops)
{
    struct csched_private *prv;

    prv = xzalloc(struct csched_private);
    if ( prv == NULL )
        return -ENOMEM;

    prv->balance_bias = xzalloc_array(uint32_t, MAX_NUMNODES);
    if ( prv->balance_bias == NULL )
    {
        xfree(prv);
        return -ENOMEM;
    }

    if ( !zalloc_cpumask_var(&prv->cpus) ||
         !zalloc_cpumask_var(&prv->idlers) )
    {
        free_cpumask_var(prv->cpus);
        xfree(prv->balance_bias);
        xfree(prv);
        return -ENOMEM;
    }

    ops->sched_data = prv;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->active_sdom);
    prv->master = UINT_MAX;

    __csched_set_tslice(prv, sched_credit_tslice_ms);

    if ( MICROSECS(sched_ratelimit_us) > MILLISECS(sched_credit_tslice_ms) )
        prv->ratelimit = prv->tslice;
    else
        prv->ratelimit = MICROSECS(sched_ratelimit_us);

    prv->vcpu_migr_delay = MICROSECS(vcpu_migration_delay_us);

    return 0;
}

static void
csched_deinit(struct scheduler *ops)
{
    struct csched_private *prv;

    prv = CSCHED_PRIV(ops);
    if ( prv != NULL )
    {
        ops->sched_data = NULL;
        free_cpumask_var(prv->cpus);
        free_cpumask_var(prv->idlers);
        xfree(prv->balance_bias);
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

static const struct scheduler sched_credit_def = {
    .name           = "SMP Credit Scheduler",
    .opt_name       = "credit",
    .sched_id       = XEN_SCHEDULER_CREDIT,
    .sched_data     = NULL,

    .global_init    = csched_global_init,

    .insert_vcpu    = csched_vcpu_insert,
    .remove_vcpu    = csched_vcpu_remove,

    .sleep          = csched_vcpu_sleep,
    .wake           = csched_vcpu_wake,
    .yield          = csched_vcpu_yield,

    .adjust         = csched_dom_cntl,
    .adjust_affinity= csched_aff_cntl,
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
    .init_pdata     = csched_init_pdata,
    .deinit_pdata   = csched_deinit_pdata,
    .free_pdata     = csched_free_pdata,
    .switch_sched   = csched_switch_sched,
    .alloc_domdata  = csched_alloc_domdata,
    .free_domdata   = csched_free_domdata,

    .tick_suspend   = csched_tick_suspend,
    .tick_resume    = csched_tick_resume,
};

REGISTER_SCHEDULER(sched_credit_def);
