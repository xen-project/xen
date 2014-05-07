
/****************************************************************************
 * (C) 2009 - George Dunlap - Citrix Systems R&D UK, Ltd
 ****************************************************************************
 *
 *        File: common/sched_credit2.c
 *      Author: George Dunlap
 *
 * Description: Credit-based SMP CPU scheduler
 * Based on an earlier verson by Emmanuel Ackaouy.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/div64.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/cpu.h>

#define d2printk(x...)
//#define d2printk printk

/*
 * Credit2 tracing events ("only" 512 available!). Check
 * include/public/trace.h for more details.
 */
#define TRC_CSCHED2_TICK             TRC_SCHED_CLASS_EVT(CSCHED2, 1)
#define TRC_CSCHED2_RUNQ_POS         TRC_SCHED_CLASS_EVT(CSCHED2, 2)
#define TRC_CSCHED2_CREDIT_BURN      TRC_SCHED_CLASS_EVT(CSCHED2, 3)
#define TRC_CSCHED2_CREDIT_ADD       TRC_SCHED_CLASS_EVT(CSCHED2, 4)
#define TRC_CSCHED2_TICKLE_CHECK     TRC_SCHED_CLASS_EVT(CSCHED2, 5)
#define TRC_CSCHED2_TICKLE           TRC_SCHED_CLASS_EVT(CSCHED2, 6)
#define TRC_CSCHED2_CREDIT_RESET     TRC_SCHED_CLASS_EVT(CSCHED2, 7)
#define TRC_CSCHED2_SCHED_TASKLET    TRC_SCHED_CLASS_EVT(CSCHED2, 8)
#define TRC_CSCHED2_UPDATE_LOAD      TRC_SCHED_CLASS_EVT(CSCHED2, 9)
#define TRC_CSCHED2_RUNQ_ASSIGN      TRC_SCHED_CLASS_EVT(CSCHED2, 10)
#define TRC_CSCHED2_UPDATE_VCPU_LOAD TRC_SCHED_CLASS_EVT(CSCHED2, 11)
#define TRC_CSCHED2_UPDATE_RUNQ_LOAD TRC_SCHED_CLASS_EVT(CSCHED2, 12)

/*
 * WARNING: This is still in an experimental phase.  Status and work can be found at the
 * credit2 wiki page:
 *  http://wiki.xen.org/wiki/Credit2_Scheduler_Development
 * TODO:
 * + Immediate bug-fixes
 *  - Do per-runqueue, grab proper lock for dump debugkey
 * + Multiple sockets
 *  - Detect cpu layout and make runqueue map, one per L2 (make_runq_map())
 *  - Simple load balancer / runqueue assignment
 *  - Runqueue load measurement
 *  - Load-based load balancer
 * + Hyperthreading
 *  - Look for non-busy core if possible
 *  - "Discount" time run on a thread with busy siblings
 * + Algorithm:
 *  - "Mixed work" problem: if a VM is playing audio (5%) but also burning cpu (e.g.,
 *    a flash animation in the background) can we schedule it with low enough latency
 *    so that audio doesn't skip?
 *  - Cap and reservation: How to implement with the current system?
 * + Optimizing
 *  - Profiling, making new algorithms, making math more efficient (no long division)
 */

/*
 * Design:
 *
 * VMs "burn" credits based on their weight; higher weight means
 * credits burn more slowly.  The highest weight vcpu burns credits at
 * a rate of 1 credit per nanosecond.  Others burn proportionally
 * more.
 *
 * vcpus are inserted into the runqueue by credit order.
 *
 * Credits are "reset" when the next vcpu in the runqueue is less than
 * or equal to zero.  At that point, everyone's credits are "clipped"
 * to a small value, and a fixed credit is added to everyone.
 *
 * The plan is for all cores that share an L2 will share the same
 * runqueue.  At the moment, there is one global runqueue for all
 * cores.
 */

/*
 * Locking:
 * - Schedule-lock is per-runqueue
 *  + Protects runqueue data, runqueue insertion, &c
 *  + Also protects updates to private sched vcpu structure
 *  + Must be grabbed using vcpu_schedule_lock_irq() to make sure vcpu->processr
 *    doesn't change under our feet.
 * - Private data lock
 *  + Protects access to global domain list
 *  + All other private data is written at init and only read afterwards.
 * Ordering:
 * - We grab private->schedule when updating domain weight; so we
 *  must never grab private if a schedule lock is held.
 */

/*
 * Basic constants
 */
/* Default weight: How much a new domain starts with */
#define CSCHED2_DEFAULT_WEIGHT       256
/* Min timer: Minimum length a timer will be set, to
 * achieve efficiency */
#define CSCHED2_MIN_TIMER            MICROSECS(500)
/* Amount of credit VMs begin with, and are reset to.
 * ATM, set so that highest-weight VMs can only run for 10ms
 * before a reset event. */
#define CSCHED2_CREDIT_INIT          MILLISECS(10)
/* Carryover: How much "extra" credit may be carried over after
 * a reset. */
#define CSCHED2_CARRYOVER_MAX        CSCHED2_MIN_TIMER
/* Stickiness: Cross-L2 migration resistance.  Should be less than
 * MIN_TIMER. */
#define CSCHED2_MIGRATE_RESIST       ((opt_migrate_resist)*MICROSECS(1))
/* How much to "compensate" a vcpu for L2 migration */
#define CSCHED2_MIGRATE_COMPENSATION MICROSECS(50)
/* Reset: Value below which credit will be reset. */
#define CSCHED2_CREDIT_RESET         0
/* Max timer: Maximum time a guest can be run for. */
#define CSCHED2_MAX_TIMER            MILLISECS(2)


#define CSCHED2_IDLE_CREDIT                 (-(1<<30))

/*
 * Flags
 */
/* CSFLAG_scheduled: Is this vcpu either running on, or context-switching off,
 * a physical cpu?
 * + Accessed only with runqueue lock held
 * + Set when chosen as next in csched2_schedule().
 * + Cleared after context switch has been saved in csched2_context_saved()
 * + Checked in vcpu_wake to see if we can add to the runqueue, or if we should
 *   set CSFLAG_delayed_runq_add
 * + Checked to be false in runq_insert.
 */
#define __CSFLAG_scheduled 1
#define CSFLAG_scheduled (1<<__CSFLAG_scheduled)
/* CSFLAG_delayed_runq_add: Do we need to add this to the runqueue once it'd done
 * being context switched out?
 * + Set when scheduling out in csched2_schedule() if prev is runnable
 * + Set in csched2_vcpu_wake if it finds CSFLAG_scheduled set
 * + Read in csched2_context_saved().  If set, it adds prev to the runqueue and
 *   clears the bit.
 */
#define __CSFLAG_delayed_runq_add 2
#define CSFLAG_delayed_runq_add (1<<__CSFLAG_delayed_runq_add)
/* CSFLAG_runq_migrate_request: This vcpu is being migrated as a result of a
 * credit2-initiated runq migrate request; migrate it to the runqueue indicated
 * in the svc struct. 
 */
#define __CSFLAG_runq_migrate_request 3
#define CSFLAG_runq_migrate_request (1<<__CSFLAG_runq_migrate_request)


int opt_migrate_resist=500;
integer_param("sched_credit2_migrate_resist", opt_migrate_resist);

/*
 * Useful macros
 */
#define CSCHED2_PRIV(_ops)   \
    ((struct csched2_private *)((_ops)->sched_data))
#define CSCHED2_VCPU(_vcpu)  ((struct csched2_vcpu *) (_vcpu)->sched_priv)
#define CSCHED2_DOM(_dom)    ((struct csched2_dom *) (_dom)->sched_priv)
/* CPU to runq_id macro */
#define c2r(_ops, _cpu)     (CSCHED2_PRIV(_ops)->runq_map[(_cpu)])
/* CPU to runqueue struct macro */
#define RQD(_ops, _cpu)     (&CSCHED2_PRIV(_ops)->rqd[c2r(_ops, _cpu)])

/*
 * Shifts for load average.
 * - granularity: Reduce granularity of time by a factor of 1000, so we can use 32-bit maths
 * - window shift: Given granularity shift, make the window about 1 second
 * - scale shift: Shift up load by this amount rather than using fractions; 128 corresponds 
 *   to a load of 1.
 */
#define LOADAVG_GRANULARITY_SHIFT (10)
int opt_load_window_shift=18;
#define  LOADAVG_WINDOW_SHIFT_MIN 4
integer_param("credit2_load_window_shift", opt_load_window_shift);
int opt_underload_balance_tolerance=0;
integer_param("credit2_balance_under", opt_underload_balance_tolerance);
int opt_overload_balance_tolerance=-3;
integer_param("credit2_balance_over", opt_overload_balance_tolerance);

/*
 * Per-runqueue data
 */
struct csched2_runqueue_data {
    int id;

    spinlock_t lock;      /* Lock for this runqueue. */
    cpumask_t active;      /* CPUs enabled for this runqueue */

    struct list_head runq; /* Ordered list of runnable vms */
    struct list_head svc;  /* List of all vcpus assigned to this runqueue */
    unsigned int max_weight;

    cpumask_t idle,        /* Currently idle */
        tickled;           /* Another cpu in the queue is already targeted for this one */
    int load;              /* Instantaneous load: Length of queue  + num non-idle threads */
    s_time_t load_last_update;  /* Last time average was updated */
    s_time_t avgload;           /* Decaying queue load */
    s_time_t b_avgload;         /* Decaying queue load modified by balancing */
};

/*
 * System-wide private data
 */
struct csched2_private {
    spinlock_t lock;
    cpumask_t initialized; /* CPU is initialized for this pool */
    
    struct list_head sdom; /* Used mostly for dump keyhandler. */

    int runq_map[NR_CPUS];
    cpumask_t active_queues; /* Queues which may have active cpus */
    struct csched2_runqueue_data rqd[NR_CPUS];

    int load_window_shift;
};

/*
 * Virtual CPU
 */
struct csched2_vcpu {
    struct list_head rqd_elem;  /* On the runqueue data list */
    struct list_head sdom_elem; /* On the domain vcpu list */
    struct list_head runq_elem; /* On the runqueue         */
    struct csched2_runqueue_data *rqd; /* Up-pointer to the runqueue */

    /* Up-pointers */
    struct csched2_dom *sdom;
    struct vcpu *vcpu;

    unsigned int weight;
    unsigned int residual;

    int credit;
    s_time_t start_time; /* When we were scheduled (used for credit) */
    unsigned flags;      /* 16 bits doesn't seem to play well with clear_bit() */

    /* Individual contribution to load */
    s_time_t load_last_update;  /* Last time average was updated */
    s_time_t avgload;           /* Decaying queue load */

    struct csched2_runqueue_data *migrate_rqd; /* Pre-determined rqd to which to migrate */
};

/*
 * Domain
 */
struct csched2_dom {
    struct list_head vcpu;
    struct list_head sdom_elem;
    struct domain *dom;
    uint16_t weight;
    uint16_t nr_vcpus;
};


/*
 * Time-to-credit, credit-to-time.
 * 
 * We keep track of the "residual" time to make sure that frequent short
 * schedules still get accounted for in the end.
 *
 * FIXME: Do pre-calculated division?
 */
static void t2c_update(struct csched2_runqueue_data *rqd, s_time_t time,
                          struct csched2_vcpu *svc)
{
    uint64_t val = time * rqd->max_weight + svc->residual;

    svc->residual = do_div(val, svc->weight);
    svc->credit -= val;
}

static s_time_t c2t(struct csched2_runqueue_data *rqd, s_time_t credit, struct csched2_vcpu *svc)
{
    return credit * svc->weight / rqd->max_weight;
}

/*
 * Runqueue related code
 */

static /*inline*/ int
__vcpu_on_runq(struct csched2_vcpu *svc)
{
    return !list_empty(&svc->runq_elem);
}

static /*inline*/ struct csched2_vcpu *
__runq_elem(struct list_head *elem)
{
    return list_entry(elem, struct csched2_vcpu, runq_elem);
}

static void
__update_runq_load(const struct scheduler *ops,
                  struct csched2_runqueue_data *rqd, int change, s_time_t now)
{
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    s_time_t delta=-1;

    now >>= LOADAVG_GRANULARITY_SHIFT;

    if ( rqd->load_last_update + (1ULL<<prv->load_window_shift) < now )
    {
        rqd->avgload = (unsigned long long)rqd->load << prv->load_window_shift;
        rqd->b_avgload = (unsigned long long)rqd->load << prv->load_window_shift;
    }
    else
    {
        delta = now - rqd->load_last_update;

        rqd->avgload =
            ( ( delta * ( (unsigned long long)rqd->load << prv->load_window_shift ) )
              + ( ((1ULL<<prv->load_window_shift) - delta) * rqd->avgload ) ) >> prv->load_window_shift;

        rqd->b_avgload =
            ( ( delta * ( (unsigned long long)rqd->load << prv->load_window_shift ) )
              + ( ((1ULL<<prv->load_window_shift) - delta) * rqd->b_avgload ) ) >> prv->load_window_shift;
    }
    rqd->load += change;
    rqd->load_last_update = now;

    {
        struct {
            unsigned rq_load:4, rq_avgload:28;
            unsigned rq_id:4, b_avgload:28;
        } d;
        d.rq_id=rqd->id;
        d.rq_load = rqd->load;
        d.rq_avgload = rqd->avgload;
        d.b_avgload = rqd->b_avgload;
        trace_var(TRC_CSCHED2_UPDATE_RUNQ_LOAD, 1,
                  sizeof(d),
                  (unsigned char *)&d);
    }
}

static void
__update_svc_load(const struct scheduler *ops,
                  struct csched2_vcpu *svc, int change, s_time_t now)
{
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    s_time_t delta=-1;
    int vcpu_load;

    if ( change == -1 )
        vcpu_load = 1;
    else if ( change == 1 )
        vcpu_load = 0;
    else
        vcpu_load = vcpu_runnable(svc->vcpu);

    now >>= LOADAVG_GRANULARITY_SHIFT;

    if ( svc->load_last_update + (1ULL<<prv->load_window_shift) < now )
    {
        svc->avgload = (unsigned long long)vcpu_load << prv->load_window_shift;
    }
    else
    {
        delta = now - svc->load_last_update;

        svc->avgload =
            ( ( delta * ( (unsigned long long)vcpu_load << prv->load_window_shift ) )
              + ( ((1ULL<<prv->load_window_shift) - delta) * svc->avgload ) ) >> prv->load_window_shift;
    }
    svc->load_last_update = now;

    {
        struct {
            unsigned dom:16,vcpu:16;
            unsigned v_avgload:32;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.v_avgload = svc->avgload;
        trace_var(TRC_CSCHED2_UPDATE_VCPU_LOAD, 1,
                  sizeof(d),
                  (unsigned char *)&d);
    }
}

static void
update_load(const struct scheduler *ops,
            struct csched2_runqueue_data *rqd,
            struct csched2_vcpu *svc, int change, s_time_t now)
{
    __update_runq_load(ops, rqd, change, now);
    if ( svc )
        __update_svc_load(ops, svc, change, now);
}

static int
__runq_insert(struct list_head *runq, struct csched2_vcpu *svc)
{
    struct list_head *iter;
    int pos = 0;

    d2printk("rqi %pv\n", svc->vcpu);

    BUG_ON(&svc->rqd->runq != runq);
    /* Idle vcpus not allowed on the runqueue anymore */
    BUG_ON(is_idle_vcpu(svc->vcpu));
    BUG_ON(svc->vcpu->is_running);
    BUG_ON(test_bit(__CSFLAG_scheduled, &svc->flags));

    list_for_each( iter, runq )
    {
        struct csched2_vcpu * iter_svc = __runq_elem(iter);

        if ( svc->credit > iter_svc->credit )
        {
            d2printk(" p%d %pv\n", pos, iter_svc->vcpu);
            break;
        }
        pos++;
    }

    list_add_tail(&svc->runq_elem, iter);

    return pos;
}

static void
runq_insert(const struct scheduler *ops, unsigned int cpu, struct csched2_vcpu *svc)
{
    struct list_head * runq = &RQD(ops, cpu)->runq;
    int pos = 0;

    ASSERT( spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock) );

    BUG_ON( __vcpu_on_runq(svc) );
    BUG_ON( c2r(ops, cpu) != c2r(ops, svc->vcpu->processor) );

    pos = __runq_insert(runq, svc);

    {
        struct {
            unsigned dom:16,vcpu:16;
            unsigned pos;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.pos = pos;
        trace_var(TRC_CSCHED2_RUNQ_POS, 0,
                  sizeof(d),
                  (unsigned char *)&d);
    }

    return;
}

static inline void
__runq_remove(struct csched2_vcpu *svc)
{
    BUG_ON( !__vcpu_on_runq(svc) );
    list_del_init(&svc->runq_elem);
}

void burn_credits(struct csched2_runqueue_data *rqd, struct csched2_vcpu *, s_time_t);

/* Check to see if the item on the runqueue is higher priority than what's
 * currently running; if so, wake up the processor */
static /*inline*/ void
runq_tickle(const struct scheduler *ops, unsigned int cpu, struct csched2_vcpu *new, s_time_t now)
{
    int i, ipid=-1;
    s_time_t lowest=(1<<30);
    struct csched2_runqueue_data *rqd = RQD(ops, cpu);
    cpumask_t mask;
    struct csched2_vcpu * cur;

    d2printk("rqt %pv curr %pv\n", new->vcpu, current);

    BUG_ON(new->vcpu->processor != cpu);
    BUG_ON(new->rqd != rqd);

    /* Look at the cpu it's running on first */
    cur = CSCHED2_VCPU(per_cpu(schedule_data, cpu).curr);
    burn_credits(rqd, cur, now);

    if ( cur->credit < new->credit )
    {
        ipid = cpu;
        goto tickle;
    }
    
    /* Get a mask of idle, but not tickled */
    cpumask_andnot(&mask, &rqd->idle, &rqd->tickled);
    
    /* If it's not empty, choose one */
    i = cpumask_cycle(cpu, &mask);
    if ( i < nr_cpu_ids )
    {
        ipid = i;
        goto tickle;
    }

    /* Otherwise, look for the non-idle cpu with the lowest credit,
     * skipping cpus which have been tickled but not scheduled yet */
    cpumask_andnot(&mask, &rqd->active, &rqd->idle);
    cpumask_andnot(&mask, &mask, &rqd->tickled);

    for_each_cpu(i, &mask)
    {
        struct csched2_vcpu * cur;

        /* Already looked at this one above */
        if ( i == cpu )
            continue;

        cur = CSCHED2_VCPU(per_cpu(schedule_data, i).curr);

        BUG_ON(is_idle_vcpu(cur->vcpu));

        /* Update credits for current to see if we want to preempt */
        burn_credits(rqd, cur, now);

        if ( cur->credit < lowest )
        {
            ipid = i;
            lowest = cur->credit;
        }

        /* TRACE */ {
            struct {
                unsigned dom:16,vcpu:16;
                unsigned credit;
            } d;
            d.dom = cur->vcpu->domain->domain_id;
            d.vcpu = cur->vcpu->vcpu_id;
            d.credit = cur->credit;
            trace_var(TRC_CSCHED2_TICKLE_CHECK, 1,
                      sizeof(d),
                      (unsigned char *)&d);
        }
    }

    /* Only switch to another processor if the credit difference is greater
     * than the migrate resistance */
    if ( ipid == -1 || lowest + CSCHED2_MIGRATE_RESIST > new->credit )
        goto no_tickle;

tickle:
    BUG_ON(ipid == -1);

    /* TRACE */ {
        struct {
            unsigned cpu:8;
        } d;
        d.cpu = ipid;
        trace_var(TRC_CSCHED2_TICKLE, 0,
                  sizeof(d),
                  (unsigned char *)&d);
    }
    cpumask_set_cpu(ipid, &rqd->tickled);
    cpu_raise_softirq(ipid, SCHEDULE_SOFTIRQ);

no_tickle:
    return;
}

/*
 * Credit-related code
 */
static void reset_credit(const struct scheduler *ops, int cpu, s_time_t now,
                         struct csched2_vcpu *snext)
{
    struct csched2_runqueue_data *rqd = RQD(ops, cpu);
    struct list_head *iter;
    int m;

    /*
     * Under normal circumstances, snext->credit should never be less
     * than -CSCHED2_MIN_TIMER.  However, under some circumstances, a
     * vcpu with low credits may be allowed to run long enough that
     * its credits are actually less than -CSCHED2_CREDIT_INIT.
     * (Instances have been observed, for example, where a vcpu with
     * 200us of credit was allowed to run for 11ms, giving it -10.8ms
     * of credit.  Thus it was still negative even after the reset.)
     *
     * If this is the case for snext, we simply want to keep moving
     * everyone up until it is in the black again.  This fair because
     * none of the other vcpus want to run at the moment.
     *
     * Rather than looping, however, we just calculate a multiplier,
     * avoiding an integer division and multiplication in the common
     * case.
     */
    m = 1;
    if ( snext->credit < -CSCHED2_CREDIT_INIT )
        m += (-snext->credit) / CSCHED2_CREDIT_INIT;

    list_for_each( iter, &rqd->svc )
    {
        struct csched2_vcpu * svc;
        int start_credit;

        svc = list_entry(iter, struct csched2_vcpu, rqd_elem);

        BUG_ON( is_idle_vcpu(svc->vcpu) );
        BUG_ON( svc->rqd != rqd );

        start_credit = svc->credit;

        /* And add INIT * m, avoiding integer multiplication in the
         * common case. */
        if ( likely(m==1) )
            svc->credit += CSCHED2_CREDIT_INIT;
        else
            svc->credit += m * CSCHED2_CREDIT_INIT;

        /* "Clip" credits to max carryover */
        if ( svc->credit > CSCHED2_CREDIT_INIT + CSCHED2_CARRYOVER_MAX )
            svc->credit = CSCHED2_CREDIT_INIT + CSCHED2_CARRYOVER_MAX;

        svc->start_time = now;

        /* TRACE */ {
            struct {
                unsigned dom:16,vcpu:16;
                unsigned credit_start, credit_end;
                unsigned multiplier;
            } d;
            d.dom = svc->vcpu->domain->domain_id;
            d.vcpu = svc->vcpu->vcpu_id;
            d.credit_start = start_credit;
            d.credit_end = svc->credit;
            d.multiplier = m;
            trace_var(TRC_CSCHED2_CREDIT_RESET, 1,
                      sizeof(d),
                      (unsigned char *)&d);
        }
    }

    /* No need to resort runqueue, as everyone's order should be the same. */
}

void burn_credits(struct csched2_runqueue_data *rqd, struct csched2_vcpu *svc, s_time_t now)
{
    s_time_t delta;

    /* Assert svc is current */
    ASSERT(svc==CSCHED2_VCPU(per_cpu(schedule_data, svc->vcpu->processor).curr));

    if ( is_idle_vcpu(svc->vcpu) )
    {
        BUG_ON(svc->credit != CSCHED2_IDLE_CREDIT);
        return;
    }

    delta = now - svc->start_time;

    if ( delta > 0 ) {
        t2c_update(rqd, delta, svc);
        svc->start_time = now;

        d2printk("b %pv c%d\n", svc->vcpu, svc->credit);
    } else {
        d2printk("%s: Time went backwards? now %"PRI_stime" start %"PRI_stime"\n",
               __func__, now, svc->start_time);
    }

    /* TRACE */
    {
        struct {
            unsigned dom:16,vcpu:16;
            unsigned credit;
            int delta;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.credit = svc->credit;
        d.delta = delta;
        trace_var(TRC_CSCHED2_CREDIT_BURN, 1,
                  sizeof(d),
                  (unsigned char *)&d);
    }
}

/* Find the domain with the highest weight. */
static void update_max_weight(struct csched2_runqueue_data *rqd, int new_weight,
                              int old_weight)
{
    /* Try to avoid brute-force search:
     * - If new_weight is larger, max_weigth <- new_weight
     * - If old_weight != max_weight, someone else is still max_weight
     *   (No action required)
     * - If old_weight == max_weight, brute-force search for max weight
     */
    if ( new_weight > rqd->max_weight )
    {
        rqd->max_weight = new_weight;
        d2printk("%s: Runqueue id %d max weight %d\n", __func__, rqd->id, rqd->max_weight);
    }
    else if ( old_weight == rqd->max_weight )
    {
        struct list_head *iter;
        int max_weight = 1;

        list_for_each( iter, &rqd->svc )
        {
            struct csched2_vcpu * svc = list_entry(iter, struct csched2_vcpu, rqd_elem);

            if ( svc->weight > max_weight )
                max_weight = svc->weight;
        }

        rqd->max_weight = max_weight;
        d2printk("%s: Runqueue %d max weight %d\n", __func__, rqd->id, rqd->max_weight);
    }
}

#ifndef NDEBUG
static /*inline*/ void
__csched2_vcpu_check(struct vcpu *vc)
{
    struct csched2_vcpu * const svc = CSCHED2_VCPU(vc);
    struct csched2_dom * const sdom = svc->sdom;

    BUG_ON( svc->vcpu != vc );
    BUG_ON( sdom != CSCHED2_DOM(vc->domain) );
    if ( sdom )
    {
        BUG_ON( is_idle_vcpu(vc) );
        BUG_ON( sdom->dom != vc->domain );
    }
    else
    {
        BUG_ON( !is_idle_vcpu(vc) );
    }
}
#define CSCHED2_VCPU_CHECK(_vc)  (__csched2_vcpu_check(_vc))
#else
#define CSCHED2_VCPU_CHECK(_vc)
#endif

static void *
csched2_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct csched2_vcpu *svc;

    /* Allocate per-VCPU info */
    svc = xzalloc(struct csched2_vcpu);
    if ( svc == NULL )
        return NULL;

    INIT_LIST_HEAD(&svc->rqd_elem);
    INIT_LIST_HEAD(&svc->sdom_elem);
    INIT_LIST_HEAD(&svc->runq_elem);

    svc->sdom = dd;
    svc->vcpu = vc;
    svc->flags = 0U;

    if ( ! is_idle_vcpu(vc) )
    {
        BUG_ON( svc->sdom == NULL );

        svc->credit = CSCHED2_CREDIT_INIT;
        svc->weight = svc->sdom->weight;
        /* Starting load of 50% */
        svc->avgload = 1ULL << (CSCHED2_PRIV(ops)->load_window_shift - 1);
        svc->load_last_update = NOW();
    }
    else
    {
        BUG_ON( svc->sdom != NULL );
        svc->credit = CSCHED2_IDLE_CREDIT;
        svc->weight = 0;
    }

    SCHED_STAT_CRANK(vcpu_init);

    return svc;
}

/* Add and remove from runqueue assignment (not active run queue) */
static void
__runq_assign(struct csched2_vcpu *svc, struct csched2_runqueue_data *rqd)
{

    svc->rqd = rqd;
    list_add_tail(&svc->rqd_elem, &svc->rqd->svc);

    update_max_weight(svc->rqd, svc->weight, 0);

    /* Expected new load based on adding this vcpu */
    rqd->b_avgload += svc->avgload;

    /* TRACE */
    {
        struct {
            unsigned dom:16,vcpu:16;
            unsigned rqi:16;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.rqi=rqd->id;
        trace_var(TRC_CSCHED2_RUNQ_ASSIGN, 1,
                  sizeof(d),
                  (unsigned char *)&d);
    }

}

static void
runq_assign(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu *svc = vc->sched_priv;

    BUG_ON(svc->rqd != NULL);

    __runq_assign(svc, RQD(ops, vc->processor));
}

static void
__runq_deassign(struct csched2_vcpu *svc)
{
    BUG_ON(__vcpu_on_runq(svc));
    BUG_ON(test_bit(__CSFLAG_scheduled, &svc->flags));

    list_del_init(&svc->rqd_elem);
    update_max_weight(svc->rqd, 0, svc->weight);

    /* Expected new load based on removing this vcpu */
    svc->rqd->b_avgload -= svc->avgload;

    svc->rqd = NULL;
}

static void
runq_deassign(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu *svc = vc->sched_priv;

    BUG_ON(svc->rqd != RQD(ops, vc->processor));

    __runq_deassign(svc);
}

static void
csched2_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu *svc = vc->sched_priv;
    struct csched2_dom * const sdom = svc->sdom;

    printk("%s: Inserting %pv\n", __func__, vc);

    /* NB: On boot, idle vcpus are inserted before alloc_pdata() has
     * been called for that cpu.
     */
    if ( ! is_idle_vcpu(vc) )
    {
        spinlock_t *lock;

        /* FIXME: Do we need the private lock here? */
        list_add_tail(&svc->sdom_elem, &svc->sdom->vcpu);

        /* Add vcpu to runqueue of initial processor */
        lock = vcpu_schedule_lock_irq(vc);

        runq_assign(ops, vc);

        vcpu_schedule_unlock_irq(lock, vc);

        sdom->nr_vcpus++;
    }

    CSCHED2_VCPU_CHECK(vc);
}

static void
csched2_free_vdata(const struct scheduler *ops, void *priv)
{
    struct csched2_vcpu *svc = priv;

    xfree(svc);
}

static void
csched2_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = CSCHED2_VCPU(vc);
    struct csched2_dom * const sdom = svc->sdom;

    BUG_ON( sdom == NULL );
    BUG_ON( !list_empty(&svc->runq_elem) );

    if ( ! is_idle_vcpu(vc) )
    {
        spinlock_t *lock;

        SCHED_STAT_CRANK(vcpu_destroy);

        /* Remove from runqueue */
        lock = vcpu_schedule_lock_irq(vc);

        runq_deassign(ops, vc);

        vcpu_schedule_unlock_irq(lock, vc);

        /* Remove from sdom list.  Don't need a lock for this, as it's called
         * syncronously when nothing else can happen. */
        list_del_init(&svc->sdom_elem);

        svc->sdom->nr_vcpus--;
    }
}

static void
csched2_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = CSCHED2_VCPU(vc);

    BUG_ON( is_idle_vcpu(vc) );

    if ( per_cpu(schedule_data, vc->processor).curr == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
    else if ( __vcpu_on_runq(svc) )
    {
        BUG_ON(svc->rqd != RQD(ops, vc->processor));
        update_load(ops, svc->rqd, svc, -1, NOW());
        __runq_remove(svc);
    }
    else if ( test_bit(__CSFLAG_delayed_runq_add, &svc->flags) )
        clear_bit(__CSFLAG_delayed_runq_add, &svc->flags);
}

static void
csched2_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = CSCHED2_VCPU(vc);
    s_time_t now = 0;

    /* Schedule lock should be held at this point. */

    d2printk("w %pv\n", vc);

    BUG_ON( is_idle_vcpu(vc) );

    /* Make sure svc priority mod happens before runq check */
    if ( unlikely(per_cpu(schedule_data, vc->processor).curr == vc) )
    {
        goto out;
    }

    if ( unlikely(__vcpu_on_runq(svc)) )
    {
        /* If we've boosted someone that's already on a runqueue, prioritize
         * it and inform the cpu in question. */
        goto out;
    }

    /* If the context hasn't been saved for this vcpu yet, we can't put it on
     * another runqueue.  Instead, we set a flag so that it will be put on the runqueue
     * after the context has been saved. */
    if ( unlikely (test_bit(__CSFLAG_scheduled, &svc->flags) ) )
    {
        set_bit(__CSFLAG_delayed_runq_add, &svc->flags);
        goto out;
    }

    /* Add into the new runqueue if necessary */
    if ( svc->rqd == NULL )
        runq_assign(ops, vc);
    else
        BUG_ON(RQD(ops, vc->processor) != svc->rqd );

    now = NOW();

    update_load(ops, svc->rqd, svc, 1, now);
        
    /* Put the VCPU on the runq */
    runq_insert(ops, vc->processor, svc);
    runq_tickle(ops, vc->processor, svc, now);

out:
    d2printk("w-\n");
    return;
}

static void
csched2_context_saved(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = CSCHED2_VCPU(vc);
    s_time_t now = NOW();
    spinlock_t *lock = vcpu_schedule_lock_irq(vc);

    BUG_ON( !is_idle_vcpu(vc) && svc->rqd != RQD(ops, vc->processor));

    /* This vcpu is now eligible to be put on the runqueue again */
    clear_bit(__CSFLAG_scheduled, &svc->flags);

    /* If someone wants it on the runqueue, put it there. */
    /*
     * NB: We can get rid of CSFLAG_scheduled by checking for
     * vc->is_running and __vcpu_on_runq(svc) here.  However,
     * since we're accessing the flags cacheline anyway,
     * it seems a bit pointless; especially as we have plenty of
     * bits free.
     */
    if ( test_and_clear_bit(__CSFLAG_delayed_runq_add, &svc->flags)
         && likely(vcpu_runnable(vc)) )
    {
        BUG_ON(__vcpu_on_runq(svc));

        runq_insert(ops, vc->processor, svc);
        runq_tickle(ops, vc->processor, svc, now);
    }
    else if ( !is_idle_vcpu(vc) )
        update_load(ops, svc->rqd, svc, -1, now);

    vcpu_schedule_unlock_irq(lock, vc);
}

#define MAX_LOAD (1ULL<<60);
static int
choose_cpu(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    int i, min_rqi = -1, new_cpu;
    struct csched2_vcpu *svc = CSCHED2_VCPU(vc);
    s_time_t min_avgload;

    BUG_ON(cpumask_empty(&prv->active_queues));

    /* Locking:
     * - vc->processor is already locked
     * - Need to grab prv lock to make sure active runqueues don't
     *   change
     * - Need to grab locks for other runqueues while checking
     *   avgload
     * Locking constraint is:
     * - Lock prv before runqueue locks
     * - Trylock between runqueue locks (no ordering)
     *
     * Since one of the runqueue locks is already held, we can't
     * just grab the prv lock.  Instead, we'll have to trylock, and
     * do something else reasonable if we fail.
     */

    if ( !spin_trylock(&prv->lock) )
    {
        if ( test_and_clear_bit(__CSFLAG_runq_migrate_request, &svc->flags) )
        {
            d2printk("%pv -\n", svc->vcpu);
            clear_bit(__CSFLAG_runq_migrate_request, &svc->flags);
        }
        /* Leave it where it is for now.  When we actually pay attention
         * to affinity we'll have to figure something out... */
        return vc->processor;
    }

    /* First check to see if we're here because someone else suggested a place
     * for us to move. */
    if ( test_and_clear_bit(__CSFLAG_runq_migrate_request, &svc->flags) )
    {
        if ( unlikely(svc->migrate_rqd->id < 0) )
        {
            printk("%s: Runqueue migrate aborted because target runqueue disappeared!\n",
                   __func__);
            /* Fall-through to normal cpu pick */
        }
        else
        {
            d2printk("%pv +\n", svc->vcpu);
            new_cpu = cpumask_cycle(vc->processor, &svc->migrate_rqd->active);
            goto out_up;
        }
    }

    /* FIXME: Pay attention to cpu affinity */                                                                                      

    min_avgload = MAX_LOAD;

    /* Find the runqueue with the lowest instantaneous load */
    for_each_cpu(i, &prv->active_queues)
    {
        struct csched2_runqueue_data *rqd;
        s_time_t rqd_avgload;

        rqd = prv->rqd + i;

        /* If checking a different runqueue, grab the lock,
         * read the avg, and then release the lock.
         *
         * If on our own runqueue, don't grab or release the lock;
         * but subtract our own load from the runqueue load to simulate
         * impartiality */
        if ( rqd == svc->rqd )
        {
            rqd_avgload = rqd->b_avgload - svc->avgload;
        }
        else if ( spin_trylock(&rqd->lock) )
        {
            rqd_avgload = rqd->b_avgload;
            spin_unlock(&rqd->lock);
        }
        else
            continue;

        if ( rqd_avgload < min_avgload )
        {
            min_avgload = rqd_avgload;
            min_rqi=i;
        }
    }

    /* We didn't find anyone (most likely because of spinlock contention); leave it where it is */
    if ( min_rqi == -1 )
        new_cpu = vc->processor;
    else
    {
        new_cpu = cpumask_cycle(vc->processor, &prv->rqd[min_rqi].active);
        BUG_ON(new_cpu >= nr_cpu_ids);
    }

out_up:
    spin_unlock(&prv->lock);

    return new_cpu;
}

/* Working state of the load-balancing algorithm */
typedef struct {
    /* NB: Modified by consider() */
    s_time_t load_delta;
    struct csched2_vcpu * best_push_svc, *best_pull_svc;
    /* NB: Read by consider() */
    struct csched2_runqueue_data *lrqd;
    struct csched2_runqueue_data *orqd;                  
} balance_state_t;

static void consider(balance_state_t *st, 
                     struct csched2_vcpu *push_svc,
                     struct csched2_vcpu *pull_svc)
{
    s_time_t l_load, o_load, delta;

    l_load = st->lrqd->b_avgload;
    o_load = st->orqd->b_avgload;
    if ( push_svc )
    {
        /* What happens to the load on both if we push? */
        l_load -= push_svc->avgload;
        o_load += push_svc->avgload;
    }
    if ( pull_svc )
    {
        /* What happens to the load on both if we pull? */
        l_load += pull_svc->avgload;
        o_load -= pull_svc->avgload;
    }

    delta = l_load - o_load;
    if ( delta < 0 )
        delta = -delta;

    if ( delta < st->load_delta )
    {
        st->load_delta = delta;
        st->best_push_svc=push_svc;
        st->best_pull_svc=pull_svc;
    }
}


static void migrate(const struct scheduler *ops,
                    struct csched2_vcpu *svc, 
                    struct csched2_runqueue_data *trqd, 
                    s_time_t now)
{
    if ( test_bit(__CSFLAG_scheduled, &svc->flags) )
    {
        d2printk("%pv %d-%d a\n", svc->vcpu, svc->rqd->id, trqd->id);
        /* It's running; mark it to migrate. */
        svc->migrate_rqd = trqd;
        set_bit(_VPF_migrating, &svc->vcpu->pause_flags);
        set_bit(__CSFLAG_runq_migrate_request, &svc->flags);
    }
    else
    {
        int on_runq=0;
        /* It's not running; just move it */
        d2printk("%pv %d-%d i\n", svc->vcpu, svc->rqd->id, trqd->id);
        if ( __vcpu_on_runq(svc) )
        {
            __runq_remove(svc);
            update_load(ops, svc->rqd, svc, -1, now);
            on_runq=1;
        }
        __runq_deassign(svc);
        svc->vcpu->processor = cpumask_any(&trqd->active);
        __runq_assign(svc, trqd);
        if ( on_runq )
        {
            update_load(ops, svc->rqd, svc, 1, now);
            runq_insert(ops, svc->vcpu->processor, svc);
            runq_tickle(ops, svc->vcpu->processor, svc, now);
        }
    }
}


static void balance_load(const struct scheduler *ops, int cpu, s_time_t now)
{
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    int i, max_delta_rqi = -1;
    struct list_head *push_iter, *pull_iter;

    balance_state_t st = { .best_push_svc = NULL, .best_pull_svc = NULL };
    
    /*
     * Basic algorithm: Push, pull, or swap.
     * - Find the runqueue with the furthest load distance
     * - Find a pair that makes the difference the least (where one
     * on either side may be empty).
     */

    /* Locking:
     * - pcpu schedule lock should be already locked
     */
    st.lrqd = RQD(ops, cpu);

    __update_runq_load(ops, st.lrqd, 0, now);

retry:
    if ( !spin_trylock(&prv->lock) )
        return;

    st.load_delta = 0;

    for_each_cpu(i, &prv->active_queues)
    {
        s_time_t delta;
        
        st.orqd = prv->rqd + i;

        if ( st.orqd == st.lrqd
             || !spin_trylock(&st.orqd->lock) )
            continue;

        __update_runq_load(ops, st.orqd, 0, now);
    
        delta = st.lrqd->b_avgload - st.orqd->b_avgload;
        if ( delta < 0 )
            delta = -delta;

        if ( delta > st.load_delta )
        {
            st.load_delta = delta;
            max_delta_rqi = i;
        }

        spin_unlock(&st.orqd->lock);
    }

    /* Minimize holding the big lock */
    spin_unlock(&prv->lock);
    if ( max_delta_rqi == -1 )
        goto out;

    {
        s_time_t load_max;
        int cpus_max;

        
        load_max = st.lrqd->b_avgload;
        if ( st.orqd->b_avgload > load_max )
            load_max = st.orqd->b_avgload;

        cpus_max = cpumask_weight(&st.lrqd->active);
        i = cpumask_weight(&st.orqd->active);
        if ( i > cpus_max )
            cpus_max = i;

        /* If we're under 100% capacaty, only shift if load difference
         * is > 1.  otherwise, shift if under 12.5% */
        if ( load_max < (1ULL<<(prv->load_window_shift))*cpus_max )
        {
            if ( st.load_delta < (1ULL<<(prv->load_window_shift+opt_underload_balance_tolerance) ) )
                 goto out;
        }
        else
            if ( st.load_delta < (1ULL<<(prv->load_window_shift+opt_overload_balance_tolerance)) )
                goto out;
    }
             
    /* Try to grab the other runqueue lock; if it's been taken in the
     * meantime, try the process over again.  This can't deadlock
     * because if it doesn't get any other rqd locks, it will simply
     * give up and return. */
    st.orqd = prv->rqd + max_delta_rqi;
    if ( !spin_trylock(&st.orqd->lock) )
        goto retry;

    /* Make sure the runqueue hasn't been deactivated since we released prv->lock */
    if ( unlikely(st.orqd->id < 0) )
        goto out_up;

    /* Look for "swap" which gives the best load average
     * FIXME: O(n^2)! */

    /* Reuse load delta (as we're trying to minimize it) */
    list_for_each( push_iter, &st.lrqd->svc )
    {
        int inner_load_updated = 0;
        struct csched2_vcpu * push_svc = list_entry(push_iter, struct csched2_vcpu, rqd_elem);

        __update_svc_load(ops, push_svc, 0, now);

        /* Skip this one if it's already been flagged to migrate */
        if ( test_bit(__CSFLAG_runq_migrate_request, &push_svc->flags) )
            continue;

        list_for_each( pull_iter, &st.orqd->svc )
        {
            struct csched2_vcpu * pull_svc = list_entry(pull_iter, struct csched2_vcpu, rqd_elem);
            
            if ( ! inner_load_updated )
            {
                __update_svc_load(ops, pull_svc, 0, now);
            }
        
            /* Skip this one if it's already been flagged to migrate */
            if ( test_bit(__CSFLAG_runq_migrate_request, &pull_svc->flags) )
                continue;

            consider(&st, push_svc, pull_svc);
        }

        inner_load_updated = 1;

        /* Consider push only */
        consider(&st, push_svc, NULL);
    }

    list_for_each( pull_iter, &st.orqd->svc )
    {
        struct csched2_vcpu * pull_svc = list_entry(pull_iter, struct csched2_vcpu, rqd_elem);
        
        /* Skip this one if it's already been flagged to migrate */
        if ( test_bit(__CSFLAG_runq_migrate_request, &pull_svc->flags) )
            continue;

        /* Consider pull only */
        consider(&st, NULL, pull_svc);
    }

    /* OK, now we have some candidates; do the moving */
    if ( st.best_push_svc )
        migrate(ops, st.best_push_svc, st.orqd, now);
    if ( st.best_pull_svc )
        migrate(ops, st.best_pull_svc, st.lrqd, now);

out_up:
    spin_unlock(&st.orqd->lock);

out:
    return;
}

static int
csched2_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    int new_cpu;

    new_cpu = choose_cpu(ops, vc);

    return new_cpu;
}

static void
csched2_vcpu_migrate(
    const struct scheduler *ops, struct vcpu *vc, unsigned int new_cpu)
{
    struct csched2_vcpu * const svc = CSCHED2_VCPU(vc);
    struct csched2_runqueue_data *trqd;

    /* Check if new_cpu is valid */
    BUG_ON(!cpumask_test_cpu(new_cpu, &CSCHED2_PRIV(ops)->initialized));

    trqd = RQD(ops, new_cpu);

    if ( trqd != svc->rqd )
        migrate(ops, svc, trqd, NOW());
}

static int
csched2_dom_cntl(
    const struct scheduler *ops,
    struct domain *d,
    struct xen_domctl_scheduler_op *op)
{
    struct csched2_dom * const sdom = CSCHED2_DOM(d);
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    unsigned long flags;

    /* Must hold csched2_priv lock to read and update sdom,
     * runq lock to update csvcs. */
    spin_lock_irqsave(&prv->lock, flags);

    if ( op->cmd == XEN_DOMCTL_SCHEDOP_getinfo )
    {
        op->u.credit2.weight = sdom->weight;
    }
    else
    {
        ASSERT(op->cmd == XEN_DOMCTL_SCHEDOP_putinfo);

        if ( op->u.credit2.weight != 0 )
        {
            struct list_head *iter;
            int old_weight;

            old_weight = sdom->weight;

            sdom->weight = op->u.credit2.weight;

            /* Update weights for vcpus, and max_weight for runqueues on which they reside */
            list_for_each ( iter, &sdom->vcpu )
            {
                struct csched2_vcpu *svc = list_entry(iter, struct csched2_vcpu, sdom_elem);

                /* NB: Locking order is important here.  Because we grab this lock here, we
                 * must never lock csched2_priv.lock if we're holding a runqueue lock.
                 * Also, calling vcpu_schedule_lock() is enough, since IRQs have already
                 * been disabled. */
                spinlock_t *lock = vcpu_schedule_lock(svc->vcpu);

                BUG_ON(svc->rqd != RQD(ops, svc->vcpu->processor));

                svc->weight = sdom->weight;
                update_max_weight(svc->rqd, svc->weight, old_weight);

                vcpu_schedule_unlock(lock, svc->vcpu);
            }
        }
    }

    spin_unlock_irqrestore(&prv->lock, flags);

    return 0;
}

static void *
csched2_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct csched2_dom *sdom;
    unsigned long flags;

    sdom = xzalloc(struct csched2_dom);
    if ( sdom == NULL )
        return NULL;

    /* Initialize credit and weight */
    INIT_LIST_HEAD(&sdom->vcpu);
    INIT_LIST_HEAD(&sdom->sdom_elem);
    sdom->dom = dom;
    sdom->weight = CSCHED2_DEFAULT_WEIGHT;
    sdom->nr_vcpus = 0;

    spin_lock_irqsave(&CSCHED2_PRIV(ops)->lock, flags);

    list_add_tail(&sdom->sdom_elem, &CSCHED2_PRIV(ops)->sdom);

    spin_unlock_irqrestore(&CSCHED2_PRIV(ops)->lock, flags);

    return (void *)sdom;
}

static int
csched2_dom_init(const struct scheduler *ops, struct domain *dom)
{
    struct csched2_dom *sdom;

    printk("%s: Initializing domain %d\n", __func__, dom->domain_id);

    if ( is_idle_domain(dom) )
        return 0;

    sdom = csched2_alloc_domdata(ops, dom);
    if ( sdom == NULL )
        return -ENOMEM;

    dom->sched_priv = sdom;

    return 0;
}

static void
csched2_free_domdata(const struct scheduler *ops, void *data)
{
    unsigned long flags;
    struct csched2_dom *sdom = data;

    spin_lock_irqsave(&CSCHED2_PRIV(ops)->lock, flags);

    list_del_init(&sdom->sdom_elem);

    spin_unlock_irqrestore(&CSCHED2_PRIV(ops)->lock, flags);

    xfree(data);
}

static void
csched2_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    struct csched2_dom *sdom = CSCHED2_DOM(dom);

    BUG_ON(!list_empty(&sdom->vcpu));

    csched2_free_domdata(ops, CSCHED2_DOM(dom));
}

/* How long should we let this vcpu run for? */
static s_time_t
csched2_runtime(const struct scheduler *ops, int cpu, struct csched2_vcpu *snext)
{
    s_time_t time; 
    int rt_credit; /* Proposed runtime measured in credits */
    struct csched2_runqueue_data *rqd = RQD(ops, cpu);
    struct list_head *runq = &rqd->runq;

    if ( is_idle_vcpu(snext->vcpu) )
        return CSCHED2_MAX_TIMER;

    /* General algorithm:
     * 1) Run until snext's credit will be 0
     * 2) But if someone is waiting, run until snext's credit is equal
     * to his
     * 3) But never run longer than MAX_TIMER or shorter than MIN_TIMER.
     */

    /* 1) Basic time: Run until credit is 0. */
    rt_credit = snext->credit;

    /* 2) If there's someone waiting whose credit is positive,
     * run until your credit ~= his */
    if ( ! list_empty(runq) )
    {
        struct csched2_vcpu *swait = __runq_elem(runq->next);

        if ( ! is_idle_vcpu(swait->vcpu)
             && swait->credit > 0 )
        {
            rt_credit = snext->credit - swait->credit;
        }
    }

    /* The next guy may actually have a higher credit, if we've tried to
     * avoid migrating him from a different cpu.  DTRT.  */
    if ( rt_credit <= 0 )
        time = CSCHED2_MIN_TIMER;
    else
    {
        /* FIXME: See if we can eliminate this conversion if we know time
         * will be outside (MIN,MAX).  Probably requires pre-calculating
         * credit values of MIN,MAX per vcpu, since each vcpu burns credit
         * at a different rate. */
        time = c2t(rqd, rt_credit, snext);

        /* Check limits */
        if ( time < CSCHED2_MIN_TIMER )
            time = CSCHED2_MIN_TIMER;
        else if ( time > CSCHED2_MAX_TIMER )
            time = CSCHED2_MAX_TIMER;
    }

    return time;
}

void __dump_execstate(void *unused);

/*
 * Find a candidate.
 */
static struct csched2_vcpu *
runq_candidate(struct csched2_runqueue_data *rqd,
               struct csched2_vcpu *scurr,
               int cpu, s_time_t now)
{
    struct list_head *iter;
    struct csched2_vcpu *snext = NULL;

    /* Default to current if runnable, idle otherwise */
    if ( vcpu_runnable(scurr->vcpu) )
        snext = scurr;
    else
        snext = CSCHED2_VCPU(idle_vcpu[cpu]);

    list_for_each( iter, &rqd->runq )
    {
        struct csched2_vcpu * svc = list_entry(iter, struct csched2_vcpu, runq_elem);

        /* If this is on a different processor, don't pull it unless
         * its credit is at least CSCHED2_MIGRATE_RESIST higher. */
        if ( svc->vcpu->processor != cpu
             && snext->credit + CSCHED2_MIGRATE_RESIST > svc->credit )
            continue;

        /* If the next one on the list has more credit than current
         * (or idle, if current is not runnable), choose it. */
        if ( svc->credit > snext->credit )
            snext = svc;

        /* In any case, if we got this far, break. */
        break;

    }

    return snext;
}

/*
 * This function is in the critical path. It is designed to be simple and
 * fast for the common case.
 */
static struct task_slice
csched2_schedule(
    const struct scheduler *ops, s_time_t now, bool_t tasklet_work_scheduled)
{
    const int cpu = smp_processor_id();
    struct csched2_runqueue_data *rqd;
    struct csched2_vcpu * const scurr = CSCHED2_VCPU(current);
    struct csched2_vcpu *snext = NULL;
    struct task_slice ret;

    SCHED_STAT_CRANK(schedule);
    CSCHED2_VCPU_CHECK(current);

    d2printk("sc p%d c %pv now %"PRI_stime"\n", cpu, scurr->vcpu, now);

    BUG_ON(!cpumask_test_cpu(cpu, &CSCHED2_PRIV(ops)->initialized));

    rqd = RQD(ops, cpu);
    BUG_ON(!cpumask_test_cpu(cpu, &rqd->active));

    /* Protected by runqueue lock */        

    /* DEBUG */
    if ( !is_idle_vcpu(scurr->vcpu) && scurr->rqd != rqd)
    {
        int other_rqi = -1, this_rqi = c2r(ops, cpu);

        if ( scurr->rqd )
        {
            int rq;
            other_rqi = -2;
            for_each_cpu ( rq, &CSCHED2_PRIV(ops)->active_queues )
            {
                if ( scurr->rqd == &CSCHED2_PRIV(ops)->rqd[rq] )
                {
                    other_rqi = rq;
                    break;
                }
            }
        }
        printk("%s: pcpu %d rq %d, but scurr %pv assigned to "
               "pcpu %d rq %d!\n",
               __func__,
               cpu, this_rqi,
               scurr->vcpu, scurr->vcpu->processor, other_rqi);
    }
    BUG_ON(!is_idle_vcpu(scurr->vcpu) && scurr->rqd != rqd);

    /* Clear "tickled" bit now that we've been scheduled */
    if ( cpumask_test_cpu(cpu, &rqd->tickled) )
        cpumask_clear_cpu(cpu, &rqd->tickled);

    /* Update credits */
    burn_credits(rqd, scurr, now);

    /*
     * Select next runnable local VCPU (ie top of local runq).
     *
     * If the current vcpu is runnable, and has higher credit than
     * the next guy on the queue (or there is noone else), we want to
     * run him again.
     *
     * If there's tasklet work to do, we want to chose the idle vcpu
     * for this processor, and mark the current for delayed runqueue
     * add.
     *
     * If the current vcpu is runnable, and there's another runnable
     * candidate, we want to mark current for delayed runqueue add,
     * and remove the next guy from the queue.
     *
     * If the current vcpu is not runnable, we want to chose the idle
     * vcpu for this processor.
     */
    if ( tasklet_work_scheduled )
    {
        trace_var(TRC_CSCHED2_SCHED_TASKLET, 0, 0,  NULL);
        snext = CSCHED2_VCPU(idle_vcpu[cpu]);
    }
    else
        snext=runq_candidate(rqd, scurr, cpu, now);

    /* If switching from a non-idle runnable vcpu, put it
     * back on the runqueue. */
    if ( snext != scurr
         && !is_idle_vcpu(scurr->vcpu)
         && vcpu_runnable(current) )
        set_bit(__CSFLAG_delayed_runq_add, &scurr->flags);

    ret.migrated = 0;

    /* Accounting for non-idle tasks */
    if ( !is_idle_vcpu(snext->vcpu) )
    {
        /* If switching, remove this from the runqueue and mark it scheduled */
        if ( snext != scurr )
        {
            BUG_ON(snext->rqd != rqd);
    
            __runq_remove(snext);
            if ( snext->vcpu->is_running )
            {
                printk("p%d: snext %pv running on p%d! scurr %pv\n",
                       cpu, snext->vcpu, snext->vcpu->processor, scurr->vcpu);
                BUG();
            }
            set_bit(__CSFLAG_scheduled, &snext->flags);
        }

        /* Check for the reset condition */
        if ( snext->credit <= CSCHED2_CREDIT_RESET )
        {
            reset_credit(ops, cpu, now, snext);
            balance_load(ops, cpu, now);
        }

        /* Clear the idle mask if necessary */
        if ( cpumask_test_cpu(cpu, &rqd->idle) )
            cpumask_clear_cpu(cpu, &rqd->idle);

        snext->start_time = now;

        /* Safe because lock for old processor is held */
        if ( snext->vcpu->processor != cpu )
        {
            snext->credit += CSCHED2_MIGRATE_COMPENSATION;
            snext->vcpu->processor = cpu;
            ret.migrated = 1;
        }
    }
    else
    {
        /* Update the idle mask if necessary */
        if ( !cpumask_test_cpu(cpu, &rqd->idle) )
            cpumask_set_cpu(cpu, &rqd->idle);
        /* Make sure avgload gets updated periodically even
         * if there's no activity */
        update_load(ops, rqd, NULL, 0, now);
    }

    /*
     * Return task to run next...
     */
    ret.time = csched2_runtime(ops, cpu, snext);
    ret.task = snext->vcpu;

    CSCHED2_VCPU_CHECK(ret.task);
    return ret;
}

static void
csched2_dump_vcpu(struct csched2_vcpu *svc)
{
    printk("[%i.%i] flags=%x cpu=%i",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id,
            svc->flags,
            svc->vcpu->processor);

    printk(" credit=%" PRIi32" [w=%u]", svc->credit, svc->weight);

    printk("\n");
}

static void
csched2_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct list_head *runq, *iter;
    struct csched2_vcpu *svc;
    int loop;
    char cpustr[100];

    /* FIXME: Do locking properly for access to runqueue structures */

    runq = &RQD(ops, cpu)->runq;

    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_sibling_mask, cpu));
    printk(" sibling=%s, ", cpustr);
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_core_mask, cpu));
    printk("core=%s\n", cpustr);

    /* current VCPU */
    svc = CSCHED2_VCPU(per_cpu(schedule_data, cpu).curr);
    if ( svc )
    {
        printk("\trun: ");
        csched2_dump_vcpu(svc);
    }

    loop = 0;
    list_for_each( iter, runq )
    {
        svc = __runq_elem(iter);
        if ( svc )
        {
            printk("\t%3d: ", ++loop);
            csched2_dump_vcpu(svc);
        }
    }
}

static void
csched2_dump(const struct scheduler *ops)
{
    struct list_head *iter_sdom, *iter_svc;
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    int i, loop;

    printk("Active queues: %d\n"
           "\tdefault-weight     = %d\n",
           cpumask_weight(&prv->active_queues),
           CSCHED2_DEFAULT_WEIGHT);
    for_each_cpu(i, &prv->active_queues)
    {
        s_time_t fraction;
        
        fraction = prv->rqd[i].avgload * 100 / (1ULL<<prv->load_window_shift);

        printk("Runqueue %d:\n"
               "\tncpus              = %u\n"
               "\tmax_weight         = %d\n"
               "\tinstload           = %d\n"
               "\taveload            = %3"PRI_stime"\n",
               i,
               cpumask_weight(&prv->rqd[i].active),
               prv->rqd[i].max_weight,
               prv->rqd[i].load,
               fraction);

    }
    /* FIXME: Locking! */

    printk("Domain info:\n");
    loop = 0;
    list_for_each( iter_sdom, &prv->sdom )
    {
        struct csched2_dom *sdom;
        sdom = list_entry(iter_sdom, struct csched2_dom, sdom_elem);

       printk("\tDomain: %d w %d v %d\n\t", 
              sdom->dom->domain_id, 
              sdom->weight, 
              sdom->nr_vcpus);

        list_for_each( iter_svc, &sdom->vcpu )
        {
            struct csched2_vcpu *svc;
            svc = list_entry(iter_svc, struct csched2_vcpu, sdom_elem);

            printk("\t%3d: ", ++loop);
            csched2_dump_vcpu(svc);
        }
    }
}

static void activate_runqueue(struct csched2_private *prv, int rqi)
{
    struct csched2_runqueue_data *rqd;

    rqd = prv->rqd + rqi;

    BUG_ON(!cpumask_empty(&rqd->active));

    rqd->max_weight = 1;
    rqd->id = rqi;
    INIT_LIST_HEAD(&rqd->svc);
    INIT_LIST_HEAD(&rqd->runq);
    spin_lock_init(&rqd->lock);

    cpumask_set_cpu(rqi, &prv->active_queues);
}

static void deactivate_runqueue(struct csched2_private *prv, int rqi)
{
    struct csched2_runqueue_data *rqd;

    rqd = prv->rqd + rqi;

    BUG_ON(!cpumask_empty(&rqd->active));
    
    rqd->id = -1;

    cpumask_clear_cpu(rqi, &prv->active_queues);
}

static void init_pcpu(const struct scheduler *ops, int cpu)
{
    int rqi;
    unsigned long flags;
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    struct csched2_runqueue_data *rqd;
    spinlock_t *old_lock;

    spin_lock_irqsave(&prv->lock, flags);

    if ( cpumask_test_cpu(cpu, &prv->initialized) )
    {
        printk("%s: Strange, cpu %d already initialized!\n", __func__, cpu);
        spin_unlock_irqrestore(&prv->lock, flags);
        return;
    }

    /* Figure out which runqueue to put it in */
    rqi = 0;

    /* Figure out which runqueue to put it in */
    /* NB: cpu 0 doesn't get a STARTING callback, so we hard-code it to runqueue 0. */
    if ( cpu == 0 )
        rqi = 0;
    else
        rqi = cpu_to_socket(cpu);

    if ( rqi < 0 )
    {
        printk("%s: cpu_to_socket(%d) returned %d!\n",
               __func__, cpu, rqi);
        BUG();
    }

    rqd=prv->rqd + rqi;

    printk("Adding cpu %d to runqueue %d\n", cpu, rqi);
    if ( ! cpumask_test_cpu(rqi, &prv->active_queues) )
    {
        printk(" First cpu on runqueue, activating\n");
        activate_runqueue(prv, rqi);
    }
    
    /* IRQs already disabled */
    old_lock=pcpu_schedule_lock(cpu);

    /* Move spinlock to new runq lock.  */
    per_cpu(schedule_data, cpu).schedule_lock = &rqd->lock;

    /* Set the runqueue map */
    prv->runq_map[cpu]=rqi;
    
    cpumask_set_cpu(cpu, &rqd->idle);
    cpumask_set_cpu(cpu, &rqd->active);

    /* _Not_ pcpu_schedule_unlock(): per_cpu().schedule_lock changed! */
    spin_unlock(old_lock);

    cpumask_set_cpu(cpu, &prv->initialized);

    spin_unlock_irqrestore(&prv->lock, flags);

    return;
}

static void *
csched2_alloc_pdata(const struct scheduler *ops, int cpu)
{
    /* Check to see if the cpu is online yet */
    /* Note: cpu 0 doesn't get a STARTING callback */
    if ( cpu == 0 || cpu_to_socket(cpu) >= 0 )
        init_pcpu(ops, cpu);
    else
        printk("%s: cpu %d not online yet, deferring initializatgion\n",
               __func__, cpu);

    return (void *)1;
}

static void
csched2_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    unsigned long flags;
    struct csched2_private *prv = CSCHED2_PRIV(ops);
    struct csched2_runqueue_data *rqd;
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    int rqi;

    spin_lock_irqsave(&prv->lock, flags);

    BUG_ON(!cpumask_test_cpu(cpu, &prv->initialized));
    
    /* Find the old runqueue and remove this cpu from it */
    rqi = prv->runq_map[cpu];

    rqd = prv->rqd + rqi;

    /* No need to save IRQs here, they're already disabled */
    spin_lock(&rqd->lock);

    BUG_ON(!cpumask_test_cpu(cpu, &rqd->idle));

    printk("Removing cpu %d from runqueue %d\n", cpu, rqi);

    cpumask_clear_cpu(cpu, &rqd->idle);
    cpumask_clear_cpu(cpu, &rqd->active);

    if ( cpumask_empty(&rqd->active) )
    {
        printk(" No cpus left on runqueue, disabling\n");
        deactivate_runqueue(prv, rqi);
    }

    /* Move spinlock to the original lock.  */
    ASSERT(sd->schedule_lock == &rqd->lock);
    ASSERT(!spin_is_locked(&sd->_lock));
    sd->schedule_lock = &sd->_lock;

    spin_unlock(&rqd->lock);

    cpumask_clear_cpu(cpu, &prv->initialized);

    spin_unlock_irqrestore(&prv->lock, flags);

    return;
}

static int
csched2_cpu_starting(int cpu)
{
    struct scheduler *ops;

    /* Hope this is safe from cpupools switching things around. :-) */
    ops = per_cpu(scheduler, cpu);

    if ( ops->alloc_pdata == csched2_alloc_pdata )
        init_pcpu(ops, cpu);

    return NOTIFY_DONE;
}

static int cpu_credit2_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_STARTING:
        csched2_cpu_starting(cpu);
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_credit2_nfb = {
    .notifier_call = cpu_credit2_callback
};

static int
csched2_global_init(void)
{
    register_cpu_notifier(&cpu_credit2_nfb);
    return 0;
}

static int
csched2_init(struct scheduler *ops)
{
    int i;
    struct csched2_private *prv;

    printk("Initializing Credit2 scheduler\n" \
           " WARNING: This is experimental software in development.\n" \
           " Use at your own risk.\n");

    printk(" load_window_shift: %d\n", opt_load_window_shift);
    printk(" underload_balance_tolerance: %d\n", opt_underload_balance_tolerance);
    printk(" overload_balance_tolerance: %d\n", opt_overload_balance_tolerance);

    if ( opt_load_window_shift < LOADAVG_WINDOW_SHIFT_MIN )
    {
        printk("%s: opt_load_window_shift %d below min %d, resetting\n",
               __func__, opt_load_window_shift, LOADAVG_WINDOW_SHIFT_MIN);
        opt_load_window_shift = LOADAVG_WINDOW_SHIFT_MIN;
    }

    /* Basically no CPU information is available at this point; just
     * set up basic structures, and a callback when the CPU info is
     * available. */

    prv = xzalloc(struct csched2_private);
    if ( prv == NULL )
        return -ENOMEM;
    ops->sched_data = prv;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->sdom);

    /* But un-initialize all runqueues */
    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        prv->runq_map[i] = -1;
        prv->rqd[i].id = -1;
    }

    prv->load_window_shift = opt_load_window_shift;

    return 0;
}

static void
csched2_deinit(const struct scheduler *ops)
{
    struct csched2_private *prv;

    prv = CSCHED2_PRIV(ops);
    if ( prv != NULL )
        xfree(prv);
}


static struct csched2_private _csched2_priv;

const struct scheduler sched_credit2_def = {
    .name           = "SMP Credit Scheduler rev2",
    .opt_name       = "credit2",
    .sched_id       = XEN_SCHEDULER_CREDIT2,
    .sched_data     = &_csched2_priv,

    .init_domain    = csched2_dom_init,
    .destroy_domain = csched2_dom_destroy,

    .insert_vcpu    = csched2_vcpu_insert,
    .remove_vcpu    = csched2_vcpu_remove,

    .sleep          = csched2_vcpu_sleep,
    .wake           = csched2_vcpu_wake,

    .adjust         = csched2_dom_cntl,

    .pick_cpu       = csched2_cpu_pick,
    .migrate        = csched2_vcpu_migrate,
    .do_schedule    = csched2_schedule,
    .context_saved  = csched2_context_saved,

    .dump_cpu_state = csched2_dump_pcpu,
    .dump_settings  = csched2_dump,
    .global_init    = csched2_global_init,
    .init           = csched2_init,
    .deinit         = csched2_deinit,
    .alloc_vdata    = csched2_alloc_vdata,
    .free_vdata     = csched2_free_vdata,
    .alloc_pdata    = csched2_alloc_pdata,
    .free_pdata     = csched2_free_pdata,
    .alloc_domdata  = csched2_alloc_domdata,
    .free_domdata   = csched2_free_domdata,
};
