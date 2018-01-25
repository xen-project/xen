
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
#include <xen/keyhandler.h>

/* Meant only for helping developers during debugging. */
/* #define d2printk printk */
#define d2printk(x...)


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
#define TRC_CSCHED2_TICKLE_NEW       TRC_SCHED_CLASS_EVT(CSCHED2, 13)
#define TRC_CSCHED2_RUNQ_MAX_WEIGHT  TRC_SCHED_CLASS_EVT(CSCHED2, 14)
#define TRC_CSCHED2_MIGRATE          TRC_SCHED_CLASS_EVT(CSCHED2, 15)
#define TRC_CSCHED2_LOAD_CHECK       TRC_SCHED_CLASS_EVT(CSCHED2, 16)
#define TRC_CSCHED2_LOAD_BALANCE     TRC_SCHED_CLASS_EVT(CSCHED2, 17)
#define TRC_CSCHED2_PICKED_CPU       TRC_SCHED_CLASS_EVT(CSCHED2, 19)
#define TRC_CSCHED2_RUNQ_CANDIDATE   TRC_SCHED_CLASS_EVT(CSCHED2, 20)
#define TRC_CSCHED2_SCHEDULE         TRC_SCHED_CLASS_EVT(CSCHED2, 21)
#define TRC_CSCHED2_RATELIMIT        TRC_SCHED_CLASS_EVT(CSCHED2, 22)
#define TRC_CSCHED2_RUNQ_CAND_CHECK  TRC_SCHED_CLASS_EVT(CSCHED2, 23)

/*
 * WARNING: This is still in an experimental phase.  Status and work can be found at the
 * credit2 wiki page:
 *  http://wiki.xen.org/wiki/Credit2_Scheduler_Development
 *
 * TODO:
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
 */

/*
 * Utilization cap:
 *
 * Setting an pCPU utilization cap for a domain means the following:
 *
 * - a domain can have a cap, expressed in terms of % of physical CPU time.
 *   A domain that must not use more than 1/4 of _one_ physical CPU, will
 *   be given a cap of 25%; a domain that must not use more than 1+1/2 of
 *   physical CPU time, will be given a cap of 150%;
 *
 * - caps are per-domain (not per-vCPU). If a domain has only 1 vCPU, and
 *   a 40% cap, that one vCPU will use 40% of one pCPU. If a somain has 4
 *   vCPUs, and a 200% cap, the equivalent of 100% time on 2 pCPUs will be
 *   split among the v vCPUs. How much each of the vCPUs will actually get,
 *   during any given interval of time, is unspecified (as it depends on
 *   various aspects: workload, system load, etc.). For instance, it is
 *   possible that, during a given time interval, 2 vCPUs use 100% each,
 *   and the other two use nothing; while during another time interval,
 *   two vCPUs use 80%, one uses 10% and the other 30%; or that each use
 *   50% (and so on and so forth).
 *
 * For implementing this, we use the following approach:
 *
 * - each domain is given a 'budget', an each domain has a timer, which
 *   replenishes the domain's budget periodically. The budget is the amount
 *   of time the vCPUs of the domain can use every 'period';
 *
 * - the period is CSCHED2_BDGT_REPL_PERIOD, and is the same for all domains
 *   (but each domain has its own timer; so the all are periodic by the same
 *   period, but replenishment of the budgets of the various domains, at
 *   periods boundaries, are not synchronous);
 *
 * - when vCPUs run, they consume budget. When they don't run, they don't
 *   consume budget. If there is no budget left for the domain, no vCPU of
 *   that domain can run. If a vCPU tries to run and finds that there is no
 *   budget, it blocks.
 *   At whatever time a vCPU wants to run, it must check the domain's budget,
 *   and if there is some, it can use it.
 *
 * - budget is replenished to the top of the capacity for the domain once
 *   per period. Even if there was some leftover budget from previous period,
 *   though, the budget after a replenishment will always be at most equal
 *   to the total capacify of the domain ('tot_budget');
 *
 * - when a budget replenishment occurs, if there are vCPUs that had been
 *   blocked because of lack of budget, they'll be unblocked, and they will
 *   (potentially) be able to run again.
 *
 * Finally, some even more implementation related detail:
 *
 * - budget is stored in a domain-wide pool. vCPUs of the domain that want
 *   to run go to such pool, and grub some. When they do so, the amount
 *   they grabbed is _immediately_ removed from the pool. This happens in
 *   vcpu_grab_budget();
 *
 * - when vCPUs stop running, if they've not consumed all the budget they
 *   took, the leftover is put back in the pool. This happens in
 *   vcpu_return_budget();
 *
 * - the above means that a vCPU can find out that there is no budget and
 *   block, not only if the cap has actually been reached (for this period),
 *   but also if some other vCPUs, in order to run, have grabbed a certain
 *   quota of budget, no matter whether they've already used it all or not.
 *   A vCPU blocking because (any form of) lack of budget is said to be
 *   "parked", and such blocking happens in park_vcpu();
 *
 * - when a vCPU stops running, and puts back some budget in the domain pool,
 *   we need to check whether there is someone which has been parked and that
 *   can be unparked. This happens in unpark_parked_vcpus(), called from
 *   csched2_context_saved();
 *
 * - of course, unparking happens also as a consequence of the domain's budget
 *   being replenished by the periodic timer. This also occurs by means of
 *   calling csched2_context_saved() (but from replenish_domain_budget());
 *
 * - parked vCPUs of a domain are kept in a (per-domain) list, called
 *   'parked_vcpus'). Manipulation of the list and of the domain-wide budget
 *   pool, must occur only when holding the 'budget_lock'.
 */

/*
 * Locking:
 *
 * - runqueue lock
 *  + it is per-runqueue, so:
 *   * cpus in a runqueue take the runqueue lock, when using
 *     pcpu_schedule_lock() / vcpu_schedule_lock() (and friends),
 *   * a cpu may (try to) take a "remote" runqueue lock, e.g., for
 *     load balancing;
 *  + serializes runqueue operations (removing and inserting vcpus);
 *  + protects runqueue-wide data in csched2_runqueue_data;
 *  + protects vcpu parameters in csched2_vcpu for the vcpu in the
 *    runqueue.
 *
 * - Private scheduler lock
 *  + protects scheduler-wide data in csched2_private, such as:
 *   * the list of domains active in this scheduler,
 *   * what cpus and what runqueues are active and in what
 *     runqueue each cpu is;
 *  + serializes the operation of changing the weights of domains;
 *
 * - Budget lock
 *  + it is per-domain;
 *  + protects, in domains that have an utilization cap;
 *   * manipulation of the total budget of the domain (as it is shared
 *     among all vCPUs of the domain),
 *   * manipulation of the list of vCPUs that are blocked waiting for
 *     some budget to be available.
 *
 * - Type:
 *  + runqueue locks are 'regular' spinlocks;
 *  + the private scheduler lock can be an rwlock. In fact, data
 *    it protects is modified only during initialization, cpupool
 *    manipulation and when changing weights, and read in all
 *    other cases (e.g., during load balancing);
 *  + budget locks are 'regular' spinlocks.
 *
 * Ordering:
 *  + tylock must be used when wanting to take a runqueue lock,
 *    if we already hold another one;
 *  + if taking both a runqueue lock and the private scheduler
 *    lock is, the latter must always be taken for first;
 *  + if taking both a runqueue lock and a budget lock, the former
 *    must always be taken for first.
 */

/*
 * Basic constants
 */
/* Default weight: How much a new domain starts with. */
#define CSCHED2_DEFAULT_WEIGHT       256
/*
 * Min timer: Minimum length a timer will be set, to
 * achieve efficiency.
 */
#define CSCHED2_MIN_TIMER            MICROSECS(500)
/*
 * Amount of credit VMs begin with, and are reset to.
 * ATM, set so that highest-weight VMs can only run for 10ms
 * before a reset event.
 */
#define CSCHED2_CREDIT_INIT          MILLISECS(10)
/*
 * Amount of credit the idle vcpus have. It never changes, as idle
 * vcpus does not consume credits, and it must be lower than whatever
 * amount of credit 'regular' vcpu would end up with.
 */
#define CSCHED2_IDLE_CREDIT          (-(1U<<30))
/*
 * Carryover: How much "extra" credit may be carried over after
 * a reset.
 */
#define CSCHED2_CARRYOVER_MAX        CSCHED2_MIN_TIMER
/*
 * Stickiness: Cross-L2 migration resistance.  Should be less than
 * MIN_TIMER.
 */
#define CSCHED2_MIGRATE_RESIST       ((opt_migrate_resist)*MICROSECS(1))
/* How much to "compensate" a vcpu for L2 migration. */
#define CSCHED2_MIGRATE_COMPENSATION MICROSECS(50)
/* How tolerant we should be when peeking at runtime of vcpus on other cpus */
#define CSCHED2_RATELIMIT_TICKLE_TOLERANCE MICROSECS(50)
/* Reset: Value below which credit will be reset. */
#define CSCHED2_CREDIT_RESET         0
/* Max timer: Maximum time a guest can be run for. */
#define CSCHED2_MAX_TIMER            CSCHED2_CREDIT_INIT
/* Period of the cap replenishment timer. */
#define CSCHED2_BDGT_REPL_PERIOD     ((opt_cap_period)*MILLISECS(1))

/*
 * Flags
 */
/*
 * CSFLAG_scheduled: Is this vcpu either running on, or context-switching off,
 * a physical cpu?
 * + Accessed only with runqueue lock held
 * + Set when chosen as next in csched2_schedule().
 * + Cleared after context switch has been saved in csched2_context_saved()
 * + Checked in vcpu_wake to see if we can add to the runqueue, or if we should
 *   set CSFLAG_delayed_runq_add
 * + Checked to be false in runq_insert.
 */
#define __CSFLAG_scheduled 1
#define CSFLAG_scheduled (1U<<__CSFLAG_scheduled)
/*
 * CSFLAG_delayed_runq_add: Do we need to add this to the runqueue once it'd done
 * being context switched out?
 * + Set when scheduling out in csched2_schedule() if prev is runnable
 * + Set in csched2_vcpu_wake if it finds CSFLAG_scheduled set
 * + Read in csched2_context_saved().  If set, it adds prev to the runqueue and
 *   clears the bit.
 */
#define __CSFLAG_delayed_runq_add 2
#define CSFLAG_delayed_runq_add (1U<<__CSFLAG_delayed_runq_add)
/*
 * CSFLAG_runq_migrate_request: This vcpu is being migrated as a result of a
 * credit2-initiated runq migrate request; migrate it to the runqueue indicated
 * in the svc struct. 
 */
#define __CSFLAG_runq_migrate_request 3
#define CSFLAG_runq_migrate_request (1U<<__CSFLAG_runq_migrate_request)
/*
 * CSFLAG_vcpu_yield: this vcpu was running, and has called vcpu_yield(). The
 * scheduler is invoked to see if we can give the cpu to someone else, and
 * get back to the yielding vcpu in a while.
 */
#define __CSFLAG_vcpu_yield 4
#define CSFLAG_vcpu_yield (1U<<__CSFLAG_vcpu_yield)

static unsigned int __read_mostly opt_migrate_resist = 500;
integer_param("sched_credit2_migrate_resist", opt_migrate_resist);

/*
 * Load tracking and load balancing
 *
 * Load history of runqueues and vcpus is accounted for by using an
 * exponential weighted moving average algorithm. However, instead of using
 * fractions,we shift everything to left by the number of bits we want to
 * use for representing the fractional part (Q-format).
 *
 * We may also want to reduce the precision of time accounting, to
 * accommodate 'longer  windows'. So, if that is the case, we just need to
 * shift all time samples to the right.
 *
 * The details of the formulas used for load tracking are explained close to
 * update_runq_load(). Let's just say here that, with full nanosecond time
 * granularity, a 30 bits wide 'decaying window' is ~1 second long.
 *
 * We want to consider the following equations:
 *
 *  avg[0] = load*P
 *  avg[i+1] = avg[i] + delta*load*P/W - delta*avg[i]/W,  0 <= delta <= W
 *
 * where W is the length of the window, P the multiplier for transitiong into
 * Q-format fixed point arithmetic and load is the instantaneous load of a
 * runqueue, which basically is the number of runnable vcpus there are on the
 * runqueue (for the meaning of the other terms, look at the doc comment to
 *  update_runq_load()).
 *
 *  So, again, with full nanosecond granularity, and 1 second window, we have:
 *
 *  W = 2^30
 *  P = 2^18
 *
 * The maximum possible value for the average load, which we want to store in
 * s_time_t type variables (i.e., we have 63 bits available) is load*P. This
 * means that, with P 18 bits wide, load can occupy 45 bits. This in turn
 * means we can have 2^45 vcpus in each runqueue, before overflow occurs!
 *
 * However, it can happen that, at step j+1, if:
 *
 *  avg[j] = load*P
 *  delta = W
 *
 * then:
 *
 *  avg[j+i] = avg[j] + W*load*P/W - W*load*P/W
 *
 * So we must be able to deal with W*load*P. This means load can't be higher
 * than:
 *
 *  2^(63 - 30 - 18) = 2^15 = 32768
 *
 * So 32768 is the maximum number of vcpus the we can have in a runqueue,
 * at any given time, and still not have problems with the load tracking
 * calculations... and this is more than fine.
 *
 * As a matter of fact, since we are using microseconds granularity, we have
 * W=2^20. So, still with 18 fractional bits and a 1 second long window, there
 * may be 2^25 = 33554432 vcpus in a runq before we have to start thinking
 * about overflow.
 */

/* If >0, decreases the granularity of time samples used for load tracking. */
#define LOADAVG_GRANULARITY_SHIFT   (10)
/* Time window during which we still give value to previous load history. */
#define LOADAVG_WINDOW_SHIFT        (30)
/* 18 bits by default (and not less than 4) for decimals. */
#define LOADAVG_PRECISION_SHIFT     (18)
#define LOADAVG_PRECISION_SHIFT_MIN (4)

/*
 * Both the length of the window and the number of fractional bits can be
 * decided with boot parameters.
 *
 * The length of the window is always expressed in nanoseconds. The actual
 * value used by default is LOADAVG_WINDOW_SHIFT - LOADAVG_GRANULARITY_SHIFT.
 */
static unsigned int __read_mostly opt_load_window_shift = LOADAVG_WINDOW_SHIFT;
integer_param("credit2_load_window_shift", opt_load_window_shift);
static unsigned int __read_mostly opt_load_precision_shift = LOADAVG_PRECISION_SHIFT;
integer_param("credit2_load_precision_shift", opt_load_precision_shift);

static int __read_mostly opt_underload_balance_tolerance = 0;
integer_param("credit2_balance_under", opt_underload_balance_tolerance);
static int __read_mostly opt_overload_balance_tolerance = -3;
integer_param("credit2_balance_over", opt_overload_balance_tolerance);
/*
 * Domains subject to a cap receive a replenishment of their runtime budget
 * once every opt_cap_period interval. Default is 10 ms. The amount of budget
 * they receive depends on their cap. For instance, a domain with a 50% cap
 * will receive 50% of 10 ms, so 5 ms.
 */
static unsigned int __read_mostly opt_cap_period = 10;    /* ms */
integer_param("credit2_cap_period_ms", opt_cap_period);

/*
 * Runqueue organization.
 *
 * The various cpus are to be assigned each one to a runqueue, and we
 * want that to happen basing on topology. At the moment, it is possible
 * to choose to arrange runqueues to be:
 *
 * - per-cpu: meaning that there will be one runqueue per logical cpu. This
 *            will happen when if the opt_runqueue parameter is set to 'cpu'.
 *
 * - per-core: meaning that there will be one runqueue per each physical
 *             core of the host. This will happen if the opt_runqueue
 *             parameter is set to 'core';
 *
 * - per-socket: meaning that there will be one runqueue per each physical
 *               socket (AKA package, which often, but not always, also
 *               matches a NUMA node) of the host; This will happen if
 *               the opt_runqueue parameter is set to 'socket';
 *
 * - per-node: meaning that there will be one runqueue per each physical
 *             NUMA node of the host. This will happen if the opt_runqueue
 *             parameter is set to 'node';
 *
 * - global: meaning that there will be only one runqueue to which all the
 *           (logical) processors of the host belong. This will happen if
 *           the opt_runqueue parameter is set to 'all'.
 *
 * Depending on the value of opt_runqueue, therefore, cpus that are part of
 * either the same physical core, the same physical socket, the same NUMA
 * node, or just all of them, will be put together to form runqueues.
 */
#define OPT_RUNQUEUE_CPU    0
#define OPT_RUNQUEUE_CORE   1
#define OPT_RUNQUEUE_SOCKET 2
#define OPT_RUNQUEUE_NODE   3
#define OPT_RUNQUEUE_ALL    4
static const char *const opt_runqueue_str[] = {
    [OPT_RUNQUEUE_CPU] = "cpu",
    [OPT_RUNQUEUE_CORE] = "core",
    [OPT_RUNQUEUE_SOCKET] = "socket",
    [OPT_RUNQUEUE_NODE] = "node",
    [OPT_RUNQUEUE_ALL] = "all"
};
static int __read_mostly opt_runqueue = OPT_RUNQUEUE_SOCKET;

static int parse_credit2_runqueue(const char *s)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(opt_runqueue_str); i++ )
    {
        if ( !strcmp(s, opt_runqueue_str[i]) )
        {
            opt_runqueue = i;
            return 0;
        }
    }

    return -EINVAL;
}
custom_param("credit2_runqueue", parse_credit2_runqueue);

/*
 * Per-runqueue data
 */
struct csched2_runqueue_data {
    spinlock_t lock;           /* Lock for this runqueue                     */

    struct list_head runq;     /* Ordered list of runnable vms               */
    int id;                    /* ID of this runqueue (-1 if invalid)        */

    int load;                  /* Instantaneous load (num of non-idle vcpus) */
    s_time_t load_last_update; /* Last time average was updated              */
    s_time_t avgload;          /* Decaying queue load                        */
    s_time_t b_avgload;        /* Decaying queue load modified by balancing  */

    cpumask_t active,          /* CPUs enabled for this runqueue             */
        smt_idle,              /* Fully idle-and-untickled cores (see below) */
        tickled,               /* Have been asked to go through schedule     */
        idle;                  /* Currently idle pcpus                       */

    struct list_head svc;      /* List of all vcpus assigned to the runqueue */
    unsigned int max_weight;   /* Max weight of the vcpus in this runqueue   */
    unsigned int pick_bias;    /* Last picked pcpu. Start from it next time  */
};

/*
 * System-wide private data
 */
struct csched2_private {
    rwlock_t lock;                     /* Private scheduler lock             */

    unsigned int load_precision_shift; /* Precision of load calculations     */
    unsigned int load_window_shift;    /* Lenght of load decaying window     */
    unsigned int ratelimit_us;         /* Rate limiting for this scheduler   */

    cpumask_t active_queues;           /* Runqueues with (maybe) active cpus */
    struct csched2_runqueue_data *rqd; /* Data of the various runqueues      */

    cpumask_t initialized;             /* CPUs part of this scheduler        */
    struct list_head sdom;             /* List of domains (for debug key)    */
};

/*
 * Physical CPU
 *
 * The only per-pCPU information we need to maintain is of which runqueue
 * each CPU is part of.
 */
static DEFINE_PER_CPU(int, runq_map);

/*
 * Virtual CPU
 */
struct csched2_vcpu {
    struct csched2_dom *sdom;          /* Up-pointer to domain                */
    struct vcpu *vcpu;                 /* Up-pointer, to vcpu                 */
    struct csched2_runqueue_data *rqd; /* Up-pointer to the runqueue          */

    int credit;                        /* Current amount of credit            */
    unsigned int weight;               /* Weight of this vcpu                 */
    unsigned int residual;             /* Reminder of div(max_weight/weight)  */
    unsigned flags;                    /* Status flags (16 bits would be ok,  */
    s_time_t budget;                   /* Current budget (if domains has cap) */
                                       /* but clear_bit() does not like that) */
    s_time_t budget_quota;             /* Budget to which vCPU is entitled    */

    s_time_t start_time;               /* Time we were scheduled (for credit) */

    /* Individual contribution to load                                        */
    s_time_t load_last_update;         /* Last time average was updated       */
    s_time_t avgload;                  /* Decaying queue load                 */

    struct list_head runq_elem;        /* On the runqueue (rqd->runq)         */
    struct list_head parked_elem;      /* On the parked_vcpus list            */
    struct list_head rqd_elem;         /* On csched2_runqueue_data's svc list */
    struct csched2_runqueue_data *migrate_rqd; /* Pre-determined migr. target */
    int tickled_cpu;                   /* Cpu that will pick us (-1 if none)  */
};

/*
 * Domain
 */
struct csched2_dom {
    struct domain *dom;         /* Up-pointer to domain                       */

    spinlock_t budget_lock;     /* Serialized budget calculations             */
    s_time_t tot_budget;        /* Total amount of budget                     */
    s_time_t budget;            /* Currently available budget                 */

    struct timer *repl_timer;   /* Timer for periodic replenishment of budget */
    s_time_t next_repl;         /* Time at which next replenishment occurs    */
    struct list_head parked_vcpus; /* List of CPUs waiting for budget         */

    struct list_head sdom_elem; /* On csched2_runqueue_data's sdom list       */
    uint16_t weight;            /* User specified weight                      */
    uint16_t cap;               /* User specified cap                         */
    uint16_t nr_vcpus;          /* Number of vcpus of this domain             */
};

/*
 * Accessor helpers functions.
 */
static inline struct csched2_private *csched2_priv(const struct scheduler *ops)
{
    return ops->sched_data;
}

static inline struct csched2_vcpu *csched2_vcpu(const struct vcpu *v)
{
    return v->sched_priv;
}

static inline struct csched2_dom *csched2_dom(const struct domain *d)
{
    return d->sched_priv;
}

/* CPU to runq_id macro */
static inline int c2r(unsigned int cpu)
{
    return per_cpu(runq_map, cpu);
}

/* CPU to runqueue struct macro */
static inline struct csched2_runqueue_data *c2rqd(const struct scheduler *ops,
                                                  unsigned int cpu)
{
    return &csched2_priv(ops)->rqd[c2r(cpu)];
}

/* Does the domain of this vCPU have a cap? */
static inline bool has_cap(const struct csched2_vcpu *svc)
{
    return svc->budget != STIME_MAX;
}

/*
 * Hyperthreading (SMT) support.
 *
 * We use a special per-runq mask (smt_idle) and update it according to the
 * following logic:
 *  - when _all_ the SMT sibling in a core are idle, all their corresponding
 *    bits are set in the smt_idle mask;
 *  - when even _just_one_ of the SMT siblings in a core is not idle, all the
 *    bits correspondings to it and to all its siblings are clear in the
 *    smt_idle mask.
 *
 * Once we have such a mask, it is easy to implement a policy that, either:
 *  - uses fully idle cores first: it is enough to try to schedule the vcpus
 *    on pcpus from smt_idle mask first. This is what happens if
 *    sched_smt_power_savings was not set at boot (default), and it maximizes
 *    true parallelism, and hence performance;
 *  - uses already busy cores first: it is enough to try to schedule the vcpus
 *    on pcpus that are idle, but are not in smt_idle. This is what happens if
 *    sched_smt_power_savings is set at boot, and it allows as more cores as
 *    possible to stay in low power states, minimizing power consumption.
 *
 * This logic is entirely implemented in runq_tickle(), and that is enough.
 * In fact, in this scheduler, placement of a vcpu on one of the pcpus of a
 * runq, _always_ happens by means of tickling:
 *  - when a vcpu wakes up, it calls csched2_vcpu_wake(), which calls
 *    runq_tickle();
 *  - when a migration is initiated in schedule.c, we call csched2_cpu_pick(),
 *    csched2_vcpu_migrate() (which calls migrate()) and csched2_vcpu_wake().
 *    csched2_cpu_pick() looks for the least loaded runq and return just any
 *    of its processors. Then, csched2_vcpu_migrate() just moves the vcpu to
 *    the chosen runq, and it is again runq_tickle(), called by
 *    csched2_vcpu_wake() that actually decides what pcpu to use within the
 *    chosen runq;
 *  - when a migration is initiated in sched_credit2.c, by calling  migrate()
 *    directly, that again temporarily use a random pcpu from the new runq,
 *    and then calls runq_tickle(), by itself.
 */

/*
 * If all the siblings of cpu (including cpu itself) are both idle and
 * untickled, set all their bits in mask.
 *
 * NB that rqd->smt_idle is different than rqd->idle.  rqd->idle
 * records pcpus that at are merely idle (i.e., at the moment do not
 * have a vcpu running on them).  But you have to manually filter out
 * which pcpus have been tickled in order to find cores that are not
 * going to be busy soon.  Filtering out tickled cpus pairwise is a
 * lot of extra pain; so for rqd->smt_idle, we explicitly make so that
 * the bits of a pcpu are set only if all the threads on its core are
 * both idle *and* untickled.
 *
 * This means changing the mask when either rqd->idle or rqd->tickled
 * changes.
 */
static inline
void smt_idle_mask_set(unsigned int cpu, const cpumask_t *idlers,
                       cpumask_t *mask)
{
    const cpumask_t *cpu_siblings = per_cpu(cpu_sibling_mask, cpu);

    if ( cpumask_subset(cpu_siblings, idlers) )
        cpumask_or(mask, mask, cpu_siblings);
}

/*
 * Clear the bits of all the siblings of cpu from mask (if necessary).
 */
static inline
void smt_idle_mask_clear(unsigned int cpu, cpumask_t *mask)
{
    const cpumask_t *cpu_siblings = per_cpu(cpu_sibling_mask, cpu);

    if ( cpumask_subset(cpu_siblings, mask) )
        cpumask_andnot(mask, mask, per_cpu(cpu_sibling_mask, cpu));
}

/*
 * In csched2_cpu_pick(), it may not be possible to actually look at remote
 * runqueues (the trylock-s on their spinlocks can fail!). If that happens,
 * we pick, in order of decreasing preference:
 *  1) svc's current pcpu, if it is part of svc's soft affinity;
 *  2) a pcpu in svc's current runqueue that is also in svc's soft affinity;
 *  3) svc's current pcpu, if it is part of svc's hard affinity;
 *  4) a pcpu in svc's current runqueue that is also in svc's hard affinity;
 *  5) just one valid pcpu from svc's hard affinity
 *
 * Of course, 1, 2 and 3 makes sense only if svc has a soft affinity. Also
 * note that at least 5 is guaranteed to _always_ return at least one pcpu.
 */
static int get_fallback_cpu(struct csched2_vcpu *svc)
{
    struct vcpu *v = svc->vcpu;
    unsigned int bs;

    SCHED_STAT_CRANK(need_fallback_cpu);

    for_each_affinity_balance_step( bs )
    {
        int cpu = v->processor;

        if ( bs == BALANCE_SOFT_AFFINITY &&
             !has_soft_affinity(v, v->cpu_hard_affinity) )
            continue;

        affinity_balance_cpumask(v, bs, cpumask_scratch_cpu(cpu));
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                    cpupool_domain_cpumask(v->domain));

        /*
         * This is cases 1 or 3 (depending on bs): if v->processor is (still)
         * in our affinity, go for it, for cache betterness.
         */
        if ( likely(cpumask_test_cpu(cpu, cpumask_scratch_cpu(cpu))) )
            return cpu;

        /*
         * This is cases 2 or 4 (depending on bs): v->processor isn't there
         * any longer, check if we at least can stay in our current runq.
         */
        if ( likely(cpumask_intersects(cpumask_scratch_cpu(cpu),
                                       &svc->rqd->active)) )
        {
            cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                        &svc->rqd->active);
            return cpumask_first(cpumask_scratch_cpu(cpu));
        }

        /*
         * We may well pick any valid pcpu from our soft-affinity, outside
         * of our current runqueue, but we decide not to. In fact, changing
         * runqueue is slow, affects load distribution, and is a source of
         * overhead for the vcpus running on the other runqueue (we need the
         * lock). So, better do that as a consequence of a well informed
         * decision (or if we really don't have any other chance, as we will,
         * at step 5, if we get to there).
         *
         * Also, being here, looking for a fallback, is an unfortunate and
         * infrequent event, while the decision of putting us in the runqueue
         * wehere we are was (likely) made taking all the relevant factors
         * into account. So let's not disrupt that, just for the sake of
         * soft-affinity, and let's wait here to be able to made (hopefully,
         * soon), another similar well informed decision.
         */
        if ( bs == BALANCE_SOFT_AFFINITY )
            continue;

        /*
         * This is cases 5: last stand, just one valid pcpu from our hard
         * affinity. It's guaranteed that there is at least one valid cpu,
         * and therefore we are sure that we return it, and never really
         * exit the loop.
         */
        ASSERT(bs == BALANCE_HARD_AFFINITY &&
               !cpumask_empty(cpumask_scratch_cpu(cpu)));
        cpu = cpumask_first(cpumask_scratch_cpu(cpu));
        if ( likely(cpu < nr_cpu_ids) )
            return cpu;
    }
    ASSERT_UNREACHABLE();
    /*
     * We can't be here.  But if that somehow happen (in non-debug builds),
     * at least return something which both online and in our hard-affinity.
     */
    return cpumask_any(cpumask_scratch_cpu(v->processor));
}

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
 * Runqueue related code.
 */

static inline int vcpu_on_runq(struct csched2_vcpu *svc)
{
    return !list_empty(&svc->runq_elem);
}

static inline struct csched2_vcpu * runq_elem(struct list_head *elem)
{
    return list_entry(elem, struct csched2_vcpu, runq_elem);
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

    __cpumask_set_cpu(rqi, &prv->active_queues);
}

static void deactivate_runqueue(struct csched2_private *prv, int rqi)
{
    struct csched2_runqueue_data *rqd;

    rqd = prv->rqd + rqi;

    BUG_ON(!cpumask_empty(&rqd->active));

    rqd->id = -1;

    __cpumask_clear_cpu(rqi, &prv->active_queues);
}

static inline bool same_node(unsigned int cpua, unsigned int cpub)
{
    return cpu_to_node(cpua) == cpu_to_node(cpub);
}

static inline bool same_socket(unsigned int cpua, unsigned int cpub)
{
    return cpu_to_socket(cpua) == cpu_to_socket(cpub);
}

static inline bool same_core(unsigned int cpua, unsigned int cpub)
{
    return same_socket(cpua, cpub) &&
           cpu_to_core(cpua) == cpu_to_core(cpub);
}

static unsigned int
cpu_to_runqueue(struct csched2_private *prv, unsigned int cpu)
{
    struct csched2_runqueue_data *rqd;
    unsigned int rqi;

    for ( rqi = 0; rqi < nr_cpu_ids; rqi++ )
    {
        unsigned int peer_cpu;

        /*
         * As soon as we come across an uninitialized runqueue, use it.
         * In fact, either:
         *  - we are initializing the first cpu, and we assign it to
         *    runqueue 0. This is handy, especially if we are dealing
         *    with the boot cpu (if credit2 is the default scheduler),
         *    as we would not be able to use cpu_to_socket() and similar
         *    helpers anyway (they're result of which is not reliable yet);
         *  - we have gone through all the active runqueues, and have not
         *    found anyone whose cpus' topology matches the one we are
         *    dealing with, so activating a new runqueue is what we want.
         */
        if ( prv->rqd[rqi].id == -1 )
            break;

        rqd = prv->rqd + rqi;
        BUG_ON(cpumask_empty(&rqd->active));

        peer_cpu = cpumask_first(&rqd->active);
        BUG_ON(cpu_to_socket(cpu) == XEN_INVALID_SOCKET_ID ||
               cpu_to_socket(peer_cpu) == XEN_INVALID_SOCKET_ID);

        if (opt_runqueue == OPT_RUNQUEUE_CPU)
            continue;
        if ( opt_runqueue == OPT_RUNQUEUE_ALL ||
             (opt_runqueue == OPT_RUNQUEUE_CORE && same_core(peer_cpu, cpu)) ||
             (opt_runqueue == OPT_RUNQUEUE_SOCKET && same_socket(peer_cpu, cpu)) ||
             (opt_runqueue == OPT_RUNQUEUE_NODE && same_node(peer_cpu, cpu)) )
            break;
    }

    /* We really expect to be able to assign each cpu to a runqueue. */
    BUG_ON(rqi >= nr_cpu_ids);

    return rqi;
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
        SCHED_STAT_CRANK(upd_max_weight_quick);
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
        SCHED_STAT_CRANK(upd_max_weight_full);
    }

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned rqi:16, max_weight:16;
        } d;
        d.rqi = rqd->id;
        d.max_weight = rqd->max_weight;
        __trace_var(TRC_CSCHED2_RUNQ_MAX_WEIGHT, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }
}

/* Add and remove from runqueue assignment (not active run queue) */
static void
_runq_assign(struct csched2_vcpu *svc, struct csched2_runqueue_data *rqd)
{

    svc->rqd = rqd;
    list_add_tail(&svc->rqd_elem, &svc->rqd->svc);

    update_max_weight(svc->rqd, svc->weight, 0);

    /* Expected new load based on adding this vcpu */
    rqd->b_avgload += svc->avgload;

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            unsigned rqi:16;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.rqi=rqd->id;
        __trace_var(TRC_CSCHED2_RUNQ_ASSIGN, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

}

static void
runq_assign(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu *svc = vc->sched_priv;

    ASSERT(svc->rqd == NULL);

    _runq_assign(svc, c2rqd(ops, vc->processor));
}

static void
_runq_deassign(struct csched2_vcpu *svc)
{
    struct csched2_runqueue_data *rqd = svc->rqd;

    ASSERT(!vcpu_on_runq(svc));
    ASSERT(!(svc->flags & CSFLAG_scheduled));

    list_del_init(&svc->rqd_elem);
    update_max_weight(rqd, 0, svc->weight);

    /* Expected new load based on removing this vcpu */
    rqd->b_avgload = max_t(s_time_t, rqd->b_avgload - svc->avgload, 0);

    svc->rqd = NULL;
}

static void
runq_deassign(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu *svc = vc->sched_priv;

    ASSERT(svc->rqd == c2rqd(ops, vc->processor));

    _runq_deassign(svc);
}

/*
 * Track the runq load by gathering instantaneous load samples, and using
 * exponentially weighted moving average (EWMA) for the 'decaying'.
 *
 * We consider a window of length W=2^(prv->load_window_shift) nsecs
 * (which takes LOADAVG_GRANULARITY_SHIFT into account).
 *
 * If load is the instantaneous load, the formula for EWMA looks as follows,
 * for the i-eth sample:
 *
 *  avg[i] = a*load + (1 - a)*avg[i-1]
 *
 * where avg[i] is the new value of the average load, avg[i-1] is the value
 * of the average load calculated so far, and a is a coefficient less or
 * equal to 1.
 *
 * So, for us, it becomes:
 *
 *  avgload = a*load + (1 - a)*avgload
 *
 * For determining a, we consider _when_ we are doing the load update, wrt
 * the length of the window. We define delta as follows:
 *
 *  delta = t - load_last_update
 *
 * where t is current time (i.e., time at which we are both sampling and
 * updating the load average) and load_last_update is the last time we did
 * that.
 *
 * There are two possible situations:
 *
 * a) delta <= W
 *    this means that, during the last window of length W, the runeuque load
 *    was avgload for (W - detla) time, and load for delta time:
 *
 *                |----------- W ---------|
 *                |                       |
 *                |     load_last_update  t
 *     -------------------------|---------|---
 *                |             |         |
 *                \__W - delta__/\_delta__/
 *                |             |         |
 *                |___avgload___|__load___|
 *
 *    So, what about using delta/W as our smoothing coefficient a. If we do,
 *    here's what happens:
 *
 *     a = delta / W
 *     1 - a = 1 - (delta / W) = (W - delta) / W
 *
 *    Which matches the above description of what happened in the last
 *    window of length W.
 *
 *    Note that this also means that the weight that we assign to both the
 *    latest load sample, and to previous history, varies at each update.
 *    The longer the latest load sample has been in efect, within the last
 *    window, the higher it weights (and the lesser the previous history
 *    weights).
 *
 *    This is some sort of extension of plain EWMA to fit even better to our
 *    use case.
 *
 * b) delta > W
 *    this means more than a full window has passed since the last update:
 *
 *                |----------- W ---------|
 *                |                       |
 *       load_last_update                 t
 *     ----|------------------------------|---
 *         |                              |
 *         \_________________delta________/
 *
 *    Basically, it means the last load sample has been in effect for more
 *    than W time, and hence we should just use it, and forget everything
 *    before that.
 *
 *    This can be seen as a 'reset condition', occurring when, for whatever
 *    reason, load has not been updated for longer than we expected. (It is
 *    also how avgload is assigned its first value.)
 *
 * The formula for avgload then becomes:
 *
 *  avgload = (delta/W)*load + (W - delta)*avgload/W
 *  avgload = delta*load/W + W*avgload/W - delta*avgload/W
 *  avgload = avgload + delta*load/W - delta*avgload/W
 *
 * So, final form is:
 *
 *  avgload_0 = load
 *  avgload = avgload + delta*load/W - delta*avgload/W,  0<=delta<=W
 *
 * As a confirmation, let's look at the extremes, when delta is 0 (i.e.,
 * what happens if we  update the load twice, at the same time instant?):
 *
 *  avgload = avgload + 0*load/W - 0*avgload/W
 *  avgload = avgload
 *
 * and when delta is W (i.e., what happens if we update at the last
 * possible instant before the window 'expires'?):
 *
 *  avgload = avgload + W*load/W - W*avgload/W
 *  avgload = avgload + load - avgload
 *  avgload = load
 *
 * Which, in both cases, is what we expect.
 */
static void
update_runq_load(const struct scheduler *ops,
                 struct csched2_runqueue_data *rqd, int change, s_time_t now)
{
    struct csched2_private *prv = csched2_priv(ops);
    s_time_t delta, load = rqd->load;
    unsigned int P, W;

    W = prv->load_window_shift;
    P = prv->load_precision_shift;
    now >>= LOADAVG_GRANULARITY_SHIFT;

    /*
     * To avoid using fractions, we shift to left by load_precision_shift,
     * and use the least last load_precision_shift bits as fractional part.
     * Looking back at the formula we want to use, we now have:
     *
     *  P = 2^(load_precision_shift)
     *  P*avgload = P*(avgload + delta*load/W - delta*avgload/W)
     *  P*avgload = P*avgload + delta*load*P/W - delta*P*avgload/W
     *
     * And if we are ok storing and using P*avgload, we can rewrite this as:
     *
     *  P*avgload = avgload'
     *  avgload' = avgload' + delta*P*load/W - delta*avgload'/W
     *
     * Coupled with, of course:
     *
     *  avgload_0' = P*load
     */

    if ( rqd->load_last_update + (1ULL << W)  < now )
    {
        rqd->avgload = load << P;
        rqd->b_avgload = load << P;
    }
    else
    {
        delta = now - rqd->load_last_update;
        if ( unlikely(delta < 0) )
        {
            d2printk("WARNING: %s: Time went backwards? now %"PRI_stime" llu %"PRI_stime"\n",
                     __func__, now, rqd->load_last_update);
            delta = 0;
        }

        /*
         * Note that, if we were to enforce (or check) some relationship
         * between P and W, we may save one shift. E.g., if we are sure
         * that P < W, we could write:
         *
         *  (delta * (load << P)) >> W
         *
         * as:
         *
         *  (delta * load) >> (W - P)
         */
        rqd->avgload = rqd->avgload +
                       ((delta * (load << P)) >> W) -
                       ((delta * rqd->avgload) >> W);
        rqd->b_avgload = rqd->b_avgload +
                         ((delta * (load << P)) >> W) -
                         ((delta * rqd->b_avgload) >> W);
    }
    rqd->load += change;
    rqd->load_last_update = now;

    /* Overflow, capable of making the load look negative, must not occur. */
    ASSERT(rqd->avgload >= 0 && rqd->b_avgload >= 0);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint64_t rq_avgload, b_avgload;
            unsigned rq_load:16, rq_id:8, shift:8;
        } d;
        d.rq_id = rqd->id;
        d.rq_load = rqd->load;
        d.rq_avgload = rqd->avgload;
        d.b_avgload = rqd->b_avgload;
        d.shift = P;
        __trace_var(TRC_CSCHED2_UPDATE_RUNQ_LOAD, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }
}

static void
update_svc_load(const struct scheduler *ops,
                struct csched2_vcpu *svc, int change, s_time_t now)
{
    struct csched2_private *prv = csched2_priv(ops);
    s_time_t delta, vcpu_load;
    unsigned int P, W;

    if ( change == -1 )
        vcpu_load = 1;
    else if ( change == 1 )
        vcpu_load = 0;
    else
        vcpu_load = vcpu_runnable(svc->vcpu);

    W = prv->load_window_shift;
    P = prv->load_precision_shift;
    now >>= LOADAVG_GRANULARITY_SHIFT;

    if ( svc->load_last_update + (1ULL << W) < now )
    {
        svc->avgload = vcpu_load << P;
    }
    else
    {
        delta = now - svc->load_last_update;
        if ( unlikely(delta < 0) )
        {
            d2printk("WARNING: %s: Time went backwards? now %"PRI_stime" llu %"PRI_stime"\n",
                     __func__, now, svc->load_last_update);
            delta = 0;
        }

        svc->avgload = svc->avgload +
                       ((delta * (vcpu_load << P)) >> W) -
                       ((delta * svc->avgload) >> W);
    }
    svc->load_last_update = now;

    /* Overflow, capable of making the load look negative, must not occur. */
    ASSERT(svc->avgload >= 0);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint64_t v_avgload;
            unsigned vcpu:16, dom:16;
            unsigned shift;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.v_avgload = svc->avgload;
        d.shift = P;
        __trace_var(TRC_CSCHED2_UPDATE_VCPU_LOAD, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }
}

static void
update_load(const struct scheduler *ops,
            struct csched2_runqueue_data *rqd,
            struct csched2_vcpu *svc, int change, s_time_t now)
{
    trace_var(TRC_CSCHED2_UPDATE_LOAD, 1, 0,  NULL);

    update_runq_load(ops, rqd, change, now);
    if ( svc )
        update_svc_load(ops, svc, change, now);
}

static void
runq_insert(const struct scheduler *ops, struct csched2_vcpu *svc)
{
    struct list_head *iter;
    unsigned int cpu = svc->vcpu->processor;
    struct list_head * runq = &c2rqd(ops, cpu)->runq;
    int pos = 0;

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    ASSERT(!vcpu_on_runq(svc));
    ASSERT(c2r(cpu) == c2r(svc->vcpu->processor));

    ASSERT(&svc->rqd->runq == runq);
    ASSERT(!is_idle_vcpu(svc->vcpu));
    ASSERT(!svc->vcpu->is_running);
    ASSERT(!(svc->flags & CSFLAG_scheduled));

    list_for_each( iter, runq )
    {
        struct csched2_vcpu * iter_svc = runq_elem(iter);

        if ( svc->credit > iter_svc->credit )
            break;

        pos++;
    }
    list_add_tail(&svc->runq_elem, iter);

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            unsigned pos;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.pos = pos;
        __trace_var(TRC_CSCHED2_RUNQ_POS, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }
}

static inline void runq_remove(struct csched2_vcpu *svc)
{
    ASSERT(vcpu_on_runq(svc));
    list_del_init(&svc->runq_elem);
}

void burn_credits(struct csched2_runqueue_data *rqd, struct csched2_vcpu *, s_time_t);

static inline void
tickle_cpu(unsigned int cpu, struct csched2_runqueue_data *rqd)
{
    __cpumask_set_cpu(cpu, &rqd->tickled);
    smt_idle_mask_clear(cpu, &rqd->smt_idle);
    cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
}

/*
 * What we want to know is whether svc, which we assume to be running on some
 * pcpu, can be interrupted and preempted (which, so far, basically means
 * whether or not it already run for more than the ratelimit, to which we
 * apply some tolerance).
 */
static inline bool is_preemptable(const struct csched2_vcpu *svc,
                                    s_time_t now, s_time_t ratelimit)
{
    if ( ratelimit <= CSCHED2_RATELIMIT_TICKLE_TOLERANCE )
        return true;

    ASSERT(svc->vcpu->is_running);
    return now - svc->vcpu->runstate.state_entry_time >
           ratelimit - CSCHED2_RATELIMIT_TICKLE_TOLERANCE;
}

/*
 * Score to preempt the target cpu.  Return a negative number if the
 * credit isn't high enough; if it is, favor a preemption on cpu in
 * this order:
 * - cpu is in new's soft-affinity, not in cur's soft-affinity
 *   (2 x CSCHED2_CREDIT_INIT score bonus);
 * - cpu is in new's soft-affinity and cur's soft-affinity, or
 *   cpu is not in new's soft-affinity, nor in cur's soft-affinity
 *   (1x CSCHED2_CREDIT_INIT score bonus);
 * - cpu is not in new's soft-affinity, while it is in cur's soft-affinity
 *   (no bonus).
 *
 * Within the same class, the highest difference of credit.
 */
static s_time_t tickle_score(const struct scheduler *ops, s_time_t now,
                             struct csched2_vcpu *new, unsigned int cpu)
{
    struct csched2_runqueue_data *rqd = c2rqd(ops, cpu);
    struct csched2_vcpu * cur = csched2_vcpu(curr_on_cpu(cpu));
    struct csched2_private *prv = csched2_priv(ops);
    s_time_t score;

    /*
     * We are dealing with cpus that are marked non-idle (i.e., that are not
     * in rqd->idle). However, some of them may be running their idle vcpu,
     * if taking care of tasklets. In that case, we want to leave it alone.
     */
    if ( unlikely(is_idle_vcpu(cur->vcpu) ||
         !is_preemptable(cur, now, MICROSECS(prv->ratelimit_us))) )
        return -1;

    burn_credits(rqd, cur, now);

    score = new->credit - cur->credit;
    if ( new->vcpu->processor != cpu )
        score -= CSCHED2_MIGRATE_RESIST;

    /*
     * If score is positive, it means new has enough credits (i.e.,
     * new->credit > cur->credit+CSCHED2_MIGRATE_RESIST).
     *
     * Let's compute the bonuses for soft-affinities.
     */
    if ( score > 0 )
    {
        if ( cpumask_test_cpu(cpu, new->vcpu->cpu_soft_affinity) )
            score += CSCHED2_CREDIT_INIT;

        if ( !cpumask_test_cpu(cpu, cur->vcpu->cpu_soft_affinity) )
            score += CSCHED2_CREDIT_INIT;
    }

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            int credit, score;
        } d;
        d.dom = cur->vcpu->domain->domain_id;
        d.vcpu = cur->vcpu->vcpu_id;
        d.credit = cur->credit;
        d.score = score;
        __trace_var(TRC_CSCHED2_TICKLE_CHECK, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    return score;
}

/*
 * Check what processor it is best to 'wake', for picking up a vcpu that has
 * just been put (back) in the runqueue. Logic is as follows:
 *  1. if there are idle processors in the runq, wake one of them;
 *  2. if there aren't idle processor, check the one were the vcpu was
 *     running before to see if we can preempt what's running there now
 *     (and hence doing just one migration);
 *  3. last stand: check all processors and see if the vcpu is in right
 *     of preempting any of the other vcpus running on them (this requires
 *     two migrations, and that's indeed why it is left as the last stand).
 *
 * Note that when we say 'idle processors' what we really mean is (pretty
 * much always) both _idle_ and _not_already_tickled_. In fact, if a
 * processor has been tickled, it will run csched2_schedule() shortly, and
 * pick up some work, so it would be wrong to consider it idle.
 */
static void
runq_tickle(const struct scheduler *ops, struct csched2_vcpu *new, s_time_t now)
{
    int i, ipid = -1;
    s_time_t max = 0;
    unsigned int bs, cpu = new->vcpu->processor;
    struct csched2_runqueue_data *rqd = c2rqd(ops, cpu);
    cpumask_t *online = cpupool_domain_cpumask(new->vcpu->domain);
    cpumask_t mask;

    ASSERT(new->rqd == rqd);

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            unsigned processor;
            int credit;
        } d;
        d.dom = new->vcpu->domain->domain_id;
        d.vcpu = new->vcpu->vcpu_id;
        d.processor = new->vcpu->processor;
        d.credit = new->credit;
        __trace_var(TRC_CSCHED2_TICKLE_NEW, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    for_each_affinity_balance_step( bs )
    {
        /* Just skip first step, if we don't have a soft affinity */
        if ( bs == BALANCE_SOFT_AFFINITY &&
             !has_soft_affinity(new->vcpu, new->vcpu->cpu_hard_affinity) )
            continue;

        affinity_balance_cpumask(new->vcpu, bs, cpumask_scratch_cpu(cpu));

        /*
         * First of all, consider idle cpus, checking if we can just
         * re-use the pcpu where we were running before.
         *
         * If there are cores where all the siblings are idle, consider
         * them first, honoring whatever the spreading-vs-consolidation
         * SMT policy wants us to do.
         */
        if ( unlikely(sched_smt_power_savings) )
        {
            cpumask_andnot(&mask, &rqd->idle, &rqd->smt_idle);
            cpumask_and(&mask, &mask, online);
        }
        else
            cpumask_and(&mask, &rqd->smt_idle, online);
        cpumask_and(&mask, &mask, cpumask_scratch_cpu(cpu));
        i = cpumask_test_or_cycle(cpu, &mask);
        if ( i < nr_cpu_ids )
        {
            SCHED_STAT_CRANK(tickled_idle_cpu);
            ipid = i;
            goto tickle;
        }

        /*
         * If there are no fully idle cores, check all idlers, after
         * having filtered out pcpus that have been tickled but haven't
         * gone through the scheduler yet.
         */
        cpumask_andnot(&mask, &rqd->idle, &rqd->tickled);
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu), online);
        cpumask_and(&mask, &mask, cpumask_scratch_cpu(cpu));
        i = cpumask_test_or_cycle(cpu, &mask);
        if ( i < nr_cpu_ids )
        {
            SCHED_STAT_CRANK(tickled_idle_cpu);
            ipid = i;
            goto tickle;
        }
    }

    /*
     * Note that, if we are here, it means we have done the hard-affinity
     * balancing step of the loop, and hence what we have in cpumask_scratch
     * is what we put there for last, i.e., new's vcpu_hard_affinity & online
     * which is exactly what we need for the next part of the function.
     */

    /*
     * Otherwise, look for the non-idle (and non-tickled) processors with
     * the lowest credit, among the ones new is allowed to run on. Again,
     * the cpu were it was running on would be the best candidate.
     *
     * For deciding which cpu to tickle, we use tickle_score(), which will
     * factor in both new's soft-affinity, and the soft-affinity of the
     * vcpu running on each cpu that we consider.
     */
    cpumask_andnot(&mask, &rqd->active, &rqd->idle);
    cpumask_andnot(&mask, &mask, &rqd->tickled);
    cpumask_and(&mask, &mask, cpumask_scratch_cpu(cpu));
    if ( __cpumask_test_and_clear_cpu(cpu, &mask) )
    {
        s_time_t score = tickle_score(ops, now, new, cpu);

        if ( score > max )
        {
            max = score;
            ipid = cpu;

            /* If this is in new's soft affinity, just take it */
            if ( cpumask_test_cpu(cpu, new->vcpu->cpu_soft_affinity) )
            {
                SCHED_STAT_CRANK(tickled_busy_cpu);
                goto tickle;
            }
        }
    }

    for_each_cpu(i, &mask)
    {
        s_time_t score;

        /* Already looked at this one above */
        ASSERT(i != cpu);

        score = tickle_score(ops, now, new, i);

        if ( score > max )
        {
            max = score;
            ipid = i;
        }
    }

    if ( ipid == -1 )
    {
        SCHED_STAT_CRANK(tickled_no_cpu);
        return;
    }

    ASSERT(!is_idle_vcpu(curr_on_cpu(ipid)));
    SCHED_STAT_CRANK(tickled_busy_cpu);
 tickle:
    BUG_ON(ipid == -1);

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned cpu:16, pad:16;
        } d;
        d.cpu = ipid; d.pad = 0;
        __trace_var(TRC_CSCHED2_TICKLE, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    tickle_cpu(ipid, rqd);

    if ( unlikely(new->tickled_cpu != -1) )
        SCHED_STAT_CRANK(tickled_cpu_overwritten);
    new->tickled_cpu = ipid;
}

/*
 * Credit-related code
 */
static void reset_credit(const struct scheduler *ops, int cpu, s_time_t now,
                         struct csched2_vcpu *snext)
{
    struct csched2_runqueue_data *rqd = c2rqd(ops, cpu);
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
        unsigned int svc_cpu;
        struct csched2_vcpu * svc;
        int start_credit;

        svc = list_entry(iter, struct csched2_vcpu, rqd_elem);
        svc_cpu = svc->vcpu->processor;

        ASSERT(!is_idle_vcpu(svc->vcpu));
        ASSERT(svc->rqd == rqd);

        /*
         * If svc is running, it is our responsibility to make sure, here,
         * that the credit it has spent so far get accounted.
         */
        if ( svc->vcpu == curr_on_cpu(svc_cpu) )
        {
            burn_credits(rqd, svc, now);
            /*
             * And, similarly, in case it has run out of budget, as a
             * consequence of this round of accounting, we also must inform
             * its pCPU that it's time to park it, and pick up someone else.
             */
            if ( unlikely(svc->budget <= 0) )
                tickle_cpu(svc_cpu, rqd);
        }

        start_credit = svc->credit;

        /*
         * Add INIT * m, avoiding integer multiplication in the common case.
         */
        if ( likely(m==1) )
            svc->credit += CSCHED2_CREDIT_INIT;
        else
            svc->credit += m * CSCHED2_CREDIT_INIT;

        /* "Clip" credits to max carryover */
        if ( svc->credit > CSCHED2_CREDIT_INIT + CSCHED2_CARRYOVER_MAX )
            svc->credit = CSCHED2_CREDIT_INIT + CSCHED2_CARRYOVER_MAX;

        svc->start_time = now;

        if ( unlikely(tb_init_done) )
        {
            struct {
                unsigned vcpu:16, dom:16;
                int credit_start, credit_end;
                unsigned multiplier;
            } d;
            d.dom = svc->vcpu->domain->domain_id;
            d.vcpu = svc->vcpu->vcpu_id;
            d.credit_start = start_credit;
            d.credit_end = svc->credit;
            d.multiplier = m;
            __trace_var(TRC_CSCHED2_CREDIT_RESET, 1,
                        sizeof(d),
                        (unsigned char *)&d);
        }
    }

    SCHED_STAT_CRANK(credit_reset);

    /* No need to resort runqueue, as everyone's order should be the same. */
}

void burn_credits(struct csched2_runqueue_data *rqd,
                  struct csched2_vcpu *svc, s_time_t now)
{
    s_time_t delta;

    ASSERT(svc == csched2_vcpu(curr_on_cpu(svc->vcpu->processor)));

    if ( unlikely(is_idle_vcpu(svc->vcpu)) )
    {
        ASSERT(svc->credit == CSCHED2_IDLE_CREDIT);
        return;
    }

    delta = now - svc->start_time;

    if ( unlikely(delta <= 0) )
    {
        if ( unlikely(delta < 0) )
            d2printk("WARNING: %s: Time went backwards? now %"PRI_stime
                     " start_time %"PRI_stime"\n", __func__, now,
                     svc->start_time);
        goto out;
    }

    SCHED_STAT_CRANK(burn_credits_t2c);
    t2c_update(rqd, delta, svc);

    if ( has_cap(svc) )
        svc->budget -= delta;

    svc->start_time = now;

 out:
    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            int credit, budget;
            int delta;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.credit = svc->credit;
        d.budget = has_cap(svc) ?  svc->budget : INT_MIN;
        d.delta = delta;
        __trace_var(TRC_CSCHED2_CREDIT_BURN, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }
}

/*
 * Budget-related code.
 */

static void park_vcpu(struct csched2_vcpu *svc)
{
    struct vcpu *v = svc->vcpu;

    ASSERT(spin_is_locked(&svc->sdom->budget_lock));

    /*
     * It was impossible to find budget for this vCPU, so it has to be
     * "parked". This implies it is not runnable, so we mark it as such in
     * its pause_flags. If the vCPU is currently scheduled (which means we
     * are here after being called from within csched_schedule()), flagging
     * is enough, as we'll choose someone else, and then context_saved()
     * will take care of updating the load properly.
     *
     * If, OTOH, the vCPU is sitting in the runqueue (which means we are here
     * after being called from within runq_candidate()), we must go all the
     * way down to taking it out of there, and updating the load accordingly.
     *
     * In both cases, we also add it to the list of parked vCPUs of the domain.
     */
    __set_bit(_VPF_parked, &v->pause_flags);
    if ( vcpu_on_runq(svc) )
    {
        runq_remove(svc);
        update_load(svc->sdom->dom->cpupool->sched, svc->rqd, svc, -1, NOW());
    }
    list_add(&svc->parked_elem, &svc->sdom->parked_vcpus);
}

static bool vcpu_grab_budget(struct csched2_vcpu *svc)
{
    struct csched2_dom *sdom = svc->sdom;
    unsigned int cpu = svc->vcpu->processor;

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    if ( svc->budget > 0 )
        return true;

    /* budget_lock nests inside runqueue lock. */
    spin_lock(&sdom->budget_lock);

    /*
     * Here, svc->budget is <= 0 (as, if it was > 0, we'd have taken the if
     * above!). That basically means the vCPU has overrun a bit --because of
     * various reasons-- and we want to take that into account. With the +=,
     * we are actually subtracting the amount of budget the vCPU has
     * overconsumed, from the total domain budget.
     */
    sdom->budget += svc->budget;

    if ( sdom->budget > 0 )
    {
        s_time_t budget;

        /* Get our quota, if there's at least as much budget */
        if ( likely(sdom->budget >= svc->budget_quota) )
            budget = svc->budget_quota;
        else
            budget = sdom->budget;

        svc->budget = budget;
        sdom->budget -= budget;
    }
    else
    {
        svc->budget = 0;
        park_vcpu(svc);
    }

    spin_unlock(&sdom->budget_lock);

    return svc->budget > 0;
}

static void
vcpu_return_budget(struct csched2_vcpu *svc, struct list_head *parked)
{
    struct csched2_dom *sdom = svc->sdom;
    unsigned int cpu = svc->vcpu->processor;

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));
    ASSERT(list_empty(parked));

    /* budget_lock nests inside runqueue lock. */
    spin_lock(&sdom->budget_lock);

    /*
     * The vCPU is stopping running (e.g., because it's blocking, or it has
     * been preempted). If it hasn't consumed all the budget it got when,
     * starting to run, put that remaining amount back in the domain's budget
     * pool.
     */
    sdom->budget += svc->budget;
    svc->budget = 0;

    /*
     * Making budget available again to the domain means that parked vCPUs
     * may be unparked and run. They are, if any, in the domain's parked_vcpus
     * list, so we want to go through that and unpark them (so they can try
     * to get some budget).
     *
     * Touching the list requires the budget_lock, which we hold. Let's
     * therefore put everyone in that list in another, temporary list, which
     * then the caller will traverse, unparking the vCPUs it finds there.
     *
     * In fact, we can't do the actual unparking here, because that requires
     * taking the runqueue lock of the vCPUs being unparked, and we can't
     * take any runqueue locks while we hold a budget_lock.
     */
    if ( sdom->budget > 0 )
        list_splice_init(&sdom->parked_vcpus, parked);

    spin_unlock(&sdom->budget_lock);
}

static void
unpark_parked_vcpus(const struct scheduler *ops, struct list_head *vcpus)
{
    struct csched2_vcpu *svc, *tmp;
    spinlock_t *lock;

    list_for_each_entry_safe(svc, tmp, vcpus, parked_elem)
    {
        unsigned long flags;
        s_time_t now;

        lock = vcpu_schedule_lock_irqsave(svc->vcpu, &flags);

        __clear_bit(_VPF_parked, &svc->vcpu->pause_flags);
        if ( unlikely(svc->flags & CSFLAG_scheduled) )
        {
            /*
             * We end here if a budget replenishment arrived between
             * csched2_schedule() (and, in particular, after a call to
             * vcpu_grab_budget() that returned false), and
             * context_saved(). By setting __CSFLAG_delayed_runq_add,
             * we tell context_saved() to put the vCPU back in the
             * runqueue, from where it will compete with the others
             * for the newly replenished budget.
             */
            ASSERT( svc->rqd != NULL );
            ASSERT( c2rqd(ops, svc->vcpu->processor) == svc->rqd );
            __set_bit(__CSFLAG_delayed_runq_add, &svc->flags);
        }
        else if ( vcpu_runnable(svc->vcpu) )
        {
            /*
             * The vCPU should go back to the runqueue, and compete for
             * the newly replenished budget, but only if it is actually
             * runnable (and was therefore offline only because of the
             * lack of budget).
             */
            now = NOW();
            update_load(ops, svc->rqd, svc, 1, now);
            runq_insert(ops, svc);
            runq_tickle(ops, svc, now);
        }
        list_del_init(&svc->parked_elem);

        vcpu_schedule_unlock_irqrestore(lock, flags, svc->vcpu);
    }
}

static inline void do_replenish(struct csched2_dom *sdom)
{
    sdom->next_repl += CSCHED2_BDGT_REPL_PERIOD;
    sdom->budget += sdom->tot_budget;
}

static void replenish_domain_budget(void* data)
{
    struct csched2_dom *sdom = data;
    unsigned long flags;
    s_time_t now;
    LIST_HEAD(parked);

    spin_lock_irqsave(&sdom->budget_lock, flags);

    now = NOW();

    /*
     * Let's do the replenishment. Note, though, that a domain may overrun,
     * which means the budget would have gone below 0 (reasons may be system
     * overbooking, accounting issues, etc.). It also may happen that we are
     * handling the replenishment (much) later than we should (reasons may
     * again be overbooking, or issues with timers).
     *
     * Even in cases of overrun or delay, however, we expect that in 99% of
     * cases, doing just one replenishment will be good enough for being able
     * to unpark the vCPUs that are waiting for some budget.
     */
    do_replenish(sdom);

    /*
     * And now, the special cases:
     * 1) if we are late enough to have skipped (at least) one full period,
     * what we must do is doing more replenishments. Note that, however,
     * every time we add tot_budget to the budget, we also move next_repl
     * away by CSCHED2_BDGT_REPL_PERIOD, to make sure the cap is always
     * respected.
     */
    if ( unlikely(sdom->next_repl <= now) )
    {
        do
            do_replenish(sdom);
        while ( sdom->next_repl <= now );
    }
    /*
     * 2) if we overrun by more than tot_budget, then budget+tot_budget is
     * still < 0, which means that we can't unpark the vCPUs. Let's bail,
     * and wait for future replenishments.
     */
    if ( unlikely(sdom->budget <= 0) )
    {
        spin_unlock_irqrestore(&sdom->budget_lock, flags);
        goto out;
    }

    /* Since we do more replenishments, make sure we didn't overshot. */
    sdom->budget = min(sdom->budget, sdom->tot_budget);

    /*
     * As above, let's prepare the temporary list, out of the domain's
     * parked_vcpus list, now that we hold the budget_lock. Then, drop such
     * lock, and pass the list to the unparking function.
     */
    list_splice_init(&sdom->parked_vcpus, &parked);

    spin_unlock_irqrestore(&sdom->budget_lock, flags);

    unpark_parked_vcpus(sdom->dom->cpupool->sched, &parked);

 out:
    set_timer(sdom->repl_timer, sdom->next_repl);
}

#ifndef NDEBUG
static inline void
csched2_vcpu_check(struct vcpu *vc)
{
    struct csched2_vcpu * const svc = csched2_vcpu(vc);
    struct csched2_dom * const sdom = svc->sdom;

    BUG_ON( svc->vcpu != vc );
    BUG_ON( sdom != csched2_dom(vc->domain) );
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
#define CSCHED2_VCPU_CHECK(_vc)  (csched2_vcpu_check(_vc))
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
    INIT_LIST_HEAD(&svc->runq_elem);

    svc->sdom = dd;
    svc->vcpu = vc;
    svc->flags = 0U;

    if ( ! is_idle_vcpu(vc) )
    {
        ASSERT(svc->sdom != NULL);
        svc->credit = CSCHED2_CREDIT_INIT;
        svc->weight = svc->sdom->weight;
        /* Starting load of 50% */
        svc->avgload = 1ULL << (csched2_priv(ops)->load_precision_shift - 1);
        svc->load_last_update = NOW() >> LOADAVG_GRANULARITY_SHIFT;
    }
    else
    {
        ASSERT(svc->sdom == NULL);
        svc->credit = CSCHED2_IDLE_CREDIT;
        svc->weight = 0;
    }
    svc->tickled_cpu = -1;

    svc->budget = STIME_MAX;
    svc->budget_quota = 0;
    INIT_LIST_HEAD(&svc->parked_elem);

    SCHED_STAT_CRANK(vcpu_alloc);

    return svc;
}

static void
csched2_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = csched2_vcpu(vc);

    ASSERT(!is_idle_vcpu(vc));
    SCHED_STAT_CRANK(vcpu_sleep);

    if ( curr_on_cpu(vc->processor) == vc )
    {
        tickle_cpu(vc->processor, svc->rqd);
    }
    else if ( vcpu_on_runq(svc) )
    {
        ASSERT(svc->rqd == c2rqd(ops, vc->processor));
        update_load(ops, svc->rqd, svc, -1, NOW());
        runq_remove(svc);
    }
    else
        __clear_bit(__CSFLAG_delayed_runq_add, &svc->flags);
}

static void
csched2_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = csched2_vcpu(vc);
    unsigned int cpu = vc->processor;
    s_time_t now;

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    ASSERT(!is_idle_vcpu(vc));

    if ( unlikely(curr_on_cpu(cpu) == vc) )
    {
        SCHED_STAT_CRANK(vcpu_wake_running);
        goto out;
    }

    if ( unlikely(vcpu_on_runq(svc)) )
    {
        SCHED_STAT_CRANK(vcpu_wake_onrunq);
        goto out;
    }

    if ( likely(vcpu_runnable(vc)) )
        SCHED_STAT_CRANK(vcpu_wake_runnable);
    else
        SCHED_STAT_CRANK(vcpu_wake_not_runnable);

    /* If the context hasn't been saved for this vcpu yet, we can't put it on
     * another runqueue.  Instead, we set a flag so that it will be put on the runqueue
     * after the context has been saved. */
    if ( unlikely(svc->flags & CSFLAG_scheduled) )
    {
        __set_bit(__CSFLAG_delayed_runq_add, &svc->flags);
        goto out;
    }

    /* Add into the new runqueue if necessary */
    if ( svc->rqd == NULL )
        runq_assign(ops, vc);
    else
        ASSERT(c2rqd(ops, vc->processor) == svc->rqd );

    now = NOW();

    update_load(ops, svc->rqd, svc, 1, now);
        
    /* Put the VCPU on the runq */
    runq_insert(ops, svc);
    runq_tickle(ops, svc, now);

out:
    return;
}

static void
csched2_vcpu_yield(const struct scheduler *ops, struct vcpu *v)
{
    struct csched2_vcpu * const svc = csched2_vcpu(v);

    __set_bit(__CSFLAG_vcpu_yield, &svc->flags);
}

static void
csched2_context_saved(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu * const svc = csched2_vcpu(vc);
    spinlock_t *lock = vcpu_schedule_lock_irq(vc);
    s_time_t now = NOW();
    LIST_HEAD(were_parked);

    BUG_ON( !is_idle_vcpu(vc) && svc->rqd != c2rqd(ops, vc->processor));
    ASSERT(is_idle_vcpu(vc) || svc->rqd == c2rqd(ops, vc->processor));

    /* This vcpu is now eligible to be put on the runqueue again */
    __clear_bit(__CSFLAG_scheduled, &svc->flags);

    if ( unlikely(has_cap(svc) && svc->budget > 0) )
        vcpu_return_budget(svc, &were_parked);

    /* If someone wants it on the runqueue, put it there. */
    /*
     * NB: We can get rid of CSFLAG_scheduled by checking for
     * vc->is_running and vcpu_on_runq(svc) here.  However,
     * since we're accessing the flags cacheline anyway,
     * it seems a bit pointless; especially as we have plenty of
     * bits free.
     */
    if ( __test_and_clear_bit(__CSFLAG_delayed_runq_add, &svc->flags)
         && likely(vcpu_runnable(vc)) )
    {
        ASSERT(!vcpu_on_runq(svc));

        runq_insert(ops, svc);
        runq_tickle(ops, svc, now);
    }
    else if ( !is_idle_vcpu(vc) )
        update_load(ops, svc->rqd, svc, -1, now);

    vcpu_schedule_unlock_irq(lock, vc);

    unpark_parked_vcpus(ops, &were_parked);
}

#define MAX_LOAD (STIME_MAX)
static int
csched2_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_private *prv = csched2_priv(ops);
    int i, min_rqi = -1, min_s_rqi = -1;
    unsigned int new_cpu, cpu = vc->processor;
    struct csched2_vcpu *svc = csched2_vcpu(vc);
    s_time_t min_avgload = MAX_LOAD, min_s_avgload = MAX_LOAD;
    bool has_soft;

    ASSERT(!cpumask_empty(&prv->active_queues));

    SCHED_STAT_CRANK(pick_cpu);

    /* Locking:
     * - Runqueue lock of vc->processor is already locked
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
    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    if ( !read_trylock(&prv->lock) )
    {
        /* We may be here because someone requested us to migrate. */
        __clear_bit(__CSFLAG_runq_migrate_request, &svc->flags);
        new_cpu = get_fallback_cpu(svc);
        /*
         * Tracing of runq and its load won't be accurate, since we could
         * not get the lock, but at least we will output the chosen pcpu.
         */
        goto out;
    }

    cpumask_and(cpumask_scratch_cpu(cpu), vc->cpu_hard_affinity,
                cpupool_domain_cpumask(vc->domain));

    /*
     * First check to see if we're here because someone else suggested a place
     * for us to move.
     */
    if ( __test_and_clear_bit(__CSFLAG_runq_migrate_request, &svc->flags) )
    {
        if ( unlikely(svc->migrate_rqd->id < 0) )
        {
            printk(XENLOG_WARNING "%s: target runqueue disappeared!\n",
                   __func__);
        }
        else if ( cpumask_intersects(cpumask_scratch_cpu(cpu),
                                     &svc->migrate_rqd->active) )
        {
            /*
             * If we've been asked to move to migrate_rqd, we should just do
             * that, which we actually do by returning one cpu from that runq.
             * There is no need to take care of soft affinity, as that will
             * happen in runq_tickle().
             */
            cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                        &svc->migrate_rqd->active);
            new_cpu = cpumask_cycle(svc->migrate_rqd->pick_bias,
                                    cpumask_scratch_cpu(cpu));

            svc->migrate_rqd->pick_bias = new_cpu;
            goto out_up;
        }
        /* Fall-through to normal cpu pick */
    }

    /*
     * What we want is:
     *  - if we have soft affinity, the runqueue with the lowest average
     *    load, among the ones that contain cpus in our soft affinity; this
     *    represents the best runq on which we would want to run.
     *  - the runqueue with the lowest average load among the ones that
     *    contains cpus in our hard affinity; this represent the best runq
     *    on which we can run.
     *
     * Find both runqueues in one pass.
     */
    has_soft = has_soft_affinity(vc, vc->cpu_hard_affinity);
    for_each_cpu(i, &prv->active_queues)
    {
        struct csched2_runqueue_data *rqd;
        s_time_t rqd_avgload = MAX_LOAD;

        rqd = prv->rqd + i;

        /*
         * If none of the cpus of this runqueue is in svc's hard-affinity,
         * skip the runqueue.
         *
         * Note that, in case svc's hard-affinity has changed, this is the
         * first time when we see such change, so it is indeed possible
         * that we end up skipping svc's current runqueue.
         */
        if ( !cpumask_intersects(cpumask_scratch_cpu(cpu), &rqd->active) )
            continue;

        /*
         * If checking a different runqueue, grab the lock, read the avg,
         * and then release the lock.
         *
         * If on our own runqueue, don't grab or release the lock;
         * but subtract our own load from the runqueue load to simulate
         * impartiality.
         */
        if ( rqd == svc->rqd )
        {
            rqd_avgload = max_t(s_time_t, rqd->b_avgload - svc->avgload, 0);
        }
        else if ( spin_trylock(&rqd->lock) )
        {
            rqd_avgload = rqd->b_avgload;
            spin_unlock(&rqd->lock);
        }

        /*
         * if svc has a soft-affinity, and some cpus of rqd are part of it,
         * see if we need to update the "soft-affinity minimum".
         */
        if ( has_soft &&
             rqd_avgload < min_s_avgload )
        {
            cpumask_t mask;

            cpumask_and(&mask, cpumask_scratch_cpu(cpu), &rqd->active);
            if ( cpumask_intersects(&mask, svc->vcpu->cpu_soft_affinity) )
            {
                min_s_avgload = rqd_avgload;
                min_s_rqi = i;
            }
        }
        /* In any case, keep the "hard-affinity minimum" updated too. */
        if ( rqd_avgload < min_avgload )
        {
            min_avgload = rqd_avgload;
            min_rqi = i;
        }
    }

    if ( has_soft && min_s_rqi != -1 )
    {
        /*
         * We have soft affinity, and we have a candidate runq, so go for it.
         *
         * Note that, to obtain the soft-affinity mask, we "just" put what we
         * have in cpumask_scratch in && with vc->cpu_soft_affinity. This is
         * ok because:
         * - we know that vc->cpu_hard_affinity and vc->cpu_soft_affinity have
         *   a non-empty intersection (because has_soft is true);
         * - we have vc->cpu_hard_affinity & cpupool_domain_cpumask() already
         *   in cpumask_scratch, we do save a lot doing like this.
         *
         * It's kind of like open coding affinity_balance_cpumask() but, in
         * this specific case, calling that would mean a lot of (unnecessary)
         * cpumask operations.
         */
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                    vc->cpu_soft_affinity);
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                    &prv->rqd[min_s_rqi].active);
    }
    else if ( min_rqi != -1 )
    {
        /*
         * Either we don't have soft-affinity, or we do, but we did not find
         * any suitable runq. But we did find one when considering hard
         * affinity, so go for it.
         *
         * cpumask_scratch already has vc->cpu_hard_affinity &
         * cpupool_domain_cpumask() in it, so it's enough that we filter
         * with the cpus of the runq.
         */
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                    &prv->rqd[min_rqi].active);
    }
    else
    {
        /*
         * We didn't find anyone at all (most likely because of spinlock
         * contention).
         */
        new_cpu = get_fallback_cpu(svc);
        min_rqi = c2r(new_cpu);
        min_avgload = prv->rqd[min_rqi].b_avgload;
        goto out_up;
    }

    new_cpu = cpumask_cycle(prv->rqd[min_rqi].pick_bias,
                            cpumask_scratch_cpu(cpu));
    prv->rqd[min_rqi].pick_bias = new_cpu;
    BUG_ON(new_cpu >= nr_cpu_ids);

 out_up:
    read_unlock(&prv->lock);
 out:
    if ( unlikely(tb_init_done) )
    {
        struct {
            uint64_t b_avgload;
            unsigned vcpu:16, dom:16;
            unsigned rq_id:16, new_cpu:16;
        } d;
        d.dom = vc->domain->domain_id;
        d.vcpu = vc->vcpu_id;
        d.rq_id = min_rqi;
        d.b_avgload = min_avgload;
        d.new_cpu = new_cpu;
        __trace_var(TRC_CSCHED2_PICKED_CPU, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

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
    int cpu = svc->vcpu->processor;

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            unsigned rqi:16, trqi:16;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.rqi = svc->rqd->id;
        d.trqi = trqd->id;
        __trace_var(TRC_CSCHED2_MIGRATE, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    if ( svc->flags & CSFLAG_scheduled )
    {
        /* It's running; mark it to migrate. */
        svc->migrate_rqd = trqd;
        __set_bit(_VPF_migrating, &svc->vcpu->pause_flags);
        __set_bit(__CSFLAG_runq_migrate_request, &svc->flags);
        SCHED_STAT_CRANK(migrate_requested);
        tickle_cpu(cpu, svc->rqd);
    }
    else
    {
        int on_runq = 0;
        /* It's not running; just move it */
        if ( vcpu_on_runq(svc) )
        {
            runq_remove(svc);
            update_load(ops, svc->rqd, NULL, -1, now);
            on_runq = 1;
        }
        _runq_deassign(svc);

        cpumask_and(cpumask_scratch_cpu(cpu), svc->vcpu->cpu_hard_affinity,
                    cpupool_domain_cpumask(svc->vcpu->domain));
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                    &trqd->active);
        svc->vcpu->processor = cpumask_cycle(trqd->pick_bias,
                                             cpumask_scratch_cpu(cpu));
        trqd->pick_bias = svc->vcpu->processor;
        ASSERT(svc->vcpu->processor < nr_cpu_ids);

        _runq_assign(svc, trqd);
        if ( on_runq )
        {
            update_load(ops, svc->rqd, NULL, 1, now);
            runq_insert(ops, svc);
            runq_tickle(ops, svc, now);
            SCHED_STAT_CRANK(migrate_on_runq);
        }
        else
            SCHED_STAT_CRANK(migrate_no_runq);
    }
}

/*
 * It makes sense considering migrating svc to rqd, if:
 *  - svc is not already flagged to migrate,
 *  - if svc is allowed to run on at least one of the pcpus of rqd.
 */
static bool vcpu_is_migrateable(struct csched2_vcpu *svc,
                                  struct csched2_runqueue_data *rqd)
{
    struct vcpu *v = svc->vcpu;
    int cpu = svc->vcpu->processor;

    cpumask_and(cpumask_scratch_cpu(cpu), v->cpu_hard_affinity,
                cpupool_domain_cpumask(v->domain));

    return !(svc->flags & CSFLAG_runq_migrate_request) &&
           cpumask_intersects(cpumask_scratch_cpu(cpu), &rqd->active);
}

static void balance_load(const struct scheduler *ops, int cpu, s_time_t now)
{
    struct csched2_private *prv = csched2_priv(ops);
    int i, max_delta_rqi = -1;
    struct list_head *push_iter, *pull_iter;
    bool inner_load_updated = 0;

    balance_state_t st = { .best_push_svc = NULL, .best_pull_svc = NULL };

    /*
     * Basic algorithm: Push, pull, or swap.
     * - Find the runqueue with the furthest load distance
     * - Find a pair that makes the difference the least (where one
     * on either side may be empty).
     */

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));
    st.lrqd = c2rqd(ops, cpu);

    update_runq_load(ops, st.lrqd, 0, now);

retry:
    if ( !read_trylock(&prv->lock) )
        return;

    st.load_delta = 0;

    for_each_cpu(i, &prv->active_queues)
    {
        s_time_t delta;
        
        st.orqd = prv->rqd + i;

        if ( st.orqd == st.lrqd
             || !spin_trylock(&st.orqd->lock) )
            continue;

        update_runq_load(ops, st.orqd, 0, now);
    
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

    /* Minimize holding the private scheduler lock. */
    read_unlock(&prv->lock);
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

        if ( unlikely(tb_init_done) )
        {
            struct {
                unsigned lrq_id:16, orq_id:16;
                unsigned load_delta;
            } d;
            d.lrq_id = st.lrqd->id;
            d.orq_id = st.orqd->id;
            d.load_delta = st.load_delta;
            __trace_var(TRC_CSCHED2_LOAD_CHECK, 1,
                        sizeof(d),
                        (unsigned char *)&d);
        }

        /*
         * If we're under 100% capacaty, only shift if load difference
         * is > 1.  otherwise, shift if under 12.5%
         */
        if ( load_max < ((s_time_t)cpus_max << prv->load_precision_shift) )
        {
            if ( st.load_delta < (1ULL << (prv->load_precision_shift +
                                           opt_underload_balance_tolerance)) )
                 goto out;
        }
        else
            if ( st.load_delta < (1ULL << (prv->load_precision_shift +
                                           opt_overload_balance_tolerance)) )
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

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint64_t lb_avgload, ob_avgload;
            unsigned lrq_id:16, orq_id:16;
        } d;
        d.lrq_id = st.lrqd->id;
        d.lb_avgload = st.lrqd->b_avgload;
        d.orq_id = st.orqd->id;
        d.ob_avgload = st.orqd->b_avgload;
        __trace_var(TRC_CSCHED2_LOAD_BALANCE, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    SCHED_STAT_CRANK(acct_load_balance);

    /* Look for "swap" which gives the best load average
     * FIXME: O(n^2)! */

    /* Reuse load delta (as we're trying to minimize it) */
    list_for_each( push_iter, &st.lrqd->svc )
    {
        struct csched2_vcpu * push_svc = list_entry(push_iter, struct csched2_vcpu, rqd_elem);

        update_svc_load(ops, push_svc, 0, now);

        if ( !vcpu_is_migrateable(push_svc, st.orqd) )
            continue;

        list_for_each( pull_iter, &st.orqd->svc )
        {
            struct csched2_vcpu * pull_svc = list_entry(pull_iter, struct csched2_vcpu, rqd_elem);
            
            if ( !inner_load_updated )
                update_svc_load(ops, pull_svc, 0, now);
        
            if ( !vcpu_is_migrateable(pull_svc, st.lrqd) )
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
        
        if ( !vcpu_is_migrateable(pull_svc, st.lrqd) )
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

static void
csched2_vcpu_migrate(
    const struct scheduler *ops, struct vcpu *vc, unsigned int new_cpu)
{
    struct domain *d = vc->domain;
    struct csched2_vcpu * const svc = csched2_vcpu(vc);
    struct csched2_runqueue_data *trqd;
    s_time_t now = NOW();

    /*
     * Being passed a target pCPU which is outside of our cpupool is only
     * valid if we are shutting down (or doing ACPI suspend), and we are
     * moving everyone to BSP, no matter whether or not BSP is inside our
     * cpupool.
     *
     * And since there indeed is the chance that it is not part of it, all
     * we must do is remove _and_ unassign the vCPU from any runqueue, as
     * well as updating v->processor with the target, so that the suspend
     * process can continue.
     *
     * It will then be during resume that a new, meaningful, value for
     * v->processor will be chosen, and during actual domain unpause that
     * the vCPU will be assigned to and added to the proper runqueue.
     */
    if ( unlikely(!cpumask_test_cpu(new_cpu, cpupool_domain_cpumask(d))) )
    {
        ASSERT(system_state == SYS_STATE_suspend);
        if ( vcpu_on_runq(svc) )
        {
            runq_remove(svc);
            update_load(ops, svc->rqd, NULL, -1, now);
        }
        _runq_deassign(svc);
        vc->processor = new_cpu;
        return;
    }

    /* If here, new_cpu must be a valid Credit2 pCPU, and in our affinity. */
    ASSERT(cpumask_test_cpu(new_cpu, &csched2_priv(ops)->initialized));
    ASSERT(cpumask_test_cpu(new_cpu, vc->cpu_hard_affinity));

    trqd = c2rqd(ops, new_cpu);

    /*
     * Do the actual movement toward new_cpu, and update vc->processor.
     * If we are changing runqueue, migrate() takes care of everything.
     * If we are not changing runqueue, we need to update vc->processor
     * here. In fact, if, for instance, we are here because the vcpu's
     * hard affinity changed, we don't want to risk leaving vc->processor
     * pointing to a pcpu where we can't run any longer.
     */
    if ( trqd != svc->rqd )
        migrate(ops, svc, trqd, now);
    else
        vc->processor = new_cpu;
}

static int
csched2_dom_cntl(
    const struct scheduler *ops,
    struct domain *d,
    struct xen_domctl_scheduler_op *op)
{
    struct csched2_dom * const sdom = csched2_dom(d);
    struct csched2_private *prv = csched2_priv(ops);
    unsigned long flags;
    struct vcpu *v;
    int rc = 0;

    /*
     * Locking:
     *  - we must take the private lock for accessing the weights of the
     *    vcpus of d, and/or the cap;
     *  - in the putinfo case, we also need the runqueue lock(s), for
     *    updating the max waight of the runqueue(s).
     *    If changing the cap, we also need the budget_lock, for updating
     *    the value of the domain budget pool (and the runqueue lock,
     *    for adjusting the parameters and rescheduling any vCPU that is
     *    running at the time of the change).
     */
    switch ( op->cmd )
    {
    case XEN_DOMCTL_SCHEDOP_getinfo:
        read_lock_irqsave(&prv->lock, flags);
        op->u.credit2.weight = sdom->weight;
        op->u.credit2.cap = sdom->cap;
        read_unlock_irqrestore(&prv->lock, flags);
        break;
    case XEN_DOMCTL_SCHEDOP_putinfo:
        write_lock_irqsave(&prv->lock, flags);
        /* Weight */
        if ( op->u.credit2.weight != 0 )
        {
            int old_weight;

            old_weight = sdom->weight;

            sdom->weight = op->u.credit2.weight;

            /* Update weights for vcpus, and max_weight for runqueues on which they reside */
            for_each_vcpu ( d, v )
            {
                struct csched2_vcpu *svc = csched2_vcpu(v);
                spinlock_t *lock = vcpu_schedule_lock(svc->vcpu);

                ASSERT(svc->rqd == c2rqd(ops, svc->vcpu->processor));

                svc->weight = sdom->weight;
                update_max_weight(svc->rqd, svc->weight, old_weight);

                vcpu_schedule_unlock(lock, svc->vcpu);
            }
        }
        /* Cap */
        if ( op->u.credit2.cap != 0 )
        {
            struct csched2_vcpu *svc;
            spinlock_t *lock;

            /* Cap is only valid if it's below 100 * nr_of_vCPUS */
            if ( op->u.credit2.cap > 100 * sdom->nr_vcpus )
            {
                rc = -EINVAL;
                write_unlock_irqrestore(&prv->lock, flags);
                break;
            }

            spin_lock(&sdom->budget_lock);
            sdom->tot_budget = (CSCHED2_BDGT_REPL_PERIOD * op->u.credit2.cap);
            sdom->tot_budget /= 100;
            spin_unlock(&sdom->budget_lock);

            /*
             * When trying to get some budget and run, each vCPU will grab
             * from the pool 1/N (with N = nr of vCPUs of the domain) of
             * the total budget. Roughly speaking, this means each vCPU will
             * have at least one chance to run during every period.
             */
            for_each_vcpu ( d, v )
            {
                svc = csched2_vcpu(v);
                lock = vcpu_schedule_lock(svc->vcpu);
                /*
                 * Too small quotas would in theory cause a lot of overhead,
                 * which then won't happen because, in csched2_runtime(),
                 * CSCHED2_MIN_TIMER is what would be used anyway.
                 */
                svc->budget_quota = max(sdom->tot_budget / sdom->nr_vcpus,
                                        CSCHED2_MIN_TIMER);
                vcpu_schedule_unlock(lock, svc->vcpu);
            }

            if ( sdom->cap == 0 )
            {
                /*
                 * We give to the domain the budget to which it is entitled,
                 * and queue its first replenishment event.
                 *
                 * Since cap is currently disabled for this domain, we
                 * know no vCPU is messing with the domain's budget, and
                 * the replenishment timer is still off.
                 * For these reasons, it is safe to do the following without
                 * taking the budget_lock.
                 */
                sdom->budget = sdom->tot_budget;
                sdom->next_repl = NOW() + CSCHED2_BDGT_REPL_PERIOD;
                set_timer(sdom->repl_timer, sdom->next_repl);

                /*
                 * Now, let's enable budget accounting for all the vCPUs.
                 * For making sure that they will start to honour the domain's
                 * cap, we set their budget to 0.
                 * This way, as soon as they will try to run, they will have
                 * to get some budget.
                 *
                 * For the vCPUs that are already running, we trigger the
                 * scheduler on their pCPU. When, as a consequence of this,
                 * csched2_schedule() will run, it will figure out there is
                 * no budget, and the vCPU will try to get some (and be parked,
                 * if there's none, and we'll switch to someone else).
                 */
                for_each_vcpu ( d, v )
                {
                    svc = csched2_vcpu(v);
                    lock = vcpu_schedule_lock(svc->vcpu);
                    if ( v->is_running )
                    {
                        unsigned int cpu = v->processor;
                        struct csched2_runqueue_data *rqd = c2rqd(ops, cpu);

                        ASSERT(curr_on_cpu(cpu) == v);

                        /*
                         * We are triggering a reschedule on the vCPU's
                         * pCPU. That will run burn_credits() and, since
                         * the vCPU is capped now, it would charge all the
                         * execution time of this last round as budget as
                         * well. That will make the vCPU budget go negative,
                         * potentially by a large amount, and it's unfair.
                         *
                         * To avoid that, call burn_credit() here, to do the
                         * accounting of this current running instance now,
                         * with budgetting still disabled. This does not
                         * prevent some small amount of budget being charged
                         * to the vCPU (i.e., the amount of time it runs from
                         * now, to when scheduling happens). The budget will
                         * also go below 0, but a lot less than how it would
                         * if we don't do this.
                         */
                        burn_credits(rqd, svc, NOW());
                        __cpumask_set_cpu(cpu, &rqd->tickled);
                        ASSERT(!cpumask_test_cpu(cpu, &rqd->smt_idle));
                        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
                    }
                    svc->budget = 0;
                    vcpu_schedule_unlock(lock, svc->vcpu);
                }
            }

            sdom->cap = op->u.credit2.cap;
        }
        else if ( sdom->cap != 0 )
        {
            LIST_HEAD(parked);

            stop_timer(sdom->repl_timer);

            /* Disable budget accounting for all the vCPUs. */
            for_each_vcpu ( d, v )
            {
                struct csched2_vcpu *svc = csched2_vcpu(v);
                spinlock_t *lock = vcpu_schedule_lock(svc->vcpu);

                svc->budget = STIME_MAX;
                svc->budget_quota = 0;

                vcpu_schedule_unlock(lock, svc->vcpu);
            }
            sdom->cap = 0;
            /*
             * We are disabling the cap for this domain, which may have
             * vCPUs waiting for a replenishment, so we unpark them all.
             * Note that, since we have already disabled budget accounting
             * for all the vCPUs of the domain, no currently running vCPU
             * will be added to the parked vCPUs list any longer.
             */
            spin_lock(&sdom->budget_lock);
            list_splice_init(&sdom->parked_vcpus, &parked);
            spin_unlock(&sdom->budget_lock);

            unpark_parked_vcpus(ops, &parked);
        }
        write_unlock_irqrestore(&prv->lock, flags);
        break;
    default:
        rc = -EINVAL;
        break;
    }


    return rc;
}

static int csched2_sys_cntl(const struct scheduler *ops,
                            struct xen_sysctl_scheduler_op *sc)
{
    struct xen_sysctl_credit2_schedule *params = &sc->u.sched_credit2;
    struct csched2_private *prv = csched2_priv(ops);
    unsigned long flags;

    switch (sc->cmd )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
        if ( params->ratelimit_us &&
             (params->ratelimit_us > XEN_SYSCTL_SCHED_RATELIMIT_MAX ||
              params->ratelimit_us < XEN_SYSCTL_SCHED_RATELIMIT_MIN ))
            return -EINVAL;

        write_lock_irqsave(&prv->lock, flags);
        if ( !prv->ratelimit_us && params->ratelimit_us )
            printk(XENLOG_INFO "Enabling context switch rate limiting\n");
        else if ( prv->ratelimit_us && !params->ratelimit_us )
            printk(XENLOG_INFO "Disabling context switch rate limiting\n");
        prv->ratelimit_us = params->ratelimit_us;
        write_unlock_irqrestore(&prv->lock, flags);

    /* FALLTHRU */
    case XEN_SYSCTL_SCHEDOP_getinfo:
        params->ratelimit_us = prv->ratelimit_us;
        break;
    }

    return 0;
}

static void *
csched2_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct csched2_private *prv = csched2_priv(ops);
    struct csched2_dom *sdom;
    unsigned long flags;

    sdom = xzalloc(struct csched2_dom);
    if ( sdom == NULL )
        return NULL;

    sdom->repl_timer = xzalloc(struct timer);
    if ( sdom->repl_timer == NULL )
    {
        xfree(sdom);
        return NULL;
    }

    /* Initialize credit, cap and weight */
    INIT_LIST_HEAD(&sdom->sdom_elem);
    sdom->dom = dom;
    sdom->weight = CSCHED2_DEFAULT_WEIGHT;
    sdom->cap = 0U;
    sdom->nr_vcpus = 0;

    init_timer(sdom->repl_timer, replenish_domain_budget, sdom,
               cpumask_any(cpupool_domain_cpumask(dom)));
    spin_lock_init(&sdom->budget_lock);
    INIT_LIST_HEAD(&sdom->parked_vcpus);

    write_lock_irqsave(&prv->lock, flags);

    list_add_tail(&sdom->sdom_elem, &csched2_priv(ops)->sdom);

    write_unlock_irqrestore(&prv->lock, flags);

    return (void *)sdom;
}

static int
csched2_dom_init(const struct scheduler *ops, struct domain *dom)
{
    struct csched2_dom *sdom;

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
    struct csched2_private *prv = csched2_priv(ops);

    kill_timer(sdom->repl_timer);

    write_lock_irqsave(&prv->lock, flags);

    list_del_init(&sdom->sdom_elem);

    write_unlock_irqrestore(&prv->lock, flags);

    xfree(sdom->repl_timer);
    xfree(data);
}

static void
csched2_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    ASSERT(csched2_dom(dom)->nr_vcpus == 0);

    csched2_free_domdata(ops, csched2_dom(dom));
}

static void
csched2_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched2_vcpu *svc = vc->sched_priv;
    struct csched2_dom * const sdom = svc->sdom;
    spinlock_t *lock;

    ASSERT(!is_idle_vcpu(vc));
    ASSERT(list_empty(&svc->runq_elem));

    /* csched2_cpu_pick() expects the pcpu lock to be held */
    lock = vcpu_schedule_lock_irq(vc);

    vc->processor = csched2_cpu_pick(ops, vc);

    spin_unlock_irq(lock);

    lock = vcpu_schedule_lock_irq(vc);

    /* Add vcpu to runqueue of initial processor */
    runq_assign(ops, vc);

    vcpu_schedule_unlock_irq(lock, vc);

    sdom->nr_vcpus++;

    SCHED_STAT_CRANK(vcpu_insert);

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
    struct csched2_vcpu * const svc = csched2_vcpu(vc);
    spinlock_t *lock;

    ASSERT(!is_idle_vcpu(vc));
    ASSERT(list_empty(&svc->runq_elem));

    SCHED_STAT_CRANK(vcpu_remove);

    /* Remove from runqueue */
    lock = vcpu_schedule_lock_irq(vc);

    runq_deassign(ops, vc);

    vcpu_schedule_unlock_irq(lock, vc);

    svc->sdom->nr_vcpus--;
}

/* How long should we let this vcpu run for? */
static s_time_t
csched2_runtime(const struct scheduler *ops, int cpu,
                struct csched2_vcpu *snext, s_time_t now)
{
    s_time_t time, min_time;
    int rt_credit; /* Proposed runtime measured in credits */
    struct csched2_runqueue_data *rqd = c2rqd(ops, cpu);
    struct list_head *runq = &rqd->runq;
    struct csched2_private *prv = csched2_priv(ops);

    /*
     * If we're idle, just stay so. Others (or external events)
     * will poke us when necessary.
     */
    if ( is_idle_vcpu(snext->vcpu) )
        return -1;

    /* General algorithm:
     * 1) Run until snext's credit will be 0.
     * 2) But if someone is waiting, run until snext's credit is equal
     *    to his.
     * 3) But, if we are capped, never run more than our budget.
     * 4) And never run longer than MAX_TIMER or shorter than MIN_TIMER or
     *    the ratelimit time.
     */

    /* Calculate mintime */
    min_time = CSCHED2_MIN_TIMER;
    if ( prv->ratelimit_us )
    {
        s_time_t ratelimit_min = MICROSECS(prv->ratelimit_us);
        if ( snext->vcpu->is_running )
            ratelimit_min = snext->vcpu->runstate.state_entry_time +
                            MICROSECS(prv->ratelimit_us) - now;
        if ( ratelimit_min > min_time )
            min_time = ratelimit_min;
    }

    /* 1) Run until snext's credit will be 0. */
    rt_credit = snext->credit;

    /*
     * 2) If there's someone waiting whose credit is positive,
     *    run until your credit ~= his.
     */
    if ( ! list_empty(runq) )
    {
        struct csched2_vcpu *swait = runq_elem(runq->next);

        if ( ! is_idle_vcpu(swait->vcpu)
             && swait->credit > 0 )
        {
            rt_credit = snext->credit - swait->credit;
        }
    }

    /*
     * The next guy on the runqueue may actually have a higher credit,
     * if we've tried to avoid migrating him from a different cpu.
     * Setting time=0 will ensure the minimum timeslice is chosen.
     *
     * FIXME: See if we can eliminate this conversion if we know time
     * will be outside (MIN,MAX).  Probably requires pre-calculating
     * credit values of MIN,MAX per vcpu, since each vcpu burns credit
     * at a different rate.
     */
    if ( rt_credit > 0 )
        time = c2t(rqd, rt_credit, snext);
    else
        time = 0;

    /*
     * 3) But, if capped, never run more than our budget.
     */
    if ( has_cap(snext) )
        time = snext->budget < time ? snext->budget : time;

    /*
     * 4) And never run longer than MAX_TIMER or less than MIN_TIMER or
     *    the rate_limit time.
     */
    if ( time < min_time )
    {
        time = min_time;
        SCHED_STAT_CRANK(runtime_min_timer);
    }
    else if (time > CSCHED2_MAX_TIMER)
    {
        time = CSCHED2_MAX_TIMER;
        SCHED_STAT_CRANK(runtime_max_timer);
    }

    return time;
}

/*
 * Find a candidate.
 */
static struct csched2_vcpu *
runq_candidate(struct csched2_runqueue_data *rqd,
               struct csched2_vcpu *scurr,
               int cpu, s_time_t now,
               unsigned int *skipped)
{
    struct list_head *iter, *temp;
    struct csched2_vcpu *snext = NULL;
    struct csched2_private *prv = csched2_priv(per_cpu(scheduler, cpu));
    bool yield = false, soft_aff_preempt = false;

    *skipped = 0;

    if ( unlikely(is_idle_vcpu(scurr->vcpu)) )
    {
        snext = scurr;
        goto check_runq;
    }

    yield = __test_and_clear_bit(__CSFLAG_vcpu_yield, &scurr->flags);

    /*
     * Return the current vcpu if it has executed for less than ratelimit.
     * Adjuststment for the selected vcpu's credit and decision
     * for how long it will run will be taken in csched2_runtime.
     *
     * Note that, if scurr is yielding, we don't let rate limiting kick in.
     * In fact, it may be the case that scurr is about to spin, and there's
     * no point forcing it to do so until rate limiting expires.
     */
    if ( !yield && prv->ratelimit_us && vcpu_runnable(scurr->vcpu) &&
         (now - scurr->vcpu->runstate.state_entry_time) <
          MICROSECS(prv->ratelimit_us) )
    {
        if ( unlikely(tb_init_done) )
        {
            struct {
                unsigned vcpu:16, dom:16;
                unsigned runtime;
            } d;
            d.dom = scurr->vcpu->domain->domain_id;
            d.vcpu = scurr->vcpu->vcpu_id;
            d.runtime = now - scurr->vcpu->runstate.state_entry_time;
            __trace_var(TRC_CSCHED2_RATELIMIT, 1,
                        sizeof(d),
                        (unsigned char *)&d);
        }
        return scurr;
    }

    /* If scurr has a soft-affinity, let's check whether cpu is part of it */
    if ( has_soft_affinity(scurr->vcpu, scurr->vcpu->cpu_hard_affinity) )
    {
        affinity_balance_cpumask(scurr->vcpu, BALANCE_SOFT_AFFINITY,
                                 cpumask_scratch);
        if ( unlikely(!cpumask_test_cpu(cpu, cpumask_scratch)) )
        {
            cpumask_t *online = cpupool_domain_cpumask(scurr->vcpu->domain);

            /* Ok, is any of the pcpus in scurr soft-affinity idle? */
            cpumask_and(cpumask_scratch, cpumask_scratch, &rqd->idle);
            cpumask_andnot(cpumask_scratch, cpumask_scratch, &rqd->tickled);
            soft_aff_preempt = cpumask_intersects(cpumask_scratch, online);
        }
    }

    /*
     * If scurr is runnable, and this cpu is in its soft-affinity, default to
     * it. We also default to it, even if cpu is not in its soft-affinity, if
     * there aren't any idle and not tickled cpu in its soft-affinity. In
     * fact, we don't want to risk leaving scurr in the runq and this cpu idle
     * only because scurr is running outside of its soft-affinity.
     *
     * On the other hand, if cpu is not in scurr's soft-affinity, and there
     * looks to be better options, go for them. That happens by defaulting to
     * idle here, which means scurr will be preempted, put back in runq, and
     * one of those idle and not tickled cpus from its soft-affinity will be
     * tickled to pick it up.
     *
     * Finally, if scurr does not have a valid soft-affinity, we also let it
     * continue to run here (in fact, soft_aff_preempt will still be false,
     * in this case).
     *
     * Of course, we also default to idle also if scurr is not runnable.
     */
    if ( vcpu_runnable(scurr->vcpu) && !soft_aff_preempt )
        snext = scurr;
    else
        snext = csched2_vcpu(idle_vcpu[cpu]);

 check_runq:
    list_for_each_safe( iter, temp, &rqd->runq )
    {
        struct csched2_vcpu * svc = list_entry(iter, struct csched2_vcpu, runq_elem);

        if ( unlikely(tb_init_done) )
        {
            struct {
                unsigned vcpu:16, dom:16;
            } d;
            d.dom = svc->vcpu->domain->domain_id;
            d.vcpu = svc->vcpu->vcpu_id;
            __trace_var(TRC_CSCHED2_RUNQ_CAND_CHECK, 1,
                        sizeof(d),
                        (unsigned char *)&d);
        }

        /* Only consider vcpus that are allowed to run on this processor. */
        if ( !cpumask_test_cpu(cpu, svc->vcpu->cpu_hard_affinity) )
        {
            (*skipped)++;
            continue;
        }

        /*
         * If a vcpu is meant to be picked up by another processor, and such
         * processor has not scheduled yet, leave it in the runqueue for him.
         */
        if ( svc->tickled_cpu != -1 && svc->tickled_cpu != cpu &&
             cpumask_test_cpu(svc->tickled_cpu, &rqd->tickled) )
        {
            (*skipped)++;
            SCHED_STAT_CRANK(deferred_to_tickled_cpu);
            continue;
        }

        /*
         * If this is on a different processor, don't pull it unless
         * its credit is at least CSCHED2_MIGRATE_RESIST higher.
         */
        if ( svc->vcpu->processor != cpu
             && snext->credit + CSCHED2_MIGRATE_RESIST > svc->credit )
        {
            (*skipped)++;
            SCHED_STAT_CRANK(migrate_resisted);
            continue;
        }

        /*
         * If the one in the runqueue has more credit than current (or idle,
         * if current is not runnable), or if current is yielding, and also
         * if the one in runqueue either is not capped, or is capped but has
         * some budget, then choose it.
         */
        if ( (yield || svc->credit > snext->credit) &&
             (!has_cap(svc) || vcpu_grab_budget(svc)) )
            snext = svc;

        /* In any case, if we got this far, break. */
        break;
    }

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned vcpu:16, dom:16;
            unsigned tickled_cpu, skipped;
            int credit;
        } d;
        d.dom = snext->vcpu->domain->domain_id;
        d.vcpu = snext->vcpu->vcpu_id;
        d.credit = snext->credit;
        d.tickled_cpu = snext->tickled_cpu;
        d.skipped = *skipped;
        __trace_var(TRC_CSCHED2_RUNQ_CANDIDATE, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    if ( unlikely(snext->tickled_cpu != -1 && snext->tickled_cpu != cpu) )
        SCHED_STAT_CRANK(tickled_cpu_overridden);

    /*
     * If snext is from a capped domain, it must have budget (or it
     * wouldn't have been in the runq). If it is not, it'd be STIME_MAX,
     * which still is >= 0.
     */
    ASSERT(snext->budget >= 0);

    return snext;
}

/*
 * This function is in the critical path. It is designed to be simple and
 * fast for the common case.
 */
static struct task_slice
csched2_schedule(
    const struct scheduler *ops, s_time_t now, bool tasklet_work_scheduled)
{
    const int cpu = smp_processor_id();
    struct csched2_runqueue_data *rqd;
    struct csched2_vcpu * const scurr = csched2_vcpu(current);
    struct csched2_vcpu *snext = NULL;
    unsigned int skipped_vcpus = 0;
    struct task_slice ret;
    bool tickled;

    SCHED_STAT_CRANK(schedule);
    CSCHED2_VCPU_CHECK(current);

    BUG_ON(!cpumask_test_cpu(cpu, &csched2_priv(ops)->initialized));

    rqd = c2rqd(ops, cpu);
    BUG_ON(!cpumask_test_cpu(cpu, &rqd->active));

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    BUG_ON(!is_idle_vcpu(scurr->vcpu) && scurr->rqd != rqd);

    /* Clear "tickled" bit now that we've been scheduled */
    tickled = cpumask_test_cpu(cpu, &rqd->tickled);
    if ( tickled )
    {
        __cpumask_clear_cpu(cpu, &rqd->tickled);
        cpumask_andnot(cpumask_scratch, &rqd->idle, &rqd->tickled);
        smt_idle_mask_set(cpu, cpumask_scratch, &rqd->smt_idle);
    }

    if ( unlikely(tb_init_done) )
    {
        struct {
            unsigned cpu:16, rq_id:16;
            unsigned tasklet:8, idle:8, smt_idle:8, tickled:8;
        } d;
        d.cpu = cpu;
        d.rq_id = c2r(cpu);
        d.tasklet = tasklet_work_scheduled;
        d.idle = is_idle_vcpu(current);
        d.smt_idle = cpumask_test_cpu(cpu, &rqd->smt_idle);
        d.tickled = tickled;
        __trace_var(TRC_CSCHED2_SCHEDULE, 1,
                    sizeof(d),
                    (unsigned char *)&d);
    }

    /* Update credits (and budget, if necessary). */
    burn_credits(rqd, scurr, now);

    /*
     *  Below 0, means that we are capped and we have overrun our  budget.
     *  Let's try to get some more but, if we fail (e.g., because of the
     *  other running vcpus), we will be parked.
     */
    if ( unlikely(scurr->budget <= 0) )
        vcpu_grab_budget(scurr);

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
        __clear_bit(__CSFLAG_vcpu_yield, &scurr->flags);
        trace_var(TRC_CSCHED2_SCHED_TASKLET, 1, 0, NULL);
        snext = csched2_vcpu(idle_vcpu[cpu]);
    }
    else
        snext = runq_candidate(rqd, scurr, cpu, now, &skipped_vcpus);

    /* If switching from a non-idle runnable vcpu, put it
     * back on the runqueue. */
    if ( snext != scurr
         && !is_idle_vcpu(scurr->vcpu)
         && vcpu_runnable(current) )
        __set_bit(__CSFLAG_delayed_runq_add, &scurr->flags);

    ret.migrated = 0;

    /* Accounting for non-idle tasks */
    if ( !is_idle_vcpu(snext->vcpu) )
    {
        /* If switching, remove this from the runqueue and mark it scheduled */
        if ( snext != scurr )
        {
            ASSERT(snext->rqd == rqd);
            ASSERT(!snext->vcpu->is_running);

            runq_remove(snext);
            __set_bit(__CSFLAG_scheduled, &snext->flags);
        }

        /*
         * The reset condition is "has a scheduler epoch come to an end?".
         * The way this is enforced is checking whether the vcpu at the top
         * of the runqueue has negative credits. This means the epochs have
         * variable length, as in one epoch expores when:
         *  1) the vcpu at the top of the runqueue has executed for
         *     around 10 ms (with default parameters);
         *  2) no other vcpu with higher credits wants to run.
         *
         * Here, where we want to check for reset, we need to make sure the
         * proper vcpu is being used. In fact, runqueue_candidate() may have
         * not returned the first vcpu in the runqueue, for various reasons
         * (e.g., affinity). Only trigger a reset when it does.
         */
        if ( skipped_vcpus == 0 && snext->credit <= CSCHED2_CREDIT_RESET )
        {
            reset_credit(ops, cpu, now, snext);
            balance_load(ops, cpu, now);
        }

        /* Clear the idle mask if necessary */
        if ( cpumask_test_cpu(cpu, &rqd->idle) )
        {
            __cpumask_clear_cpu(cpu, &rqd->idle);
            smt_idle_mask_clear(cpu, &rqd->smt_idle);
        }

        snext->start_time = now;
        snext->tickled_cpu = -1;

        /* Safe because lock for old processor is held */
        if ( snext->vcpu->processor != cpu )
        {
            snext->credit += CSCHED2_MIGRATE_COMPENSATION;
            snext->vcpu->processor = cpu;
            SCHED_STAT_CRANK(migrated);
            ret.migrated = 1;
        }
    }
    else
    {
        /*
         * Update the idle mask if necessary. Note that, if we're scheduling
         * idle in order to carry on some tasklet work, we want to play busy!
         */
        if ( tasklet_work_scheduled )
        {
            if ( cpumask_test_cpu(cpu, &rqd->idle) )
            {
                __cpumask_clear_cpu(cpu, &rqd->idle);
                smt_idle_mask_clear(cpu, &rqd->smt_idle);
            }
        }
        else if ( !cpumask_test_cpu(cpu, &rqd->idle) )
        {
            __cpumask_set_cpu(cpu, &rqd->idle);
            cpumask_andnot(cpumask_scratch, &rqd->idle, &rqd->tickled);
            smt_idle_mask_set(cpu, cpumask_scratch, &rqd->smt_idle);
        }
        /* Make sure avgload gets updated periodically even
         * if there's no activity */
        update_load(ops, rqd, NULL, 0, now);
    }

    /*
     * Return task to run next...
     */
    ret.time = csched2_runtime(ops, cpu, snext, now);
    ret.task = snext->vcpu;

    CSCHED2_VCPU_CHECK(ret.task);
    return ret;
}

static void
csched2_dump_vcpu(struct csched2_private *prv, struct csched2_vcpu *svc)
{
    printk("[%i.%i] flags=%x cpu=%i",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id,
            svc->flags,
            svc->vcpu->processor);

    printk(" credit=%" PRIi32" [w=%u]", svc->credit, svc->weight);

    if ( has_cap(svc) )
        printk(" budget=%"PRI_stime"(%"PRI_stime")",
               svc->budget, svc->budget_quota);

    printk(" load=%"PRI_stime" (~%"PRI_stime"%%)", svc->avgload,
           (svc->avgload * 100) >> prv->load_precision_shift);

    printk("\n");
}

static inline void
dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct csched2_private *prv = csched2_priv(ops);
    struct csched2_vcpu *svc;
#define cpustr keyhandler_scratch

    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_sibling_mask, cpu));
    printk("CPU[%02d] runq=%d, sibling=%s, ", cpu, c2r(cpu), cpustr);
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_core_mask, cpu));
    printk("core=%s\n", cpustr);

    /* current VCPU (nothing to say if that's the idle vcpu) */
    svc = csched2_vcpu(curr_on_cpu(cpu));
    if ( svc && !is_idle_vcpu(svc->vcpu) )
    {
        printk("\trun: ");
        csched2_dump_vcpu(prv, svc);
    }
#undef cpustr
}

static void
csched2_dump(const struct scheduler *ops)
{
    struct list_head *iter_sdom;
    struct csched2_private *prv = csched2_priv(ops);
    unsigned long flags;
    unsigned int i, j, loop;
#define cpustr keyhandler_scratch

    /*
     * We need the private scheduler lock as we access global
     * scheduler data and (below) the list of active domains.
     */
    read_lock_irqsave(&prv->lock, flags);

    printk("Active queues: %d\n"
           "\tdefault-weight     = %d\n",
           cpumask_weight(&prv->active_queues),
           CSCHED2_DEFAULT_WEIGHT);
    for_each_cpu(i, &prv->active_queues)
    {
        s_time_t fraction;

        fraction = (prv->rqd[i].avgload * 100) >> prv->load_precision_shift;

        cpulist_scnprintf(cpustr, sizeof(cpustr), &prv->rqd[i].active);
        printk("Runqueue %d:\n"
               "\tncpus              = %u\n"
               "\tcpus               = %s\n"
               "\tmax_weight         = %u\n"
               "\tpick_bias          = %u\n"
               "\tinstload           = %d\n"
               "\taveload            = %"PRI_stime" (~%"PRI_stime"%%)\n",
               i,
               cpumask_weight(&prv->rqd[i].active),
               cpustr,
               prv->rqd[i].max_weight,
               prv->rqd[i].pick_bias,
               prv->rqd[i].load,
               prv->rqd[i].avgload,
               fraction);

        cpumask_scnprintf(cpustr, sizeof(cpustr), &prv->rqd[i].idle);
        printk("\tidlers: %s\n", cpustr);
        cpumask_scnprintf(cpustr, sizeof(cpustr), &prv->rqd[i].tickled);
        printk("\ttickled: %s\n", cpustr);
        cpumask_scnprintf(cpustr, sizeof(cpustr), &prv->rqd[i].smt_idle);
        printk("\tfully idle cores: %s\n", cpustr);
    }

    printk("Domain info:\n");
    loop = 0;
    list_for_each( iter_sdom, &prv->sdom )
    {
        struct csched2_dom *sdom;
        struct vcpu *v;

        sdom = list_entry(iter_sdom, struct csched2_dom, sdom_elem);

        printk("\tDomain: %d w %d c %u v %d\n",
               sdom->dom->domain_id,
               sdom->weight,
               sdom->cap,
               sdom->nr_vcpus);

        for_each_vcpu( sdom->dom, v )
        {
            struct csched2_vcpu * const svc = csched2_vcpu(v);
            spinlock_t *lock;

            lock = vcpu_schedule_lock(svc->vcpu);

            printk("\t%3d: ", ++loop);
            csched2_dump_vcpu(prv, svc);

            vcpu_schedule_unlock(lock, svc->vcpu);
        }
    }

    for_each_cpu(i, &prv->active_queues)
    {
        struct csched2_runqueue_data *rqd = prv->rqd + i;
        struct list_head *iter, *runq = &rqd->runq;
        int loop = 0;

        /* We need the lock to scan the runqueue. */
        spin_lock(&rqd->lock);

        printk("Runqueue %d:\n", i);

        for_each_cpu(j, &rqd->active)
            dump_pcpu(ops, j);

        printk("RUNQ:\n");
        list_for_each( iter, runq )
        {
            struct csched2_vcpu *svc = runq_elem(iter);

            if ( svc )
            {
                printk("\t%3d: ", loop++);
                csched2_dump_vcpu(prv, svc);
            }
        }
        spin_unlock(&rqd->lock);
    }

    read_unlock_irqrestore(&prv->lock, flags);
#undef cpustr
}

/* Returns the ID of the runqueue the cpu is assigned to. */
static unsigned
init_pdata(struct csched2_private *prv, unsigned int cpu)
{
    unsigned rqi;
    struct csched2_runqueue_data *rqd;

    ASSERT(rw_is_write_locked(&prv->lock));
    ASSERT(!cpumask_test_cpu(cpu, &prv->initialized));

    /* Figure out which runqueue to put it in */
    rqi = cpu_to_runqueue(prv, cpu);

    rqd = prv->rqd + rqi;

    printk(XENLOG_INFO "Adding cpu %d to runqueue %d\n", cpu, rqi);
    if ( ! cpumask_test_cpu(rqi, &prv->active_queues) )
    {
        printk(XENLOG_INFO " First cpu on runqueue, activating\n");
        activate_runqueue(prv, rqi);
    }
    
    /* Set the runqueue map */
    per_cpu(runq_map, cpu) = rqi;
    
    __cpumask_set_cpu(cpu, &rqd->idle);
    __cpumask_set_cpu(cpu, &rqd->active);
    __cpumask_set_cpu(cpu, &prv->initialized);
    __cpumask_set_cpu(cpu, &rqd->smt_idle);

    if ( cpumask_weight(&rqd->active) == 1 )
        rqd->pick_bias = cpu;

    return rqi;
}

static void
csched2_init_pdata(const struct scheduler *ops, void *pdata, int cpu)
{
    struct csched2_private *prv = csched2_priv(ops);
    spinlock_t *old_lock;
    unsigned long flags;
    unsigned rqi;

    /*
     * pdata contains what alloc_pdata returned. But since we don't (need to)
     * implement alloc_pdata, either that's NULL, or something is very wrong!
     */
    ASSERT(!pdata);

    write_lock_irqsave(&prv->lock, flags);
    old_lock = pcpu_schedule_lock(cpu);

    rqi = init_pdata(prv, cpu);
    /* Move the scheduler lock to the new runq lock. */
    per_cpu(schedule_data, cpu).schedule_lock = &prv->rqd[rqi].lock;

    /* _Not_ pcpu_schedule_unlock(): schedule_lock may have changed! */
    spin_unlock(old_lock);
    write_unlock_irqrestore(&prv->lock, flags);
}

/* Change the scheduler of cpu to us (Credit2). */
static void
csched2_switch_sched(struct scheduler *new_ops, unsigned int cpu,
                     void *pdata, void *vdata)
{
    struct csched2_private *prv = csched2_priv(new_ops);
    struct csched2_vcpu *svc = vdata;
    unsigned rqi;

    ASSERT(!pdata && svc && is_idle_vcpu(svc->vcpu));

    /*
     * We own one runqueue lock already (from schedule_cpu_switch()). This
     * looks like it violates this scheduler's locking rules, but it does
     * not, as what we own is the lock of another scheduler, that hence has
     * no particular (ordering) relationship with our private global lock.
     * And owning exactly that one (the lock of the old scheduler of this
     * cpu) is what is necessary to prevent races.
     */
    ASSERT(!local_irq_is_enabled());
    write_lock(&prv->lock);

    idle_vcpu[cpu]->sched_priv = vdata;

    rqi = init_pdata(prv, cpu);

    /*
     * Now that we know what runqueue we'll go in, double check what's said
     * above: the lock we already hold is not the one of this runqueue of
     * this scheduler, and so it's safe to have taken it /before/ our
     * private global lock.
     */
    ASSERT(per_cpu(schedule_data, cpu).schedule_lock != &prv->rqd[rqi].lock);

    per_cpu(scheduler, cpu) = new_ops;
    per_cpu(schedule_data, cpu).sched_priv = NULL; /* no pdata */

    /*
     * (Re?)route the lock to the per pCPU lock as /last/ thing. In fact,
     * if it is free (and it can be) we want that anyone that manages
     * taking it, find all the initializations we've done above in place.
     */
    smp_mb();
    per_cpu(schedule_data, cpu).schedule_lock = &prv->rqd[rqi].lock;

    write_unlock(&prv->lock);
}

static void
csched2_deinit_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    unsigned long flags;
    struct csched2_private *prv = csched2_priv(ops);
    struct csched2_runqueue_data *rqd;
    int rqi;

    write_lock_irqsave(&prv->lock, flags);

    /*
     * alloc_pdata is not implemented, so pcpu must be NULL. On the other
     * hand, init_pdata must have been called for this pCPU.
     */
    ASSERT(!pcpu && cpumask_test_cpu(cpu, &prv->initialized));
    
    /* Find the old runqueue and remove this cpu from it */
    rqi = per_cpu(runq_map, cpu);

    rqd = prv->rqd + rqi;

    /* No need to save IRQs here, they're already disabled */
    spin_lock(&rqd->lock);

    printk(XENLOG_INFO "Removing cpu %d from runqueue %d\n", cpu, rqi);

    __cpumask_clear_cpu(cpu, &rqd->idle);
    __cpumask_clear_cpu(cpu, &rqd->smt_idle);
    __cpumask_clear_cpu(cpu, &rqd->active);

    if ( cpumask_empty(&rqd->active) )
    {
        printk(XENLOG_INFO " No cpus left on runqueue, disabling\n");
        deactivate_runqueue(prv, rqi);
    }
    else if ( rqd->pick_bias == cpu )
        rqd->pick_bias = cpumask_first(&rqd->active);

    per_cpu(runq_map, cpu) = -1;

    spin_unlock(&rqd->lock);

    __cpumask_clear_cpu(cpu, &prv->initialized);

    write_unlock_irqrestore(&prv->lock, flags);

    return;
}

static int
csched2_init(struct scheduler *ops)
{
    int i;
    struct csched2_private *prv;

    printk("Initializing Credit2 scheduler\n");

    printk(XENLOG_INFO " load_precision_shift: %d\n"
           XENLOG_INFO " load_window_shift: %d\n"
           XENLOG_INFO " underload_balance_tolerance: %d\n"
           XENLOG_INFO " overload_balance_tolerance: %d\n"
           XENLOG_INFO " runqueues arrangement: %s\n"
           XENLOG_INFO " cap enforcement granularity: %dms\n",
           opt_load_precision_shift,
           opt_load_window_shift,
           opt_underload_balance_tolerance,
           opt_overload_balance_tolerance,
           opt_runqueue_str[opt_runqueue],
           opt_cap_period);

    if ( opt_load_precision_shift < LOADAVG_PRECISION_SHIFT_MIN )
    {
        printk("WARNING: %s: opt_load_precision_shift %d below min %d, resetting\n",
               __func__, opt_load_precision_shift, LOADAVG_PRECISION_SHIFT_MIN);
        opt_load_precision_shift = LOADAVG_PRECISION_SHIFT_MIN;
    }

    if ( opt_load_window_shift <= LOADAVG_GRANULARITY_SHIFT )
    {
        printk("WARNING: %s: opt_load_window_shift %d too short, resetting\n",
               __func__, opt_load_window_shift);
        opt_load_window_shift = LOADAVG_WINDOW_SHIFT;
    }
    printk(XENLOG_INFO "load tracking window length %llu ns\n",
           1ULL << opt_load_window_shift);

    if ( CSCHED2_BDGT_REPL_PERIOD < CSCHED2_MIN_TIMER )
    {
        printk("WARNING: %s: opt_cap_period %d too small, resetting\n",
               __func__, opt_cap_period);
        opt_cap_period = 10; /* ms */
    }

    /*
     * Basically no CPU information is available at this point; just
     * set up basic structures, and a callback when the CPU info is
     * available.
     */

    prv = xzalloc(struct csched2_private);
    if ( prv == NULL )
        return -ENOMEM;
    ops->sched_data = prv;

    rwlock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->sdom);

    /* Allocate all runqueues and mark them as un-initialized */
    prv->rqd = xzalloc_array(struct csched2_runqueue_data, nr_cpu_ids);
    if ( !prv->rqd )
    {
        xfree(prv);
        return -ENOMEM;
    }
    for ( i = 0; i < nr_cpu_ids; i++ )
        prv->rqd[i].id = -1;

    /* initialize ratelimit */
    prv->ratelimit_us = sched_ratelimit_us;

    prv->load_precision_shift = opt_load_precision_shift;
    prv->load_window_shift = opt_load_window_shift - LOADAVG_GRANULARITY_SHIFT;
    ASSERT(opt_load_window_shift > 0);

    return 0;
}

static void
csched2_deinit(struct scheduler *ops)
{
    struct csched2_private *prv;

    prv = csched2_priv(ops);
    ops->sched_data = NULL;
    xfree(prv);
}

static const struct scheduler sched_credit2_def = {
    .name           = "SMP Credit Scheduler rev2",
    .opt_name       = "credit2",
    .sched_id       = XEN_SCHEDULER_CREDIT2,
    .sched_data     = NULL,

    .init_domain    = csched2_dom_init,
    .destroy_domain = csched2_dom_destroy,

    .insert_vcpu    = csched2_vcpu_insert,
    .remove_vcpu    = csched2_vcpu_remove,

    .sleep          = csched2_vcpu_sleep,
    .wake           = csched2_vcpu_wake,
    .yield          = csched2_vcpu_yield,

    .adjust         = csched2_dom_cntl,
    .adjust_global  = csched2_sys_cntl,

    .pick_cpu       = csched2_cpu_pick,
    .migrate        = csched2_vcpu_migrate,
    .do_schedule    = csched2_schedule,
    .context_saved  = csched2_context_saved,

    .dump_settings  = csched2_dump,
    .init           = csched2_init,
    .deinit         = csched2_deinit,
    .alloc_vdata    = csched2_alloc_vdata,
    .free_vdata     = csched2_free_vdata,
    .init_pdata     = csched2_init_pdata,
    .deinit_pdata   = csched2_deinit_pdata,
    .switch_sched   = csched2_switch_sched,
    .alloc_domdata  = csched2_alloc_domdata,
    .free_domdata   = csched2_free_domdata,
};

REGISTER_SCHEDULER(sched_credit2_def);
