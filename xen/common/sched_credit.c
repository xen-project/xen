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
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/atomic.h>


/*
 * CSCHED_STATS
 *
 * Manage very basic counters and stats.
 *
 * Useful for debugging live systems. The stats are displayed
 * with runq dumps ('r' on the Xen console).
 */
#define CSCHED_STATS


/*
 * Basic constants
 */
#define CSCHED_TICK             10      /* milliseconds */
#define CSCHED_TSLICE           30      /* milliseconds */
#define CSCHED_ACCT_NTICKS      3
#define CSCHED_ACCT_PERIOD      (CSCHED_ACCT_NTICKS * CSCHED_TICK)
#define CSCHED_DEFAULT_WEIGHT   256


/*
 * Priorities
 */
#define CSCHED_PRI_TS_UNDER     -1      /* time-share w/ credits */
#define CSCHED_PRI_TS_OVER      -2      /* time-share w/o credits */
#define CSCHED_PRI_IDLE         -64     /* idle */
#define CSCHED_PRI_TS_PARKED    -65     /* time-share w/ capped credits */


/*
 * Useful macros
 */
#define CSCHED_PCPU(_c)     ((struct csched_pcpu *)schedule_data[_c].sched_priv)
#define CSCHED_VCPU(_vcpu)  ((struct csched_vcpu *) (_vcpu)->sched_priv)
#define CSCHED_DOM(_dom)    ((struct csched_dom *) (_dom)->sched_priv)
#define RUNQ(_cpu)          (&(CSCHED_PCPU(_cpu)->runq))


/*
 * Stats
 */
#ifdef CSCHED_STATS

#define CSCHED_STAT(_X)         (csched_priv.stats._X)
#define CSCHED_STAT_DEFINE(_X)  uint32_t _X;
#define CSCHED_STAT_PRINTK(_X)                                  \
    do                                                          \
    {                                                           \
        printk("\t%-30s = %u\n", #_X, CSCHED_STAT(_X));  \
    } while ( 0 );

#define CSCHED_STATS_EXPAND_SCHED(_MACRO)   \
    _MACRO(vcpu_init)                       \
    _MACRO(vcpu_sleep)                      \
    _MACRO(vcpu_wake_running)               \
    _MACRO(vcpu_wake_onrunq)                \
    _MACRO(vcpu_wake_runnable)              \
    _MACRO(vcpu_wake_not_runnable)          \
    _MACRO(dom_destroy)                     \
    _MACRO(schedule)                        \
    _MACRO(tickle_local_idler)              \
    _MACRO(tickle_local_over)               \
    _MACRO(tickle_local_under)              \
    _MACRO(tickle_local_other)              \
    _MACRO(acct_run)                        \
    _MACRO(acct_no_work)                    \
    _MACRO(acct_balance)                    \
    _MACRO(acct_reorder)                    \
    _MACRO(acct_min_credit)                 \
    _MACRO(acct_vcpu_active)                \
    _MACRO(acct_vcpu_idle)                  \
    _MACRO(acct_vcpu_credit_min)

#define CSCHED_STATS_EXPAND_SMP_LOAD_BALANCE(_MACRO)    \
    _MACRO(vcpu_migrate)                                \
    _MACRO(load_balance_idle)                           \
    _MACRO(load_balance_over)                           \
    _MACRO(load_balance_other)                          \
    _MACRO(steal_trylock_failed)                        \
    _MACRO(steal_peer_down)                             \
    _MACRO(steal_peer_idle)                             \
    _MACRO(steal_peer_running)                          \
    _MACRO(steal_peer_pinned)                           \
    _MACRO(tickle_idlers_none)                          \
    _MACRO(tickle_idlers_some)

#ifndef NDEBUG
#define CSCHED_STATS_EXPAND_CHECKS(_MACRO)  \
    _MACRO(vcpu_check)
#else
#define CSCHED_STATS_EXPAND_CHECKS(_MACRO)
#endif

#define CSCHED_STATS_EXPAND(_MACRO)                 \
    CSCHED_STATS_EXPAND_SCHED(_MACRO)               \
    CSCHED_STATS_EXPAND_SMP_LOAD_BALANCE(_MACRO)    \
    CSCHED_STATS_EXPAND_CHECKS(_MACRO)

#define CSCHED_STATS_RESET()                                        \
    do                                                              \
    {                                                               \
        memset(&csched_priv.stats, 0, sizeof(csched_priv.stats));   \
    } while ( 0 )

#define CSCHED_STATS_DEFINE()                   \
    struct                                      \
    {                                           \
        CSCHED_STATS_EXPAND(CSCHED_STAT_DEFINE) \
    } stats

#define CSCHED_STATS_PRINTK()                   \
    do                                          \
    {                                           \
        printk("stats:\n");                     \
        CSCHED_STATS_EXPAND(CSCHED_STAT_PRINTK) \
    } while ( 0 )

#define CSCHED_STAT_CRANK(_X)   (CSCHED_STAT(_X)++)

#else /* CSCHED_STATS */

#define CSCHED_STATS_RESET()    do {} while ( 0 )
#define CSCHED_STATS_DEFINE()   do {} while ( 0 )
#define CSCHED_STATS_PRINTK()   do {} while ( 0 )
#define CSCHED_STAT_CRANK(_X)   do {} while ( 0 )

#endif /* CSCHED_STATS */


/*
 * Physical CPU
 */
struct csched_pcpu {
    struct list_head runq;
    uint32_t runq_sort_last;
};

/*
 * Virtual CPU
 */
struct csched_vcpu {
    struct list_head runq_elem;
    struct list_head active_vcpu_elem;
    struct csched_dom *sdom;
    struct vcpu *vcpu;
    atomic_t credit;
    int credit_last;
    uint32_t credit_incr;
    uint32_t state_active;
    uint32_t state_idle;
    int16_t pri;
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
    spinlock_t lock;
    struct list_head active_sdom;
    uint32_t ncpus;
    unsigned int master;
    cpumask_t idlers;
    uint32_t weight;
    uint32_t credit;
    int credit_balance;
    uint32_t runq_sort;
    CSCHED_STATS_DEFINE();
};


/*
 * Global variables
 */
static struct csched_private csched_priv;



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

    list_add_tail(&svc->runq_elem, iter);
}

static inline void
__runq_remove(struct csched_vcpu *svc)
{
    BUG_ON( !__vcpu_on_runq(svc) );
    list_del_init(&svc->runq_elem);
}

static inline void
__runq_tickle(unsigned int cpu, struct csched_vcpu *new)
{
    struct csched_vcpu * const cur = CSCHED_VCPU(schedule_data[cpu].curr);
    cpumask_t mask;

    ASSERT(cur);
    cpus_clear(mask);

    /* If strictly higher priority than current VCPU, signal the CPU */
    if ( new->pri > cur->pri )
    {
        if ( cur->pri == CSCHED_PRI_IDLE )
            CSCHED_STAT_CRANK(tickle_local_idler);
        else if ( cur->pri == CSCHED_PRI_TS_OVER )
            CSCHED_STAT_CRANK(tickle_local_over);
        else if ( cur->pri == CSCHED_PRI_TS_UNDER )
            CSCHED_STAT_CRANK(tickle_local_under);
        else
            CSCHED_STAT_CRANK(tickle_local_other);

        cpu_set(cpu, mask);
    }

    /*
     * If this CPU has at least two runnable VCPUs, we tickle any idlers to
     * let them know there is runnable work in the system...
     */
    if ( cur->pri > CSCHED_PRI_IDLE )
    {
        if ( cpus_empty(csched_priv.idlers) )
        {
            CSCHED_STAT_CRANK(tickle_idlers_none);
        }
        else
        {
            CSCHED_STAT_CRANK(tickle_idlers_some);
            cpus_or(mask, mask, csched_priv.idlers);
        }
    }

    /* Send scheduler interrupts to designated CPUs */
    if ( !cpus_empty(mask) )
        cpumask_raise_softirq(mask, SCHEDULE_SOFTIRQ);
}

static int
csched_pcpu_init(int cpu)
{
    struct csched_pcpu *spc;
    unsigned long flags;

    /* Allocate per-PCPU info */
    spc = xmalloc(struct csched_pcpu);
    if ( spc == NULL )
        return -1;

    spin_lock_irqsave(&csched_priv.lock, flags);

    /* Initialize/update system-wide config */
    csched_priv.credit += CSCHED_ACCT_PERIOD;
    if ( csched_priv.ncpus <= cpu )
        csched_priv.ncpus = cpu + 1;
    if ( csched_priv.master >= csched_priv.ncpus )
        csched_priv.master = cpu;

    INIT_LIST_HEAD(&spc->runq);
    spc->runq_sort_last = csched_priv.runq_sort;
    schedule_data[cpu].sched_priv = spc;

    /* Start off idling... */
    BUG_ON( !is_idle_vcpu(schedule_data[cpu].curr) );
    cpu_set(cpu, csched_priv.idlers);

    spin_unlock_irqrestore(&csched_priv.lock, flags);

    return 0;
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

    CSCHED_STAT_CRANK(vcpu_check);
}
#define CSCHED_VCPU_CHECK(_vc)  (__csched_vcpu_check(_vc))
#else
#define CSCHED_VCPU_CHECK(_vc)
#endif

static inline int
__csched_vcpu_is_stealable(int local_cpu, struct vcpu *vc)
{
    /*
     * Don't pick up work that's in the peer's scheduling tail. Also only pick
     * up work that's allowed to run on our CPU.
     */
    if ( unlikely(test_bit(_VCPUF_running, &vc->vcpu_flags)) )
    {
        CSCHED_STAT_CRANK(steal_peer_running);
        return 0;
    }

    if ( unlikely(!cpu_isset(local_cpu, vc->cpu_affinity)) )
    {
        CSCHED_STAT_CRANK(steal_peer_pinned);
        return 0;
    }

    return 1;
}

static void
csched_vcpu_acct(struct csched_vcpu *svc, int credit_dec)
{
    struct csched_dom * const sdom = svc->sdom;
    unsigned long flags;

    /* Update credits */
    atomic_sub(credit_dec, &svc->credit);

    /* Put this VCPU and domain back on the active list if it was idling */
    if ( list_empty(&svc->active_vcpu_elem) )
    {
        spin_lock_irqsave(&csched_priv.lock, flags);

        if ( list_empty(&svc->active_vcpu_elem) )
        {
            CSCHED_STAT_CRANK(acct_vcpu_active);
            svc->state_active++;

            sdom->active_vcpu_count++;
            list_add(&svc->active_vcpu_elem, &sdom->active_vcpu);
            if ( list_empty(&sdom->active_sdom_elem) )
            {
                list_add(&sdom->active_sdom_elem, &csched_priv.active_sdom);
                csched_priv.weight += sdom->weight;
            }
        }

        spin_unlock_irqrestore(&csched_priv.lock, flags);
    }
}

static inline void
__csched_vcpu_acct_idle_locked(struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;

    BUG_ON( list_empty(&svc->active_vcpu_elem) );

    CSCHED_STAT_CRANK(acct_vcpu_idle);
    svc->state_idle++;

    sdom->active_vcpu_count--;
    list_del_init(&svc->active_vcpu_elem);
    if ( list_empty(&sdom->active_vcpu) )
    {
        BUG_ON( csched_priv.weight < sdom->weight );
        list_del_init(&sdom->active_sdom_elem);
        csched_priv.weight -= sdom->weight;
    }

    atomic_set(&svc->credit, 0);
}

static int
csched_vcpu_init(struct vcpu *vc)
{
    struct domain * const dom = vc->domain;
    struct csched_dom *sdom;
    struct csched_vcpu *svc;
    int16_t pri;

    CSCHED_STAT_CRANK(vcpu_init);

    /* Allocate, if appropriate, per-domain info */
    if ( is_idle_vcpu(vc) )
    {
        sdom = NULL;
        pri = CSCHED_PRI_IDLE;
    }
    else if ( CSCHED_DOM(dom) )
    {
        sdom = CSCHED_DOM(dom);
        pri = CSCHED_PRI_TS_UNDER;
    }
    else 
    {
        sdom = xmalloc(struct csched_dom);
        if ( !sdom )
            return -1;

        /* Initialize credit and weight */
        INIT_LIST_HEAD(&sdom->active_vcpu);
        sdom->active_vcpu_count = 0;
        INIT_LIST_HEAD(&sdom->active_sdom_elem);
        sdom->dom = dom;
        sdom->weight = CSCHED_DEFAULT_WEIGHT;
        sdom->cap = 0U;
        dom->sched_priv = sdom;
        pri = CSCHED_PRI_TS_UNDER;
    }

    /* Allocate per-VCPU info */
    svc = xmalloc(struct csched_vcpu);
    if ( !svc )
        return -1;

    INIT_LIST_HEAD(&svc->runq_elem);
    INIT_LIST_HEAD(&svc->active_vcpu_elem);
    svc->sdom = sdom;
    svc->vcpu = vc;
    atomic_set(&svc->credit, 0);
    svc->credit_last = 0;
    svc->credit_incr = 0U;
    svc->state_active = 0U;
    svc->state_idle = 0U;
    svc->pri = pri;
    vc->sched_priv = svc;

    CSCHED_VCPU_CHECK(vc);

    /* Attach fair-share VCPUs to the accounting list */
    if ( likely(sdom != NULL) )
        csched_vcpu_acct(svc, 0);

    /* Allocate per-PCPU info */
    if ( unlikely(!CSCHED_PCPU(vc->processor)) )
    {
        if ( csched_pcpu_init(vc->processor) != 0 )
            return -1;
    }

    CSCHED_VCPU_CHECK(vc);

    return 0;
}

static void
csched_vcpu_free(struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    struct csched_dom * const sdom = svc->sdom;
    unsigned long flags;

    BUG_ON( sdom == NULL );
    BUG_ON( !list_empty(&svc->runq_elem) );

    spin_lock_irqsave(&csched_priv.lock, flags);

    if ( !list_empty(&svc->active_vcpu_elem) )
        __csched_vcpu_acct_idle_locked(svc);

    spin_unlock_irqrestore(&csched_priv.lock, flags);

    xfree(svc);
}

static void
csched_vcpu_sleep(struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);

    CSCHED_STAT_CRANK(vcpu_sleep);

    BUG_ON( is_idle_vcpu(vc) );

    if ( schedule_data[vc->processor].curr == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
    else if ( __vcpu_on_runq(svc) )
        __runq_remove(svc);
}

static void
csched_vcpu_wake(struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    const unsigned int cpu = vc->processor;

    BUG_ON( is_idle_vcpu(vc) );

    if ( unlikely(schedule_data[cpu].curr == vc) )
    {
        CSCHED_STAT_CRANK(vcpu_wake_running);
        return;
    }
    if ( unlikely(__vcpu_on_runq(svc)) )
    {
        CSCHED_STAT_CRANK(vcpu_wake_onrunq);
        return;
    }

    if ( likely(vcpu_runnable(vc)) )
        CSCHED_STAT_CRANK(vcpu_wake_runnable);
    else
        CSCHED_STAT_CRANK(vcpu_wake_not_runnable);

    /* Put the VCPU on the runq and tickle CPUs */
    __runq_insert(cpu, svc);
    __runq_tickle(cpu, svc);
}

static int
csched_vcpu_set_affinity(struct vcpu *vc, cpumask_t *affinity)
{
    unsigned long flags;
    int lcpu;

    if ( vc == current )
    {
        /* No locking needed but also can't move on the spot... */
        if ( !cpu_isset(vc->processor, *affinity) )
            return -EBUSY;

        vc->cpu_affinity = *affinity;
    }
    else
    {
        /* Pause, modify, and unpause. */
        vcpu_pause(vc);

        vc->cpu_affinity = *affinity;
        if ( !cpu_isset(vc->processor, vc->cpu_affinity) )
        {
            /*
             * We must grab the scheduler lock for the CPU currently owning
             * this VCPU before changing its ownership.
             */
            vcpu_schedule_lock_irqsave(vc, flags);
            lcpu = vc->processor;

            vc->processor = first_cpu(vc->cpu_affinity);

            spin_unlock_irqrestore(&schedule_data[lcpu].schedule_lock, flags);
        }

        vcpu_unpause(vc);
    }

    return 0;
}

static int
csched_dom_cntl(
    struct domain *d,
    struct sched_adjdom_cmd *cmd)
{
    struct csched_dom * const sdom = CSCHED_DOM(d);
    unsigned long flags;

    if ( cmd->direction == SCHED_INFO_GET )
    {
        cmd->u.credit.weight = sdom->weight;
        cmd->u.credit.cap = sdom->cap;
    }
    else
    {
        ASSERT( cmd->direction == SCHED_INFO_PUT );

        spin_lock_irqsave(&csched_priv.lock, flags);

        if ( cmd->u.credit.weight != 0 )
        {
            if ( !list_empty(&sdom->active_sdom_elem) )
            {
                csched_priv.weight -= sdom->weight;
                csched_priv.weight += cmd->u.credit.weight;
            }
            sdom->weight = cmd->u.credit.weight;
        }

        if ( cmd->u.credit.cap != (uint16_t)~0U )
            sdom->cap = cmd->u.credit.cap;

        spin_unlock_irqrestore(&csched_priv.lock, flags);
    }

    return 0;
}

static void
csched_dom_destroy(struct domain *dom)
{
    struct csched_dom * const sdom = CSCHED_DOM(dom);
    int i;

    CSCHED_STAT_CRANK(dom_destroy);

    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
    {
        if ( dom->vcpu[i] )
            csched_vcpu_free(dom->vcpu[i]);
    }

    xfree(sdom);
}

/*
 * This is a O(n) optimized sort of the runq.
 *
 * Time-share VCPUs can only be one of two priorities, UNDER or OVER. We walk
 * through the runq and move up any UNDERs that are preceded by OVERS. We
 * remember the last UNDER to make the move up operation O(1).
 */
static void
csched_runq_sort(unsigned int cpu)
{
    struct csched_pcpu * const spc = CSCHED_PCPU(cpu);
    struct list_head *runq, *elem, *next, *last_under;
    struct csched_vcpu *svc_elem;
    unsigned long flags;
    int sort_epoch;

    sort_epoch = csched_priv.runq_sort;
    if ( sort_epoch == spc->runq_sort_last )
        return;

    spc->runq_sort_last = sort_epoch;

    spin_lock_irqsave(&schedule_data[cpu].schedule_lock, flags);

    runq = &spc->runq;
    elem = runq->next;
    last_under = runq;

    while ( elem != runq )
    {
        next = elem->next;
        svc_elem = __runq_elem(elem);

        if ( svc_elem->pri == CSCHED_PRI_TS_UNDER )
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

    spin_unlock_irqrestore(&schedule_data[cpu].schedule_lock, flags);
}

static void
csched_acct(void)
{
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
    int credit_balance;
    int credit_xtra;
    int credit;


    spin_lock_irqsave(&csched_priv.lock, flags);

    weight_total = csched_priv.weight;
    credit_total = csched_priv.credit;

    /* Converge balance towards 0 when it drops negative */
    if ( csched_priv.credit_balance < 0 )
    {
        credit_total -= csched_priv.credit_balance;
        CSCHED_STAT_CRANK(acct_balance);
    }

    if ( unlikely(weight_total == 0) )
    {
        csched_priv.credit_balance = 0;
        spin_unlock_irqrestore(&csched_priv.lock, flags);
        CSCHED_STAT_CRANK(acct_no_work);
        return;
    }

    CSCHED_STAT_CRANK(acct_run);

    weight_left = weight_total;
    credit_balance = 0;
    credit_xtra = 0;

    list_for_each_safe( iter_sdom, next_sdom, &csched_priv.active_sdom )
    {
        sdom = list_entry(iter_sdom, struct csched_dom, active_sdom_elem);

        BUG_ON( is_idle_domain(sdom->dom) );
        BUG_ON( sdom->active_vcpu_count == 0 );
        BUG_ON( sdom->weight == 0 );
        BUG_ON( sdom->weight > weight_left );

        weight_left -= sdom->weight;

        /*
         * A domain's fair share is computed using its weight in competition
         * with that of all other active domains.
         *
         * At most, a domain can use credits to run all its active VCPUs
         * for one full accounting period. We allow a domain to earn more
         * only when the system-wide credit balance is negative.
         */
        credit_peak = sdom->active_vcpu_count * CSCHED_ACCT_PERIOD;
        if ( csched_priv.credit_balance < 0 )
        {
            credit_peak += ( ( -csched_priv.credit_balance * sdom->weight) +
                             (weight_total - 1)
                           ) / weight_total;
        }
        if ( sdom->cap != 0U )
        {
            uint32_t credit_cap = ((sdom->cap * CSCHED_ACCT_PERIOD) + 99) / 100;
            if ( credit_cap < credit_peak )
                credit_peak = credit_cap;
        }

        credit_fair = ( ( credit_total * sdom->weight) + (weight_total - 1)
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
                CSCHED_STAT_CRANK(acct_reorder);
                list_del(&sdom->active_sdom_elem);
                list_add(&sdom->active_sdom_elem, &csched_priv.active_sdom);
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
                if ( sdom->cap == 0U )
                    svc->pri = CSCHED_PRI_TS_OVER;
                else
                    svc->pri = CSCHED_PRI_TS_PARKED;

                if ( credit < -CSCHED_TSLICE )
                {
                    CSCHED_STAT_CRANK(acct_min_credit);
                    credit = -CSCHED_TSLICE;
                    atomic_set(&svc->credit, credit);
                }
            }
            else
            {
                svc->pri = CSCHED_PRI_TS_UNDER;

                if ( credit > CSCHED_TSLICE )
                    __csched_vcpu_acct_idle_locked(svc);
            }

            svc->credit_last = credit;
            svc->credit_incr = credit_fair;
            credit_balance += credit;
        }
    }

    csched_priv.credit_balance = credit_balance;

    spin_unlock_irqrestore(&csched_priv.lock, flags);

    /* Inform each CPU that its runq needs to be sorted */
    csched_priv.runq_sort++;
}

static void
csched_tick(unsigned int cpu)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(current);
    struct csched_dom * const sdom = svc->sdom;

    /*
     * Accounting for running VCPU
     *
     * Note: Some VCPUs, such as the idle tasks, are not credit scheduled.
     */
    if ( likely(sdom != NULL) )
    {
        csched_vcpu_acct(svc, CSCHED_TICK);
    }

    /*
     * Accounting duty
     *
     * Note: Currently, this is always done by the master boot CPU. Eventually,
     * we could distribute or at the very least cycle the duty.
     */
    if ( (csched_priv.master == cpu) &&
         (schedule_data[cpu].tick % CSCHED_ACCT_NTICKS) == 0 )
    {
        csched_acct();
    }

    /*
     * Check if runq needs to be sorted
     *
     * Every physical CPU resorts the runq after the accounting master has
     * modified priorities. This is a special O(n) sort and runs at most
     * once per accounting period (currently 30 milliseconds).
     */
    csched_runq_sort(cpu);
}

static struct csched_vcpu *
csched_runq_steal(struct csched_pcpu *spc, int cpu, int pri)
{
    struct list_head *iter;
    struct csched_vcpu *speer;
    struct vcpu *vc;

    list_for_each( iter, &spc->runq )
    {
        speer = __runq_elem(iter);

        /*
         * If next available VCPU here is not of higher priority than ours,
         * this PCPU is useless to us.
         */
        if ( speer->pri <= CSCHED_PRI_IDLE || speer->pri <= pri )
        {
            CSCHED_STAT_CRANK(steal_peer_idle);
            break;
        }

        /* Is this VCPU is runnable on our PCPU? */
        vc = speer->vcpu;
        BUG_ON( is_idle_vcpu(vc) );

        if ( __csched_vcpu_is_stealable(cpu, vc) )
        {
            /* We got a candidate. Grab it! */
            __runq_remove(speer);
            vc->processor = cpu;

            return speer;
        }
    }

    return NULL;
}

static struct csched_vcpu *
csched_load_balance(int cpu, struct csched_vcpu *snext)
{
    struct csched_pcpu *spc;
    struct csched_vcpu *speer;
    int peer_cpu;

    if ( snext->pri == CSCHED_PRI_IDLE )
        CSCHED_STAT_CRANK(load_balance_idle);
    else if ( snext->pri == CSCHED_PRI_TS_OVER )
        CSCHED_STAT_CRANK(load_balance_over);
    else
        CSCHED_STAT_CRANK(load_balance_other);

    peer_cpu = cpu;
    BUG_ON( peer_cpu != snext->vcpu->processor );

    while ( 1 )
    {
        /* For each PCPU in the system starting with our neighbour... */
        peer_cpu = (peer_cpu + 1) % csched_priv.ncpus;
        if ( peer_cpu == cpu )
            break;

        /*
         * Get ahold of the scheduler lock for this peer CPU.
         *
         * Note: We don't spin on this lock but simply try it. Spinning could
         * cause a deadlock if the peer CPU is also load balancing and trying
         * to lock this CPU.
         */
        if ( spin_trylock(&schedule_data[peer_cpu].schedule_lock) )
        {

            spc = CSCHED_PCPU(peer_cpu);
            if ( unlikely(spc == NULL) )
            {
                CSCHED_STAT_CRANK(steal_peer_down);
                speer = NULL;
            }
            else
            {
                speer = csched_runq_steal(spc, cpu, snext->pri);
            }

            spin_unlock(&schedule_data[peer_cpu].schedule_lock);

            /* Got one! */
            if ( speer )
            {
                CSCHED_STAT_CRANK(vcpu_migrate);
                return speer;
            }
        }
        else
        {
            CSCHED_STAT_CRANK(steal_trylock_failed);
        }
    }


    /* Failed to find more important work */
    __runq_remove(snext);
    return snext;
}

/*
 * This function is in the critical path. It is designed to be simple and
 * fast for the common case.
 */
static struct task_slice
csched_schedule(s_time_t now)
{
    const int cpu = smp_processor_id();
    struct list_head * const runq = RUNQ(cpu);
    struct csched_vcpu * const scurr = CSCHED_VCPU(current);
    struct csched_vcpu *snext;
    struct task_slice ret;

    CSCHED_STAT_CRANK(schedule);
    CSCHED_VCPU_CHECK(current);

    /*
     * Select next runnable local VCPU (ie top of local runq)
     */
    if ( vcpu_runnable(current) )
        __runq_insert(cpu, scurr);
    else
        BUG_ON( is_idle_vcpu(current) || list_empty(runq) );

    snext = __runq_elem(runq->next);

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
        snext = csched_load_balance(cpu, snext);

    /*
     * Update idlers mask if necessary. When we're idling, other CPUs
     * will tickle us when they get extra work.
     */
    if ( snext->pri == CSCHED_PRI_IDLE )
    {
        if ( !cpu_isset(cpu, csched_priv.idlers) )
            cpu_set(cpu, csched_priv.idlers);
    }
    else if ( cpu_isset(cpu, csched_priv.idlers) )
    {
        cpu_clear(cpu, csched_priv.idlers);
    }

    /*
     * Return task to run next...
     */
    ret.time = MILLISECS(CSCHED_TSLICE);
    ret.task = snext->vcpu;

    CSCHED_VCPU_CHECK(ret.task);

    return ret;
}

static void
csched_dump_vcpu(struct csched_vcpu *svc)
{
    struct csched_dom * const sdom = svc->sdom;

    printk("[%i.%i] pri=%i cpu=%i",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id,
            svc->pri,
            svc->vcpu->processor);

    if ( sdom )
    {
        printk(" credit=%i (%d+%u) {a=%u i=%u w=%u}",
            atomic_read(&svc->credit),
            svc->credit_last,
            svc->credit_incr,
            svc->state_active,
            svc->state_idle,
            sdom->weight);
    }

    printk("\n");
}

static void
csched_dump_pcpu(int cpu)
{
    struct list_head *runq, *iter;
    struct csched_pcpu *spc;
    struct csched_vcpu *svc;
    int loop;

    spc = CSCHED_PCPU(cpu);
    runq = &spc->runq;

    printk(" tick=%lu, sort=%d\n",
            schedule_data[cpu].tick,
            spc->runq_sort_last);

    /* current VCPU */
    svc = CSCHED_VCPU(schedule_data[cpu].curr);
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
}

static void
csched_dump(void)
{
    struct list_head *iter_sdom, *iter_svc;
    int loop;

    printk("info:\n"
           "\tncpus              = %u\n"
           "\tmaster             = %u\n"
           "\tcredit             = %u\n"
           "\tcredit balance     = %d\n"
           "\tweight             = %u\n"
           "\trunq_sort          = %u\n"
           "\ttick               = %dms\n"
           "\ttslice             = %dms\n"
           "\taccounting period  = %dms\n"
           "\tdefault-weight     = %d\n",
           csched_priv.ncpus,
           csched_priv.master,
           csched_priv.credit,
           csched_priv.credit_balance,
           csched_priv.weight,
           csched_priv.runq_sort,
           CSCHED_TICK,
           CSCHED_TSLICE,
           CSCHED_ACCT_PERIOD,
           CSCHED_DEFAULT_WEIGHT);

    printk("idlers: 0x%lx\n", csched_priv.idlers.bits[0]);

    CSCHED_STATS_PRINTK();

    printk("active vcpus:\n");
    loop = 0;
    list_for_each( iter_sdom, &csched_priv.active_sdom )
    {
        struct csched_dom *sdom;
        sdom = list_entry(iter_sdom, struct csched_dom, active_sdom_elem);

        list_for_each( iter_svc, &sdom->active_vcpu )
        {
            struct csched_vcpu *svc;
            svc = list_entry(iter_svc, struct csched_vcpu, active_vcpu_elem);

            printk("\t%3d: ", ++loop);
            csched_dump_vcpu(svc);
        }
    }
}

static void
csched_init(void)
{
    spin_lock_init(&csched_priv.lock);
    INIT_LIST_HEAD(&csched_priv.active_sdom);
    csched_priv.ncpus = 0;
    csched_priv.master = UINT_MAX;
    cpus_clear(csched_priv.idlers);
    csched_priv.weight = 0U;
    csched_priv.credit = 0U;
    csched_priv.credit_balance = 0;
    csched_priv.runq_sort = 0U;
    CSCHED_STATS_RESET();
}


struct scheduler sched_credit_def = {
    .name           = "SMP Credit Scheduler",
    .opt_name       = "credit",
    .sched_id       = SCHED_CREDIT,

    .init_vcpu      = csched_vcpu_init,
    .destroy_domain = csched_dom_destroy,

    .sleep          = csched_vcpu_sleep,
    .wake           = csched_vcpu_wake,

    .set_affinity   = csched_vcpu_set_affinity,

    .adjdom         = csched_dom_cntl,

    .tick           = csched_tick,
    .do_schedule    = csched_schedule,

    .dump_cpu_state = csched_dump_pcpu,
    .dump_settings  = csched_dump,
    .init           = csched_init,
};
