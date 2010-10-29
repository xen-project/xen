
/****************************************************************************
 * (C) 2009 - George Dunlap - Citrix Systems R&D UK, Ltd
 ****************************************************************************
 *
 *        File: common/csched_credit2.c
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
#include <asm/atomic.h>
#include <xen/errno.h>
#include <xen/trace.h>

#if __i386__
#define PRI_stime "lld"
#else
#define PRI_stime "ld"
#endif

#define d2printk(x...)
//#define d2printk printk

#define TRC_CSCHED2_TICK        TRC_SCHED_CLASS + 1
#define TRC_CSCHED2_RUNQ_POS    TRC_SCHED_CLASS + 2
#define TRC_CSCHED2_CREDIT_BURN TRC_SCHED_CLASS + 3
#define TRC_CSCHED2_CREDIT_ADD  TRC_SCHED_CLASS + 4
#define TRC_CSCHED2_TICKLE_CHECK TRC_SCHED_CLASS + 5

/*
 * WARNING: This is still in an experimental phase.  Status and work can be found at the
 * credit2 wiki page:
 *  http://wiki.xensource.com/xenwiki/Credit2_Scheduler_Development
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
#define CSCHED_DEFAULT_WEIGHT       256
/* Min timer: Minimum length a timer will be set, to
 * achieve efficiency */
#define CSCHED_MIN_TIMER            MICROSECS(500)
/* Amount of credit VMs begin with, and are reset to.
 * ATM, set so that highest-weight VMs can only run for 10ms
 * before a reset event. */
#define CSCHED_CREDIT_INIT          MILLISECS(10)
/* Carryover: How much "extra" credit may be carried over after
 * a reset. */
#define CSCHED_CARRYOVER_MAX        CSCHED_MIN_TIMER
/* Reset: Value below which credit will be reset. */
#define CSCHED_CREDIT_RESET         0
/* Max timer: Maximum time a guest can be run for. */
#define CSCHED_MAX_TIMER            MILLISECS(2)


#define CSCHED_IDLE_CREDIT                 (-(1<<30))

/*
 * Flags
 */
/* CSFLAG_scheduled: Is this vcpu either running on, or context-switching off,
 * a physical cpu?
 * + Accessed only with runqueue lock held
 * + Set when chosen as next in csched_schedule().
 * + Cleared after context switch has been saved in csched_context_saved()
 * + Checked in vcpu_wake to see if we can add to the runqueue, or if we should
 *   set CSFLAG_delayed_runq_add
 * + Checked to be false in runq_insert.
 */
#define __CSFLAG_scheduled 1
#define CSFLAG_scheduled (1<<__CSFLAG_scheduled)
/* CSFLAG_delayed_runq_add: Do we need to add this to the runqueue once it'd done
 * being context switched out?
 * + Set when scheduling out in csched_schedule() if prev is runnable
 * + Set in csched_vcpu_wake if it finds CSFLAG_scheduled set
 * + Read in csched_context_saved().  If set, it adds prev to the runqueue and
 *   clears the bit.
 */
#define __CSFLAG_delayed_runq_add 2
#define CSFLAG_delayed_runq_add (1<<__CSFLAG_delayed_runq_add)


/*
 * Useful macros
 */
#define CSCHED_PRIV(_ops)   \
    ((struct csched_private *)((_ops)->sched_data))
#define CSCHED_VCPU(_vcpu)  ((struct csched_vcpu *) (_vcpu)->sched_priv)
#define CSCHED_DOM(_dom)    ((struct csched_dom *) (_dom)->sched_priv)
#define CSCHED_CPUONLINE(_pool)    \
    (((_pool) == NULL) ? &cpupool_free_cpus : &(_pool)->cpu_valid)
/* CPU to runq_id macro */
#define c2r(_ops, _cpu)     (CSCHED_PRIV(_ops)->runq_map[(_cpu)])
/* CPU to runqueue struct macro */
#define RQD(_ops, _cpu)     (&CSCHED_PRIV(_ops)->rqd[c2r(_ops, _cpu)])

/*
 * Per-runqueue data
 */
struct csched_runqueue_data {
    int id;
    struct list_head runq; /* Ordered list of runnable vms */
    struct list_head svc;  /* List of all vcpus assigned to this runqueue */
    int max_weight;
    int cpu_min, cpu_max;  /* Range of physical cpus this runqueue runs */
};

/*
 * System-wide private data
 */
struct csched_private {
    spinlock_t lock;
    uint32_t ncpus;

    struct list_head sdom; /* Used mostly for dump keyhandler. */

    int runq_map[NR_CPUS];
    uint32_t runq_count;
    struct csched_runqueue_data rqd[NR_CPUS];
};

/*
 * Virtual CPU
 */
struct csched_vcpu {
    struct list_head rqd_elem;  /* On the runqueue data list */
    struct list_head sdom_elem; /* On the domain vcpu list */
    struct list_head runq_elem; /* On the runqueue         */

    /* Up-pointers */
    struct csched_dom *sdom;
    struct vcpu *vcpu;

    int weight;

    int credit;
    s_time_t start_time; /* When we were scheduled (used for credit) */
    unsigned flags;      /* 16 bits doesn't seem to play well with clear_bit() */

};

/*
 * Domain
 */
struct csched_dom {
    struct list_head vcpu;
    struct list_head sdom_elem;
    struct domain *dom;
    uint16_t weight;
    uint16_t nr_vcpus;
};


/*
 * Time-to-credit, credit-to-time.
 * FIXME: Do pre-calculated division?
 */
static s_time_t t2c(struct csched_runqueue_data *rqd, s_time_t time, struct csched_vcpu *svc)
{
    return time * rqd->max_weight / svc->weight;
}

static s_time_t c2t(struct csched_runqueue_data *rqd, s_time_t credit, struct csched_vcpu *svc)
{
    return credit * svc->weight / rqd->max_weight;
}

/*
 * Runqueue related code
 */

static /*inline*/ int
__vcpu_on_runq(struct csched_vcpu *svc)
{
    return !list_empty(&svc->runq_elem);
}

static /*inline*/ struct csched_vcpu *
__runq_elem(struct list_head *elem)
{
    return list_entry(elem, struct csched_vcpu, runq_elem);
}

static int
__runq_insert(struct list_head *runq, struct csched_vcpu *svc)
{
    struct list_head *iter;
    int pos = 0;

    d2printk("rqi d%dv%d\n",
           svc->vcpu->domain->domain_id,
           svc->vcpu->vcpu_id);

    /* Idle vcpus not allowed on the runqueue anymore */
    BUG_ON(is_idle_vcpu(svc->vcpu));
    BUG_ON(svc->vcpu->is_running);
    BUG_ON(test_bit(__CSFLAG_scheduled, &svc->flags));

    list_for_each( iter, runq )
    {
        struct csched_vcpu * iter_svc = __runq_elem(iter);

        if ( svc->credit > iter_svc->credit )
        {
            d2printk(" p%d d%dv%d\n",
                   pos,
                   iter_svc->vcpu->domain->domain_id,
                   iter_svc->vcpu->vcpu_id);
            break;
        }
        pos++;
    }

    list_add_tail(&svc->runq_elem, iter);

    return pos;
}

static void
runq_insert(const struct scheduler *ops, unsigned int cpu, struct csched_vcpu *svc)
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
        trace_var(TRC_CSCHED2_RUNQ_POS, 1,
                  sizeof(d),
                  (unsigned char *)&d);
    }

    return;
}

static inline void
__runq_remove(struct csched_vcpu *svc)
{
    BUG_ON( !__vcpu_on_runq(svc) );
    list_del_init(&svc->runq_elem);
}

void burn_credits(struct csched_runqueue_data *rqd, struct csched_vcpu *, s_time_t);

/* Check to see if the item on the runqueue is higher priority than what's
 * currently running; if so, wake up the processor */
static /*inline*/ void
runq_tickle(const struct scheduler *ops, unsigned int cpu, struct csched_vcpu *new, s_time_t now)
{
    int i, ipid=-1;
    s_time_t lowest=(1<<30);
    struct csched_runqueue_data *rqd = RQD(ops, cpu);
    cpumask_t *online;

    d2printk("rqt d%dv%d cd%dv%d\n",
             new->vcpu->domain->domain_id,
             new->vcpu->vcpu_id,
             current->domain->domain_id,
             current->vcpu_id);

    online = CSCHED_CPUONLINE(per_cpu(cpupool, cpu));
    /* Find the cpu in this queue group that has the lowest credits */
    for ( i=rqd->cpu_min ; i < rqd->cpu_max ; i++ )
    {
        struct csched_vcpu * cur;

        /* Skip cpus that aren't online */
        if ( !cpu_isset(i, *online) )
            continue;

        cur = CSCHED_VCPU(per_cpu(schedule_data, i).curr);

        /* FIXME: keep track of idlers, chose from the mask */
        if ( is_idle_vcpu(cur->vcpu) )
        {
            ipid = i;
            lowest = CSCHED_IDLE_CREDIT;
            break;
        }
        else
        {
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
    }

    if ( ipid != -1 )
    {
        int cdiff = lowest - new->credit;

        if ( lowest == CSCHED_IDLE_CREDIT || cdiff < 0 ) {
            d2printk("si %d\n", ipid);
            cpu_raise_softirq(ipid, SCHEDULE_SOFTIRQ);
        }
        else
            /* FIXME: Wake up later? */;
    }
}

/*
 * Credit-related code
 */
static void reset_credit(const struct scheduler *ops, int cpu, s_time_t now)
{
    struct list_head *iter;

    list_for_each( iter, &RQD(ops, cpu)->svc )
    {
        struct csched_vcpu * svc = list_entry(iter, struct csched_vcpu, rqd_elem);

        BUG_ON( is_idle_vcpu(svc->vcpu) );

        /* "Clip" credits to max carryover */
        if ( svc->credit > CSCHED_CARRYOVER_MAX )
            svc->credit = CSCHED_CARRYOVER_MAX;
        /* And add INIT */
        svc->credit += CSCHED_CREDIT_INIT;
        svc->start_time = now;

        /* FIXME: Trace credit */
    }

    /* No need to resort runqueue, as everyone's order should be the same. */
}

void burn_credits(struct csched_runqueue_data *rqd, struct csched_vcpu *svc, s_time_t now)
{
    s_time_t delta;

    /* Assert svc is current */
    ASSERT(svc==CSCHED_VCPU(per_cpu(schedule_data, svc->vcpu->processor).curr));

    if ( is_idle_vcpu(svc->vcpu) )
    {
        BUG_ON(svc->credit != CSCHED_IDLE_CREDIT);
        return;
    }

    delta = now - svc->start_time;

    if ( delta > 0 ) {
        /* This will round down; should we consider rounding up...? */
        svc->credit -= t2c(rqd, delta, svc);
        svc->start_time = now;

        d2printk("b d%dv%d c%d\n",
                 svc->vcpu->domain->domain_id,
                 svc->vcpu->vcpu_id,
                 svc->credit);
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
void update_max_weight(struct csched_runqueue_data *rqd, int new_weight, int old_weight)
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
        printk("%s: Runqueue id %d max weight %d\n", __func__, rqd->id, rqd->max_weight);
    }
    else if ( old_weight == rqd->max_weight )
    {
        struct list_head *iter;
        int max_weight = 1;

        list_for_each( iter, &rqd->svc )
        {
            struct csched_vcpu * svc = list_entry(iter, struct csched_vcpu, rqd_elem);

            if ( svc->weight > max_weight )
                max_weight = svc->weight;
        }

        rqd->max_weight = max_weight;
        printk("%s: Runqueue %d max weight %d\n", __func__, rqd->id, rqd->max_weight);
    }
}

#ifndef NDEBUG
static /*inline*/ void
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
}
#define CSCHED_VCPU_CHECK(_vc)  (__csched_vcpu_check(_vc))
#else
#define CSCHED_VCPU_CHECK(_vc)
#endif

static void *
csched_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct csched_vcpu *svc;

    /* Allocate per-VCPU info */
    svc = xmalloc(struct csched_vcpu);
    if ( svc == NULL )
        return NULL;
    memset(svc, 0, sizeof(*svc));

    INIT_LIST_HEAD(&svc->rqd_elem);
    INIT_LIST_HEAD(&svc->sdom_elem);
    INIT_LIST_HEAD(&svc->runq_elem);

    svc->sdom = dd;
    svc->vcpu = vc;
    svc->flags = 0U;

    if ( ! is_idle_vcpu(vc) )
    {
        BUG_ON( svc->sdom == NULL );

        svc->credit = CSCHED_CREDIT_INIT;
        svc->weight = svc->sdom->weight;
    }
    else
    {
        BUG_ON( svc->sdom != NULL );
        svc->credit = CSCHED_IDLE_CREDIT;
        svc->weight = 0;
    }

    return svc;
}

static void
csched_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu *svc = vc->sched_priv;
    struct domain * const dom = vc->domain;
    struct csched_dom *sdom = CSCHED_DOM(dom);

    printk("%s: Inserting d%dv%d\n",
           __func__, dom->domain_id, vc->vcpu_id);

    if ( ! is_idle_vcpu(vc) )
    {
        /* FIXME: Do we need the private lock here? */
        list_add_tail(&svc->sdom_elem, &svc->sdom->vcpu);

        /* Add vcpu to runqueue of initial processor */
        /* FIXME: Abstract for multiple runqueues */
        vcpu_schedule_lock_irq(vc);

        list_add_tail(&svc->rqd_elem, &RQD(ops, vc->processor)->svc);
        update_max_weight(RQD(ops, vc->processor), svc->weight, 0);

        vcpu_schedule_unlock_irq(vc);

        sdom->nr_vcpus++;
    }

    CSCHED_VCPU_CHECK(vc);
}

static void
csched_free_vdata(const struct scheduler *ops, void *priv)
{
    struct csched_vcpu *svc = priv;

    xfree(svc);
}

static void
csched_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    struct csched_dom * const sdom = svc->sdom;

    BUG_ON( sdom == NULL );
    BUG_ON( !list_empty(&svc->runq_elem) );

    if ( ! is_idle_vcpu(vc) )
    {
        /* Remove from runqueue */
        vcpu_schedule_lock_irq(vc);

        list_del_init(&svc->rqd_elem);
        update_max_weight(RQD(ops, vc->processor), 0, svc->weight);

        vcpu_schedule_unlock_irq(vc);

        /* Remove from sdom list.  Don't need a lock for this, as it's called
         * syncronously when nothing else can happen. */
        list_del_init(&svc->sdom_elem);

        svc->sdom->nr_vcpus--;
    }
}

static void
csched_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);

    BUG_ON( is_idle_vcpu(vc) );

    if ( per_cpu(schedule_data, vc->processor).curr == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
    else if ( __vcpu_on_runq(svc) )
        __runq_remove(svc);
}

static void
csched_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);
    const unsigned int cpu = vc->processor;
    s_time_t now = 0;

    /* Schedule lock should be held at this point. */

    d2printk("w d%dv%d\n", vc->domain->domain_id, vc->vcpu_id);

    BUG_ON( is_idle_vcpu(vc) );

    /* Make sure svc priority mod happens before runq check */
    if ( unlikely(per_cpu(schedule_data, cpu).curr == vc) )
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

    now = NOW();

    /* Put the VCPU on the runq */
    runq_insert(ops, cpu, svc);
    runq_tickle(ops, cpu, svc, now);

out:
    d2printk("w-\n");
    return;
}

static void
csched_context_saved(const struct scheduler *ops, struct vcpu *vc)
{
    struct csched_vcpu * const svc = CSCHED_VCPU(vc);

    vcpu_schedule_lock_irq(vc);

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
    if ( test_bit(__CSFLAG_delayed_runq_add, &svc->flags) )
    {
        const unsigned int cpu = vc->processor;

        clear_bit(__CSFLAG_delayed_runq_add, &svc->flags);

        BUG_ON(__vcpu_on_runq(svc));

        runq_insert(ops, cpu, svc);
        runq_tickle(ops, cpu, svc, NOW());
    }

    vcpu_schedule_unlock_irq(vc);
}

static int
csched_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    /* FIXME: Chose a schedule group based on load */
    /* FIXME: Migrate the vcpu to the new runqueue list, updating
       max_weight for each runqueue */
    return 0;
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

            /* Must hold csched_priv lock to update sdom, runq lock to
             * update csvcs. */
            spin_lock_irqsave(&prv->lock, flags);

            old_weight = sdom->weight;

            sdom->weight = op->u.credit2.weight;

            /* Update weights for vcpus, and max_weight for runqueues on which they reside */
            list_for_each ( iter, &sdom->vcpu )
            {
                struct csched_vcpu *svc = list_entry(iter, struct csched_vcpu, sdom_elem);

                /* NB: Locking order is important here.  Because we grab this lock here, we
                 * must never lock csched_priv.lock if we're holding a runqueue
                 * lock. */
                vcpu_schedule_lock_irq(svc->vcpu);

                svc->weight = sdom->weight;
                update_max_weight(RQD(ops, svc->vcpu->processor), svc->weight, old_weight);

                vcpu_schedule_unlock_irq(svc->vcpu);
            }

            spin_unlock_irqrestore(&prv->lock, flags);
        }
    }

    return 0;
}

static void *
csched_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom;
    int flags;

    sdom = xmalloc(struct csched_dom);
    if ( sdom == NULL )
        return NULL;
    memset(sdom, 0, sizeof(*sdom));

    /* Initialize credit and weight */
    INIT_LIST_HEAD(&sdom->vcpu);
    INIT_LIST_HEAD(&sdom->sdom_elem);
    sdom->dom = dom;
    sdom->weight = CSCHED_DEFAULT_WEIGHT;
    sdom->nr_vcpus = 0;

    spin_lock_irqsave(&CSCHED_PRIV(ops)->lock, flags);

    list_add_tail(&sdom->sdom_elem, &CSCHED_PRIV(ops)->sdom);

    spin_unlock_irqrestore(&CSCHED_PRIV(ops)->lock, flags);

    return (void *)sdom;
}

static int
csched_dom_init(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom;

    printk("%s: Initializing domain %d\n", __func__, dom->domain_id);

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
    int flags;
    struct csched_dom *sdom = data;

    spin_lock_irqsave(&CSCHED_PRIV(ops)->lock, flags);

    list_del_init(&sdom->sdom_elem);

    spin_unlock_irqrestore(&CSCHED_PRIV(ops)->lock, flags);

    xfree(data);
}

static void
csched_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    struct csched_dom *sdom = CSCHED_DOM(dom);

    BUG_ON(!list_empty(&sdom->vcpu));

    csched_free_domdata(ops, CSCHED_DOM(dom));
}

/* How long should we let this vcpu run for? */
static s_time_t
csched_runtime(const struct scheduler *ops, int cpu, struct csched_vcpu *snext)
{
    s_time_t time = CSCHED_MAX_TIMER;
    struct csched_runqueue_data *rqd = RQD(ops, cpu);
    struct list_head *runq = &rqd->runq;

    if ( is_idle_vcpu(snext->vcpu) )
        return CSCHED_MAX_TIMER;

    /* Basic time */
    time = c2t(rqd, snext->credit, snext);

    /* Next guy on runqueue */
    if ( ! list_empty(runq) )
    {
        struct csched_vcpu *svc = __runq_elem(runq->next);
        s_time_t ntime;

        if ( ! is_idle_vcpu(svc->vcpu) )
        {
            ntime = c2t(rqd, snext->credit - svc->credit, snext);

            if ( time > ntime )
                time = ntime;
        }
    }

    /* Check limits */
    if ( time < CSCHED_MIN_TIMER )
        time = CSCHED_MIN_TIMER;
    else if ( time > CSCHED_MAX_TIMER )
        time = CSCHED_MAX_TIMER;

    return time;
}

void __dump_execstate(void *unused);

/*
 * This function is in the critical path. It is designed to be simple and
 * fast for the common case.
 */
static struct task_slice
csched_schedule(
    const struct scheduler *ops, s_time_t now, bool_t tasklet_work_scheduled)
{
    const int cpu = smp_processor_id();
    struct csched_runqueue_data *rqd = RQD(ops, cpu);
    struct list_head * const runq = &rqd->runq;
    struct csched_vcpu * const scurr = CSCHED_VCPU(current);
    struct csched_vcpu *snext = NULL;
    struct task_slice ret;

    CSCHED_VCPU_CHECK(current);

    d2printk("sc p%d c d%dv%d now %"PRI_stime"\n",
             cpu,
             scurr->vcpu->domain->domain_id,
             scurr->vcpu->vcpu_id,
             now);


    /* Protected by runqueue lock */

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
     * If the current vcpu is runnable, and the next guy on the queue
     * has higher credit, we want to mark current for delayed runqueue
     * add, and remove the next guy from the queue.
     *
     * If the current vcpu is not runnable, we want to chose the idle
     * vcpu for this processor.
     */
    if ( list_empty(runq) || tasklet_work_scheduled )
        snext = CSCHED_VCPU(idle_vcpu[cpu]);
    else
        snext = __runq_elem(runq->next);

    if ( !is_idle_vcpu(current) && vcpu_runnable(current) )
    {
        /* If the current vcpu is runnable, and has higher credit
         * than the next on the runqueue, and isn't being preempted
         * by a tasklet, run him again.
         * Otherwise, set him for delayed runq add. */
        if ( !tasklet_work_scheduled && scurr->credit > snext->credit)
            snext = scurr;
        else
            set_bit(__CSFLAG_delayed_runq_add, &scurr->flags);
    }

    if ( snext != scurr && !is_idle_vcpu(snext->vcpu) )
    {
        __runq_remove(snext);
        if ( snext->vcpu->is_running )
        {
            printk("p%d: snext d%dv%d running on p%d! scurr d%dv%d\n",
                   cpu,
                   snext->vcpu->domain->domain_id, snext->vcpu->vcpu_id,
                   snext->vcpu->processor,
                   scurr->vcpu->domain->domain_id,
                   scurr->vcpu->vcpu_id);
            BUG();
        }
        set_bit(__CSFLAG_scheduled, &snext->flags);
    }

    if ( !is_idle_vcpu(snext->vcpu) && snext->credit <= CSCHED_CREDIT_RESET )
        reset_credit(ops, cpu, now);

#if 0
    /*
     * Update idlers mask if necessary. When we're idling, other CPUs
     * will tickle us when they get extra work.
     */
    if ( is_idle_vcpu(snext->vcpu) )
    {
        if ( !cpu_isset(cpu, csched_priv.idlers) )
            cpu_set(cpu, csched_priv.idlers);
    }
    else if ( cpu_isset(cpu, csched_priv.idlers) )
    {
        cpu_clear(cpu, csched_priv.idlers);
    }
#endif

    ret.migrated = 0;

    if ( !is_idle_vcpu(snext->vcpu) )
    {
        snext->start_time = now;
        /* Safe because lock for old processor is held */
        if ( snext->vcpu->processor != cpu )
        {
            snext->vcpu->processor = cpu;
            ret.migrated = 1;
        }
    }

    /*
     * Return task to run next...
     */
    ret.time = csched_runtime(ops, cpu, snext);
    ret.task = snext->vcpu;

    CSCHED_VCPU_CHECK(ret.task);
    return ret;
}

static void
csched_dump_vcpu(struct csched_vcpu *svc)
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
csched_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct list_head *runq, *iter;
    struct csched_vcpu *svc;
    int loop;
    char cpustr[100];

    /* FIXME: Do locking properly for access to runqueue structures */

    runq = &RQD(ops, cpu)->runq;

    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_sibling_map,cpu));
    printk(" sibling=%s, ", cpustr);
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_core_map,cpu));
    printk("core=%s\n", cpustr);

    /* current VCPU */
    svc = CSCHED_VCPU(per_cpu(schedule_data, cpu).curr);
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
csched_dump(const struct scheduler *ops)
{
    struct list_head *iter_sdom, *iter_svc;
    struct csched_private *prv = CSCHED_PRIV(ops);
    int loop;

    printk("info:\n"
           "\tncpus              = %u\n"
           "\tdefault-weight     = %d\n",
           prv->ncpus,
           CSCHED_DEFAULT_WEIGHT);

    /* FIXME: Locking! */

    printk("active vcpus:\n");
    loop = 0;
    list_for_each( iter_sdom, &prv->sdom )
    {
        struct csched_dom *sdom;
        sdom = list_entry(iter_sdom, struct csched_dom, sdom_elem);

        list_for_each( iter_svc, &sdom->vcpu )
        {
            struct csched_vcpu *svc;
            svc = list_entry(iter_svc, struct csched_vcpu, sdom_elem);

            printk("\t%3d: ", ++loop);
            csched_dump_vcpu(svc);
        }
    }
}

static void
csched_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    unsigned long flags;
    struct csched_private *prv = CSCHED_PRIV(ops);

    spin_lock_irqsave(&prv->lock, flags);
    prv->ncpus--;
    spin_unlock_irqrestore(&prv->lock, flags);

    return;
}

static void *
csched_alloc_pdata(const struct scheduler *ops, int cpu)
{
    spinlock_t *new_lock;
    spinlock_t *old_lock = per_cpu(schedule_data, cpu).schedule_lock;
    unsigned long flags;
    struct csched_private *prv = CSCHED_PRIV(ops);

    spin_lock_irqsave(old_lock, flags);
    new_lock = &per_cpu(schedule_data, prv->runq_map[cpu])._lock;
    per_cpu(schedule_data, cpu).schedule_lock = new_lock;
    spin_unlock_irqrestore(old_lock, flags);

    spin_lock_irqsave(&prv->lock, flags);
    prv->ncpus++;
    spin_unlock_irqrestore(&prv->lock, flags);

    return (void *)1;
}

static void
make_runq_map(struct csched_private *prv)
{
    /* FIXME: Read pcpu layout and do this properly */
    prv->runq_count = 1;
    prv->rqd[0].cpu_min = 0;
    prv->rqd[0].cpu_max = NR_CPUS;
    memset(prv->runq_map, 0, sizeof(prv->runq_map));
}

static int
csched_init(struct scheduler *ops)
{
    int i;
    struct csched_private *prv;

    printk("Initializing Credit2 scheduler\n" \
           " WARNING: This is experimental software in development.\n" \
           " Use at your own risk.\n");

    prv = xmalloc(struct csched_private);
    if ( prv == NULL )
        return -ENOMEM;
    memset(prv, 0, sizeof(*prv));
    ops->sched_data = prv;

    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->sdom);

    prv->ncpus = 0;

    make_runq_map(prv);

    for ( i=0; i<prv->runq_count ; i++ )
    {
        struct csched_runqueue_data *rqd = prv->rqd + i;

        rqd->max_weight = 1;
        rqd->id = i;
        INIT_LIST_HEAD(&rqd->svc);
        INIT_LIST_HEAD(&rqd->runq);
    }

    return 0;
}

static void
csched_deinit(const struct scheduler *ops)
{
    struct csched_private *prv;

    prv = CSCHED_PRIV(ops);
    if ( prv != NULL )
        xfree(prv);
}


static struct csched_private _csched_priv;

const struct scheduler sched_credit2_def = {
    .name           = "SMP Credit Scheduler rev2",
    .opt_name       = "credit2",
    .sched_id       = XEN_SCHEDULER_CREDIT2,
    .sched_data     = &_csched_priv,

    .init_domain    = csched_dom_init,
    .destroy_domain = csched_dom_destroy,

    .insert_vcpu    = csched_vcpu_insert,
    .remove_vcpu    = csched_vcpu_remove,

    .sleep          = csched_vcpu_sleep,
    .wake           = csched_vcpu_wake,

    .adjust         = csched_dom_cntl,

    .pick_cpu       = csched_cpu_pick,
    .do_schedule    = csched_schedule,
    .context_saved  = csched_context_saved,

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
};
