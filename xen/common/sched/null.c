/*
 * xen/common/sched_null.c
 *
 *  Copyright (c) 2017, Dario Faggioli, Citrix Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The 'null' scheduler always choose to run, on each pCPU, either nothing
 * (i.e., the pCPU stays idle) or always the same unit.
 *
 * It is aimed at supporting static scenarios, where there always are
 * less units than pCPUs (and the units don't need to move among pCPUs
 * for any reason) with the least possible overhead.
 *
 * Typical usecase are embedded applications, but also HPC, especially
 * if the scheduler is used inside a cpupool.
 */

#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/trace.h>

#include "private.h"

/*
 * null tracing events. Check include/public/trace.h for more details.
 */
#define TRC_SNULL_PICKED_CPU    TRC_SCHED_CLASS_EVT(SNULL, 1)
#define TRC_SNULL_UNIT_ASSIGN   TRC_SCHED_CLASS_EVT(SNULL, 2)
#define TRC_SNULL_UNIT_DEASSIGN TRC_SCHED_CLASS_EVT(SNULL, 3)
#define TRC_SNULL_MIGRATE       TRC_SCHED_CLASS_EVT(SNULL, 4)
#define TRC_SNULL_SCHEDULE      TRC_SCHED_CLASS_EVT(SNULL, 5)
#define TRC_SNULL_TASKLET       TRC_SCHED_CLASS_EVT(SNULL, 6)

/*
 * Locking:
 * - Scheduler-lock (a.k.a. runqueue lock):
 *  + is per-pCPU;
 *  + serializes assignment and deassignment of units to a pCPU.
 * - Private data lock (a.k.a. private scheduler lock):
 *  + is scheduler-wide;
 *  + serializes accesses to the list of domains in this scheduler.
 * - Waitqueue lock:
 *  + is scheduler-wide;
 *  + serialize accesses to the list of units waiting to be assigned
 *    to pCPUs.
 *
 * Ordering is: private lock, runqueue lock, waitqueue lock. Or, OTOH,
 * waitqueue lock nests inside runqueue lock which nests inside private
 * lock. More specifically:
 *  + if we need both runqueue and private locks, we must acquire the
 *    private lock for first;
 *  + if we need both runqueue and waitqueue locks, we must acquire
 *    the runqueue lock for first;
 *  + if we need both private and waitqueue locks, we must acquire
 *    the private lock for first;
 *  + if we already own a runqueue lock, we must never acquire
 *    the private lock;
 *  + if we already own the waitqueue lock, we must never acquire
 *    the runqueue lock or the private lock.
 */

/*
 * System-wide private data
 */
struct null_private {
    spinlock_t lock;        /* scheduler lock; nests inside cpupool_lock */
    struct list_head ndom;  /* Domains of this scheduler                 */
    struct list_head waitq; /* units not assigned to any pCPU            */
    spinlock_t waitq_lock;  /* serializes waitq; nests inside runq locks */
    cpumask_t cpus_free;    /* CPUs without a unit associated to them    */
};

/*
 * Physical CPU
 */
struct null_pcpu {
    struct sched_unit *unit;
};

/*
 * Schedule unit
 */
struct null_unit {
    struct list_head waitq_elem;
    struct sched_unit *unit;
};

/*
 * Domain
 */
struct null_dom {
    struct list_head ndom_elem;
    struct domain *dom;
};

/*
 * Accessor helpers functions
 */
static inline struct null_private *null_priv(const struct scheduler *ops)
{
    return ops->sched_data;
}

static inline struct null_unit *null_unit(const struct sched_unit *unit)
{
    return unit->priv;
}

static inline bool unit_check_affinity(struct sched_unit *unit,
                                       unsigned int cpu,
                                       unsigned int balance_step)
{
    affinity_balance_cpumask(unit, balance_step, cpumask_scratch_cpu(cpu));
    cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                cpupool_domain_master_cpumask(unit->domain));

    return cpumask_test_cpu(cpu, cpumask_scratch_cpu(cpu));
}

static int null_init(struct scheduler *ops)
{
    struct null_private *prv;

    printk("Initializing null scheduler\n"
           "WARNING: This is experimental software in development.\n"
           "Use at your own risk.\n");

    prv = xzalloc(struct null_private);
    if ( prv == NULL )
        return -ENOMEM;

    spin_lock_init(&prv->lock);
    spin_lock_init(&prv->waitq_lock);
    INIT_LIST_HEAD(&prv->ndom);
    INIT_LIST_HEAD(&prv->waitq);

    ops->sched_data = prv;

    return 0;
}

static void null_deinit(struct scheduler *ops)
{
    xfree(ops->sched_data);
    ops->sched_data = NULL;
}

static void init_pdata(struct null_private *prv, struct null_pcpu *npc,
                       unsigned int cpu)
{
    /* Mark the pCPU as free, and with no unit assigned */
    cpumask_set_cpu(cpu, &prv->cpus_free);
    npc->unit = NULL;
}

static void null_init_pdata(const struct scheduler *ops, void *pdata, int cpu)
{
    struct null_private *prv = null_priv(ops);

    ASSERT(pdata);

    init_pdata(prv, pdata, cpu);
}

static void null_deinit_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct null_private *prv = null_priv(ops);
    struct null_pcpu *npc = pcpu;

    ASSERT(npc);

    cpumask_clear_cpu(cpu, &prv->cpus_free);
    npc->unit = NULL;
}

static void *null_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct null_pcpu *npc;

    npc = xzalloc(struct null_pcpu);
    if ( npc == NULL )
        return ERR_PTR(-ENOMEM);

    return npc;
}

static void null_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    xfree(pcpu);
}

static void *null_alloc_udata(const struct scheduler *ops,
                              struct sched_unit *unit, void *dd)
{
    struct null_unit *nvc;

    nvc = xzalloc(struct null_unit);
    if ( nvc == NULL )
        return NULL;

    INIT_LIST_HEAD(&nvc->waitq_elem);
    nvc->unit = unit;

    SCHED_STAT_CRANK(unit_alloc);

    return nvc;
}

static void null_free_udata(const struct scheduler *ops, void *priv)
{
    struct null_unit *nvc = priv;

    xfree(nvc);
}

static void * null_alloc_domdata(const struct scheduler *ops,
                                 struct domain *d)
{
    struct null_private *prv = null_priv(ops);
    struct null_dom *ndom;
    unsigned long flags;

    ndom = xzalloc(struct null_dom);
    if ( ndom == NULL )
        return ERR_PTR(-ENOMEM);

    ndom->dom = d;

    spin_lock_irqsave(&prv->lock, flags);
    list_add_tail(&ndom->ndom_elem, &null_priv(ops)->ndom);
    spin_unlock_irqrestore(&prv->lock, flags);

    return ndom;
}

static void null_free_domdata(const struct scheduler *ops, void *data)
{
    struct null_dom *ndom = data;
    struct null_private *prv = null_priv(ops);

    if ( ndom )
    {
        unsigned long flags;

        spin_lock_irqsave(&prv->lock, flags);
        list_del_init(&ndom->ndom_elem);
        spin_unlock_irqrestore(&prv->lock, flags);

        xfree(ndom);
    }
}

/*
 * unit to pCPU assignment and placement. This _only_ happens:
 *  - on insert,
 *  - on migrate.
 *
 * Insert occurs when a unit joins this scheduler for the first time
 * (e.g., when the domain it's part of is moved to the scheduler's
 * cpupool).
 *
 * Migration may be necessary if a pCPU (with a unit assigned to it)
 * is removed from the scheduler's cpupool.
 *
 * So this is not part of any hot path.
 */
static struct sched_resource *
pick_res(struct null_private *prv, const struct sched_unit *unit)
{
    unsigned int bs;
    unsigned int cpu = sched_unit_master(unit), new_cpu;
    cpumask_t *cpus = cpupool_domain_master_cpumask(unit->domain);
    struct null_pcpu *npc = get_sched_res(cpu)->sched_priv;

    ASSERT(spin_is_locked(get_sched_res(cpu)->schedule_lock));

    for_each_affinity_balance_step( bs )
    {
        if ( bs == BALANCE_SOFT_AFFINITY && !has_soft_affinity(unit) )
            continue;

        affinity_balance_cpumask(unit, bs, cpumask_scratch_cpu(cpu));
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu), cpus);

        /*
         * If our processor is free, or we are assigned to it, and it is also
         * still valid and part of our affinity, just go for it.
         * (Note that we may call unit_check_affinity(), but we deliberately
         * don't, so we get to keep in the scratch cpumask what we have just
         * put in it.)
         */
        if ( likely((npc->unit == NULL || npc->unit == unit)
                    && cpumask_test_cpu(cpu, cpumask_scratch_cpu(cpu))) )
        {
            new_cpu = cpu;
            goto out;
        }

        /* If not, just go for a free pCPU, within our affinity, if any */
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                    &prv->cpus_free);
        new_cpu = cpumask_first(cpumask_scratch_cpu(cpu));

        if ( likely(new_cpu != nr_cpu_ids) )
            goto out;
    }

    /*
     * If we didn't find any free pCPU, just pick any valid pcpu, even if
     * it has another unit assigned. This will happen during shutdown and
     * suspend/resume, but it may also happen during "normal operation", if
     * all the pCPUs are busy.
     *
     * In fact, there must always be something sane in v->processor, or
     * unit_schedule_lock() and friends won't work. This is not a problem,
     * as we will actually assign the unit to the pCPU we return from here,
     * only if the pCPU is free.
     */
    cpumask_and(cpumask_scratch_cpu(cpu), cpus, unit->cpu_hard_affinity);
    new_cpu = cpumask_any(cpumask_scratch_cpu(cpu));

 out:
    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t unit, dom;
            uint32_t new_cpu;
        } d;
        d.dom = unit->domain->domain_id;
        d.unit = unit->unit_id;
        d.new_cpu = new_cpu;
        __trace_var(TRC_SNULL_PICKED_CPU, 1, sizeof(d), &d);
    }

    return get_sched_res(new_cpu);
}

static void unit_assign(struct null_private *prv, struct sched_unit *unit,
                        unsigned int cpu)
{
    struct null_pcpu *npc = get_sched_res(cpu)->sched_priv;

    ASSERT(is_unit_online(unit));

    npc->unit = unit;
    sched_set_res(unit, get_sched_res(cpu));
    cpumask_clear_cpu(cpu, &prv->cpus_free);

    dprintk(XENLOG_G_INFO, "%d <-- %pdv%d\n", cpu, unit->domain, unit->unit_id);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t unit, dom;
            uint32_t cpu;
        } d;
        d.dom = unit->domain->domain_id;
        d.unit = unit->unit_id;
        d.cpu = cpu;
        __trace_var(TRC_SNULL_UNIT_ASSIGN, 1, sizeof(d), &d);
    }
}

/* Returns true if a cpu was tickled */
static bool unit_deassign(struct null_private *prv, struct sched_unit *unit)
{
    unsigned int bs;
    unsigned int cpu = sched_unit_master(unit);
    struct null_unit *wvc;
    struct null_pcpu *npc = get_sched_res(cpu)->sched_priv;

    ASSERT(list_empty(&null_unit(unit)->waitq_elem));
    ASSERT(npc->unit == unit);
    ASSERT(!cpumask_test_cpu(cpu, &prv->cpus_free));

    npc->unit = NULL;
    cpumask_set_cpu(cpu, &prv->cpus_free);

    dprintk(XENLOG_G_INFO, "%d <-- NULL (%pdv%d)\n", cpu, unit->domain,
            unit->unit_id);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t unit, dom;
            uint32_t cpu;
        } d;
        d.dom = unit->domain->domain_id;
        d.unit = unit->unit_id;
        d.cpu = cpu;
        __trace_var(TRC_SNULL_UNIT_DEASSIGN, 1, sizeof(d), &d);
    }

    spin_lock(&prv->waitq_lock);

    /*
     * If unit is assigned to a pCPU, let's see if there is someone waiting,
     * suitable to be assigned to it (prioritizing units that have
     * soft-affinity with cpu).
     */
    for_each_affinity_balance_step( bs )
    {
        list_for_each_entry( wvc, &prv->waitq, waitq_elem )
        {
            if ( bs == BALANCE_SOFT_AFFINITY &&
                 !has_soft_affinity(wvc->unit) )
                continue;

            if ( unit_check_affinity(wvc->unit, cpu, bs) )
            {
                list_del_init(&wvc->waitq_elem);
                unit_assign(prv, wvc->unit, cpu);
                cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
                spin_unlock(&prv->waitq_lock);
                return true;
            }
        }
    }
    spin_unlock(&prv->waitq_lock);

    return false;
}

/* Change the scheduler of cpu to us (null). */
static spinlock_t *null_switch_sched(struct scheduler *new_ops,
                                     unsigned int cpu,
                                     void *pdata, void *vdata)
{
    struct sched_resource *sr = get_sched_res(cpu);
    struct null_private *prv = null_priv(new_ops);
    struct null_unit *nvc = vdata;

    ASSERT(nvc && is_idle_unit(nvc->unit));

    sched_idle_unit(cpu)->priv = vdata;

    /*
     * We are holding the runqueue lock already (it's been taken in
     * schedule_cpu_switch()). It actually may or may not be the 'right'
     * one for this cpu, but that is ok for preventing races.
     */
    ASSERT(!local_irq_is_enabled());

    init_pdata(prv, pdata, cpu);

    return &sr->_lock;
}

static void null_unit_insert(const struct scheduler *ops,
                             struct sched_unit *unit)
{
    struct null_private *prv = null_priv(ops);
    struct null_unit *nvc = null_unit(unit);
    struct null_pcpu *npc;
    unsigned int cpu;
    spinlock_t *lock;

    ASSERT(!is_idle_unit(unit));

    lock = unit_schedule_lock_irq(unit);

    if ( unlikely(!is_unit_online(unit)) )
    {
        unit_schedule_unlock_irq(lock, unit);
        return;
    }

 retry:
    sched_set_res(unit, pick_res(prv, unit));
    cpu = sched_unit_master(unit);
    npc = get_sched_res(cpu)->sched_priv;

    spin_unlock(lock);

    lock = unit_schedule_lock(unit);

    cpumask_and(cpumask_scratch_cpu(cpu), unit->cpu_hard_affinity,
                cpupool_domain_master_cpumask(unit->domain));

    /* If the pCPU is free, we assign unit to it */
    if ( likely(npc->unit == NULL) )
    {
        /*
         * Insert is followed by vcpu_wake(), so there's no need to poke
         * the pcpu with the SCHEDULE_SOFTIRQ, as wake will do that.
         */
        unit_assign(prv, unit, cpu);
    }
    else if ( cpumask_intersects(&prv->cpus_free, cpumask_scratch_cpu(cpu)) )
    {
        /*
         * If the pCPU is not free (e.g., because we raced with another
         * insert or a migrate), but there are other free pCPUs, we can
         * try to pick again.
         */
         goto retry;
    }
    else
    {
        /*
         * If the pCPU is not free, and there aren't any (valid) others,
         * we have no alternatives than to go into the waitqueue.
         */
        spin_lock(&prv->waitq_lock);
        list_add_tail(&nvc->waitq_elem, &prv->waitq);
        dprintk(XENLOG_G_WARNING, "WARNING: %pdv%d not assigned to any CPU!\n",
                unit->domain, unit->unit_id);
        spin_unlock(&prv->waitq_lock);
    }
    spin_unlock_irq(lock);

    SCHED_STAT_CRANK(unit_insert);
}

static void null_unit_remove(const struct scheduler *ops,
                             struct sched_unit *unit)
{
    struct null_private *prv = null_priv(ops);
    struct null_unit *nvc = null_unit(unit);
    spinlock_t *lock;

    ASSERT(!is_idle_unit(unit));

    lock = unit_schedule_lock_irq(unit);

    /* If offline, the unit shouldn't be assigned, nor in the waitqueue */
    if ( unlikely(!is_unit_online(unit)) )
    {
        struct null_pcpu *npc;

        npc = unit->res->sched_priv;
        ASSERT(npc->unit != unit);
        ASSERT(list_empty(&nvc->waitq_elem));
        goto out;
    }

    /* If unit is in waitqueue, just get it out of there and bail */
    if ( unlikely(!list_empty(&nvc->waitq_elem)) )
    {
        spin_lock(&prv->waitq_lock);
        list_del_init(&nvc->waitq_elem);
        spin_unlock(&prv->waitq_lock);

        goto out;
    }

    unit_deassign(prv, unit);

 out:
    unit_schedule_unlock_irq(lock, unit);

    SCHED_STAT_CRANK(unit_remove);
}

static void null_unit_wake(const struct scheduler *ops,
                           struct sched_unit *unit)
{
    struct null_private *prv = null_priv(ops);
    struct null_unit *nvc = null_unit(unit);
    unsigned int cpu = sched_unit_master(unit);
    struct null_pcpu *npc = get_sched_res(cpu)->sched_priv;

    ASSERT(!is_idle_unit(unit));

    if ( unlikely(curr_on_cpu(sched_unit_master(unit)) == unit) )
    {
        SCHED_STAT_CRANK(unit_wake_running);
        return;
    }

    if ( unlikely(!list_empty(&nvc->waitq_elem)) )
    {
        /* Not exactly "on runq", but close enough for reusing the counter */
        SCHED_STAT_CRANK(unit_wake_onrunq);
        return;
    }

    if ( likely(unit_runnable(unit)) )
        SCHED_STAT_CRANK(unit_wake_runnable);
    else
        SCHED_STAT_CRANK(unit_wake_not_runnable);

    if ( likely(npc->unit == unit) )
    {
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
        return;
    }

    /*
     * If a unit is neither on a pCPU nor in the waitqueue, it means it was
     * offline, and that it is now coming back being online. If we're lucky,
     * and its previous resource is free (and affinities match), we can just
     * assign the unit to it (we own the proper lock already) and be done.
     */
    if ( npc->unit == NULL &&
         unit_check_affinity(unit, cpu, BALANCE_HARD_AFFINITY) )
    {
        if ( !has_soft_affinity(unit) ||
             unit_check_affinity(unit, cpu, BALANCE_SOFT_AFFINITY) )
        {
            unit_assign(prv, unit, cpu);
            cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
            return;
        }
    }

    /*
     * If the resource is not free (or affinities do not match) we need
     * to assign unit to some other one, but we can't do it here, as:
     * - we don't own  the proper lock,
     * - we can't change v->processor under vcpu_wake()'s feet.
     * So we add it to the waitqueue, and tickle all the free CPUs (if any)
     * on which unit can run. The first one that schedules will pick it up.
     */
    spin_lock(&prv->waitq_lock);
    list_add_tail(&nvc->waitq_elem, &prv->waitq);
    spin_unlock(&prv->waitq_lock);

    cpumask_and(cpumask_scratch_cpu(cpu), unit->cpu_hard_affinity,
                cpupool_domain_master_cpumask(unit->domain));
    cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                &prv->cpus_free);

    if ( cpumask_empty(cpumask_scratch_cpu(cpu)) )
        dprintk(XENLOG_G_WARNING, "WARNING: d%dv%d not assigned to any CPU!\n",
                unit->domain->domain_id, unit->unit_id);
    else
        cpumask_raise_softirq(cpumask_scratch_cpu(cpu), SCHEDULE_SOFTIRQ);
}

static void null_unit_sleep(const struct scheduler *ops,
                            struct sched_unit *unit)
{
    struct null_private *prv = null_priv(ops);
    unsigned int cpu = sched_unit_master(unit);
    struct null_pcpu *npc = get_sched_res(cpu)->sched_priv;
    bool tickled = false;

    ASSERT(!is_idle_unit(unit));

    /*
     * Check if the unit is in the process of being offlined. If yes,
     * we need to remove it from either its pCPU or the waitqueue.
     */
    if ( unlikely(!is_unit_online(unit)) )
    {
        struct null_unit *nvc = null_unit(unit);

        if ( unlikely(!list_empty(&nvc->waitq_elem)) )
        {
            spin_lock(&prv->waitq_lock);
            list_del_init(&nvc->waitq_elem);
            spin_unlock(&prv->waitq_lock);
        }
        else if ( npc->unit == unit )
            tickled = unit_deassign(prv, unit);
    }

    /* If unit is not assigned to a pCPU, or is not running, no need to bother */
    if ( likely(!tickled && curr_on_cpu(cpu) == unit) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);

    SCHED_STAT_CRANK(unit_sleep);
}

static struct sched_resource *
null_res_pick(const struct scheduler *ops, const struct sched_unit *unit)
{
    ASSERT(!is_idle_unit(unit));
    return pick_res(null_priv(ops), unit);
}

static void null_unit_migrate(const struct scheduler *ops,
                              struct sched_unit *unit, unsigned int new_cpu)
{
    struct null_private *prv = null_priv(ops);
    struct null_unit *nvc = null_unit(unit);
    struct null_pcpu *npc;

    ASSERT(!is_idle_unit(unit));

    if ( sched_unit_master(unit) == new_cpu )
        return;

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t unit, dom;
            uint16_t cpu, new_cpu;
        } d;
        d.dom = unit->domain->domain_id;
        d.unit = unit->unit_id;
        d.cpu = sched_unit_master(unit);
        d.new_cpu = new_cpu;
        __trace_var(TRC_SNULL_MIGRATE, 1, sizeof(d), &d);
    }

    /*
     * If unit is assigned to a pCPU, then such pCPU becomes free, and we
     * should look in the waitqueue if anyone else can be assigned to it.
     */
    npc = unit->res->sched_priv;
    if ( likely(npc->unit == unit) )
    {
        unit_deassign(prv, unit);
        SCHED_STAT_CRANK(migrate_running);
    }
    else if ( !list_empty(&nvc->waitq_elem) )
        SCHED_STAT_CRANK(migrate_on_runq);

    SCHED_STAT_CRANK(migrated);

    /*
     * If a unit is (going) offline, we want it to be neither assigned
     * to a pCPU, nor in the waitqueue.
     *
     * If it was on a cpu, we've removed it from there above. If it is
     * in the waitqueue, we remove it from there now. And then we bail.
     */
    if ( unlikely(!is_unit_online(unit)) )
    {
        spin_lock(&prv->waitq_lock);
        list_del_init(&nvc->waitq_elem);
        spin_unlock(&prv->waitq_lock);
        goto out;
    }

    /*
     * Let's now consider new_cpu, which is where unit is being sent. It can be
     * either free, or have a unit already assigned to it.
     *
     * In the former case we should assign unit to it, and try to get it to run,
     * if possible, according to affinity.
     *
     * In latter, all we can do is to park unit in the waitqueue.
     */
    npc = get_sched_res(new_cpu)->sched_priv;
    if ( npc->unit == NULL &&
         unit_check_affinity(unit, new_cpu, BALANCE_HARD_AFFINITY) )
    {
        /* unit might have been in the waitqueue, so remove it */
        spin_lock(&prv->waitq_lock);
        list_del_init(&nvc->waitq_elem);
        spin_unlock(&prv->waitq_lock);

        unit_assign(prv, unit, new_cpu);
    }
    else
    {
        /* Put unit in the waitqueue, if it wasn't there already */
        spin_lock(&prv->waitq_lock);
        if ( list_empty(&nvc->waitq_elem) )
        {
            list_add_tail(&nvc->waitq_elem, &prv->waitq);
            dprintk(XENLOG_G_WARNING,
                    "WARNING: %pdv%d not assigned to any CPU!\n", unit->domain,
                    unit->unit_id);
        }
        spin_unlock(&prv->waitq_lock);
    }

    /*
     * Whatever all the above, we always at least override v->processor.
     * This is especially important for shutdown or suspend/resume paths,
     * when it is important to let our caller (cpu_disable_scheduler())
     * know that the migration did happen, to the best of our possibilities,
     * at least. In case of suspend, any temporary inconsistency caused
     * by this, will be fixed-up during resume.
     */
 out:
    sched_set_res(unit, get_sched_res(new_cpu));
}

#ifndef NDEBUG
static inline void null_unit_check(struct sched_unit *unit)
{
    struct null_unit * const nvc = null_unit(unit);
    struct null_dom * const ndom = unit->domain->sched_priv;

    BUG_ON(nvc->unit != unit);

    if ( ndom )
        BUG_ON(is_idle_unit(unit));
    else
        BUG_ON(!is_idle_unit(unit));

    SCHED_STAT_CRANK(unit_check);
}
#define NULL_UNIT_CHECK(unit)  (null_unit_check(unit))
#else
#define NULL_UNIT_CHECK(unit)
#endif


/*
 * The most simple scheduling function of all times! We either return:
 *  - the unit assigned to the pCPU, if there's one and it can run;
 *  - the idle unit, otherwise.
 */
static void null_schedule(const struct scheduler *ops, struct sched_unit *prev,
                          s_time_t now, bool tasklet_work_scheduled)
{
    unsigned int bs;
    const unsigned int cur_cpu = smp_processor_id();
    const unsigned int sched_cpu = sched_get_resource_cpu(cur_cpu);
    struct null_pcpu *npc = get_sched_res(sched_cpu)->sched_priv;
    struct null_private *prv = null_priv(ops);
    struct null_unit *wvc;

    SCHED_STAT_CRANK(schedule);
    NULL_UNIT_CHECK(current->sched_unit);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t tasklet, cpu;
            int16_t unit, dom;
        } d;
        d.cpu = cur_cpu;
        d.tasklet = tasklet_work_scheduled;
        if ( npc->unit == NULL )
        {
            d.unit = d.dom = -1;
        }
        else
        {
            d.unit = npc->unit->unit_id;
            d.dom = npc->unit->domain->domain_id;
        }
        __trace_var(TRC_SNULL_SCHEDULE, 1, sizeof(d), &d);
    }

    if ( tasklet_work_scheduled )
    {
        trace_var(TRC_SNULL_TASKLET, 1, 0, NULL);
        prev->next_task = sched_idle_unit(sched_cpu);
    }
    else
        prev->next_task = npc->unit;
    prev->next_time = -1;

    /*
     * We may be new in the cpupool, or just coming back online. In which
     * case, there may be units in the waitqueue that we can assign to us
     * and run.
     */
    if ( unlikely(prev->next_task == NULL) )
    {
        bool unit_found;

        spin_lock(&prv->waitq_lock);

        if ( list_empty(&prv->waitq) )
            goto unlock;

        /*
         * We scan the waitqueue twice, for prioritizing units that have
         * soft-affinity with cpu. This may look like something expensive to
         * do here in null_schedule(), but it's actually fine, because we do
         * it only in cases where a pcpu has no unit associated (e.g., as
         * said above, the cpu has just joined a cpupool).
         */
        unit_found = false;
        for_each_affinity_balance_step( bs )
        {
            list_for_each_entry( wvc, &prv->waitq, waitq_elem )
            {
                if ( bs == BALANCE_SOFT_AFFINITY &&
                     !has_soft_affinity(wvc->unit) )
                    continue;

                if ( unit_check_affinity(wvc->unit, sched_cpu, bs) )
                {
                    spinlock_t *lock;

                    unit_found = true;

                    /*
                     * If the unit in the waitqueue has just come up online,
                     * we risk racing with vcpu_wake(). To avoid this, sync
                     * on the spinlock that vcpu_wake() holds, but only with
                     * trylock, to avoid deadlock).
                     */
                    lock = pcpu_schedule_trylock(sched_unit_master(wvc->unit));

                    /*
                     * We know the vcpu's lock is not this resource's lock. In
                     * fact, if it were, since this cpu is free, vcpu_wake()
                     * would have assigned the unit to here directly.
                     */
                    ASSERT(lock != get_sched_res(sched_cpu)->schedule_lock);

                    if ( lock ) {
                        unit_assign(prv, wvc->unit, sched_cpu);
                        list_del_init(&wvc->waitq_elem);
                        prev->next_task = wvc->unit;
                        spin_unlock(lock);
                        goto unlock;
                    }
                }
            }
        }
        /*
         * If we did find a unit with suitable affinity in the waitqueue, but
         * we could not pick it up (due to lock contention), and hence we are
         * still free, plan for another try. In fact, we don't want such unit
         * to be stuck in the waitqueue, when there are free cpus where it
         * could run.
         */
        if ( unlikely( unit_found && prev->next_task == NULL &&
                       !list_empty(&prv->waitq)) )
            cpu_raise_softirq(cur_cpu, SCHEDULE_SOFTIRQ);
 unlock:
        spin_unlock(&prv->waitq_lock);

        if ( prev->next_task == NULL &&
             !cpumask_test_cpu(sched_cpu, &prv->cpus_free) )
            cpumask_set_cpu(sched_cpu, &prv->cpus_free);
    }

    if ( unlikely(prev->next_task == NULL ||
                  !unit_runnable_state(prev->next_task)) )
        prev->next_task = sched_idle_unit(sched_cpu);

    NULL_UNIT_CHECK(prev->next_task);

    prev->next_task->migrated = false;
}

static inline void dump_unit(struct null_private *prv, struct null_unit *nvc)
{
    printk("[%i.%i] pcpu=%d", nvc->unit->domain->domain_id,
            nvc->unit->unit_id, list_empty(&nvc->waitq_elem) ?
                                sched_unit_master(nvc->unit) : -1);
}

static void null_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct null_private *prv = null_priv(ops);
    struct null_pcpu *npc = get_sched_res(cpu)->sched_priv;
    struct null_unit *nvc;
    spinlock_t *lock;
    unsigned long flags;

    lock = pcpu_schedule_lock_irqsave(cpu, &flags);

    printk("CPU[%02d] sibling={%*pbl}, core={%*pbl}",
           cpu, CPUMASK_PR(per_cpu(cpu_sibling_mask, cpu)),
           CPUMASK_PR(per_cpu(cpu_core_mask, cpu)));
    if ( npc->unit != NULL )
        printk(", unit=%pdv%d", npc->unit->domain, npc->unit->unit_id);
    printk("\n");

    /* current unit (nothing to say if that's the idle unit) */
    nvc = null_unit(curr_on_cpu(cpu));
    if ( nvc && !is_idle_unit(nvc->unit) )
    {
        printk("\trun: ");
        dump_unit(prv, nvc);
        printk("\n");
    }

    pcpu_schedule_unlock_irqrestore(lock, flags, cpu);
}

static void null_dump(const struct scheduler *ops)
{
    struct null_private *prv = null_priv(ops);
    struct list_head *iter;
    unsigned long flags;
    unsigned int loop;

    spin_lock_irqsave(&prv->lock, flags);

    printk("\tcpus_free = %*pbl\n", CPUMASK_PR(&prv->cpus_free));

    printk("Domain info:\n");
    loop = 0;
    list_for_each( iter, &prv->ndom )
    {
        struct null_dom *ndom;
        struct sched_unit *unit;

        ndom = list_entry(iter, struct null_dom, ndom_elem);

        printk("\tDomain: %d\n", ndom->dom->domain_id);
        for_each_sched_unit( ndom->dom, unit )
        {
            struct null_unit * const nvc = null_unit(unit);
            spinlock_t *lock;

            lock = unit_schedule_lock(unit);

            printk("\t%3d: ", ++loop);
            dump_unit(prv, nvc);
            printk("\n");

            unit_schedule_unlock(lock, unit);
        }
    }

    printk("Waitqueue: ");
    loop = 0;
    spin_lock(&prv->waitq_lock);
    list_for_each( iter, &prv->waitq )
    {
        struct null_unit *nvc = list_entry(iter, struct null_unit, waitq_elem);

        if ( loop++ != 0 )
            printk(", ");
        if ( loop % 24 == 0 )
            printk("\n\t");
        printk("%pdv%d", nvc->unit->domain, nvc->unit->unit_id);
    }
    printk("\n");
    spin_unlock(&prv->waitq_lock);

    spin_unlock_irqrestore(&prv->lock, flags);
}

static const struct scheduler sched_null_def = {
    .name           = "null Scheduler",
    .opt_name       = "null",
    .sched_id       = XEN_SCHEDULER_NULL,
    .sched_data     = NULL,

    .init           = null_init,
    .deinit         = null_deinit,
    .alloc_pdata    = null_alloc_pdata,
    .free_pdata     = null_free_pdata,
    .init_pdata     = null_init_pdata,
    .switch_sched   = null_switch_sched,
    .deinit_pdata   = null_deinit_pdata,

    .alloc_udata    = null_alloc_udata,
    .free_udata     = null_free_udata,
    .alloc_domdata  = null_alloc_domdata,
    .free_domdata   = null_free_domdata,

    .insert_unit    = null_unit_insert,
    .remove_unit    = null_unit_remove,

    .wake           = null_unit_wake,
    .sleep          = null_unit_sleep,
    .pick_resource  = null_res_pick,
    .migrate        = null_unit_migrate,
    .do_schedule    = null_schedule,

    .dump_cpu_state = null_dump_pcpu,
    .dump_settings  = null_dump,
};

REGISTER_SCHEDULER(sched_null_def);
