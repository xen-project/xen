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
 * (i.e., the pCPU stays idle) or always the same vCPU.
 *
 * It is aimed at supporting static scenarios, where there always are
 * less vCPUs than pCPUs (and the vCPUs don't need to move among pCPUs
 * for any reason) with the least possible overhead.
 *
 * Typical usecase are embedded applications, but also HPC, especially
 * if the scheduler is used inside a cpupool.
 */

#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <xen/trace.h>

/*
 * null tracing events. Check include/public/trace.h for more details.
 */
#define TRC_SNULL_PICKED_CPU    TRC_SCHED_CLASS_EVT(SNULL, 1)
#define TRC_SNULL_VCPU_ASSIGN   TRC_SCHED_CLASS_EVT(SNULL, 2)
#define TRC_SNULL_VCPU_DEASSIGN TRC_SCHED_CLASS_EVT(SNULL, 3)
#define TRC_SNULL_MIGRATE       TRC_SCHED_CLASS_EVT(SNULL, 4)
#define TRC_SNULL_SCHEDULE      TRC_SCHED_CLASS_EVT(SNULL, 5)
#define TRC_SNULL_TASKLET       TRC_SCHED_CLASS_EVT(SNULL, 6)

/*
 * Locking:
 * - Scheduler-lock (a.k.a. runqueue lock):
 *  + is per-pCPU;
 *  + serializes assignment and deassignment of vCPUs to a pCPU.
 * - Private data lock (a.k.a. private scheduler lock):
 *  + is scheduler-wide;
 *  + serializes accesses to the list of domains in this scheduler.
 * - Waitqueue lock:
 *  + is scheduler-wide;
 *  + serialize accesses to the list of vCPUs waiting to be assigned
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
    struct list_head waitq; /* vCPUs not assigned to any pCPU            */
    spinlock_t waitq_lock;  /* serializes waitq; nests inside runq locks */
    cpumask_t cpus_free;    /* CPUs without a vCPU associated to them    */
};

/*
 * Physical CPU
 */
struct null_pcpu {
    struct vcpu *vcpu;
};
DEFINE_PER_CPU(struct null_pcpu, npc);

/*
 * Virtual CPU
 */
struct null_vcpu {
    struct list_head waitq_elem;
    struct vcpu *vcpu;
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

static inline struct null_vcpu *null_vcpu(const struct vcpu *v)
{
    return v->sched_priv;
}

static inline bool vcpu_check_affinity(struct vcpu *v, unsigned int cpu,
                                       unsigned int balance_step)
{
    affinity_balance_cpumask(v, balance_step, cpumask_scratch_cpu(cpu));
    cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu),
                cpupool_domain_cpumask(v->domain));

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

static void init_pdata(struct null_private *prv, unsigned int cpu)
{
    /* Mark the pCPU as free, and with no vCPU assigned */
    cpumask_set_cpu(cpu, &prv->cpus_free);
    per_cpu(npc, cpu).vcpu = NULL;
}

static void null_init_pdata(const struct scheduler *ops, void *pdata, int cpu)
{
    struct null_private *prv = null_priv(ops);
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);

    /* alloc_pdata is not implemented, so we want this to be NULL. */
    ASSERT(!pdata);

    /*
     * The scheduler lock points already to the default per-cpu spinlock,
     * so there is no remapping to be done.
     */
    ASSERT(sd->schedule_lock == &sd->_lock && !spin_is_locked(&sd->_lock));

    init_pdata(prv, cpu);
}

static void null_deinit_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct null_private *prv = null_priv(ops);

    /* alloc_pdata not implemented, so this must have stayed NULL */
    ASSERT(!pcpu);

    cpumask_clear_cpu(cpu, &prv->cpus_free);
    per_cpu(npc, cpu).vcpu = NULL;
}

static void *null_alloc_vdata(const struct scheduler *ops,
                              struct vcpu *v, void *dd)
{
    struct null_vcpu *nvc;

    nvc = xzalloc(struct null_vcpu);
    if ( nvc == NULL )
        return NULL;

    INIT_LIST_HEAD(&nvc->waitq_elem);
    nvc->vcpu = v;

    SCHED_STAT_CRANK(vcpu_alloc);

    return nvc;
}

static void null_free_vdata(const struct scheduler *ops, void *priv)
{
    struct null_vcpu *nvc = priv;

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
 * vCPU to pCPU assignment and placement. This _only_ happens:
 *  - on insert,
 *  - on migrate.
 *
 * Insert occurs when a vCPU joins this scheduler for the first time
 * (e.g., when the domain it's part of is moved to the scheduler's
 * cpupool).
 *
 * Migration may be necessary if a pCPU (with a vCPU assigned to it)
 * is removed from the scheduler's cpupool.
 *
 * So this is not part of any hot path.
 */
static unsigned int pick_cpu(struct null_private *prv, struct vcpu *v)
{
    unsigned int bs;
    unsigned int cpu = v->processor, new_cpu;
    cpumask_t *cpus = cpupool_domain_cpumask(v->domain);

    ASSERT(spin_is_locked(per_cpu(schedule_data, cpu).schedule_lock));

    for_each_affinity_balance_step( bs )
    {
        if ( bs == BALANCE_SOFT_AFFINITY && !has_soft_affinity(v) )
            continue;

        affinity_balance_cpumask(v, bs, cpumask_scratch_cpu(cpu));
        cpumask_and(cpumask_scratch_cpu(cpu), cpumask_scratch_cpu(cpu), cpus);

        /*
         * If our processor is free, or we are assigned to it, and it is also
         * still valid and part of our affinity, just go for it.
         * (Note that we may call vcpu_check_affinity(), but we deliberately
         * don't, so we get to keep in the scratch cpumask what we have just
         * put in it.)
         */
        if ( likely((per_cpu(npc, cpu).vcpu == NULL || per_cpu(npc, cpu).vcpu == v)
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
     * it has another vCPU assigned. This will happen during shutdown and
     * suspend/resume, but it may also happen during "normal operation", if
     * all the pCPUs are busy.
     *
     * In fact, there must always be something sane in v->processor, or
     * vcpu_schedule_lock() and friends won't work. This is not a problem,
     * as we will actually assign the vCPU to the pCPU we return from here,
     * only if the pCPU is free.
     */
    cpumask_and(cpumask_scratch_cpu(cpu), cpus, v->cpu_hard_affinity);
    new_cpu = cpumask_any(cpumask_scratch_cpu(cpu));

 out:
    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t vcpu, dom;
            uint32_t new_cpu;
        } d;
        d.dom = v->domain->domain_id;
        d.vcpu = v->vcpu_id;
        d.new_cpu = new_cpu;
        __trace_var(TRC_SNULL_PICKED_CPU, 1, sizeof(d), &d);
    }

    return new_cpu;
}

static void vcpu_assign(struct null_private *prv, struct vcpu *v,
                        unsigned int cpu)
{
    per_cpu(npc, cpu).vcpu = v;
    v->processor = cpu;
    cpumask_clear_cpu(cpu, &prv->cpus_free);

    dprintk(XENLOG_G_INFO, "%d <-- %pv\n", cpu, v);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t vcpu, dom;
            uint32_t cpu;
        } d;
        d.dom = v->domain->domain_id;
        d.vcpu = v->vcpu_id;
        d.cpu = cpu;
        __trace_var(TRC_SNULL_VCPU_ASSIGN, 1, sizeof(d), &d);
    }
}

static void vcpu_deassign(struct null_private *prv, struct vcpu *v)
{
    unsigned int bs;
    unsigned int cpu = v->processor;
    struct null_vcpu *wvc;

    ASSERT(list_empty(&null_vcpu(v)->waitq_elem));

    per_cpu(npc, cpu).vcpu = NULL;
    cpumask_set_cpu(cpu, &prv->cpus_free);

    dprintk(XENLOG_G_INFO, "%d <-- NULL (%pv)\n", cpu, v);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t vcpu, dom;
            uint32_t cpu;
        } d;
        d.dom = v->domain->domain_id;
        d.vcpu = v->vcpu_id;
        d.cpu = cpu;
        __trace_var(TRC_SNULL_VCPU_DEASSIGN, 1, sizeof(d), &d);
    }

    spin_lock(&prv->waitq_lock);

    /*
     * If v is assigned to a pCPU, let's see if there is someone waiting,
     * suitable to be assigned to it (prioritizing vcpus that have
     * soft-affinity with cpu).
     */
    for_each_affinity_balance_step( bs )
    {
        list_for_each_entry( wvc, &prv->waitq, waitq_elem )
        {
            if ( bs == BALANCE_SOFT_AFFINITY && !has_soft_affinity(wvc->vcpu) )
                continue;

            if ( vcpu_check_affinity(wvc->vcpu, cpu, bs) )
            {
                list_del_init(&wvc->waitq_elem);
                vcpu_assign(prv, wvc->vcpu, cpu);
                cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
                spin_unlock(&prv->waitq_lock);
                return;
            }
        }
    }
    spin_unlock(&prv->waitq_lock);
}

/* Change the scheduler of cpu to us (null). */
static spinlock_t *null_switch_sched(struct scheduler *new_ops,
                                     unsigned int cpu,
                                     void *pdata, void *vdata)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    struct null_private *prv = null_priv(new_ops);
    struct null_vcpu *nvc = vdata;

    ASSERT(nvc && is_idle_vcpu(nvc->vcpu));

    idle_vcpu[cpu]->sched_priv = vdata;

    /*
     * We are holding the runqueue lock already (it's been taken in
     * schedule_cpu_switch()). It actually may or may not be the 'right'
     * one for this cpu, but that is ok for preventing races.
     */
    ASSERT(!local_irq_is_enabled());

    init_pdata(prv, cpu);

    return &sd->_lock;
}

static void null_vcpu_insert(const struct scheduler *ops, struct vcpu *v)
{
    struct null_private *prv = null_priv(ops);
    struct null_vcpu *nvc = null_vcpu(v);
    unsigned int cpu;
    spinlock_t *lock;

    ASSERT(!is_idle_vcpu(v));

    lock = vcpu_schedule_lock_irq(v);
 retry:

    cpu = v->processor = pick_cpu(prv, v);

    spin_unlock(lock);

    lock = vcpu_schedule_lock(v);

    cpumask_and(cpumask_scratch_cpu(cpu), v->cpu_hard_affinity,
                cpupool_domain_cpumask(v->domain));

    /* If the pCPU is free, we assign v to it */
    if ( likely(per_cpu(npc, cpu).vcpu == NULL) )
    {
        /*
         * Insert is followed by vcpu_wake(), so there's no need to poke
         * the pcpu with the SCHEDULE_SOFTIRQ, as wake will do that.
         */
        vcpu_assign(prv, v, cpu);
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
        dprintk(XENLOG_G_WARNING, "WARNING: %pv not assigned to any CPU!\n", v);
        spin_unlock(&prv->waitq_lock);
    }
    spin_unlock_irq(lock);

    SCHED_STAT_CRANK(vcpu_insert);
}

static void null_vcpu_remove(const struct scheduler *ops, struct vcpu *v)
{
    struct null_private *prv = null_priv(ops);
    struct null_vcpu *nvc = null_vcpu(v);
    spinlock_t *lock;

    ASSERT(!is_idle_vcpu(v));

    lock = vcpu_schedule_lock_irq(v);

    /* If v is in waitqueue, just get it out of there and bail */
    if ( unlikely(!list_empty(&nvc->waitq_elem)) )
    {
        spin_lock(&prv->waitq_lock);
        list_del_init(&nvc->waitq_elem);
        spin_unlock(&prv->waitq_lock);

        goto out;
    }

    ASSERT(per_cpu(npc, v->processor).vcpu == v);
    ASSERT(!cpumask_test_cpu(v->processor, &prv->cpus_free));

    vcpu_deassign(prv, v);

 out:
    vcpu_schedule_unlock_irq(lock, v);

    SCHED_STAT_CRANK(vcpu_remove);
}

static void null_vcpu_wake(const struct scheduler *ops, struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    if ( unlikely(curr_on_cpu(v->processor) == v) )
    {
        SCHED_STAT_CRANK(vcpu_wake_running);
        return;
    }

    if ( unlikely(!list_empty(&null_vcpu(v)->waitq_elem)) )
    {
        /* Not exactly "on runq", but close enough for reusing the counter */
        SCHED_STAT_CRANK(vcpu_wake_onrunq);
        return;
    }

    if ( likely(vcpu_runnable(v)) )
        SCHED_STAT_CRANK(vcpu_wake_runnable);
    else
        SCHED_STAT_CRANK(vcpu_wake_not_runnable);

    /* Note that we get here only for vCPUs assigned to a pCPU */
    cpu_raise_softirq(v->processor, SCHEDULE_SOFTIRQ);
}

static void null_vcpu_sleep(const struct scheduler *ops, struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    /* If v is not assigned to a pCPU, or is not running, no need to bother */
    if ( curr_on_cpu(v->processor) == v )
        cpu_raise_softirq(v->processor, SCHEDULE_SOFTIRQ);

    SCHED_STAT_CRANK(vcpu_sleep);
}

static int null_cpu_pick(const struct scheduler *ops, struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));
    return pick_cpu(null_priv(ops), v);
}

static void null_vcpu_migrate(const struct scheduler *ops, struct vcpu *v,
                              unsigned int new_cpu)
{
    struct null_private *prv = null_priv(ops);
    struct null_vcpu *nvc = null_vcpu(v);

    ASSERT(!is_idle_vcpu(v));

    if ( v->processor == new_cpu )
        return;

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t vcpu, dom;
            uint16_t cpu, new_cpu;
        } d;
        d.dom = v->domain->domain_id;
        d.vcpu = v->vcpu_id;
        d.cpu = v->processor;
        d.new_cpu = new_cpu;
        __trace_var(TRC_SNULL_MIGRATE, 1, sizeof(d), &d);
    }

    /*
     * v is either assigned to a pCPU, or in the waitqueue.
     *
     * In the former case, the pCPU to which it was assigned would
     * become free, and we, therefore, should check whether there is
     * anyone in the waitqueue that can be assigned to it.
     *
     * In the latter, there is just nothing to do.
     */
    if ( likely(list_empty(&nvc->waitq_elem)) )
    {
        vcpu_deassign(prv, v);
        SCHED_STAT_CRANK(migrate_running);
    }
    else
        SCHED_STAT_CRANK(migrate_on_runq);

    SCHED_STAT_CRANK(migrated);

    /*
     * Let's now consider new_cpu, which is where v is being sent. It can be
     * either free, or have a vCPU already assigned to it.
     *
     * In the former case, we should assign v to it, and try to get it to run,
     * if possible, according to affinity.
     *
     * In latter, all we can do is to park v in the waitqueue.
     */
    if ( per_cpu(npc, new_cpu).vcpu == NULL &&
         vcpu_check_affinity(v, new_cpu, BALANCE_HARD_AFFINITY) )
    {
        /* v might have been in the waitqueue, so remove it */
        spin_lock(&prv->waitq_lock);
        list_del_init(&nvc->waitq_elem);
        spin_unlock(&prv->waitq_lock);

        vcpu_assign(prv, v, new_cpu);
    }
    else
    {
        /* Put v in the waitqueue, if it wasn't there already */
        spin_lock(&prv->waitq_lock);
        if ( list_empty(&nvc->waitq_elem) )
        {
            list_add_tail(&nvc->waitq_elem, &prv->waitq);
            dprintk(XENLOG_G_WARNING, "WARNING: %pv not assigned to any CPU!\n", v);
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
    v->processor = new_cpu;
}

#ifndef NDEBUG
static inline void null_vcpu_check(struct vcpu *v)
{
    struct null_vcpu * const nvc = null_vcpu(v);
    struct null_dom * const ndom = v->domain->sched_priv;

    BUG_ON(nvc->vcpu != v);

    if ( ndom )
        BUG_ON(is_idle_vcpu(v));
    else
        BUG_ON(!is_idle_vcpu(v));

    SCHED_STAT_CRANK(vcpu_check);
}
#define NULL_VCPU_CHECK(v)  (null_vcpu_check(v))
#else
#define NULL_VCPU_CHECK(v)
#endif


/*
 * The most simple scheduling function of all times! We either return:
 *  - the vCPU assigned to the pCPU, if there's one and it can run;
 *  - the idle vCPU, otherwise.
 */
static struct task_slice null_schedule(const struct scheduler *ops,
                                       s_time_t now,
                                       bool_t tasklet_work_scheduled)
{
    unsigned int bs;
    const unsigned int cpu = smp_processor_id();
    struct null_private *prv = null_priv(ops);
    struct null_vcpu *wvc;
    struct task_slice ret;

    SCHED_STAT_CRANK(schedule);
    NULL_VCPU_CHECK(current);

    if ( unlikely(tb_init_done) )
    {
        struct {
            uint16_t tasklet, cpu;
            int16_t vcpu, dom;
        } d;
        d.cpu = cpu;
        d.tasklet = tasklet_work_scheduled;
        if ( per_cpu(npc, cpu).vcpu == NULL )
        {
            d.vcpu = d.dom = -1;
        }
        else
        {
            d.vcpu = per_cpu(npc, cpu).vcpu->vcpu_id;
            d.dom = per_cpu(npc, cpu).vcpu->domain->domain_id;
        }
        __trace_var(TRC_SNULL_SCHEDULE, 1, sizeof(d), &d);
    }

    if ( tasklet_work_scheduled )
    {
        trace_var(TRC_SNULL_TASKLET, 1, 0, NULL);
        ret.task = idle_vcpu[cpu];
    }
    else
        ret.task = per_cpu(npc, cpu).vcpu;
    ret.migrated = 0;
    ret.time = -1;

    /*
     * We may be new in the cpupool, or just coming back online. In which
     * case, there may be vCPUs in the waitqueue that we can assign to us
     * and run.
     */
    if ( unlikely(ret.task == NULL) )
    {
        spin_lock(&prv->waitq_lock);

        if ( list_empty(&prv->waitq) )
            goto unlock;

        /*
         * We scan the waitqueue twice, for prioritizing vcpus that have
         * soft-affinity with cpu. This may look like something expensive to
         * do here in null_schedule(), but it's actually fine, beceuse we do
         * it only in cases where a pcpu has no vcpu associated (e.g., as
         * said above, the cpu has just joined a cpupool).
         */
        for_each_affinity_balance_step( bs )
        {
            list_for_each_entry( wvc, &prv->waitq, waitq_elem )
            {
                if ( bs == BALANCE_SOFT_AFFINITY &&
                     !has_soft_affinity(wvc->vcpu) )
                    continue;

                if ( vcpu_check_affinity(wvc->vcpu, cpu, bs) )
                {
                    vcpu_assign(prv, wvc->vcpu, cpu);
                    list_del_init(&wvc->waitq_elem);
                    ret.task = wvc->vcpu;
                    goto unlock;
                }
            }
        }
 unlock:
        spin_unlock(&prv->waitq_lock);
    }

    if ( unlikely(ret.task == NULL || !vcpu_runnable(ret.task)) )
        ret.task = idle_vcpu[cpu];

    NULL_VCPU_CHECK(ret.task);
    return ret;
}

static inline void dump_vcpu(struct null_private *prv, struct null_vcpu *nvc)
{
    printk("[%i.%i] pcpu=%d", nvc->vcpu->domain->domain_id,
            nvc->vcpu->vcpu_id, list_empty(&nvc->waitq_elem) ?
                                nvc->vcpu->processor : -1);
}

static void null_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct null_private *prv = null_priv(ops);
    struct null_vcpu *nvc;
    spinlock_t *lock;
    unsigned long flags;

    lock = pcpu_schedule_lock_irqsave(cpu, &flags);

    printk("CPU[%02d] sibling=%*pb, core=%*pb",
           cpu, CPUMASK_PR(per_cpu(cpu_sibling_mask, cpu)),
           CPUMASK_PR(per_cpu(cpu_core_mask, cpu)));
    if ( per_cpu(npc, cpu).vcpu != NULL )
        printk(", vcpu=%pv", per_cpu(npc, cpu).vcpu);
    printk("\n");

    /* current VCPU (nothing to say if that's the idle vcpu) */
    nvc = null_vcpu(curr_on_cpu(cpu));
    if ( nvc && !is_idle_vcpu(nvc->vcpu) )
    {
        printk("\trun: ");
        dump_vcpu(prv, nvc);
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
        struct vcpu *v;

        ndom = list_entry(iter, struct null_dom, ndom_elem);

        printk("\tDomain: %d\n", ndom->dom->domain_id);
        for_each_vcpu( ndom->dom, v )
        {
            struct null_vcpu * const nvc = null_vcpu(v);
            spinlock_t *lock;

            lock = vcpu_schedule_lock(nvc->vcpu);

            printk("\t%3d: ", ++loop);
            dump_vcpu(prv, nvc);
            printk("\n");

            vcpu_schedule_unlock(lock, nvc->vcpu);
        }
    }

    printk("Waitqueue: ");
    loop = 0;
    spin_lock(&prv->waitq_lock);
    list_for_each( iter, &prv->waitq )
    {
        struct null_vcpu *nvc = list_entry(iter, struct null_vcpu, waitq_elem);

        if ( loop++ != 0 )
            printk(", ");
        if ( loop % 24 == 0 )
            printk("\n\t");
        printk("%pv", nvc->vcpu);
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
    .init_pdata     = null_init_pdata,
    .switch_sched   = null_switch_sched,
    .deinit_pdata   = null_deinit_pdata,

    .alloc_vdata    = null_alloc_vdata,
    .free_vdata     = null_free_vdata,
    .alloc_domdata  = null_alloc_domdata,
    .free_domdata   = null_free_domdata,

    .insert_vcpu    = null_vcpu_insert,
    .remove_vcpu    = null_vcpu_remove,

    .wake           = null_vcpu_wake,
    .sleep          = null_vcpu_sleep,
    .pick_cpu       = null_cpu_pick,
    .migrate        = null_vcpu_migrate,
    .do_schedule    = null_schedule,

    .dump_cpu_state = null_dump_pcpu,
    .dump_settings  = null_dump,
};

REGISTER_SCHEDULER(sched_null_def);
