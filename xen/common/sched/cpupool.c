/******************************************************************************
 * cpupool.c
 * 
 * Generic cpupool-handling functions.
 *
 * Cpupools are a feature to have configurable scheduling domains. Each
 * cpupool runs an own scheduler on a dedicated set of physical cpus.
 * A domain is bound to one cpupool at any time, but it can be moved to
 * another cpupool.
 *
 * (C) 2009, Juergen Gross, Fujitsu Technology Solutions
 */

#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/guest_access.h>
#include <xen/hypfs.h>
#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/param.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <xen/warning.h>

#include "private.h"

struct cpupool *cpupool0;                /* Initial cpupool with Dom0 */
cpumask_t cpupool_free_cpus;             /* cpus not in any cpupool */

static LIST_HEAD(cpupool_list);          /* linked list, sorted by poolid */

static int cpupool_moving_cpu = -1;
static struct cpupool *cpupool_cpu_moving = NULL;
static cpumask_t cpupool_locked_cpus;

/* This lock nests inside sysctl or hypfs lock. */
static DEFINE_SPINLOCK(cpupool_lock);

static enum sched_gran __read_mostly opt_sched_granularity = SCHED_GRAN_cpu;
static unsigned int __read_mostly sched_granularity = 1;

#define SCHED_GRAN_NAME_LEN  8
struct sched_gran_name {
    enum sched_gran mode;
    char name[SCHED_GRAN_NAME_LEN];
};

static const struct sched_gran_name sg_name[] = {
    {SCHED_GRAN_cpu, "cpu"},
    {SCHED_GRAN_core, "core"},
    {SCHED_GRAN_socket, "socket"},
};

static const char *sched_gran_get_name(enum sched_gran mode)
{
    const char *name = "";
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(sg_name); i++ )
    {
        if ( mode == sg_name[i].mode )
        {
            name = sg_name[i].name;
            break;
        }
    }

    return name;
}

static void sched_gran_print(enum sched_gran mode, unsigned int gran)
{
    printk("Scheduling granularity: %s, %u CPU%s per sched-resource\n",
           sched_gran_get_name(mode), gran, gran == 1 ? "" : "s");
}

#ifdef CONFIG_HAS_SCHED_GRANULARITY
static int sched_gran_get(const char *str, enum sched_gran *mode)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(sg_name); i++ )
    {
        if ( strcmp(sg_name[i].name, str) == 0 )
        {
            *mode = sg_name[i].mode;
            return 0;
        }
    }

    return -EINVAL;
}

static int __init sched_select_granularity(const char *str)
{
    return sched_gran_get(str, &opt_sched_granularity);
}
custom_param("sched-gran", sched_select_granularity);
#elif defined(CONFIG_HYPFS)
static int sched_gran_get(const char *str, enum sched_gran *mode)
{
    return -EINVAL;
}
#endif

static unsigned int cpupool_check_granularity(enum sched_gran mode)
{
    unsigned int cpu;
    unsigned int siblings, gran = 0;

    if ( mode == SCHED_GRAN_cpu )
        return 1;

    for_each_online_cpu ( cpu )
    {
        siblings = cpumask_weight(sched_get_opt_cpumask(mode, cpu));
        if ( gran == 0 )
            gran = siblings;
        else if ( gran != siblings )
            return 0;
    }

    return gran;
}

/* Setup data for selected scheduler granularity. */
static void __init cpupool_gran_init(void)
{
    unsigned int gran = 0;
    const char *fallback = NULL;

    while ( gran == 0 )
    {
        gran = cpupool_check_granularity(opt_sched_granularity);

        if ( gran == 0 )
        {
            switch ( opt_sched_granularity )
            {
            case SCHED_GRAN_core:
                opt_sched_granularity = SCHED_GRAN_cpu;
                fallback = "Asymmetric cpu configuration.\n"
                           "Falling back to sched-gran=cpu.\n";
                break;
            case SCHED_GRAN_socket:
                opt_sched_granularity = SCHED_GRAN_core;
                fallback = "Asymmetric cpu configuration.\n"
                           "Falling back to sched-gran=core.\n";
                break;
            default:
                ASSERT_UNREACHABLE();
                break;
            }
        }
    }

    if ( fallback )
        warning_add(fallback);

    if ( opt_sched_granularity != SCHED_GRAN_cpu )
        sched_disable_smt_switching = true;

    sched_granularity = gran;
    sched_gran_print(opt_sched_granularity, sched_granularity);
}

unsigned int cpupool_get_granularity(const struct cpupool *c)
{
    return c ? c->sched_gran : 1;
}

static void free_cpupool_struct(struct cpupool *c)
{
    if ( c )
    {
        free_cpumask_var(c->res_valid);
        free_cpumask_var(c->cpu_valid);
    }
    xfree(c);
}

static struct cpupool *alloc_cpupool_struct(void)
{
    struct cpupool *c = xzalloc(struct cpupool);

    if ( !c )
        return NULL;

    if ( !zalloc_cpumask_var(&c->cpu_valid) ||
         !zalloc_cpumask_var(&c->res_valid) )
    {
        free_cpupool_struct(c);
        c = NULL;
    }

    return c;
}

/*
 * find a cpupool by it's id. to be called with cpupool lock held
 * if exact is not specified, the first cpupool with an id larger or equal to
 * the searched id is returned
 * returns NULL if not found.
 */
static struct cpupool *__cpupool_find_by_id(unsigned int id, bool exact)
{
    struct cpupool *q;

    ASSERT(spin_is_locked(&cpupool_lock));

    list_for_each_entry(q, &cpupool_list, list)
        if ( q->cpupool_id == id || (!exact && q->cpupool_id > id) )
            return q;

    return NULL;
}

static struct cpupool *cpupool_find_by_id(unsigned int poolid)
{
    return __cpupool_find_by_id(poolid, true);
}

static struct cpupool *__cpupool_get_by_id(unsigned int poolid, bool exact)
{
    struct cpupool *c;
    spin_lock(&cpupool_lock);
    c = __cpupool_find_by_id(poolid, exact);
    if ( c != NULL )
        atomic_inc(&c->refcnt);
    spin_unlock(&cpupool_lock);
    return c;
}

struct cpupool *cpupool_get_by_id(unsigned int poolid)
{
    return __cpupool_get_by_id(poolid, true);
}

static struct cpupool *cpupool_get_next_by_id(unsigned int poolid)
{
    return __cpupool_get_by_id(poolid, false);
}

void cpupool_put(struct cpupool *pool)
{
    if ( !atomic_dec_and_test(&pool->refcnt) )
        return;
    scheduler_free(pool->sched);
    free_cpupool_struct(pool);
}

/*
 * create a new cpupool with specified poolid and scheduler
 * returns pointer to new cpupool structure if okay, NULL else
 * possible failures:
 * - no memory
 * - poolid already used
 * - unknown scheduler
 */
static struct cpupool *cpupool_create(unsigned int poolid,
                                      unsigned int sched_id)
{
    struct cpupool *c;
    struct cpupool *q;
    int ret;

    if ( (c = alloc_cpupool_struct()) == NULL )
        return ERR_PTR(-ENOMEM);

    /* One reference for caller, one reference for cpupool_destroy(). */
    atomic_set(&c->refcnt, 2);

    debugtrace_printk("cpupool_create(pool=%u,sched=%u)\n", poolid, sched_id);

    spin_lock(&cpupool_lock);

    if ( poolid != CPUPOOLID_NONE )
    {
        q = __cpupool_find_by_id(poolid, false);
        if ( !q )
            list_add_tail(&c->list, &cpupool_list);
        else
        {
            list_add_tail(&c->list, &q->list);
            if ( q->cpupool_id == poolid )
            {
                ret = -EEXIST;
                goto err;
            }
        }

        c->cpupool_id = poolid;
    }
    else
    {
        /* Cpupool 0 is created with specified id at boot and never removed. */
        ASSERT(!list_empty(&cpupool_list));

        q = list_last_entry(&cpupool_list, struct cpupool, list);
        /* In case of wrap search for first free id. */
        if ( q->cpupool_id == CPUPOOLID_NONE - 1 )
        {
            list_for_each_entry(q, &cpupool_list, list)
                if ( q->cpupool_id + 1 != list_next_entry(q, list)->cpupool_id )
                    break;
        }

        list_add(&c->list, &q->list);

        c->cpupool_id = q->cpupool_id + 1;
    }

    if ( poolid == 0 )
        c->sched = scheduler_get_default();
    else
        c->sched = scheduler_alloc(sched_id);
    if ( IS_ERR(c->sched) )
    {
        ret = PTR_ERR(c->sched);
        goto err;
    }

    c->sched->cpupool = c;
    c->gran = opt_sched_granularity;
    c->sched_gran = sched_granularity;

    spin_unlock(&cpupool_lock);

    debugtrace_printk("Created cpupool %u with scheduler %s (%s)\n",
                      c->cpupool_id, c->sched->name, c->sched->opt_name);

    return c;

 err:
    list_del(&c->list);

    spin_unlock(&cpupool_lock);

    free_cpupool_struct(c);

    return ERR_PTR(ret);
}
/*
 * destroys the given cpupool
 * returns 0 on success, 1 else
 * possible failures:
 * - pool still in use
 * - cpus still assigned to pool
 */
static int cpupool_destroy(struct cpupool *c)
{
    spin_lock(&cpupool_lock);

    if ( (c->n_dom != 0) || cpumask_weight(c->cpu_valid) )
    {
        spin_unlock(&cpupool_lock);
        return -EBUSY;
    }

    list_del(&c->list);

    spin_unlock(&cpupool_lock);

    cpupool_put(c);

    debugtrace_printk("cpupool_destroy(pool=%u)\n", c->cpupool_id);
    return 0;
}

/*
 * Move domain to another cpupool
 */
static int cpupool_move_domain_locked(struct domain *d, struct cpupool *c)
{
    int ret;

    if ( unlikely(d->cpupool == c) )
        return 0;

    d->cpupool->n_dom--;
    ret = sched_move_domain(d, c);
    if ( ret )
        d->cpupool->n_dom++;
    else
        c->n_dom++;

    return ret;
}
int cpupool_move_domain(struct domain *d, struct cpupool *c)
{
    int ret;

    spin_lock(&cpupool_lock);

    ret = cpupool_move_domain_locked(d, c);

    spin_unlock(&cpupool_lock);

    return ret;
}

/*
 * assign a specific cpu to a cpupool
 * cpupool_lock must be held
 */
static int cpupool_assign_cpu_locked(struct cpupool *c, unsigned int cpu)
{
    int ret;
    struct domain *d;
    const cpumask_t *cpus;

    cpus = sched_get_opt_cpumask(c->gran, cpu);

    if ( (cpupool_moving_cpu == cpu) && (c != cpupool_cpu_moving) )
        return -EADDRNOTAVAIL;
    ret = schedule_cpu_add(cpumask_first(cpus), c);
    if ( ret )
        return ret;

    rcu_read_lock(&sched_res_rculock);

    cpumask_andnot(&cpupool_free_cpus, &cpupool_free_cpus, cpus);
    if (cpupool_moving_cpu == cpu)
    {
        cpupool_moving_cpu = -1;
        cpupool_put(cpupool_cpu_moving);
        cpupool_cpu_moving = NULL;
    }
    cpumask_or(c->cpu_valid, c->cpu_valid, cpus);
    cpumask_and(c->res_valid, c->cpu_valid, &sched_res_mask);

    rcu_read_unlock(&sched_res_rculock);

    rcu_read_lock(&domlist_read_lock);
    for_each_domain_in_cpupool(d, c)
    {
        domain_update_node_affinity(d);
    }
    rcu_read_unlock(&domlist_read_lock);

    return 0;
}

static int cpupool_unassign_cpu_finish(struct cpupool *c)
{
    int cpu = cpupool_moving_cpu;
    const cpumask_t *cpus;
    struct domain *d;
    int ret;

    if ( c != cpupool_cpu_moving )
        return -EADDRNOTAVAIL;

    /*
     * We need this for scanning the domain list, both in
     * cpu_disable_scheduler(), and at the bottom of this function.
     */
    rcu_read_lock(&domlist_read_lock);
    ret = cpu_disable_scheduler(cpu);

    rcu_read_lock(&sched_res_rculock);
    cpus = get_sched_res(cpu)->cpus;
    cpumask_or(&cpupool_free_cpus, &cpupool_free_cpus, cpus);

    /*
     * cpu_disable_scheduler() returning an error doesn't require resetting
     * cpupool_free_cpus' cpu bit. All error cases should be of temporary
     * nature and tools will retry the operation. Even if the number of
     * retries may be limited, the in-between state can easily be repaired
     * by adding the cpu to the cpupool again.
     */
    if ( !ret )
    {
        ret = schedule_cpu_rm(cpu);
        if ( ret )
            cpumask_andnot(&cpupool_free_cpus, &cpupool_free_cpus, cpus);
        else
        {
            cpupool_moving_cpu = -1;
            cpupool_put(cpupool_cpu_moving);
            cpupool_cpu_moving = NULL;
        }
    }
    rcu_read_unlock(&sched_res_rculock);

    for_each_domain_in_cpupool(d, c)
    {
        domain_update_node_affinity(d);
    }
    rcu_read_unlock(&domlist_read_lock);

    return ret;
}

static int cpupool_unassign_cpu_start(struct cpupool *c, unsigned int cpu)
{
    int ret;
    struct domain *d;
    const cpumask_t *cpus;

    spin_lock(&cpupool_lock);
    ret = -EADDRNOTAVAIL;
    if ( ((cpupool_moving_cpu != -1) || !cpumask_test_cpu(cpu, c->cpu_valid))
         && (cpu != cpupool_moving_cpu) )
        goto out;

    ret = 0;
    rcu_read_lock(&sched_res_rculock);
    cpus = get_sched_res(cpu)->cpus;

    if ( (c->n_dom > 0) &&
         (cpumask_weight(c->cpu_valid) == cpumask_weight(cpus)) &&
         (cpu != cpupool_moving_cpu) )
    {
        rcu_read_lock(&domlist_read_lock);
        for_each_domain_in_cpupool(d, c)
        {
            if ( !d->is_dying && system_state == SYS_STATE_active )
            {
                ret = -EBUSY;
                break;
            }
            ret = cpupool_move_domain_locked(d, cpupool0);
            if ( ret )
                break;
        }
        rcu_read_unlock(&domlist_read_lock);
        if ( ret )
            goto out_rcu;
    }
    cpupool_moving_cpu = cpu;
    atomic_inc(&c->refcnt);
    cpupool_cpu_moving = c;
    cpumask_andnot(c->cpu_valid, c->cpu_valid, cpus);
    cpumask_and(c->res_valid, c->cpu_valid, &sched_res_mask);

 out_rcu:
    rcu_read_unlock(&sched_res_rculock);
 out:
    spin_unlock(&cpupool_lock);

    return ret;
}

static long cpupool_unassign_cpu_helper(void *info)
{
    struct cpupool *c = info;
    long ret;

    debugtrace_printk("cpupool_unassign_cpu(pool=%u,cpu=%d)\n",
                      cpupool_cpu_moving->cpupool_id, cpupool_moving_cpu);
    spin_lock(&cpupool_lock);

    ret = cpupool_unassign_cpu_finish(c);

    spin_unlock(&cpupool_lock);
    debugtrace_printk("cpupool_unassign_cpu ret=%ld\n", ret);

    return ret;
}

/*
 * unassign a specific cpu from a cpupool
 * we must be sure not to run on the cpu to be unassigned! to achieve this
 * the main functionality is performed via continue_hypercall_on_cpu on a
 * specific cpu.
 * if the cpu to be removed is the last one of the cpupool no active domain
 * must be bound to the cpupool. dying domains are moved to cpupool0 as they
 * might be zombies.
 * possible failures:
 * - last cpu and still active domains in cpupool
 * - cpu just being unplugged
 */
static int cpupool_unassign_cpu(struct cpupool *c, unsigned int cpu)
{
    int work_cpu;
    int ret;
    unsigned int master_cpu;

    debugtrace_printk("cpupool_unassign_cpu(pool=%u,cpu=%d)\n",
                      c->cpupool_id, cpu);

    if ( !cpu_online(cpu) )
        return -EINVAL;

    master_cpu = sched_get_resource_cpu(cpu);
    ret = cpupool_unassign_cpu_start(c, master_cpu);
    if ( ret )
    {
        debugtrace_printk("cpupool_unassign_cpu(pool=%u,cpu=%d) ret %d\n",
                          c->cpupool_id, cpu, ret);
        return ret;
    }

    work_cpu = sched_get_resource_cpu(smp_processor_id());
    if ( work_cpu == master_cpu )
    {
        work_cpu = cpumask_first(cpupool0->cpu_valid);
        if ( work_cpu == master_cpu )
            work_cpu = cpumask_last(cpupool0->cpu_valid);
    }
    return continue_hypercall_on_cpu(work_cpu, cpupool_unassign_cpu_helper, c);
}

/*
 * add a new domain to a cpupool
 * possible failures:
 * - pool does not exist
 * - no cpu assigned to pool
 */
int cpupool_add_domain(struct domain *d, unsigned int poolid)
{
    struct cpupool *c;
    int rc;
    int n_dom = 0;

    if ( poolid == CPUPOOLID_NONE )
        return 0;
    spin_lock(&cpupool_lock);
    c = cpupool_find_by_id(poolid);
    if ( c == NULL )
        rc = -ESRCH;
    else if ( !cpumask_weight(c->cpu_valid) )
        rc = -ENODEV;
    else
    {
        c->n_dom++;
        n_dom = c->n_dom;
        d->cpupool = c;
        rc = 0;
    }
    spin_unlock(&cpupool_lock);
    debugtrace_printk("cpupool_add_domain(dom=%d,pool=%u) n_dom %d rc %d\n",
                      d->domain_id, poolid, n_dom, rc);
    return rc;
}

/*
 * remove a domain from a cpupool
 */
void cpupool_rm_domain(struct domain *d)
{
    unsigned int cpupool_id;
    int n_dom;

    if ( d->cpupool == NULL )
        return;
    spin_lock(&cpupool_lock);
    cpupool_id = d->cpupool->cpupool_id;
    d->cpupool->n_dom--;
    n_dom = d->cpupool->n_dom;
    d->cpupool = NULL;
    spin_unlock(&cpupool_lock);
    debugtrace_printk("cpupool_rm_domain(dom=%d,pool=%u) n_dom %d\n",
                      d->domain_id, cpupool_id, n_dom);
    return;
}

/*
 * Called to add a cpu to a pool. CPUs being hot-plugged are added to pool0,
 * as they must have been in there when unplugged.
 */
static int cpupool_cpu_add(unsigned int cpu)
{
    int ret = 0;
    const cpumask_t *cpus;

    spin_lock(&cpupool_lock);
    cpumask_clear_cpu(cpu, &cpupool_locked_cpus);
    cpumask_set_cpu(cpu, &cpupool_free_cpus);

    /*
     * If we are not resuming, we are hot-plugging cpu, and in which case
     * we add it to pool0, as it certainly was there when hot-unplagged
     * (or unplugging would have failed) and that is the default behavior
     * anyway.
     */
    rcu_read_lock(&sched_res_rculock);
    get_sched_res(cpu)->cpupool = NULL;

    cpus = sched_get_opt_cpumask(cpupool0->gran, cpu);
    if ( cpumask_subset(cpus, &cpupool_free_cpus) &&
         cpumask_weight(cpus) == cpupool_get_granularity(cpupool0) )
        ret = cpupool_assign_cpu_locked(cpupool0, cpu);

    rcu_read_unlock(&sched_res_rculock);

    spin_unlock(&cpupool_lock);

    return ret;
}

/*
 * This function is called in stop_machine context, so we can be sure no
 * non-idle vcpu is active on the system.
 */
static void cpupool_cpu_remove(unsigned int cpu)
{
    int ret;

    ASSERT(is_idle_vcpu(current));

    if ( !cpumask_test_cpu(cpu, &cpupool_free_cpus) )
    {
        ret = cpupool_unassign_cpu_finish(cpupool0);
        BUG_ON(ret);
    }
    cpumask_clear_cpu(cpu, &cpupool_free_cpus);
}

/*
 * Called before a CPU is being removed from the system.
 * Removing a CPU is allowed for free CPUs or CPUs in Pool-0 (those are moved
 * to free cpus actually before removing them).
 * The CPU is locked, to forbid adding it again to another cpupool.
 */
static int cpupool_cpu_remove_prologue(unsigned int cpu)
{
    int ret = 0;
    cpumask_t *cpus;
    unsigned int master_cpu;

    spin_lock(&cpupool_lock);

    rcu_read_lock(&sched_res_rculock);
    cpus = get_sched_res(cpu)->cpus;
    master_cpu = sched_get_resource_cpu(cpu);
    if ( cpumask_intersects(cpus, &cpupool_locked_cpus) )
        ret = -EBUSY;
    else
        cpumask_set_cpu(cpu, &cpupool_locked_cpus);
    rcu_read_unlock(&sched_res_rculock);

    spin_unlock(&cpupool_lock);

    if ( ret )
        return  ret;

    if ( cpumask_test_cpu(master_cpu, cpupool0->cpu_valid) )
    {
        /* Cpupool0 is populated only after all cpus are up. */
        ASSERT(system_state == SYS_STATE_active);

        ret = cpupool_unassign_cpu_start(cpupool0, master_cpu);
    }
    else if ( !cpumask_test_cpu(master_cpu, &cpupool_free_cpus) )
        ret = -ENODEV;

    return ret;
}

/*
 * Called during resume for all cpus which didn't come up again. The cpu must
 * be removed from the cpupool it is assigned to. In case a cpupool will be
 * left without cpu we move all domains of that cpupool to cpupool0.
 * As we are called with all domains still frozen there is no need to take the
 * cpupool lock here.
 */
static void cpupool_cpu_remove_forced(unsigned int cpu)
{
    struct cpupool *c;
    int ret;
    unsigned int master_cpu = sched_get_resource_cpu(cpu);

    list_for_each_entry(c, &cpupool_list, list)
    {
        if ( cpumask_test_cpu(master_cpu, c->cpu_valid) )
        {
            ret = cpupool_unassign_cpu_start(c, master_cpu);
            BUG_ON(ret);
            ret = cpupool_unassign_cpu_finish(c);
            BUG_ON(ret);
        }
    }

    cpumask_clear_cpu(cpu, &cpupool_free_cpus);

    rcu_read_lock(&sched_res_rculock);
    sched_rm_cpu(cpu);
    rcu_read_unlock(&sched_res_rculock);
}

/*
 * do cpupool related sysctl operations
 */
int cpupool_do_sysctl(struct xen_sysctl_cpupool_op *op)
{
    int ret = 0;
    struct cpupool *c;

    switch ( op->op )
    {

    case XEN_SYSCTL_CPUPOOL_OP_CREATE:
    {
        unsigned int poolid;

        poolid = (op->cpupool_id == XEN_SYSCTL_CPUPOOL_PAR_ANY) ?
            CPUPOOLID_NONE: op->cpupool_id;
        c = cpupool_create(poolid, op->sched_id);
        if ( IS_ERR(c) )
            ret = PTR_ERR(c);
        else
        {
            op->cpupool_id = c->cpupool_id;
            cpupool_put(c);
        }
    }
    break;

    case XEN_SYSCTL_CPUPOOL_OP_DESTROY:
    {
        c = cpupool_get_by_id(op->cpupool_id);
        ret = -ENOENT;
        if ( c == NULL )
            break;
        ret = cpupool_destroy(c);
        cpupool_put(c);
    }
    break;

    case XEN_SYSCTL_CPUPOOL_OP_INFO:
    {
        c = cpupool_get_next_by_id(op->cpupool_id);
        ret = -ENOENT;
        if ( c == NULL )
            break;
        op->cpupool_id = c->cpupool_id;
        op->sched_id = c->sched->sched_id;
        op->n_dom = c->n_dom;
        ret = cpumask_to_xenctl_bitmap(&op->cpumap, c->cpu_valid);
        cpupool_put(c);
    }
    break;

    case XEN_SYSCTL_CPUPOOL_OP_ADDCPU:
    {
        unsigned cpu;
        const cpumask_t *cpus;

        cpu = op->cpu;
        debugtrace_printk("cpupool_assign_cpu(pool=%u,cpu=%u)\n",
                          op->cpupool_id, cpu);

        spin_lock(&cpupool_lock);

        c = cpupool_find_by_id(op->cpupool_id);
        ret = -ENOENT;
        if ( c == NULL )
            goto addcpu_out;
        if ( cpu == XEN_SYSCTL_CPUPOOL_PAR_ANY )
        {
            for_each_cpu ( cpu, &cpupool_free_cpus )
            {
                cpus = sched_get_opt_cpumask(c->gran, cpu);
                if ( cpumask_subset(cpus, &cpupool_free_cpus) )
                    break;
            }
            ret = -ENODEV;
            if ( cpu >= nr_cpu_ids )
                goto addcpu_out;
        }
        ret = -EINVAL;
        if ( cpu >= nr_cpu_ids )
            goto addcpu_out;
        ret = -ENODEV;
        cpus = sched_get_opt_cpumask(c->gran, cpu);
        if ( !cpumask_subset(cpus, &cpupool_free_cpus) ||
             cpumask_intersects(cpus, &cpupool_locked_cpus) )
            goto addcpu_out;
        ret = cpupool_assign_cpu_locked(c, cpu);

    addcpu_out:
        spin_unlock(&cpupool_lock);
        debugtrace_printk("cpupool_assign_cpu(pool=%u,cpu=%u) ret %d\n",
                          op->cpupool_id, cpu, ret);

    }
    break;

    case XEN_SYSCTL_CPUPOOL_OP_RMCPU:
    {
        unsigned cpu;

        c = cpupool_get_by_id(op->cpupool_id);
        ret = -ENOENT;
        if ( c == NULL )
            break;
        cpu = op->cpu;
        if ( cpu == XEN_SYSCTL_CPUPOOL_PAR_ANY )
            cpu = cpumask_last(c->cpu_valid);
        ret = (cpu < nr_cpu_ids) ? cpupool_unassign_cpu(c, cpu) : -EINVAL;
        cpupool_put(c);
    }
    break;

    case XEN_SYSCTL_CPUPOOL_OP_MOVEDOMAIN:
    {
        struct domain *d;

        ret = rcu_lock_remote_domain_by_id(op->domid, &d);
        if ( ret )
            break;
        if ( d->cpupool == NULL )
        {
            ret = -EINVAL;
            rcu_unlock_domain(d);
            break;
        }
        if ( op->cpupool_id == d->cpupool->cpupool_id )
        {
            ret = 0;
            rcu_unlock_domain(d);
            break;
        }
        debugtrace_printk("cpupool move_domain(dom=%d)->pool=%u\n",
                          d->domain_id, op->cpupool_id);
        ret = -ENOENT;
        spin_lock(&cpupool_lock);

        c = cpupool_find_by_id(op->cpupool_id);
        if ( (c != NULL) && cpumask_weight(c->cpu_valid) )
            ret = cpupool_move_domain_locked(d, c);

        spin_unlock(&cpupool_lock);
        debugtrace_printk("cpupool move_domain(dom=%d)->pool=%u ret %d\n",
                          d->domain_id, op->cpupool_id, ret);
        rcu_unlock_domain(d);
    }
    break;

    case XEN_SYSCTL_CPUPOOL_OP_FREEINFO:
    {
        ret = cpumask_to_xenctl_bitmap(
            &op->cpumap, &cpupool_free_cpus);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

unsigned int cpupool_get_id(const struct domain *d)
{
    return d->cpupool ? d->cpupool->cpupool_id : CPUPOOLID_NONE;
}

const cpumask_t *cpupool_valid_cpus(const struct cpupool *pool)
{
    return pool->cpu_valid;
}

void dump_runq(unsigned char key)
{
    s_time_t         now = NOW();
    struct cpupool *c;

    spin_lock(&cpupool_lock);

    printk("sched_smt_power_savings: %s\n",
            sched_smt_power_savings? "enabled":"disabled");
    printk("NOW=%"PRI_stime"\n", now);

    printk("Online Cpus: %*pbl\n", CPUMASK_PR(&cpu_online_map));
    if ( !cpumask_empty(&cpupool_free_cpus) )
    {
        printk("Free Cpus: %*pbl\n", CPUMASK_PR(&cpupool_free_cpus));
        schedule_dump(NULL);
    }

    list_for_each_entry(c, &cpupool_list, list)
    {
        printk("Cpupool %u:\n", c->cpupool_id);
        printk("Cpus: %*pbl\n", CPUMASK_PR(c->cpu_valid));
        sched_gran_print(c->gran, cpupool_get_granularity(c));
        schedule_dump(c);
    }

    spin_unlock(&cpupool_lock);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_DOWN_FAILED:
    case CPU_ONLINE:
        if ( system_state <= SYS_STATE_active )
            rc = cpupool_cpu_add(cpu);
        break;
    case CPU_DOWN_PREPARE:
        /* Suspend/Resume don't change assignments of cpus to cpupools. */
        if ( system_state <= SYS_STATE_active )
            rc = cpupool_cpu_remove_prologue(cpu);
        break;
    case CPU_DYING:
        /* Suspend/Resume don't change assignments of cpus to cpupools. */
        if ( system_state <= SYS_STATE_active )
            cpupool_cpu_remove(cpu);
        break;
    case CPU_RESUME_FAILED:
        cpupool_cpu_remove_forced(cpu);
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

#ifdef CONFIG_HYPFS

static HYPFS_DIR_INIT(cpupool_pooldir, "%u");

static int cpupool_dir_read(const struct hypfs_entry *entry,
                            XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    int ret = 0;
    struct cpupool *c;
    struct hypfs_dyndir_id *data;

    data = hypfs_get_dyndata();

    list_for_each_entry(c, &cpupool_list, list)
    {
        data->id = c->cpupool_id;
        data->data = c;

        ret = hypfs_read_dyndir_id_entry(&cpupool_pooldir, c->cpupool_id,
                                         list_is_last(&c->list, &cpupool_list),
                                         &uaddr);
        if ( ret )
            break;
    }

    return ret;
}

static unsigned int cpupool_dir_getsize(const struct hypfs_entry *entry)
{
    const struct cpupool *c;
    unsigned int size = 0;

    list_for_each_entry(c, &cpupool_list, list)
        size += hypfs_dynid_entry_size(entry, c->cpupool_id);

    return size;
}

static const struct hypfs_entry *cpupool_dir_enter(
    const struct hypfs_entry *entry)
{
    struct hypfs_dyndir_id *data;

    data = hypfs_alloc_dyndata(struct hypfs_dyndir_id);
    if ( !data )
        return ERR_PTR(-ENOMEM);
    data->id = CPUPOOLID_NONE;

    spin_lock(&cpupool_lock);

    return entry;
}

static void cpupool_dir_exit(const struct hypfs_entry *entry)
{
    spin_unlock(&cpupool_lock);

    hypfs_free_dyndata();
}

static struct hypfs_entry *cpupool_dir_findentry(
    const struct hypfs_entry_dir *dir, const char *name, unsigned int name_len)
{
    unsigned long id;
    const char *end;
    struct cpupool *cpupool;

    id = simple_strtoul(name, &end, 10);
    if ( end != name + name_len || id > UINT_MAX )
        return ERR_PTR(-ENOENT);

    cpupool = __cpupool_find_by_id(id, true);

    if ( !cpupool )
        return ERR_PTR(-ENOENT);

    return hypfs_gen_dyndir_id_entry(&cpupool_pooldir, id, cpupool);
}

static int cpupool_gran_read(const struct hypfs_entry *entry,
                             XEN_GUEST_HANDLE_PARAM(void) uaddr)
{
    const struct hypfs_dyndir_id *data;
    const struct cpupool *cpupool;
    const char *gran;

    data = hypfs_get_dyndata();
    cpupool = data->data;
    ASSERT(cpupool);

    gran = sched_gran_get_name(cpupool->gran);

    if ( !*gran )
        return -ENOENT;

    return copy_to_guest(uaddr, gran, strlen(gran) + 1) ? -EFAULT : 0;
}

static unsigned int hypfs_gran_getsize(const struct hypfs_entry *entry)
{
    const struct hypfs_dyndir_id *data;
    const struct cpupool *cpupool;
    const char *gran;

    data = hypfs_get_dyndata();
    cpupool = data->data;
    ASSERT(cpupool);

    gran = sched_gran_get_name(cpupool->gran);

    return strlen(gran) + 1;
}

static int cpupool_gran_write(struct hypfs_entry_leaf *leaf,
                              XEN_GUEST_HANDLE_PARAM(const_void) uaddr,
                              unsigned int ulen)
{
    const struct hypfs_dyndir_id *data;
    struct cpupool *cpupool;
    enum sched_gran gran;
    unsigned int sched_gran = 0;
    char name[SCHED_GRAN_NAME_LEN];
    int ret = 0;

    if ( ulen > SCHED_GRAN_NAME_LEN )
        return -ENOSPC;

    if ( copy_from_guest(name, uaddr, ulen) )
        return -EFAULT;

    if ( memchr(name, 0, ulen) == (name + ulen - 1) )
        sched_gran = sched_gran_get(name, &gran) ?
                     0 : cpupool_check_granularity(gran);
    if ( sched_gran == 0 )
        return -EINVAL;

    data = hypfs_get_dyndata();
    cpupool = data->data;
    ASSERT(cpupool);

    /* Guarded by the cpupool_lock taken in cpupool_dir_enter(). */
    if ( !cpumask_empty(cpupool->cpu_valid) )
        ret = -EBUSY;
    else
    {
        cpupool->gran = gran;
        cpupool->sched_gran = sched_gran;
    }

    return ret;
}

static const struct hypfs_funcs cpupool_gran_funcs = {
    .enter = hypfs_node_enter,
    .exit = hypfs_node_exit,
    .read = cpupool_gran_read,
    .write = cpupool_gran_write,
    .getsize = hypfs_gran_getsize,
    .findentry = hypfs_leaf_findentry,
};

static HYPFS_VARSIZE_INIT(cpupool_gran, XEN_HYPFS_TYPE_STRING, "sched-gran",
                          SCHED_GRAN_NAME_LEN, &cpupool_gran_funcs);
static char granstr[SCHED_GRAN_NAME_LEN] = {
    [0 ... SCHED_GRAN_NAME_LEN - 2] = '?',
    [SCHED_GRAN_NAME_LEN - 1] = 0
};

static const struct hypfs_funcs cpupool_dir_funcs = {
    .enter = cpupool_dir_enter,
    .exit = cpupool_dir_exit,
    .read = cpupool_dir_read,
    .write = hypfs_write_deny,
    .getsize = cpupool_dir_getsize,
    .findentry = cpupool_dir_findentry,
};

static HYPFS_DIR_INIT_FUNC(cpupool_dir, "cpupool", &cpupool_dir_funcs);

static void cpupool_hypfs_init(void)
{
    hypfs_add_dir(&hypfs_root, &cpupool_dir, true);
    hypfs_add_dyndir(&cpupool_dir, &cpupool_pooldir);
    hypfs_string_set_reference(&cpupool_gran, granstr);
    hypfs_add_leaf(&cpupool_pooldir, &cpupool_gran, true);
}

#else /* CONFIG_HYPFS */

static void cpupool_hypfs_init(void)
{
}

#endif /* CONFIG_HYPFS */

static int __init cpupool_init(void)
{
    unsigned int cpu;

    cpupool_gran_init();

    cpupool_hypfs_init();

    cpupool0 = cpupool_create(0, 0);
    BUG_ON(IS_ERR(cpupool0));
    cpupool_put(cpupool0);
    register_cpu_notifier(&cpu_nfb);

    spin_lock(&cpupool_lock);

    cpumask_copy(&cpupool_free_cpus, &cpu_online_map);

    for_each_cpu ( cpu, &cpupool_free_cpus )
        cpupool_assign_cpu_locked(cpupool0, cpu);

    spin_unlock(&cpupool_lock);

    return 0;
}
__initcall(cpupool_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
