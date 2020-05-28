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

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/cpumask.h>
#include <xen/param.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <xen/warning.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>

#include "private.h"

#define for_each_cpupool(ptr)    \
    for ((ptr) = &cpupool_list; *(ptr) != NULL; (ptr) = &((*(ptr))->next))

struct cpupool *cpupool0;                /* Initial cpupool with Dom0 */
cpumask_t cpupool_free_cpus;             /* cpus not in any cpupool */

static struct cpupool *cpupool_list;     /* linked list, sorted by poolid */

static int cpupool_moving_cpu = -1;
static struct cpupool *cpupool_cpu_moving = NULL;
static cpumask_t cpupool_locked_cpus;

static DEFINE_SPINLOCK(cpupool_lock);

static enum sched_gran __read_mostly opt_sched_granularity = SCHED_GRAN_cpu;
static unsigned int __read_mostly sched_granularity = 1;

struct sched_gran_name {
    enum sched_gran mode;
    char name[8];
};

static const struct sched_gran_name sg_name[] = {
    {SCHED_GRAN_cpu, "cpu"},
    {SCHED_GRAN_core, "core"},
    {SCHED_GRAN_socket, "socket"},
};

static void sched_gran_print(enum sched_gran mode, unsigned int gran)
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

    printk("Scheduling granularity: %s, %u CPU%s per sched-resource\n",
           name, gran, gran == 1 ? "" : "s");
}

#ifdef CONFIG_HAS_SCHED_GRANULARITY
static int __init sched_select_granularity(const char *str)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(sg_name); i++ )
    {
        if ( strcmp(sg_name[i].name, str) == 0 )
        {
            opt_sched_granularity = sg_name[i].mode;
            return 0;
        }
    }

    return -EINVAL;
}
custom_param("sched-gran", sched_select_granularity);
#endif

static unsigned int __init cpupool_check_granularity(void)
{
    unsigned int cpu;
    unsigned int siblings, gran = 0;

    if ( opt_sched_granularity == SCHED_GRAN_cpu )
        return 1;

    for_each_online_cpu ( cpu )
    {
        siblings = cpumask_weight(sched_get_opt_cpumask(opt_sched_granularity,
                                                        cpu));
        if ( gran == 0 )
            gran = siblings;
        else if ( gran != siblings )
            return 0;
    }

    sched_disable_smt_switching = true;

    return gran;
}

/* Setup data for selected scheduler granularity. */
static void __init cpupool_gran_init(void)
{
    unsigned int gran = 0;
    const char *fallback = NULL;

    while ( gran == 0 )
    {
        gran = cpupool_check_granularity();

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

    sched_granularity = gran;
    sched_gran_print(opt_sched_granularity, sched_granularity);
}

unsigned int cpupool_get_granularity(const struct cpupool *c)
{
    return c ? sched_granularity : 1;
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
static struct cpupool *__cpupool_find_by_id(int id, bool exact)
{
    struct cpupool **q;

    ASSERT(spin_is_locked(&cpupool_lock));

    for_each_cpupool(q)
        if ( (*q)->cpupool_id >= id )
            break;

    return (!exact || (*q == NULL) || ((*q)->cpupool_id == id)) ? *q : NULL;
}

static struct cpupool *cpupool_find_by_id(int poolid)
{
    return __cpupool_find_by_id(poolid, true);
}

static struct cpupool *__cpupool_get_by_id(int poolid, bool exact)
{
    struct cpupool *c;
    spin_lock(&cpupool_lock);
    c = __cpupool_find_by_id(poolid, exact);
    if ( c != NULL )
        atomic_inc(&c->refcnt);
    spin_unlock(&cpupool_lock);
    return c;
}

struct cpupool *cpupool_get_by_id(int poolid)
{
    return __cpupool_get_by_id(poolid, true);
}

static struct cpupool *cpupool_get_next_by_id(int poolid)
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
static struct cpupool *cpupool_create(
    int poolid, unsigned int sched_id, int *perr)
{
    struct cpupool *c;
    struct cpupool **q;
    int last = 0;

    *perr = -ENOMEM;
    if ( (c = alloc_cpupool_struct()) == NULL )
        return NULL;

    /* One reference for caller, one reference for cpupool_destroy(). */
    atomic_set(&c->refcnt, 2);

    debugtrace_printk("cpupool_create(pool=%d,sched=%u)\n", poolid, sched_id);

    spin_lock(&cpupool_lock);

    for_each_cpupool(q)
    {
        last = (*q)->cpupool_id;
        if ( (poolid != CPUPOOLID_NONE) && (last >= poolid) )
            break;
    }
    if ( *q != NULL )
    {
        if ( (*q)->cpupool_id == poolid )
        {
            *perr = -EEXIST;
            goto err;
        }
        c->next = *q;
    }

    c->cpupool_id = (poolid == CPUPOOLID_NONE) ? (last + 1) : poolid;
    if ( poolid == 0 )
    {
        c->sched = scheduler_get_default();
    }
    else
    {
        c->sched = scheduler_alloc(sched_id, perr);
        if ( c->sched == NULL )
            goto err;
    }
    c->sched->cpupool = c;
    c->gran = opt_sched_granularity;

    *q = c;

    spin_unlock(&cpupool_lock);

    debugtrace_printk("Created cpupool %d with scheduler %s (%s)\n",
                      c->cpupool_id, c->sched->name, c->sched->opt_name);

    *perr = 0;
    return c;

 err:
    spin_unlock(&cpupool_lock);
    free_cpupool_struct(c);
    return NULL;
}
/*
 * destroys the given cpupool
 * returns 0 on success, 1 else
 * possible failures:
 * - pool still in use
 * - cpus still assigned to pool
 * - pool not in list
 */
static int cpupool_destroy(struct cpupool *c)
{
    struct cpupool **q;

    spin_lock(&cpupool_lock);
    for_each_cpupool(q)
        if ( *q == c )
            break;
    if ( *q != c )
    {
        spin_unlock(&cpupool_lock);
        return -ENOENT;
    }
    if ( (c->n_dom != 0) || cpumask_weight(c->cpu_valid) )
    {
        spin_unlock(&cpupool_lock);
        return -EBUSY;
    }
    *q = c->next;
    spin_unlock(&cpupool_lock);

    cpupool_put(c);

    debugtrace_printk("cpupool_destroy(pool=%d)\n", c->cpupool_id);
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

    debugtrace_printk("cpupool_unassign_cpu(pool=%d,cpu=%d)\n",
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

    debugtrace_printk("cpupool_unassign_cpu(pool=%d,cpu=%d)\n",
                      c->cpupool_id, cpu);

    if ( !cpu_online(cpu) )
        return -EINVAL;

    master_cpu = sched_get_resource_cpu(cpu);
    ret = cpupool_unassign_cpu_start(c, master_cpu);
    if ( ret )
    {
        debugtrace_printk("cpupool_unassign_cpu(pool=%d,cpu=%d) ret %d\n",
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
int cpupool_add_domain(struct domain *d, int poolid)
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
    debugtrace_printk("cpupool_add_domain(dom=%d,pool=%d) n_dom %d rc %d\n",
                      d->domain_id, poolid, n_dom, rc);
    return rc;
}

/*
 * remove a domain from a cpupool
 */
void cpupool_rm_domain(struct domain *d)
{
    int cpupool_id;
    int n_dom;

    if ( d->cpupool == NULL )
        return;
    spin_lock(&cpupool_lock);
    cpupool_id = d->cpupool->cpupool_id;
    d->cpupool->n_dom--;
    n_dom = d->cpupool->n_dom;
    d->cpupool = NULL;
    spin_unlock(&cpupool_lock);
    debugtrace_printk("cpupool_rm_domain(dom=%d,pool=%d) n_dom %d\n",
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
    struct cpupool **c;
    int ret;
    unsigned int master_cpu = sched_get_resource_cpu(cpu);

    for_each_cpupool ( c )
    {
        if ( cpumask_test_cpu(master_cpu, (*c)->cpu_valid) )
        {
            ret = cpupool_unassign_cpu_start(*c, master_cpu);
            BUG_ON(ret);
            ret = cpupool_unassign_cpu_finish(*c);
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
    int ret;
    struct cpupool *c;

    switch ( op->op )
    {

    case XEN_SYSCTL_CPUPOOL_OP_CREATE:
    {
        int poolid;

        poolid = (op->cpupool_id == XEN_SYSCTL_CPUPOOL_PAR_ANY) ?
            CPUPOOLID_NONE: op->cpupool_id;
        c = cpupool_create(poolid, op->sched_id, &ret);
        if ( c != NULL )
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
        debugtrace_printk("cpupool_assign_cpu(pool=%d,cpu=%d)\n",
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
        debugtrace_printk("cpupool_assign_cpu(pool=%d,cpu=%d) ret %d\n",
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
        debugtrace_printk("cpupool move_domain(dom=%d)->pool=%d\n",
                          d->domain_id, op->cpupool_id);
        ret = -ENOENT;
        spin_lock(&cpupool_lock);

        c = cpupool_find_by_id(op->cpupool_id);
        if ( (c != NULL) && cpumask_weight(c->cpu_valid) )
            ret = cpupool_move_domain_locked(d, c);

        spin_unlock(&cpupool_lock);
        debugtrace_printk("cpupool move_domain(dom=%d)->pool=%d ret %d\n",
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

int cpupool_get_id(const struct domain *d)
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
    struct cpupool **c;

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

    for_each_cpupool(c)
    {
        printk("Cpupool %d:\n", (*c)->cpupool_id);
        printk("Cpus: %*pbl\n", CPUMASK_PR((*c)->cpu_valid));
        sched_gran_print((*c)->gran, cpupool_get_granularity(*c));
        schedule_dump(*c);
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

static int __init cpupool_init(void)
{
    unsigned int cpu;
    int err;

    cpupool_gran_init();

    cpupool0 = cpupool_create(0, 0, &err);
    BUG_ON(cpupool0 == NULL);
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
