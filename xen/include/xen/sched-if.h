/******************************************************************************
 * Additional declarations for the generic scheduler interface.  This should
 * only be included by files that implement conforming schedulers.
 *
 * Portions by Mark Williamson are (C) 2004 Intel Research Cambridge
 */

#ifndef __XEN_SCHED_IF_H__
#define __XEN_SCHED_IF_H__

#include <xen/percpu.h>

/* A global pointer to the initial cpupool (POOL0). */
extern struct cpupool *cpupool0;

/* cpus currently in no cpupool */
extern cpumask_t cpupool_free_cpus;

/* Scheduler generic parameters
 * */
extern int sched_ratelimit_us;


/*
 * In order to allow a scheduler to remap the lock->cpu mapping,
 * we have a per-cpu pointer, along with a pre-allocated set of
 * locks.  The generic schedule init code will point each schedule lock
 * pointer to the schedule lock; if the scheduler wants to remap them,
 * it can simply modify the schedule locks.
 * 
 * For cache betterness, keep the actual lock in the same cache area
 * as the rest of the struct.  Just have the scheduler point to the
 * one it wants (This may be the one right in front of it).*/
struct schedule_data {
    spinlock_t         *schedule_lock,
                       _lock;
    struct vcpu        *curr;           /* current task                    */
    void               *sched_priv;
    struct timer        s_timer;        /* scheduling timer                */
    atomic_t            urgent_count;   /* how many urgent vcpus           */
};

DECLARE_PER_CPU(struct schedule_data, schedule_data);
DECLARE_PER_CPU(struct scheduler *, scheduler);
DECLARE_PER_CPU(struct cpupool *, cpupool);

static inline spinlock_t * pcpu_schedule_lock(int cpu)
{
    spinlock_t * lock=NULL;

    for ( ; ; )
    {
        /* The per_cpu(v->processor) may also change, if changing
         * cpu pool also changes the scheduler lock.  Retry
         * until they match.
         */
        lock=per_cpu(schedule_data, cpu).schedule_lock;

        spin_lock(lock);
        if ( likely(lock == per_cpu(schedule_data, cpu).schedule_lock) )
            break;
        spin_unlock(lock);
    }
    return lock;
}

static inline int pcpu_schedule_trylock(int cpu)
{
    spinlock_t * lock=NULL;

    lock=per_cpu(schedule_data, cpu).schedule_lock;
    if ( ! spin_trylock(lock) )
        return 0;
    if ( lock == per_cpu(schedule_data, cpu).schedule_lock )
        return 1;
    else
    {
        spin_unlock(lock);
        return 0;
    }
}

#define pcpu_schedule_lock_irq(p) \
    do { local_irq_disable(); pcpu_schedule_lock(p); } while ( 0 )
#define pcpu_schedule_lock_irqsave(p, flags) \
    do { local_irq_save(flags); pcpu_schedule_lock(p); } while ( 0 )

static inline void pcpu_schedule_unlock(int cpu)
{
    spin_unlock(per_cpu(schedule_data, cpu).schedule_lock);
}

#define pcpu_schedule_unlock_irq(p) \
    do { pcpu_schedule_unlock(p); local_irq_enable(); } while ( 0 )
#define pcpu_schedule_unlock_irqrestore(p, flags) \
    do { pcpu_schedule_unlock(p); local_irq_restore(flags); } while ( 0 )

static inline void vcpu_schedule_lock(struct vcpu *v)
{
    spinlock_t * lock;

    for ( ; ; )
    {
        /* v->processor may change when grabbing the lock; but
         * per_cpu(v->processor) may also change, if changing
         * cpu pool also changes the scheduler lock.  Retry
         * until they match.
         *
         * It may also be the case that v->processor may change
         * but the lock may be the same; this will succeed
         * in that case.
         */
        lock=per_cpu(schedule_data, v->processor).schedule_lock;

        spin_lock(lock);
        if ( likely(lock == per_cpu(schedule_data, v->processor).schedule_lock) )
            break;
        spin_unlock(lock);
    }
}

#define vcpu_schedule_lock_irq(v) \
    do { local_irq_disable(); vcpu_schedule_lock(v); } while ( 0 )
#define vcpu_schedule_lock_irqsave(v, flags) \
    do { local_irq_save(flags); vcpu_schedule_lock(v); } while ( 0 )

static inline void vcpu_schedule_unlock(struct vcpu *v)
{
    spin_unlock(per_cpu(schedule_data, v->processor).schedule_lock);
}

#define vcpu_schedule_unlock_irq(v) \
    do { vcpu_schedule_unlock(v); local_irq_enable(); } while ( 0 )
#define vcpu_schedule_unlock_irqrestore(v, flags) \
    do { vcpu_schedule_unlock(v); local_irq_restore(flags); } while ( 0 )

struct task_slice {
    struct vcpu *task;
    s_time_t     time;
    bool_t       migrated;
};

struct scheduler {
    char *name;             /* full name for this scheduler      */
    char *opt_name;         /* option name for this scheduler    */
    unsigned int sched_id;  /* ID for this scheduler             */
    void *sched_data;       /* global data pointer               */

    int          (*global_init)    (void);

    int          (*init)           (struct scheduler *);
    void         (*deinit)         (const struct scheduler *);

    void         (*free_vdata)     (const struct scheduler *, void *);
    void *       (*alloc_vdata)    (const struct scheduler *, struct vcpu *,
                                    void *);
    void         (*free_pdata)     (const struct scheduler *, void *, int);
    void *       (*alloc_pdata)    (const struct scheduler *, int);
    void         (*free_domdata)   (const struct scheduler *, void *);
    void *       (*alloc_domdata)  (const struct scheduler *, struct domain *);

    int          (*init_domain)    (const struct scheduler *, struct domain *);
    void         (*destroy_domain) (const struct scheduler *, struct domain *);

    /* Activate / deactivate vcpus in a cpu pool */
    void         (*insert_vcpu)    (const struct scheduler *, struct vcpu *);
    void         (*remove_vcpu)    (const struct scheduler *, struct vcpu *);

    void         (*sleep)          (const struct scheduler *, struct vcpu *);
    void         (*wake)           (const struct scheduler *, struct vcpu *);
    void         (*yield)          (const struct scheduler *, struct vcpu *);
    void         (*context_saved)  (const struct scheduler *, struct vcpu *);

    struct task_slice (*do_schedule) (const struct scheduler *, s_time_t,
                                      bool_t tasklet_work_scheduled);

    int          (*pick_cpu)       (const struct scheduler *, struct vcpu *);
    void         (*migrate)        (const struct scheduler *, struct vcpu *,
                                    unsigned int);
    int          (*adjust)         (const struct scheduler *, struct domain *,
                                    struct xen_domctl_scheduler_op *);
    int          (*adjust_global)  (const struct scheduler *,
                                    struct xen_sysctl_scheduler_op *);
    void         (*dump_settings)  (const struct scheduler *);
    void         (*dump_cpu_state) (const struct scheduler *, int);

    void         (*tick_suspend)    (const struct scheduler *, unsigned int);
    void         (*tick_resume)     (const struct scheduler *, unsigned int);
};

extern const struct scheduler sched_sedf_def;
extern const struct scheduler sched_credit_def;
extern const struct scheduler sched_credit2_def;
extern const struct scheduler sched_arinc653_def;


struct cpupool
{
    int              cpupool_id;
    cpumask_var_t    cpu_valid;      /* all cpus assigned to pool */
    struct cpupool   *next;
    unsigned int     n_dom;
    struct scheduler *sched;
    atomic_t         refcnt;
};

#define cpupool_scheduler_cpumask(_pool) \
    (((_pool) == NULL) ? &cpupool_free_cpus : (_pool)->cpu_valid)
#define cpupool_online_cpumask(_pool) \
    (((_pool) == NULL) ? &cpu_online_map : (_pool)->cpu_valid)

#endif /* __XEN_SCHED_IF_H__ */
