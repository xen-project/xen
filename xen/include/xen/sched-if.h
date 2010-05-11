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
    struct vcpu        *idle;           /* idle task for this cpu          */
    void               *sched_priv;
    void               *sched_idlevpriv; /* default scheduler vcpu data    */
    struct timer        s_timer;        /* scheduling timer                */
    atomic_t            urgent_count;   /* how many urgent vcpus           */
} __cacheline_aligned;

DECLARE_PER_CPU(struct schedule_data, schedule_data);
DECLARE_PER_CPU(struct scheduler *, scheduler);
DECLARE_PER_CPU(struct cpupool *, cpupool);

static inline void vcpu_schedule_lock(struct vcpu *v)
{
    unsigned int cpu;

    for ( ; ; )
    {
        /* NB: For schedulers with multiple cores per runqueue,
         * a vcpu may change processor w/o changing runqueues;
         * so we may release a lock only to grab it again.
         *
         * If that is measured to be an issue, then the check
         * should be changed to checking if the locks pointed to
         * by cpu and v->processor are still the same.
         */
        cpu = v->processor;
        spin_lock(per_cpu(schedule_data, cpu).schedule_lock);
        if ( likely(v->processor == cpu) )
            break;
        spin_unlock(per_cpu(schedule_data, cpu).schedule_lock);
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
};

struct scheduler {
    char *name;             /* full name for this scheduler      */
    char *opt_name;         /* option name for this scheduler    */
    unsigned int sched_id;  /* ID for this scheduler             */
    void *sched_data;       /* global data pointer               */

    int          (*init)           (struct scheduler *, int);
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

    void         (*insert_vcpu)    (const struct scheduler *, struct vcpu *);
    void         (*destroy_vcpu)   (const struct scheduler *, struct vcpu *);

    void         (*sleep)          (const struct scheduler *, struct vcpu *);
    void         (*wake)           (const struct scheduler *, struct vcpu *);
    void         (*context_saved)  (const struct scheduler *, struct vcpu *);

    struct task_slice (*do_schedule) (const struct scheduler *, s_time_t,
                                      bool_t tasklet_work_scheduled);

    int          (*pick_cpu)       (const struct scheduler *, struct vcpu *);
    int          (*adjust)         (const struct scheduler *, struct domain *,
                                    struct xen_domctl_scheduler_op *);
    int          (*adjust_global)  (const struct scheduler *,
                                    struct xen_sysctl_scheduler_op *);
    void         (*dump_settings)  (const struct scheduler *);
    void         (*dump_cpu_state) (const struct scheduler *, int);

    void         (*tick_suspend)    (const struct scheduler *, unsigned int);
    void         (*tick_resume)     (const struct scheduler *, unsigned int);
};

struct cpupool
{
    int              cpupool_id;
    cpumask_t        cpu_valid;      /* all cpus assigned to pool */
    struct cpupool   *next;
    unsigned int     n_dom;
    struct scheduler sched;
};

const struct scheduler *scheduler_get_by_id(unsigned int id);

#endif /* __XEN_SCHED_IF_H__ */
