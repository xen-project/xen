/******************************************************************************
 * Additional declarations for the generic scheduler interface.  This should
 * only be included by files that implement conforming schedulers.
 *
 * Portions by Mark Williamson are (C) 2004 Intel Research Cambridge
 */

#ifndef __XEN_SCHED_IF_H__
#define __XEN_SCHED_IF_H__

struct schedule_data {
    spinlock_t          schedule_lock;  /* spinlock protecting curr        */
    struct vcpu        *curr;           /* current task                    */
    struct vcpu        *idle;           /* idle task for this cpu          */
    void               *sched_priv;
    struct timer        s_timer;        /* scheduling timer                */
    unsigned long       tick;           /* current periodic 'tick'         */
} __cacheline_aligned;

extern struct schedule_data schedule_data[];

static inline void vcpu_schedule_lock(struct vcpu *v)
{
    unsigned int cpu;

    for ( ; ; )
    {
        cpu = v->processor;
        spin_lock(&schedule_data[cpu].schedule_lock);
        if ( likely(v->processor == cpu) )
            break;
        spin_unlock(&schedule_data[cpu].schedule_lock);
    }
}

#define vcpu_schedule_lock_irq(v) \
    do { local_irq_disable(); vcpu_schedule_lock(v); } while ( 0 )
#define vcpu_schedule_lock_irqsave(v, flags) \
    do { local_irq_save(flags); vcpu_schedule_lock(v); } while ( 0 )

static inline void vcpu_schedule_unlock(struct vcpu *v)
{
    spin_unlock(&schedule_data[v->processor].schedule_lock);
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

    int          (*alloc_task)     (struct vcpu *);
    void         (*add_task)       (struct vcpu *);
    void         (*free_task)      (struct domain *);
    void         (*rem_task)       (struct vcpu *);
    void         (*sleep)          (struct vcpu *);
    void         (*wake)           (struct vcpu *);
    int          (*set_affinity)   (struct vcpu *, cpumask_t *);
    struct task_slice (*do_schedule) (s_time_t);
    int          (*control)        (struct sched_ctl_cmd *);
    int          (*adjdom)         (struct domain *,
                                    struct sched_adjdom_cmd *);
    void         (*dump_settings)  (void);
    void         (*dump_cpu_state) (int);
};

#endif /* __XEN_SCHED_IF_H__ */
