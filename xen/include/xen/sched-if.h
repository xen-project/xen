/******************************************************************************
 * Additional declarations for the generic scheduler interface.  This should
 * only be included by files that implement conforming schedulers.
 *
 * Portions by Mark Williamson are (C) 2004 Intel Research Cambridge
 */

#ifndef __XEN_SCHED_IF_H__
#define __XEN_SCHED_IF_H__

#define BUCKETS  10
/*300*/

struct schedule_data {
    spinlock_t          schedule_lock;  /* spinlock protecting curr        */
    struct vcpu *curr;           /* current task                    */
    struct vcpu *idle;           /* idle task for this cpu          */
    void               *sched_priv;
    struct ac_timer     s_timer;        /* scheduling timer                */
    unsigned long       tick;           /* current periodic 'tick'         */
#ifdef BUCKETS
    u32                 hist[BUCKETS];  /* for scheduler latency histogram */
#endif
} __cacheline_aligned;

struct task_slice {
    struct vcpu *task;
    s_time_t            time;
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

extern struct schedule_data schedule_data[];

#endif /* __XEN_SCHED_IF_H__ */
