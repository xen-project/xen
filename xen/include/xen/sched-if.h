#include <asm/types.h>

/*
 * Additional declarations for the generic scheduler interface.  This should
 * only be included by files that implement conforming schedulers.
 *
 * Portions by Mark Williamson are (C) 2004 Intel Research Cambridge
 */

#define BUCKETS 10

typedef struct schedule_data_st
{
    struct list_head    runqueue;       /* runqueue */
    struct domain *curr;           /* current task */
    struct domain *idle;           /* idle task for this cpu */
    void *              sched_priv;
    struct ac_timer     s_timer;        /* scheduling timer  */
#ifdef BUCKETS
    u32                 hist[BUCKETS];  /* for scheduler latency histogram */
#endif
} __cacheline_aligned schedule_data_t;


typedef struct task_slice_st
{
    struct domain *task;
    s_time_t            time;
} task_slice_t;

struct scheduler
{
    char *name;             /* full name for this scheduler      */
    char *opt_name;         /* option name for this scheduler    */
    unsigned int sched_id;  /* ID for this scheduler             */

    int          (*init_scheduler) ();
    int          (*alloc_task)     (struct domain *);
    void         (*add_task)       (struct domain *);
    void         (*free_task)      (struct domain *);
    void         (*rem_task)       (struct domain *);
    void         (*wake_up)        (struct domain *);
    void         (*do_block)       (struct domain *);
    task_slice_t (*do_schedule)    (s_time_t);
    int          (*control)        (struct sched_ctl_cmd *);
    int          (*adjdom)         (struct domain *,
                                    struct sched_adjdom_cmd *);
    void         (*dump_settings)  (void);
    void         (*dump_cpu_state) (int);
    void         (*dump_runq_el)   (struct domain *);
    int          (*prn_state)      (int);
    void         (*pause)          (struct domain *);
};

/* per CPU scheduler information */
extern schedule_data_t schedule_data[];

/*
 * Wrappers for run-queue management. Must be called with the schedule_lock
 * held.
 */
static inline void __add_to_runqueue_head(struct domain * p)
{    
    list_add(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __add_to_runqueue_tail(struct domain * p)
{
    list_add_tail(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __del_from_runqueue(struct domain * p)
{
    list_del(&p->run_list);
    p->run_list.next = NULL;
}

static inline int __task_on_runqueue(struct domain *p)
{
    return p->run_list.next != NULL;
}

#define next_domain(p) \\
        list_entry((p)->run_list.next, struct domain, run_list)


static inline int __runqueue_empty(int cpu)
{
    return list_empty(&schedule_data[cpu].runqueue);
}
