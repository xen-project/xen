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
    int          (*init_idle_task) (struct domain *);
    int          (*alloc_task)     (struct domain *);
    void         (*add_task)       (struct domain *);
    void         (*free_task)      (struct domain *);
    void         (*rem_task)       (struct domain *);
    void         (*sleep)          (struct domain *);
    void         (*wake)           (struct domain *);
    void         (*do_block)       (struct domain *);
    task_slice_t (*do_schedule)    (s_time_t);
    int          (*control)        (struct sched_ctl_cmd *);
    int          (*adjdom)         (struct domain *,
                                    struct sched_adjdom_cmd *);
    void         (*dump_settings)  (void);
    void         (*dump_cpu_state) (int);
    int          (*prn_state)      (int);
};

/* per CPU scheduler information */
extern schedule_data_t schedule_data[];

/*
 * Wrappers for run-queue management. Must be called with the schedule_lock
 * held.
 */
static inline void __add_to_runqueue_head(struct list_head *run_list, struct list_head *runqueue)
{
    list_add(run_list, runqueue);
}

static inline void __add_to_runqueue_tail(struct list_head *run_list, struct list_head *runqueue)
{
    list_add_tail(run_list, runqueue);
}

static inline void __del_from_runqueue(struct list_head *run_list)
{
    list_del(run_list);
    run_list->next = NULL;
}

static inline int __task_on_runqueue(struct list_head *run_list)
{
    return run_list->next != NULL;
}

