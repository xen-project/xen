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
    struct task_struct *curr;           /* current task */
    struct task_struct *idle;           /* idle task for this cpu */
    void *              sched_priv;
    struct ac_timer     s_timer;        /* scheduling timer  */
#ifdef BUCKETS
    u32                 hist[BUCKETS];  /* for scheduler latency histogram */
#endif
} __cacheline_aligned schedule_data_t;


typedef struct task_slice_st
{
    struct task_struct *task;
    s_time_t            time;
} task_slice_t;

struct scheduler
{
    char *name;             /* full name for this scheduler      */
    char *opt_name;         /* option name for this scheduler    */
    unsigned int sched_id;  /* ID for this scheduler             */

    int          (*init_scheduler) ();
    int          (*alloc_task)     (struct task_struct *);
    void         (*add_task)       (struct task_struct *);
    void         (*free_task)      (struct task_struct *);
    void         (*rem_task)       (struct task_struct *);
    void         (*wake_up)        (struct task_struct *);
    void         (*do_block)       (struct task_struct *);
    task_slice_t (*do_schedule)    (s_time_t);
    int          (*control)        (struct sched_ctl_cmd *);
    int          (*adjdom)         (struct task_struct *,
                                    struct sched_adjdom_cmd *);
    s32          (*reschedule)     (struct task_struct *);
    void         (*dump_settings)  (void);
    void         (*dump_cpu_state) (int);
    void         (*dump_runq_el)   (struct task_struct *);
    int          (*prn_state)      (int);
};

/* per CPU scheduler information */
extern schedule_data_t schedule_data[];

/*
 * Wrappers for run-queue management. Must be called with the schedule_lock
 * held.
 */
static inline void __add_to_runqueue_head(struct task_struct * p)
{    
    list_add(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __add_to_runqueue_tail(struct task_struct * p)
{
    list_add_tail(&p->run_list, &schedule_data[p->processor].runqueue);
}

static inline void __del_from_runqueue(struct task_struct * p)
{
    list_del(&p->run_list);
    p->run_list.next = NULL;
}

static inline int __task_on_runqueue(struct task_struct *p)
{
    return p->run_list.next != NULL;
}

#define next_domain(p) \\
        list_entry((p)->run_list.next, struct task_struct, run_list)


static inline int __runqueue_empty(int cpu)
{
    return list_empty(&schedule_data[cpu].runqueue);
}
