/****************************************************************************
 * Round Robin Scheduler for Xen
 *
 * by Mark Williamson (C) 2004 Intel Research Cambridge
 */

#include <xen/sched.h>
#include <xen/sched-if.h>
#include <public/sched_ctl.h>
#include <xen/ac_timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/slab.h>

#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */

static s_time_t rr_slice = MILLISECS(10);

/* Only runqueue pointers and domain pointer*/
struct rrobin_dom_info
{
    struct list_head run_list;
    struct domain    *domain;
};

#define RR_INFO(d)      ((struct rrobin_dom_info *)d->sched_priv)
#define RUNLIST(d)      ((struct list_head *)&(RR_INFO(d)->run_list))
#define RUNQUEUE(cpu)   RUNLIST(schedule_data[cpu].idle)

static inline void __add_to_runqueue_head(struct domain *d)
{
    list_add(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __add_to_runqueue_tail(struct domain *d)
{
    list_add_tail(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __del_from_runqueue(struct domain *d)
{
    struct list_head *runlist = RUNLIST(d);
    list_del(runlist);
    runlist->next = NULL;
}

static inline int __task_on_runqueue(struct domain *d)
{
    return (RUNLIST(d))->next != NULL;
}

/* Initialises the runqueues and creates the domain info cache */
static int rr_init_scheduler()
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
        INIT_LIST_HEAD(RUNQUEUE(i));
   
    return 0;                                                                
}
/* Allocates memory for per domain private scheduling data*/
static int rr_alloc_task(struct domain *d)
{
    if ( (d->sched_priv = new(struct rrobin_dom_info) == NULL )
        return -1;
    memset(d->sched_priv, 0, sizeof(struct rrobin_dom_info));
    return 0;
}

/* Setup the rr_dom_info */
static void rr_add_task(struct domain *d)
{
    struct rrobin_dom_info *inf;
    RR_INFO(d)->domain = d;
    inf = RR_INFO(d);
}

/* Frees memory used by domain info */
static void rr_free_task(struct domain *d)
{
    ASSERT(d->sched_priv != NULL);
    xfree(d->sched_priv);
}

/* Initialises idle task */
static int rr_init_idle_task(struct domain *d)
{
    if ( rr_alloc_task(d) < 0 )
        return -1;

    rr_add_task(d);

    set_bit(DF_RUNNING, &d->flags);
    if ( !__task_on_runqueue(d) )
         __add_to_runqueue_head(d);

    return 0;
}

/* Main scheduling function */
static struct task_slice rr_do_schedule(s_time_t now)
{
    struct domain *prev = current;
    int cpu = current->processor;
    struct task_slice ret;
    
    if ( !is_idle_task(prev) )
    {
        __del_from_runqueue(prev);
    
        if ( domain_runnable(prev) )
            __add_to_runqueue_tail(prev);
    }
    
    ret.task = list_entry(RUNQUEUE(cpu)->next, 
                          struct rrobin_dom_info, 
                          run_list)->domain;
    ret.time = rr_slice;
    return ret;
}

/* Set/retrive control parameter(s) */
static int rr_ctl(struct sched_ctl_cmd *cmd)
{
    if ( cmd->direction == SCHED_INFO_PUT )
    {
        rr_slice = cmd->u.rrobin.slice;
    }
    else /* cmd->direction == SCHED_INFO_GET */
    {
        cmd->u.rrobin.slice = rr_slice;
    }
    
    return 0;
}

static void rr_dump_settings()
{
    printk("rr_slice = %llu ", rr_slice);
}

static void rr_sleep(struct domain *d)
{
    if ( test_bit(DF_RUNNING, &d->flags) )
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
    else if ( __task_on_runqueue(d) )
        __del_from_runqueue(d);
}

void rr_wake(struct domain *d)
{
    struct domain       *curr;
    s_time_t            now;
    int                 cpu = d->processor;

    if ( unlikely(__task_on_runqueue(d)) )
        return;

    __add_to_runqueue_head(d);

    now = NOW();

    curr = schedule_data[cpu].curr;
     if ( is_idle_task(curr) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
}


static void rr_dump_domain(struct domain *d)
{
    printk("%u has=%c ", d->id,
           test_bit(DF_RUNNING, &d->flags) ? 'T':'F');
    printk("c=0x%X%08X\n", (u32)(d->cpu_time>>32), (u32)d->cpu_time);
}

static void rr_dump_cpu_state(int i)
{
    struct list_head *queue;
    int loop = 0;
    struct rrobin_dom_info *d_inf;

    queue = RUNQUEUE(i);
    printk("QUEUE rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
        (unsigned long) queue->next, (unsigned long) queue->prev);

    printk("%3d: ",loop++);
    d_inf = list_entry(queue, struct rrobin_dom_info, run_list);
    rr_dump_domain(d_inf->domain);
 
    list_for_each_entry ( d_inf, queue, run_list )
    {
        printk("%3d: ",loop++);
        rr_dump_domain(d_inf->domain);
    }
}


struct scheduler sched_rrobin_def = {
    .name     = "Round-Robin Scheduler",
    .opt_name = "rrobin",
    .sched_id = SCHED_RROBIN,
    
    .init_idle_task = rr_init_idle_task,
    .alloc_task     = rr_alloc_task,
    .add_task       = rr_add_task,
    .free_task      = rr_free_task,
    .init_scheduler = rr_init_scheduler,
    .do_schedule    = rr_do_schedule,
    .control        = rr_ctl,
    .dump_settings  = rr_dump_settings,
    .dump_cpu_state = rr_dump_cpu_state,
    .sleep          = rr_sleep,
    .wake           = rr_wake,
};



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
