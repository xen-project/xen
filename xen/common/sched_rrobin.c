/****************************************************************************
 * Round Robin Scheduler for Xen
 *
 * by Mark Williamson (C) 2004 Intel Research Cambridge
 */

#include <xen/sched.h>
#include <xen/sched-if.h>
#include <hypervisor-ifs/sched_ctl.h>
#include <xen/ac_timer.h>
#include <xen/softirq.h>
#include <xen/time.h>

#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */

static s_time_t rr_slice = MILLISECS(10);

static task_slice_t rr_do_schedule(s_time_t now)
{
    struct domain *prev = current;
    int cpu = current->processor;
    task_slice_t ret;
 
    __del_from_runqueue(prev);
    
    if ( domain_runnable(prev) )
      __add_to_runqueue_tail(prev);
    
    ret.task = list_entry(schedule_data[cpu].runqueue.next,
                    struct domain, run_list);

    ret.time = rr_slice;

    return ret;
}

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
    s_time_t             now, min_time;
    int                  cpu = d->processor;

    /* If on the runqueue already then someone has done the wakeup work. */
    if ( unlikely(__task_on_runqueue(d)) )
        return;

    __add_to_runqueue_head(d);

    now = NOW();

    curr = schedule_data[cpu].curr;

    /* Currently-running domain should run at least for ctx_allow. */
    min_time = curr->lastschd + curr->min_slice;
    
    if ( is_idle_task(curr) || (min_time <= now) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    else if ( schedule_data[cpu].s_timer.expires > (min_time + TIME_SLOP) )
        mod_ac_timer(&schedule_data[cpu].s_timer, min_time);
}

struct scheduler sched_rrobin_def = {
    .name     = "Round-Robin Scheduler",
    .opt_name = "rrobin",
    .sched_id = SCHED_RROBIN,

    .do_schedule    = rr_do_schedule,
    .control        = rr_ctl,
    .dump_settings  = rr_dump_settings,
    .sleep          = rr_sleep,
    .wake           = rr_wake,
};


