/****************************************************************************
 * Very stupid Round Robin Scheduler for Xen
 *
 * by Mark Williamson (C) 2004 Intel Research Cambridge
 */

#include <xen/sched.h>
#include <xen/sched-if.h>
#include <hypervisor-ifs/sched_ctl.h>
#include <xen/ac_timer.h>
#include <xen/time.h>

static s_time_t rr_slice = MILLISECS(10);

static task_slice_t rr_do_schedule(s_time_t now)
{
    struct task_struct *prev = current;
    int cpu = current->processor;
    task_slice_t ret;
 
    __del_from_runqueue(prev);
    
    if ( prev->state == TASK_RUNNING )
      __add_to_runqueue_tail(prev);
    
    ret.task = list_entry(schedule_data[cpu].runqueue.next,
                    struct task_struct, run_list);

    ret.time = rr_slice;

    return ret;
}

static int rr_ctl(struct sched_ctl_cmd *cmd)
{
    rr_slice = cmd->u.rrobin.slice;
    return 0;
}

static void rr_dump_settings()
{
    printk("rr_slice = %llu ", rr_slice);
}

static void rr_pause(struct task_struct *p)
{
    if ( __task_on_runqueue(p) )
        __del_from_runqueue(p);
}

struct scheduler sched_rrobin_def = {
    .name     = "Round-Robin Scheduler",
    .opt_name = "rrobin",
    .sched_id = SCHED_RROBIN,

    .wake_up        = __add_to_runqueue_head,
    .do_schedule    = rr_do_schedule,
    .control        = rr_ctl,
    .dump_settings  = rr_dump_settings,
    .pause          = rr_pause,
};


