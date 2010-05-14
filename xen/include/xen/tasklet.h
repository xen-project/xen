/******************************************************************************
 * tasklet.h
 * 
 * Tasklets are dynamically-allocatable tasks run in VCPU context
 * (specifically, the idle VCPU's context) on at most one CPU at a time.
 */

#ifndef __XEN_TASKLET_H__
#define __XEN_TASKLET_H__

#include <xen/types.h>
#include <xen/list.h>

struct tasklet
{
    struct list_head list;
    int scheduled_on;
    bool_t is_running;
    bool_t is_dead;
    void (*func)(unsigned long);
    unsigned long data;
};

#define DECLARE_TASKLET(name, func, data) \
    struct tasklet name = { LIST_HEAD_INIT(name.list), -1, 0, 0, func, data }

/* Indicates status of tasklet work on each CPU. */
DECLARE_PER_CPU(unsigned long, tasklet_work_to_do);
#define _TASKLET_enqueued  0 /* Tasklet work is enqueued for this CPU. */
#define _TASKLET_scheduled 1 /* Scheduler has scheduled do_tasklet(). */
#define TASKLET_enqueued   (1ul << _TASKLET_enqueued)
#define TASKLET_scheduled  (1ul << _TASKLET_scheduled)

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu);
void tasklet_schedule(struct tasklet *t);
void do_tasklet(void);
void tasklet_kill(struct tasklet *t);
void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void tasklet_subsys_init(void);

#endif /* __XEN_TASKLET_H__ */
