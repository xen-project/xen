/******************************************************************************
 * tasklet.h
 * 
 * Tasklets are dynamically-allocatable tasks run in either VCPU context
 * (specifically, the idle VCPU's context) or in softirq context, on at most
 * one CPU at a time. Softirq versus VCPU context execution is specified
 * during per-tasklet initialisation.
 */

#ifndef __XEN_TASKLET_H__
#define __XEN_TASKLET_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/percpu.h>

struct tasklet
{
    struct list_head list;
    int scheduled_on;
    bool_t is_softirq;
    bool_t is_running;
    bool_t is_dead;
    void (*func)(unsigned long);
    unsigned long data;
};

#define _DECLARE_TASKLET(name, func, data, softirq)                     \
    struct tasklet name = {                                             \
        LIST_HEAD_INIT(name.list), -1, softirq, 0, 0, func, data }
#define DECLARE_TASKLET(name, func, data)               \
    _DECLARE_TASKLET(name, func, data, 0)
#define DECLARE_SOFTIRQ_TASKLET(name, func, data)       \
    _DECLARE_TASKLET(name, func, data, 1)

/* Indicates status of tasklet work on each CPU. */
DECLARE_PER_CPU(unsigned long, tasklet_work_to_do);
#define _TASKLET_enqueued  0 /* Tasklet work is enqueued for this CPU. */
#define _TASKLET_scheduled 1 /* Scheduler has scheduled do_tasklet(). */
#define TASKLET_enqueued   (1ul << _TASKLET_enqueued)
#define TASKLET_scheduled  (1ul << _TASKLET_scheduled)

static inline bool tasklet_work_to_do(unsigned int cpu)
{
    /*
     * Work must be enqueued *and* scheduled. Otherwise there is no work to
     * do, and/or scheduler needs to run to update idle vcpu priority.
     */
    return per_cpu(tasklet_work_to_do, cpu) == (TASKLET_enqueued|
                                                TASKLET_scheduled);
}

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu);
void tasklet_schedule(struct tasklet *t);
void do_tasklet(void);
void tasklet_kill(struct tasklet *t);
void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void softirq_tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void tasklet_subsys_init(void);

#endif /* __XEN_TASKLET_H__ */
