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

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu);
void tasklet_schedule(struct tasklet *t);
void do_tasklet(void);
bool_t tasklet_queue_empty(unsigned int cpu);
void tasklet_kill(struct tasklet *t);
void migrate_tasklets_from_cpu(unsigned int cpu);
void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);
void tasklet_subsys_init(void);

#endif /* __XEN_TASKLET_H__ */
