/******************************************************************************
 * wait.h
 * 
 * Sleep in hypervisor context for some event to occur.
 */

#ifndef __XEN_WAIT_H__
#define __XEN_WAIT_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>

struct waitqueue_head {
    spinlock_t lock;
    struct list_head list;
};

/* Statically define and initialise a waitqueue. */
#define DEFINE_WAITQUEUE_HEAD(name)             \
    struct waitqueue_head name = {              \
        .lock = SPIN_LOCK_UNLOCKED,             \
        .list = LIST_HEAD_INIT((name).list)     \
    }

/* Dynamically initialise a waitqueue. */
void init_waitqueue_head(struct waitqueue_head *wq);

/* Wake all VCPUs waiting on specified waitqueue. */
void wake_up(struct waitqueue_head *wq);

/* Wait on specified waitqueue until @condition is true. */
#define wait_event(wq, condition)               \
do {                                            \
    if ( condition )                            \
        break;                                  \
    for ( ; ; ) {                               \
        prepare_to_wait(&wq);                   \
        if ( condition )                        \
            break;                              \
        wait();                                 \
    }                                           \
    finish_wait(&wq);                           \
} while (0)

/* Private functions. */
int init_waitqueue_vcpu(struct vcpu *v);
void destroy_waitqueue_vcpu(struct vcpu *v);
void prepare_to_wait(struct waitqueue_head *wq);
void wait(void);
void finish_wait(struct waitqueue_head *wq);
void check_wakeup_from_wait(void);

#endif /* __XEN_WAIT_H__ */
