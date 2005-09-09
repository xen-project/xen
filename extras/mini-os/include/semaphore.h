#ifndef _SEMAPHORE_H_
#define _SEMAPHORE_H_

#include <wait.h>

/*
 * Implementation of semaphore in Mini-os is simple, because 
 * there are no preemptive threads, the atomicity is guaranteed.
 */

struct semaphore
{
	int count;
	struct wait_queue_head wait;
};


#define __SEMAPHORE_INITIALIZER(name, n)                            \
{                                                                   \
    .count    = n,                                                  \
    .wait           = __WAIT_QUEUE_HEAD_INITIALIZER((name).wait)    \
}

#define __MUTEX_INITIALIZER(name) \
    __SEMAPHORE_INITIALIZER(name,1)
                           
#define __DECLARE_SEMAPHORE_GENERIC(name,count) \
    struct semaphore name = __SEMAPHORE_INITIALIZER(name,count)
    
#define DECLARE_MUTEX(name) __DECLARE_SEMAPHORE_GENERIC(name,1)

#define DECLARE_MUTEX_LOCKED(name) __DECLARE_SEMAPHORE_GENERIC(name,0)

static void inline down(struct semaphore *sem)
{
    wait_event(sem->wait, sem->count > 0);
    sem->count--;
}

static void inline up(struct semaphore *sem)
{
    sem->count++;
    wake_up(&sem->wait);
}

#endif /* _SEMAPHORE_H */
