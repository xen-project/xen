#ifndef _SEMAPHORE_H_
#define _SEMAPHORE_H_

#include <wait.h>
#include <spinlock.h>

/*
 * Implementation of semaphore in Mini-os is simple, because 
 * there are no preemptive threads, the atomicity is guaranteed.
 */

struct semaphore
{
	int count;
	struct wait_queue_head wait;
};

/*
 * the semaphore definition
 */
struct rw_semaphore {
	signed long		count;
	spinlock_t		wait_lock;
	struct list_head	wait_list;
	int			debug;
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

static inline void init_MUTEX(struct semaphore *sem)
{
  sem->count = 1;
  init_waitqueue_head(&sem->wait);
}

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

/* FIXME! Thre read/write semaphores are unimplemented! */
static inline void init_rwsem(struct rw_semaphore *sem)
{
  sem->count = 1;
}

static inline void down_read(struct rw_semaphore *sem)
{
}


static inline void up_read(struct rw_semaphore *sem)
{
}

static inline void up_write(struct rw_semaphore *sem)
{
}

static inline void down_write(struct rw_semaphore *sem)
{
}

#endif /* _SEMAPHORE_H */
