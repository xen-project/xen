
/*
 * Oh dear. Task queues were removed from Linux 2.6 and replaced by work 
 * queues. Unfortunately the semantics is not the same. With task queues we 
 * can defer work until a particular event occurs -- this is not
 * straightforwardly done with work queues (queued work is performed asap, or
 * after some fixed timeout). Conversely, work queues are a (slightly) neater
 * way of deferring work to a process context than using task queues in 2.4.
 * 
 * So, what we do here is a bit weird:
 *  1. On 2.4, we emulate work queues over task queues.
 *  2. On 2.6, we emulate task queues over work queues.
 * 
 * Note how much harder the latter is. :-)
 */

#ifndef __QUEUES_H__
#define __QUEUES_H__

#include <linux/version.h>
#include <linux/list.h>
#include <linux/workqueue.h>

struct tq_struct { 
    struct work_struct work;
    struct list_head   list;
    unsigned long      pending;
};
#define INIT_TQUEUE(_name, _fn, _arg)               \
    do {                                            \
        INIT_LIST_HEAD(&(_name)->list);             \
        (_name)->pending = 0;                       \
        INIT_WORK(&(_name)->work, (_fn), (_arg));   \
    } while ( 0 )

typedef struct {
    struct list_head list;
    spinlock_t       lock;
} task_queue;
#define DECLARE_TASK_QUEUE(_name) \
    task_queue _name = { LIST_HEAD_INIT((_name).list), SPIN_LOCK_UNLOCKED }

static inline int queue_task(struct tq_struct *tqe, task_queue *tql)
{
    unsigned long flags;
    if ( test_and_set_bit(0, &tqe->pending) )
        return 0;
    spin_lock_irqsave(&tql->lock, flags);
    list_add_tail(&tqe->list, &tql->list);
    spin_unlock_irqrestore(&tql->lock, flags);
    return 1;
}

static inline void run_task_queue(task_queue *tql)
{
    struct list_head head, *ent;
    struct tq_struct *tqe;
    unsigned long flags;

    spin_lock_irqsave(&tql->lock, flags);
    list_add(&head, &tql->list);
    list_del_init(&tql->list);
    spin_unlock_irqrestore(&tql->lock, flags);

    while ( !list_empty(&head) )
    {
        ent = head.next;
        list_del_init(ent);
        tqe = list_entry(ent, struct tq_struct, list);
        wmb(); tqe->pending = 0;
        schedule_work(&tqe->work);
    }
}

#endif /* __QUEUES_H__ */
