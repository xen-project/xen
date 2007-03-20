#ifndef __WAIT_H__
#define __WAIT_H__

#include <sched.h>
#include <list.h>
#include <lib.h>
#include <os.h>

struct wait_queue
{
    struct thread *thread;
    struct list_head thread_list;
};

struct wait_queue_head
{
    /* TODO - lock required? */
    struct list_head thread_list;
};

#define DECLARE_WAIT_QUEUE_HEAD(name) \
   struct wait_queue_head name =     \
        { .thread_list = { &(name).thread_list, &(name).thread_list} }

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {                           \
    .thread_list      = { &(name).thread_list, &(name).thread_list } }


#define DEFINE_WAIT(name)                               \
struct wait_queue name = {                              \
    .thread       = current,                            \
    .thread_list  = LIST_HEAD_INIT((name).thread_list), \
}


static inline void init_waitqueue_head(struct wait_queue_head *h)
{
  INIT_LIST_HEAD(&h->thread_list);
}

static inline void init_waitqueue_entry(struct wait_queue *q, struct thread *thread)
{
    q->thread = thread;
}


static inline void add_wait_queue(struct wait_queue_head *h, struct wait_queue *q)
{
    if (list_empty(&q->thread_list))
        list_add(&q->thread_list, &h->thread_list);   
}

static inline void remove_wait_queue(struct wait_queue *q)
{
    list_del(&q->thread_list);
}

static inline void wake_up(struct wait_queue_head *head)
{
    struct list_head *tmp, *next;
    list_for_each_safe(tmp, next, &head->thread_list)
    {
         struct wait_queue *curr;
         curr = list_entry(tmp, struct wait_queue, thread_list);
         wake(curr->thread);
    }
}

#define add_waiter(w, wq) do {  \
    unsigned long flags;        \
    local_irq_save(flags);      \
    add_wait_queue(&wq, &w);    \
    block(current);             \
    local_irq_restore(flags);   \
} while (0)

#define remove_waiter(w) do {   \
    unsigned long flags;        \
    local_irq_save(flags);      \
    remove_wait_queue(&w);      \
    local_irq_restore(flags);   \
} while (0)

#define wait_event(wq, condition) do{             \
    unsigned long flags;                          \
    if(condition)                                 \
        break;                                    \
    DEFINE_WAIT(__wait);                          \
    for(;;)                                       \
    {                                             \
        /* protect the list */                    \
        local_irq_save(flags);                    \
        add_wait_queue(&wq, &__wait);             \
        block(current);                           \
        local_irq_restore(flags);                 \
        if(condition)                             \
            break;                                \
        schedule();                               \
    }                                             \
    local_irq_save(flags);                        \
    /* need to wake up */                         \
    wake(current);                                \
    remove_wait_queue(&__wait);                   \
    local_irq_restore(flags);                     \
} while(0) 




#endif /* __WAIT_H__ */
