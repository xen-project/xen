#ifndef __WAITTYPE_H__
#define __WAITTYPE_H__

#include <list.h>

struct thread;
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

#endif
