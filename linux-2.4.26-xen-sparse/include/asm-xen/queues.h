
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
#include <linux/tqueue.h>

#define DECLARE_WORK(_name, _fn, _arg) \
    struct tq_struct _name = { .routine = _fn, .data = _arg }
#define schedule_work(_w) schedule_task(_w)

#endif /* __QUEUES_H__ */
