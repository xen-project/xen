
/* Work-queue emulation over task queues. Pretty simple. */

#ifndef __QUEUES_H__
#define __QUEUES_H__

#include <linux/version.h>
#include <linux/list.h>
#include <linux/tqueue.h>

#define DECLARE_TQUEUE(_name, _fn, _arg) \
    struct tq_struct _name = { LIST_HEAD_INIT((_name).list), 0, _fn, _arg }
#define DECLARE_WORK(_name, _fn, _arg) DECLARE_TQUEUE(_name, _fn, _arg)

#define work_struct tq_struct
#define INIT_WORK(_work, _fn, _arg) INIT_TQUEUE(_work, _fn, _arg)

#define schedule_work(_w) schedule_task(_w)

#endif /* __QUEUES_H__ */
