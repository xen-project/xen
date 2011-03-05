/******************************************************************************
 * preempt.h
 * 
 * Track atomic regions in the hypervisor which disallow sleeping.
 * 
 * Copyright (c) 2010, Keir Fraser <keir@xen.org>
 */

#ifndef __XEN_PREEMPT_H__
#define __XEN_PREEMPT_H__

#include <xen/config.h>
#include <xen/percpu.h>
#include <xen/irq.h>    /* in_irq() */
#include <asm/system.h> /* local_irq_is_enabled() */

DECLARE_PER_CPU(unsigned int, __preempt_count);

/*
 * XXX: Preemption support is not needed for 4.1 branch as synchronous
 * yield (via waitqueues) is not used. Furthermore there are still some
 * unbalanced rcu_lock/unlock usages on some code paths and the stricter
 * requirements of the preemption subsystem can cause us to BUG out on them.
 */
#if 0

#define preempt_count() (this_cpu(__preempt_count))

#define preempt_disable() do {                  \
    preempt_count()++;                          \
    barrier();                                  \
} while (0)

#define preempt_enable() do {                   \
    barrier();                                  \
    preempt_count()--;                          \
} while (0)

#else

#define preempt_count()   0
#define preempt_disable() ((void)0)
#define preempt_enable()  ((void)0)

#endif

#define in_atomic() (preempt_count() || in_irq() || !local_irq_is_enabled())

#endif /* __XEN_PREEMPT_H__ */
