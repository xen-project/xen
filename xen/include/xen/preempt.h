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

#define preempt_count() (this_cpu(__preempt_count))

#define preempt_disable() do {                  \
    preempt_count()++;                          \
    barrier();                                  \
} while (0)

#define preempt_enable() do {                   \
    barrier();                                  \
    preempt_count()--;                          \
} while (0)

#define in_atomic() (preempt_count() || in_irq() || !local_irq_is_enabled())

#endif /* __XEN_PREEMPT_H__ */
