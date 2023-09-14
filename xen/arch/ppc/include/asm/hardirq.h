/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_HARDIRQ_H__
#define __ASM_PPC_HARDIRQ_H__

#include <xen/cache.h>

typedef struct {
        unsigned long __softirq_pending;
        unsigned int __local_irq_count;
} __cacheline_aligned irq_cpustat_t;

#include <xen/irq_cpustat.h>    /* Standard mappings for irq_cpustat_t above */

#define in_irq() (local_irq_count(smp_processor_id()) != 0)

#define irq_enter()     (local_irq_count(smp_processor_id())++)
#define irq_exit()      (local_irq_count(smp_processor_id())--)

#endif /* __ASM_PPC_HARDIRQ_H__ */
