#ifndef __ASM_HARDIRQ_H
#define __ASM_HARDIRQ_H

#include <xen/config.h>
#include <xen/irq.h>

/* assembly code in softirq.h is sensitive to the offsets of these fields */
typedef struct {
	unsigned int __softirq_pending;
	unsigned int __local_irq_count;
	unsigned int __local_bh_count;
	unsigned int __nmi_count;
	unsigned long idle_timestamp;
} ____cacheline_aligned irq_cpustat_t;

#include <xen/irq_cpustat.h>	/* Standard mappings for irq_cpustat_t above */

/*
 * Are we in an interrupt context? Either doing bottom half
 * or hardware interrupt processing?
 */
#define in_interrupt() ({ int __cpu = smp_processor_id(); \
	(local_irq_count(__cpu) + local_bh_count(__cpu) != 0); })

#define in_irq() (local_irq_count(smp_processor_id()) != 0)

#define irq_enter(cpu, irq)	(local_irq_count(cpu)++)
#define irq_exit(cpu, irq)	(local_irq_count(cpu)--)

#endif /* __ASM_HARDIRQ_H */
