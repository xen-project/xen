#ifndef __ASM_HARDIRQ_H
#define __ASM_HARDIRQ_H

#include <xen/config.h>
#include <xen/cache.h>
#include <xen/types.h>

typedef struct {
	unsigned int __softirq_pending;
	unsigned int __local_irq_count;
	unsigned int __nmi_count;
	bool_t __mwait_wakeup;
} __cacheline_aligned irq_cpustat_t;

#include <xen/irq_cpustat.h>	/* Standard mappings for irq_cpustat_t above */

#define in_irq() (local_irq_count(smp_processor_id()) != 0)

#define irq_enter()	(local_irq_count(smp_processor_id())++)
#define irq_exit()	(local_irq_count(smp_processor_id())--)

void ack_bad_irq(unsigned int irq);

extern void apic_intr_init(void);
extern void smp_intr_init(void);

#endif /* __ASM_HARDIRQ_H */
