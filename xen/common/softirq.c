/******************************************************************************
 * common/softirq.c
 * 
 * Softirqs in Xen are only executed in an outermost activation (e.g., never 
 * within an interrupt activation). This simplifies some things and generally 
 * seems a good thing.
 * 
 * Copyright (c) 2003, K A Fraser
 * Copyright (c) 1992, Linus Torvalds
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/interrupt.h>
#include <xen/init.h>

irq_cpustat_t irq_stat[NR_CPUS];

static softirq_handler softirq_handlers[NR_SOFTIRQS] __cacheline_aligned;

asmlinkage void do_softirq()
{
    unsigned int pending, cpu = smp_processor_id();
    softirq_handler *h;

    while ( (pending = xchg(&softirq_pending(cpu), 0)) != 0 )
    {
        h = softirq_handlers;
        while ( pending )
        {
            if ( pending & 1 )
                (*h)();
            h++;
            pending >>= 1;
        }
    }
}

inline void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    __cpu_raise_softirq(cpu, nr);
#ifdef CONFIG_SMP
    if ( cpu != smp_processor_id() )
        smp_send_event_check_cpu(cpu);
#endif
}

void raise_softirq(unsigned int nr)
{
    __cpu_raise_softirq(smp_processor_id(), nr);
}

void open_softirq(int nr, softirq_handler handler)
{
    softirq_handlers[nr] = handler;
}
