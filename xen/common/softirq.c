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
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/softirq.h>

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

void open_softirq(int nr, softirq_handler handler)
{
    softirq_handlers[nr] = handler;
}
