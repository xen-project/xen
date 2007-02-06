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
#include <xen/rcupdate.h>
#include <xen/softirq.h>

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS];
#endif

static softirq_handler softirq_handlers[NR_SOFTIRQS];

asmlinkage void do_softirq(void)
{
    unsigned int i, cpu;
    unsigned long pending;

    for ( ; ; )
    {
        /*
         * Initialise @cpu on every iteration: SCHEDULE_SOFTIRQ may move
         * us to another processor.
         */
        cpu = smp_processor_id();

        if ( rcu_pending(cpu) )
            rcu_check_callbacks(cpu);

        if ( (pending = softirq_pending(cpu)) == 0 )
            break;

        i = find_first_set_bit(pending);
        clear_bit(i, &softirq_pending(cpu));
        (*softirq_handlers[i])();
    }
}

void open_softirq(int nr, softirq_handler handler)
{
    softirq_handlers[nr] = handler;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
