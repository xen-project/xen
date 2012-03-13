/*
 * xen/arch/arm/smpboot.c
 *
 * Dummy smpboot support
 *
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/delay.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include "gic.h"

cpumask_t cpu_online_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_present_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_possible_map;
EXPORT_SYMBOL(cpu_possible_map);

/* Xen stack for bringing up the first CPU. */
static unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
       __attribute__((__aligned__(STACK_SIZE)));

/* Pointer to the stack, used by head.S when entering C */
unsigned char *init_stack = cpu0_boot_stack;

void __init
smp_prepare_cpus (unsigned int max_cpus)
{
    int i;
    set_processor_id(0); /* needed early, for smp_processor_id() */

    cpumask_clear(&cpu_online_map);
    cpumask_set_cpu(0, &cpu_online_map);

    cpumask_clear(&cpu_possible_map);
    for ( i = 0; i < max_cpus; i++ )
        cpumask_set_cpu(i, &cpu_possible_map);
    cpumask_copy(&cpu_present_map, &cpu_possible_map);
}

/* Shared state for coordinating CPU bringup */
unsigned long smp_up_cpu = 0;
static bool_t cpu_is_dead = 0;

/* Boot the current CPU */
void __cpuinit start_secondary(unsigned long boot_phys_offset,
                               unsigned long arm_type,
                               unsigned long atag_paddr,
                               unsigned long cpuid)
{
    memset(get_cpu_info(), 0, sizeof (struct cpu_info));

    /* TODO: handle boards where CPUIDs are not contiguous */
    set_processor_id(cpuid);

    /* Setup Hyp vector base */
    WRITE_CP32((uint32_t) hyp_traps_vector, HVBAR);

    dprintk(XENLOG_DEBUG, "CPU %li awake.\n", cpuid);

    gic_init_secondary_cpu();

    set_current(idle_vcpu[cpuid]);
    this_cpu(curr_vcpu) = current;

    /* Run local notifiers */
    notify_cpu_starting(cpuid);
    wmb();

    /* Now report this CPU is up */
    cpumask_set_cpu(cpuid, &cpu_online_map);
    wmb();

    local_irq_enable();

    dprintk(XENLOG_DEBUG, "CPU %li booted.\n", cpuid);

    startup_cpu_idle_loop();
}

/* Shut down the current CPU */
void __cpu_disable(void)
{
    unsigned int cpu = get_processor_id();

    local_irq_disable();
    gic_disable_cpu();
    /* Allow any queued timer interrupts to get serviced */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    /* It's now safe to remove this processor from the online map */
    cpumask_clear_cpu(cpu, &cpu_online_map);

    if ( cpu_disable_scheduler(cpu) )
        BUG();
    mb();

    /* Return to caller; eventually the IPI mechanism will unwind and the 
     * scheduler will drop to the idle loop, which will call stop_cpu(). */
}

void stop_cpu(void)
{
    local_irq_disable();
    cpu_is_dead = 1;
    /* Make sure the write happens before we sleep forever */
    dsb();
    isb();
    while ( 1 ) 
        asm volatile("wfi");
}

/* Bring up a remote CPU */
int __cpu_up(unsigned int cpu)
{
    /* Tell the remote CPU which stack to boot on. */
    init_stack = idle_vcpu[cpu]->arch.stack;

    /* Unblock the CPU.  It should be waiting in the loop in head.S
     * for an event to arrive when smp_up_cpu matches its cpuid. */
    smp_up_cpu = cpu;
    asm volatile("dsb; isb; sev");

    while ( !cpu_online(cpu) )
    {
        cpu_relax();
        process_pending_softirqs();
    }

    return 0;
}

/* Wait for a remote CPU to die */
void __cpu_die(unsigned int cpu)
{
    unsigned int i = 0;

    while ( !cpu_is_dead )
    {
        mdelay(100);
        cpu_relax();
        process_pending_softirqs();
        if ( (++i % 10) == 0 )
            printk(KERN_ERR "CPU %u still not dead...\n", cpu);
        mb();
    }
    cpu_is_dead = 0;
    mb();
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
