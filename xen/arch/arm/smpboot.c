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

#include <xen/cpumask.h>
#include <xen/smp.h>
#include <xen/init.h>
#include <xen/errno.h>

cpumask_t cpu_online_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_present_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_possible_map;
EXPORT_SYMBOL(cpu_possible_map);

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

/* Bring up a non-boot CPU */
int __cpu_up(unsigned int cpu)
{
    /* Not yet... */
    return -ENODEV;
}

/* Shut down the current CPU */
void __cpu_disable(void)
{
    /* TODO: take down timers, GIC, &c. */
    BUG();
}

/* Wait for a remote CPU to die */
void __cpu_die(unsigned int cpu)
{
    /* TODO: interlock with __cpu_disable */
    BUG();
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
