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

cpumask_t cpu_online_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_present_map;
EXPORT_SYMBOL(cpu_online_map);
cpumask_t cpu_possible_map;
EXPORT_SYMBOL(cpu_possible_map);

void __init
smp_prepare_cpus (unsigned int max_cpus)
{
        set_processor_id(0); /* needed early, for smp_processor_id() */

        cpumask_clear(&cpu_online_map);
        cpumask_clear(&cpu_present_map);
        cpumask_clear(&cpu_possible_map);
        cpumask_set_cpu(0, &cpu_online_map);
        cpumask_set_cpu(0, &cpu_present_map);
        cpumask_set_cpu(0, &cpu_possible_map);
        return;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
