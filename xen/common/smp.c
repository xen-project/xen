/*
 * xen/common/smp.c
 *
 * Generic SMP function
 *
 * Copyright (c) 2013 Citrix Systems.
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

#include <asm/hardirq.h>
#include <asm/processor.h>
#include <xen/spinlock.h>
#include <xen/smp.h>

/*
 * Structure and data for smp_call_function()/on_selected_cpus().
 */
static DEFINE_SPINLOCK(call_lock);
static struct call_data_struct {
    void (*func) (void *info);
    void *info;
    int wait;
    cpumask_t selected;
} call_data;

void smp_call_function(
    void (*func) (void *info),
    void *info,
    int wait)
{
    cpumask_t allbutself;

    cpumask_andnot(&allbutself, &cpu_online_map,
                   cpumask_of(smp_processor_id()));
    on_selected_cpus(&allbutself, func, info, wait);
}

void on_selected_cpus(
    const cpumask_t *selected,
    void (*func) (void *info),
    void *info,
    int wait)
{
    unsigned int nr_cpus;

    ASSERT(local_irq_is_enabled());
    ASSERT(cpumask_subset(selected, &cpu_online_map));

    spin_lock(&call_lock);

    cpumask_copy(&call_data.selected, selected);

    nr_cpus = cpumask_weight(&call_data.selected);
    if ( nr_cpus == 0 )
        goto out;

    call_data.func = func;
    call_data.info = info;
    call_data.wait = wait;

    smp_send_call_function_mask(&call_data.selected);

    while ( !cpumask_empty(&call_data.selected) )
        cpu_relax();

out:
    spin_unlock(&call_lock);
}

void smp_call_function_interrupt(void)
{
    void (*func)(void *info) = call_data.func;
    void *info = call_data.info;
    unsigned int cpu = smp_processor_id();

    if ( !cpumask_test_cpu(cpu, &call_data.selected) )
        return;

    irq_enter();

    if ( call_data.wait )
    {
        (*func)(info);
        smp_mb();
        cpumask_clear_cpu(cpu, &call_data.selected);
    }
    else
    {
        smp_mb();
        cpumask_clear_cpu(cpu, &call_data.selected);
        (*func)(info);
    }

    irq_exit();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
