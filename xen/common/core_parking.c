/*
 *  core_parking.c - implement core parking according to dom0 requirement
 *
 *  Copyright (C) 2012, Intel Corporation.
 *     Author: Liu, Jinsong <jinsong.liu@intel.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 */

#include <xen/types.h>
#include <xen/cpu.h>
#include <xen/init.h>
#include <xen/cpumask.h>
#include <asm/percpu.h>
#include <asm/smp.h>

#define CORE_PARKING_INCREMENT 1
#define CORE_PARKING_DECREMENT 2

static unsigned int core_parking_power(unsigned int event);
static unsigned int core_parking_performance(unsigned int event);

static uint32_t cur_idle_nums;
static unsigned int core_parking_cpunum[NR_CPUS] = {[0 ... NR_CPUS-1] = -1};

static struct core_parking_policy {
    char name[30];
    unsigned int (*next)(unsigned int event);
} *core_parking_policy;

static enum core_parking_controller {
    POWER_FIRST,
    PERFORMANCE_FIRST
} core_parking_controller = POWER_FIRST;

static void __init setup_core_parking_option(char *str)
{
    if ( !strcmp(str, "power") )
        core_parking_controller = POWER_FIRST;
    else if ( !strcmp(str, "performance") )
        core_parking_controller = PERFORMANCE_FIRST;
    else
        return;
}
custom_param("core_parking", setup_core_parking_option);

static unsigned int core_parking_performance(unsigned int event)
{
    unsigned int cpu = -1;

    switch ( event )
    {
    case CORE_PARKING_INCREMENT:
    {
        int core_tmp, core_weight = -1;
        int sibling_tmp, sibling_weight = -1;
        cpumask_t core_candidate_map, sibling_candidate_map;
        cpumask_clear(&core_candidate_map);
        cpumask_clear(&sibling_candidate_map);

        for_each_cpu(cpu, &cpu_online_map)
        {
            if ( cpu == 0 )
                continue;

            core_tmp = cpumask_weight(per_cpu(cpu_core_mask, cpu));
            if ( core_weight < core_tmp )
            {
                core_weight = core_tmp;
                cpumask_copy(&core_candidate_map, cpumask_of(cpu));
            }
            else if ( core_weight == core_tmp )
                __cpumask_set_cpu(cpu, &core_candidate_map);
        }

        for_each_cpu(cpu, &core_candidate_map)
        {
            sibling_tmp = cpumask_weight(per_cpu(cpu_sibling_mask, cpu));
            if ( sibling_weight < sibling_tmp )
            {
                sibling_weight = sibling_tmp;
                cpumask_copy(&sibling_candidate_map, cpumask_of(cpu));
            }
            else if ( sibling_weight == sibling_tmp )
                __cpumask_set_cpu(cpu, &sibling_candidate_map);
        }

        cpu = cpumask_first(&sibling_candidate_map);
    }
    break;

    case CORE_PARKING_DECREMENT:
    {
        cpu = core_parking_cpunum[cur_idle_nums -1];
    }
    break;

    default:
        break;
    }

    return cpu;
}

static unsigned int core_parking_power(unsigned int event)
{
    unsigned int cpu = -1;

    switch ( event )
    {
    case CORE_PARKING_INCREMENT:
    {
        int core_tmp, core_weight = NR_CPUS + 1;
        int sibling_tmp, sibling_weight = NR_CPUS + 1;
        cpumask_t core_candidate_map, sibling_candidate_map;
        cpumask_clear(&core_candidate_map);
        cpumask_clear(&sibling_candidate_map);

        for_each_cpu(cpu, &cpu_online_map)
        {
            if ( cpu == 0 )
                continue;

            core_tmp = cpumask_weight(per_cpu(cpu_core_mask, cpu));
            if ( core_weight > core_tmp )
            {
                core_weight = core_tmp;
                cpumask_copy(&core_candidate_map, cpumask_of(cpu));
            }
            else if ( core_weight == core_tmp )
                __cpumask_set_cpu(cpu, &core_candidate_map);
        }

        for_each_cpu(cpu, &core_candidate_map)
        {
            sibling_tmp = cpumask_weight(per_cpu(cpu_sibling_mask, cpu));
            if ( sibling_weight > sibling_tmp )
            {
                sibling_weight = sibling_tmp;
                cpumask_copy(&sibling_candidate_map, cpumask_of(cpu));
            }
            else if ( sibling_weight == sibling_tmp )
                __cpumask_set_cpu(cpu, &sibling_candidate_map);
        }

        cpu = cpumask_first(&sibling_candidate_map);
    }
    break;

    case CORE_PARKING_DECREMENT:
    {
        cpu = core_parking_cpunum[cur_idle_nums -1];
    }
    break;

    default:
        break;
    }

    return cpu;
}

long core_parking_helper(void *data)
{
    uint32_t idle_nums = (unsigned long)data;
    unsigned int cpu;
    int ret = 0;

    if ( !core_parking_policy )
        return -EINVAL;

    while ( cur_idle_nums < idle_nums )
    {
        cpu = core_parking_policy->next(CORE_PARKING_INCREMENT);
        ret = cpu_down(cpu);
        if ( ret )
            return ret;
        core_parking_cpunum[cur_idle_nums++] = cpu;
    }

    while ( cur_idle_nums > idle_nums )
    {
        cpu = core_parking_policy->next(CORE_PARKING_DECREMENT);
        ret = cpu_up(cpu);
        if ( ret )
            return ret;
        core_parking_cpunum[--cur_idle_nums] = -1;
    }

    return ret;
}

uint32_t get_cur_idle_nums(void)
{
    return cur_idle_nums;
}

static struct core_parking_policy power_first = {
    .name = "power",
    .next = core_parking_power,
};

static struct core_parking_policy performance_first = {
    .name = "performance",
    .next = core_parking_performance,
};

static int register_core_parking_policy(struct core_parking_policy *policy)
{
    if ( !policy || !policy->next )
        return -EINVAL;

    core_parking_policy = policy;
    return 0;
}

static int __init core_parking_init(void)
{
    int ret = 0;

    if ( core_parking_controller == PERFORMANCE_FIRST )
        ret = register_core_parking_policy(&performance_first);
    else
        ret = register_core_parking_policy(&power_first);

    return ret;
}
__initcall(core_parking_init);
