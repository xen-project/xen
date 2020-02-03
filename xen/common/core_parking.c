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
#include <xen/param.h>

#include <asm/smp.h>

#define CORE_PARKING_INCREMENT 1
#define CORE_PARKING_DECREMENT 2

static DEFINE_SPINLOCK(accounting_lock);
static uint32_t cur_idle_nums;
static unsigned int core_parking_cpunum[NR_CPUS] = {[0 ... NR_CPUS-1] = -1};

static const struct cp_policy {
    char name[30];
    unsigned int (*next)(unsigned int event);
} *__read_mostly core_parking_policy;

static enum core_parking_controller {
    POWER_FIRST,
    PERFORMANCE_FIRST
} core_parking_controller __initdata = POWER_FIRST;

static int __init setup_core_parking_option(const char *str)
{
    if ( !strcmp(str, "power") )
        core_parking_controller = POWER_FIRST;
    else if ( !strcmp(str, "performance") )
        core_parking_controller = PERFORMANCE_FIRST;
    else
        return -EINVAL;

    return 0;
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
        spin_lock(&accounting_lock);
        cpu = core_parking_cpunum[cur_idle_nums - 1];
        spin_unlock(&accounting_lock);
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
        spin_lock(&accounting_lock);
        cpu = core_parking_cpunum[cur_idle_nums - 1];
        spin_unlock(&accounting_lock);
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

        spin_lock(&accounting_lock);
        BUG_ON(cur_idle_nums >= ARRAY_SIZE(core_parking_cpunum));
        core_parking_cpunum[cur_idle_nums++] = cpu;
        spin_unlock(&accounting_lock);
    }

    while ( cur_idle_nums > idle_nums )
    {
        cpu = core_parking_policy->next(CORE_PARKING_DECREMENT);
        ret = cpu_up(cpu);
        if ( ret )
            return ret;

        if ( !core_parking_remove(cpu) )
        {
            ret = cpu_down(cpu);
            if ( ret == -EEXIST )
                ret = 0;
            if ( ret )
                break;
        }
    }

    return ret;
}

bool core_parking_remove(unsigned int cpu)
{
    unsigned int i;
    bool found = false;

    spin_lock(&accounting_lock);

    for ( i = 0; i < cur_idle_nums; ++i )
        if ( core_parking_cpunum[i] == cpu )
        {
            found = true;
            --cur_idle_nums;
            break;
        }

    for ( ; i < cur_idle_nums; ++i )
        core_parking_cpunum[i] = core_parking_cpunum[i + 1];

    spin_unlock(&accounting_lock);

    return found;
}

uint32_t get_cur_idle_nums(void)
{
    return cur_idle_nums;
}

static const struct cp_policy power_first = {
    .name = "power",
    .next = core_parking_power,
};

static const struct cp_policy performance_first = {
    .name = "performance",
    .next = core_parking_performance,
};

static int __init register_core_parking_policy(const struct cp_policy *policy)
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
