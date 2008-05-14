/*
 *  utility.c - misc functions for cpufreq driver and Px statistic
 *
 *  Copyright (C) 2001 Russell King
 *            (C) 2002 - 2003 Dominik Brodowski <linux@brodo.de>
 *
 *  Oct 2005 - Ashok Raj <ashok.raj@intel.com>
 *    Added handling for CPU hotplug
 *  Feb 2006 - Jacob Shin <jacob.shin@amd.com>
 *    Fix handling for CPU hotplug -- affected CPUs
 *  Feb 2008 - Liu Jinsong <jinsong.liu@intel.com>
 *    1. Merge cpufreq.c and freq_table.c of linux 2.6.23
 *    And poring to Xen hypervisor
 *    2. some Px statistic interface funcdtions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <xen/errno.h>
#include <xen/cpumask.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/percpu.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <asm/config.h>
#include <acpi/cpufreq/cpufreq.h>
#include <public/sysctl.h>

struct cpufreq_driver *cpufreq_driver;

/*********************************************************************
 *                   FREQUENCY TABLE HELPERS                         *
 *********************************************************************/

int cpufreq_frequency_table_cpuinfo(struct cpufreq_policy *policy,
                                    struct cpufreq_frequency_table *table)
{
    unsigned int min_freq = ~0;
    unsigned int max_freq = 0;
    unsigned int i;

    for (i=0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
        unsigned int freq = table[i].frequency;
        if (freq == CPUFREQ_ENTRY_INVALID)
            continue;
        if (freq < min_freq)
            min_freq = freq;
        if (freq > max_freq)
            max_freq = freq;
    }

    policy->min = policy->cpuinfo.min_freq = min_freq;
    policy->max = policy->cpuinfo.max_freq = max_freq;

    if (policy->min == ~0)
        return -EINVAL;
    else
        return 0;
}

int cpufreq_frequency_table_target(struct cpufreq_policy *policy,
                                   struct cpufreq_frequency_table *table,
                                   unsigned int target_freq,
                                   unsigned int relation,
                                   unsigned int *index)
{
    struct cpufreq_frequency_table optimal = {
        .index = ~0,
        .frequency = 0,
    };
    struct cpufreq_frequency_table suboptimal = {
        .index = ~0,
        .frequency = 0,
    };
    unsigned int i;

    switch (relation) {
    case CPUFREQ_RELATION_H:
        suboptimal.frequency = ~0;
        break;
    case CPUFREQ_RELATION_L:
        optimal.frequency = ~0;
        break;
    }

    if (!cpu_online(policy->cpu))
        return -EINVAL;

    for (i=0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
        unsigned int freq = table[i].frequency;
        if (freq == CPUFREQ_ENTRY_INVALID)
            continue;
        if ((freq < policy->min) || (freq > policy->max))
            continue;
        switch(relation) {
        case CPUFREQ_RELATION_H:
            if (freq <= target_freq) {
                if (freq >= optimal.frequency) {
                    optimal.frequency = freq;
                    optimal.index = i;
                }
            } else {
                if (freq <= suboptimal.frequency) {
                    suboptimal.frequency = freq;
                    suboptimal.index = i;
                }
            }
            break;
        case CPUFREQ_RELATION_L:
            if (freq >= target_freq) {
                if (freq <= optimal.frequency) {
                    optimal.frequency = freq;
                    optimal.index = i;
                }
            } else {
                if (freq >= suboptimal.frequency) {
                    suboptimal.frequency = freq;
                    suboptimal.index = i;
                }
            }
            break;
        }
    }
    if (optimal.index > i) {
        if (suboptimal.index > i)
            return -EINVAL;
        *index = suboptimal.index;
    } else
        *index = optimal.index;

    return 0;
}


/*********************************************************************
 *               GOVERNORS                                           *
 *********************************************************************/

int __cpufreq_driver_target(struct cpufreq_policy *policy,
                            unsigned int target_freq,
                            unsigned int relation)
{
    int retval = -EINVAL;

    if (cpu_online(policy->cpu) && cpufreq_driver->target)
        retval = cpufreq_driver->target(policy, target_freq, relation);

    return retval;
}

int __cpufreq_driver_getavg(struct cpufreq_policy *policy)
{
    int ret = 0;

    if (!policy)
        return -EINVAL;

    if (cpu_online(policy->cpu) && cpufreq_driver->getavg)
        ret = cpufreq_driver->getavg(policy->cpu);

    return ret;
}
