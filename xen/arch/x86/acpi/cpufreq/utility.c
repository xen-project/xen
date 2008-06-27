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
 *                    Px STATISTIC INFO                              *
 *********************************************************************/

void px_statistic_suspend(void)
{
    int cpu;
    uint64_t now;

    now = NOW();

    for_each_online_cpu(cpu) {
        struct pm_px *pxpt = &px_statistic_data[cpu];
        pxpt->u.pt[pxpt->u.cur].residency +=
                    now - pxpt->prev_state_wall;
    }
}

void px_statistic_resume(void)
{
    int cpu;
    uint64_t now;

    now = NOW();

    for_each_online_cpu(cpu) {
        struct pm_px *pxpt = &px_statistic_data[cpu];
        pxpt->prev_state_wall = now;
    }
}

void px_statistic_update(cpumask_t cpumask, uint8_t from, uint8_t to)
{
    uint32_t i;
    uint64_t now;

    now = NOW();

    for_each_cpu_mask(i, cpumask) {
        struct pm_px *pxpt = &px_statistic_data[i];
        uint32_t statnum = processor_pminfo[i].perf.state_count;

        pxpt->u.last = from;
        pxpt->u.cur = to;
        pxpt->u.pt[to].count++;
        pxpt->u.pt[from].residency += now - pxpt->prev_state_wall;

        (*(pxpt->u.trans_pt + from*statnum + to))++;

        pxpt->prev_state_wall = now;
    }
}

int px_statistic_init(int cpuid)
{
    uint32_t i, count;
    struct pm_px *pxpt = &px_statistic_data[cpuid];
    struct processor_pminfo *pmpt = &processor_pminfo[cpuid];

    count = pmpt->perf.state_count;

    pxpt->u.trans_pt = xmalloc_array(uint64_t, count * count);
    if (!pxpt->u.trans_pt)
        return -ENOMEM;

    pxpt->u.pt = xmalloc_array(struct pm_px_val, count);
    if (!pxpt->u.pt) {
        xfree(pxpt->u.trans_pt);
        return -ENOMEM;
    }

    memset(pxpt->u.trans_pt, 0, count * count * (sizeof(uint64_t)));
    memset(pxpt->u.pt, 0, count * (sizeof(struct pm_px_val)));

    pxpt->u.total = pmpt->perf.state_count;
    pxpt->u.usable = pmpt->perf.state_count - pmpt->perf.ppc;

    for (i=0; i < pmpt->perf.state_count; i++)
        pxpt->u.pt[i].freq = pmpt->perf.states[i].core_frequency;

    pxpt->prev_state_wall = NOW();

    return 0;
}

void px_statistic_reset(int cpuid)
{
    uint32_t i, j, count;
    struct pm_px *pxpt = &px_statistic_data[cpuid];

    count = processor_pminfo[cpuid].perf.state_count;

    for (i=0; i < count; i++) {
        pxpt->u.pt[i].residency = 0;
        pxpt->u.pt[i].count = 0;

        for (j=0; j < count; j++)
            *(pxpt->u.trans_pt + i*count + j) = 0;
    }

    pxpt->prev_state_wall = NOW();
}


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


/*********************************************************************
 *               CPUFREQ SUSPEND/RESUME                              *
 *********************************************************************/

void cpufreq_suspend(void)
{
    int cpu;

    /* to protect the case when Px was controlled by dom0-kernel */
    /* or when CPU_FREQ not set in which case ACPI Px objects not parsed */
    for_each_online_cpu(cpu) {
        struct processor_performance *perf = &processor_pminfo[cpu].perf;

        if (!perf->init)
            return;
    }

    cpufreq_dom_dbs(CPUFREQ_GOV_STOP);

    cpufreq_dom_exit();

    px_statistic_suspend();
}

int cpufreq_resume(void)
{
    int cpu, ret = 0;

    /* 1. to protect the case when Px was controlled by dom0-kernel */
    /* or when CPU_FREQ not set in which case ACPI Px objects not parsed */
    /* 2. set state and resume flag to sync cpu to right state and freq */
    for_each_online_cpu(cpu) {
        struct processor_performance *perf = &processor_pminfo[cpu].perf;
        struct cpufreq_policy *policy = &xen_px_policy[cpu];

        if (!perf->init)
            goto err;
        perf->state = 0;
        policy->resume = 1;
    }

    px_statistic_resume();

    ret = cpufreq_dom_init();
    if (ret)
        goto err;

    ret = cpufreq_dom_dbs(CPUFREQ_GOV_START);
    if (ret)
        goto err;

    return ret;

err:
    cpufreq_dom_exit();
    return ret;
}
