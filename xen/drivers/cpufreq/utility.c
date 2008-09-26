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

struct cpufreq_driver   *cpufreq_driver;
struct processor_pminfo *__read_mostly processor_pminfo[NR_CPUS];
struct cpufreq_policy   *__read_mostly cpufreq_cpu_policy[NR_CPUS];

/*********************************************************************
 *                    Px STATISTIC INFO                              *
 *********************************************************************/

void cpufreq_statistic_update(cpumask_t cpumask, uint8_t from, uint8_t to)
{
    uint32_t i;
    uint64_t now;

    now = NOW();

    for_each_cpu_mask(i, cpumask) {
        struct pm_px *pxpt = cpufreq_statistic_data[i];
        struct processor_pminfo *pmpt = processor_pminfo[i];
        uint64_t total_idle_ns;
        uint64_t tmp_idle_ns;

        if ( !pxpt || !pmpt )
            continue;

        total_idle_ns = get_cpu_idle_time(i);
        tmp_idle_ns = total_idle_ns - pxpt->prev_idle_wall;

        pxpt->u.last = from;
        pxpt->u.cur = to;
        pxpt->u.pt[to].count++;
        pxpt->u.pt[from].residency += now - pxpt->prev_state_wall;
        pxpt->u.pt[from].residency -= tmp_idle_ns;

        (*(pxpt->u.trans_pt + from * pmpt->perf.state_count + to))++;

        pxpt->prev_state_wall = now;
        pxpt->prev_idle_wall = total_idle_ns;
    }
}

int cpufreq_statistic_init(unsigned int cpuid)
{
    uint32_t i, count;
    struct pm_px *pxpt = cpufreq_statistic_data[cpuid];
    const struct processor_pminfo *pmpt = processor_pminfo[cpuid];

    count = pmpt->perf.state_count;

    if ( !pmpt )
        return -EINVAL;

    if ( !pxpt )
    {
        pxpt = xmalloc(struct pm_px);
        if ( !pxpt )
            return -ENOMEM;
        memset(pxpt, 0, sizeof(*pxpt));
        cpufreq_statistic_data[cpuid] = pxpt;
    }

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
    pxpt->u.usable = pmpt->perf.state_count - pmpt->perf.platform_limit;

    for (i=0; i < pmpt->perf.state_count; i++)
        pxpt->u.pt[i].freq = pmpt->perf.states[i].core_frequency;

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpuid);

    return 0;
}

void cpufreq_statistic_exit(unsigned int cpuid)
{
    struct pm_px *pxpt = cpufreq_statistic_data[cpuid];

    if (!pxpt)
        return;
    xfree(pxpt->u.trans_pt);
    xfree(pxpt->u.pt);
    memset(pxpt, 0, sizeof(struct pm_px));
}

void cpufreq_statistic_reset(unsigned int cpuid)
{
    uint32_t i, j, count;
    struct pm_px *pxpt = cpufreq_statistic_data[cpuid];
    const struct processor_pminfo *pmpt = processor_pminfo[cpuid];

    if ( !pxpt || !pmpt )
        return;

    count = pmpt->perf.state_count;

    for (i=0; i < count; i++) {
        pxpt->u.pt[i].residency = 0;
        pxpt->u.pt[i].count = 0;

        for (j=0; j < count; j++)
            *(pxpt->u.trans_pt + i*count + j) = 0;
    }

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpuid);
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

int cpufreq_frequency_table_verify(struct cpufreq_policy *policy,
                                   struct cpufreq_frequency_table *table)
{
    unsigned int next_larger = ~0;
    unsigned int i;
    unsigned int count = 0;

    if (!cpu_online(policy->cpu))
        return -EINVAL;

    cpufreq_verify_within_limits(policy, policy->cpuinfo.min_freq,
                                 policy->cpuinfo.max_freq);

    for (i=0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
        unsigned int freq = table[i].frequency;
        if (freq == CPUFREQ_ENTRY_INVALID)
            continue;
        if ((freq >= policy->min) && (freq <= policy->max))
            count++;
        else if ((next_larger > freq) && (freq > policy->max))
            next_larger = freq;
    }

    if (!count)
        policy->max = next_larger;

    cpufreq_verify_within_limits(policy, policy->cpuinfo.min_freq,
                                 policy->cpuinfo.max_freq);

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
 *                 POLICY                                            *
 *********************************************************************/

/*
 * data   : current policy.
 * policy : policy to be set.
 */
int __cpufreq_set_policy(struct cpufreq_policy *data,
                                struct cpufreq_policy *policy)
{
    int ret = 0;

    memcpy(&policy->cpuinfo, &data->cpuinfo, sizeof(struct cpufreq_cpuinfo));

    if (policy->min > data->min && policy->min > policy->max)
        return -EINVAL;

    /* verify the cpu speed can be set within this limit */
    ret = cpufreq_driver->verify(policy);
    if (ret)
        return ret;

    data->min = policy->min;
    data->max = policy->max;

    if (policy->governor != data->governor) {
        /* save old, working values */
        struct cpufreq_governor *old_gov = data->governor;

        /* end old governor */
        if (data->governor)
            __cpufreq_governor(data, CPUFREQ_GOV_STOP);

        /* start new governor */
        data->governor = policy->governor;
        if (__cpufreq_governor(data, CPUFREQ_GOV_START)) {
            /* new governor failed, so re-start old one */
            if (old_gov) {
                data->governor = old_gov;
                __cpufreq_governor(data, CPUFREQ_GOV_START);
            }
            return -EINVAL;
        }
        /* might be a policy change, too, so fall through */
    }

    return __cpufreq_governor(data, CPUFREQ_GOV_LIMITS);
}
