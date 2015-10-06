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
#include <xen/trace.h>
#include <acpi/cpufreq/cpufreq.h>
#include <public/sysctl.h>

struct cpufreq_driver   *cpufreq_driver;
struct processor_pminfo *__read_mostly processor_pminfo[NR_CPUS];
DEFINE_PER_CPU_READ_MOSTLY(struct cpufreq_policy *, cpufreq_cpu_policy);

DEFINE_PER_CPU(spinlock_t, cpufreq_statistic_lock);

/*********************************************************************
 *                    Px STATISTIC INFO                              *
 *********************************************************************/

void cpufreq_residency_update(unsigned int cpu, uint8_t state)
{
    uint64_t now, total_idle_ns;
    int64_t delta;
    struct pm_px *pxpt = per_cpu(cpufreq_statistic_data, cpu);

    total_idle_ns = get_cpu_idle_time(cpu);
    now = NOW();

    delta = (now - pxpt->prev_state_wall) - 
            (total_idle_ns - pxpt->prev_idle_wall);

    if ( likely(delta >= 0) )
        pxpt->u.pt[state].residency += delta;

    pxpt->prev_state_wall = now;
    pxpt->prev_idle_wall = total_idle_ns;
}

void cpufreq_statistic_update(unsigned int cpu, uint8_t from, uint8_t to)
{
    struct pm_px *pxpt;
    struct processor_pminfo *pmpt = processor_pminfo[cpu];
    spinlock_t *cpufreq_statistic_lock = 
               &per_cpu(cpufreq_statistic_lock, cpu);

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpu);
    if ( !pxpt || !pmpt ) {
        spin_unlock(cpufreq_statistic_lock);
        return;
    }

    pxpt->u.last = from;
    pxpt->u.cur = to;
    pxpt->u.pt[to].count++;

    cpufreq_residency_update(cpu, from);

    (*(pxpt->u.trans_pt + from * pmpt->perf.state_count + to))++;

    spin_unlock(cpufreq_statistic_lock);
}

int cpufreq_statistic_init(unsigned int cpuid)
{
    uint32_t i, count;
    struct pm_px *pxpt;
    const struct processor_pminfo *pmpt = processor_pminfo[cpuid];
    spinlock_t *cpufreq_statistic_lock = 
                          &per_cpu(cpufreq_statistic_lock, cpuid);

    spin_lock_init(cpufreq_statistic_lock);

    if ( !pmpt )
        return -EINVAL;

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpuid);
    if ( pxpt ) {
        spin_unlock(cpufreq_statistic_lock);
        return 0;
    }

    count = pmpt->perf.state_count;

    pxpt = xzalloc(struct pm_px);
    if ( !pxpt ) {
        spin_unlock(cpufreq_statistic_lock);
        return -ENOMEM;
    }
    per_cpu(cpufreq_statistic_data, cpuid) = pxpt;

    pxpt->u.trans_pt = xzalloc_array(uint64_t, count * count);
    if (!pxpt->u.trans_pt) {
        xfree(pxpt);
        spin_unlock(cpufreq_statistic_lock);
        return -ENOMEM;
    }

    pxpt->u.pt = xzalloc_array(struct pm_px_val, count);
    if (!pxpt->u.pt) {
        xfree(pxpt->u.trans_pt);
        xfree(pxpt);
        spin_unlock(cpufreq_statistic_lock);
        return -ENOMEM;
    }

    pxpt->u.total = pmpt->perf.state_count;
    pxpt->u.usable = pmpt->perf.state_count - pmpt->perf.platform_limit;

    for (i=0; i < pmpt->perf.state_count; i++)
        pxpt->u.pt[i].freq = pmpt->perf.states[i].core_frequency;

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpuid);

    spin_unlock(cpufreq_statistic_lock);

    return 0;
}

void cpufreq_statistic_exit(unsigned int cpuid)
{
    struct pm_px *pxpt;
    spinlock_t *cpufreq_statistic_lock = 
               &per_cpu(cpufreq_statistic_lock, cpuid);

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpuid);
    if (!pxpt) {
        spin_unlock(cpufreq_statistic_lock);
        return;
    }

    xfree(pxpt->u.trans_pt);
    xfree(pxpt->u.pt);
    xfree(pxpt);
    per_cpu(cpufreq_statistic_data, cpuid) = NULL;

    spin_unlock(cpufreq_statistic_lock);
}

void cpufreq_statistic_reset(unsigned int cpuid)
{
    uint32_t i, j, count;
    struct pm_px *pxpt;
    const struct processor_pminfo *pmpt = processor_pminfo[cpuid];
    spinlock_t *cpufreq_statistic_lock = 
               &per_cpu(cpufreq_statistic_lock, cpuid);

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpuid);
    if ( !pmpt || !pxpt || !pxpt->u.pt || !pxpt->u.trans_pt ) {
        spin_unlock(cpufreq_statistic_lock);
        return;
    }

    count = pmpt->perf.state_count;

    for (i=0; i < count; i++) {
        pxpt->u.pt[i].residency = 0;
        pxpt->u.pt[i].count = 0;

        for (j=0; j < count; j++)
            *(pxpt->u.trans_pt + i*count + j) = 0;
    }

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpuid);

    spin_unlock(cpufreq_statistic_lock);
}


/*********************************************************************
 *                   FREQUENCY TABLE HELPERS                         *
 *********************************************************************/

int cpufreq_frequency_table_cpuinfo(struct cpufreq_policy *policy,
                                    struct cpufreq_frequency_table *table)
{
    unsigned int min_freq = ~0;
    unsigned int max_freq = 0;
    unsigned int second_max_freq = 0;
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
    for (i=0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
        unsigned int freq = table[i].frequency;
        if (freq == CPUFREQ_ENTRY_INVALID || freq == max_freq)
            continue;
        if (freq > second_max_freq)
            second_max_freq = freq;
    }
    if (second_max_freq == 0)
        second_max_freq = max_freq;
    if (cpufreq_verbose)
        printk("max_freq: %u    second_max_freq: %u\n",
               max_freq, second_max_freq);

    policy->min = policy->cpuinfo.min_freq = min_freq;
    policy->max = policy->cpuinfo.max_freq = max_freq;
    policy->cpuinfo.second_max_freq = second_max_freq;

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
    {
        unsigned int prev_freq = policy->cur;

        retval = cpufreq_driver->target(policy, target_freq, relation);
        if ( retval == 0 )
            TRACE_2D(TRC_PM_FREQ_CHANGE, prev_freq/1000, policy->cur/1000);
    }

    return retval;
}

int cpufreq_driver_getavg(unsigned int cpu, unsigned int flag)
{
    struct cpufreq_policy *policy;
    int freq_avg;

    if (!cpu_online(cpu) || !(policy = per_cpu(cpufreq_cpu_policy, cpu)))
        return 0;

    if (cpufreq_driver->getavg)
    {
        freq_avg = cpufreq_driver->getavg(cpu, flag);
        if (freq_avg > 0)
            return freq_avg;
    }

    return policy->cur;
}

int cpufreq_update_turbo(int cpuid, int new_state)
{
    struct cpufreq_policy *policy;
    int curr_state;
    int ret = 0;

    if (new_state != CPUFREQ_TURBO_ENABLED &&
        new_state != CPUFREQ_TURBO_DISABLED)
        return -EINVAL;

    policy = per_cpu(cpufreq_cpu_policy, cpuid);
    if (!policy)
        return -EACCES;

    if (policy->turbo == CPUFREQ_TURBO_UNSUPPORTED)
        return -EOPNOTSUPP;

    curr_state = policy->turbo;
    if (curr_state == new_state)
        return 0;

    policy->turbo = new_state;
    if (cpufreq_driver->update)
    {
        ret = cpufreq_driver->update(cpuid, policy);
        if (ret)
            policy->turbo = curr_state;
    }

    return ret;
}


int cpufreq_get_turbo_status(int cpuid)
{
    struct cpufreq_policy *policy;

    policy = per_cpu(cpufreq_cpu_policy, cpuid);
    return policy && policy->turbo == CPUFREQ_TURBO_ENABLED;
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
    data->limits = policy->limits;
    if (cpufreq_driver->setpolicy)
        return cpufreq_driver->setpolicy(data);

    if (policy->governor != data->governor) {
        /* save old, working values */
        struct cpufreq_governor *old_gov = data->governor;

        /* end old governor */
        if (data->governor)
            __cpufreq_governor(data, CPUFREQ_GOV_STOP);

        /* start new governor */
        data->governor = policy->governor;
        if (__cpufreq_governor(data, CPUFREQ_GOV_START)) {
            printk(KERN_WARNING "Fail change to %s governor\n",
                                 data->governor->name);

            /* new governor failed, so re-start old one */
            data->governor = old_gov;
            if (old_gov) {
                __cpufreq_governor(data, CPUFREQ_GOV_START);
                printk(KERN_WARNING "Still stay at %s governor\n",
                                     data->governor->name);
            }
            return -EINVAL;
        }
        /* might be a policy change, too, so fall through */
    }

    return __cpufreq_governor(data, CPUFREQ_GOV_LIMITS);
}
