/*
 *  xen/drivers/cpufreq/cpufreq_misc_gov.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2002 - 2004 Dominik Brodowski <linux@brodo.de>
 *
 *     Nov 2008 Liu Jinsong <jinsong.liu@intel.com>
 *     Porting cpufreq_userspace.c, cpufreq_performance.c, and 
 *     cpufreq_powersave.c from Liunx 2.6.23 to Xen hypervisor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <xen/cpu.h>
#include <xen/init.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <acpi/cpufreq/cpufreq.h>

/*
 * cpufreq userspace governor
 */
static unsigned int __read_mostly userspace_cmdline_freq;
static DEFINE_PER_CPU(unsigned int, cpu_set_freq);

static int cpufreq_governor_userspace(struct cpufreq_policy *policy,
                                      unsigned int event)
{
    int ret = 0;
    unsigned int cpu;

    if (unlikely(!policy) || 
        unlikely(!cpu_online(cpu = policy->cpu)))
        return -EINVAL;

    switch (event) {
    case CPUFREQ_GOV_START:
        if (!per_cpu(cpu_set_freq, cpu))
            per_cpu(cpu_set_freq, cpu) = policy->cur;
        break;
    case CPUFREQ_GOV_STOP:
        per_cpu(cpu_set_freq, cpu) = 0;
        break;
    case CPUFREQ_GOV_LIMITS:
        if (policy->max < per_cpu(cpu_set_freq, cpu))
            ret = __cpufreq_driver_target(policy, policy->max,
                        CPUFREQ_RELATION_H);
        else if (policy->min > per_cpu(cpu_set_freq, cpu))
            ret = __cpufreq_driver_target(policy, policy->min,
                        CPUFREQ_RELATION_L);
        else
            ret = __cpufreq_driver_target(policy, per_cpu(cpu_set_freq, cpu),
                        CPUFREQ_RELATION_L);

        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

int write_userspace_scaling_setspeed(unsigned int cpu, unsigned int freq)
{
    struct cpufreq_policy *policy;

    if (!cpu_online(cpu) || !(policy = per_cpu(cpufreq_cpu_policy, cpu)))
        return -EINVAL;

    per_cpu(cpu_set_freq, cpu) = freq;

    if (freq < policy->min)
        freq = policy->min;
    if (freq > policy->max)
        freq = policy->max;

    return __cpufreq_driver_target(policy, freq, CPUFREQ_RELATION_L);
}

static bool_t __init
cpufreq_userspace_handle_option(const char *name, const char *val)
{
    if (!strcmp(name, "speed") && val) {
        userspace_cmdline_freq = simple_strtoul(val, NULL, 0);
        return 1;
    }
    return 0;
}

static int cpufreq_userspace_cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch (action)
    {
    case CPU_UP_PREPARE:
        per_cpu(cpu_set_freq, cpu) = userspace_cmdline_freq;
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpufreq_userspace_cpu_nfb = {
    .notifier_call = cpufreq_userspace_cpu_callback
};

struct cpufreq_governor cpufreq_gov_userspace = {
    .name = "userspace",
    .governor = cpufreq_governor_userspace,
    .handle_option = cpufreq_userspace_handle_option
};

static int __init cpufreq_gov_userspace_init(void)
{
    unsigned int cpu;

    for_each_online_cpu(cpu)
        per_cpu(cpu_set_freq, cpu) = userspace_cmdline_freq;
    register_cpu_notifier(&cpufreq_userspace_cpu_nfb);
    return cpufreq_register_governor(&cpufreq_gov_userspace);
}
__initcall(cpufreq_gov_userspace_init);


/*
 * cpufreq performance governor
 */
static int cpufreq_governor_performance(struct cpufreq_policy *policy,
                                      unsigned int event)
{
    int ret = 0;

    if (!policy)
        return -EINVAL;

    switch (event) {
    case CPUFREQ_GOV_START:
    case CPUFREQ_GOV_STOP:
        break;
    case CPUFREQ_GOV_LIMITS:
        ret = __cpufreq_driver_target(policy, policy->max,
                        CPUFREQ_RELATION_H);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

struct cpufreq_governor cpufreq_gov_performance = {
    .name = "performance",
    .governor = cpufreq_governor_performance,
};

static int __init cpufreq_gov_performance_init(void)
{
    return cpufreq_register_governor(&cpufreq_gov_performance);
}
__initcall(cpufreq_gov_performance_init);


/*
 * cpufreq powersave governor
 */
static int cpufreq_governor_powersave(struct cpufreq_policy *policy,
                                      unsigned int event)
{
    int ret = 0;

    if (!policy)
        return -EINVAL;

    switch (event) {
    case CPUFREQ_GOV_START:
    case CPUFREQ_GOV_STOP:
        break;
    case CPUFREQ_GOV_LIMITS:
        ret = __cpufreq_driver_target(policy, policy->min,
                        CPUFREQ_RELATION_L);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

struct cpufreq_governor cpufreq_gov_powersave = {
    .name = "powersave",
    .governor = cpufreq_governor_powersave,
};

static int __init cpufreq_gov_powersave_init(void)
{
    return cpufreq_register_governor(&cpufreq_gov_powersave);
}
__initcall(cpufreq_gov_powersave_init);
