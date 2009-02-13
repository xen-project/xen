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

#include <xen/init.h>
#include <xen/sched.h>
#include <acpi/cpufreq/cpufreq.h>

static unsigned int usr_speed;

/*
 * cpufreq userspace governor
 */
static int cpufreq_governor_userspace(struct cpufreq_policy *policy,
                                      unsigned int event)
{
    int ret = 0;
    unsigned int freq;

    if (!policy)
        return -EINVAL;

    switch (event) {
    case CPUFREQ_GOV_START:
    case CPUFREQ_GOV_STOP:
        break;
    case CPUFREQ_GOV_LIMITS:
        freq = usr_speed ? : policy->cur;
        if (policy->max < freq)
            ret = __cpufreq_driver_target(policy, policy->max,
                        CPUFREQ_RELATION_H);
        else if (policy->min > freq)
            ret = __cpufreq_driver_target(policy, policy->min,
                        CPUFREQ_RELATION_L);
        else if (usr_speed)
            ret = __cpufreq_driver_target(policy, freq,
                        CPUFREQ_RELATION_L);

        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

static void __init 
cpufreq_userspace_handle_option(const char *name, const char *val)
{
    if (!strcmp(name, "speed") && val)
        usr_speed = simple_strtoul(val, NULL, 0);
}

struct cpufreq_governor cpufreq_gov_userspace = {
    .name = "userspace",
    .governor = cpufreq_governor_userspace,
    .handle_option = cpufreq_userspace_handle_option
};

static int __init cpufreq_gov_userspace_init(void)
{
    return cpufreq_register_governor(&cpufreq_gov_userspace);
}
__initcall(cpufreq_gov_userspace_init);

static void __exit cpufreq_gov_userspace_exit(void)
{
    cpufreq_unregister_governor(&cpufreq_gov_userspace);
}
__exitcall(cpufreq_gov_userspace_exit);


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

static void __exit cpufreq_gov_performance_exit(void)
{
    cpufreq_unregister_governor(&cpufreq_gov_performance);
}
__exitcall(cpufreq_gov_performance_exit);


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

static void __exit cpufreq_gov_powersave_exit(void)
{
    cpufreq_unregister_governor(&cpufreq_gov_powersave);
}
__exitcall(cpufreq_gov_powersave_exit);
