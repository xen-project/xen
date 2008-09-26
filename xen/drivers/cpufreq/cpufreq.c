/*
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2002 - 2004 Dominik Brodowski <linux@brodo.de>
 *  Copyright (C) 2006        Denis Sadykov <denis.m.sadykov@intel.com>
 *
 *  Feb 2008 - Liu Jinsong <jinsong.liu@intel.com>
 *      Add cpufreq limit change handle and per-cpu cpufreq add/del
 *      to cope with cpu hotplug
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/cpumask.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <xen/xmalloc.h>
#include <asm/bug.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/config.h>
#include <asm/processor.h>
#include <asm/percpu.h>
#include <asm/cpufeature.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/cpufreq.h>

/* TODO: change to link list later as domain number may be sparse */
static cpumask_t cpufreq_dom_map[NR_CPUS];

int cpufreq_limit_change(unsigned int cpu)
{
    struct processor_performance *perf = &processor_pminfo[cpu]->perf;
    struct cpufreq_policy *data = cpufreq_cpu_policy[cpu];
    struct cpufreq_policy policy;

    if (!cpu_online(cpu) || !data || !processor_pminfo[cpu])
        return -ENODEV;

    if ((perf->platform_limit < 0) || 
        (perf->platform_limit >= perf->state_count))
        return -EINVAL;

    memcpy(&policy, data, sizeof(struct cpufreq_policy)); 

    policy.max =
        perf->states[perf->platform_limit].core_frequency * 1000;

    return __cpufreq_set_policy(data, &policy);
}

int cpufreq_add_cpu(unsigned int cpu)
{
    int ret = 0;
    unsigned int firstcpu;
    unsigned int dom;
    unsigned int j;
    struct cpufreq_policy new_policy;
    struct cpufreq_policy *policy;
    struct processor_performance *perf = &processor_pminfo[cpu]->perf;

    /* to protect the case when Px was not controlled by xen */
    if (!processor_pminfo[cpu] || !(perf->init & XEN_PX_INIT))
        return 0;

    if (cpu_is_offline(cpu) || cpufreq_cpu_policy[cpu])
        return -EINVAL;

    ret = cpufreq_statistic_init(cpu);
    if (ret)
        return ret;

    dom = perf->domain_info.domain;
    if (cpus_weight(cpufreq_dom_map[dom])) {
        /* share policy with the first cpu since on same boat */
        firstcpu = first_cpu(cpufreq_dom_map[dom]);
        policy = cpufreq_cpu_policy[firstcpu];

        cpufreq_cpu_policy[cpu] = policy;
        cpu_set(cpu, cpufreq_dom_map[dom]);
        cpu_set(cpu, policy->cpus);

        printk(KERN_EMERG"adding CPU %u\n", cpu);
    } else {
        /* for the first cpu, setup policy and do init work */
        policy = xmalloc(struct cpufreq_policy);
        if (!policy) {
            cpufreq_statistic_exit(cpu);
            return -ENOMEM;
        }
        memset(policy, 0, sizeof(struct cpufreq_policy));

        cpufreq_cpu_policy[cpu] = policy;
        cpu_set(cpu, cpufreq_dom_map[dom]);
        cpu_set(cpu, policy->cpus);

        policy->cpu = cpu;
        ret = cpufreq_driver->init(policy);
        if (ret)
            goto err1;
        printk(KERN_EMERG"CPU %u initialization completed\n", cpu);
    }

    /*
     * After get full cpumap of the coordination domain,
     * we can safely start gov here.
     */
    if (cpus_weight(cpufreq_dom_map[dom]) ==
        perf->domain_info.num_processors) {
        memcpy(&new_policy, policy, sizeof(struct cpufreq_policy));
        policy->governor = NULL;
        ret = __cpufreq_set_policy(policy, &new_policy);
        if (ret)
            goto err2;
    }

    return 0;

err2:
    cpufreq_driver->exit(policy);
err1:
    for_each_cpu_mask(j, cpufreq_dom_map[dom]) {
        cpufreq_cpu_policy[j] = NULL;
        cpufreq_statistic_exit(j);
    }

    cpus_clear(cpufreq_dom_map[dom]);
    xfree(policy);
    return ret;
}

int cpufreq_del_cpu(unsigned int cpu)
{
    unsigned int dom;
    struct cpufreq_policy *policy;
    struct processor_performance *perf = &processor_pminfo[cpu]->perf;

    /* to protect the case when Px was not controlled by xen */
    if (!processor_pminfo[cpu] || !(perf->init & XEN_PX_INIT))
        return 0;

    if (cpu_is_offline(cpu) || !cpufreq_cpu_policy[cpu])
        return -EINVAL;

    dom = perf->domain_info.domain;
    policy = cpufreq_cpu_policy[cpu];

    printk(KERN_EMERG"deleting CPU %u\n", cpu);

    /* for the first cpu of the domain, stop gov */
    if (cpus_weight(cpufreq_dom_map[dom]) ==
        perf->domain_info.num_processors)
        __cpufreq_governor(policy, CPUFREQ_GOV_STOP);

    cpufreq_cpu_policy[cpu] = NULL;
    cpu_clear(cpu, policy->cpus);
    cpu_clear(cpu, cpufreq_dom_map[dom]);
    cpufreq_statistic_exit(cpu);

    /* for the last cpu of the domain, clean room */
    /* It's safe here to free freq_table, drv_data and policy */
    if (!cpus_weight(cpufreq_dom_map[dom])) {
        cpufreq_driver->exit(policy);
        xfree(policy);
    }

    return 0;
}

