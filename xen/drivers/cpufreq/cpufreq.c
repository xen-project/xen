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
#include <xen/list.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <xen/domain.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <asm/config.h>
#include <asm/processor.h>
#include <asm/percpu.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/cpufreq.h>

struct cpufreq_dom {
    unsigned int	dom;
    cpumask_t		map;
    struct list_head	node;
};
static LIST_HEAD(cpufreq_dom_list_head);

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
    unsigned int dom, domexist = 0;
    unsigned int j;
    struct list_head *pos;
    struct cpufreq_dom *cpufreq_dom = NULL;
    struct cpufreq_policy new_policy;
    struct cpufreq_policy *policy;
    struct processor_performance *perf = &processor_pminfo[cpu]->perf;

    /* to protect the case when Px was not controlled by xen */
    if (!processor_pminfo[cpu]      ||
        !(perf->init & XEN_PX_INIT) ||
        !cpu_online(cpu))
        return -EINVAL;

    if (cpufreq_cpu_policy[cpu])
        return 0;

    ret = cpufreq_statistic_init(cpu);
    if (ret)
        return ret;

    dom = perf->domain_info.domain;

    list_for_each(pos, &cpufreq_dom_list_head) {
        cpufreq_dom = list_entry(pos, struct cpufreq_dom, node);
        if (dom == cpufreq_dom->dom) {
            domexist = 1;
            break;
        }
    }

    if (domexist) {
        /* share policy with the first cpu since on same boat */
        firstcpu = first_cpu(cpufreq_dom->map);
        policy = cpufreq_cpu_policy[firstcpu];

        cpufreq_cpu_policy[cpu] = policy;
        cpu_set(cpu, cpufreq_dom->map);
        cpu_set(cpu, policy->cpus);

        printk(KERN_EMERG"adding CPU %u\n", cpu);
    } else {
        cpufreq_dom = xmalloc(struct cpufreq_dom);
        if (!cpufreq_dom) {
            cpufreq_statistic_exit(cpu);
            return -ENOMEM;
        }
        memset(cpufreq_dom, 0, sizeof(struct cpufreq_dom));
        cpufreq_dom->dom = dom;
        cpu_set(cpu, cpufreq_dom->map);
        list_add(&cpufreq_dom->node, &cpufreq_dom_list_head);

        /* for the first cpu, setup policy and do init work */
        policy = xmalloc(struct cpufreq_policy);
        if (!policy) {
            list_del(&cpufreq_dom->node);
            xfree(cpufreq_dom);
            cpufreq_statistic_exit(cpu);
            return -ENOMEM;
        }
        memset(policy, 0, sizeof(struct cpufreq_policy));
        policy->cpu = cpu;
        cpu_set(cpu, policy->cpus);
        cpufreq_cpu_policy[cpu] = policy;

        ret = cpufreq_driver->init(policy);
        if (ret)
            goto err1;
        printk(KERN_EMERG"CPU %u initialization completed\n", cpu);
    }

    /*
     * After get full cpumap of the coordination domain,
     * we can safely start gov here.
     */
    if (cpus_weight(cpufreq_dom->map) ==
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
    for_each_cpu_mask(j, cpufreq_dom->map) {
        cpufreq_cpu_policy[j] = NULL;
        cpufreq_statistic_exit(j);
    }

    list_del(&cpufreq_dom->node);
    xfree(cpufreq_dom);
    xfree(policy);
    return ret;
}

int cpufreq_del_cpu(unsigned int cpu)
{
    unsigned int dom, domexist = 0;
    struct list_head *pos;
    struct cpufreq_dom *cpufreq_dom;
    struct cpufreq_policy *policy;
    struct processor_performance *perf = &processor_pminfo[cpu]->perf;

    /* to protect the case when Px was not controlled by xen */
    if (!processor_pminfo[cpu]      ||
        !(perf->init & XEN_PX_INIT) ||
        !cpu_online(cpu))
        return -EINVAL;

    if (!cpufreq_cpu_policy[cpu])
        return 0;

    dom = perf->domain_info.domain;
    policy = cpufreq_cpu_policy[cpu];

    list_for_each(pos, &cpufreq_dom_list_head) {
        cpufreq_dom = list_entry(pos, struct cpufreq_dom, node);
        if (dom == cpufreq_dom->dom) {
            domexist = 1;
            break;
        }
    }

    if (!domexist)
        return -EINVAL;

    /* for the first cpu of the domain, stop gov */
    if (cpus_weight(cpufreq_dom->map) ==
        perf->domain_info.num_processors)
        __cpufreq_governor(policy, CPUFREQ_GOV_STOP);

    cpufreq_cpu_policy[cpu] = NULL;
    cpu_clear(cpu, policy->cpus);
    cpu_clear(cpu, cpufreq_dom->map);
    cpufreq_statistic_exit(cpu);

    /* for the last cpu of the domain, clean room */
    /* It's safe here to free freq_table, drv_data and policy */
    if (!cpus_weight(cpufreq_dom->map)) {
        cpufreq_driver->exit(policy);
        list_del(&cpufreq_dom->node);
        xfree(cpufreq_dom);
        xfree(policy);
    }

    printk(KERN_EMERG"deleting CPU %u\n", cpu);
    return 0;
}

static void print_PCT(struct xen_pct_register *ptr)
{
    printk(KERN_INFO "\t_PCT: descriptor=%d, length=%d, space_id=%d, "
            "bit_width=%d, bit_offset=%d, reserved=%d, address=%"PRId64"\n",
            ptr->descriptor, ptr->length, ptr->space_id, ptr->bit_width, 
            ptr->bit_offset, ptr->reserved, ptr->address);
}

static void print_PSS(struct xen_processor_px *ptr, int count)
{
    int i;
    printk(KERN_INFO "\t_PSS: state_count=%d\n", count);
    for (i=0; i<count; i++){
        printk(KERN_INFO "\tState%d: %"PRId64"MHz %"PRId64"mW %"PRId64"us "
               "%"PRId64"us 0x%"PRIx64" 0x%"PRIx64"\n",
                i,
                ptr[i].core_frequency,
                ptr[i].power, 
                ptr[i].transition_latency,
                ptr[i].bus_master_latency,
                ptr[i].control,
                ptr[i].status
              );
    }
}

static void print_PSD( struct xen_psd_package *ptr)
{
    printk(KERN_INFO "\t_PSD: num_entries=%"PRId64" rev=%"PRId64
           " domain=%"PRId64" coord_type=%"PRId64" num_processors=%"PRId64"\n",
            ptr->num_entries, ptr->revision, ptr->domain, ptr->coord_type, 
            ptr->num_processors);
}

static void print_PPC(unsigned int platform_limit)
{
    printk(KERN_INFO "\t_PPC: %d\n", platform_limit);
}

int set_px_pminfo(uint32_t acpi_id, struct xen_processor_performance *dom0_px_info)
{
    int ret=0, cpuid;
    struct processor_pminfo *pmpt;
    struct processor_performance *pxpt;

    cpuid = get_cpu_id(acpi_id);
    if ( cpuid < 0 || !dom0_px_info)
    {
        ret = -EINVAL;
        goto out;
    }
    printk(KERN_INFO "Set CPU acpi_id(%d) cpuid(%d) Px State info:\n",
            acpi_id, cpuid);

    pmpt = processor_pminfo[cpuid];
    if ( !pmpt )
    {
        pmpt = xmalloc(struct processor_pminfo);
        if ( !pmpt )
        {
            ret = -ENOMEM;
            goto out;
        }
        memset(pmpt, 0, sizeof(*pmpt));
        processor_pminfo[cpuid] = pmpt;
    }
    pxpt = &pmpt->perf;
    pmpt->acpi_id = acpi_id;
    pmpt->id = cpuid;

    if ( dom0_px_info->flags & XEN_PX_PCT )
    {
        memcpy ((void *)&pxpt->control_register,
                (void *)&dom0_px_info->control_register,
                sizeof(struct xen_pct_register));
        memcpy ((void *)&pxpt->status_register,
                (void *)&dom0_px_info->status_register,
                sizeof(struct xen_pct_register));
        print_PCT(&pxpt->control_register);
        print_PCT(&pxpt->status_register);
    }
    if ( dom0_px_info->flags & XEN_PX_PSS ) 
    {
        if ( !(pxpt->states = xmalloc_array(struct xen_processor_px,
                        dom0_px_info->state_count)) )
        {
            ret = -ENOMEM;
            goto out;
        }
        copy_from_guest(pxpt->states, dom0_px_info->states, 
                                      dom0_px_info->state_count);
        pxpt->state_count = dom0_px_info->state_count;
        print_PSS(pxpt->states,pxpt->state_count);
    }
    if ( dom0_px_info->flags & XEN_PX_PSD )
    {
        pxpt->shared_type = dom0_px_info->shared_type;
        memcpy ((void *)&pxpt->domain_info,
                (void *)&dom0_px_info->domain_info,
                sizeof(struct xen_psd_package));
        print_PSD(&pxpt->domain_info);
    }
    if ( dom0_px_info->flags & XEN_PX_PPC )
    {
        pxpt->platform_limit = dom0_px_info->platform_limit;
        print_PPC(pxpt->platform_limit);

        if ( pxpt->init == XEN_PX_INIT )
        {

            ret = cpufreq_limit_change(cpuid); 
            goto out;
        }
    }

    if ( dom0_px_info->flags == ( XEN_PX_PCT | XEN_PX_PSS |
                XEN_PX_PSD | XEN_PX_PPC ) )
    {
        pxpt->init = XEN_PX_INIT;

        ret = cpufreq_cpu_init(cpuid);
        goto out;
    }

out:
    return ret;
}

