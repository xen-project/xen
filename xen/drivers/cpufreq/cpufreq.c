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
#include <xen/string.h>
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

static unsigned int usr_max_freq, usr_min_freq;
static void cpufreq_cmdline_common_para(struct cpufreq_policy *new_policy);

struct cpufreq_dom {
    unsigned int	dom;
    cpumask_t		map;
    struct list_head	node;
};
static LIST_HEAD(cpufreq_dom_list_head);

struct cpufreq_governor *cpufreq_opt_governor;
LIST_HEAD(cpufreq_governor_list);

struct cpufreq_governor *__find_governor(const char *governor)
{
    struct cpufreq_governor *t;

    if (!governor)
        return NULL;

    list_for_each_entry(t, &cpufreq_governor_list, governor_list)
        if (!strnicmp(governor, t->name, CPUFREQ_NAME_LEN))
            return t;

    return NULL;
}

int cpufreq_register_governor(struct cpufreq_governor *governor)
{
    if (!governor)
        return -EINVAL;

    if (__find_governor(governor->name) != NULL)
        return -EEXIST;

    list_add(&governor->governor_list, &cpufreq_governor_list);
    return 0;
}

int cpufreq_unregister_governor(struct cpufreq_governor *governor)
{
    int cpu = smp_processor_id();
    struct cpufreq_policy *policy = cpufreq_cpu_policy[cpu];

    if (!governor || !policy)
        return -EINVAL;

    /* error if unregister current cpufreq governor */
    if (governor == policy->governor)
        return -EBUSY;

    if (__find_governor(governor->name) == NULL)
        return -ENOENT;

    list_del(&governor->governor_list);
    return 0;
}

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
    unsigned int hw_all = 0;
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

    if (!cpufreq_driver)
        return 0;

    if (cpufreq_cpu_policy[cpu])
        return 0;

    if (perf->shared_type == CPUFREQ_SHARED_TYPE_HW)
        hw_all = 1;

    dom = perf->domain_info.domain;

    list_for_each(pos, &cpufreq_dom_list_head) {
        cpufreq_dom = list_entry(pos, struct cpufreq_dom, node);
        if (dom == cpufreq_dom->dom) {
            domexist = 1;
            break;
        }
    }

    if (!domexist) {
        cpufreq_dom = xmalloc(struct cpufreq_dom);
        if (!cpufreq_dom)
            return -ENOMEM;

        memset(cpufreq_dom, 0, sizeof(struct cpufreq_dom));
        cpufreq_dom->dom = dom;
        list_add(&cpufreq_dom->node, &cpufreq_dom_list_head);
    } else {
        /* domain sanity check under whatever coordination type */
        firstcpu = first_cpu(cpufreq_dom->map);
        if ((perf->domain_info.coord_type !=
            processor_pminfo[firstcpu]->perf.domain_info.coord_type) ||
            (perf->domain_info.num_processors !=
            processor_pminfo[firstcpu]->perf.domain_info.num_processors)) {

            printk(KERN_WARNING "cpufreq fail to add CPU%d:"
                   "incorrect _PSD(%"PRIu64":%"PRIu64"), "
                   "expect(%"PRIu64"/%"PRIu64")\n",
                   cpu, perf->domain_info.coord_type,
                   perf->domain_info.num_processors,
                   processor_pminfo[firstcpu]->perf.domain_info.coord_type,
                   processor_pminfo[firstcpu]->perf.domain_info.num_processors
                );
            return -EINVAL;
        }
    }

    if (!domexist || hw_all) {
        policy = xmalloc(struct cpufreq_policy);
        if (!policy)
            ret = -ENOMEM;

        memset(policy, 0, sizeof(struct cpufreq_policy));
        policy->cpu = cpu;
        cpufreq_cpu_policy[cpu] = policy;

        ret = cpufreq_driver->init(policy);
        if (ret) {
            xfree(policy);
            cpufreq_cpu_policy[cpu] = NULL;
            return ret;
        }
        printk(KERN_EMERG"CPU %u initialization completed\n", cpu);
    } else {
        firstcpu = first_cpu(cpufreq_dom->map);
        policy = cpufreq_cpu_policy[firstcpu];

        cpufreq_cpu_policy[cpu] = policy;
        printk(KERN_EMERG"adding CPU %u\n", cpu);
    }

    cpu_set(cpu, policy->cpus);
    cpu_set(cpu, cpufreq_dom->map);

    ret = cpufreq_statistic_init(cpu);
    if (ret)
        goto err1;

    if (hw_all ||
        (cpus_weight(cpufreq_dom->map) == perf->domain_info.num_processors)) {
        memcpy(&new_policy, policy, sizeof(struct cpufreq_policy));
        policy->governor = NULL;

        cpufreq_cmdline_common_para(&new_policy);

        ret = __cpufreq_set_policy(policy, &new_policy);
        if (ret) {
            if (new_policy.governor == CPUFREQ_DEFAULT_GOVERNOR)
                /* if default governor fail, cpufreq really meet troubles */
                goto err2;
            else {
                /* grub option governor fail */
                /* give one more chance to default gov */
                memcpy(&new_policy, policy, sizeof(struct cpufreq_policy));
                new_policy.governor = CPUFREQ_DEFAULT_GOVERNOR;
                ret = __cpufreq_set_policy(policy, &new_policy);
                if (ret)
                    goto err2;
            }
        }
    }

    return 0;

err2:
    cpufreq_statistic_exit(cpu);
err1:
    cpufreq_cpu_policy[cpu] = NULL;
    cpu_clear(cpu, policy->cpus);
    cpu_clear(cpu, cpufreq_dom->map);

    if (cpus_empty(policy->cpus)) {
        cpufreq_driver->exit(policy);
        xfree(policy);
    }

    if (cpus_empty(cpufreq_dom->map)) {
        list_del(&cpufreq_dom->node);
        xfree(cpufreq_dom);
    }

    return ret;
}

int cpufreq_del_cpu(unsigned int cpu)
{
    unsigned int dom, domexist = 0;
    unsigned int hw_all = 0;
    struct list_head *pos;
    struct cpufreq_dom *cpufreq_dom = NULL;
    struct cpufreq_policy *policy;
    struct processor_performance *perf = &processor_pminfo[cpu]->perf;

    /* to protect the case when Px was not controlled by xen */
    if (!processor_pminfo[cpu]      ||
        !(perf->init & XEN_PX_INIT) ||
        !cpu_online(cpu))
        return -EINVAL;

    if (!cpufreq_cpu_policy[cpu])
        return 0;

    if (perf->shared_type == CPUFREQ_SHARED_TYPE_HW)
        hw_all = 1;

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

    /* for HW_ALL, stop gov for each core of the _PSD domain */
    /* for SW_ALL & SW_ANY, stop gov for the 1st core of the _PSD domain */
    if (hw_all ||
        (cpus_weight(cpufreq_dom->map) == perf->domain_info.num_processors))
        __cpufreq_governor(policy, CPUFREQ_GOV_STOP);

    cpufreq_statistic_exit(cpu);
    cpufreq_cpu_policy[cpu] = NULL;
    cpu_clear(cpu, policy->cpus);
    cpu_clear(cpu, cpufreq_dom->map);

    if (cpus_empty(policy->cpus)) {
        cpufreq_driver->exit(policy);
        xfree(policy);
    }

    /* for the last cpu of the domain, clean room */
    /* It's safe here to free freq_table, drv_data and policy */
    if (cpus_empty(cpufreq_dom->map)) {
        list_del(&cpufreq_dom->node);
        xfree(cpufreq_dom);
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
        /* space_id check */
        if (dom0_px_info->control_register.space_id != 
            dom0_px_info->status_register.space_id)
        {
            ret = -EINVAL;
            goto out;
        }

#ifdef CONFIG_IA64
        /* for IA64, currently it only supports FFH */
        if (dom0_px_info->control_register.space_id !=
            ACPI_ADR_SPACE_FIXED_HARDWARE)
        {
            ret = -EINVAL;
            goto out;
        }
#endif

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
        /* capability check */
        if (dom0_px_info->state_count <= 1)
        {
            ret = -EINVAL;
            goto out;
        }

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
#ifdef CONFIG_X86
        /* for X86, check domain coordination */
        /* for IA64, _PSD is optional for current IA64 cpufreq algorithm */
        if (dom0_px_info->shared_type != CPUFREQ_SHARED_TYPE_ALL &&
            dom0_px_info->shared_type != CPUFREQ_SHARED_TYPE_ANY &&
            dom0_px_info->shared_type != CPUFREQ_SHARED_TYPE_HW)
        {
            ret = -EINVAL;
            goto out;
        }
#endif

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

static void cpufreq_cmdline_common_para(struct cpufreq_policy *new_policy)
{
    if (usr_max_freq)
        new_policy->max = usr_max_freq;
    if (usr_min_freq)
        new_policy->min = usr_min_freq;
}

static int __init cpufreq_handle_common_option(const char *name, const char *val)
{
    if (!strcmp(name, "maxfreq") && val) {
        usr_max_freq = simple_strtoul(val, NULL, 0);
        return 1;
    }

    if (!strcmp(name, "minfreq") && val) {
        usr_min_freq = simple_strtoul(val, NULL, 0);
        return 1;
    }

    return 0;
}

void __init cpufreq_cmdline_parse(char *str)
{
    static struct cpufreq_governor *__initdata cpufreq_governors[] =
    {
        &cpufreq_gov_userspace,
        &cpufreq_gov_dbs,
        &cpufreq_gov_performance,
        &cpufreq_gov_powersave
    };
    unsigned int gov_index = 0;

    do {
        char *val, *end = strchr(str, ',');
        unsigned int i;

        if (end)
            *end++ = '\0';
        val = strchr(str, '=');
        if (val)
            *val++ = '\0';

        if (!cpufreq_opt_governor) {
            if (!val) {
                for (i = 0; i < ARRAY_SIZE(cpufreq_governors); ++i) {
                    if (!strcmp(str, cpufreq_governors[i]->name)) {
                        cpufreq_opt_governor = cpufreq_governors[i];
                        gov_index = i;
                        str = NULL;
                        break;
                    }
                }
            } else {
                cpufreq_opt_governor = CPUFREQ_DEFAULT_GOVERNOR;
            }
        }

        if (str && !cpufreq_handle_common_option(str, val) &&
            cpufreq_governors[gov_index]->handle_option)
            cpufreq_governors[gov_index]->handle_option(str, val);

        str = end;
    } while (str);
}
