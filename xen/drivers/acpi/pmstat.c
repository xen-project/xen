/*****************************************************************************
#  pmstat.c - Power Management statistic information (Px/Cx/Tx, etc.)
#
#  Copyright (c) 2008, Liu Jinsong <jinsong.liu@intel.com>
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License as published by the Free 
# Software Foundation; either version 2 of the License, or (at your option) 
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; If not, see <http://www.gnu.org/licenses/>.
#
# The full GNU General Public License is included in this distribution in the
# file called LICENSE.
#
*****************************************************************************/

#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/irq.h>
#include <xen/iocap.h>
#include <xen/compat.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <public/xen.h>
#include <xen/cpumask.h>
#include <asm/processor.h>
#include <xen/percpu.h>
#include <xen/domain.h>
#include <xen/acpi.h>

#include <public/sysctl.h>
#include <acpi/cpufreq/cpufreq.h>
#include <xen/pmstat.h>

DEFINE_PER_CPU_READ_MOSTLY(struct pm_px *, cpufreq_statistic_data);

/*
 * Get PM statistic info
 */
int do_get_pm_info(struct xen_sysctl_get_pmstat *op)
{
    int ret = 0;
    const struct processor_pminfo *pmpt;

    if ( !op || (op->cpuid >= nr_cpu_ids) || !cpu_online(op->cpuid) )
        return -EINVAL;
    pmpt = processor_pminfo[op->cpuid];

    switch ( op->type & PMSTAT_CATEGORY_MASK )
    {
    case PMSTAT_CX:
        if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_CX) )
            return -ENODEV;
        break;
    case PMSTAT_PX:
        if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_PX) )
            return -ENODEV;
        if ( !cpufreq_driver )
            return -ENODEV;
        if ( !pmpt || !(pmpt->perf.init & XEN_PX_INIT) )
            return -EINVAL;
        break;
    default:
        return -ENODEV;
    }

    switch ( op->type )
    {
    case PMSTAT_get_max_px:
    {
        op->u.getpx.total = pmpt->perf.state_count;
        break;
    }

    case PMSTAT_get_pxstat:
    {
        uint32_t ct;
        struct pm_px *pxpt;
        spinlock_t *cpufreq_statistic_lock = 
                   &per_cpu(cpufreq_statistic_lock, op->cpuid);

        spin_lock(cpufreq_statistic_lock);

        pxpt = per_cpu(cpufreq_statistic_data, op->cpuid);
        if ( !pxpt || !pxpt->u.pt || !pxpt->u.trans_pt )
        {
            spin_unlock(cpufreq_statistic_lock);
            return -ENODATA;
        }

        pxpt->u.usable = pmpt->perf.state_count - pmpt->perf.platform_limit;

        cpufreq_residency_update(op->cpuid, pxpt->u.cur);

        ct = pmpt->perf.state_count;
        if ( copy_to_guest(op->u.getpx.trans_pt, pxpt->u.trans_pt, ct*ct) )
        {
            spin_unlock(cpufreq_statistic_lock);
            ret = -EFAULT;
            break;
        }

        if ( copy_to_guest(op->u.getpx.pt, pxpt->u.pt, ct) )
        {
            spin_unlock(cpufreq_statistic_lock);
            ret = -EFAULT;
            break;
        }

        op->u.getpx.total = pxpt->u.total;
        op->u.getpx.usable = pxpt->u.usable;
        op->u.getpx.last = pxpt->u.last;
        op->u.getpx.cur = pxpt->u.cur;

        spin_unlock(cpufreq_statistic_lock);

        break;
    }

    case PMSTAT_reset_pxstat:
    {
        cpufreq_statistic_reset(op->cpuid);
        break;
    }

    case PMSTAT_get_max_cx:
    {
        op->u.getcx.nr = pmstat_get_cx_nr(op->cpuid);
        ret = 0;
        break;
    }

    case PMSTAT_get_cxstat:
    {
        ret = pmstat_get_cx_stat(op->cpuid, &op->u.getcx);
        break;
    }

    case PMSTAT_reset_cxstat:
    {
        ret = pmstat_reset_cx_stat(op->cpuid);
        break;
    }

    default:
        printk("not defined sub-hypercall @ do_get_pm_info\n");
        ret = -ENOSYS;
        break;
    }

    return ret;
}

/*
 * 1. Get PM parameter
 * 2. Provide user PM control
 */
static int read_scaling_available_governors(char *scaling_available_governors,
                                            unsigned int size)
{
    unsigned int i = 0;
    struct cpufreq_governor *t;

    if ( !scaling_available_governors )
        return -EINVAL;

    list_for_each_entry(t, &cpufreq_governor_list, governor_list)
    {
        i += scnprintf(&scaling_available_governors[i],
                       CPUFREQ_NAME_LEN, "%s ", t->name);
        if ( i > size )
            return -EINVAL;
    }
    scaling_available_governors[i-1] = '\0';

    return 0;
}

static int get_cpufreq_para(struct xen_sysctl_pm_op *op)
{
    uint32_t ret = 0;
    const struct processor_pminfo *pmpt;
    struct cpufreq_policy *policy;
    uint32_t gov_num = 0;
    uint32_t *affected_cpus;
    uint32_t *scaling_available_frequencies;
    char     *scaling_available_governors;
    struct list_head *pos;
    uint32_t cpu, i, j = 0;

    pmpt = processor_pminfo[op->cpuid];
    policy = per_cpu(cpufreq_cpu_policy, op->cpuid);

    if ( !pmpt || !pmpt->perf.states ||
         !policy || !policy->governor )
        return -EINVAL;

    list_for_each(pos, &cpufreq_governor_list)
        gov_num++;

    if ( (op->u.get_para.cpu_num  != cpumask_weight(policy->cpus)) ||
         (op->u.get_para.freq_num != pmpt->perf.state_count)    ||
         (op->u.get_para.gov_num  != gov_num) )
    {
        op->u.get_para.cpu_num =  cpumask_weight(policy->cpus);
        op->u.get_para.freq_num = pmpt->perf.state_count;
        op->u.get_para.gov_num  = gov_num;
        return -EAGAIN;
    }

    if ( !(affected_cpus = xzalloc_array(uint32_t, op->u.get_para.cpu_num)) )
        return -ENOMEM;
    for_each_cpu(cpu, policy->cpus)
        affected_cpus[j++] = cpu;
    ret = copy_to_guest(op->u.get_para.affected_cpus,
                       affected_cpus, op->u.get_para.cpu_num);
    xfree(affected_cpus);
    if ( ret )
        return ret;

    if ( !(scaling_available_frequencies =
           xzalloc_array(uint32_t, op->u.get_para.freq_num)) )
        return -ENOMEM;
    for ( i = 0; i < op->u.get_para.freq_num; i++ )
        scaling_available_frequencies[i] =
                        pmpt->perf.states[i].core_frequency * 1000;
    ret = copy_to_guest(op->u.get_para.scaling_available_frequencies,
                   scaling_available_frequencies, op->u.get_para.freq_num);
    xfree(scaling_available_frequencies);
    if ( ret )
        return ret;

    if ( !(scaling_available_governors =
           xzalloc_array(char, gov_num * CPUFREQ_NAME_LEN)) )
        return -ENOMEM;
    if ( (ret = read_scaling_available_governors(scaling_available_governors,
                gov_num * CPUFREQ_NAME_LEN * sizeof(char))) )
    {
        xfree(scaling_available_governors);
        return ret;
    }
    ret = copy_to_guest(op->u.get_para.scaling_available_governors,
                scaling_available_governors, gov_num * CPUFREQ_NAME_LEN);
    xfree(scaling_available_governors);
    if ( ret )
        return ret;

    op->u.get_para.cpuinfo_cur_freq =
        cpufreq_driver->get ? cpufreq_driver->get(op->cpuid) : policy->cur;
    op->u.get_para.cpuinfo_max_freq = policy->cpuinfo.max_freq;
    op->u.get_para.cpuinfo_min_freq = policy->cpuinfo.min_freq;
    op->u.get_para.scaling_cur_freq = policy->cur;
    op->u.get_para.scaling_max_freq = policy->max;
    op->u.get_para.scaling_min_freq = policy->min;

    if ( cpufreq_driver->name[0] )
        strlcpy(op->u.get_para.scaling_driver, 
            cpufreq_driver->name, CPUFREQ_NAME_LEN);
    else
        strlcpy(op->u.get_para.scaling_driver, "Unknown", CPUFREQ_NAME_LEN);

    if ( policy->governor->name[0] )
        strlcpy(op->u.get_para.scaling_governor, 
            policy->governor->name, CPUFREQ_NAME_LEN);
    else
        strlcpy(op->u.get_para.scaling_governor, "Unknown", CPUFREQ_NAME_LEN);

    /* governor specific para */
    if ( !strnicmp(op->u.get_para.scaling_governor, 
                   "userspace", CPUFREQ_NAME_LEN) )
    {
        op->u.get_para.u.userspace.scaling_setspeed = policy->cur;
    }

    if ( !strnicmp(op->u.get_para.scaling_governor, 
                   "ondemand", CPUFREQ_NAME_LEN) )
    {
        ret = get_cpufreq_ondemand_para(
            &op->u.get_para.u.ondemand.sampling_rate_max,
            &op->u.get_para.u.ondemand.sampling_rate_min,
            &op->u.get_para.u.ondemand.sampling_rate,
            &op->u.get_para.u.ondemand.up_threshold);
    }
    op->u.get_para.turbo_enabled = cpufreq_get_turbo_status(op->cpuid);

    return ret;
}

static int set_cpufreq_gov(struct xen_sysctl_pm_op *op)
{
    struct cpufreq_policy new_policy, *old_policy;

    old_policy = per_cpu(cpufreq_cpu_policy, op->cpuid);
    if ( !old_policy )
        return -EINVAL;

    memcpy(&new_policy, old_policy, sizeof(struct cpufreq_policy));

    new_policy.governor = __find_governor(op->u.set_gov.scaling_governor);
    if (new_policy.governor == NULL)
        return -EINVAL;

    return __cpufreq_set_policy(old_policy, &new_policy);
}

static int set_cpufreq_para(struct xen_sysctl_pm_op *op)
{
    int ret = 0;
    struct cpufreq_policy *policy;

    policy = per_cpu(cpufreq_cpu_policy, op->cpuid);

    if ( !policy || !policy->governor )
        return -EINVAL;

    switch(op->u.set_para.ctrl_type)
    {
    case SCALING_MAX_FREQ:
    {
        struct cpufreq_policy new_policy;

        memcpy(&new_policy, policy, sizeof(struct cpufreq_policy));
        new_policy.max = op->u.set_para.ctrl_value;
        ret = __cpufreq_set_policy(policy, &new_policy);

        break;
    }

    case SCALING_MIN_FREQ:
    {
        struct cpufreq_policy new_policy;

        memcpy(&new_policy, policy, sizeof(struct cpufreq_policy));
        new_policy.min = op->u.set_para.ctrl_value;
        ret = __cpufreq_set_policy(policy, &new_policy);

        break;
    }

    case SCALING_SETSPEED:
    {
        unsigned int freq =op->u.set_para.ctrl_value;

        if ( !strnicmp(policy->governor->name,
                       "userspace", CPUFREQ_NAME_LEN) )
            ret = write_userspace_scaling_setspeed(op->cpuid, freq);
        else
            ret = -EINVAL;

        break;
    }

    case SAMPLING_RATE:
    {
        unsigned int sampling_rate = op->u.set_para.ctrl_value;

        if ( !strnicmp(policy->governor->name,
                       "ondemand", CPUFREQ_NAME_LEN) )
            ret = write_ondemand_sampling_rate(sampling_rate);
        else
            ret = -EINVAL;

        break;
    }

    case UP_THRESHOLD:
    {
        unsigned int up_threshold = op->u.set_para.ctrl_value;

        if ( !strnicmp(policy->governor->name,
                       "ondemand", CPUFREQ_NAME_LEN) )
            ret = write_ondemand_up_threshold(up_threshold);
        else
            ret = -EINVAL;

        break;
    }

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

int do_pm_op(struct xen_sysctl_pm_op *op)
{
    int ret = 0;
    const struct processor_pminfo *pmpt;

    if ( !op || op->cpuid >= nr_cpu_ids || !cpu_online(op->cpuid) )
        return -EINVAL;
    pmpt = processor_pminfo[op->cpuid];

    switch ( op->cmd & PM_PARA_CATEGORY_MASK )
    {
    case CPUFREQ_PARA:
        if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_PX) )
            return -ENODEV;
        if ( !pmpt || !(pmpt->perf.init & XEN_PX_INIT) )
            return -EINVAL;
        break;
    }

    switch ( op->cmd )
    {
    case GET_CPUFREQ_PARA:
    {
        ret = get_cpufreq_para(op);
        break;
    }

    case SET_CPUFREQ_GOV:
    {
        ret = set_cpufreq_gov(op);
        break;
    }

    case SET_CPUFREQ_PARA:
    {
        ret = set_cpufreq_para(op);
        break;
    }

    case GET_CPUFREQ_AVGFREQ:
    {
        op->u.get_avgfreq = cpufreq_driver_getavg(op->cpuid, USR_GETAVG);
        break;
    }

    case XEN_SYSCTL_pm_op_set_sched_opt_smt:
    {
        uint32_t saved_value;

        saved_value = sched_smt_power_savings;
        sched_smt_power_savings = !!op->u.set_sched_opt_smt;
        op->u.set_sched_opt_smt = saved_value;

        break;
    }

    case XEN_SYSCTL_pm_op_set_vcpu_migration_delay:
    {
        set_vcpu_migration_delay(op->u.set_vcpu_migration_delay);
        break;
    }

    case XEN_SYSCTL_pm_op_get_vcpu_migration_delay:
    {
        op->u.get_vcpu_migration_delay = get_vcpu_migration_delay();
        break;
    }

    case XEN_SYSCTL_pm_op_get_max_cstate:
    {
        op->u.get_max_cstate = acpi_get_cstate_limit();
        break;
    }

    case XEN_SYSCTL_pm_op_set_max_cstate:
    {
        acpi_set_cstate_limit(op->u.set_max_cstate);
        break;
    }

    case XEN_SYSCTL_pm_op_enable_turbo:
    {
        ret = cpufreq_update_turbo(op->cpuid, CPUFREQ_TURBO_ENABLED);
        break;
    }

    case XEN_SYSCTL_pm_op_disable_turbo:
    {
        ret = cpufreq_update_turbo(op->cpuid, CPUFREQ_TURBO_DISABLED);
        break;
    }

    default:
        printk("not defined sub-hypercall @ do_pm_op\n");
        ret = -ENOSYS;
        break;
    }

    return ret;
}

int acpi_set_pdc_bits(u32 acpi_id, XEN_GUEST_HANDLE_PARAM(uint32) pdc)
{
    u32 bits[3];
    int ret;

    if ( copy_from_guest(bits, pdc, 2) )
        ret = -EFAULT;
    else if ( bits[0] != ACPI_PDC_REVISION_ID || !bits[1] )
        ret = -EINVAL;
    else if ( copy_from_guest_offset(bits + 2, pdc, 2, 1) )
        ret = -EFAULT;
    else
    {
        u32 mask = 0;

        if ( xen_processor_pmbits & XEN_PROCESSOR_PM_CX )
            mask |= ACPI_PDC_C_MASK | ACPI_PDC_SMP_C1PT;
        if ( xen_processor_pmbits & XEN_PROCESSOR_PM_PX )
            mask |= ACPI_PDC_P_MASK | ACPI_PDC_SMP_C1PT;
        if ( xen_processor_pmbits & XEN_PROCESSOR_PM_TX )
            mask |= ACPI_PDC_T_MASK | ACPI_PDC_SMP_C1PT;
        bits[2] &= (ACPI_PDC_C_MASK | ACPI_PDC_P_MASK | ACPI_PDC_T_MASK |
                    ACPI_PDC_SMP_C1PT) & ~mask;
        ret = arch_acpi_set_pdc_bits(acpi_id, bits, mask);
    }
    if ( !ret && __copy_to_guest_offset(pdc, 2, bits + 2, 1) )
        ret = -EFAULT;

    return ret;
}
