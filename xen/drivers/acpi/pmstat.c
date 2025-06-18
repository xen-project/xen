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

static DEFINE_PER_CPU_READ_MOSTLY(struct pm_px *, cpufreq_statistic_data);

static DEFINE_PER_CPU(spinlock_t, cpufreq_statistic_lock);

/*********************************************************************
 *                    Px STATISTIC INFO                              *
 *********************************************************************/

static void cpufreq_residency_update(unsigned int cpu, uint8_t state)
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
    const struct processor_pminfo *pmpt = processor_pminfo[cpu];
    spinlock_t *cpufreq_statistic_lock =
               &per_cpu(cpufreq_statistic_lock, cpu);

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpu);
    if ( !pxpt || !pmpt )
    {
        spin_unlock(cpufreq_statistic_lock);
        return;
    }

    pxpt->u.last = from;
    pxpt->u.cur = to;
    pxpt->u.pt[to].count++;

    cpufreq_residency_update(cpu, from);

    pxpt->u.trans_pt[from * pmpt->perf.state_count + to]++;

    spin_unlock(cpufreq_statistic_lock);
}

int cpufreq_statistic_init(unsigned int cpu)
{
    unsigned int i, count;
    struct pm_px *pxpt;
    const struct processor_pminfo *pmpt = processor_pminfo[cpu];
    spinlock_t *cpufreq_statistic_lock = &per_cpu(cpufreq_statistic_lock, cpu);

    spin_lock_init(cpufreq_statistic_lock);

    if ( !pmpt )
        return -EINVAL;

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpu);
    if ( pxpt )
    {
        spin_unlock(cpufreq_statistic_lock);
        return 0;
    }

    count = pmpt->perf.state_count;

    pxpt = xzalloc(struct pm_px);
    if ( !pxpt )
    {
        spin_unlock(cpufreq_statistic_lock);
        return -ENOMEM;
    }
    per_cpu(cpufreq_statistic_data, cpu) = pxpt;

    pxpt->u.trans_pt = xzalloc_array(uint64_t, count * count);
    if ( !pxpt->u.trans_pt )
    {
        xfree(pxpt);
        spin_unlock(cpufreq_statistic_lock);
        return -ENOMEM;
    }

    pxpt->u.pt = xzalloc_array(struct pm_px_val, count);
    if ( !pxpt->u.pt )
    {
        xfree(pxpt->u.trans_pt);
        xfree(pxpt);
        spin_unlock(cpufreq_statistic_lock);
        return -ENOMEM;
    }

    pxpt->u.total = pmpt->perf.state_count;
    pxpt->u.usable = pmpt->perf.state_count - pmpt->perf.platform_limit;

    for ( i = 0; i < pmpt->perf.state_count; i++ )
        pxpt->u.pt[i].freq = pmpt->perf.states[i].core_frequency;

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpu);

    spin_unlock(cpufreq_statistic_lock);

    return 0;
}

void cpufreq_statistic_exit(unsigned int cpu)
{
    struct pm_px *pxpt;
    spinlock_t *cpufreq_statistic_lock = &per_cpu(cpufreq_statistic_lock, cpu);

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpu);
    if ( !pxpt )
    {
        spin_unlock(cpufreq_statistic_lock);
        return;
    }

    xfree(pxpt->u.trans_pt);
    xfree(pxpt->u.pt);
    xfree(pxpt);
    per_cpu(cpufreq_statistic_data, cpu) = NULL;

    spin_unlock(cpufreq_statistic_lock);
}

static void cpufreq_statistic_reset(unsigned int cpu)
{
    unsigned int i, j, count;
    struct pm_px *pxpt;
    const struct processor_pminfo *pmpt = processor_pminfo[cpu];
    spinlock_t *cpufreq_statistic_lock = &per_cpu(cpufreq_statistic_lock, cpu);

    spin_lock(cpufreq_statistic_lock);

    pxpt = per_cpu(cpufreq_statistic_data, cpu);
    if ( !pmpt || !pxpt || !pxpt->u.pt || !pxpt->u.trans_pt )
    {
        spin_unlock(cpufreq_statistic_lock);
        return;
    }

    count = pmpt->perf.state_count;

    for ( i = 0; i < count; i++ )
    {
        pxpt->u.pt[i].residency = 0;
        pxpt->u.pt[i].count = 0;

        for ( j = 0; j < count; j++ )
            pxpt->u.trans_pt[i * count + j] = 0;
    }

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpu);

    spin_unlock(cpufreq_statistic_lock);
}

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
        if ( !cpufreq_driver.init )
            return -ENODEV;
        if ( hwp_active() )
            return -EOPNOTSUPP;
        if ( !pmpt || !(pmpt->init & XEN_PX_INIT) )
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

        /*
         * Avoid partial copying of 2-D array, whereas partial copying of a
         * simple vector (further down) is deemed okay.
         */
        ct = pmpt->perf.state_count;
        if ( ct > op->u.getpx.total )
            ct = op->u.getpx.total;
        else if ( copy_to_guest(op->u.getpx.trans_pt, pxpt->u.trans_pt, ct * ct) )
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
    uint32_t *data;
    char     *scaling_available_governors;
    struct list_head *pos;
    unsigned int cpu, i = 0;

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

    if ( !(data = xzalloc_array(uint32_t,
                                max(op->u.get_para.cpu_num,
                                    op->u.get_para.freq_num))) )
        return -ENOMEM;

    for_each_cpu(cpu, policy->cpus)
        data[i++] = cpu;
    ret = copy_to_guest(op->u.get_para.affected_cpus,
                        data, op->u.get_para.cpu_num);

    for ( i = 0; i < op->u.get_para.freq_num; i++ )
        data[i] = pmpt->perf.states[i].core_frequency * 1000;
    ret += copy_to_guest(op->u.get_para.scaling_available_frequencies,
                         data, op->u.get_para.freq_num);

    xfree(data);
    if ( ret )
        return -EFAULT;

    op->u.get_para.cpuinfo_cur_freq =
        cpufreq_driver.get ? alternative_call(cpufreq_driver.get, op->cpuid)
                           : policy->cur;
    op->u.get_para.cpuinfo_max_freq = policy->cpuinfo.max_freq;
    op->u.get_para.cpuinfo_min_freq = policy->cpuinfo.min_freq;
    op->u.get_para.turbo_enabled = cpufreq_get_turbo_status(op->cpuid);

    if ( cpufreq_driver.name[0] )
        strlcpy(op->u.get_para.scaling_driver,
            cpufreq_driver.name, CPUFREQ_NAME_LEN);
    else
        strlcpy(op->u.get_para.scaling_driver, "Unknown", CPUFREQ_NAME_LEN);

    if ( hwp_active() )
        ret = get_hwp_para(policy->cpu, &op->u.get_para.u.cppc_para);
    else
    {
        if ( !(scaling_available_governors =
               xzalloc_array(char, gov_num * CPUFREQ_NAME_LEN)) )
            return -ENOMEM;
        if ( (ret = read_scaling_available_governors(
                        scaling_available_governors,
                        (gov_num * CPUFREQ_NAME_LEN *
                         sizeof(*scaling_available_governors)))) )
        {
            xfree(scaling_available_governors);
            return ret;
        }
        ret = copy_to_guest(op->u.get_para.scaling_available_governors,
                            scaling_available_governors,
                            gov_num * CPUFREQ_NAME_LEN);
        xfree(scaling_available_governors);
        if ( ret )
            return -EFAULT;

        op->u.get_para.u.s.scaling_cur_freq = policy->cur;
        op->u.get_para.u.s.scaling_max_freq = policy->max;
        op->u.get_para.u.s.scaling_min_freq = policy->min;

        if ( policy->governor->name[0] )
            strlcpy(op->u.get_para.u.s.scaling_governor,
                policy->governor->name, CPUFREQ_NAME_LEN);
        else
            strlcpy(op->u.get_para.u.s.scaling_governor, "Unknown",
                    CPUFREQ_NAME_LEN);

        /* governor specific para */
        if ( !strncasecmp(op->u.get_para.u.s.scaling_governor,
                          "userspace", CPUFREQ_NAME_LEN) )
            op->u.get_para.u.s.u.userspace.scaling_setspeed = policy->cur;

        if ( !strncasecmp(op->u.get_para.u.s.scaling_governor,
                          "ondemand", CPUFREQ_NAME_LEN) )
            ret = get_cpufreq_ondemand_para(
                &op->u.get_para.u.s.u.ondemand.sampling_rate_max,
                &op->u.get_para.u.s.u.ondemand.sampling_rate_min,
                &op->u.get_para.u.s.u.ondemand.sampling_rate,
                &op->u.get_para.u.s.u.ondemand.up_threshold);
    }

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

    if ( hwp_active() )
        return -EOPNOTSUPP;

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

        if ( !strncasecmp(policy->governor->name,
                          "userspace", CPUFREQ_NAME_LEN) )
            ret = write_userspace_scaling_setspeed(op->cpuid, freq);
        else
            ret = -EINVAL;

        break;
    }

    case SAMPLING_RATE:
    {
        unsigned int sampling_rate = op->u.set_para.ctrl_value;

        if ( !strncasecmp(policy->governor->name,
                          "ondemand", CPUFREQ_NAME_LEN) )
            ret = write_ondemand_sampling_rate(sampling_rate);
        else
            ret = -EINVAL;

        break;
    }

    case UP_THRESHOLD:
    {
        unsigned int up_threshold = op->u.set_para.ctrl_value;

        if ( !strncasecmp(policy->governor->name,
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

static int set_cpufreq_cppc(struct xen_sysctl_pm_op *op)
{
    struct cpufreq_policy *policy = per_cpu(cpufreq_cpu_policy, op->cpuid);

    if ( !policy || !policy->governor )
        return -ENOENT;

    if ( !hwp_active() )
        return -EOPNOTSUPP;

    return set_hwp_para(policy, &op->u.set_cppc);
}

int do_pm_op(struct xen_sysctl_pm_op *op)
{
    int ret = 0;
    const struct processor_pminfo *pmpt;

    switch ( op->cmd )
    {
    case XEN_SYSCTL_pm_op_set_sched_opt_smt:
    {
        uint32_t saved_value = sched_smt_power_savings;

        if ( op->cpuid != 0 )
            return -EINVAL;
        sched_smt_power_savings = !!op->u.set_sched_opt_smt;
        op->u.set_sched_opt_smt = saved_value;
        return 0;
    }

    case XEN_SYSCTL_pm_op_get_max_cstate:
        BUILD_BUG_ON(XEN_SYSCTL_CX_UNLIMITED != UINT_MAX);
        if ( op->cpuid == 0 )
            op->u.get_max_cstate = acpi_get_cstate_limit();
        else if ( op->cpuid == 1 )
            op->u.get_max_cstate = acpi_get_csubstate_limit();
        else
            ret = -EINVAL;
        return ret;

    case XEN_SYSCTL_pm_op_set_max_cstate:
        if ( op->cpuid == 0 )
            acpi_set_cstate_limit(op->u.set_max_cstate);
        else if ( op->cpuid == 1 )
            acpi_set_csubstate_limit(op->u.set_max_cstate);
        else
            ret = -EINVAL;
        return ret;
    }

    if ( op->cpuid >= nr_cpu_ids || !cpu_online(op->cpuid) )
        return -EINVAL;
    pmpt = processor_pminfo[op->cpuid];

    switch ( op->cmd & PM_PARA_CATEGORY_MASK )
    {
    case CPUFREQ_PARA:
        if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_PX) )
            return -ENODEV;
        if ( !pmpt || !(pmpt->init & XEN_PX_INIT) )
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

    case SET_CPUFREQ_CPPC:
        ret = set_cpufreq_cppc(op);
        break;

    case GET_CPUFREQ_AVGFREQ:
    {
        op->u.get_avgfreq = cpufreq_driver_getavg(op->cpuid, USR_GETAVG);
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
