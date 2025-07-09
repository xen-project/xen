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

    pxpt->u.total = count;
    pxpt->u.usable = count - pmpt->perf.platform_limit;

    for ( i = 0; i < count; i++ )
        pxpt->u.pt[i].freq = pmpt->perf.states[i].core_frequency;

    pxpt->prev_state_wall = NOW();
    pxpt->prev_idle_wall = get_cpu_idle_time(cpu);

    per_cpu(cpufreq_statistic_data, cpu) = pxpt;

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
