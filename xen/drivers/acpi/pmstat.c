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
# this program; if not, write to the Free Software Foundation, Inc., 59 
# Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# The full GNU General Public License is included in this distribution in the
# file called LICENSE.
#
*****************************************************************************/

#include <xen/config.h>
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

#include <public/sysctl.h>
#include <acpi/cpufreq/cpufreq.h>

struct pm_px *__read_mostly cpufreq_statistic_data[NR_CPUS];

extern uint32_t pmstat_get_cx_nr(uint32_t cpuid);
extern int pmstat_get_cx_stat(uint32_t cpuid, struct pm_cx_stat *stat);
extern int pmstat_reset_cx_stat(uint32_t cpuid);

int do_get_pm_info(struct xen_sysctl_get_pmstat *op)
{
    int ret = 0;
    const struct processor_pminfo *pmpt = processor_pminfo[op->cpuid];

    if ( (op->cpuid >= NR_CPUS) || !cpu_online(op->cpuid) )
        return -EINVAL;

    switch ( op->type & PMSTAT_CATEGORY_MASK )
    {
    case PMSTAT_CX:
        if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_CX) )
            return -ENODEV;
        break;
    case PMSTAT_PX:
        if ( !(xen_processor_pmbits & XEN_PROCESSOR_PM_PX) )
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
        uint64_t now, ct;
        uint64_t total_idle_ns;
        uint64_t tmp_idle_ns;
        struct pm_px *pxpt = cpufreq_statistic_data[op->cpuid];

        if ( !pxpt )
            return -ENODATA;

        total_idle_ns = get_cpu_idle_time(op->cpuid);
        tmp_idle_ns = total_idle_ns - pxpt->prev_idle_wall;

        now = NOW();
        pxpt->u.usable = pmpt->perf.state_count - pmpt->perf.platform_limit;
        pxpt->u.pt[pxpt->u.cur].residency += now - pxpt->prev_state_wall;
        pxpt->u.pt[pxpt->u.cur].residency -= tmp_idle_ns;
        pxpt->prev_state_wall = now;
        pxpt->prev_idle_wall = total_idle_ns;

        ct = pmpt->perf.state_count;
        if ( copy_to_guest(op->u.getpx.trans_pt, pxpt->u.trans_pt, ct*ct) )
        {
            ret = -EFAULT;
            break;
        }

        if ( copy_to_guest(op->u.getpx.pt, pxpt->u.pt, ct) )
        {
            ret = -EFAULT;
            break;
        }

        op->u.getpx.total = pxpt->u.total;
        op->u.getpx.usable = pxpt->u.usable;
        op->u.getpx.last = pxpt->u.last;
        op->u.getpx.cur = pxpt->u.cur;

        break;
    }

    case PMSTAT_reset_pxstat:
    {
        cpufreq_statistic_reset(op->cpuid);
        break;
    }

#ifdef CONFIG_X86
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
#endif

    default:
        printk("not defined sub-hypercall @ do_get_pm_info\n");
        ret = -ENOSYS;
        break;
    }

    return ret;
}
