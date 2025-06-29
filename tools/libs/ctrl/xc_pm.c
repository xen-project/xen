/******************************************************************************
 * xc_pm.c - Libxc API for Xen Power Management (Px/Cx/Tx, etc.) statistic
 *
 * Copyright (c) 2008, Liu Jinsong <jinsong.liu@intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdbool.h>
#include "xc_private.h"

#include <xen-tools/common-macros.h>

/*
 * Get PM statistic info
 */
int xc_pm_get_max_px(xc_interface *xch, int cpuid, int *max_px)
{
    struct xen_sysctl sysctl = {};
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_get_max_px;
    sysctl.u.get_pmstat.cpuid = cpuid;
    ret = xc_sysctl(xch, &sysctl);
    if ( ret )
        return ret;

    *max_px = sysctl.u.get_pmstat.u.getpx.total;
    return ret;
}

int xc_pm_get_pxstat(xc_interface *xch, int cpuid, struct xc_px_stat *pxpt)
{
    struct xen_sysctl sysctl = {};
    DECLARE_NAMED_HYPERCALL_BOUNCE(trans, pxpt->trans_pt,
                                   pxpt->total * pxpt->total * sizeof(uint64_t),
                                   XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    DECLARE_NAMED_HYPERCALL_BOUNCE(pt, pxpt->pt,
                                   pxpt->total * sizeof(struct xc_px_val),
                                   XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    int ret;

    if ( !pxpt->trans_pt || !pxpt->pt )
    {
        errno = EINVAL;
        return -1;
    }

    if ( xc_hypercall_bounce_pre(xch, trans) )
        return -1;

    if ( xc_hypercall_bounce_pre(xch, pt) )
    {
        xc_hypercall_bounce_post(xch, trans);
        return -1;
    }

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_get_pxstat;
    sysctl.u.get_pmstat.cpuid = cpuid;
    sysctl.u.get_pmstat.u.getpx.total = pxpt->total;
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getpx.trans_pt, trans);
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getpx.pt, pt);

    ret = xc_sysctl(xch, &sysctl);
    if ( ret )
    {
	xc_hypercall_bounce_post(xch, trans);
	xc_hypercall_bounce_post(xch, pt);
        return ret;
    }

    pxpt->total = sysctl.u.get_pmstat.u.getpx.total;
    pxpt->usable = sysctl.u.get_pmstat.u.getpx.usable;
    pxpt->last = sysctl.u.get_pmstat.u.getpx.last;
    pxpt->cur = sysctl.u.get_pmstat.u.getpx.cur;

    xc_hypercall_bounce_post(xch, trans);
    xc_hypercall_bounce_post(xch, pt);

    return ret;
}

int xc_pm_reset_pxstat(xc_interface *xch, int cpuid)
{
    struct xen_sysctl sysctl = {};

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_reset_pxstat;
    sysctl.u.get_pmstat.cpuid = cpuid;

    return xc_sysctl(xch, &sysctl);
}

int xc_pm_get_max_cx(xc_interface *xch, int cpuid, int *max_cx)
{
    struct xen_sysctl sysctl = {};
    int ret = 0;

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_get_max_cx;
    sysctl.u.get_pmstat.cpuid = cpuid;
    if ( (ret = xc_sysctl(xch, &sysctl)) != 0 )
        return ret;

    *max_cx = sysctl.u.get_pmstat.u.getcx.nr;
    return ret;
}

int xc_pm_get_cxstat(xc_interface *xch, int cpuid, struct xc_cx_stat *cxpt)
{
    struct xen_sysctl sysctl = {};
    DECLARE_NAMED_HYPERCALL_BOUNCE(triggers, cxpt->triggers,
                                   cxpt->nr * sizeof(*cxpt->triggers),
                                   XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_NAMED_HYPERCALL_BOUNCE(residencies, cxpt->residencies,
                                   cxpt->nr * sizeof(*cxpt->residencies),
                                   XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_NAMED_HYPERCALL_BOUNCE(pc, cxpt->pc,
                                   cxpt->nr_pc * sizeof(*cxpt->pc),
                                   XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_NAMED_HYPERCALL_BOUNCE(cc, cxpt->cc,
                                   cxpt->nr_cc * sizeof(*cxpt->cc),
                                   XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret = -1;

    if ( xc_hypercall_bounce_pre(xch, triggers) )
        goto unlock_0;
    if ( xc_hypercall_bounce_pre(xch, residencies) )
        goto unlock_1;
    if ( xc_hypercall_bounce_pre(xch, pc) )
        goto unlock_2;
    if ( xc_hypercall_bounce_pre(xch, cc) )
        goto unlock_3;

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_get_cxstat;
    sysctl.u.get_pmstat.cpuid = cpuid;
    sysctl.u.get_pmstat.u.getcx.nr = cxpt->nr;
    sysctl.u.get_pmstat.u.getcx.nr_pc = cxpt->nr_pc;
    sysctl.u.get_pmstat.u.getcx.nr_cc = cxpt->nr_cc;
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getcx.triggers, triggers);
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getcx.residencies, residencies);
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getcx.pc, pc);
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getcx.cc, cc);

    if ( (ret = xc_sysctl(xch, &sysctl)) )
        goto unlock_4;

    cxpt->nr = sysctl.u.get_pmstat.u.getcx.nr;
    cxpt->last = sysctl.u.get_pmstat.u.getcx.last;
    cxpt->idle_time = sysctl.u.get_pmstat.u.getcx.idle_time;
    cxpt->nr_pc = sysctl.u.get_pmstat.u.getcx.nr_pc;
    cxpt->nr_cc = sysctl.u.get_pmstat.u.getcx.nr_cc;

unlock_4:
    xc_hypercall_bounce_post(xch, cc);
unlock_3:
    xc_hypercall_bounce_post(xch, pc);
unlock_2:
    xc_hypercall_bounce_post(xch, residencies);
unlock_1:
    xc_hypercall_bounce_post(xch, triggers);
unlock_0:
    return ret;
}

int xc_pm_reset_cxstat(xc_interface *xch, int cpuid)
{
    struct xen_sysctl sysctl = {};

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_reset_cxstat;
    sysctl.u.get_pmstat.cpuid = cpuid;

    return xc_sysctl(xch, &sysctl);
}


/*
 * 1. Get PM parameter
 * 2. Provide user PM control
 */
int xc_get_cpufreq_para(xc_interface *xch, int cpuid,
                        struct xc_get_cpufreq_para *user_para)
{
    struct xen_sysctl sysctl = {};
    int ret = 0;
    struct xen_get_cpufreq_para *sys_para = &sysctl.u.pm_op.u.get_para;
    DECLARE_NAMED_HYPERCALL_BOUNCE(affected_cpus,
			 user_para->affected_cpus,
			 user_para->cpu_num * sizeof(uint32_t), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    DECLARE_NAMED_HYPERCALL_BOUNCE(scaling_available_frequencies,
			 user_para->scaling_available_frequencies,
			 user_para->freq_num * sizeof(uint32_t), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    DECLARE_NAMED_HYPERCALL_BOUNCE(scaling_available_governors,
			 user_para->scaling_available_governors,
			 user_para->gov_num * CPUFREQ_NAME_LEN * sizeof(char), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    bool has_num = user_para->cpu_num && user_para->freq_num;

    if ( has_num )
    {
        if ( (!user_para->affected_cpus)                    ||
             (!user_para->scaling_available_frequencies)    ||
             (user_para->gov_num && !user_para->scaling_available_governors) )
        {
            errno = EINVAL;
            return -1;
        }
        ret = xc_hypercall_bounce_pre(xch, affected_cpus);
        if ( ret )
            return ret;
        ret = xc_hypercall_bounce_pre(xch, scaling_available_frequencies);
        if ( ret )
            goto unlock_2;
        if ( user_para->gov_num )
            ret = xc_hypercall_bounce_pre(xch, scaling_available_governors);
        if ( ret )
            goto unlock_3;

        set_xen_guest_handle(sys_para->affected_cpus, affected_cpus);
        set_xen_guest_handle(sys_para->scaling_available_frequencies, scaling_available_frequencies);
        if ( user_para->gov_num )
            set_xen_guest_handle(sys_para->scaling_available_governors,
                                 scaling_available_governors);
    }

    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = GET_CPUFREQ_PARA;
    sysctl.u.pm_op.cpuid = cpuid;
    sys_para->cpu_num  = user_para->cpu_num;
    sys_para->freq_num = user_para->freq_num;
    sys_para->gov_num  = user_para->gov_num;

    ret = xc_sysctl(xch, &sysctl);
    if ( ret )
    {
        if ( errno == EAGAIN )
        {
            user_para->cpu_num  = sys_para->cpu_num;
            user_para->freq_num = sys_para->freq_num;
            user_para->gov_num  = sys_para->gov_num;
        }

        if ( has_num )
            goto unlock_4;
        return ret;
    }
    else
    {
        user_para->cpuinfo_cur_freq = sys_para->cpuinfo_cur_freq;
        user_para->cpuinfo_max_freq = sys_para->cpuinfo_max_freq;
        user_para->cpuinfo_min_freq = sys_para->cpuinfo_min_freq;
        user_para->turbo_enabled    = sys_para->turbo_enabled;

        memcpy(user_para->scaling_driver,
                sys_para->scaling_driver, CPUFREQ_NAME_LEN);

        /*
         * Copy to user_para no matter what cpufreq driver/governor.
         *
         * First sanity check layout of the union subject to memcpy() below.
         */
        BUILD_BUG_ON(sizeof(user_para->u) != sizeof(sys_para->u));

#define CHK_FIELD(fld) \
        BUILD_BUG_ON(offsetof(typeof(user_para->u), fld) != \
                     offsetof(typeof(sys_para->u),  fld))

        CHK_FIELD(s.scaling_cur_freq);
        CHK_FIELD(s.scaling_governor);
        CHK_FIELD(s.scaling_max_freq);
        CHK_FIELD(s.scaling_min_freq);
        CHK_FIELD(s.u.userspace);
        CHK_FIELD(s.u.ondemand);
        CHK_FIELD(cppc_para);

#undef CHK_FIELD

        memcpy(&user_para->u, &sys_para->u, sizeof(sys_para->u));
    }

unlock_4:
    xc_hypercall_bounce_post(xch, scaling_available_governors);
unlock_3:
    xc_hypercall_bounce_post(xch, scaling_available_frequencies);
unlock_2:
    xc_hypercall_bounce_post(xch, affected_cpus);

    return ret;
}

int xc_set_cpufreq_gov(xc_interface *xch, int cpuid, char *govname)
{
    struct xen_sysctl sysctl = {};
    char *scaling_governor = sysctl.u.pm_op.u.set_gov.scaling_governor;

    if ( !xch || !govname )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = SET_CPUFREQ_GOV;
    sysctl.u.pm_op.cpuid = cpuid;
    strncpy(scaling_governor, govname, CPUFREQ_NAME_LEN - 1);
    scaling_governor[CPUFREQ_NAME_LEN - 1] = '\0';

    return xc_sysctl(xch, &sysctl);
}

int xc_set_cpufreq_para(xc_interface *xch, int cpuid, 
                        int ctrl_type, int ctrl_value)
{
    struct xen_sysctl sysctl = {};

    if ( !xch )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = SET_CPUFREQ_PARA;
    sysctl.u.pm_op.cpuid = cpuid;
    sysctl.u.pm_op.u.set_para.ctrl_type = ctrl_type;
    sysctl.u.pm_op.u.set_para.ctrl_value = ctrl_value;

    return xc_sysctl(xch, &sysctl);
}

int xc_set_cpufreq_cppc(xc_interface *xch, int cpuid,
                        xc_set_cppc_para_t *set_cppc)
{
    struct xen_sysctl sysctl = {};
    int ret;

    if ( !xch )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = SET_CPUFREQ_CPPC;
    sysctl.u.pm_op.cpuid = cpuid;
    sysctl.u.pm_op.u.set_cppc = *set_cppc;

    ret = xc_sysctl(xch, &sysctl);

    *set_cppc = sysctl.u.pm_op.u.set_cppc;

    return ret;
}

int xc_get_cpufreq_avgfreq(xc_interface *xch, int cpuid, int *avg_freq)
{
    int ret = 0;
    struct xen_sysctl sysctl = {};

    if ( !xch || !avg_freq )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = GET_CPUFREQ_AVGFREQ;
    sysctl.u.pm_op.cpuid = cpuid;
    ret = xc_sysctl(xch, &sysctl);

    *avg_freq = sysctl.u.pm_op.u.get_avgfreq;

    return ret;
}

/* value:   0 - disable sched_smt_power_savings 
            1 - enable sched_smt_power_savings
 */
int xc_set_sched_opt_smt(xc_interface *xch, uint32_t value)
{
   int rc;
   struct xen_sysctl sysctl = {};

   sysctl.cmd = XEN_SYSCTL_pm_op;
   sysctl.u.pm_op.cmd = XEN_SYSCTL_pm_op_set_sched_opt_smt;
   sysctl.u.pm_op.cpuid = 0;
   sysctl.u.pm_op.u.set_sched_opt_smt = value;
   rc = do_sysctl(xch, &sysctl);

   return rc;
}

static int get_max_cstate(xc_interface *xch, uint32_t *value, uint32_t type)
{
    int rc;
    struct xen_sysctl sysctl = {};

    if ( !xch || !value )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = XEN_SYSCTL_pm_op_get_max_cstate;
    sysctl.u.pm_op.cpuid = type;
    sysctl.u.pm_op.u.get_max_cstate = 0;
    rc = do_sysctl(xch, &sysctl);
    *value = sysctl.u.pm_op.u.get_max_cstate;

    return rc;
}

int xc_get_cpuidle_max_cstate(xc_interface *xch, uint32_t *value)
{
    return get_max_cstate(xch, value, 0);
}

int xc_get_cpuidle_max_csubstate(xc_interface *xch, uint32_t *value)
{
    return get_max_cstate(xch, value, 1);
}

static int set_max_cstate(xc_interface *xch, uint32_t value, uint32_t type)
{
    struct xen_sysctl sysctl = {};

    if ( !xch )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = XEN_SYSCTL_pm_op_set_max_cstate;
    sysctl.u.pm_op.cpuid = type;
    sysctl.u.pm_op.u.set_max_cstate = value;

    return do_sysctl(xch, &sysctl);
}

int xc_set_cpuidle_max_cstate(xc_interface *xch, uint32_t value)
{
    return set_max_cstate(xch, value, 0);
}

int xc_set_cpuidle_max_csubstate(xc_interface *xch, uint32_t value)
{
    return set_max_cstate(xch, value, 1);
}

int xc_enable_turbo(xc_interface *xch, int cpuid)
{
    struct xen_sysctl sysctl = {};

    if ( !xch )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = XEN_SYSCTL_pm_op_enable_turbo;
    sysctl.u.pm_op.cpuid = cpuid;
    return do_sysctl(xch, &sysctl);
}

int xc_disable_turbo(xc_interface *xch, int cpuid)
{
    struct xen_sysctl sysctl = {};

    if ( !xch )
    {
        errno = EINVAL;
        return -1;
    }
    sysctl.cmd = XEN_SYSCTL_pm_op;
    sysctl.u.pm_op.cmd = XEN_SYSCTL_pm_op_disable_turbo;
    sysctl.u.pm_op.cpuid = cpuid;
    return do_sysctl(xch, &sysctl);
}
