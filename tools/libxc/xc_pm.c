/******************************************************************************
 * xc_pm.c - Libxc API for Xen Power Management (Px/Cx/Tx, etc.) statistic
 *
 * Copyright (c) 2008, Liu Jinsong <jinsong.liu@intel.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "xc_private.h"

int xc_pm_get_max_px(int xc_handle, int cpuid, int *max_px)
{
    DECLARE_SYSCTL;
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_get_max_px;
    sysctl.u.get_pmstat.cpuid = cpuid;
    ret = xc_sysctl(xc_handle, &sysctl);
    if ( ret )
        return ret;

    *max_px = sysctl.u.get_pmstat.u.getpx.total;
    return ret;
}

int xc_pm_get_pxstat(int xc_handle, int cpuid, struct xc_px_stat *pxpt)
{
    DECLARE_SYSCTL;
    int max_px, ret;

    if ( !pxpt || !(pxpt->trans_pt) || !(pxpt->pt) )
        return -EINVAL;

    if ( (ret = xc_pm_get_max_px(xc_handle, cpuid, &max_px)) != 0)
        return ret;

    if ( (ret = lock_pages(pxpt->trans_pt, 
        max_px * max_px * sizeof(uint64_t))) != 0 )
        return ret;

    if ( (ret = lock_pages(pxpt->pt, 
        max_px * sizeof(struct xc_px_val))) != 0 )
    {
        unlock_pages(pxpt->trans_pt, max_px * max_px * sizeof(uint64_t));
        return ret;
    }

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_get_pxstat;
    sysctl.u.get_pmstat.cpuid = cpuid;
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getpx.trans_pt, pxpt->trans_pt);
    set_xen_guest_handle(sysctl.u.get_pmstat.u.getpx.pt, 
                        (pm_px_val_t *)pxpt->pt);

    ret = xc_sysctl(xc_handle, &sysctl);
    if ( ret )
    {
        unlock_pages(pxpt->trans_pt, max_px * max_px * sizeof(uint64_t));
        unlock_pages(pxpt->pt, max_px * sizeof(struct xc_px_val));
        return ret;
    }

    pxpt->total = sysctl.u.get_pmstat.u.getpx.total;
    pxpt->usable = sysctl.u.get_pmstat.u.getpx.usable;
    pxpt->last = sysctl.u.get_pmstat.u.getpx.last;
    pxpt->cur = sysctl.u.get_pmstat.u.getpx.cur;

    unlock_pages(pxpt->trans_pt, max_px * max_px * sizeof(uint64_t));
    unlock_pages(pxpt->pt, max_px * sizeof(struct xc_px_val));

    return ret;
}

int xc_pm_reset_pxstat(int xc_handle, int cpuid)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_get_pmstat;
    sysctl.u.get_pmstat.type = PMSTAT_reset_pxstat;
    sysctl.u.get_pmstat.cpuid = cpuid;

    return xc_sysctl(xc_handle, &sysctl);
}
