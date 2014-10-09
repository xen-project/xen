/*
 * xc_psr.c
 *
 * platform shared resource related API functions.
 *
 * Copyright (C) 2014      Intel Corporation
 * Author Dongxiao Xu <dongxiao.xu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "xc_private.h"
#include "xc_msr_x86.h"

#define IA32_CMT_CTR_ERROR_MASK         (0x3ull << 62)

#define EVTID_L3_OCCUPANCY             0x1

int xc_psr_cmt_attach(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_psr_cmt_op;
    domctl.domain = (domid_t)domid;
    domctl.u.psr_cmt_op.cmd = XEN_DOMCTL_PSR_CMT_OP_ATTACH;

    return do_domctl(xch, &domctl);
}

int xc_psr_cmt_detach(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_psr_cmt_op;
    domctl.domain = (domid_t)domid;
    domctl.u.psr_cmt_op.cmd = XEN_DOMCTL_PSR_CMT_OP_DETACH;

    return do_domctl(xch, &domctl);
}

int xc_psr_cmt_get_domain_rmid(xc_interface *xch, uint32_t domid,
                                    uint32_t *rmid)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_psr_cmt_op;
    domctl.domain = (domid_t)domid;
    domctl.u.psr_cmt_op.cmd = XEN_DOMCTL_PSR_CMT_OP_QUERY_RMID;

    rc = do_domctl(xch, &domctl);

    if ( !rc )
        *rmid = domctl.u.psr_cmt_op.data;

    return rc;
}

int xc_psr_cmt_get_total_rmid(xc_interface *xch, uint32_t *total_rmid)
{
    static int val = 0;
    int rc;
    DECLARE_SYSCTL;

    if ( val )
    {
        *total_rmid = val;
        return 0;
    }

    sysctl.cmd = XEN_SYSCTL_psr_cmt_op;
    sysctl.u.psr_cmt_op.cmd = XEN_SYSCTL_PSR_CMT_get_total_rmid;
    sysctl.u.psr_cmt_op.flags = 0;

    rc = xc_sysctl(xch, &sysctl);
    if ( !rc )
        val = *total_rmid = sysctl.u.psr_cmt_op.u.data;

    return rc;
}

int xc_psr_cmt_get_l3_upscaling_factor(xc_interface *xch,
                                            uint32_t *upscaling_factor)
{
    static int val = 0;
    int rc;
    DECLARE_SYSCTL;

    if ( val )
    {
        *upscaling_factor = val;
        return 0;
    }

    sysctl.cmd = XEN_SYSCTL_psr_cmt_op;
    sysctl.u.psr_cmt_op.cmd =
        XEN_SYSCTL_PSR_CMT_get_l3_upscaling_factor;
    sysctl.u.psr_cmt_op.flags = 0;

    rc = xc_sysctl(xch, &sysctl);
    if ( !rc )
        val = *upscaling_factor = sysctl.u.psr_cmt_op.u.data;

    return rc;
}

int xc_psr_cmt_get_l3_cache_size(xc_interface *xch, uint32_t cpu,
                                      uint32_t *l3_cache_size)
{
    static int val = 0;
    int rc;
    DECLARE_SYSCTL;

    if ( val )
    {
        *l3_cache_size = val;
        return 0;
    }

    sysctl.cmd = XEN_SYSCTL_psr_cmt_op;
    sysctl.u.psr_cmt_op.cmd =
        XEN_SYSCTL_PSR_CMT_get_l3_cache_size;
    sysctl.u.psr_cmt_op.flags = 0;
    sysctl.u.psr_cmt_op.u.l3_cache.cpu = cpu;

    rc = xc_sysctl(xch, &sysctl);
    if ( !rc )
        val = *l3_cache_size= sysctl.u.psr_cmt_op.u.data;

    return rc;
}

int xc_psr_cmt_get_data(xc_interface *xch, uint32_t rmid,
    uint32_t cpu, xc_psr_cmt_type type, uint64_t *monitor_data)
{
    xc_resource_op_t op;
    xc_resource_entry_t entries[2];
    uint32_t evtid;
    int rc;

    switch ( type )
    {
    case XC_PSR_CMT_L3_OCCUPANCY:
        evtid = EVTID_L3_OCCUPANCY;
        break;
    default:
        return -1;
    }

    entries[0].u.cmd = XEN_RESOURCE_OP_MSR_WRITE;
    entries[0].idx = MSR_IA32_CMT_EVTSEL;
    entries[0].val = (uint64_t)rmid << 32 | evtid;
    entries[0].rsvd = 0;

    entries[1].u.cmd = XEN_RESOURCE_OP_MSR_READ;
    entries[1].idx = MSR_IA32_CMT_CTR;
    entries[1].val = 0;
    entries[1].rsvd = 0;

    op.cpu = cpu;
    op.nr_entries = 2;
    op.entries = entries;

    rc = xc_resource_op(xch, 1, &op);
    if ( rc < 0 )
        return rc;

    if ( op.result !=2 || entries[1].val & IA32_CMT_CTR_ERROR_MASK )
        return -1;

    *monitor_data = entries[1].val;

    return 0;
}

int xc_psr_cmt_enabled(xc_interface *xch)
{
    static int val = -1;
    int rc;
    DECLARE_SYSCTL;

    if ( val >= 0 )
        return val;

    sysctl.cmd = XEN_SYSCTL_psr_cmt_op;
    sysctl.u.psr_cmt_op.cmd = XEN_SYSCTL_PSR_CMT_enabled;
    sysctl.u.psr_cmt_op.flags = 0;

    rc = do_sysctl(xch, &sysctl);
    if ( !rc )
    {
        val = sysctl.u.psr_cmt_op.u.data;
        return val;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
