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

#include <assert.h>
#include "xc_private.h"
#include "xc_msr_x86.h"

#define IA32_CMT_CTR_ERROR_MASK         (0x3ull << 62)

#define EVTID_L3_OCCUPANCY             0x1
#define EVTID_TOTAL_MEM_COUNT          0x2
#define EVTID_LOCAL_MEM_COUNT          0x3

int xc_psr_cmt_attach(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_psr_cmt_op;
    domctl.domain = domid;
    domctl.u.psr_cmt_op.cmd = XEN_DOMCTL_PSR_CMT_OP_ATTACH;

    return do_domctl(xch, &domctl);
}

int xc_psr_cmt_detach(xc_interface *xch, uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_psr_cmt_op;
    domctl.domain = domid;
    domctl.u.psr_cmt_op.cmd = XEN_DOMCTL_PSR_CMT_OP_DETACH;

    return do_domctl(xch, &domctl);
}

int xc_psr_cmt_get_domain_rmid(xc_interface *xch, uint32_t domid,
                               uint32_t *rmid)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_psr_cmt_op;
    domctl.domain = domid;
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

int xc_psr_cmt_get_l3_event_mask(xc_interface *xch, uint32_t *event_mask)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_psr_cmt_op;
    sysctl.u.psr_cmt_op.cmd =
        XEN_SYSCTL_PSR_CMT_get_l3_event_mask;
    sysctl.u.psr_cmt_op.flags = 0;

    rc = xc_sysctl(xch, &sysctl);
    if ( !rc )
        *event_mask = sysctl.u.psr_cmt_op.u.data;

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

int xc_psr_cmt_get_data(xc_interface *xch, uint32_t rmid, uint32_t cpu,
                        xc_psr_cmt_type type, uint64_t *monitor_data,
                        uint64_t *tsc)
{
    xc_resource_op_t op;
    xc_resource_entry_t entries[3];
    xc_resource_entry_t *tsc_entry = NULL;
    uint32_t evtid, nr = 0;
    int rc;

    switch ( type )
    {
    case XC_PSR_CMT_L3_OCCUPANCY:
        evtid = EVTID_L3_OCCUPANCY;
        break;
    case XC_PSR_CMT_TOTAL_MEM_COUNT:
        evtid = EVTID_TOTAL_MEM_COUNT;
        break;
    case XC_PSR_CMT_LOCAL_MEM_COUNT:
        evtid = EVTID_LOCAL_MEM_COUNT;
        break;
    default:
        return -1;
    }

    entries[nr].u.cmd = XEN_RESOURCE_OP_MSR_WRITE;
    entries[nr].idx = MSR_IA32_CMT_EVTSEL;
    entries[nr].val = (uint64_t)rmid << 32 | evtid;
    entries[nr].rsvd = 0;
    nr++;

    entries[nr].u.cmd = XEN_RESOURCE_OP_MSR_READ;
    entries[nr].idx = MSR_IA32_CMT_CTR;
    entries[nr].val = 0;
    entries[nr].rsvd = 0;
    nr++;

    if ( tsc != NULL )
    {
        tsc_entry = &entries[nr];
        entries[nr].u.cmd = XEN_RESOURCE_OP_MSR_READ;
        entries[nr].idx = MSR_IA32_TSC;
        entries[nr].val = 0;
        entries[nr].rsvd = 0;
        nr++;
    }

    assert(nr <= ARRAY_SIZE(entries));

    op.cpu = cpu;
    op.nr_entries = nr;
    op.entries = entries;

    rc = xc_resource_op(xch, 1, &op);
    if ( rc < 0 )
        return rc;

    if ( op.result != nr || entries[1].val & IA32_CMT_CTR_ERROR_MASK )
        return -1;

    *monitor_data = entries[1].val;

    if ( tsc_entry != NULL )
        *tsc = tsc_entry->val;

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
int xc_psr_set_domain_data(xc_interface *xch, uint32_t domid,
                           xc_psr_type type, uint32_t target,
                           uint64_t data)
{
    DECLARE_DOMCTL;
    uint32_t cmd;

    switch ( type )
    {
    case XC_PSR_CAT_L3_CBM:
        cmd = XEN_DOMCTL_PSR_SET_L3_CBM;
        break;
    case XC_PSR_CAT_L3_CBM_CODE:
        cmd = XEN_DOMCTL_PSR_SET_L3_CODE;
        break;
    case XC_PSR_CAT_L3_CBM_DATA:
        cmd = XEN_DOMCTL_PSR_SET_L3_DATA;
        break;
    case XC_PSR_CAT_L2_CBM:
        cmd = XEN_DOMCTL_PSR_SET_L2_CBM;
        break;
    case XC_PSR_MBA_THRTL:
        cmd = XEN_DOMCTL_PSR_SET_MBA_THRTL;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_psr_alloc;
    domctl.domain = domid;
    domctl.u.psr_alloc.cmd = cmd;
    domctl.u.psr_alloc.target = target;
    domctl.u.psr_alloc.data = data;

    return do_domctl(xch, &domctl);
}

int xc_psr_get_domain_data(xc_interface *xch, uint32_t domid,
                           xc_psr_type type, uint32_t target,
                           uint64_t *data)
{
    int rc;
    DECLARE_DOMCTL;
    uint32_t cmd;

    switch ( type )
    {
    case XC_PSR_CAT_L3_CBM:
        cmd = XEN_DOMCTL_PSR_GET_L3_CBM;
        break;
    case XC_PSR_CAT_L3_CBM_CODE:
        cmd = XEN_DOMCTL_PSR_GET_L3_CODE;
        break;
    case XC_PSR_CAT_L3_CBM_DATA:
        cmd = XEN_DOMCTL_PSR_GET_L3_DATA;
        break;
    case XC_PSR_CAT_L2_CBM:
        cmd = XEN_DOMCTL_PSR_GET_L2_CBM;
        break;
    case XC_PSR_MBA_THRTL:
        cmd = XEN_DOMCTL_PSR_GET_MBA_THRTL;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_psr_alloc;
    domctl.domain = domid;
    domctl.u.psr_alloc.cmd = cmd;
    domctl.u.psr_alloc.target = target;

    rc = do_domctl(xch, &domctl);

    if ( !rc )
        *data = domctl.u.psr_alloc.data;

    return rc;
}

int xc_psr_get_hw_info(xc_interface *xch, uint32_t socket,
                       xc_psr_feat_type type, xc_psr_hw_info *hw_info)
{
    int rc = -1;
    DECLARE_SYSCTL;

    if ( !hw_info )
    {
        errno = EINVAL;
        return rc;
    }

    sysctl.cmd = XEN_SYSCTL_psr_alloc;
    sysctl.u.psr_alloc.target = socket;

    switch ( type )
    {
    case XC_PSR_CAT_L2:
    case XC_PSR_CAT_L3:
        sysctl.u.psr_alloc.cmd = (type == XC_PSR_CAT_L2) ?
                                 XEN_SYSCTL_PSR_get_l2_info :
                                 XEN_SYSCTL_PSR_get_l3_info;

        rc = xc_sysctl(xch, &sysctl);
        if ( rc )
            break;

        hw_info->cat.cos_max = sysctl.u.psr_alloc.u.cat_info.cos_max;
        hw_info->cat.cbm_len = sysctl.u.psr_alloc.u.cat_info.cbm_len;
        hw_info->cat.cdp_enabled = (type == XC_PSR_CAT_L2) ?
                                   false :
                                   (sysctl.u.psr_alloc.u.cat_info.flags &
                                    XEN_SYSCTL_PSR_CAT_L3_CDP);

        break;
    case XC_PSR_MBA:
        sysctl.u.psr_alloc.cmd = XEN_SYSCTL_PSR_get_mba_info;
        rc = xc_sysctl(xch, &sysctl);
        if ( rc )
            break;

        hw_info->mba.cos_max = sysctl.u.psr_alloc.u.mba_info.cos_max;
        hw_info->mba.thrtl_max = sysctl.u.psr_alloc.u.mba_info.thrtl_max;
        hw_info->mba.linear = sysctl.u.psr_alloc.u.mba_info.flags &
                              XEN_SYSCTL_PSR_MBA_LINEAR;

        break;
    default:
        errno = EOPNOTSUPP;
        break;
    }

    return rc;
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
