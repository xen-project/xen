/******************************************************************************
 *
 * xc_memshr.c
 *
 * Interface to low-level memory sharing functionality.
 *
 * Copyright (c) 2009 Citrix (R&D) Inc. (Grzegorz Milos)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "xc_private.h"
#include <xen/memory.h>
#include <xen/grant_table.h>

int xc_memshr_control(int xc_handle,
                      uint32_t domid,
                      int enable)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_CONTROL;
    op->enable = enable;

    return do_domctl(xc_handle, &domctl);
}

int xc_memshr_nominate_gfn(int xc_handle,
                           uint32_t domid,
                           unsigned long gfn,
                           uint64_t *handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;
    int ret;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_NOMINATE_GFN;
    op->nominate.gfn = gfn;

    ret = do_domctl(xc_handle, &domctl);
    if(!ret) *handle = op->nominate.handle; 

    return ret;
}

int xc_memshr_nominate_gref(int xc_handle,
                            uint32_t domid,
                            grant_ref_t gref,
                            uint64_t *handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;
    int ret;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_NOMINATE_GREF;
    op->nominate.grant_ref = gref;

    ret = do_domctl(xc_handle, &domctl);
    if(!ret) *handle = op->nominate.handle; 

    return ret;
}

int xc_memshr_share(int xc_handle,
                    uint64_t source_handle,
                    uint64_t client_handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = 0;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_SHARE;
    op->share.source_handle = source_handle;
    op->share.client_handle = client_handle;

    return do_domctl(xc_handle, &domctl);
}

int xc_memshr_domain_resume(int xc_handle,
                            uint32_t domid)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_RESUME;

    return do_domctl(xc_handle, &domctl);
}

int xc_memshr_debug_gfn(int xc_handle,
                        uint32_t domid,
                        unsigned long gfn)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_DEBUG_GFN;
    op->debug.gfn = gfn;

    return do_domctl(xc_handle, &domctl);
}

int xc_memshr_debug_mfn(int xc_handle,
                        uint32_t domid,
                        unsigned long mfn)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_DEBUG_MFN;
    op->debug.mfn = mfn;

    return do_domctl(xc_handle, &domctl);
}

int xc_memshr_debug_gref(int xc_handle,
                         uint32_t domid,
                         grant_ref_t gref)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_DEBUG_GREF;
    op->debug.gref = gref;

    return do_domctl(xc_handle, &domctl);
}

