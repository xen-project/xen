/******************************************************************************
 *
 * xc_memshr.c
 *
 * Interface to low-level memory sharing functionality.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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

int xc_memshr_control(xc_interface *xch,
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
    op->u.enable = enable;

    return do_domctl(xch, &domctl);
}

int xc_memshr_nominate_gfn(xc_interface *xch,
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
    op->u.nominate.u.gfn = gfn;

    ret = do_domctl(xch, &domctl);
    if(!ret) *handle = op->u.nominate.handle; 

    return ret;
}

int xc_memshr_nominate_gref(xc_interface *xch,
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
    op->u.nominate.u.grant_ref = gref;

    ret = do_domctl(xch, &domctl);
    if(!ret) *handle = op->u.nominate.handle; 

    return ret;
}

int xc_memshr_share(xc_interface *xch,
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
    op->u.share.source_handle = source_handle;
    op->u.share.client_handle = client_handle;

    return do_domctl(xch, &domctl);
}

int xc_memshr_domain_resume(xc_interface *xch,
                            uint32_t domid)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = (domid_t)domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_SHARING_OP_RESUME;

    return do_domctl(xch, &domctl);
}

int xc_memshr_debug_gfn(xc_interface *xch,
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
    op->u.debug.u.gfn = gfn;

    return do_domctl(xch, &domctl);
}

int xc_memshr_debug_mfn(xc_interface *xch,
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
    op->u.debug.u.mfn = mfn;

    return do_domctl(xch, &domctl);
}

int xc_memshr_debug_gref(xc_interface *xch,
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
    op->u.debug.u.gref = gref;

    return do_domctl(xch, &domctl);
}

