/******************************************************************************
 *
 * xc_memshr.c
 *
 * Interface to low-level memory sharing functionality.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"
#include <xen/memory.h>
#include <xen/grant_table.h>

int xc_memshr_control(xc_interface *xch,
                      domid_t domid,
                      int enable)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_CONTROL;
    op->u.enable = enable;

    return do_domctl(xch, &domctl);
}

int xc_memshr_nominate_gfn(xc_interface *xch,
                           domid_t domid,
                           unsigned long gfn,
                           uint64_t *handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;
    int ret;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_NOMINATE_GFN;
    op->u.nominate.u.gfn = gfn;

    ret = do_domctl(xch, &domctl);
    if(!ret) *handle = op->u.nominate.handle; 

    return ret;
}

int xc_memshr_nominate_gref(xc_interface *xch,
                            domid_t domid,
                            grant_ref_t gref,
                            uint64_t *handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;
    int ret;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_NOMINATE_GREF;
    op->u.nominate.u.grant_ref = gref;

    ret = do_domctl(xch, &domctl);
    if(!ret) *handle = op->u.nominate.handle; 

    return ret;
}

int xc_memshr_share_gfns(xc_interface *xch,
                         domid_t source_domain,
                         unsigned long source_gfn,
                         uint64_t source_handle,
                         domid_t client_domain,
                         unsigned long client_gfn,
                         uint64_t client_handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = source_domain;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_SHARE;
    op->u.share.source_handle = source_handle;
    op->u.share.source_gfn    = source_gfn;
    op->u.share.client_domain = client_domain;
    op->u.share.client_gfn    = client_gfn;
    op->u.share.client_handle = client_handle;

    return do_domctl(xch, &domctl);
}

int xc_memshr_share_grefs(xc_interface *xch,
                          domid_t source_domain,
                          grant_ref_t source_gref,
                          uint64_t source_handle,
                          domid_t client_domain,
                          grant_ref_t client_gref,
                          uint64_t client_handle)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = source_domain;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_SHARE;
    op->u.share.source_handle = source_handle;
    XEN_DOMCTL_MEM_SHARING_FIELD_MAKE_GREF(op->u.share.source_gfn, source_gref);
    op->u.share.client_domain = client_domain;
    XEN_DOMCTL_MEM_SHARING_FIELD_MAKE_GREF(op->u.share.client_gfn, client_gref);
    op->u.share.client_handle = client_handle;

    return do_domctl(xch, &domctl);
}

int xc_memshr_add_to_physmap(xc_interface *xch,
                    domid_t source_domain,
                    unsigned long source_gfn,
                    uint64_t source_handle,
                    domid_t client_domain,
                    unsigned long client_gfn)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd                  = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version    = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain               = source_domain;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_ADD_PHYSMAP;
    op->u.share.source_gfn      = source_gfn;
    op->u.share.source_handle   = source_handle;
    op->u.share.client_gfn      = client_gfn;
    op->u.share.client_domain   = client_domain;

    return do_domctl(xch, &domctl);
}

int xc_memshr_domain_resume(xc_interface *xch,
                            domid_t domid)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_RESUME;

    return do_domctl(xch, &domctl);
}

int xc_memshr_debug_gfn(xc_interface *xch,
                        domid_t domid,
                        unsigned long gfn)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_DEBUG_GFN;
    op->u.debug.u.gfn = gfn;

    return do_domctl(xch, &domctl);
}

int xc_memshr_debug_mfn(xc_interface *xch,
                        domid_t domid,
                        unsigned long mfn)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_DEBUG_MFN;
    op->u.debug.u.mfn = mfn;

    return do_domctl(xch, &domctl);
}

int xc_memshr_debug_gref(xc_interface *xch,
                         domid_t domid,
                         grant_ref_t gref)
{
    DECLARE_DOMCTL;
    struct xen_domctl_mem_sharing_op *op;

    domctl.cmd = XEN_DOMCTL_mem_sharing_op;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
    domctl.domain = domid;
    op = &(domctl.u.mem_sharing_op);
    op->op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_DEBUG_GREF;
    op->u.debug.u.gref = gref;

    return do_domctl(xch, &domctl);
}

long xc_sharing_freed_pages(xc_interface *xch)
{
    return do_memory_op(xch, XENMEM_get_sharing_freed_pages, NULL, 0);
}

long xc_sharing_used_frames(xc_interface *xch)
{
    return do_memory_op(xch, XENMEM_get_sharing_shared_pages, NULL, 0);
}

