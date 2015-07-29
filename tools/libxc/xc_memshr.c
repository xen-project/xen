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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
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
    op->op = XEN_DOMCTL_MEM_SHARING_CONTROL;
    op->u.enable = enable;

    return do_domctl(xch, &domctl);
}

int xc_memshr_ring_enable(xc_interface *xch, 
                          domid_t domid, 
                          uint32_t *port)
{
    if ( !port )
    {
        errno = EINVAL;
        return -1;
    }

    return xc_vm_event_control(xch, domid,
                               XEN_VM_EVENT_ENABLE,
                               XEN_DOMCTL_VM_EVENT_OP_SHARING,
                               port);
}

int xc_memshr_ring_disable(xc_interface *xch, 
                           domid_t domid)
{
    return xc_vm_event_control(xch, domid,
                               XEN_VM_EVENT_DISABLE,
                               XEN_DOMCTL_VM_EVENT_OP_SHARING,
                               NULL);
}

static int xc_memshr_memop(xc_interface *xch, domid_t domid, 
                            xen_mem_sharing_op_t *mso)
{
    mso->domain = domid;

    return do_memory_op(xch, XENMEM_sharing_op, mso, sizeof(*mso));
}

int xc_memshr_nominate_gfn(xc_interface *xch,
                           domid_t domid,
                           unsigned long gfn,
                           uint64_t *handle)
{
    int rc;
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_nominate_gfn;
    mso.u.nominate.u.gfn = gfn; 

    rc = xc_memshr_memop(xch, domid, &mso);

    if (!rc) *handle = mso.u.nominate.handle; 

    return rc;
}

int xc_memshr_nominate_gref(xc_interface *xch,
                            domid_t domid,
                            grant_ref_t gref,
                            uint64_t *handle)
{
    int rc;
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_nominate_gref;
    mso.u.nominate.u.grant_ref = gref; 

    rc = xc_memshr_memop(xch, domid, &mso);

    if (!rc) *handle = mso.u.nominate.handle; 

    return rc;
}

int xc_memshr_share_gfns(xc_interface *xch,
                         domid_t source_domain,
                         unsigned long source_gfn,
                         uint64_t source_handle,
                         domid_t client_domain,
                         unsigned long client_gfn,
                         uint64_t client_handle)
{
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_share;

    mso.u.share.source_handle = source_handle;
    mso.u.share.source_gfn    = source_gfn;
    mso.u.share.client_domain = client_domain;
    mso.u.share.client_gfn    = client_gfn;
    mso.u.share.client_handle = client_handle;

    return xc_memshr_memop(xch, source_domain, &mso);
}

int xc_memshr_share_grefs(xc_interface *xch,
                          domid_t source_domain,
                          grant_ref_t source_gref,
                          uint64_t source_handle,
                          domid_t client_domain,
                          grant_ref_t client_gref,
                          uint64_t client_handle)
{
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_share;

    mso.u.share.source_handle = source_handle;
    XENMEM_SHARING_OP_FIELD_MAKE_GREF(mso.u.share.source_gfn, source_gref);
    mso.u.share.client_domain = client_domain;
    XENMEM_SHARING_OP_FIELD_MAKE_GREF(mso.u.share.client_gfn, client_gref);
    mso.u.share.client_handle = client_handle;

    return xc_memshr_memop(xch, source_domain, &mso);
}

int xc_memshr_add_to_physmap(xc_interface *xch,
                    domid_t source_domain,
                    unsigned long source_gfn,
                    uint64_t source_handle,
                    domid_t client_domain,
                    unsigned long client_gfn)
{
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_add_physmap;

    mso.u.share.source_handle = source_handle;
    mso.u.share.source_gfn    = source_gfn;
    mso.u.share.client_domain = client_domain;
    mso.u.share.client_gfn    = client_gfn;

    return xc_memshr_memop(xch, source_domain, &mso);
}

int xc_memshr_domain_resume(xc_interface *xch,
                            domid_t domid)
{
    return xc_vm_event_control(xch, domid,
                               XEN_VM_EVENT_RESUME,
                               XEN_DOMCTL_VM_EVENT_OP_SHARING,
                               NULL);
}

int xc_memshr_debug_gfn(xc_interface *xch,
                        domid_t domid,
                        unsigned long gfn)
{
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_debug_gfn;
    mso.u.debug.u.gfn = gfn; 

    return xc_memshr_memop(xch, domid, &mso);
}

int xc_memshr_debug_gref(xc_interface *xch,
                         domid_t domid,
                         grant_ref_t gref)
{
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_debug_gref;
    mso.u.debug.u.gref = gref; 

    return xc_memshr_memop(xch, domid, &mso);
}

int xc_memshr_audit(xc_interface *xch)
{
    xen_mem_sharing_op_t mso;

    memset(&mso, 0, sizeof(mso));

    mso.op = XENMEM_sharing_op_audit;

    return do_memory_op(xch, XENMEM_sharing_op, &mso, sizeof(mso));
}

long xc_sharing_freed_pages(xc_interface *xch)
{
    return do_memory_op(xch, XENMEM_get_sharing_freed_pages, NULL, 0);
}

long xc_sharing_used_frames(xc_interface *xch)
{
    return do_memory_op(xch, XENMEM_get_sharing_shared_pages, NULL, 0);
}

