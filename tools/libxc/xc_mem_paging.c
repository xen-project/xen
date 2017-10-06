/******************************************************************************
 *
 * tools/libxc/xc_mem_paging.c
 *
 * Interface to low-level memory paging functionality.
 *
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
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

static int xc_mem_paging_memop(xc_interface *xch, uint32_t domain_id,
                               unsigned int op, uint64_t gfn, void *buffer)
{
    xen_mem_paging_op_t mpo;

    memset(&mpo, 0, sizeof(mpo));

    mpo.op      = op;
    mpo.domain  = domain_id;
    mpo.gfn     = gfn;
    mpo.buffer  = (unsigned long) buffer;

    return do_memory_op(xch, XENMEM_paging_op, &mpo, sizeof(mpo));
}

int xc_mem_paging_enable(xc_interface *xch, uint32_t domain_id,
                         uint32_t *port)
{
    if ( !port )
    {
        errno = EINVAL;
        return -1;
    }

    return xc_vm_event_control(xch, domain_id,
                               XEN_VM_EVENT_ENABLE,
                               XEN_DOMCTL_VM_EVENT_OP_PAGING,
                               port);
}

int xc_mem_paging_disable(xc_interface *xch, uint32_t domain_id)
{
    return xc_vm_event_control(xch, domain_id,
                               XEN_VM_EVENT_DISABLE,
                               XEN_DOMCTL_VM_EVENT_OP_PAGING,
                               NULL);
}

int xc_mem_paging_resume(xc_interface *xch, uint32_t domain_id)
{
    return xc_vm_event_control(xch, domain_id,
                               XEN_VM_EVENT_RESUME,
                               XEN_DOMCTL_VM_EVENT_OP_PAGING,
                               NULL);
}

int xc_mem_paging_nominate(xc_interface *xch, uint32_t domain_id, uint64_t gfn)
{
    return xc_mem_paging_memop(xch, domain_id,
                               XENMEM_paging_op_nominate,
                               gfn, NULL);
}

int xc_mem_paging_evict(xc_interface *xch, uint32_t domain_id, uint64_t gfn)
{
    return xc_mem_paging_memop(xch, domain_id,
                               XENMEM_paging_op_evict,
                               gfn, NULL);
}

int xc_mem_paging_prep(xc_interface *xch, uint32_t domain_id, uint64_t gfn)
{
    return xc_mem_paging_memop(xch, domain_id,
                               XENMEM_paging_op_prep,
                               gfn, NULL);
}

int xc_mem_paging_load(xc_interface *xch, uint32_t domain_id,
                       uint64_t gfn, void *buffer)
{
    int rc, old_errno;

    errno = EINVAL;

    if ( !buffer )
        return -1;

    if ( ((unsigned long) buffer) & (XC_PAGE_SIZE - 1) )
        return -1;

    if ( mlock(buffer, XC_PAGE_SIZE) )
        return -1;

    rc = xc_mem_paging_memop(xch, domain_id,
                             XENMEM_paging_op_prep,
                             gfn, buffer);

    old_errno = errno;
    munlock(buffer, XC_PAGE_SIZE);
    errno = old_errno;

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
