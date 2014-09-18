/******************************************************************************
 *
 * xc_mem_event.c
 *
 * Interface to low-level memory event functionality.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
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

int xc_mem_event_control(xc_interface *xch, domid_t domain_id, unsigned int op,
                         unsigned int mode, uint32_t *port)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_mem_event_op;
    domctl.domain = domain_id;
    domctl.u.mem_event_op.op = op;
    domctl.u.mem_event_op.mode = mode;
    
    rc = do_domctl(xch, &domctl);
    if ( !rc && port )
        *port = domctl.u.mem_event_op.port;
    return rc;
}

int xc_mem_event_memop(xc_interface *xch, domid_t domain_id, 
                        unsigned int op, unsigned int mode,
                        uint64_t gfn, void *buffer)
{
    xen_mem_event_op_t meo;

    memset(&meo, 0, sizeof(meo));

    meo.op      = op;
    meo.domain  = domain_id;
    meo.gfn     = gfn;
    meo.buffer  = (unsigned long) buffer;

    return do_memory_op(xch, mode, &meo, sizeof(meo));
}

void *xc_mem_event_enable(xc_interface *xch, domid_t domain_id, int param,
                          uint32_t *port, int enable_introspection)
{
    void *ring_page = NULL;
    uint64_t pfn;
    xen_pfn_t ring_pfn, mmap_pfn;
    unsigned int op, mode;
    int rc1, rc2, saved_errno;

    if ( !port )
    {
        errno = EINVAL;
        return NULL;
    }

    /* Pause the domain for ring page setup */
    rc1 = xc_domain_pause(xch, domain_id);
    if ( rc1 != 0 )
    {
        PERROR("Unable to pause domain\n");
        return NULL;
    }

    /* Get the pfn of the ring page */
    rc1 = xc_hvm_param_get(xch, domain_id, param, &pfn);
    if ( rc1 != 0 )
    {
        PERROR("Failed to get pfn of ring page\n");
        goto out;
    }

    ring_pfn = pfn;
    mmap_pfn = pfn;
    ring_page = xc_map_foreign_batch(xch, domain_id, PROT_READ | PROT_WRITE,
                                     &mmap_pfn, 1);
    if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
    {
        /* Map failed, populate ring page */
        rc1 = xc_domain_populate_physmap_exact(xch, domain_id, 1, 0, 0,
                                              &ring_pfn);
        if ( rc1 != 0 )
        {
            PERROR("Failed to populate ring pfn\n");
            goto out;
        }

        mmap_pfn = ring_pfn;
        ring_page = xc_map_foreign_batch(xch, domain_id, PROT_READ | PROT_WRITE,
                                         &mmap_pfn, 1);
        if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
        {
            PERROR("Could not map the ring page\n");
            goto out;
        }
    }

    switch ( param )
    {
    case HVM_PARAM_PAGING_RING_PFN:
        op = XEN_DOMCTL_MEM_EVENT_OP_PAGING_ENABLE;
        mode = XEN_DOMCTL_MEM_EVENT_OP_PAGING;
        break;

    case HVM_PARAM_ACCESS_RING_PFN:
        if ( enable_introspection )
            op = XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE_INTROSPECTION;
        else
            op = XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE;
        mode = XEN_DOMCTL_MEM_EVENT_OP_ACCESS;
        break;

    case HVM_PARAM_SHARING_RING_PFN:
        op = XEN_DOMCTL_MEM_EVENT_OP_SHARING_ENABLE;
        mode = XEN_DOMCTL_MEM_EVENT_OP_SHARING;
        break;

    /*
     * This is for the outside chance that the HVM_PARAM is valid but is invalid
     * as far as mem_event goes.
     */
    default:
        errno = EINVAL;
        rc1 = -1;
        goto out;
    }

    rc1 = xc_mem_event_control(xch, domain_id, op, mode, port);
    if ( rc1 != 0 )
    {
        PERROR("Failed to enable mem_event\n");
        goto out;
    }

    /* Remove the ring_pfn from the guest's physmap */
    rc1 = xc_domain_decrease_reservation_exact(xch, domain_id, 1, 0, &ring_pfn);
    if ( rc1 != 0 )
        PERROR("Failed to remove ring page from guest physmap");

 out:
    saved_errno = errno;

    rc2 = xc_domain_unpause(xch, domain_id);
    if ( rc1 != 0 || rc2 != 0 )
    {
        if ( rc2 != 0 )
        {
            if ( rc1 == 0 )
                saved_errno = errno;
            PERROR("Unable to unpause domain");
        }

        if ( ring_page )
            munmap(ring_page, XC_PAGE_SIZE);
        ring_page = NULL;

        errno = saved_errno;
    }

    return ring_page;
}
