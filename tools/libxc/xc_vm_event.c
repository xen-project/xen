/******************************************************************************
 *
 * xc_vm_event.c
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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

int xc_vm_event_control(xc_interface *xch, uint32_t domain_id, unsigned int op,
                        unsigned int mode, uint32_t *port)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_vm_event_op;
    domctl.domain = domain_id;
    domctl.u.vm_event_op.op = op;
    domctl.u.vm_event_op.mode = mode;

    rc = do_domctl(xch, &domctl);
    if ( !rc && port )
        *port = domctl.u.vm_event_op.port;
    return rc;
}

void *xc_vm_event_enable(xc_interface *xch, uint32_t domain_id, int param,
                         uint32_t *port)
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
    rc1 = xc_get_pfn_type_batch(xch, domain_id, 1, &mmap_pfn);
    if ( rc1 || mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
    {
        /* Page not in the physmap, try to populate it */
        rc1 = xc_domain_populate_physmap_exact(xch, domain_id, 1, 0, 0,
                                              &ring_pfn);
        if ( rc1 != 0 )
        {
            PERROR("Failed to populate ring pfn\n");
            goto out;
        }
    }

    mmap_pfn = ring_pfn;
    ring_page = xc_map_foreign_pages(xch, domain_id, PROT_READ | PROT_WRITE,
                                         &mmap_pfn, 1);
    if ( !ring_page )
    {
        PERROR("Could not map the ring page\n");
        goto out;
    }

    switch ( param )
    {
    case HVM_PARAM_PAGING_RING_PFN:
        op = XEN_VM_EVENT_ENABLE;
        mode = XEN_DOMCTL_VM_EVENT_OP_PAGING;
        break;

    case HVM_PARAM_MONITOR_RING_PFN:
        op = XEN_VM_EVENT_ENABLE;
        mode = XEN_DOMCTL_VM_EVENT_OP_MONITOR;
        break;

    case HVM_PARAM_SHARING_RING_PFN:
        op = XEN_VM_EVENT_ENABLE;
        mode = XEN_DOMCTL_VM_EVENT_OP_SHARING;
        break;

    /*
     * This is for the outside chance that the HVM_PARAM is valid but is invalid
     * as far as vm_event goes.
     */
    default:
        errno = EINVAL;
        rc1 = -1;
        goto out;
    }

    rc1 = xc_vm_event_control(xch, domain_id, op, mode, port);
    if ( rc1 != 0 )
    {
        PERROR("Failed to enable vm_event\n");
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
            xenforeignmemory_unmap(xch->fmem, ring_page, 1);
        ring_page = NULL;

        errno = saved_errno;
    }

    return ring_page;
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
