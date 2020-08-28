/******************************************************************************
 *
 * tools/libxc/xc_mem_access.c
 *
 * Interface to low-level memory access mode functionality
 *
 * Copyright (c) 2011 Virtuata, Inc.
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

int xc_set_mem_access(xc_interface *xch,
                      uint32_t domain_id,
                      xenmem_access_t access,
                      uint64_t first_pfn,
                      uint32_t nr)
{
    xen_mem_access_op_t mao =
    {
        .op     = XENMEM_access_op_set_access,
        .domid  = domain_id,
        .access = access,
        .pfn    = first_pfn,
        .nr     = nr
    };

    return do_memory_op(xch, XENMEM_access_op, &mao, sizeof(mao));
}

int xc_set_mem_access_multi(xc_interface *xch,
                            uint32_t domain_id,
                            uint8_t *access,
                            uint64_t *pages,
                            uint32_t nr)
{
    DECLARE_HYPERCALL_BOUNCE(access, nr, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(pages, nr * sizeof(uint64_t),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    int rc;

    xen_mem_access_op_t mao =
    {
        .op       = XENMEM_access_op_set_access_multi,
        .domid    = domain_id,
        .access   = XENMEM_access_default + 1, /* Invalid value */
        .pfn      = ~0UL, /* Invalid GFN */
        .nr       = nr,
    };

    if ( xc_hypercall_bounce_pre(xch, pages) ||
         xc_hypercall_bounce_pre(xch, access) )
    {
        PERROR("Could not bounce memory for XENMEM_access_op_set_access_multi");
        return -1;
    }

    set_xen_guest_handle(mao.pfn_list, pages);
    set_xen_guest_handle(mao.access_list, access);

    rc = do_memory_op(xch, XENMEM_access_op, &mao, sizeof(mao));

    xc_hypercall_bounce_post(xch, access);
    xc_hypercall_bounce_post(xch, pages);

    return rc;
}

int xc_get_mem_access(xc_interface *xch,
                      uint32_t domain_id,
                      uint64_t pfn,
                      xenmem_access_t *access)
{
    int rc;
    xen_mem_access_op_t mao =
    {
        .op    = XENMEM_access_op_get_access,
        .domid = domain_id,
        .pfn   = pfn
    };

    rc = do_memory_op(xch, XENMEM_access_op, &mao, sizeof(mao));

    if ( rc == 0 )
        *access = mao.access;

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
