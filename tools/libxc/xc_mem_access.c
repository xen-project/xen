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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"


int xc_mem_access_enable(xc_interface *xch, domid_t domain_id,
                         uint32_t *port)
{
    if ( !port )
    {
        errno = EINVAL;
        return -1;
    }

    return xc_mem_event_control(xch, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE,
                                XEN_DOMCTL_MEM_EVENT_OP_ACCESS,
                                port);
}

int xc_mem_access_disable(xc_interface *xch, domid_t domain_id)
{
    return xc_mem_event_control(xch, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_ACCESS_DISABLE,
                                XEN_DOMCTL_MEM_EVENT_OP_ACCESS,
                                NULL);
}

int xc_mem_access_resume(xc_interface *xch, domid_t domain_id, unsigned long gfn)
{
    return xc_mem_event_memop(xch, domain_id,
                                XENMEM_access_op_resume,
                                XENMEM_access_op,
                                gfn, NULL);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
