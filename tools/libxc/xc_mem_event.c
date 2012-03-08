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

