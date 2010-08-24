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
                         unsigned int mode, void *shared_page,
                         void *ring_page, unsigned long gfn)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_mem_event_op;
    domctl.domain = domain_id;
    domctl.u.mem_event_op.op = op;
    domctl.u.mem_event_op.mode = mode;

    domctl.u.mem_event_op.shared_addr = (unsigned long)shared_page;
    domctl.u.mem_event_op.ring_addr = (unsigned long)ring_page;

    domctl.u.mem_event_op.gfn = gfn;
    
    return do_domctl(xch, &domctl);
}

int xc_mem_event_enable(xc_interface *xch, domid_t domain_id,
                        void *shared_page, void *ring_page)
{
    return xc_mem_event_control(xch, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_ENABLE, 0,
                                shared_page, ring_page, INVALID_MFN);
}

int xc_mem_event_disable(xc_interface *xch, domid_t domain_id)
{
    return xc_mem_event_control(xch, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_DISABLE, 0,
                                NULL, NULL, INVALID_MFN);
}

