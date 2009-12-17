/******************************************************************************
 *
 * tools/libxc/xc_mem_paging.c
 *
 * Interface to low-level memory paging functionality.
 *
 * Copyright (c) 2009 by Citrix (R&D) Ltd. (Patrick Colp)
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


int xc_mem_paging_nominate(int xc_handle, domid_t domain_id, unsigned long gfn)
{
    return xc_mem_event_control(xc_handle, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING_NOMINATE,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING, NULL, NULL,
                                gfn);
}

int xc_mem_paging_evict(int xc_handle, domid_t domain_id, unsigned long gfn)
{
    return xc_mem_event_control(xc_handle, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING_EVICT,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING, NULL, NULL,
                                gfn);
}

int xc_mem_paging_prep(int xc_handle, domid_t domain_id, unsigned long gfn)
{
    return xc_mem_event_control(xc_handle, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING_PREP,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING, NULL, NULL,
                                gfn);
}

int xc_mem_paging_resume(int xc_handle, domid_t domain_id, unsigned long gfn)
{
    return xc_mem_event_control(xc_handle, domain_id,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING_RESUME,
                                XEN_DOMCTL_MEM_EVENT_OP_PAGING, NULL, NULL,
                                gfn);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
