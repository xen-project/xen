/******************************************************************************
 * tools/xenpaging/xenpaging.h
 *
 * Xen domain paging.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
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


#ifndef __XEN_PAGING2_H__
#define __XEN_PAGING2_H__


#include "spinlock.h"
#include "xc.h"
#include <xc_private.h>

#include <xen/event_channel.h>
#include <xen/mem_event.h>

#include "mem_event.h"


typedef struct xenpaging {
    xc_interface *xc_handle;

    xc_platform_info_t *platform_info;
    xc_domaininfo_t    *domain_info;

    unsigned long  bitmap_size;
    unsigned long *bitmap;

    mem_event_t mem_event;
} xenpaging_t;


typedef struct xenpaging_victim {
    /* the domain to evict a page from */
    domid_t domain_id;
    /* the gfn of the page to evict */
    unsigned long gfn;
    /* the mfn of evicted page */
    unsigned long mfn;
} xenpaging_victim_t;


#endif // __XEN_PAGING_H__


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
