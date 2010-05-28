/******************************************************************************
 * tools/xenpaging/lib/xc.h
 *
 * libxc add-ons. 
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


#ifndef __XC_H__
#define __XC_H__


#include <stdarg.h>
#include <xc_private.h>
#include <xen/mem_event.h>


#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { DPRINTF("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif


#define BITS_PER_LONG 64


typedef struct xc_platform_info {
    unsigned long max_mfn;
    unsigned long hvirt_start;
    unsigned int  pt_levels;
    unsigned int  guest_width;
} xc_platform_info_t;


int alloc_bitmap(unsigned long **bitmap, unsigned long bitmap_size);

int xc_mem_paging_flush_ioemu_cache(domid_t domain_id);
int xc_wait_for_event(xc_interface *xch, int xce_handle);
int xc_wait_for_event_or_timeout(xc_interface *xch, int xce_handle, unsigned long ms);

int xc_get_platform_info(xc_interface *xc_handle, domid_t domain_id,
                         xc_platform_info_t *platform_info);


#endif // __XC_H__


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
