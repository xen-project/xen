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









int xc_mem_paging_flush_ioemu_cache(domid_t domain_id);
int xc_wait_for_event(xc_interface *xch, xc_evtchn *xce);
int xc_wait_for_event_or_timeout(xc_interface *xch, xc_evtchn *xce, unsigned long ms);



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
