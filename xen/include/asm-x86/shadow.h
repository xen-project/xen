/******************************************************************************
 * include/asm-x86/shadow.h
 * 
 * Copyright (c) 2006 by XenSource Inc.
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

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

/* This file is just a wrapper around the new Shadow2 header,
 * providing names that must be defined in any shadow implementation. */

#include <asm/shadow2.h>

/* How to make sure a page is not referred to in a shadow PT */
/* This will need to be a for_each_vcpu if we go to per-vcpu shadows */ 
#define shadow_drop_references(_d, _p)                      \
    shadow2_remove_all_mappings((_d)->vcpu[0], _mfn(page_to_mfn(_p)))
#define shadow_sync_and_drop_references(_d, _p)             \
    shadow2_remove_all_mappings((_d)->vcpu[0], _mfn(page_to_mfn(_p)))

/* Whether we are translating the domain's frame numbers for it */
#define shadow_mode_translate(d)  shadow2_mode_translate(d)

/* ...and  if so, how to add and remove entries in the mapping */
#define guest_physmap_add_page(_d, _p, _m)                  \
    shadow2_guest_physmap_add_page((_d), (_p), (_m))
#define guest_physmap_remove_page(_d, _p, _m   )            \
    shadow2_guest_physmap_remove_page((_d), (_p), (_m))

#endif /* _XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
