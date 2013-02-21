/******************************************************************************
 * tools/xenpaging/policy.h
 *
 * Xen domain paging policy hooks.
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


#ifndef __XEN_PAGING_POLICY_H__
#define __XEN_PAGING_POLICY_H__


#include "xenpaging.h"


int policy_init(struct xenpaging *paging);
unsigned long policy_choose_victim(struct xenpaging *paging);
void policy_notify_paged_out(unsigned long gfn);
void policy_notify_paged_in(unsigned long gfn);
void policy_notify_paged_in_nomru(unsigned long gfn);
void policy_notify_dropped(unsigned long gfn);

#endif // __XEN_PAGING_POLICY_H__


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
