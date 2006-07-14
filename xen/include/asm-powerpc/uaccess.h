/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __PPC_UACCESS_H__
#define __PPC_UACCESS_H__

#include <xen/errno.h>
#include <asm/page.h>
#include <asm/guest_access.h>

/* since we run in real mode, we can safely access all addresses.
 * XXX well, except IO. should we check for that here? */
#define access_ok(addr,size) 1
#define array_access_ok(addr,count,size) 1

#define __copy_to_user copy_to_user
#define __copy_from_user copy_from_user
#define copy_to_user(to,from,len) xencomm_copy_to_guest(to,from,len,0)
#define copy_from_user(to,from,len) xencomm_copy_from_guest(to,from,len,0)

#endif /* __PPC_UACCESS_H__ */
