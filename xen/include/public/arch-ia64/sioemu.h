/******************************************************************************
 * sioemu.h
 *
 * Copyright (c) 2008 Tristan Gingold <tgingold@free.fr>
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
 *
 */

#ifndef __XEN_PUBLIC_IA64_SIOEMU_H__
#define __XEN_PUBLIC_IA64_SIOEMU_H__

/* Defines the callback entry point.  r8=ip, r9=data.
   Must be called per-vcpu.  */
#define SIOEMU_HYPERCALL_SET_CALLBACK 0x01

/* Finish sioemu fw initialization and start firmware.  r8=ip.  */
#define SIOEMU_HYPERCALL_START_FW 0x02

/* Add IO pages in physmap.  */
#define SIOEMU_HYPERCALL_ADD_IO_PHYSMAP 0x03

/* Get wallclock time.  */
#define SIOEMU_HYPERCALL_GET_TIME 0x04

/* Return from callback.  r16=0.
   Unmask vcpu events.  */
#define SIOEMU_HYPERPRIVOP_CALLBACK_RETURN 0x01

#endif /* __XEN_PUBLIC_IA64_SIOEMU_H__ */
