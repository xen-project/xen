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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _ASM_MEMORY_H_
#define _ASM_MEMORY_H_

#include <xen/config.h>

/*
 * Arguably the bitops and *xchg operations don't imply any memory barrier
 * or SMP ordering, but in fact a lot of drivers expect them to imply
 * both, since they do on x86 cpus.
 */
#ifdef CONFIG_SMP
#define EIEIO_ON_SMP    "eieio\n"
#define ISYNC_ON_SMP    "\n\tisync"
#else
#define EIEIO_ON_SMP
#define ISYNC_ON_SMP
#endif 

#endif
