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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_HCALLS_H_
#define _ASM_HCALLS_H_

#include <xen/config.h>
#include <xen/types.h>

/* table of standard PAPR hcalls */
extern u32 *papr_hcalls;

extern void papr_hcall_jump(struct cpu_user_regs *regs, u32 address);

#define XEN_MARK(a) ((a) | (~0UL << 16))

#endif
