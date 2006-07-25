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
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_DEBUGGER_H_
#define _ASM_DEBUGGER_H_

#ifdef CRASH_DEBUG

#include <xen/gdbstub.h>

static inline int debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    (void)__trap_to_gdb(regs, vector);
    return vector;
}

#define debugger_trap_immediate() __asm__ __volatile__ ("trap");

#else /* CRASH_DEBUG */

#define debugger_trap_fatal(_v, _r) (0)
#define debugger_trap_immediate() ((void)0)

#endif /* CRASH_DEBUG */

#endif
