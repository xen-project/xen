/*
 * asm-x86/pv/mm.h
 *
 * Memory management interfaces for PV guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __X86_PV_MM_H__
#define __X86_PV_MM_H__

#ifdef CONFIG_PV

int pv_ro_page_fault(unsigned long addr, struct cpu_user_regs *regs);

#else

#include <xen/lib.h>

static inline int pv_ro_page_fault(unsigned long addr,
                                   struct cpu_user_regs *regs)
{
    ASSERT_UNREACHABLE();
    return 0;
}

#endif

#endif /* __X86_PV_MM_H__ */
