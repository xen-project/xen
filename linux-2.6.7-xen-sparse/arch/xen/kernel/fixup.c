/******************************************************************************
 * fixup.c
 * 
 * Binary-rewriting of certain IA32 instructions, on notification by Xen.
 * Used to avoid repeated slow emulation of common instructions used by the
 * user-space TLS (Thread-Local Storage) libraries.
 * 
 * Copyright (c) 2004, K A Fraser
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

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/kernel.h>

asmlinkage void do_fixup_4gb_segment(struct pt_regs *regs, long error_code)
{
}
