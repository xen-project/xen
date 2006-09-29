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
 * Authors: Jimi Xenidis <jimix@us.ibm.com>
 */

#ifndef _ARCH_POWERPC_RTAS_H_
#define _ARCH_POWERPC_RTAS_H_

extern int rtas_entry;
extern unsigned long rtas_msr;
extern unsigned long rtas_base;
extern unsigned long rtas_end;

extern int prom_call(void *arg, unsigned base,
                     unsigned long func, unsigned long msr);
extern int rtas_init(void *);
extern int rtas_halt(void);
extern int rtas_reboot(void);
#endif
