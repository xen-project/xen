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
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _ARCH_POWERPC_POWERPC64_SCOM_H_
#define _ARCH_POWERPC_POWERPC64_SCOM_H_

extern void cpu_scom_init(void);
int cpu_scom_read(unsigned int addr, unsigned long *d);
int cpu_scom_write(unsigned int addr, unsigned long d);
void cpu_scom_AMCR(void);

/* SCOMC addresses are 16bit but we are given 24 bits in the
 * books. The low oerder 8 bits are some kinda parity thin and should
 * be ignored */
#define SCOM_AMC_REG       0x022601
#define SCOM_AMC_AND_MASK  0x022700
#define SCOM_AMC_OR_MASK   0x022800
#define SCOM_CMCE          0x030901
#define SCOM_PMCR          0x400801
#define SCOM_PTSR          0x408001

#endif
