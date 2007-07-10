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
 * Copyright (C) IBM Corp. 2005, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <asm/config.h>
#include <asm/processor.h>
#include <asm/papr.h>
#include <asm/asm-offsets.h>

#define HSC .long 0x44000022

_GLOBAL(xen_hvcall)
    HSC
    blr

/* The following stub will get instantiated as RTAS in the guest */	
#define H_RTAS_PROXY 23
    .p2align 3
    .global _rtas_image_start
    .global _rtas_image_end
_rtas_image_start:
    mr	r4,r3
    lis	r3,0xffff
    ori	r3,r3,H_RTAS_PROXY
    HSC
    blr
    nop
_rtas_image_end:
