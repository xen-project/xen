/*
 * Copyright (C) 2005 Jimi Xenidis <jimix@watson.ibm.com>, IBM Corporation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */
	
### 32 bit strapping code so Of will like us
	.section	".text"
	.align 3
	.globl _start
		
_start:
	## Double word align the MSR value below
	nop
	bl _real_start
	## static value for MSR
	.llong 0x9000000000001000

	## see also docs/reference/ppc/msr.txt
##bit C  Hex               Name Desc
##  0 63 80000000 00000000 SF   64-bit Mode
##  3 60 10000000 00000000 HV   Hypervisor State iff PR = 0 in hypervisor state.
## 51 12 00000000 00001000 ME   Machine Check Enable

_real_start:		
	# pass the original msr as argument to hype_init
	mfmsr   8

	## Set PC
	li	21, 0
	oris	21, 21, _hype64@h
	ori	21, 21, _hype64@l
#ifdef __BRIDGE64__
	## In 64bit we use rfid to switch from 32bit to 64 bit
	mtsrr0	21

	## Set MSR
	mflr	21
	ld	22, 0(21)
	mtsrr1	22
	bl __leap
	/* should never return */
	trap
__leap:		
	rfid
#else
	mtctr 21
	bctrl
	/* should never return */
	trap
#endif

	
_real_end:
	.data
	.align 3
	## Hypervisor starts here, at the first data address
	## linker magic positions _hype64 0x100 after _start
	## hype/ppc64/Makefile.isa 
_hype64:		


