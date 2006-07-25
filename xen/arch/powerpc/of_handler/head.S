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
 */
/*
 * Glue code for open-firmware client interface implementation.
 */

#define OF_STACK_SIZE (32*1024)

#include <asm/config.h>
#include <asm/processor.h>

#define SAVE_STACK	0
#define SAVE_SRR0	1
#define SAVE_SRR1	2
#define SAVE_MSR	3
#define SAVE_LR		4
#define SAVE_TOC	5
#define SAVE_BASE	6
#define SAVE_BCHAIN	7  /* MUST be last */

/* This code is NOT MP safe and does not need to be */
	.p2align 3
	. = 0x0
_GLOBAL(ofh_start)		# make the linker happy
_ofh_cih:
	## r3 holds the parameter.  All other volatiles are available.
	mflr	r0
	# Obtain address of _ofh_work_space via a branch-and-link
	bl	_ofh_cih_continue
_ofh_work_space:
	nop

	. = 0x10
	.global _ofh_tree
_ofh_tree:
	.long 0xdeadbeef
	.long 0x0

	. = 0x18
	.global _ofh_inited
_ofh_inited:
	.long 0x0	

	. = 0x20
	.global _ofh_lastarg
_ofh_lastarg:
	.long 0x0	
	.long 0x0	
	
	. = 0x30
_ofh_cih_stack_end:
	.space	OF_STACK_SIZE
_ofh_cih_stack:
   
_ofh_cih_continue:
	mflr	r12				# r12 = &_ofh_work_space
	mr	r11, r1				# r11 = orig stk ptr

	/* load base address in r4 */
	LOADADDR(r4, _ofh_work_space)
	sub	r4, r12, r4
	

	# save srr0/1
	mfsrr0	r9
	mfsrr1	r8
	mfmsr	r7
	LOADADDR(r5, _ofh_cih_64bit)
	add	r5, r5, r4	# offset base
	mtsrr0	r5
	# r5 = MSR_SF
	li	r5,-1
	rldicr	r5,r5,0,0
	or	r5,r5,r7
	mtsrr1	r5
	rfid
	trap

_ofh_cih_64bit:		
	# move to local stack
	lis	r1, (_ofh_cih_stack - _ofh_cih_stack_end) >> 16
	ori	r1, r1, (_ofh_cih_stack - _ofh_cih_stack_end) & 0xffff
	add	r1, r12, r1
	# create an initial chain
	li	r10, 0
	# frame with 3 slots
	stdu	r10, -(STACK_FRAME_OVERHEAD + (SAVE_BCHAIN * 8))(r1)
	# preserve base
	std	r4, (STACK_FRAME_OVERHEAD + (SAVE_BASE * 8))(r1)
	# preserve orig stk ptr
	std	r11, (STACK_FRAME_OVERHEAD + (SAVE_STACK * 8))(r1)
	# preserve orig srr0
	std	r9, (STACK_FRAME_OVERHEAD + (SAVE_SRR0 * 8))(r1)
	# preserve orig srr1
	std	r8, (STACK_FRAME_OVERHEAD + (SAVE_SRR1 * 8))(r1)
	# preserve orig msr
	std	r7, (STACK_FRAME_OVERHEAD + (SAVE_MSR * 8))(r1)
	# preserve orig lr
	std	r0,  (STACK_FRAME_OVERHEAD + (SAVE_LR * 8))(r1)
	# preserve orig toc
	std	r2,  (STACK_FRAME_OVERHEAD + (SAVE_TOC * 8))(r1)

	LOADADDR(r2, ofh_start)	# get the address of any function
	add	r2, r2, r4	# add the base
	ld	r2, 8(r2)	# get the TOC for that funtion
	add	r2, r2, r4	# add the base

	bl	_ENTRY(ofh_handler)			# call handler

	ld	r4, (STACK_FRAME_OVERHEAD + (SAVE_BASE * 8))(r1)
	ld	r9, (STACK_FRAME_OVERHEAD + (SAVE_SRR0 * 8))(r1)
	ld	r8, (STACK_FRAME_OVERHEAD + (SAVE_SRR1 * 8))(r1)
	ld	r7, (STACK_FRAME_OVERHEAD + (SAVE_MSR * 8))(r1)
	ld	r2, (STACK_FRAME_OVERHEAD + (SAVE_TOC * 8))(r1)
	ld	r0, (STACK_FRAME_OVERHEAD + (SAVE_LR * 8))(r1)
	ld	r1, (STACK_FRAME_OVERHEAD + (SAVE_STACK * 8))(r1)

	LOADADDR(r5, _ofh_cih_orig_msr)
	add	r5, r5, r4
	mtsrr0 r5
	mtsrr1 r7
	rfid
	
_ofh_cih_orig_msr:
	mtsrr0	r9
	mtsrr1	r8
	mtlr	r0
	blr

_GLOBAL(get_base)
	mflr	r0
	bl	1f
1:	mflr	r5
	LOADADDR(r4,1b)
	subf	r3,r4,r5
	mtlr	r0
	blr
