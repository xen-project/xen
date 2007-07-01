/*
 * head.S: VMXAssist runtime start off.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#include "vm86.h"
#include "machine.h"

/*
 * When a partition tries to mask off the CR0_PE bit a world
 * switch happens to the environment below. The magic indicates
 * that this is a valid context.
 */
	jmp	_start

	.align	8
	.long	VMXASSIST_MAGIC
	.long	newctx			/* new context */
	.long	oldctx			/* old context */

/*
 * This is the real start. Control was transfered to this point
 * with CR0_PE set and executing in some 32-bit segment. We call
 * main and setup our own environment.
 */
	.globl	_start
	.code32
_start:
	cli

	/* save register parameters to C land */

	/* clear bss */
	cld
	xorb	%al, %al
	movl	$_bbss, %edi
	movl	$_ebss, %ecx
	subl	%edi, %ecx
	rep	stosb

	movl	%edx, booting_cpu
	movl	%ebx, booting_vector

	/* make sure we are in a sane world */
	clts

	/* setup my own stack */
	movl	$stack_top, %esp
	movl	%esp, %ebp

	/* go ... */
	call    main
	jmp	halt

/*
 * Something bad happened, print invoking %eip and loop forever
 */
	.align	4
	.globl	halt
halt:
	push	$halt_msg
	call	printf
	cli
	jmp	.

	.data
halt_msg:
	.asciz	"Halt called from %%eip 0x%x\n"


/*
 * Our stack
 */
	.bss
	.align	8
	.globl	stack, stack_top
stack:
	.skip	STACK_SIZE
stack_top:

