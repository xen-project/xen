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
#ifdef TEST
	.byte 0x55, 0xaa
	.byte 0x80
	.code16
	jmp	_start16
#else
	jmp	_start
#endif

	.align	8
	.long	VMXASSIST_MAGIC
	.long	newctx			/* new context */
	.long	oldctx			/* old context */

#ifdef TEST
/*
 * We are running in 16-bit. Get into the protected mode as soon as
 * possible. We use our own (minimal) GDT to get started.
 *
 * ROM is a misnomer as this code isn't really rommable (although it
 * only requires a few changes) but it does live in a BIOS ROM segment.
 * This code allows me to debug vmxassists under (a modified version of)
 * Bochs and load it as a "optromimage1".
 */
	.code16
	.globl	_start16
_start16:
        cli

        /* load our own global descriptor table */
        data32 addr32 lgdt %cs:(rom_gdtr - TEXTADDR)

        /* go to protected mode */
        movl    %cr0, %eax
        orl     $CR0_PE, %eax
        movl    %eax, %cr0
        data32  ljmp $0x08, $1f

        .align  32
        .globl  rom_gdt
rom_gdt:
        .word   0, 0            /* 0x00: reserved */
        .byte   0, 0, 0, 0

        .word   0xFFFF, 0       /* 0x08: CS 32-bit */
        .byte   0, 0x9A, 0xCF, 0

        .word   0xFFFF, 0       /* 0x10: CS 32-bit */
        .byte   0, 0x92, 0xCF, 0
rom_gdt_end:

        .align  4
        .globl  rom_gdtr
rom_gdtr:
        .word   rom_gdt_end - rom_gdt - 1
        .long   rom_gdt

        .code32
1:
        /* welcome to the 32-bit world */
        movw    $0x10, %ax
        movw    %ax, %ds
        movw    %ax, %es
        movw    %ax, %ss
        movw    %ax, %fs
        movw    %ax, %gs

        /* enable Bochs debug facilities */
        movw    $0x8A00, %dx
        movw    $0x8A00, %ax
        outw    %ax, (%dx)

	jmp	_start
#endif /* TEST */

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
#ifdef TEST
	xorl	%edx, %edx
#endif
	movl	%edx, booting_cpu
	movl	%ebx, booting_vector

	/* clear bss */
	cld
	xorb	%al, %al
	movl	$_bbss, %edi
	movl	$_ebss, %ecx
	subl	%edi, %ecx
	rep	stosb

	/* make sure we are in a sane world */
	clts

	/* setup my own stack */
	movl	$stack_top - 4*4, %esp
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
#ifdef TEST
        movw    $0x8A00, %dx
        movw    $0x8AE0, %ax
        outw    %ax, (%dx)
#endif
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

