/*
 * trap.S: Trap and world switch handlers
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
#include "machine.h"
#include "vm86.h"
#include "offsets.h"

/*
 * All processor exception/faults/interrupts end up here.
 *
 * On an exception/fault, the processor pushes CS:EIP, SS, ESP and an
 * optional error code onto the stack. The common_trap routine
 * below saves the processor context and transfers control to trap()
 * whose job it is to virtualize and pass on the trap.
 */
	.macro	TRAP_HANDLER trapno error
	.text
	.align	16
1:	.if	\error == 0
	pushl	$0			/* dummy error code */
	.endif
	pushl	$\trapno
	jmp	common_trap
	.section .rodata
	.long	1b
	.text
	.endm

	.section .rodata
	.code32
	.align	4
	.global	trap_handlers
trap_handlers:
	TRAP_HANDLER	0, 0	/* divide error */
	TRAP_HANDLER	1, 0	/* debug */
	TRAP_HANDLER	2, 0	/* NMI interrupt */
	TRAP_HANDLER	3, 0	/* breakpoint */
	TRAP_HANDLER	4, 0	/* overflow */
	TRAP_HANDLER	5, 0	/* BOUND range exceeded */
	TRAP_HANDLER	6, 0	/* invalid opcode */
	TRAP_HANDLER	7, 0	/* device not available */
	TRAP_HANDLER	8, 1	/* double fault */
	TRAP_HANDLER	9, 0	/* coprocessor segment overrun */
	TRAP_HANDLER	10, 1	/* invalid TSS */
	TRAP_HANDLER	11, 1	/* segment not present */
	TRAP_HANDLER	12, 1	/* stack-segment fault */
	TRAP_HANDLER	13, 1	/* general protection */
	TRAP_HANDLER	14, 1	/* page fault */
	TRAP_HANDLER	15, 0	/* reserved */
	TRAP_HANDLER	16, 0	/* FPU floating-point error */
	TRAP_HANDLER	17, 1	/* alignment check */
	TRAP_HANDLER	18, 0	/* machine check */
	TRAP_HANDLER	19, 0	/* SIMD floating-point error */
	TRAP_HANDLER	20, 0	/* reserved */
	TRAP_HANDLER	21, 0	/* reserved */
	TRAP_HANDLER	22, 0	/* reserved */
	TRAP_HANDLER	23, 0	/* reserved */
	TRAP_HANDLER	24, 0	/* reserved */
	TRAP_HANDLER	25, 0	/* reserved */
	TRAP_HANDLER	26, 0	/* reserved */
	TRAP_HANDLER	27, 0	/* reserved */
	TRAP_HANDLER	28, 0	/* reserved */
	TRAP_HANDLER	29, 0	/* reserved */
	TRAP_HANDLER	30, 0	/* reserved */
	TRAP_HANDLER	31, 0	/* reserved */
	TRAP_HANDLER	32, 0	/* irq 0 */
	TRAP_HANDLER	33, 0	/* irq 1 */
	TRAP_HANDLER	34, 0	/* irq 2 */
	TRAP_HANDLER	35, 0	/* irq 3 */
	TRAP_HANDLER	36, 0	/* irq 4 */
	TRAP_HANDLER	37, 0	/* irq 5 */
	TRAP_HANDLER	38, 0	/* irq 6 */
	TRAP_HANDLER	39, 0	/* irq 7 */
	TRAP_HANDLER	40, 0	/* irq 8 */
	TRAP_HANDLER	41, 0	/* irq 9 */
	TRAP_HANDLER	42, 0	/* irq 10 */
	TRAP_HANDLER	43, 0	/* irq 11 */
	TRAP_HANDLER	44, 0	/* irq 12 */
	TRAP_HANDLER	45, 0	/* irq 13 */
	TRAP_HANDLER	46, 0	/* irq 14 */
	TRAP_HANDLER	47, 0	/* irq 15 */

	.text
	.code32
	.align	16
common_trap:				/* common trap handler */
	pushl	%gs
	pushl	%fs
	pushl	%ds
	pushl	%es
	pushal

	movl	$DATA_SELECTOR, %eax	/* make sure these are sane */
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%esp, %ebp

	pushl	%ebp
	pushl	52(%ebp)
	pushl	48(%ebp)
	call	trap			/* trap(trapno, errno, regs) */
	addl	$12, %esp

trap_return:
	popal
	popl	%es
	popl	%ds
	popl	%fs
	popl	%gs
	addl	$8, %esp		/* skip trapno, errno */
	iret
	/* NOT REACHED */


/*
 * A world switch to real mode occured. The hypervisor saved the
 * executing context into "oldctx" and instantiated "newctx", which
 * gets us here. Here we push a stack frame that is compatible with
 * a trap frame (see above) so that we can handle this event as a
 * regular trap.
 */
	.text
	.align	16
	.globl	switch_to_real_mode
switch_to_real_mode:
	pushl	oldctx+VMX_ASSIST_CTX_GS_SEL /* 16 to 32-bit transition */
	pushl	oldctx+VMX_ASSIST_CTX_FS_SEL
	pushl	oldctx+VMX_ASSIST_CTX_DS_SEL
	pushl	oldctx+VMX_ASSIST_CTX_ES_SEL
	pushl	oldctx+VMX_ASSIST_CTX_SS_SEL
	pushl	oldctx+VMX_ASSIST_CTX_ESP
	pushl	oldctx+VMX_ASSIST_CTX_EFLAGS
	pushl	oldctx+VMX_ASSIST_CTX_CS_SEL
	pushl	oldctx+VMX_ASSIST_CTX_EIP
	pushl	$-1			/* trapno, errno */
	pushl	$-1
	pushl	%gs
	pushl	%fs
	pushl	%ds
	pushl	%es
	pushal

	movl	%esp, %ebp
	pushl	%ebp
	call	enter_real_mode
	addl	$4, %esp

	jmp	trap_return
	/* NOT REACHED */


/*
 * Switch to protected mode. At this point all the registers have
 * been reloaded by trap_return and all we have to do is cause a
 * world switch by turning on CR0.PE.
 */
	.text
	.align	16
	.globl	switch_to_protected_mode
switch_to_protected_mode:
	movl	oldctx+VMX_ASSIST_CTX_CR0, %esp
	movl	%esp, %cr0		/* actual world switch ! */

	/* NOT REACHED */
	pushl	$switch_failed
	call	panic
	jmp	.

	.data
	.align	4
switch_failed:
	.asciz	"World switch to protected mode failed\n"

