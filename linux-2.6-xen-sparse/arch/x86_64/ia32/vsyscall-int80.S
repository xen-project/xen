/*
 * Code for the vsyscall page.  This version uses the old int $0x80 method.
 *
 * NOTE:
 * 1) __kernel_vsyscall _must_ be first in this page.
 * 2) there are alignment constraints on this stub, see vsyscall-sigreturn.S
 *    for details.
 */
#include <asm/ia32_unistd.h>
#include <asm/asm-offsets.h>

	.code32
	.text
	.section .text.vsyscall,"ax"
	.globl __kernel_vsyscall
	.type __kernel_vsyscall,@function
__kernel_vsyscall:
.LSTART_vsyscall:
	int $0x80
	ret
.LEND_vsyscall:
	.size __kernel_vsyscall,.-.LSTART_vsyscall
	.previous

	.section .eh_frame,"a",@progbits
.LSTARTFRAME:
	.long .LENDCIE-.LSTARTCIE
.LSTARTCIE:
	.long 0			/* CIE ID */
	.byte 1			/* Version number */
	.string "zR"		/* NUL-terminated augmentation string */
	.uleb128 1		/* Code alignment factor */
	.sleb128 -4		/* Data alignment factor */
	.byte 8			/* Return address register column */
	.uleb128 1		/* Augmentation value length */
	.byte 0x1b		/* DW_EH_PE_pcrel|DW_EH_PE_sdata4. */
	.byte 0x0c		/* DW_CFA_def_cfa */
	.uleb128 4
	.uleb128 4
	.byte 0x88		/* DW_CFA_offset, column 0x8 */
	.uleb128 1
	.align 4
.LENDCIE:

	.long .LENDFDE1-.LSTARTFDE1	/* Length FDE */
.LSTARTFDE1:
	.long .LSTARTFDE1-.LSTARTFRAME	/* CIE pointer */
	.long .LSTART_vsyscall-.	/* PC-relative start address */
	.long .LEND_vsyscall-.LSTART_vsyscall
	.uleb128 0			/* Augmentation length */
	.align 4
.LENDFDE1:
		
/*
 * Get the common code for the sigreturn entry points.
 */
#define SYSCALL_ENTER_KERNEL    int $0x80
#include "vsyscall-sigreturn.S"
