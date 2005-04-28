/*
 *
 *	Trampoline.S	Derived from Setup.S by Linus Torvalds
 *
 *	4 Jan 1997 Michael Chastain: changed to gnu as.
 *
 *	Entry: CS:IP point to the start of our code, we are 
 *	in real mode with no stack, but the rest of the 
 *	trampoline page to make our stack and everything else
 *	is a mystery.
 *
 *	On entry to trampoline_data, the processor is in real mode
 *	with 16-bit addressing and 16-bit data.  CS has some value
 *	and IP is zero.  Thus, data addresses need to be absolute
 *	(no relocation) and are taken with regard to r_base.
 */

#include <xen/config.h>
#include <public/xen.h>
#include <asm/page.h>

#ifdef CONFIG_SMP
        
.data

.code16

ENTRY(trampoline_data)
r_base = .
        mov	%cs, %ax	# Code and data in the same place
	mov	%ax, %ds

	movl	$0xA5A5A5A5, %ebx # Flag an SMP trampoline
	cli			# We should be safe anyway

	movl	$0xA5A5A5A5, trampoline_data - r_base

	lidt	idt_48 - r_base	# load idt with 0, 0
	lgdt	gdt_48 - r_base	# load gdt with whatever is appropriate

	xor	%ax, %ax
	inc	%ax		# protected mode (PE) bit
	lmsw	%ax		# into protected mode
	jmp	flush_instr
flush_instr:
#if defined(__x86_64__)
	ljmpl	$__HYPERVISOR_CS32, $0x100000 # 1MB
#else        
	ljmpl	$__HYPERVISOR_CS,   $0x100000 # 1MB
#endif

idt_48:
	.word	0			# idt limit = 0
	.word	0, 0			# idt base = 0L

gdt_48:
	.word	(LAST_RESERVED_GDT_ENTRY*8)+7
#ifdef __i386__
	.long	gdt_table-__PAGE_OFFSET
#else
	.long   0x100200 # gdt_table
#endif

ENTRY(trampoline_end)

#endif /* CONFIG_SMP */
