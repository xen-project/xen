/*
 * Relocate a kexec_image to its destination and call it.
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * Portions derived from Linux's arch/x86/kernel/relocate_kernel_64.S.
 *
 *   Copyright (C) 2002-2005 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */
#include <xen/config.h>
#include <xen/kimage.h>

#include <asm/asm_defns.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/machine_kexec.h>

        .section .text.kexec, "ax", @progbits
        .align PAGE_SIZE
        .code64

ENTRY(kexec_reloc)
        /* %rdi - code page maddr */
        /* %rsi - page table maddr */
        /* %rdx - indirection page maddr */
        /* %rcx - entry maddr (%rbp) */
        /* %r8 - flags */

        movq    %rcx, %rbp

        /* Setup stack. */
        leaq    (reloc_stack - kexec_reloc)(%rdi), %rsp

        /* Load reloc page table. */
        movq    %rsi, %cr3

        /* Jump to identity mapped code. */
        leaq    (identity_mapped - kexec_reloc)(%rdi), %rax
        jmpq    *%rax

identity_mapped:
        /*
         * Set cr0 to a known state:
         *  - Paging enabled
         *  - Alignment check disabled
         *  - Write protect disabled
         *  - No task switch
         *  - Don't do FP software emulation.
         *  - Protected mode enabled
         */
        movq    %cr0, %rax
        andl    $~(X86_CR0_AM | X86_CR0_WP | X86_CR0_TS | X86_CR0_EM), %eax
        orl     $(X86_CR0_PG | X86_CR0_PE), %eax
        movq    %rax, %cr0

        /*
         * Set cr4 to a known state:
         *  - physical address extension enabled
         */
        movl    $X86_CR4_PAE, %eax
        movq    %rax, %cr4

        movq    %rdx, %rdi
        call    relocate_pages

        /* Need to switch to 32-bit mode? */
        testq   $KEXEC_RELOC_FLAG_COMPAT, %r8
        jnz     call_32_bit

call_64_bit:
        /* Call the image entry point.  This should never return. */
        callq   *%rbp
        ud2

call_32_bit:
        /* Setup IDT. */
        lidt    compat_mode_idt(%rip)

        /* Load compat GDT. */
        leaq    compat_mode_gdt(%rip), %rax
        movq    %rax, (compat_mode_gdt_desc + 2)(%rip)
        lgdt    compat_mode_gdt_desc(%rip)

        /* Relocate compatibility mode entry point address. */
        leal    compatibility_mode(%rip), %eax
        movl    %eax, compatibility_mode_far(%rip)

        /* Enter compatibility mode. */
        ljmp    *compatibility_mode_far(%rip)

relocate_pages:
        /* %rdi - indirection page maddr */
        pushq   %rbx

        cld
        movq    %rdi, %rbx
        xorl    %edi, %edi
        xorl    %esi, %esi

next_entry: /* top, read another word for the indirection page */

        movq    (%rbx), %rcx
        addq    $8, %rbx
is_dest:
        testb   $IND_DESTINATION, %cl
        jz      is_ind
        movq    %rcx, %rdi
        andq    $PAGE_MASK, %rdi
        jmp     next_entry
is_ind:
        testb   $IND_INDIRECTION, %cl
        jz      is_done
        movq    %rcx, %rbx
        andq    $PAGE_MASK, %rbx
        jmp     next_entry
is_done:
        testb   $IND_DONE, %cl
        jnz     done
is_source:
        testb   $IND_SOURCE, %cl
        jz      is_zero
        movq    %rcx, %rsi      /* For every source page do a copy */
        andq    $PAGE_MASK, %rsi
        movl    $(PAGE_SIZE / 8), %ecx
        rep movsq
        jmp     next_entry
is_zero:
        testb   $IND_ZERO, %cl
        jz      next_entry
        movl    $(PAGE_SIZE / 8), %ecx  /* Zero the destination page. */
        xorl    %eax, %eax
        rep stosq
        jmp     next_entry
done:
        popq    %rbx
        ret

        .code32

compatibility_mode:
        /* Setup some sane segments. */
        movl    $0x0008, %eax
        movl    %eax, %ds
        movl    %eax, %es
        movl    %eax, %fs
        movl    %eax, %gs
        movl    %eax, %ss

        /* Disable paging and therefore leave 64 bit mode. */
        movl    %cr0, %eax
        andl    $~X86_CR0_PG, %eax
        movl    %eax, %cr0

        /* Disable long mode */
        movl    $MSR_EFER, %ecx
        rdmsr
        andl    $~EFER_LME, %eax
        wrmsr

        /* Clear cr4 to disable PAE. */
        xorl    %eax, %eax
        movl    %eax, %cr4

        /* Call the image entry point.  This should never return. */
        call    *%ebp
        ud2

        .align 4
compatibility_mode_far:
        .long 0x00000000             /* set in call_32_bit above */
        .word 0x0010

compat_mode_gdt_desc:
        .word (3*8)-1
        .quad 0x0000000000000000     /* set in call_32_bit above */

        .align 8
compat_mode_gdt:
        .quad 0x0000000000000000     /* null                              */
        .quad 0x00cf92000000ffff     /* 0x0008 ring 0 data                */
        .quad 0x00cf9a000000ffff     /* 0x0010 ring 0 code, compatibility */

compat_mode_idt:
        .word 0                      /* limit */
        .long 0                      /* base */

        /*
         * 16 words of stack are more than enough.
         */
        .fill 16,8,0
reloc_stack:

        .globl kexec_reloc_size
kexec_reloc_size:
        .long . - kexec_reloc
