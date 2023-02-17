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

        .file __FILE__

/* All contents of .text.kexec wants to be kept together. */
#undef CONFIG_CC_SPLIT_SECTIONS

#include <xen/kimage.h>

#include <asm/asm_defns.h>
#include <asm/cache.h>
#include <asm/msr-index.h>
#include <asm/page.h>
#include <asm/machine_kexec.h>

        .section .text.kexec, "ax", @progbits
        .code64

FUNC(kexec_reloc, PAGE_SIZE)
        /* %rdi - code page maddr */
        /* %rsi - page table maddr */
        /* %rdx - indirection page maddr */
        /* %rcx - entry maddr (%rbp) */
        /* %r8 - flags */

        movq    %rcx, %rbp

        /* Setup stack. */
        leaq    (.Lreloc_stack_base - kexec_reloc)(%rdi), %rsp

        /* Load reloc page table. */
        movq    %rsi, %cr3

        /* Jump to identity mapped code. */
        leaq    (.L_identity_mapped - kexec_reloc)(%rdi), %rax
        jmpq    *%rax

.L_identity_mapped:
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
        jnz     .L_call_32_bit

.L_call_64_bit:
        /* Call the image entry point.  This should never return. */
        callq   *%rbp
        ud2

.L_call_32_bit:
        /* Setup IDT. */
        lidt    compat_mode_idt(%rip)

        /* Load compat GDT. */
        leaq    compat_mode_gdt(%rip), %rax
        movq    %rax, (compat_mode_gdt_desc + 2)(%rip)
        lgdt    compat_mode_gdt_desc(%rip)

        /* Enter compatibility mode. */
        lea     compatibility_mode(%rip), %rax
        push    $0x10
        push    %rax
        lretq
END(kexec_reloc)

FUNC_LOCAL(relocate_pages)
        /* %rdi - indirection page maddr */
        pushq   %rbx

        cld
        movq    %rdi, %rbx
        xorl    %edi, %edi
        xorl    %esi, %esi

.L_next_entry: /* top, read another word for the indirection page */

        movq    (%rbx), %rcx
        addq    $8, %rbx
.L_is_dest:
        testb   $IND_DESTINATION, %cl
        jz      .L_is_ind
        movq    %rcx, %rdi
        andq    $PAGE_MASK, %rdi
        jmp     .L_next_entry
.L_is_ind:
        testb   $IND_INDIRECTION, %cl
        jz      .L_is_done
        movq    %rcx, %rbx
        andq    $PAGE_MASK, %rbx
        jmp     .L_next_entry
.L_is_done:
        testb   $IND_DONE, %cl
        jnz     .L_done
.L_is_source:
        testb   $IND_SOURCE, %cl
        jz      .L_is_zero
        movq    %rcx, %rsi      /* For every source page do a copy */
        andq    $PAGE_MASK, %rsi
        movl    $(PAGE_SIZE / 8), %ecx
        rep movsq
        jmp     .L_next_entry
.L_is_zero:
        testb   $IND_ZERO, %cl
        jz      .L_next_entry
        movl    $(PAGE_SIZE / 8), %ecx  /* Zero the destination page. */
        xorl    %eax, %eax
        rep stosq
        jmp     .L_next_entry
.L_done:
        popq    %rbx
        ret
END(relocate_pages)

        .code32

FUNC_LOCAL(compatibility_mode)
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
END(compatibility_mode)

        /* Separate code and data into into different cache lines */
        .balign L1_CACHE_BYTES

DATA_LOCAL(compat_mode_gdt_desc, 4)
        .word .Lcompat_mode_gdt_end - compat_mode_gdt -1
        .quad 0x0000000000000000     /* set in call_32_bit above */
END(compat_mode_gdt_desc)

DATA_LOCAL(compat_mode_gdt, 8)
        .quad 0x0000000000000000     /* null                              */
        .quad 0x00cf93000000ffff     /* 0x0008 ring 0 data                */
        .quad 0x00cf9b000000ffff     /* 0x0010 ring 0 code, compatibility */
.Lcompat_mode_gdt_end:
END(compat_mode_gdt)

DATA_LOCAL(compat_mode_idt)
        .word 0                      /* limit */
        .long 0                      /* base */
END(compat_mode_idt)

        /*
         * 16 words of stack are more than enough.
         */
DATA_LOCAL(reloc_stack, 8)
        .fill 16,8,0
.Lreloc_stack_base:
END(reloc_stack)
