/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <asm/asm_defns.h>

        .section .init.text, "ax", @progbits

        /*
         * Used during early boot, before alternatives have run and inlined
         * the appropriate instruction.  Called using the hypercall ABI.
         */
ENTRY(early_hypercall)
        cmpb    $0, early_hypercall_insn(%rip)
        jl      .L_setup
        je      1f

        vmmcall
        ret

1:      vmcall
        ret

.L_setup:
        /*
         * When setting up the first time around, all registers need
         * preserving.  Save the non-callee-saved ones.
         */
        push    %r11
        push    %r10
        push    %r9
        push    %r8
        push    %rdi
        push    %rsi
        push    %rdx
        push    %rcx
        push    %rax

        call    early_hypercall_setup

        pop     %rax
        pop     %rcx
        pop     %rdx
        pop     %rsi
        pop     %rdi
        pop     %r8
        pop     %r9
        pop     %r10
        pop     %r11

        jmp     early_hypercall

        .type early_hypercall, @function
        .size early_hypercall, . - early_hypercall
