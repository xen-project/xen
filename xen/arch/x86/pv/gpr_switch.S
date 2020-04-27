/*
 * GPR context switch between host and guest.
 * Used by IO-port-access emulation stub.
 *
 * Copyright (c) 2006, Novell, Inc.
 */

        .file __FILE__

#include <asm/asm_defns.h>

/* Load guest GPRs.  Parameter in %rdi, clobbers all registers. */
ENTRY(load_guest_gprs)
        movq  UREGS_rdx(%rdi), %rdx
        movq  UREGS_rax(%rdi), %rax
        movq  UREGS_rbx(%rdi), %rbx
        movq  UREGS_rsi(%rdi), %rsi
        movq  UREGS_rbp(%rdi), %rbp
        movq  UREGS_r8 (%rdi), %r8
        movq  UREGS_r12(%rdi), %r12
        movq  UREGS_r9 (%rdi), %r9
        movq  UREGS_r13(%rdi), %r13
        movq  UREGS_r10(%rdi), %r10
        movq  UREGS_r14(%rdi), %r14
        movq  UREGS_r11(%rdi), %r11
        movq  UREGS_r15(%rdi), %r15
        movq  UREGS_rcx(%rdi), %rcx
        movq  UREGS_rdi(%rdi), %rdi
        ret

        .size load_guest_gprs, . - load_guest_gprs
        .type load_guest_gprs, STT_FUNC


/* Save guest GPRs.  Parameter on the stack above the return address. */
ENTRY(save_guest_gprs)
        pushq %rdi
        movq  2*8(%rsp), %rdi
        movq  %rax, UREGS_rax(%rdi)
        popq        UREGS_rdi(%rdi)
        movq  %r15, UREGS_r15(%rdi)
        movq  %r11, UREGS_r11(%rdi)
        movq  %r14, UREGS_r14(%rdi)
        movq  %r10, UREGS_r10(%rdi)
        movq  %r13, UREGS_r13(%rdi)
        movq  %r9,  UREGS_r9 (%rdi)
        movq  %r12, UREGS_r12(%rdi)
        movq  %r8,  UREGS_r8 (%rdi)
        movq  %rbp, UREGS_rbp(%rdi)
        movq  %rsi, UREGS_rsi(%rdi)
        movq  %rbx, UREGS_rbx(%rdi)
        movq  %rdx, UREGS_rdx(%rdi)
        movq  %rcx, UREGS_rcx(%rdi)
        ret

        .size save_guest_gprs, . - save_guest_gprs
        .type save_guest_gprs, STT_FUNC
