/*
 * GPR context switch between host and guest.
 * Used by IO-port-access emulation stub.
 *
 * Copyright (c) 2006, Novell, Inc.
 */

        .file __FILE__

#include <asm/asm_defns.h>

ENTRY(host_to_guest_gpr_switch)
        movq  (%rsp), %rcx
        movq  %rdi, (%rsp)
        movq  UREGS_rdx(%rdi), %rdx
        pushq %rbx
        movq  UREGS_rax(%rdi), %rax
        movq  UREGS_rbx(%rdi), %rbx
        pushq %rbp
        movq  UREGS_rsi(%rdi), %rsi
        movq  UREGS_rbp(%rdi), %rbp
        pushq %r12
        movq  UREGS_r8(%rdi), %r8
        movq  UREGS_r12(%rdi), %r12
        pushq %r13
        movq  UREGS_r9(%rdi), %r9
        movq  UREGS_r13(%rdi), %r13
        pushq %r14
        movq  UREGS_r10(%rdi), %r10
        movq  UREGS_r14(%rdi), %r14
        pushq %r15
        movq  UREGS_r11(%rdi), %r11
        movq  UREGS_r15(%rdi), %r15
        pushq %rcx /* dummy push, filled by guest_to_host_gpr_switch pointer */
        pushq %rcx
        leaq  guest_to_host_gpr_switch(%rip),%rcx
        movq  %rcx,8(%rsp)
        movq  UREGS_rcx(%rdi), %rcx
        movq  UREGS_rdi(%rdi), %rdi
        ret

ENTRY(guest_to_host_gpr_switch)
        pushq %rdi
        movq  7*8(%rsp), %rdi
        movq  %rax, UREGS_rax(%rdi)
        popq  UREGS_rdi(%rdi)
        movq  %r15, UREGS_r15(%rdi)
        movq  %r11, UREGS_r11(%rdi)
        popq  %r15
        movq  %r14, UREGS_r14(%rdi)
        movq  %r10, UREGS_r10(%rdi)
        popq  %r14
        movq  %r13, UREGS_r13(%rdi)
        movq  %r9, UREGS_r9(%rdi)
        popq  %r13
        movq  %r12, UREGS_r12(%rdi)
        movq  %r8, UREGS_r8(%rdi)
        popq  %r12
        movq  %rbp, UREGS_rbp(%rdi)
        movq  %rsi, UREGS_rsi(%rdi)
        popq  %rbp
        movq  %rbx, UREGS_rbx(%rdi)
        movq  %rdx, UREGS_rdx(%rdi)
        popq  %rbx
        movq  %rcx, UREGS_rcx(%rdi)
        popq  %rcx
        ret
