/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Adapted from Linux's arch/powerpc/kernel/entry_64.S, with the
 * following copyright notice:
 *
 *  PowerPC version
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *  Rewritten by Cort Dougan (cort@cs.nmt.edu) for PReP
 *    Copyright (C) 1996 Cort Dougan <cort@cs.nmt.edu>
 *  Adapted for Power Macintosh by Paul Mackerras.
 *  Low-level exception handlers and MMU support
 *  rewritten by Paul Mackerras.
 *    Copyright (C) 1996 Paul Mackerras.
 *  MPC8xx modifications Copyright (C) 1997 Dan Malek (dmalek@jlc.net).
 */

#include <asm/asm-offsets.h>
#include <asm/asm-defns.h>
#include <asm/msr.h>

/* size of minimum stack frame that can hold an entire cpu_user_regs struct */
#define STACK_SWITCH_FRAME_SIZE UREGS_sizeof

    .section .init.text, "ax", @progbits

ENTRY(enter_of)
    mflr    %r0
    std     %r0, 16(%r1)
    stdu    %r1, -STACK_SWITCH_FRAME_SIZE(%r1) /* Save SP and create stack space */

    /*
     * Because PROM is running in 32b mode, it clobbers the high order half
     * of all registers that it saves.  We therefore save those registers
     * PROM might touch to the stack.  (%r0, %r3-%r13 are caller saved)
     */
    SAVE_GPR(2, %r1)
    SAVE_GPR(13, %r1)
    SAVE_NVGPRS(%r1)
    mfcr    %r10
    mfmsr   %r11
    std     %r10, UREGS_cr(%r1)
    std     %r11, UREGS_msr(%r1)

    /* Put PROM address in SRR0 */
    mtsrr0  %r4

    /* Setup our trampoline return addr in LR */
    bcl     20, 31, .+4
0:  mflr    %r4
    addi    %r4, %r4, 1f - 0b
    mtlr    %r4

    /* Prepare a 32-bit mode big endian MSR */
    LOAD_IMM64(%r12, MSR_SF | MSR_LE)
    andc    %r11, %r11, %r12
    mtsrr1  %r11
    rfid

1:  /* Return from OF */
    FIXUP_ENDIAN

    /* Just make sure that %r1 top 32 bits didn't get corrupt by OF */
    rldicl  %r1, %r1, 0, 32

    /* Restore the MSR (back to 64 bits) */
    ld      %r0, UREGS_msr(%r1)
    mtmsrd  %r0
    isync

    /* Restore other registers */
    REST_GPR(2, %r1)
    REST_GPR(13, %r1)
    REST_NVGPRS(%r1)
    ld      %r4, UREGS_cr(%r1)
    mtcr    %r4

    addi    %r1, %r1, STACK_SWITCH_FRAME_SIZE
    ld      %r0, 16(%r1)
    mtlr    %r0
    blr

    .size enter_of, . - enter_of
    .type enter_of, %function
