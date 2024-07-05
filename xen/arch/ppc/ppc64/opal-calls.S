/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Adapted from Linux's arch/powerpc/boot/opal-calls.S
 *
 * Copyright (c) 2016 IBM Corporation.
 * Copyright Raptor Engineering, LLC
 */

#include <asm/asm-defns.h>
#include <asm/opal-api.h>
#include <asm/msr.h>

    .text

#define OPAL_CALL(name, token)  \
    .globl name;                \
name:                           \
    li      %r0, token;         \
    b       opal_call

 _GLOBAL_TOC(opal_call)
    /* Back up LR, CR, r2 in caller's stack frame */
    mflr    %r11
    mfcr    %r12
    std     %r2, 24(%r1)
    std     %r11, 16(%r1)
    stw     %r12, 8(%r1)

    /* Use r14 (non-volatile) to store the virtual address of opal_return_mmu */
    std     %r14, -8(%r1)
    stdu    %r1, -48(%r1)
    LOAD_REG_ADDR(%r14, opal_return_mmu)

    /*
     * Setup new MSR without LE or MMU. Original MSR will be preserved across
     * opal call in r13
     */
    mfmsr   %r13
    li      %r11, MSR_LE | MSR_IR | MSR_DR
    andc    %r12, %r13, %r11
    mthsrr1 %r12

    LOAD_REG_ADDR(%r11, opal_return_real)
    mtlr     %r11

    /* Load the opal call entry point and base */
    LOAD_REG_ADDR(%r11, opal)
    ld      %r12, OPAL_entry(%r11)
    ld      %r2, OPAL_base(%r11)
    mthsrr0 %r12
    hrfid

opal_return_real:
    /*
     * OPAL will always return to us in Big Endian mode. Since we are going
     * to restore the old MSR with the correct endianness and MMU status set, we
     * can avoid an unnecessary FIXUP_ENDIAN trampoline by just encoding the
     * required Big Endian instructions to restore the old MSR direclty.
     */
    .long 0xa64bbb7d /* mthsrr1 %r13 (Old MSR) */
    .long 0xa64bda7d /* mthsrr0 %r14 (Virtual address of opal_return_mmu) */
    .long 0x2402004c /* hrfid */

opal_return_mmu:
    /*
     * We're back in the correct endianness and MMU mode, restore registers
     * and return
     */
    addi    %r1, %r1, 48
    ld      %r14, -8(%r1)
    lwz     %r11, 8(%r1)
    ld      %r12, 16(%r1)
    ld      %r2, 24(%r1)
    mtcr    %r11
    mtlr    %r12

    blr

OPAL_CALL(opal_console_write, OPAL_CONSOLE_WRITE)
OPAL_CALL(opal_console_flush, OPAL_CONSOLE_FLUSH)
OPAL_CALL(opal_reinit_cpus, OPAL_REINIT_CPUS)

OPAL_CALL(opal_cec_power_down, OPAL_CEC_POWER_DOWN)
OPAL_CALL(opal_cec_reboot, OPAL_CEC_REBOOT)
OPAL_CALL(opal_poll_events, OPAL_POLL_EVENTS)
