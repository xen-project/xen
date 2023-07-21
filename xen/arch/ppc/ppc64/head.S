/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <asm/asm-defns.h>

    .section .text.header, "ax", %progbits

ENTRY(start)
    /*
     * NOTE: argument registers (r3-r9) must be preserved until the C entrypoint
     */
    FIXUP_ENDIAN

    /* set up the TOC pointer */
    LOAD_IMM32(%r2, .TOC.)

    /* set up the initial stack */
    LOAD_IMM32(%r1, cpu0_boot_stack)
    li      %r11, 0
    stdu    %r11, -STACK_FRAME_OVERHEAD(%r1)

    /* clear .bss */
    LOAD_IMM32(%r14, __bss_start)
    LOAD_IMM32(%r15, __bss_end)
1:
    std     %r11, 0(%r14)
    addi    %r14, %r14, 8
    cmpld   %r14, %r15
    blt     1b

    /* call the C entrypoint */
    bl      start_xen

    /* should never return */
    trap

    .size start, . - start
    .type start, %function
