/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <asm/asm-defns.h>
#include <asm/asm-offsets.h>

    .section .text.header, "ax", %progbits

ENTRY(start)
    /*
     * NOTE: argument registers (r3-r9) must be preserved until the C entrypoint
     */
    FIXUP_ENDIAN

    /* set up the TOC pointer */
    bcl     20, 31, 1f
1:  mflr    %r12
    addis   %r2, %r12, .TOC.-1b@ha
    addi    %r2, %r2, .TOC.-1b@l

    /* set up the initial stack */
    LOAD_REG_ADDR(%r1, cpu0_boot_stack)
    li      %r11, 0
    stdu    %r11, -STACK_FRAME_OVERHEAD(%r1)

    /* clear .bss */
    LOAD_REG_ADDR(%r14, __bss_start)
    LOAD_REG_ADDR(%r15, __bss_end)
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
