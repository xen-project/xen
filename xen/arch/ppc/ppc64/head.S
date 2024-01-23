/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <asm/asm-defns.h>
#include <asm/asm-offsets.h>
#include <asm/msr.h>

    .section .text.header, "ax", %progbits

FUNC(start)
    /*
     * NOTE: argument registers (r3-r9) must be preserved until the C entrypoint
     */
    FIXUP_ENDIAN

    /* set up the TOC pointer */
    bcl     20, 31, 1f
1:  mflr    %r12
    addis   %r2, %r12, .TOC.-1b@ha
    addi    %r2, %r2, .TOC.-1b@l

    /*
     * Copy Xen to physical address zero and jump to XEN_VIRT_START
     * (0xc000000000000000). This works because the hardware will ignore the top
     * four address bits when the MMU is off.
     */
    LOAD_REG_ADDR(%r14, _start)
    LOAD_IMM64(%r12, XEN_VIRT_START)

    /* If we're at the correct address, skip copy */
    cmpld   %r14, %r12
    beq     .L_correct_address

    /* Copy bytes until _end */
    LOAD_REG_ADDR(%r11, _end)
    addi    %r14, %r14, -8
    li      %r13, -8
.L_copy_xen:
    ldu     %r10, 8(%r14)
    stdu    %r10, 8(%r13)
    cmpld   %r14, %r11
    blt     .L_copy_xen

    /* Jump to XEN_VIRT_START */
    mtctr   %r12
    bctr
.L_correct_address:

    /* set up the initial stack */
    LOAD_REG_ADDR(%r1, cpu0_boot_stack + STACK_SIZE)
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
END(start)

FUNC(enable_mmu)
    mflr %r3
    mfmsr %r4

    /* enable instruction and data relocation (MMU) */
    ori %r4, %r4, (MSR_IR | MSR_DR)

    mtsrr0 %r3 /* return to caller after MMU enable */
    mtsrr1 %r4
    rfid
END(enable_mmu)
