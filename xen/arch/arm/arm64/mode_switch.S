/*
 * xen/arch/arm/arm64/mode_switch.S
 *
 * Start-of day code to take a CPU from EL3 to EL2. Largely taken from
 *       bootwrapper.
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2012 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/config.h>
#include <asm/page.h>
#include <asm/asm_defns.h>

/* Get up a CPU into EL2.  Clobbers x0-x3.
 *
 * Expects x22 == CPU number
 * Expects x30  == EL2 entry point
 *
 * This code is specific to the VE model, and not intended to be used
 * on production systems.  As such it's a bit hackier than the main
 * boot code in head.S.  In future it will be replaced by better
 * integration with the bootloader/firmware so that Xen always starts
 * at EL2.
 */

.globl enter_el2_mode
enter_el2_mode:
        mov     x0, #0x30                       // RES1
        orr     x0, x0, #(1 << 0)               // Non-secure EL1
        orr     x0, x0, #(1 << 8)               // HVC enable
        orr     x0, x0, #(1 << 10)              // 64-bit EL2
        msr     scr_el3, x0

        msr     cptr_el3, xzr                   // Disable copro. traps to EL3

        ldr     x0, =0x01800000                 // 24Mhz
        msr     cntfrq_el0, x0

        /*
         * Check for the primary CPU to avoid a race on the distributor
         * registers.
         */
        cbnz    x22, 1f

        ldr     x1, =(GIC_BASE_ADDRESS+GIC_DR_OFFSET) // GICD_CTLR
        mov     w0, #3                          // EnableGrp0 | EnableGrp1
        str     w0, [x1]

1:      ldr     x1, =(GIC_BASE_ADDRESS+GIC_DR_OFFSET+0x80) // GICD_IGROUPR
        mov     w0, #~0                         // Grp1 interrupts
        str     w0, [x1], #4
        b.ne    2f                              // Only local interrupts for secondary CPUs
        str     w0, [x1], #4
        str     w0, [x1], #4

2:      ldr     x1, =(GIC_BASE_ADDRESS+GIC_CR_OFFSET) // GICC_CTLR
        ldr     w0, [x1]
        mov     w0, #3                          // EnableGrp0 | EnableGrp1
        str     w0, [x1]

        mov     w0, #1 << 7                     // allow NS access to GICC_PMR
        str     w0, [x1, #4]                    // GICC_PMR

        msr     sctlr_el2, xzr

        /*
         * Prepare the switch to the EL2_SP1 mode from EL3
         */
        msr     elr_el3, x30                    // Return to desired function
        mov     x1, #0x3c9                      // EL2_SP1 | D | A | I | F
        msr     spsr_el3, x1
        eret
