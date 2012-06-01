/*
 * xen/arch/arm/mode_switch.S
 *
 * Start-of day code to take a CPU from Secure mode to Hyp mode.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011-2012 Citrix Systems.
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

/* Get up a CPU into Hyp mode.  Clobbers r0-r3.
 *
 * This code is specific to the VE model, and not intended to be used
 * on production systems.  As such it's a bit hackier than the main
 * boot code in head.S.  In future it will be replaced by better
 * integration with the bootloader/firmware so that Xen always starts
 * in Hyp mode. */

.globl enter_hyp_mode
enter_hyp_mode:
	mov   r3, lr                 /* Put return address in non-banked reg */
	cpsid aif, #0x16             /* Enter Monitor mode */
	mrc   CP32(r0, SCR)
	orr   r0, r0, #0x100         /* Set HCE */
	orr   r0, r0, #0xb1          /* Set SCD, AW, FW and NS */
	bic   r0, r0, #0xe           /* Clear EA, FIQ and IRQ */
	mcr   CP32(r0, SCR)
	/* Ugly: the system timer's frequency register is only
	 * programmable in Secure state.  Since we don't know where its
	 * memory-mapped control registers live, we can't find out the
	 * right frequency.  Use the VE model's default frequency here. */
	ldr   r0, =0x5f5e100         /* 100 MHz */
	mcr   CP32(r0, CNTFRQ)
	ldr   r0, =0x40c00           /* SMP, c11, c10 in non-secure mode */
	mcr   CP32(r0, NSACR)
	/* Continuing ugliness: Set up the GIC so NS state owns interrupts */
	mov   r0, #GIC_BASE_ADDRESS
	add   r0, r0, #GIC_DR_OFFSET
	mov   r1, #0
	str   r1, [r0]               /* Disable delivery in the distributor */
	add   r0, r0, #0x80          /* GICD_IGROUP0 */
	mov   r2, #0xffffffff        /* All interrupts to group 1 */
	str   r2, [r0]
	str   r2, [r0, #4]
	str   r2, [r0, #8]
	/* Must drop priority mask below 0x80 before entering NS state */
	mov   r0, #GIC_BASE_ADDRESS
	add   r0, r0, #GIC_CR_OFFSET
	ldr   r1, =0xff
	str   r1, [r0, #0x4]         /* -> GICC_PMR */
	/* Reset a few config registers */
	mov   r0, #0
	mcr   CP32(r0, FCSEIDR)
	mcr   CP32(r0, CONTEXTIDR)
	/* Allow non-secure access to coprocessors, FIQs, VFP and NEON */
	ldr   r1, =0x3fff            /* 14 CP bits set, all others clear */
	mcr   CP32(r1, NSACR)

	mrs   r0, cpsr               /* Copy the CPSR */
	add   r0, r0, #0x4           /* 0x16 (Monitor) -> 0x1a (Hyp) */
	msr   spsr_cxsf, r0          /* into the SPSR */
	movs  pc, r3                 /* Exception-return into Hyp mode */
