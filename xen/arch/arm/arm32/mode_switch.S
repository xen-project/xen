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
#include <asm/platforms/vexpress.h>
#include <asm/asm_defns.h>
#include <asm/gic.h>


/* XXX: Versatile Express specific code */
/* wake up secondary cpus */
.globl kick_cpus
kick_cpus:
        /* write start paddr to v2m sysreg FLAGSSET register */
        ldr   r0, =(V2M_SYS_MMIO_BASE)        /* base V2M sysreg MMIO address */
        dsb
        mov   r2, #0xffffffff
        str   r2, [r0, #(V2M_SYS_FLAGSCLR)]
        dsb
        ldr   r2, =start
        add   r2, r2, r10
        str   r2, [r0, #(V2M_SYS_FLAGSSET)]
        dsb
        /* send an interrupt */
        ldr   r0, =(GIC_BASE_ADDRESS + GIC_DR_OFFSET) /* base GICD MMIO address */
        mov   r2, #0x1
        str   r2, [r0, #(GICD_CTLR * 4)]      /* enable distributor */
        mov   r2, #0xfe0000
        str   r2, [r0, #(GICD_SGIR * 4)]      /* send IPI to everybody */
        dsb
        str   r2, [r0, #(GICD_CTLR * 4)]      /* disable distributor */
        mov   pc, lr


/* Get up a CPU into Hyp mode.  Clobbers r0-r3.
 *
 * Expects r12 == CPU number
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
        mov   r0, #GIC_BASE_ADDRESS
        add   r0, r0, #GIC_DR_OFFSET
        /* Disable the GIC distributor, on the boot CPU only */
        mov   r1, #0
        teq   r12, #0                /* Is this the boot CPU? */
        streq r1, [r0]
        /* Continuing ugliness: Set up the GIC so NS state owns interrupts,
         * The first 32 interrupts (SGIs & PPIs) must be configured on all
         * CPUs while the remainder are SPIs and only need to be done one, on
         * the boot CPU. */
        add   r0, r0, #0x80          /* GICD_IGROUP0 */
        mov   r2, #0xffffffff        /* All interrupts to group 1 */
        teq   r12, #0                /* Boot CPU? */
        str   r2, [r0]               /* Interrupts  0-31 (SGI & PPI) */
        streq r2, [r0, #4]           /* Interrupts 32-63 (SPI) */
        streq r2, [r0, #8]           /* Interrupts 64-95 (SPI) */
        /* Disable the GIC CPU interface on all processors */
        mov   r0, #GIC_BASE_ADDRESS
        add   r0, r0, #GIC_CR_OFFSET
        mov   r1, #0
        str   r1, [r0]
        /* Must drop priority mask below 0x80 before entering NS state */
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

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
