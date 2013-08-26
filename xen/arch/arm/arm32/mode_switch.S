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
#include <asm/platforms/exynos5.h>
#include <asm/asm_defns.h>
#include <asm/gic.h>

/* Wake up secondary cpus
 * This code relies on Machine ID and only works for Vexpress and the Arndale
 * TODO: Move this code either later (via platform specific desc) or in a bootwrapper
 * r5: Machine ID
 * Clobber r0 r2 */
GLOBAL(kick_cpus)
        ldr   r0, =MACH_TYPE_SMDK5250
        teq   r5, r0                          /* Are we running on the arndale? */
        beq   kick_cpus_arndale
        /* otherwise versatile express */
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
        ldr   r2, =V2M_GIC_BASE_ADDRESS       /* r2 := VE gic base address */
        b     kick_cpus_sgi
kick_cpus_arndale:
        /* write start paddr to CPU 1 sysreg register */
        ldr   r0, =(S5P_PA_SYSRAM)
        ldr   r2, =start
        add   r2, r2, r10
        str   r2, [r0]
        dsb
        ldr   r2, =EXYNOS5_GIC_BASE_ADDRESS   /* r2 := Exynos5 gic base address */
kick_cpus_sgi:
        /* send an interrupt */
        ldr   r0, =GIC_DR_OFFSET              /* GIC distributor offset */
        add   r0, r2                          /* r0 := r0 + gic base address */
        mov   r2, #0x1
        str   r2, [r0, #(GICD_CTLR * 4)]      /* enable distributor */
        mov   r2, #0xfe0000
        str   r2, [r0, #(GICD_SGIR * 4)]      /* send IPI to everybody, SGI0 = Event check */
        dsb
        str   r2, [r0, #(GICD_CTLR * 4)]      /* disable distributor */
        mov   pc, lr


/* Get up a CPU into Hyp mode.  Clobbers r0-r3.
 *
 * r5: Machine ID
 * r12: CPU number
 *
 * This code is specific to the VE model/Arndale, and not intended to be used
 * on production systems.  As such it's a bit hackier than the main
 * boot code in head.S.  In future it will be replaced by better
 * integration with the bootloader/firmware so that Xen always starts
 * in Hyp mode.
 * Clobber r0 - r4 */
GLOBAL(enter_hyp_mode)
        mov   r3, lr                 /* Put return address in non-banked reg */
        cpsid aif, #0x16             /* Enter Monitor mode */
        mrc   CP32(r0, SCR)
        orr   r0, r0, #0x100         /* Set HCE */
        orr   r0, r0, #0xb1          /* Set SCD, AW, FW and NS */
        bic   r0, r0, #0xe           /* Clear EA, FIQ and IRQ */
        mcr   CP32(r0, SCR)

        ldr   r2, =MACH_TYPE_SMDK5250   /* r4 := Arndale machine ID */
        /* By default load Arndale defaults values */
        ldr   r0, =EXYNOS5_TIMER_FREQUENCY  /* r0 := timer's frequency */
        ldr   r1, =EXYNOS5_GIC_BASE_ADDRESS /* r1 := GIC base address */
        /* If it's not the Arndale machine ID, load VE values */
        teq   r5, r2
        ldrne r0, =V2M_TIMER_FREQUENCY
        ldrne r1, =V2M_GIC_BASE_ADDRESS

        /* Ugly: the system timer's frequency register is only
         * programmable in Secure state.  Since we don't know where its
         * memory-mapped control registers live, we can't find out the
         * right frequency. */
        mcr   CP32(r0, CNTFRQ)

        mrc   CP32(r0,NSACR)
        ldr   r4, =0x3fff            /* Allow access to all co-processors in NS mode */
        orr   r0, r0, r4
        orr   r0, r0, #(1<<18)       /* CA7/CA15: Allow access to ACTLR.SMP in NS mode */
        mcr   CP32(r0, NSACR)

        add   r0, r1, #GIC_DR_OFFSET
        /* Disable the GIC distributor, on the boot CPU only */
        mov   r4, #0
        teq   r12, #0                /* Is this the boot CPU? */
        streq r4, [r0]
        /* Continuing ugliness: Set up the GIC so NS state owns interrupts,
         * The first 32 interrupts (SGIs & PPIs) must be configured on all
         * CPUs while the remainder are SPIs and only need to be done one, on
         * the boot CPU. */
        add   r0, r0, #0x80          /* GICD_IGROUP0 */
        mov   r2, #0xffffffff        /* All interrupts to group 1 */
        str   r2, [r0]               /* Interrupts  0-31 (SGI & PPI) */
        teq   r12, #0                /* Boot CPU? */
        bne   skip_spis              /* Don't route SPIs on secondary CPUs */

        add   r4, r1, #GIC_DR_OFFSET
        ldr   r4, [r4, #4]            /* r4 := Interrupt Controller Type Reg */
        and   r4, r4, #GICD_TYPE_LINES /* r4 := number of SPIs */
1:      teq   r4, #0
        beq   skip_spis
        add   r0, r0, #4             /* Go to the new group */
        str   r2, [r0]               /* Update the group */
        sub  r4, r4, #1
        b     1b
skip_spis:
        /* Disable the GIC CPU interface on all processors */
        add   r0, r1, #GIC_CR_OFFSET
        mov   r1, #0
        str   r1, [r0]
        /* Must drop priority mask below 0x80 before entering NS state */
        ldr   r1, =0xff
        str   r1, [r0, #0x4]         /* -> GICC_PMR */
        /* Reset a few config registers */
        mov   r0, #0
        mcr   CP32(r0, FCSEIDR)
        mcr   CP32(r0, CONTEXTIDR)

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
