/*
 * xen/arch/arm/head.S
 *
 * Start-of-day code for an ARMv7-A with virt extensions.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
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

#include <asm/page.h>
#include <asm/early_printk.h>

#define ZIMAGE_MAGIC_NUMBER 0x016f2818

#if defined(CONFIG_EARLY_PRINTK) && defined(CONFIG_EARLY_PRINTK_INC)
#include CONFIG_EARLY_PRINTK_INC
#endif

/*
 * Common register usage in this file:
 *   r0  -
 *   r1  -
 *   r2  -
 *   r3  -
 *   r4  -
 *   r5  -
 *   r6  -
 *   r7  -
 *   r8  - DTB address (boot CPU only)
 *   r9  - paddr(start)
 *   r10 - phys offset
 *   r11 - UART address
 *   r12 - Temporary mapping created
 *   r13 - SP
 *   r14 - LR
 *   r15 - PC
 */

        .section .text.header, "ax", %progbits
        .arm

        /*
         * This must be the very first address in the loaded image.
         * It should be linked at XEN_VIRT_START, and loaded at any
         * 4K-aligned address.
         */
GLOBAL(start)
        /*
         * zImage magic header, see:
         * http://www.simtec.co.uk/products/SWLINUX/files/booting_article.html#d0e309
         */
        .rept 8
        mov   r0, r0
        .endr
        b     past_zImage

        .word ZIMAGE_MAGIC_NUMBER    /* Magic numbers to help the loader */
        .word 0x00000000             /* absolute load/run zImage address or
                                      * 0 for PiC */
        .word (_end - start)         /* zImage end address */

past_zImage:
        cpsid aif                    /* Disable all interrupts */

        /* Save the bootloader arguments in less-clobberable registers */
        mov   r8, r2                 /* r8 := DTB base address */

        /* Find out where we are */
        mov_w r0, start
        adr   r9, start              /* r9  := paddr (start) */
        sub   r10, r9, r0            /* r10 := phys-offset */

        /* Using the DTB in the .dtb section? */
.ifnes CONFIG_DTB_FILE,""
        adr_l r8, _sdtb
.endif

        /* Initialize the UART if earlyprintk has been enabled. */
#ifdef CONFIG_EARLY_PRINTK
        bl    init_uart
#endif
        PRINT("- Boot CPU booting -\r\n")

        bl    check_cpu_mode
        bl    cpu_init

        mov_w lr, primary_switched
        b     enable_boot_cpu_mm

primary_switched:
        bl    zero_bss
        PRINT("- Ready -\r\n")
        /* Setup the arguments for start_xen and jump to C world */
        mov   r0, r8                 /* r0 := paddr(FDT) */
        mov_w r1, start_xen
        b     launch
ENDPROC(start)

GLOBAL(init_secondary)
        cpsid aif                    /* Disable all interrupts */

        /* Find out where we are */
        mov_w r0, start
        adr   r9, start              /* r9  := paddr (start) */
        sub   r10, r9, r0            /* r10 := phys-offset */

        mrc   CP32(r1, MPIDR)
        bic   r7, r1, #(~MPIDR_HWID_MASK) /* Mask out flags to get CPU ID */

        adr_l r0, smp_up_cpu
        dsb
2:      ldr   r1, [r0]
        cmp   r1, r7
        beq   1f
        wfe
        b     2b
1:

#ifdef CONFIG_EARLY_PRINTK
        mov_w r11, CONFIG_EARLY_UART_BASE_ADDRESS   /* r11 := UART base address */
        PRINT("- CPU ")
        print_reg r7
        PRINT(" booting -\r\n")
#endif
        bl    check_cpu_mode
        bl    cpu_init

        mov_w lr, secondary_switched
        b     enable_secondary_cpu_mm
secondary_switched:
        PRINT("- Ready -\r\n")
        /* Jump to C world */
        mov_w r1, start_secondary
        b     launch
ENDPROC(init_secondary)

/*
 * Check if the CPU supports virtualization extensions and has been booted
 * in Hypervisor mode.
 *
 * This function will never return when the CPU doesn't support
 * virtualization extensions or is booted in another mode than
 * Hypervisor mode.
 *
 * Clobbers r0 - r3
 */
check_cpu_mode:
        /* Check that this CPU has Hyp mode */
        mrc   CP32(r0, ID_PFR1)
        and   r0, r0, #0xf000        /* Bits 12-15 define virt extensions */
        teq   r0, #0x1000            /* Must == 0x1 or may be incompatible */
        beq   1f
        PRINT("- CPU doesn't support the virtualization extensions -\r\n")
        b     fail
1:

        /* Check that we're already in Hyp mode */
        mrs   r0, cpsr
        and   r0, r0, #0x1f          /* Mode is in the low 5 bits of CPSR */
        teq   r0, #0x1a              /* Hyp Mode? */
        moveq pc, lr                 /* Yes, return */

        /* OK, we're boned. */
        PRINT("- Xen must be entered in NS Hyp mode -\r\n")
        PRINT("- Please update the bootloader -\r\n")
        b     fail
ENDPROC(check_cpu_mode)

/*
 * Zero BSS
 *
 * Clobbers r0 - r3
 */
zero_bss:
        PRINT("- Zero BSS -\r\n")
        mov_w r0, __bss_start        /* r0 := vaddr(__bss_start) */
        mov_w r1, __bss_end          /* r1 := vaddr(__bss_end)   */
        cmp   r1, r0
        beq   skip_bss

        mov   r2, #0
1:      str   r2, [r0], #4
        cmp   r0, r1
        blo   1b

skip_bss:
        mov   pc, lr
ENDPROC(zero_bss)

cpu_init:
        PRINT("- Setting up control registers -\r\n")

        mov   r5, lr                       /* r5 := return address */

        /* Get processor specific proc info into r1 */
        bl    __lookup_processor_type
        teq   r1, #0
        bne   1f
        mov   r4, r0
        PRINT("- Missing processor info: ")
        print_reg r4
        PRINT(" -\r\n")
        b     cpu_init_done
1:
        /* Jump to cpu_init */
        ldr   r1, [r1, #PROCINFO_cpu_init]  /* r1 := vaddr(init func) */
        adr   lr, cpu_init_done             /* Save return address */
        add   pc, r1, r10                   /* Call paddr(init func) */

cpu_init_done:
        /* Set up memory attribute type tables */
        mov_w r0, MAIR0VAL
        mov_w r1, MAIR1VAL
        mcr   CP32(r0, HMAIR0)
        mcr   CP32(r1, HMAIR1)

        /*
         * Set up the HTCR:
         * PT walks use Inner-Shareable accesses,
         * PT walks are write-back, write-allocate in both cache levels,
         * Full 32-bit address space goes through this table.
         */
        mov_w r0, (TCR_RES1|TCR_SH0_IS|TCR_ORGN0_WBWA|TCR_IRGN0_WBWA|TCR_T0SZ(0))
        mcr   CP32(r0, HTCR)

        mov_w r0, HSCTLR_SET
        mcr   CP32(r0, HSCTLR)
        isb

        mov   pc, r5                        /* Return address is in r5 */
ENDPROC(cpu_init)

/*
 * Setup the initial stack and jump to the C world
 *
 * Inputs:
 *   r0 : Argument 0 of the C function to call
 *   r1 : C entry point
 *
 * Clobbers r3
 */
launch:
        mov_w r3, init_data
        add   r3, #INITINFO_stack    /* Find the boot-time stack */
        ldr   sp, [r3]
        add   sp, #STACK_SIZE        /* (which grows down from the top). */
        sub   sp, #CPUINFO_sizeof    /* Make room for CPU save record */

        /* Jump to C world */
       bx    r1
ENDPROC(launch)

/* Fail-stop */
fail:   PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b
ENDPROC(fail)

#ifdef CONFIG_EARLY_PRINTK
/*
 * Initialize the UART. Should only be called on the boot CPU.
 *
 * Output:
 *  r11: Early UART base physical address
 *
 * Clobbers r0 - r3
 */
init_uart:
        mov_w r11, CONFIG_EARLY_UART_BASE_ADDRESS
#ifdef CONFIG_EARLY_UART_INIT
        early_uart_init r11, r1, r2
#endif
        PRINT("- UART enabled -\r\n")
        mov   pc, lr
ENDPROC(init_uart)

/*
 * Print early debug messages.
 * Note: This function must be called from assembly.
 * r0: Nul-terminated string to print.
 * r11: Early UART base address
 * Clobbers r0-r1
 */
ENTRY(asm_puts)
        early_uart_ready r11, r1
        ldrb  r1, [r0], #1           /* Load next char */
        teq   r1, #0                 /* Exit on nul */
        moveq pc, lr
        early_uart_transmit r11, r1
        b asm_puts
ENDPROC(asm_puts)

/*
 * Print a 32-bit number in hex.
 * Note: This function must be called from assembly.
 * r0: Number to print.
 * r11: Early UART base address
 * Clobbers r0-r3
 */
ENTRY(asm_putn)
        adr_l r1, hex
        mov   r3, #8
1:
        early_uart_ready r11, r2
        and   r2, r0, #0xf0000000    /* Mask off the top nybble */
        ldrb  r2, [r1, r2, lsr #28]  /* Convert to a char */
        early_uart_transmit r11, r2
        lsl   r0, #4                 /* Roll it through one nybble at a time */
        subs  r3, r3, #1
        bne   1b
        mov   pc, lr
ENDPROC(asm_putn)

RODATA_SECT(.rodata.idmap, hex, "0123456789abcdef")

#endif /* CONFIG_EARLY_PRINTK */

/* This provides a C-API version of __lookup_processor_type */
ENTRY(lookup_processor_type)
        stmfd sp!, {r4, lr}
        bl    __lookup_processor_type
        mov r0, r1
        ldmfd sp!, {r4, pc}

/*
 * Read processor ID register (CP#15, CR0), and Look up in the linker-built
 * supported processor list.
 *
 * Returns:
 * r0: CPUID
 * r1: proc_info pointer
 * Clobbers r2-r4
 */
__lookup_processor_type:
        mrc   CP32(r0, MIDR)                /* r0 := our cpu id */
        adr_l r1, __proc_info_start
        adr_l r2, __proc_info_end
1:      ldr   r3, [r1, #PROCINFO_cpu_mask]
        and   r4, r0, r3                    /* r4 := our cpu id with mask */
        ldr   r3, [r1, #PROCINFO_cpu_val]   /* r3 := cpu val in current proc info */
        teq   r4, r3
        beq   2f                            /* Match => exit, or try next proc info */
        add   r1, r1, #PROCINFO_sizeof
        cmp   r1, r2
        blo   1b
        /* We failed to find the proc_info, return NULL */
        mov   r1, #0
2:
        mov   pc, lr
ENDPROC(__lookup_processor_type)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
