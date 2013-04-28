/*
 * xen/arch/arm/head.S
 *
 * Start-of-day code for an ARMv8.
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2012 Citrix Systems.
 *
 * Based on ARMv7-A head.S by
 * Tim Deegan <tim@xen.org>
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

#define PT_PT     0xe7f /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_MEM    0xe7d /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=111 T=0 P=1 */
#define PT_DEV    0xe71 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=0 P=1 */
#define PT_DEV_L3 0xe73 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=1 P=1 */

#if (defined (EARLY_PRINTK)) && (defined (EARLY_PRINTK_INC))
#include EARLY_PRINTK_INC
#endif

/* Macro to print a string to the UART, if there is one.
 * Clobbers x0-x3. */
#ifdef EARLY_PRINTK
#define PRINT(_s)       \
        adr   x0, 98f ; \
        bl    puts    ; \
        b     99f     ; \
98:     .asciz _s     ; \
        .align 2      ; \
99:
#else /* EARLY_PRINTK */
#define PRINT(s)
#endif /* !EARLY_PRINTK */

        /*.aarch64*/

        /*
         * Kernel startup entry point.
         * ---------------------------
         *
         * The requirements are:
         *   MMU = off, D-cache = off, I-cache = on or off,
         *   x0 = physical address to the FDT blob.
         *
         * This must be the very first address in the loaded image.
         * It should be linked at XEN_VIRT_START, and loaded at any
         * 2MB-aligned address.  All of text+data+bss must fit in 2MB,
         * or the initial pagetable code below will need adjustment.
         */

        .global start
start:
        /*
         * DO NOT MODIFY. Image header expected by Linux boot-loaders.
         */
        b       real_start           /* branch to kernel start, magic */
        .long   0                    /* reserved */
        .quad   0                    /* Image load offset from start of RAM */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */

real_start:
        msr   DAIFSet, 0xf           /* Disable all interrupts */

        /* Save the bootloader arguments in less-clobberable registers */
        mov   x21, x0                /* x21 := DTB, physical address  */

        /* Find out where we are */
        ldr   x0, =start
        adr   x19, start             /* x19 := paddr (start) */
        sub   x20, x19, x0           /* x20 := phys-offset */

        /* Using the DTB in the .dtb section? */
#ifdef CONFIG_DTB_FILE
        ldr   x21, =_sdtb
        add   x21, x21, x20          /* x21 := paddr(DTB) */
#endif

        /* Are we the boot CPU? */
        mov   x22, #0                /* x22 := CPU ID */
        mrs   x0, mpidr_el1
        tbz   x0, 31, boot_cpu       /* Multiprocessor extension supported? */
        tbnz  x0, 30, boot_cpu       /* Uniprocessor system? */

        mov   x13, #(0xff << 24)
        bics  x22, x0, x13           /* Mask out flags to get CPU ID */
        b.eq  boot_cpu               /* If we're CPU 0, boot now */

        /* Non-boot CPUs wait here to be woken up one at a time. */
1:      dsb   sy
        ldr   x0, =smp_up_cpu        /* VA of gate */
        add   x0, x0, x20            /* PA of gate */
        ldr   x1, [x0]               /* Which CPU is being booted? */
        cmp   x1, x22                /* Is it us? */
        b.eq  2f
        wfe
        b     1b
2:

boot_cpu:
#ifdef EARLY_PRINTK
        ldr   x23, =EARLY_UART_BASE_ADDRESS /* x23 := UART base address */
        cbnz  x22, 1f
        bl    init_uart                 /* CPU 0 sets up the UART too */
1:      PRINT("- CPU ")
        mov   x0, x22
        bl    putn
        PRINT(" booting -\r\n")
#endif

        PRINT("- Current EL ")
        mrs   x0, CurrentEL
        bl    putn
        PRINT(" -\r\n")

        /* Are we in EL3 */
        mrs   x0, CurrentEL
        cmp   x0, #PSR_MODE_EL3t
        ccmp  x0, #PSR_MODE_EL3h, #0x4, ne
        b.eq  1f /* Yes */

        /* Are we in EL2 */
        cmp   x0, #PSR_MODE_EL2t
        ccmp  x0, #PSR_MODE_EL2h, #0x4, ne
        b.eq  2f /* Yes */

        /* Otherwise, it must have been EL0 or EL1 */
        PRINT("- CPU is not in EL3 or EL2 -\r\n")
        b     fail

1:      PRINT("- Started in EL3 -\r\n- Entering EL2 -\r\n")
        ldr   x1, =enter_el2_mode    /* VA of function */
        add   x1, x1, x20            /* PA of function */
        adr   x30, el2               /* Set return address for call */
        br    x1                     /* Call function */

2:      PRINT("- Started in EL2 mode -\r\n")

el2:
        /* Zero BSS On the boot CPU to avoid nasty surprises */
        cbnz  x22, skip_bss

        PRINT("- Zero BSS -\r\n")
        ldr   x0, =__bss_start       /* Load start & end of bss */
        ldr   x1, =__bss_end
        add   x0, x0, x20            /* Apply physical offset */
        add   x1, x1, x20

1:      str   xzr, [x0], #8
        cmp   x0, x1
        b.lo  1b

skip_bss:

        PRINT("- Setting up control registers -\r\n")

        /* Set up memory attribute type tables */
        ldr   x0, =MAIRVAL
        msr   mair_el2, x0

        /* Set up the HTCR:
         * PASize -- 4G
         * Top byte is used
         * PT walks use Outer-Shareable accesses,
         * PT walks are write-back, write-allocate in both cache levels,
         * Full 64-bit address space goes through this table. */
        ldr   x0, =0x80802500
        msr   tcr_el2, x0

        /* Set up the HSCTLR:
         * Exceptions in LE ARM,
         * Low-latency IRQs disabled,
         * Write-implies-XN disabled (for now),
         * D-cache disabled (for now),
         * I-cache enabled,
         * Alignment checking enabled,
         * MMU translation disabled (for now). */
        ldr   x0, =(HSCTLR_BASE|SCTLR_A)
        msr   SCTLR_EL2, x0

        /* Write Xen's PT's paddr into the HTTBR */
        ldr   x4, =boot_pgtable
        add   x4, x4, x20            /* x4 := paddr (xen_pagetable) */
        msr   TTBR0_EL2, x4

        /* Non-boot CPUs don't need to rebuild the pagetable */
        cbnz  x22, pt_ready

        ldr   x1, =boot_first
        add   x1, x1, x20            /* x1 := paddr (xen_first) */
        mov   x3, #PT_PT             /* x2 := table map of xen_first */
        orr   x2, x1, x3             /* (+ rights for linear PT) */
        str   x2, [x4, #0]           /* Map it in slot 0 */

        mov   x4, x1                 /* Next level into xen_first */

       /* console fixmap */
        ldr   x1, =xen_fixmap
        add   x1, x1, x20            /* x1 := paddr (xen_fixmap) */
        lsr   x2, x23, #12
        lsl   x2, x2, #12            /* 4K aligned paddr of UART */
        mov   x3, #PT_DEV_L3
        orr   x2, x2, x3             /* x2 := 4K dev map including UART */
        str   x2, [x1, #(FIXMAP_CONSOLE*8)] /* Map it in the first fixmap's slot */

        /* Build the baseline idle pagetable's first-level entries */
        ldr   x1, =xen_second
        add   x1, x1, x20            /* x1 := paddr (xen_second) */
        mov   x3, #PT_PT             /* x2 := table map of xen_second */
        orr   x2, x1, x3             /* (+ rights for linear PT) */
        str   x2, [x4, #0]           /* Map it in slot 0 */
        add   x2, x2, #0x1000
        str   x2, [x4, #8]           /* Map 2nd page in slot 1 */
        add   x2, x2, #0x1000
        str   x2, [x4, #16]          /* Map 3rd page in slot 2 */
        add   x2, x2, #0x1000
        str   x2, [x4, #24]          /* Map 4th page in slot 3 */

        /* Now set up the second-level entries */
        mov   x3, #PT_MEM
        orr   x2, x19, x3            /* x2 := 2MB normal map of Xen */
        orr   x4, xzr, x19, lsr #18
        str   x2, [x1, x4]           /* Map Xen there */
        ldr   x4, =start
        lsr   x4, x4, #18            /* Slot for vaddr(start) */
        str   x2, [x1, x4]           /* Map Xen there too */

        /* xen_fixmap pagetable */
        ldr   x2, =xen_fixmap
        add   x2, x2, x20            /* x2 := paddr (xen_fixmap) */
        mov   x3, #PT_PT
        orr   x2, x2, x3             /* x2 := table map of xen_fixmap */
        add   x4, x4, #8
        str   x2, [x1, x4]           /* Map it in the fixmap's slot */

        lsr   x2, x21, #21
        lsl   x2, x2, #21            /* 2MB-aligned paddr of DTB */
        mov   x3, #PT_MEM            /* x2 := 2MB RAM incl. DTB */
        orr   x2, x2, x3
        add   x4, x4, #8
        str   x2, [x1, x4]           /* Map it in the early boot slot */

pt_ready:
        PRINT("- Turning on paging -\r\n")

        ldr   x1, =paging            /* Explicit vaddr, not RIP-relative */
        mrs   x0, SCTLR_EL2
        orr   x0, x0, #SCTLR_M       /* Enable MMU */
        orr   x0, x0, #SCTLR_C       /* Enable D-cache */
        dsb   sy                     /* Flush PTE writes and finish reads */
        msr   SCTLR_EL2, x0          /* now paging is enabled */
        isb                          /* Now, flush the icache */
        br    x1                     /* Get a proper vaddr into PC */
paging:

        /* Use a virtual address to access the UART. */
        ldr   x23, =FIXMAP_ADDR(FIXMAP_CONSOLE)

        PRINT("- Ready -\r\n")

        /* The boot CPU should go straight into C now */
        cbz   x22, launch

        /* Non-boot CPUs need to move on to the relocated pagetables */
        ldr   x4, =boot_ttbr         /* VA of TTBR0_EL2 stashed by CPU 0 */
        add   x4, x4, x20            /* PA of it */
        ldr   x4, [x4]               /* Actual value */
        dsb   sy
        msr   TTBR0_EL2, x4
        dsb   sy
        isb
        tlbi  alle2
        dsb   sy                     /* Ensure completion of TLB flush */
        isb

        /* Non-boot CPUs report that they've got this far */
        ldr   x0, =ready_cpus
1:      ldaxr x1, [x0]               /*            { read # of ready CPUs } */
        add   x1, x1, #1             /* Atomically { ++                   } */
        stlxr w2, x1, [x0]           /*            { writeback            } */
        cbnz  w2, 1b
        dsb   sy
        dc    cvac, x0               /* Flush D-Cache */
        dsb   sy

        /* Here, the non-boot CPUs must wait again -- they're now running on
         * the boot CPU's pagetables so it's safe for the boot CPU to
         * overwrite the non-relocated copy of Xen.  Once it's done that,
         * and brought up the memory allocator, non-boot CPUs can get their
         * own stacks and enter C. */
1:      wfe
        dsb   sy
        ldr   x0, =smp_up_cpu
        ldr   x1, [x0]               /* Which CPU is being booted? */
        cmp   x1, x22                /* Is it us? */
        b.ne  1b

launch:
        ldr   x0, =init_stack        /* Find the boot-time stack */
        ldr   x0, [x0]
        add   x0, x0, #STACK_SIZE    /* (which grows down from the top). */
        sub   x0, x0, #CPUINFO_sizeof /* Make room for CPU save record */
        mov   sp, x0

        mov   x0, x20                /* Marshal args: - phys_offset */
        mov   x1, x21                /*               - FDT */
        mov   x2, x22                /*               - CPU ID */
        cbz   x22, start_xen         /* and disappear into the land of C */
        b     start_secondary        /* (to the appropriate entry point) */

/* Fail-stop
 * r0: string explaining why */
fail:   PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b

#ifdef EARLY_PRINTK

/* Bring up the UART.
 * x23: Early UART base address
 * Clobbers x0-x1 */
init_uart:
        early_uart_init x23, 0
        adr   x0, 1f
        b     puts
1:      .asciz "- UART enabled -\r\n"
        .align 4

/* Print early debug messages.
 * x0: Nul-terminated string to print.
 * x23: Early UART base address
 * Clobbers x0-x1 */
puts:
        early_uart_ready x23, 1
        ldrb  w1, [x0], #1           /* Load next char */
        cbz   w1, 1f                 /* Exit on nul */
        early_uart_transmit x23, w1
        b     puts
1:
        ret

/* Print a 32-bit number in hex.  Specific to the PL011 UART.
 * x0: Number to print.
 * x23: Early UART base address
 * Clobbers x0-x3 */
putn:
        adr   x1, hex
        mov   x3, #8
1:
        early_uart_ready x23, 2
        and   x2, x0, #0xf0000000    /* Mask off the top nybble */
        lsr   x2, x2, #28
        ldrb  w2, [x1, x2]           /* Convert to a char */
        early_uart_transmit x23, w2
        lsl   x0, x0, #4             /* Roll it through one nybble at a time */
        subs  x3, x3, #1
        b.ne  1b
        ret

hex:    .ascii "0123456789abcdef"
        .align 2

#else  /* EARLY_PRINTK */

init_uart:
.global early_puts
early_puts:
puts:
putn:   ret

#endif /* EARLY_PRINTK */
