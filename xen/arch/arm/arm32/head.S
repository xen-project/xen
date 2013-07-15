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

#include <asm/config.h>
#include <asm/page.h>
#include <asm/processor-ca15.h>
#include <asm/processor-ca7.h>
#include <asm/asm_defns.h>

#define ZIMAGE_MAGIC_NUMBER 0x016f2818

#define PT_PT     0xe7f /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_MEM    0xe7d /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=111 T=0 P=1 */
#define PT_DEV    0xe71 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=0 P=1 */
#define PT_DEV_L3 0xe73 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=1 P=1 */

#define PT_UPPER(x) (PT_##x & 0xf00)
#define PT_LOWER(x) (PT_##x & 0x0ff)

#if (defined (EARLY_PRINTK)) && (defined (EARLY_PRINTK_INC))
#include EARLY_PRINTK_INC
#endif

/* Macro to print a string to the UART, if there is one.
 * Clobbers r0-r3. */
#ifdef EARLY_PRINTK
#define PRINT(_s)       \
        adr   r0, 98f ; \
        bl    puts    ; \
        b     99f     ; \
98:     .asciz _s     ; \
        .align 2      ; \
99:
#else /* EARLY_PRINTK */
#define PRINT(s)
#endif /* !EARLY_PRINTK */

        .arm

        /* This must be the very first address in the loaded image.
         * It should be linked at XEN_VIRT_START, and loaded at any
         * 2MB-aligned address.  All of text+data+bss must fit in 2MB,
         * or the initial pagetable code below will need adjustment. */
        .global start
start:

        /* zImage magic header, see:
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
        mov   r5, r1                 /* r5: ARM-linux machine type */
        mov   r8, r2                 /* r8 := DTB base address */

        /* Find out where we are */
        ldr   r0, =start
        adr   r9, start              /* r9  := paddr (start) */
        sub   r10, r9, r0            /* r10 := phys-offset */

        /* Using the DTB in the .dtb section? */
#ifdef CONFIG_DTB_FILE
        ldr   r8, =_sdtb
        add   r8, r10                /* r8 := paddr(DTB) */
#endif

        /* Are we the boot CPU? */
        mov   r12, #0                /* r12 := CPU ID */
        mrc   CP32(r0, MPIDR)
        tst   r0, #(1<<31)           /* Multiprocessor extension supported? */
        beq   boot_cpu
        tst   r0, #(1<<30)           /* Uniprocessor system? */
        bne   boot_cpu
        bics  r12, r0, #(0xff << 24) /* Mask out flags to get CPU ID */
        beq   boot_cpu               /* If we're CPU 0, boot now */

        /* Non-boot CPUs wait here to be woken up one at a time. */
1:      dsb
        ldr   r0, =smp_up_cpu        /* VA of gate */
        add   r0, r0, r10            /* PA of gate */
        ldr   r1, [r0]               /* Which CPU is being booted? */
        teq   r1, r12                /* Is it us? */
        wfene
        bne   1b

boot_cpu:
#ifdef EARLY_PRINTK
        ldr   r11, =EARLY_UART_BASE_ADDRESS  /* r11 := UART base address */
        teq   r12, #0                   /* CPU 0 sets up the UART too */
        bleq  init_uart
        PRINT("- CPU ")
        mov   r0, r12
        bl    putn
        PRINT(" booting -\r\n")
#endif
        /* Secondary CPUs doesn't have machine ID
         *  - Store machine ID on boot CPU
         *  - Load machine ID on secondary CPUs
         * Machine ID is needed in kick_cpus and enter_hyp_mode */
        ldr   r0, =machine_id           /* VA of machine_id */
        add   r0, r0, r10               /* PA of machine_id */
        teq   r12, #0
        streq r5, [r0]                  /* On boot CPU save machine ID */
        ldrne r5, [r0]                  /* If non boot cpu r5 := machine ID */

        /* Wake up secondary cpus */
        teq   r12, #0
        bleq  kick_cpus

        PRINT("- Machine ID ")
        mov   r0, r5
        bl    putn
        PRINT(" -\r\n")

        /* Check that this CPU has Hyp mode */
        mrc   CP32(r0, ID_PFR1)
        and   r0, r0, #0xf000        /* Bits 12-15 define virt extensions */
        teq   r0, #0x1000            /* Must == 0x1 or may be incompatible */
        beq   1f
        PRINT("- CPU doesn't support the virtualization extensions -\r\n")
        b     fail
1:
        /* Check if we're already in it */
        mrs   r0, cpsr
        and   r0, r0, #0x1f          /* Mode is in the low 5 bits of CPSR */
        teq   r0, #0x1a              /* Hyp Mode? */
        bne   1f
        PRINT("- Started in Hyp mode -\r\n")
        b     hyp
1:
        /* Otherwise, it must have been Secure Supervisor mode */
        mrc   CP32(r0, SCR)
        tst   r0, #0x1               /* Not-Secure bit set? */
        beq   1f
        PRINT("- CPU is not in Hyp mode or Secure state -\r\n")
        b     fail
1:
        /* OK, we're in Secure state. */
        PRINT("- Started in Secure state -\r\n- Entering Hyp mode -\r\n")
        ldr   r0, =enter_hyp_mode    /* VA of function */
        adr   lr, hyp                /* Set return address for call */
        add   pc, r0, r10            /* Call PA of function */

hyp:

        /* Zero BSS On the boot CPU to avoid nasty surprises */
        teq   r12, #0
        bne   skip_bss

        PRINT("- Zero BSS -\r\n")
        ldr   r0, =__bss_start       /* Load start & end of bss */
        ldr   r1, =__bss_end
        add   r0, r0, r10            /* Apply physical offset */
        add   r1, r1, r10

        mov   r2, #0
1:      str   r2, [r0], #4
        cmp   r0, r1
        blo   1b

skip_bss:
        PRINT("- Setting up control registers -\r\n")

        /* Get processor specific proc info into r1 */
        mrc   CP32(r0, MIDR)                /* r0 := our cpu id */
        ldr   r1, = __proc_info_start
        add   r1, r1, r10                   /* r1 := paddr of table (start) */
        ldr   r2, = __proc_info_end
        add   r2, r2, r10                   /* r2 := paddr of table (end) */
1:      ldr   r3, [r1, #PROCINFO_cpu_mask]
        and   r4, r0, r3                    /* r4 := our cpu id with mask */
        ldr   r3, [r1, #PROCINFO_cpu_val]   /* r3 := cpu val in current proc info */
        teq   r4, r3
        beq   2f                            /* Match => exit, or try next proc info */
        add   r1, r1, #PROCINFO_sizeof
        cmp   r1, r2
        blo   1b
        mov   r4, r0
        PRINT("- Missing processor info: ")
        mov   r0, r4
        bl    putn
        PRINT(" -\r\n")
        b     fail

2:
        /* Jump to cpu_init */
        ldr   r1, [r1, #PROCINFO_cpu_init]  /* r1 := vaddr(init func) */
        adr   lr, cpu_init_done             /* Save return address */
        add   pc, r1, r10                   /* Call paddr(init func) */

cpu_init_done:
        /* Set up memory attribute type tables */
        ldr   r0, =MAIR0VAL
        ldr   r1, =MAIR1VAL
        mcr   CP32(r0, MAIR0)
        mcr   CP32(r1, MAIR1)
        mcr   CP32(r0, HMAIR0)
        mcr   CP32(r1, HMAIR1)

        /* Set up the HTCR:
         * PT walks use Outer-Shareable accesses,
         * PT walks are write-back, write-allocate in both cache levels,
         * Full 32-bit address space goes through this table. */
        ldr   r0, =0x80002500
        mcr   CP32(r0, HTCR)

        /* Set up the HSCTLR:
         * Exceptions in LE ARM,
         * Low-latency IRQs disabled,
         * Write-implies-XN disabled (for now),
         * D-cache disabled (for now),
         * I-cache enabled,
         * Alignment checking enabled,
         * MMU translation disabled (for now). */
        ldr   r0, =(HSCTLR_BASE|SCTLR_A)
        mcr   CP32(r0, HSCTLR)

        /* Write Xen's PT's paddr into the HTTBR */
        ldr   r4, =boot_pgtable
        add   r4, r4, r10            /* r4 := paddr (xen_pagetable) */
        mov   r5, #0                 /* r4:r5 is paddr (xen_pagetable) */
        mcrr  CP64(r4, r5, HTTBR)

        /* Non-boot CPUs don't need to rebuild the pagetable */
        teq   r12, #0
        bne   pt_ready

        /* console fixmap */
#if defined(EARLY_PRINTK)
        ldr   r1, =xen_fixmap
        add   r1, r1, r10            /* r1 := paddr (xen_fixmap) */
        mov   r3, #0
        lsr   r2, r11, #12
        lsl   r2, r2, #12            /* 4K aligned paddr of UART */
        orr   r2, r2, #PT_UPPER(DEV_L3)
        orr   r2, r2, #PT_LOWER(DEV_L3) /* r2:r3 := 4K dev map including UART */
        strd  r2, r3, [r1, #(FIXMAP_CONSOLE*8)] /* Map it in the first fixmap's slot */
#endif

        /* Build the baseline idle pagetable's first-level entries */
        ldr   r1, =xen_second
        add   r1, r1, r10            /* r1 := paddr (xen_second) */
        mov   r3, #0x0
        orr   r2, r1, #PT_UPPER(PT)  /* r2:r3 := table map of xen_second */
        orr   r2, r2, #PT_LOWER(PT)  /* (+ rights for linear PT) */
        strd  r2, r3, [r4, #0]       /* Map it in slot 0 */
        add   r2, r2, #0x1000
        strd  r2, r3, [r4, #8]       /* Map 2nd page in slot 1 */
        add   r2, r2, #0x1000
        strd  r2, r3, [r4, #16]      /* Map 3rd page in slot 2 */
        add   r2, r2, #0x1000
        strd  r2, r3, [r4, #24]      /* Map 4th page in slot 3 */

        /* Now set up the second-level entries */
        orr   r2, r9, #PT_UPPER(MEM)
        orr   r2, r2, #PT_LOWER(MEM) /* r2:r3 := 2MB normal map of Xen */
        mov   r4, r9, lsr #18        /* Slot for paddr(start) */
        strd  r2, r3, [r1, r4]       /* Map Xen there */
        ldr   r4, =start
        lsr   r4, #18                /* Slot for vaddr(start) */
        strd  r2, r3, [r1, r4]       /* Map Xen there too */

        /* xen_fixmap pagetable */
        ldr   r2, =xen_fixmap
        add   r2, r2, r10            /* r2 := paddr (xen_fixmap) */
        orr   r2, r2, #PT_UPPER(PT)
        orr   r2, r2, #PT_LOWER(PT)  /* r2:r3 := table map of xen_fixmap */
        add   r4, r4, #8
        strd  r2, r3, [r1, r4]       /* Map it in the fixmap's slot */

        mov   r3, #0x0
        lsr   r2, r8, #21
        lsl   r2, r2, #21            /* 2MB-aligned paddr of DTB */
        orr   r2, r2, #PT_UPPER(MEM)
        orr   r2, r2, #PT_LOWER(MEM) /* r2:r3 := 2MB RAM incl. DTB */
        add   r4, r4, #8
        strd  r2, r3, [r1, r4]       /* Map it in the early boot slot */

pt_ready:
        PRINT("- Turning on paging -\r\n")

        ldr   r1, =paging            /* Explicit vaddr, not RIP-relative */
        mrc   CP32(r0, HSCTLR)
        orr   r0, r0, #(SCTLR_M|SCTLR_C) /* Enable MMU and D-cache */
        dsb                          /* Flush PTE writes and finish reads */
        mcr   CP32(r0, HSCTLR)       /* now paging is enabled */
        isb                          /* Now, flush the icache */
        mov   pc, r1                 /* Get a proper vaddr into PC */
paging:


#ifdef EARLY_PRINTK
        /* Use a virtual address to access the UART. */
        ldr   r11, =FIXMAP_ADDR(FIXMAP_CONSOLE)
#endif

        PRINT("- Ready -\r\n")

        /* The boot CPU should go straight into C now */
        teq   r12, #0
        beq   launch

        /* Non-boot CPUs need to move on to the relocated pagetables */
        mov   r0, #0
        ldr   r4, =boot_ttbr         /* VA of HTTBR value stashed by CPU 0 */
        add   r4, r4, r10            /* PA of it */
        ldrd  r4, r5, [r4]           /* Actual value */
        dsb
        mcrr  CP64(r4, r5, HTTBR)
        dsb
        isb
        mcr   CP32(r0, TLBIALLH)     /* Flush hypervisor TLB */
        mcr   CP32(r0, ICIALLU)      /* Flush I-cache */
        mcr   CP32(r0, BPIALL)       /* Flush branch predictor */
        dsb                          /* Ensure completion of TLB+BP flush */
        isb

        /* Non-boot CPUs report that they've got this far */
        ldr   r0, =ready_cpus
1:      ldrex r1, [r0]               /*            { read # of ready CPUs } */
        add   r1, r1, #1             /* Atomically { ++                   } */
        strex r2, r1, [r0]           /*            { writeback            } */
        teq   r2, #0
        bne   1b
        dsb
        mcr   CP32(r0, DCCMVAC)      /* flush D-Cache */
        dsb

        /* Here, the non-boot CPUs must wait again -- they're now running on
         * the boot CPU's pagetables so it's safe for the boot CPU to
         * overwrite the non-relocated copy of Xen.  Once it's done that,
         * and brought up the memory allocator, non-boot CPUs can get their
         * own stacks and enter C. */
1:      wfe
        dsb
        ldr   r0, =smp_up_cpu
        ldr   r1, [r0]               /* Which CPU is being booted? */
        teq   r1, r12                /* Is it us? */
        bne   1b

launch:
        ldr   r0, =init_stack        /* Find the boot-time stack */
        ldr   sp, [r0]
        add   sp, #STACK_SIZE        /* (which grows down from the top). */
        sub   sp, #CPUINFO_sizeof    /* Make room for CPU save record */
        mov   r0, r10                /* Marshal args: - phys_offset */
        mov   r1, r8                 /*               - DTB address */
        movs  r2, r12                /*               - CPU ID */
        beq   start_xen              /* and disappear into the land of C */
        b     start_secondary        /* (to the appropriate entry point) */

/* Fail-stop
 * r0: string explaining why */
fail:   PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b


#ifdef EARLY_PRINTK
/* Bring up the UART.
 * r11: Early UART base address
 * Clobbers r0-r2 */
init_uart:
#ifdef EARLY_PRINTK_INIT_UART
        early_uart_init r11, r1, r2
#endif
        adr   r0, 1f
        b     puts                  /* Jump to puts */
1:      .asciz "- UART enabled -\r\n"
        .align 4

/* Print early debug messages.
 * r0: Nul-terminated string to print.
 * r11: Early UART base address
 * Clobbers r0-r1 */
puts:
        early_uart_ready r11, r1
        ldrb  r1, [r0], #1           /* Load next char */
        teq   r1, #0                 /* Exit on nul */
        moveq pc, lr
        early_uart_transmit r11, r1
        b puts

/* Print a 32-bit number in hex.  Specific to the PL011 UART.
 * r0: Number to print.
 * r11: Early UART base address
 * Clobbers r0-r3 */
putn:
        adr   r1, hex
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

hex:    .ascii "0123456789abcdef"
        .align 2

#else  /* EARLY_PRINTK */

init_uart:
.global early_puts
early_puts:
puts:
putn:   mov   pc, lr

#endif /* !EARLY_PRINTK */

/* Place holder for machine ID */
machine_id: .word 0x0

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
