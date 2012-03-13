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
#include <asm/asm_defns.h>


/* Macro to print a string to the UART, if there is one.
 * Clobbers r0-r3. */
#ifdef EARLY_UART_ADDRESS
#define PRINT(_s)       \
	adr   r0, 98f ; \
	bl    puts    ; \
	b     99f     ; \
98:	.asciz _s     ; \
	.align 2      ; \
99:
#else
#define PRINT(s)
#endif

	.arm

	/* This must be the very first address in the loaded image.
	 * It should be linked at XEN_VIRT_START, and loaded at any
	 * 2MB-aligned address.  All of text+data+bss must fit in 2MB,
	 * or the initial pagetable code below will need adjustment. */
	.global start
start:
	cpsid aif                    /* Disable all interrupts */

	/* Save the bootloader arguments in less-clobberable registers */
	mov   r7, r1                 /* r7 := ARM-linux machine type */
	mov   r8, r2                 /* r8 := ATAG base address */

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

	/* Non-boot CPUs wait here to be woken up one at a time.
	 * This is basically an open-coded spin-lock to serialize. */
	ldr   r0, =boot_gate         /* VA of gate */
	add   r0, r0, r10            /* PA of gate */
	mov   r1, #1                 /* (1 == locked) */
1:	wfe
	ldrex r2, [r0]               /* Linked read of current value */
	teq   r2, #0                 /* (0 == unlocked) */
	strexeq r2, r1, [r0]         /* Matching update -> locked */
	teq   r2, #0                 /* (0 == succeeded) */
	bne   1b

boot_cpu:
#ifdef EARLY_UART_ADDRESS
	ldr   r11, =EARLY_UART_ADDRESS  /* r11 := UART base address */
	teq   r12, #0                   /* CPU 0 sets up the UART too */
	bleq  init_uart
	PRINT("- CPU ")
	mov   r0, r12
	bl    putn
	PRINT(" booting -\r\n")
#endif

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

	/* Dance into Hyp mode */
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
	/* FIXME: ought to reset some other NS control regs here */
	adr   r1, 1f
	adr   r0, hyp                /* Store paddr (hyp entry point) */
	str   r0, [r1]               /* where we can use it for RFE */
	isb                          /* Ensure we see the stored target address */
	rfeia r1                     /* Enter Hyp mode */

1:	.word 0                      /* PC to enter Hyp mode at */
	.word 0x000001da             /* CPSR: LE, Abort/IRQ/FIQ off, Hyp */

hyp:
	PRINT("- Setting up control registers -\r\n")

	/* Set up memory attribute type tables */
	ldr   r0, =MAIR0VAL
	ldr   r1, =MAIR1VAL
	mcr   CP32(r0, MAIR0)
	mcr   CP32(r1, MAIR1)
	mcr   CP32(r0, HMAIR0)
	mcr   CP32(r1, HMAIR1)

	/* Set up the HTCR:
	 * PT walks use Outer-Shareable accesses,
	 * PT walks are write-back, no-write-allocate in both cache levels,
	 * Full 32-bit address space goes through this table. */
	ldr   r0, =0x80002500
	mcr   CP32(r0, HTCR)

	/* Set up the HSCTLR:
	 * Exceptions in LE ARM,
	 * Low-latency IRQs disabled,
	 * Write-implies-XN disabled (for now),
	 * I-cache and d-cache enabled,
	 * Alignment checking enabled,
	 * MMU translation disabled (for now). */
	ldr   r0, =(HSCTLR_BASE|SCTLR_A|SCTLR_C)
	mcr   CP32(r0, HSCTLR)

	/* Write Xen's PT's paddr into the HTTBR */
	ldr   r4, =xen_pgtable
	add   r4, r4, r10            /* r4 := paddr (xen_pagetable) */
	mov   r5, #0                 /* r4:r5 is paddr (xen_pagetable) */
	mcrr  CP64(r4, r5, HTTBR)

	/* Non-boot CPUs don't need to rebuild the pagetable */
	teq   r12, #0
	bne   pt_ready
	
	/* Build the baseline idle pagetable's first-level entries */
	ldr   r1, =xen_second
	add   r1, r1, r10            /* r1 := paddr (xen_second) */
	mov   r3, #0x0
	orr   r2, r1, #0xe00         /* r2:r3 := table map of xen_second */
	orr   r2, r2, #0x07f         /* (+ rights for linear PT) */
	strd  r2, r3, [r4, #0]       /* Map it in slot 0 */
	add   r2, r2, #0x1000
	strd  r2, r3, [r4, #8]       /* Map 2nd page in slot 1 */
	add   r2, r2, #0x1000
	strd  r2, r3, [r4, #16]      /* Map 3rd page in slot 2 */
	add   r2, r2, #0x1000
	strd  r2, r3, [r4, #24]      /* Map 4th page in slot 3 */

	/* Now set up the second-level entries */
	orr   r2, r9, #0xe00
	orr   r2, r2, #0x07d         /* r2:r3 := 2MB normal map of Xen */
	mov   r4, r9, lsr #18        /* Slot for paddr(start) */
	strd  r2, r3, [r1, r4]       /* Map Xen there */
	ldr   r4, =start
	lsr   r4, #18                /* Slot for vaddr(start) */
	strd  r2, r3, [r1, r4]       /* Map Xen there too */
#ifdef EARLY_UART_ADDRESS
	ldr   r3, =(1<<(54-32))      /* NS for device mapping */
	lsr   r2, r11, #21
	lsl   r2, r2, #21            /* 2MB-aligned paddr of UART */
	orr   r2, r2, #0xe00
	orr   r2, r2, #0x071         /* r2:r3 := 2MB dev map including UART */
	add   r4, r4, #8
	strd  r2, r3, [r1, r4]       /* Map it in the fixmap's slot */
#else
	add   r4, r4, #8             /* Skip over unused fixmap slot */
#endif
	mov   r3, #0x0
	lsr   r2, r8, #21
	lsl   r2, r2, #21            /* 2MB-aligned paddr of DTB */
	orr   r2, r2, #0xf00
	orr   r2, r2, #0x07d         /* r2:r3 := 2MB RAM incl. DTB */
	add   r4, r4, #8
	strd  r2, r3, [r1, r4]       /* Map it in the early boot slot */

pt_ready:
	PRINT("- Turning on paging -\r\n")

	ldr   r1, =paging            /* Explicit vaddr, not RIP-relative */
	mrc   CP32(r0, HSCTLR)
	orr   r0, r0, #0x1           /* Add in the MMU enable bit */
	dsb                          /* Flush PTE writes and finish reads */
	mcr   CP32(r0, HSCTLR)       /* now paging is enabled */
	isb                          /* Now, flush the icache */
	mov   pc, r1                 /* Get a proper vaddr into PC */
paging:

#ifdef EARLY_UART_ADDRESS
	/* Recover the UART address in the new address space. */
	lsl   r11, #11
	lsr   r11, #11               /* UART base's offset from 2MB base */
	adr   r0, start
	add   r0, r0, #0x200000      /* vaddr of the fixmap's 2MB slot */
	add   r11, r11, r0           /* r11 := vaddr (UART base address) */
#endif

	PRINT("- Ready -\r\n")

	/* The boot CPU should go straight into C now */
	teq   r12, #0
	beq   launch

	/* Signal the next non-boot CPU to come and join us here */
	ldr   r0, =boot_gate         /* VA of gate */
	add   r0, r0, r10            /* PA of gate */
	mov   r1, #0                 /* (0 == unlocked) */
	str   r1, [r0]
	dsb
	isb
	sev

	/* Move on to the relocated pagetables */
	mov   r0, #0
	ldr   r4, =boot_httbr        /* VA of HTTBR value stashed by CPU 0 */
	add   r4, r4, r10            /* PA of it */
	ldrd  r4, r5, [r4]           /* Actual value */
	mcrr  CP64(r4, r5, HTTBR)
	mcr   CP32(r0, TLBIALLH)     /* Flush hypervisor TLB */
	mcr   CP32(r0, BPIALL)       /* Flush branch predictor */
	dsb                          /* Ensure completion of TLB+BP flush */
	isb
 	/* Now, the UART is in its proper fixmap address */
	ldrne r11, =FIXMAP_ADDR(FIXMAP_CONSOLE)

	/* Non-boot CPUs report that they've got this far */
	ldr   r0, =ready_cpus
1:	ldrex r1, [r0]               /*            { read # of ready CPUs } */
	add   r1, r1, #1             /* Atomically { ++                   } */
	strex r2, r1, [r0]           /*            { writeback            } */
	teq   r2, #0
	bne   1b
	dsb

	/* Here, the non-boot CPUs must wait again -- they're now running on
	 * the boot CPU's pagetables so it's safe for the boot CPU to
	 * overwrite the non-relocated copy of Xen.  Once it's done that,
	 * and brought up the memory allocator, non-boot CPUs can get their
	 * own stacks and enter C. */
1:	wfe
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
	mov   r1, r7                 /*               - machine type */
	mov   r2, r8                 /*               - ATAG address */
	movs  r3, r12                /*               - CPU ID */
	beq   start_xen              /* and disappear into the land of C */
	b     start_secondary        /* (to the appropriate entry point) */

/* Fail-stop
 * r0: string explaining why */
fail:	PRINT("- Boot failed -\r\n")
1:	wfe
	b     1b

#ifdef EARLY_UART_ADDRESS

/* Bring up the UART. Specific to the PL011 UART.
 * Clobbers r0-r2 */
init_uart:
	mov   r1, #0x0
	str   r1, [r11, #0x24]       /* -> UARTIBRD (Baud divisor fraction) */
	mov   r1, #0x4               /* 7.3728MHz / 0x4 == 16 * 115200 */
	str   r1, [r11, #0x24]       /* -> UARTIBRD (Baud divisor integer) */
	mov   r1, #0x60              /* 8n1 */
	str   r1, [r11, #0x24]       /* -> UARTLCR_H (Line control) */
	ldr   r1, =0x00000301        /* RXE | TXE | UARTEN */
	str   r1, [r11, #0x30]       /* -> UARTCR (Control Register) */
	adr   r0, 1f
	b     puts
1:	.asciz "- UART enabled -\r\n"
	.align 4

/* Print early debug messages.  Specific to the PL011 UART.
 * r0: Nul-terminated string to print.
 * Clobbers r0-r2 */
puts:
	ldr   r2, [r11, #0x18]       /* <- UARTFR (Flag register) */
	tst   r2, #0x8               /* Check BUSY bit */
	bne   puts                   /* Wait for the UART to be ready */
	ldrb  r2, [r0], #1           /* Load next char */
	teq   r2, #0                 /* Exit on nul */
	moveq pc, lr
	str   r2, [r11]              /* -> UARTDR (Data Register) */
	b     puts

/* Print a 32-bit number in hex.  Specific to the PL011 UART.
 * r0: Number to print.
 * clobbers r0-r3 */
putn:
	adr   r1, hex
	mov   r3, #8
1:	ldr   r2, [r11, #0x18]       /* <- UARTFR (Flag register) */
	tst   r2, #0x8               /* Check BUSY bit */
	bne   1b                     /* Wait for the UART to be ready */
	and   r2, r0, #0xf0000000    /* Mask off the top nybble */
	ldrb  r2, [r1, r2, lsr #28]  /* Convert to a char */
	str   r2, [r11]              /* -> UARTDR (Data Register) */
	lsl   r0, #4                 /* Roll it through one nybble at a time */
	subs  r3, r3, #1
	bne   1b
	mov   pc, lr

hex:	.ascii "0123456789abcdef"
	.align 2

#else  /* EARLY_UART_ADDRESS */

init_uart:
.global early_puts
early_puts:
puts:
putn:	mov   pc, lr

#endif /* EARLY_UART_ADDRESS */
