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

#include <asm/page.h>
#include <asm/early_printk.h>

#ifdef CONFIG_ARM_EFI
#include <efi/efierr.h>
#include <asm/arm64/efibind.h>
#endif

#define __HEAD_FLAG_PAGE_SIZE   ((PAGE_SHIFT - 10) / 2)

#define __HEAD_FLAG_PHYS_BASE   1

#define __HEAD_FLAGS            ((__HEAD_FLAG_PAGE_SIZE << 1) | \
                                 (__HEAD_FLAG_PHYS_BASE << 3))

#if defined(CONFIG_EARLY_PRINTK) && defined(CONFIG_EARLY_PRINTK_INC)
#include CONFIG_EARLY_PRINTK_INC
#endif

/*
 * Common register usage in this file:
 *  x0  -
 *  x1  -
 *  x2  -
 *  x3  -
 *  x4  -
 *  x5  -
 *  x6  -
 *  x7  -
 *  x8  -
 *  x9  -
 *  x10 -
 *  x11 -
 *  x12 -
 *  x13 -
 *  x14 -
 *  x15 -
 *  x16 -
 *  x17 -
 *  x18 -
 *  x19 - paddr(start)
 *  x20 - phys offset
 *  x21 - DTB address (boot cpu only)
 *  x22 -
 *  x23 - UART address
 *  x24 -
 *  x25 -
 *  x26 - skip_zero_bss (boot cpu only)
 *  x27 -
 *  x28 -
 *  x29 -
 *  x30 - lr
 */

.section .text.header, "ax", %progbits
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
 * 4K-aligned address.
 */

FUNC(start)
        /*
         * DO NOT MODIFY. Image header expected by Linux boot-loaders.
         */
efi_head:
        /*
         * This add instruction has no meaningful effect except that
         * its opcode forms the magic "MZ" signature of a PE/COFF file
         * that is required for UEFI applications.
         */
        add     x13, x18, #0x16
        b       real_start           /* branch to kernel start */
END(start)
        .quad   0                    /* Image load offset from start of RAM */
        .quad   _end - start         /* Effective size of kernel image, little-endian */
        .quad   __HEAD_FLAGS         /* Informative flags, little-endian */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */
        .byte   0x41                 /* Magic number, "ARM\x64" */
        .byte   0x52
        .byte   0x4d
        .byte   0x64
#ifndef CONFIG_ARM_EFI
        .long   0                    /* 0 means no PE header. */
#else
        .long   pe_header - efi_head /* Offset to the PE header. */
        /*
         * Add the PE/COFF header to the file.  The address of this header
         * is at offset 0x3c in the file, and is part of Linux "Image"
         * header.  The arm64 Linux Image format is designed to support
         * being both an 'Image' format binary and a PE/COFF binary.
         * The PE/COFF format is defined by Microsoft, and is available
         * from: http://msdn.microsoft.com/en-us/gg463119.aspx
         * Version 8.3 adds support for arm64 and UEFI usage.
         */

        .align  3
pe_header:
        .ascii  "PE"
        .short  0
coff_header:
        .short  0xaa64                          /* AArch64 */
        .short  2                               /* nr_sections */
        .long   0                               /* TimeDateStamp */
        .long   0                               /* PointerToSymbolTable */
        .long   1                               /* NumberOfSymbols */
        .short  section_table - optional_header /* SizeOfOptionalHeader */
        .short  0x206                           /* Characteristics. */
                                                /* IMAGE_FILE_DEBUG_STRIPPED | */
                                                /* IMAGE_FILE_EXECUTABLE_IMAGE | */
                                                /* IMAGE_FILE_LINE_NUMS_STRIPPED */
optional_header:
        .short  0x20b                           /* PE32+ format */
        .byte   0x02                            /* MajorLinkerVersion */
        .byte   0x14                            /* MinorLinkerVersion */
        .long   _end - real_start               /* SizeOfCode */
        .long   0                               /* SizeOfInitializedData */
        .long   0                               /* SizeOfUninitializedData */
        .long   efi_start - efi_head            /* AddressOfEntryPoint */
        .long   real_start - efi_head           /* BaseOfCode */

extra_header_fields:
        .quad   0                               /* ImageBase */
        .long   0x1000                          /* SectionAlignment (4 KByte) */
        .long   0x8                             /* FileAlignment */
        .short  0                               /* MajorOperatingSystemVersion */
        .short  0                               /* MinorOperatingSystemVersion */
        .short  0                               /* MajorImageVersion */
        .short  0                               /* MinorImageVersion */
        .short  0                               /* MajorSubsystemVersion */
        .short  0                               /* MinorSubsystemVersion */
        .long   0                               /* Win32VersionValue */

        .long   _end - efi_head                 /* SizeOfImage */

        /* Everything before the kernel image is considered part of the header */
        .long   real_start - efi_head           /* SizeOfHeaders */
        .long   0                               /* CheckSum */
        .short  0xa                             /* Subsystem (EFI application) */
        .short  0                               /* DllCharacteristics */
        .quad   0                               /* SizeOfStackReserve */
        .quad   0                               /* SizeOfStackCommit */
        .quad   0                               /* SizeOfHeapReserve */
        .quad   0                               /* SizeOfHeapCommit */
        .long   0                               /* LoaderFlags */
        .long   0x6                             /* NumberOfRvaAndSizes */

        .quad   0                               /* ExportTable */
        .quad   0                               /* ImportTable */
        .quad   0                               /* ResourceTable */
        .quad   0                               /* ExceptionTable */
        .quad   0                               /* CertificationTable */
        .quad   0                               /* BaseRelocationTable */

        /* Section table */
section_table:

        /*
         * The EFI application loader requires a relocation section
         * because EFI applications must be relocatable.  This is a
         * dummy section as far as we are concerned.
         */
        .ascii  ".reloc"
        .byte   0
        .byte   0                               /* end of 0 padding of section name */
        .long   0
        .long   0
        .long   0                               /* SizeOfRawData */
        .long   0                               /* PointerToRawData */
        .long   0                               /* PointerToRelocations */
        .long   0                               /* PointerToLineNumbers */
        .short  0                               /* NumberOfRelocations */
        .short  0                               /* NumberOfLineNumbers */
        .long   0x42100040                      /* Characteristics (section flags) */


        .ascii  ".text"
        .byte   0
        .byte   0
        .byte   0                               /* end of 0 padding of section name */
        .long   _end - real_start               /* VirtualSize */
        .long   real_start - efi_head           /* VirtualAddress */
        .long   __init_end_efi - real_start     /* SizeOfRawData */
        .long   real_start - efi_head           /* PointerToRawData */

        .long   0                /* PointerToRelocations (0 for executables) */
        .long   0                /* PointerToLineNumbers (0 for executables) */
        .short  0                /* NumberOfRelocations  (0 for executables) */
        .short  0                /* NumberOfLineNumbers  (0 for executables) */
        .long   0xe0500020       /* Characteristics (section flags) */
        .align  5
#endif /* CONFIG_ARM_EFI */

FUNC_LOCAL(real_start)
        /* BSS should be zeroed when booting without EFI */
        mov   x26, #0                /* x26 := skip_zero_bss */

real_start_efi:
        msr   DAIFSet, 0xf           /* Disable all interrupts */

        /* Save the bootloader arguments in less-clobberable registers */
        mov   x21, x0                /* x21 := DTB, physical address  */

        /* Find out where we are */
        ldr   x0, =start
        adr   x19, start             /* x19 := paddr (start) */
        sub   x20, x19, x0           /* x20 := phys-offset */

        /* Using the DTB in the .dtb section? */
.ifnes CONFIG_DTB_FILE,""
        adr_l x21, _sdtb
.endif

        /* Initialize the UART if earlyprintk has been enabled. */
#ifdef CONFIG_EARLY_PRINTK
        bl    init_uart
#endif
        PRINT("- Boot CPU booting -\r\n")

        bl    check_cpu_mode
        bl    cpu_init

        ldr   lr, =primary_switched
        b     enable_boot_cpu_mm

primary_switched:
        bl    zero_bss
        PRINT("- Ready -\r\n")
        /* Setup the arguments for start_xen and jump to C world */
        mov   x0, x21                /* x0 := paddr(FDT) */
        ldr   x1, =start_xen
        b     launch
END(real_start)

FUNC(init_secondary)
        msr   DAIFSet, 0xf           /* Disable all interrupts */

        /* Find out where we are */
        ldr   x0, =start
        adr   x19, start             /* x19 := paddr (start) */
        sub   x20, x19, x0           /* x20 := phys-offset */

        mrs   x0, mpidr_el1
        ldr   x13, =(~MPIDR_HWID_MASK)
        bic   x24, x0, x13           /* Mask out flags to get CPU ID */

        /* Wait here until __cpu_up is ready to handle the CPU */
        adr_l x0, smp_up_cpu
        dsb   sy
2:      ldr   x1, [x0]
        cmp   x1, x24
        beq   1f
        wfe
        b     2b
1:

#ifdef CONFIG_EARLY_PRINTK
        ldr   x23, =CONFIG_EARLY_UART_BASE_ADDRESS /* x23 := UART base address */
        PRINT_ID("- CPU ")
        print_reg x24
        PRINT_ID(" booting -\r\n")
#endif
        bl    check_cpu_mode
        bl    cpu_init

        ldr   lr, =secondary_switched
        b     enable_secondary_cpu_mm

secondary_switched:
        PRINT("- Ready -\r\n")
        /* Jump to C world */
        ldr   x1, =start_secondary
        b     launch
END(init_secondary)

/*
 * Check if the CPU has been booted in Hypervisor mode.
 * This function will never return when the CPU is booted in another mode
 * than Hypervisor mode.
 *
 * Clobbers x0 - x5
 */
FUNC_LOCAL(check_cpu_mode)
        PRINT_ID("- Current EL ")
        mrs   x5, CurrentEL
        print_reg x5
        PRINT_ID(" -\r\n")

        /* Are we in EL2 */
        cmp   x5, #PSR_MODE_EL2t
        ccmp  x5, #PSR_MODE_EL2h, #0x4, ne
        b.ne  1f /* No */
        ret
1:
        /* OK, we're boned. */
        PRINT_ID("- Xen must be entered in NS EL2 mode -\r\n")
        PRINT_ID("- Please update the bootloader -\r\n")
        b fail
END(check_cpu_mode)

/*
 * Zero BSS
 *
 * Inputs:
 *   x26: Do we need to zero BSS?
 *
 * Clobbers x0 - x3
 */
FUNC_LOCAL(zero_bss)
        /* Zero BSS only when requested */
        cbnz  x26, skip_bss

        PRINT("- Zero BSS -\r\n")
        ldr   x0, =__bss_start       /* x0 := vaddr(__bss_start) */
        ldr   x1, =__bss_end         /* x1 := vaddr(__bss_end)   */
        cmp   x1, x0
        beq   skip_bss

1:      str   xzr, [x0], #8
        cmp   x0, x1
        b.lo  1b

skip_bss:
        ret
END(zero_bss)

/*
 * Initialize the processor for turning the MMU on.
 *
 * Clobbers x0 - x3
 */
FUNC_LOCAL(cpu_init)
        PRINT_ID("- Initialize CPU -\r\n")

        /* Set up memory attribute type tables */
        ldr   x0, =MAIRVAL
        msr   mair_el2, x0

        /*
         * Set up TCR_EL2:
         * PS -- Based on ID_AA64MMFR0_EL1.PARange
         * Top byte is used
         * PT walks use Inner-Shareable accesses,
         * PT walks are write-back, write-allocate in both cache levels,
         * 48-bit virtual address space goes through this table.
         */
        ldr   x0, =(TCR_RES1|TCR_SH0_IS|TCR_ORGN0_WBWA|TCR_IRGN0_WBWA|TCR_T0SZ(64-48))
        /* ID_AA64MMFR0_EL1[3:0] (PARange) corresponds to TCR_EL2[18:16] (PS) */
        mrs   x1, ID_AA64MMFR0_EL1
        /* Limit to 48 bits, 256TB PA range (#5) */
        ubfm  x1, x1, #0, #3
        mov   x2, #5
        cmp   x1, x2
        csel  x1, x1, x2, lt

        bfi   x0, x1, #16, #3

        msr   tcr_el2, x0

        ldr   x0, =SCTLR_EL2_SET
        msr   SCTLR_EL2, x0
        isb

        /*
         * Ensure that any exceptions encountered at EL2
         * are handled using the EL2 stack pointer, rather
         * than SP_EL0.
         */
        msr spsel, #1
        ret
END(cpu_init)

/*
 * Setup the initial stack and jump to the C world
 *
 * Inputs:
 *   x0 : Argument 0 of the C function to call
 *   x1 : C entry point
 *
 * Clobbers x3
 */
FUNC_LOCAL(launch)
        ldr   x3, =init_data
        add   x3, x3, #INITINFO_stack /* Find the boot-time stack */
        ldr   x3, [x3]
        add   x3, x3, #STACK_SIZE     /* (which grows down from the top). */
        sub   x3, x3, #CPUINFO_sizeof /* Make room for CPU save record */
        mov   sp, x3

        /* Jump to C world */
        br    x1
END(launch)

/* Fail-stop */
FUNC_LOCAL(fail)
        PRINT_ID("- Boot failed -\r\n")
1:      wfe
        b     1b
END(fail)

#ifdef CONFIG_EARLY_PRINTK
/*
 * Initialize the UART. Should only be called on the boot CPU.
 *
 * Output:
 *  x23: Early UART base physical address
 *
 * Clobbers x0 - x1
 */
FUNC_LOCAL(init_uart)
        ldr   x23, =CONFIG_EARLY_UART_BASE_ADDRESS
#ifdef CONFIG_EARLY_UART_INIT
        early_uart_init x23, 0
#endif
        PRINT("- UART enabled -\r\n")
        ret
END(init_uart)

/*
 * Print early debug messages.
 * Note: This function must be called from assembly.
 * x0: Nul-terminated string to print.
 * x23: Early UART base address
 * Clobbers x0-x1
 */
FUNC(asm_puts)
        early_uart_ready x23, 1
        ldrb  w1, [x0], #1           /* Load next char */
        cbz   w1, 1f                 /* Exit on nul */
        early_uart_transmit x23, w1
        b     asm_puts
1:
        ret
END(asm_puts)

/*
 * Print a 64-bit number in hex.
 * Note: This function must be called from assembly.
 * x0: Number to print.
 * x23: Early UART base address
 * Clobbers x0-x3
 */
FUNC(asm_putn)
        adr_l x1, hex
        mov   x3, #16
1:
        early_uart_ready x23, 2
        and   x2, x0, #(0xf<<60)     /* Mask off the top nybble */
        lsr   x2, x2, #60
        ldrb  w2, [x1, x2]           /* Convert to a char */
        early_uart_transmit x23, w2
        lsl   x0, x0, #4             /* Roll it through one nybble at a time */
        subs  x3, x3, #1
        b.ne  1b
        ret
END(asm_putn)

RODATA_SECT(.rodata.idmap, hex, "0123456789abcdef")

#endif /* CONFIG_EARLY_PRINTK */

/* This provides a C-API version of __lookup_processor_type
 * TODO: For now, the implementation return NULL every time
 */
FUNC(lookup_processor_type)
        mov  x0, #0
        ret
END(lookup_processor_type)

#ifdef CONFIG_ARM_EFI
/*
 *  Function to transition from EFI loader in C, to Xen entry point.
 *  void noreturn efi_xen_start(void *fdt_ptr, uint32_t fdt_size);
 */
FUNC(efi_xen_start)
        /*
         * Preserve x0 (fdt pointer) across call to __flush_dcache_area,
         * restore for entry into Xen.
         */
        mov   x20, x0

        /* flush dcache covering the FDT updated by EFI boot code */
        bl    __flush_dcache_area

        /*
         * Flush dcache covering current runtime addresses
         * of xen text/data. Then flush all of icache.
         */
        adr_l x1, _start
        mov   x0, x1
        adr_l x2, _end
        sub   x1, x2, x1

        bl    __flush_dcache_area
        ic    ialluis
        tlbi  alle2

        /*
         * Turn off cache and MMU as Xen expects. EFI enables them, but also
         * mandates a 1:1 (unity) VA->PA mapping, so we can turn off the
         * MMU while executing EFI code before entering Xen.
         * The EFI loader calls this to start Xen.
         */

        /* Turn off Dcache and MMU */
        mrs   x0, sctlr_el2
        bic   x0, x0, #1 << 0        /* clear SCTLR.M */
        bic   x0, x0, #1 << 2        /* clear SCTLR.C */
        msr   sctlr_el2, x0
        isb

        /* Jump to Xen entry point */
        mov   x0, x20
        mov   x1, xzr
        mov   x2, xzr
        mov   x3, xzr
        /*
         * The EFI stub and Xen may share some information living in
         * BSS. Don't zero BSS to avoid loosing them.
         *
         * Note that the EFI firmware has already zeroed BSS for us
         * before jump into the stub.
         */
        mov   x26, #1               /* x26 := skip_zero_bss */

        b     real_start_efi
END(efi_xen_start)

#endif /* CONFIG_ARM_EFI */

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
