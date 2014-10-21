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
#include <asm/early_printk.h>
#include <efi/efierr.h>
#include <asm/arm64/efibind.h>

#define PT_PT     0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_MEM    0xf7d /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=0 P=1 */
#define PT_MEM_L3 0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_DEV    0xe71 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=0 P=1 */
#define PT_DEV_L3 0xe73 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=1 P=1 */

#if (defined (CONFIG_EARLY_PRINTK)) && (defined (EARLY_PRINTK_INC))
#include EARLY_PRINTK_INC
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
 *  x22 - is_secondary_cpu
 *  x23 - UART address
 *  x24 - cpuid
 *  x25 - identity map in place
 *  x26 -
 *  x27 -
 *  x28 -
 *  x29 -
 *  x30 - lr
 */

/* Macro to print a string to the UART, if there is one.
 * Clobbers x0-x3. */
#ifdef CONFIG_EARLY_PRINTK
#define PRINT(_s)       \
        adr   x0, 98f ; \
        bl    puts    ; \
        b     99f     ; \
98:     .asciz _s     ; \
        .align 2      ; \
99:
#else /* CONFIG_EARLY_PRINTK */
#define PRINT(s)
#endif /* !CONFIG_EARLY_PRINTK */

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
         * 4K-aligned address.  All of text+data+bss must fit in 2MB,
         * or the initial pagetable code below will need adjustment.
         */

GLOBAL(start)
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
        .quad   0                    /* Image load offset from start of RAM */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */
        .quad   0                    /* reserved */
        .byte   0x41                 /* Magic number, "ARM\x64" */
        .byte   0x52
        .byte   0x4d
        .byte   0x64
        .long   pe_header - efi_head        /* Offset to the PE header. */

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

        mov   x22, #0                /* x22 := is_secondary_cpu */

        b     common_start

GLOBAL(init_secondary)
        msr   DAIFSet, 0xf           /* Disable all interrupts */

        /* Find out where we are */
        ldr   x0, =start
        adr   x19, start             /* x19 := paddr (start) */
        sub   x20, x19, x0           /* x20 := phys-offset */

        mov   x22, #1                /* x22 := is_secondary_cpu */

common_start:
        mov   x24, #0                /* x24 := CPU ID. Initialy zero until we
                                      * find that multiprocessor extensions are
                                      * present and the system is SMP  */
        mrs   x0, mpidr_el1
        tbz   x0, _MPIDR_SMP, 1f     /* Multiprocessor extension not supported? */
        tbnz  x0, _MPIDR_UP, 1f      /* Uniprocessor system? */

        mov   x13, #(~MPIDR_HWID_MASK)
        bic   x24, x0, x13           /* Mask out flags to get CPU ID */
1:

        /* Non-boot CPUs wait here until __cpu_up is ready for them */
        cbz   x22, 1f

        ldr   x0, =smp_up_cpu
        add   x0, x0, x20            /* Apply physical offset */
        dsb   sy
2:      ldr   x1, [x0]
        cmp   x1, x24
        beq   1f
        wfe
        b     2b
1:

#ifdef CONFIG_EARLY_PRINTK
        ldr   x23, =EARLY_UART_BASE_ADDRESS /* x23 := UART base address */
        cbnz  x22, 1f
        bl    init_uart                 /* Boot CPU sets up the UART too */
1:      PRINT("- CPU ")
        mov   x0, x24
        bl    putn
        PRINT(" booting -\r\n")
#endif

        PRINT("- Current EL ")
        mrs   x4, CurrentEL
        mov   x0, x4
        bl    putn
        PRINT(" -\r\n")

        /* Are we in EL2 */
        cmp   x4, #PSR_MODE_EL2t
        ccmp  x4, #PSR_MODE_EL2h, #0x4, ne
        b.eq  el2 /* Yes */

        /* OK, we're boned. */
        PRINT("- Xen must be entered in NS EL2 mode -\r\n" \
              "- Please update the bootloader -\r\n")
        b fail

el2:    PRINT("- Xen starting at EL2 -\r\n")

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

        /* XXXX call PROCINFO_cpu_init here */

        /* Set up memory attribute type tables */
        ldr   x0, =MAIRVAL
        msr   mair_el2, x0

        /* Set up TCR_EL2:
         * PS -- Based on ID_AA64MMFR0_EL1.PARange
         * Top byte is used
         * PT walks use Inner-Shareable accesses,
         * PT walks are write-back, write-allocate in both cache levels,
         * Full 64-bit address space goes through this table. */
        ldr   x0, =(TCR_RES1|TCR_SH0_IS|TCR_ORGN0_WBWA|TCR_IRGN0_WBWA|TCR_T0SZ(0))
        /* ID_AA64MMFR0_EL1[3:0] (PARange) corresponds to TCR_EL2[18:16] (PS) */
        mrs   x1, ID_AA64MMFR0_EL1
        bfi   x0, x1, #16, #3

        msr   tcr_el2, x0

        /* Set up the SCTLR_EL2:
         * Exceptions in LE ARM,
         * Low-latency IRQs disabled,
         * Write-implies-XN disabled (for now),
         * D-cache disabled (for now),
         * I-cache enabled,
         * Alignment checking disabled,
         * MMU translation disabled (for now). */
        ldr   x0, =(HSCTLR_BASE)
        msr   SCTLR_EL2, x0

        /* Rebuild the boot pagetable's first-level entries. The structure
         * is described in mm.c.
         *
         * After the CPU enables paging it will add the fixmap mapping
         * to these page tables, however this may clash with the 1:1
         * mapping. So each CPU must rebuild the page tables here with
         * the 1:1 in place. */

        /* If Xen is loaded at exactly XEN_VIRT_START then we don't
         * need an additional 1:1 mapping, the virtual mapping will
         * suffice.
         */
        cmp   x19, #XEN_VIRT_START
        cset  x25, eq                /* x25 := identity map in place, or not */

        /* Write Xen's PT's paddr into TTBR0_EL2 */
        ldr   x4, =boot_pgtable
        add   x4, x4, x20            /* x4 := paddr (boot_pagetable) */
        msr   TTBR0_EL2, x4

        /* Setup boot_pgtable: */
        ldr   x1, =boot_first
        add   x1, x1, x20            /* x1 := paddr (boot_first) */

        /* ... map boot_first in boot_pgtable[0] */
        mov   x3, #PT_PT             /* x2 := table map of boot_first */
        orr   x2, x1, x3             /*       + rights for linear PT */
        str   x2, [x4, #0]           /* Map it in slot 0 */

        /* ... map of paddr(start) in boot_pgtable+boot_first_id */
        lsr   x1, x19, #ZEROETH_SHIFT/* Offset of base paddr in boot_pgtable */
        cbz   x1, 1f                 /* It's in slot 0, map in boot_first
                                      * or boot_second later on */

        /* Level zero does not support superpage mappings, so we have
         * to use an extra first level page in which we create a 1GB mapping.
         */
        ldr   x2, =boot_first_id
        add   x2, x2, x20            /* x2 := paddr (boot_first_id) */

        mov   x3, #PT_PT             /* x2 := table map of boot_first_id */
        orr   x2, x2, x3             /*       + rights for linear PT */
        lsl   x1, x1, #3             /* x1 := Slot offset */
        str   x2, [x4, x1]

        ldr   x4, =boot_first_id     /* Next level into boot_first_id */
        add   x4, x4, x20            /* x4 := paddr(boot_first_id) */

        lsr   x1, x19, #FIRST_SHIFT  /* x1 := Offset of base paddr in boot_first_id */
        lsl   x2, x1, #FIRST_SHIFT   /* x2 := Base address for 1GB mapping */
        mov   x3, #PT_MEM            /* x2 := Section map */
        orr   x2, x2, x3
        and   x1, x1, #LPAE_ENTRY_MASK /* x1 := Slot offset */
        lsl   x1, x1, #3
        str   x2, [x4, x1]           /* Mapping of paddr(start) */
        mov   x25, #1                /* x25 := identity map now in place */

1:      /* Setup boot_first: */
        ldr   x4, =boot_first        /* Next level into boot_first */
        add   x4, x4, x20            /* x4 := paddr(boot_first) */

        /* ... map boot_second in boot_first[0] */
        ldr   x1, =boot_second
        add   x1, x1, x20            /* x1 := paddr(boot_second) */
        mov   x3, #PT_PT             /* x2 := table map of boot_second */
        orr   x2, x1, x3             /*       + rights for linear PT */
        str   x2, [x4, #0]           /* Map it in slot 0 */

        /* ... map of paddr(start) in boot_first */
        cbnz  x25, 1f                /* x25 is set if already created */
        lsr   x2, x19, #FIRST_SHIFT  /* x2 := Offset of base paddr in boot_first */
        and   x1, x2, #LPAE_ENTRY_MASK /* x1 := Slot to use */
        cbz   x1, 1f                 /* It's in slot 0, map in boot_second */

        lsl   x2, x2, #FIRST_SHIFT   /* Base address for 1GB mapping */
        mov   x3, #PT_MEM            /* x2 := Section map */
        orr   x2, x2, x3
        lsl   x1, x1, #3             /* x1 := Slot offset */
        str   x2, [x4, x1]           /* Create mapping of paddr(start)*/
        mov   x25, #1                /* x25 := identity map now in place */

1:      /* Setup boot_second: */
        ldr   x4, =boot_second       /* Next level into boot_second */
        add   x4, x4, x20            /* x4 := paddr(boot_second) */

        /* ... map boot_third in boot_second[1] */
        ldr   x1, =boot_third
        add   x1, x1, x20            /* x1 := paddr(boot_third) */
        mov   x3, #PT_PT             /* x2 := table map of boot_third */
        orr   x2, x1, x3             /*       + rights for linear PT */
        str   x2, [x4, #8]           /* Map it in slot 1 */

        /* ... map of paddr(start) in boot_second */
        cbnz  x25, 1f                /* x25 is set if already created */
        lsr   x2, x19, #SECOND_SHIFT /* x2 := Offset of base paddr in boot_second */
        and   x1, x2, #LPAE_ENTRY_MASK /* x1 := Slot to use */
        cmp   x1, #1
        b.eq  virtphys_clash         /* It's in slot 1, which we cannot handle */

        lsl   x2, x2, #SECOND_SHIFT  /* Base address for 2MB mapping */
        mov   x3, #PT_MEM            /* x2 := Section map */
        orr   x2, x2, x3
        lsl   x1, x1, #3             /* x1 := Slot offset */
        str   x2, [x4, x1]           /* Create mapping of paddr(start)*/
        mov   x25, #1                /* x25 := identity map now in place */

1:      /* Setup boot_third: */
        ldr   x4, =boot_third
        add   x4, x4, x20            /* x4 := paddr (boot_third) */

        lsr   x2, x19, #THIRD_SHIFT  /* Base address for 4K mapping */
        lsl   x2, x2, #THIRD_SHIFT
        mov   x3, #PT_MEM_L3         /* x2 := Section map */
        orr   x2, x2, x3

        /* ... map of vaddr(start) in boot_third */
        mov   x1, xzr
1:      str   x2, [x4, x1]           /* Map vaddr(start) */
        add   x2, x2, #PAGE_SIZE     /* Next page */
        add   x1, x1, #8             /* Next slot */
        cmp   x1, #(LPAE_ENTRIES<<3) /* 512 entries per page */
        b.lt  1b

        /* Defer fixmap and dtb mapping until after paging enabled, to
         * avoid them clashing with the 1:1 mapping. */

        /* boot pagetable setup complete */

        cbnz  x25, 1f                /* Did we manage to create an identity mapping ? */
        PRINT("Unable to build boot page tables - Failed to identity map Xen.\r\n")
        b     fail
virtphys_clash:
        /* Identity map clashes with boot_third, which we cannot handle yet */
        PRINT("- Unable to build boot page tables - virt and phys addresses clash. -\r\n")
        b     fail

1:
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

        /* Now we can install the fixmap and dtb mappings, since we
         * don't need the 1:1 map any more */
        dsb   sy
#if defined(CONFIG_EARLY_PRINTK) /* Fixmap is only used by early printk */
        /* Non-boot CPUs don't need to rebuild the fixmap itself, just
         * the mapping from boot_second to xen_fixmap */
        cbnz  x22, 1f

        /* Add UART to the fixmap table */
        ldr   x1, =xen_fixmap
        add   x1, x1, x20            /* x1 := paddr (xen_fixmap) */
        lsr   x2, x23, #THIRD_SHIFT
        lsl   x2, x2, #THIRD_SHIFT   /* 4K aligned paddr of UART */
        mov   x3, #PT_DEV_L3
        orr   x2, x2, x3             /* x2 := 4K dev map including UART */
        str   x2, [x1, #(FIXMAP_CONSOLE*8)] /* Map it in the first fixmap's slot */
1:

        /* Map fixmap into boot_second */
        ldr   x4, =boot_second       /* x4 := vaddr (boot_second) */
        ldr   x2, =xen_fixmap
        add   x2, x2, x20            /* x2 := paddr (xen_fixmap) */
        mov   x3, #PT_PT
        orr   x2, x2, x3             /* x2 := table map of xen_fixmap */
        ldr   x1, =FIXMAP_ADDR(0)
        lsr   x1, x1, #(SECOND_SHIFT - 3)   /* x1 := Slot for FIXMAP(0) */
        str   x2, [x4, x1]           /* Map it in the fixmap's slot */

        /* Use a virtual address to access the UART. */
        ldr   x23, =EARLY_UART_VIRTUAL_ADDRESS
#endif

        /* Map the DTB in the boot misc slot */
        cbnz  x22, 1f                /* Only on boot CPU */

        ldr   x4, =boot_second       /* x4 := vaddr (boot_second) */
        lsr   x2, x21, #SECOND_SHIFT
        lsl   x2, x2, #SECOND_SHIFT  /* x2 := 2MB-aligned paddr of DTB */
        mov   x3, #PT_MEM            /* x2 := 2MB RAM incl. DTB */
        orr   x2, x2, x3
        ldr   x1, =BOOT_FDT_VIRT_START
        lsr   x1, x1, #(SECOND_SHIFT - 3)   /* x4 := Slot for BOOT_FDT_VIRT_START */
        str   x2, [x4, x1]           /* Map it in the early fdt slot */
1:

        /*
         * Flush the TLB in case the 1:1 mapping happens to clash with
         * the virtual addresses used by the fixmap or DTB.
         */
        dsb   sy                     /* Ensure any page table updates made above
                                      * have occurred. */

        isb
        tlbi  alle2
        dsb   sy                     /* Ensure completion of TLB flush */
        isb

        PRINT("- Ready -\r\n")

        /* The boot CPU should go straight into C now */
        cbz   x22, launch

        /* Non-boot CPUs need to move on to the proper pagetables, which were
         * setup in init_secondary_pagetables. */

        ldr   x4, =init_ttbr         /* VA of TTBR0_EL2 stashed by CPU 0 */
        ldr   x4, [x4]               /* Actual value */
        dsb   sy
        msr   TTBR0_EL2, x4
        dsb   sy
        isb
        tlbi  alle2
        dsb   sy                     /* Ensure completion of TLB flush */
        isb

launch:
        ldr   x0, =init_data
        add   x0, x0, #INITINFO_stack /* Find the boot-time stack */
        ldr   x0, [x0]
        add   x0, x0, #STACK_SIZE    /* (which grows down from the top). */
        sub   x0, x0, #CPUINFO_sizeof /* Make room for CPU save record */
        mov   sp, x0

        mov   x0, x20                /* Marshal args: - phys_offset */
        mov   x1, x21                /*               - FDT */
        mov   x2, x24                /*               - CPU ID */
        cbz   x22, start_xen         /* and disappear into the land of C */
        b     start_secondary        /* (to the appropriate entry point) */

/* Fail-stop */
fail:   PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b

GLOBAL(_end_boot)

/* Copy Xen to new location and switch TTBR
 * x0    ttbr
 * x1    source address
 * x2    destination address
 * x3    length
 *
 * Source and destination must be word aligned, length is rounded up
 * to a 16 byte boundary.
 *
 * MUST BE VERY CAREFUL when saving things to RAM over the copy */
ENTRY(relocate_xen)
        /* Copy 16 bytes at a time using:
         *   x9: counter
         *   x10: data
         *   x11: data
         *   x12: source
         *   x13: destination
         */
        mov     x9, x3
        mov     x12, x1
        mov     x13, x2

1:      ldp     x10, x11, [x12], #16
        stp     x10, x11, [x13], #16

        subs    x9, x9, #16
        bgt     1b

        /* Flush destination from dcache using:
         * x9: counter
         * x10: step
         * x11: vaddr
         */
        dsb   sy        /* So the CPU issues all writes to the range */

        mov   x9, x3
        ldr   x10, =cacheline_bytes /* x10 := step */
        ldr   x10, [x10]
        mov   x11, x2

1:      dc    cvac, x11

        add   x11, x11, x10
        subs  x9, x9, x10
        bgt   1b

        dsb   sy                     /* Ensure the flushes happen before
                                      * continuing */
        isb                          /* Ensure synchronization with previous
                                      * changes to text */
        tlbi   alle2                 /* Flush hypervisor TLB */
        ic     iallu                 /* Flush I-cache */
        dsb    sy                    /* Ensure completion of TLB flush */
        isb

        msr    TTBR0_EL2, x0

        isb                          /* Ensure synchronization with previous
                                      * changes to text */
        tlbi   alle2                 /* Flush hypervisor TLB */
        ic     iallu                 /* Flush I-cache */
        dsb    sy                    /* Ensure completion of TLB flush */
        isb

        ret

#ifdef CONFIG_EARLY_PRINTK
/* Bring up the UART.
 * x23: Early UART base address
 * Clobbers x0-x1 */
init_uart:
#ifdef EARLY_PRINTK_INIT_UART
        early_uart_init x23, 0
#endif
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

#else  /* CONFIG_EARLY_PRINTK */

ENTRY(early_puts)
init_uart:
puts:
putn:   ret

#endif /* !CONFIG_EARLY_PRINTK */

/* This provides a C-API version of __lookup_processor_type
 * TODO: For now, the implementation return NULL every time
 */
ENTRY(lookup_processor_type)
        mov  x0, #0
        ret
/*
 *  Function to transition from EFI loader in C, to Xen entry point.
 *  void noreturn efi_xen_start(void *fdt_ptr, uint32_t fdt_size);
 */
ENTRY(efi_xen_start)
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
        adrp  x1, _start
        add   x1, x1, #:lo12:_start
        mov   x0, x1
        adrp  x2, _end
        add   x2, x2, #:lo12:_end
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
        b     real_start
ENDPROC(efi_xen_start)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
