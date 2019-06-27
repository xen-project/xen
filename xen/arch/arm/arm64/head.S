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
#include <asm/asm_defns.h>
#include <asm/early_printk.h>
#include <efi/efierr.h>
#include <asm/arm64/efibind.h>
#include <asm/arm64/macros.h>

#define PT_PT     0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_MEM    0xf7d /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=0 P=1 */
#define PT_MEM_L3 0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_DEV    0xe71 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=0 P=1 */
#define PT_DEV_L3 0xe73 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=1 P=1 */

/* Convenience defines to get slot used by Xen mapping. */
#define XEN_ZEROETH_SLOT    zeroeth_table_offset(XEN_VIRT_START)
#define XEN_FIRST_SLOT      first_table_offset(XEN_VIRT_START)
#define XEN_SECOND_SLOT     second_table_offset(XEN_VIRT_START)

#define __HEAD_FLAG_PAGE_SIZE   ((PAGE_SHIFT - 10) / 2)

#define __HEAD_FLAG_PHYS_BASE   1

#define __HEAD_FLAGS            ((__HEAD_FLAG_PAGE_SIZE << 1) | \
                                 (__HEAD_FLAG_PHYS_BASE << 3))

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
 *  x24 -
 *  x25 -
 *  x26 - skip_zero_bss (boot cpu only)
 *  x27 -
 *  x28 -
 *  x29 -
 *  x30 - lr
 */

#ifdef CONFIG_EARLY_PRINTK
/*
 * Macro to print a string to the UART, if there is one.
 *
 * Clobbers x0 - x3
 */
#define PRINT(_s)          \
        mov   x3, lr ;     \
        adr   x0, 98f ;    \
        bl    puts    ;    \
        mov   lr, x3 ;     \
        RODATA_STR(98, _s)

/*
 * Macro to print the value of register \xb
 *
 * Clobbers x0 - x4
 */
.macro print_reg xb
        mov   x0, \xb
        mov   x4, lr
        bl    putn
        mov   lr, x4
.endm

#else /* CONFIG_EARLY_PRINTK */
#define PRINT(s)

.macro print_reg xb
.endm

#endif /* !CONFIG_EARLY_PRINTK */

/*
 * Pseudo-op for PC relative adr <reg>, <symbol> where <symbol> is
 * within the range +/- 4GB of the PC.
 *
 * @dst: destination register (64 bit wide)
 * @sym: name of the symbol
 */
.macro  adr_l, dst, sym
        adrp \dst, \sym
        add  \dst, \dst, :lo12:\sym
.endm

/* Load the physical address of a symbol into xb */
.macro load_paddr xb, sym
        ldr \xb, =\sym
        add \xb, \xb, x20
.endm

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
        .quad   _end - start         /* Effective size of kernel image, little-endian */
        .quad   __HEAD_FLAGS         /* Informative flags, little-endian */
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
#ifdef CONFIG_DTB_FILE
        load_paddr x21, _sdtb
#endif

        /* Initialize the UART if earlyprintk has been enabled. */
#ifdef CONFIG_EARLY_PRINTK
        bl    init_uart
#endif
        PRINT("- Boot CPU booting -\r\n")

        mov   x22, #0                /* x22 := is_secondary_cpu */

        bl    check_cpu_mode
        bl    cpu_init
        bl    create_page_tables
        bl    enable_mmu

        /* We are still in the 1:1 mapping. Jump to the runtime Virtual Address. */
        ldr   x0, =primary_switched
        br    x0
primary_switched:
        /*
         * The 1:1 map may clash with other parts of the Xen virtual memory
         * layout. As it is not used anymore, remove it completely to
         * avoid having to worry about replacing existing mapping
         * afterwards.
         */
        bl    remove_identity_mapping
        bl    setup_fixmap
#ifdef CONFIG_EARLY_PRINTK
        /* Use a virtual address to access the UART. */
        ldr   x23, =EARLY_UART_VIRTUAL_ADDRESS
#endif
        bl    zero_bss
        PRINT("- Ready -\r\n")
        /* Setup the arguments for start_xen and jump to C world */
        mov   x0, x20                /* x0 := Physical offset */
        mov   x1, x21                /* x1 := paddr(FDT) */
        ldr   x2, =start_xen
        b     launch
ENDPROC(real_start)

GLOBAL(init_secondary)
        msr   DAIFSet, 0xf           /* Disable all interrupts */

        /* Find out where we are */
        ldr   x0, =start
        adr   x19, start             /* x19 := paddr (start) */
        sub   x20, x19, x0           /* x20 := phys-offset */

        mov   x22, #1                /* x22 := is_secondary_cpu */

        mrs   x0, mpidr_el1
        ldr   x13, =(~MPIDR_HWID_MASK)
        bic   x24, x0, x13           /* Mask out flags to get CPU ID */

        /* Wait here until __cpu_up is ready to handle the CPU */
        load_paddr x0, smp_up_cpu
        dsb   sy
2:      ldr   x1, [x0]
        cmp   x1, x24
        beq   1f
        wfe
        b     2b
1:

#ifdef CONFIG_EARLY_PRINTK
        ldr   x23, =EARLY_UART_BASE_ADDRESS /* x23 := UART base address */
        PRINT("- CPU ")
        print_reg x24
        PRINT(" booting -\r\n")
#endif
        bl    check_cpu_mode
        bl    cpu_init
        bl    create_page_tables
        bl    enable_mmu

        /* We are still in the 1:1 mapping. Jump to the runtime Virtual Address. */
        ldr   x0, =secondary_switched
        br    x0
secondary_switched:
        /*
         * Non-boot CPUs need to move on to the proper pagetables, which were
         * setup in init_secondary_pagetables.
         *
         * XXX: This is not compliant with the Arm Arm.
         */
        ldr   x4, =init_ttbr         /* VA of TTBR0_EL2 stashed by CPU 0 */
        ldr   x4, [x4]               /* Actual value */
        dsb   sy
        msr   TTBR0_EL2, x4
        dsb   sy
        isb
        tlbi  alle2
        dsb   sy                     /* Ensure completion of TLB flush */
        isb

#ifdef CONFIG_EARLY_PRINTK
        /* Use a virtual address to access the UART. */
        ldr   x23, =EARLY_UART_VIRTUAL_ADDRESS
#endif
        PRINT("- Ready -\r\n")
        /* Jump to C world */
        ldr   x2, =start_secondary
        b     launch
ENDPROC(init_secondary)

/*
 * Check if the CPU has been booted in Hypervisor mode.
 * This function will never return when the CPU is booted in another mode
 * than Hypervisor mode.
 *
 * Clobbers x0 - x5
 */
check_cpu_mode:
        PRINT("- Current EL ")
        mrs   x5, CurrentEL
        print_reg x5
        PRINT(" -\r\n")

        /* Are we in EL2 */
        cmp   x5, #PSR_MODE_EL2t
        ccmp  x5, #PSR_MODE_EL2h, #0x4, ne
        b.ne  1f /* No */
        ret
1:
        /* OK, we're boned. */
        PRINT("- Xen must be entered in NS EL2 mode -\r\n")
        PRINT("- Please update the bootloader -\r\n")
        b fail
ENDPROC(check_cpu_mode)

/*
 * Zero BSS
 *
 * Inputs:
 *   x26: Do we need to zero BSS?
 *
 * Clobbers x0 - x3
 */
zero_bss:
        /* Zero BSS only when requested */
        cbnz  x26, skip_bss

        PRINT("- Zero BSS -\r\n")
        ldr   x0, =__bss_start       /* x0 := vaddr(__bss_start) */
        ldr   x1, =__bss_end         /* x1 := vaddr(__bss_start) */

1:      str   xzr, [x0], #8
        cmp   x0, x1
        b.lo  1b

skip_bss:
        ret
ENDPROC(zero_bss)

/*
 * Initialize the processor for turning the MMU on.
 *
 * Clobbers x0 - x3
 */
cpu_init:
        PRINT("- Initialize CPU -\r\n")

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
        bfi   x0, x1, #16, #3

        msr   tcr_el2, x0

        ldr   x0, =SCTLR_EL2_SET
        msr   SCTLR_EL2, x0

        /*
         * Ensure that any exceptions encountered at EL2
         * are handled using the EL2 stack pointer, rather
         * than SP_EL0.
         */
        msr spsel, #1
        ret
ENDPROC(cpu_init)

/*
 * Macro to create a page table entry in \ptbl to \tbl
 *
 * ptbl:    table symbol where the entry will be created
 * tbl:     table symbol to point to
 * virt:    virtual address
 * shift:   #imm page table shift
 * tmp1:    scratch register
 * tmp2:    scratch register
 * tmp3:    scratch register
 *
 * Preserves \virt
 * Clobbers \tmp1, \tmp2, \tmp3
 *
 * Also use x20 for the phys offset.
 *
 * Note that all parameters using registers should be distinct.
 */
.macro create_table_entry, ptbl, tbl, virt, shift, tmp1, tmp2, tmp3
        lsr   \tmp1, \virt, #\shift
        and   \tmp1, \tmp1, #LPAE_ENTRY_MASK/* \tmp1 := slot in \tlb */

        load_paddr \tmp2, \tbl
        mov   \tmp3, #PT_PT                 /* \tmp3 := right for linear PT */
        orr   \tmp3, \tmp3, \tmp2           /*          + \tlb paddr */

        adr_l \tmp2, \ptbl

        str   \tmp3, [\tmp2, \tmp1, lsl #3]
.endm

/*
 * Macro to create a mapping entry in \tbl to \phys. Only mapping in 3rd
 * level table (i.e page granularity) is supported.
 *
 * ptbl:     table symbol where the entry will be created
 * virt:    virtual address
 * phys:    physical address (should be page aligned)
 * tmp1:    scratch register
 * tmp2:    scratch register
 * tmp3:    scratch register
 * type:    mapping type. If not specified it will be normal memory (PT_MEM_L3)
 *
 * Preserves \virt, \phys
 * Clobbers \tmp1, \tmp2, \tmp3
 *
 * Note that all parameters using registers should be distinct.
 */
.macro create_mapping_entry, ptbl, virt, phys, tmp1, tmp2, tmp3, type=PT_MEM_L3
        and   \tmp3, \phys, #THIRD_MASK     /* \tmp3 := PAGE_ALIGNED(phys) */

        lsr   \tmp1, \virt, #THIRD_SHIFT
        and   \tmp1, \tmp1, #LPAE_ENTRY_MASK/* \tmp1 := slot in \tlb */

        mov   \tmp2, #\type                 /* \tmp2 := right for section PT */
        orr   \tmp2, \tmp2, \tmp3           /*          + PAGE_ALIGNED(phys) */

        adr_l \tmp3, \ptbl

        str   \tmp2, [\tmp3, \tmp1, lsl #3]
.endm

/*
 * Rebuild the boot pagetable's first-level entries. The structure
 * is described in mm.c.
 *
 * After the CPU enables paging it will add the fixmap mapping
 * to these page tables, however this may clash with the 1:1
 * mapping. So each CPU must rebuild the page tables here with
 * the 1:1 in place.
 *
 * Inputs:
 *   x19: paddr(start)
 *   x20: phys offset
 *
 * Clobbers x0 - x4
 */
create_page_tables:
        /* Prepare the page-tables for mapping Xen */
        ldr   x0, =XEN_VIRT_START
        create_table_entry boot_pgtable, boot_first, x0, ZEROETH_SHIFT, x1, x2, x3
        create_table_entry boot_first, boot_second, x0, FIRST_SHIFT, x1, x2, x3
        create_table_entry boot_second, boot_third, x0, SECOND_SHIFT, x1, x2, x3

        /* Map Xen */
        adr_l x4, boot_third

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

        /*
         * If Xen is loaded at exactly XEN_VIRT_START then we don't
         * need an additional 1:1 mapping, the virtual mapping will
         * suffice.
         */
        cmp   x19, #XEN_VIRT_START
        bne   1f
        ret
1:
        /*
         * Setup the 1:1 mapping so we can turn the MMU on. Note that
         * only the first page of Xen will be part of the 1:1 mapping.
         */

        /*
         * Find the zeroeth slot used. If the slot is not
         * XEN_ZEROETH_SLOT, then the 1:1 mapping will use its own set of
         * page-tables from the first level.
         */
        lsr   x0, x19, #ZEROETH_SHIFT   /* x0 := zeroeth slot */
        cmp   x0, #XEN_ZEROETH_SLOT
        beq   1f
        create_table_entry boot_pgtable, boot_first_id, x19, ZEROETH_SHIFT, x0, x1, x2
        b     link_from_first_id

1:
        /*
         * Find the first slot used. If the slot is not XEN_FIRST_SLOT,
         * then the 1:1 mapping will use its own set of page-tables from
         * the second level.
         */
        lsr   x0, x19, #FIRST_SHIFT
        and   x0, x0, #LPAE_ENTRY_MASK  /* x0 := first slot */
        cmp   x0, #XEN_FIRST_SLOT
        beq   1f
        create_table_entry boot_first, boot_second_id, x19, FIRST_SHIFT, x0, x1, x2
        b     link_from_second_id

1:
        /*
         * Find the second slot used. If the slot is XEN_SECOND_SLOT, then the
         * 1:1 mapping will use its own set of page-tables from the
         * third level. For slot XEN_SECOND_SLOT, Xen is not yet able to handle
         * it.
         */
        lsr   x0, x19, #SECOND_SHIFT
        and   x0, x0, #LPAE_ENTRY_MASK  /* x0 := first slot */
        cmp   x0, #XEN_SECOND_SLOT
        beq   virtphys_clash
        create_table_entry boot_second, boot_third_id, x19, SECOND_SHIFT, x0, x1, x2
        b     link_from_third_id

link_from_first_id:
        create_table_entry boot_first_id, boot_second_id, x19, FIRST_SHIFT, x0, x1, x2
link_from_second_id:
        create_table_entry boot_second_id, boot_third_id, x19, SECOND_SHIFT, x0, x1, x2
link_from_third_id:
        create_mapping_entry boot_third_id, x19, x19, x0, x1, x2
        ret

virtphys_clash:
        /* Identity map clashes with boot_third, which we cannot handle yet */
        PRINT("- Unable to build boot page tables - virt and phys addresses clash. -\r\n")
        b     fail
ENDPROC(create_page_tables)

/*
 * Turn on the Data Cache and the MMU. The function will return on the 1:1
 * mapping. In other word, the caller is responsible to switch to the runtime
 * mapping.
 *
 * Clobbers x0 - x3
 */
enable_mmu:
        PRINT("- Turning on paging -\r\n")

        /*
         * The state of the TLBs is unknown before turning on the MMU.
         * Flush them to avoid stale one.
         */
        tlbi  alle2                  /* Flush hypervisor TLBs */
        dsb   nsh

        /* Write Xen's PT's paddr into TTBR0_EL2 */
        load_paddr x0, boot_pgtable
        msr   TTBR0_EL2, x0
        isb

        mrs   x0, SCTLR_EL2
        orr   x0, x0, #SCTLR_Axx_ELx_M  /* Enable MMU */
        orr   x0, x0, #SCTLR_Axx_ELx_C  /* Enable D-cache */
        dsb   sy                     /* Flush PTE writes and finish reads */
        msr   SCTLR_EL2, x0          /* now paging is enabled */
        isb                          /* Now, flush the icache */
        ret
ENDPROC(enable_mmu)

/*
 * Remove the 1:1 map from the page-tables. It is not easy to keep track
 * where the 1:1 map was mapped, so we will look for the top-level entry
 * exclusive to the 1:1 map and remove it.
 *
 * Inputs:
 *   x19: paddr(start)
 *
 * Clobbers x0 - x1
 */
remove_identity_mapping:
        /*
         * Find the zeroeth slot used. Remove the entry from zeroeth
         * table if the slot is not XEN_ZEROETH_SLOT.
         */
        lsr   x1, x19, #ZEROETH_SHIFT   /* x1 := zeroeth slot */
        cmp   x1, #XEN_ZEROETH_SLOT
        beq   1f
        /* It is not in slot XEN_ZEROETH_SLOT, remove the entry. */
        ldr   x0, =boot_pgtable         /* x0 := root table */
        str   xzr, [x0, x1, lsl #3]
        b     identity_mapping_removed

1:
        /*
         * Find the first slot used. Remove the entry for the first
         * table if the slot is not XEN_FIRST_SLOT.
         */
        lsr   x1, x19, #FIRST_SHIFT
        and   x1, x1, #LPAE_ENTRY_MASK  /* x1 := first slot */
        cmp   x1, #XEN_FIRST_SLOT
        beq   1f
        /* It is not in slot XEN_FIRST_SLOT, remove the entry. */
        ldr   x0, =boot_first           /* x0 := first table */
        str   xzr, [x0, x1, lsl #3]
        b     identity_mapping_removed

1:
        /*
         * Find the second slot used. Remove the entry for the first
         * table if the slot is not XEN_SECOND_SLOT.
         */
        lsr   x1, x19, #SECOND_SHIFT
        and   x1, x1, #LPAE_ENTRY_MASK  /* x1 := first slot */
        cmp   x1, #XEN_SECOND_SLOT
        beq   identity_mapping_removed
        /* It is not in slot 1, remove the entry */
        ldr   x0, =boot_second          /* x0 := second table */
        str   xzr, [x0, x1, lsl #3]

identity_mapping_removed:
        /* See asm-arm/arm64/flushtlb.h for the explanation of the sequence. */
        dsb   nshst
        tlbi  alle2
        dsb   nsh
        isb

        ret
ENDPROC(remove_identity_mapping)

/*
 * Map the UART in the fixmap (when earlyprintk is used) and hook the
 * fixmap table in the page tables.
 *
 * The fixmap cannot be mapped in create_page_tables because it may
 * clash with the 1:1 mapping.
 *
 * Inputs:
 *   x20: Physical offset
 *   x23: Early UART base physical address
 *
 * Clobbers x0 - x3
 */
setup_fixmap:
#ifdef CONFIG_EARLY_PRINTK
        /* Add UART to the fixmap table */
        ldr   x0, =EARLY_UART_VIRTUAL_ADDRESS
        create_mapping_entry xen_fixmap, x0, x23, x1, x2, x3, type=PT_DEV_L3
#endif
        /* Map fixmap into boot_second */
        ldr   x0, =FIXMAP_ADDR(0)
        create_table_entry boot_second, xen_fixmap, x0, SECOND_SHIFT, x1, x2, x3
        /* Ensure any page table updates made above have occurred. */
        dsb   nshst

        ret
ENDPROC(setup_fixmap)

/*
 * Setup the initial stack and jump to the C world
 *
 * Inputs:
 *   x0 : Argument 0 of the C function to call
 *   x1 : Argument 1 of the C function to call
 *   x2 : C entry point
 *
 * Clobbers x3
 */
launch:
        ldr   x3, =init_data
        add   x3, x3, #INITINFO_stack /* Find the boot-time stack */
        ldr   x3, [x3]
        add   x3, x3, #STACK_SIZE     /* (which grows down from the top). */
        sub   x3, x3, #CPUINFO_sizeof /* Make room for CPU save record */
        mov   sp, x3

        /* Jump to C world */
        br    x2
ENDPROC(launch)

/* Fail-stop */
fail:   PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b

GLOBAL(_end_boot)

/*
 * Switch TTBR
 *
 * x0    ttbr
 *
 * TODO: This code does not comply with break-before-make.
 */
ENTRY(switch_ttbr)
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
/*
 * Initialize the UART. Should only be called on the boot CPU.
 *
 * Output:
 *  x23: Early UART base physical address
 *
 * Clobbers x0 - x1
 */
init_uart:
        ldr   x23, =EARLY_UART_BASE_ADDRESS
#ifdef EARLY_PRINTK_INIT_UART
        early_uart_init x23, 0
#endif
        PRINT("- UART enabled -\r\n")
        ret

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
ENDPROC(puts)

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
ENDPROC(putn)

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
ENDPROC(efi_xen_start)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
