/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/arm32/mmu/head.S
 *
 * Arm32 MMU specific start-of-day code.
 */

#include <asm/page.h>
#include <asm/early_printk.h>

#define PT_PT     0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_MEM    0xf7d /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=0 P=1 */
#define PT_MEM_L3 0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_DEV    0xe71 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=0 P=1 */
#define PT_DEV_L3 0xe73 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=1 P=1 */

#define PT_UPPER(x) (PT_##x & 0xf00)
#define PT_LOWER(x) (PT_##x & 0x0ff)

/* Convenience defines to get slot used by Xen mapping. */
#define XEN_FIRST_SLOT      first_table_offset(XEN_VIRT_START)
#define XEN_SECOND_SLOT     second_table_offset(XEN_VIRT_START)

/* Offset between the early boot xen mapping and the runtime xen mapping */
#define XEN_TEMPORARY_OFFSET      (TEMPORARY_XEN_VIRT_START - XEN_VIRT_START)

.macro load_paddr rb, sym
        mov_w \rb, \sym
        add   \rb, \rb, r10
.endm

/*
 * Flush local TLBs
 *
 * @tmp: Scratch register
 *
 * See asm/arm32/flushtlb.h for the explanation of the sequence.
 */
.macro flush_xen_tlb_local tmp
        dsb   nshst
        mcr   CP32(\tmp, TLBIALLH)
        dsb   nsh
        isb
.endm

/*
 * Enforce Xen page-tables do not contain mapping that are both
 * Writable and eXecutables.
 *
 * This should be called on each secondary CPU.
 */
.macro pt_enforce_wxn tmp
        mrc   CP32(\tmp, HSCTLR)
        orr   \tmp, \tmp, #SCTLR_Axx_ELx_WXN
        dsb
        mcr   CP32(\tmp, HSCTLR)
        /*
         * The TLBs may cache SCTLR_EL2.WXN. So ensure it is synchronized
         * before flushing the TLBs.
         */
        isb
        flush_xen_tlb_local \tmp
.endm

/* Macro to find the slot number at a given page-table level
 *
 * slot:     slot computed
 * virt:     virtual address
 * lvl:      page-table level
 *
 * Note that ubxf is unpredictable when the end bit is above 32-bit. So we
 * can't use it for first level offset.
 */
.macro get_table_slot, slot, virt, lvl
    .if \lvl == 1
        lsr   \slot, \virt, #XEN_PT_LEVEL_SHIFT(\lvl)
    .else
        ubfx  \slot, \virt, #XEN_PT_LEVEL_SHIFT(\lvl), #XEN_PT_LPAE_SHIFT
    .endif
.endm

/*
 * Macro to create a page table entry in \ptbl to \tbl (physical
 * address)
 *
 * ptbl:    table symbol where the entry will be created
 * tbl:     physical address of the table to point to
 * virt:    virtual address
 * lvl:     page-table level
 *
 * Preserves \virt
 * Clobbers \tbl, r1 - r3
 *
 * Note that \tbl and \virt should be in a register other than r1 - r3
 */
.macro create_table_entry_from_paddr, ptbl, tbl, virt, lvl
        get_table_slot r1, \virt, \lvl  /* r1 := slot in \tbl */
        lsl   r1, r1, #3                /* r1 := slot offset in \tbl */

        movw  r2, #PT_PT             /* r2:r3 := right for linear PT */
        orr   r2, r2, \tbl           /*           + \tbl paddr */
        mov   r3, #0

        adr_l \tbl, \ptbl            /* \tbl := (v,p)addr of \ptbl */

        strd  r2, r3, [\tbl, r1]
.endm

/*
 * Macro to create a page table entry in \ptbl to \tbl (symbol)
 *
 * ptbl:    table symbol where the entry will be created
 * tbl:     table symbol to point to
 * virt:    virtual address
 * lvl:     page-table level
 *
 * Preserves \virt
 * Clobbers r1 - r4
 *
 * Also use r10 for the phys offset.
 *
 * Note that \virt should be in a register other than r1 - r4
 */
.macro create_table_entry, ptbl, tbl, virt, lvl
        load_paddr r4, \tbl
        create_table_entry_from_paddr \ptbl, r4, \virt, \lvl
 .endm

/*
 * Macro to create a mapping entry in \tbl to \paddr. Only mapping in 3rd
 * level table (i.e page granularity) is supported.
 *
 * ptbl:     table symbol where the entry will be created
 * virt:    virtual address
 * phys:    physical address
 * type:    mapping type. If not specified it will be normal memory (PT_MEM_L3)
 *
 * Preserves \virt, \phys
 * Clobbers r1 - r4
 *
 * Note that \virt and \paddr should be in other registers than r1 - r4
 * and be distinct.
 */
.macro create_mapping_entry, ptbl, virt, phys, type=PT_MEM_L3
        mov_w r2, XEN_PT_LPAE_ENTRY_MASK
        lsr   r1, \virt, #THIRD_SHIFT
        and   r1, r1, r2             /* r1 := slot in \tlb */
        lsl   r1, r1, #3             /* r1 := slot offset in \tlb */

        lsr   r4, \phys, #THIRD_SHIFT
        lsl   r4, r4, #THIRD_SHIFT   /* r4 := PAGE_ALIGNED(phys) */

        movw  r2, #\type             /* r2:r3 := right for section PT */
        orr   r2, r2, r4             /*          + PAGE_ALIGNED(phys) */
        mov   r3, #0

        adr_l r4, \ptbl

        strd  r2, r3, [r4, r1]
.endm

.section .text.idmap, "ax", %progbits

/*
 * Rebuild the boot pagetable's first-level entries. The structure
 * is described in mm.c.
 *
 * Inputs:
 *   r9 : paddr(start)
 *   r10: phys offset
 *
 * Output:
 *   r12: Was a temporary mapping created?
 *
 * Clobbers r0 - r5
 */
create_page_tables:
        /* Prepare the page-tables for mapping Xen */
        mov_w r0, XEN_VIRT_START

        /*
         * We need to use a stash register because
         * create_table_entry_paddr() will clobber the register storing
         * the physical address of the table to point to.
         */
        adr_l r5, boot_third
        mov_w r4, XEN_VIRT_START
.rept XEN_NR_ENTRIES(2)
        mov   r0, r5                        /* r0 := paddr(l3 table) */
        create_table_entry_from_paddr boot_second, r0, r4, 2
        add   r4, r4, #XEN_PT_LEVEL_SIZE(2) /* r4 := Next vaddr */
        add   r5, r5, #PAGE_SIZE            /* r5 := Next table */
.endr

        /* Map the fixmap into boot_second */
        mov_w r0, FIXMAP_ADDR(0)
        create_table_entry boot_second, xen_fixmap, r0, 2

        /*
         * Find the size of Xen in pages and multiply by the size of a
         * PTE. This will then be compared in the mapping loop below.
         *
         * Note the multiplication is just to avoid using an extra
         * register/instruction per iteration.
         */
        mov_w r0, _start            /* r0 := vaddr(_start) */
        mov_w r1, _end              /* r1 := vaddr(_end) */
        sub   r0, r1, r0            /* r0 := effective size of Xen */
        lsr   r0, r0, #PAGE_SHIFT   /* r0 := Number of pages for Xen */
        lsl   r0, r0, #3            /* r0 := Number of pages * PTE size */

        /* Setup boot_third: */
        adr_l r4, boot_third

        lsr   r2, r9, #THIRD_SHIFT  /* Base address for 4K mapping */
        lsl   r2, r2, #THIRD_SHIFT
        orr   r2, r2, #PT_UPPER(MEM_L3) /* r2:r3 := map */
        orr   r2, r2, #PT_LOWER(MEM_L3)
        mov   r3, #0x0

        /* ... map of vaddr(start) in boot_third */
        mov   r1, #0
1:      strd  r2, r3, [r4, r1]       /* Map vaddr(start) */
        add   r2, r2, #PAGE_SIZE     /* Next page */
        add   r1, r1, #8             /* Next slot */
        cmp   r1, r0                 /* Loop until we map all of Xen */
        blo   1b

        /*
         * Setup the 1:1 mapping so we can turn the MMU on. Note that
         * only the first page of Xen will be part of the 1:1 mapping.
         */
        create_table_entry boot_pgtable, boot_second_id, r9, 1
        create_table_entry boot_second_id, boot_third_id, r9, 2
        create_mapping_entry boot_third_id, r9, r9

        /*
         * Find the first slot used. If the slot is not the same
         * as TEMPORARY_AREA_FIRST_SLOT, then we will want to switch
         * to the temporary mapping before jumping to the runtime
         * virtual mapping.
         */
        get_table_slot r1, r9, 1     /* r1 := first slot */
        cmp   r1, #TEMPORARY_AREA_FIRST_SLOT
        bne   use_temporary_mapping

        mov_w r0, XEN_VIRT_START
        create_table_entry boot_pgtable, boot_second, r0, 1
        mov   r12, #0                /* r12 := temporary mapping not created */
        mov   pc, lr

use_temporary_mapping:
        /*
         * The identity mapping is not using the first slot
         * TEMPORARY_AREA_FIRST_SLOT. Create a temporary mapping.
         * See switch_to_runtime_mapping for more details.
         */
        PRINT("- Create temporary mapping -\r\n")

        /* Map boot_second (cover Xen mappings) to the temporary 1st slot */
        mov_w r0, TEMPORARY_XEN_VIRT_START
        create_table_entry boot_pgtable, boot_second, r0, 1

        mov   r12, #1                /* r12 := temporary mapping created */
        mov   pc, lr
ENDPROC(create_page_tables)

/*
 * Turn on the Data Cache and the MMU. The function will return
 * to the virtual address provided in LR (e.g. the runtime mapping).
 *
 * Inputs:
 *   r9 : paddr(start)
 *  r12 : Was the temporary mapping created?
 *   lr : Virtual address to return to
 *
 * Clobbers r0 - r5
 */
enable_mmu:
        PRINT("- Turning on paging -\r\n")

        /*
         * The state of the TLBs is unknown before turning on the MMU.
         * Flush them to avoid stale one.
         */
        flush_xen_tlb_local r0

        /* Write Xen's PT's paddr into the HTTBR */
        adr_l r0, boot_pgtable
        mov   r1, #0                 /* r0:r1 is paddr (boot_pagetable) */
        mcrr  CP64(r0, r1, HTTBR)
        isb

        mrc   CP32(r0, HSCTLR)
        /* Enable MMU and D-cache */
        orr   r0, r0, #(SCTLR_Axx_ELx_M|SCTLR_Axx_ELx_C)
        dsb                          /* Flush PTE writes and finish reads */
        mcr   CP32(r0, HSCTLR)       /* now paging is enabled */
        isb                          /* Now, flush the icache */

        /*
         * At this stage, the UART address will depend on whether the
         * temporary mapping was created or not.
         *
         * If it was, then the UART will be mapped in the temporary
         * area. Otherwise, it will be mapped at runtime virtual
         * mapping.
         */
#ifdef CONFIG_EARLY_PRINTK
        teq   r12, #1               /* Was the temporary mapping created? */
        mov_w_on_cond eq, r11, TEMPORARY_EARLY_UART_VIRTUAL_ADDRESS
        mov_w_on_cond ne, r11, EARLY_UART_VIRTUAL_ADDRESS
#endif
        PRINT_ID("- Paging turned on -\r\n")

        /*
         * The MMU is turned on and we are in the 1:1 mapping. Switch
         * to the runtime mapping.
         */
        mov   r5, lr                /* Save LR before overwritting it */
        mov_w lr, 1f                /* Virtual address in the runtime mapping */
        b     switch_to_runtime_mapping
1:
        mov   lr, r5                /* Restore LR */

        /*
         * Now we are running at the runtime address. The UART can
         * be accessed using its runtime virtual address.
         */
#ifdef CONFIG_EARLY_PRINTK
        mov_w r11, EARLY_UART_VIRTUAL_ADDRESS
#endif

        PRINT("- Switched to the runtime mapping -\r\n")

        /*
         * At this point, either the 1:1 map or the temporary mapping
         * will be present. The former may clash with other parts of the
         * Xen virtual memory layout. As both of them are not used
         * anymore, remove them completely to avoid having to worry
         * about replacing existing mapping afterwards.
         *
         * On return this will jump to the virtual address requested by
         * the caller.
         */
        teq   r12, #0
        beq   remove_identity_mapping
        b     remove_temporary_mapping
ENDPROC(enable_mmu)

/*
 * Switch to the runtime mapping. The logic depends on whether the
 * runtime virtual region is clashing with the physical address
 *
 *  - If it is not clashing, we can directly jump to the address in
 *    the runtime mapping.
 *  - If it is clashing, create_page_tables() would have mapped Xen to
 *    a temporary virtual address. We need to switch to the temporary
 *    mapping so we can remove the identity mapping and map Xen at the
 *    correct position.
 *
 * Inputs
 *    r9: paddr(start)
 *   r12: Was a temporary mapping created?
 *    lr: Address in the runtime mapping to jump to
 *
 * Clobbers r0 - r4
 */
switch_to_runtime_mapping:
        /*
         * Jump to the runtime mapping if the virt and phys are not
         * clashing
         */
        teq   r12, #0
        beq   ready_to_switch

        PRINT_ID("- Switching to the temporary mapping -\r\n")
        /* We are still in the 1:1 mapping. Jump to the temporary Virtual address. */
        mov_w r0, 1f
        add   r0, r0, #XEN_TEMPORARY_OFFSET /* r0 := address in temporary mapping */
        mov   pc, r0

1:
        PRINT("- Running on the temporary mapping  -\r\n")
        /* Remove boot_second_id */
        mov   r2, #0
        mov   r3, #0
        adr_l r0, boot_pgtable
        get_table_slot r1, r9, 1            /* r1 := first slot */
        lsl   r1, r1, #3                    /* r1 := first slot offset */
        strd  r2, r3, [r0, r1]

        flush_xen_tlb_local r0

        PRINT("- 1:1 mapping removed -\r\n")

        /* Map boot_second into boot_pgtable */
        mov_w r0, XEN_VIRT_START
        create_table_entry boot_pgtable, boot_second, r0, 1

        /* Ensure any page table updates are visible before continuing */
        dsb   nsh
        /*
         * The function will return on the runtime mapping. So we want
         * to prevent instruction fetch before the dsb completes.
         */
        isb

        PRINT("- Runtime mapping mapped -\r\n")
ready_to_switch:
        PRINT_ID("- Jumping to runtime address -\r\n")

        mov   pc, lr
ENDPROC(switch_to_runtime_mapping)

/*
 * Enable mm (turn on the data cache and the MMU) for secondary CPUs.
 * The function will return to the virtual address provided in LR (e.g. the
 * runtime mapping).
 *
 * Inputs:
 *   r9 : paddr(start)
 *   r10: phys offset
 *   lr : Virtual address to return to.
 *
 * Output:
 *   r12: Was a temporary mapping created?
 *
 * Clobbers r0 - r6
 */
ENTRY(enable_secondary_cpu_mm)
        mov   r6, lr

        bl    create_page_tables

        /* Address in the runtime mapping to jump to after the MMU is enabled */
        mov_w lr, 1f
        b     enable_mmu
1:
        PRINT("- Switching to the runtime page-tables -\r\n")

        /*
         * Non-boot CPUs need to move on to the proper pagetables, which were
         * setup in prepare_secondary_mm.
         *
         * XXX: This is not compliant with the Arm Arm.
         */
        mov_w r4, init_ttbr          /* VA of HTTBR value stashed by CPU 0 */
        ldrd  r4, r5, [r4]           /* Actual value */
        dsb
        mcrr  CP64(r4, r5, HTTBR)
        dsb
        isb
        flush_xen_tlb_local r0
        pt_enforce_wxn r0

        /* Return to the virtual address requested by the caller. */
        mov   pc, r6
ENDPROC(enable_secondary_cpu_mm)

/*
 * Enable mm (turn on the data cache and the MMU) for the boot CPU.
 * The function will return to the virtual address provided in LR (e.g. the
 * runtime mapping).
 *
 * Inputs:
 *   r9 : paddr(start)
 *   r10: phys offset
 *   r11: UART physical address
 *   lr : Virtual address to return to.
 *
 * Output:
 *   r12: Was a temporary mapping created?
 *
 * Clobbers r0 - r6
 */
ENTRY(enable_boot_cpu_mm)
        mov   r6, lr

#ifdef CONFIG_EARLY_PRINTK
        /*
         * Add the UART mapping to the fixmap so the UART can be used
         * as the MMU is on. This only needs to be done on the boot CPU.
         */
        mov_w r0, EARLY_UART_VIRTUAL_ADDRESS
        create_mapping_entry xen_fixmap, r0, r11, type=PT_DEV_L3
#endif

        bl    create_page_tables

        /* Address in the runtime mapping to jump to after the MMU is enabled */
        mov   lr, r6
        b     enable_mmu
ENDPROC(enable_boot_cpu_mm)

/*
 * Remove the 1:1 map from the page-tables. It is not easy to keep track
 * where the 1:1 map was mapped, so we will look for the top-level entry
 * exclusive to the 1:1 map and remove it.
 *
 * Inputs:
 *   r9 : paddr(start)
 *
 * Clobbers r0 - r3
 */
remove_identity_mapping:
        PRINT("- Removing the identity mapping -\r\n")

        /* r2:r3 := invalid page-table entry */
        mov   r2, #0x0
        mov   r3, #0x0

        /* Find the first slot used and remove it */
        get_table_slot r1, r9, 1     /* r1 := first slot */
        mov_w r0, boot_pgtable       /* r0 := root table */
        lsl   r1, r1, #3             /* r1 := Slot offset */
        strd  r2, r3, [r0, r1]

        flush_xen_tlb_local r0
        mov   pc, lr
ENDPROC(remove_identity_mapping)

/*
 * Remove the temporary mapping of Xen starting at TEMPORARY_XEN_VIRT_START.
 *
 * Clobbers r0 - r3
 */
remove_temporary_mapping:
        PRINT("- Removing the temporary mapping -\r\n")

        /* r2:r3 := invalid page-table entry */
        mov   r2, #0
        mov   r3, #0

        adr_l r0, boot_pgtable
        mov_w r1, TEMPORARY_XEN_VIRT_START
        get_table_slot r1, r1, 1     /* r1 := first slot */
        lsl   r1, r1, #3             /* r1 := first slot offset */
        strd  r2, r3, [r0, r1]

        flush_xen_tlb_local r0

        mov  pc, lr
ENDPROC(remove_temporary_mapping)

/* Fail-stop */
fail:   PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b
ENDPROC(fail)

/*
 * Switch TTBR
 * r1:r0       ttbr
 *
 * TODO: This code does not comply with break-before-make.
 */
ENTRY(switch_ttbr)
        dsb                            /* Ensure the flushes happen before
                                        * continuing */
        isb                            /* Ensure synchronization with previous
                                        * changes to text */
        mcr   CP32(r0, TLBIALLH)       /* Flush hypervisor TLB */
        mcr   CP32(r0, ICIALLU)        /* Flush I-cache */
        mcr   CP32(r0, BPIALL)         /* Flush branch predictor */
        dsb                            /* Ensure completion of TLB+BP flush */
        isb

        mcrr  CP64(r0, r1, HTTBR)

        dsb                            /* ensure memory accesses do not cross
                                        * over the TTBR0 write */
        isb                            /* Ensure synchronization with previous
                                        * changes to text */
        mcr   CP32(r0, TLBIALLH)       /* Flush hypervisor TLB */
        mcr   CP32(r0, ICIALLU)        /* Flush I-cache */
        mcr   CP32(r0, BPIALL)         /* Flush branch predictor */
        dsb                            /* Ensure completion of TLB+BP flush */
        isb

        mov pc, lr
ENDPROC(switch_ttbr)
