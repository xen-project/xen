/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/arm64/mmu/head.S
 *
 * Arm64 MMU specific start-of-day code.
 */

#include <asm/page.h>
#include <asm/early_printk.h>

#define PT_PT     0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_MEM    0xf7d /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=0 P=1 */
#define PT_MEM_L3 0xf7f /* nG=1 AF=1 SH=11 AP=01 NS=1 ATTR=111 T=1 P=1 */
#define PT_DEV    0xe71 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=0 P=1 */
#define PT_DEV_L3 0xe73 /* nG=1 AF=1 SH=10 AP=01 NS=1 ATTR=100 T=1 P=1 */

/* Convenience defines to get slot used by Xen mapping. */
#define XEN_ZEROETH_SLOT    zeroeth_table_offset(XEN_VIRT_START)
#define XEN_FIRST_SLOT      first_table_offset(XEN_VIRT_START)
#define XEN_SECOND_SLOT     second_table_offset(XEN_VIRT_START)

/* Load the physical address of a symbol into xb */
.macro load_paddr xb, sym
        ldr \xb, =\sym
        add \xb, \xb, x20
.endm

/*
 * Flush local TLBs
 *
 * See asm/arm64/flushtlb.h for the explanation of the sequence.
 */
.macro flush_xen_tlb_local
        dsb   nshst
        tlbi  alle2
        dsb   nsh
        isb
.endm

/*
 * Macro to find the slot number at a given page-table level
 *
 * slot:     slot computed
 * virt:     virtual address
 * lvl:      page-table level
 */
.macro get_table_slot, slot, virt, lvl
        ubfx  \slot, \virt, #XEN_PT_LEVEL_SHIFT(\lvl), #XEN_PT_LPAE_SHIFT
.endm

/*
 * Macro to create a page table entry in \ptbl to \tbl
 * ptbl:    table symbol where the entry will be created
 * tbl:     physical address of the table to point to
 * virt:    virtual address
 * lvl:     page-table level
 * tmp1:    scratch register
 * tmp2:    scratch register
 *
 * Preserves \virt
 * Clobbers \tbl, \tmp1, \tmp2
 *
 * Note that all parameters using registers should be distinct.
 */
.macro create_table_entry_from_paddr, ptbl, tbl, virt, lvl, tmp1, tmp2
        get_table_slot \tmp1, \virt, \lvl   /* \tmp1 := slot in \tbl */

        mov   \tmp2, #PT_PT                 /* \tmp2 := right for linear PT */
        orr   \tmp2, \tmp2, \tbl            /*          + \tbl */

        adr_l \tbl, \ptbl                   /* \tbl := address(\ptbl) */

        str   \tmp2, [\tbl, \tmp1, lsl #3]
.endm

/*
 * Macro to create a page table entry in \ptbl to \tbl
 *
 * ptbl:    table symbol where the entry will be created
 * tbl:     table symbol to point to
 * virt:    virtual address
 * lvl:     page-table level
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
.macro create_table_entry, ptbl, tbl, virt, lvl, tmp1, tmp2, tmp3
        load_paddr \tmp1, \tbl
        create_table_entry_from_paddr \ptbl, \tmp1, \virt, \lvl, \tmp2, \tmp3
.endm

/*
 * Macro to create a mapping entry in \tbl to \phys. Only mapping in 3rd
 * level table (i.e page granularity) is supported.
 *
 * ptbl:    table symbol where the entry will be created
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

        get_table_slot \tmp1, \virt, 3      /* \tmp1 := slot in \tlb */

        mov   \tmp2, #\type                 /* \tmp2 := right for section PT */
        orr   \tmp2, \tmp2, \tmp3           /*          + PAGE_ALIGNED(phys) */

        adr_l \tmp3, \ptbl

        str   \tmp2, [\tmp3, \tmp1, lsl #3]
.endm

.section .text.idmap, "ax", %progbits

/*
 * Rebuild the boot pagetable's first-level entries. The structure
 * is described in mm.c.
 *
 * Inputs:
 *   x19: paddr(start)
 *   x20: phys offset
 *
 * Clobbers x0 - x4
 */
FUNC_LOCAL(create_page_tables)
        /* Prepare the page-tables for mapping Xen */
        ldr   x0, =XEN_VIRT_START
        create_table_entry boot_pgtable, boot_first, x0, 0, x1, x2, x3
        create_table_entry boot_first, boot_second, x0, 1, x1, x2, x3

        /*
         * We need to use a stash register because
         * create_table_entry_paddr() will clobber the register storing
         * the physical address of the table to point to.
         */
        load_paddr x4, boot_third
        ldr   x1, =XEN_VIRT_START
.rept XEN_NR_ENTRIES(2)
        mov   x0, x4                            /* x0 := paddr(l3 table) */
        create_table_entry_from_paddr boot_second, x0, x1, 2, x2, x3
        add   x1, x1, #XEN_PT_LEVEL_SIZE(2)     /* x1 := Next vaddr */
        add   x4, x4, #PAGE_SIZE                /* x4 := Next table */
.endr

        /*
         * Find the size of Xen in pages and multiply by the size of a
         * PTE. This will then be compared in the mapping loop below.
         *
         * Note the multiplication is just to avoid using an extra
         * register/instruction per iteration.
         */
        ldr   x0, =_start            /* x0 := vaddr(_start) */
        ldr   x1, =_end              /* x1 := vaddr(_end) */
        sub   x0, x1, x0             /* x0 := effective size of Xen */
        lsr   x0, x0, #PAGE_SHIFT    /* x0 := Number of pages for Xen */
        lsl   x0, x0, #3             /* x0 := Number of pages * PTE size */

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
        cmp   x1, x0                 /* Loop until we map all of Xen */
        b.lt  1b

        /*
         * If Xen is loaded at exactly XEN_VIRT_START then we don't
         * need an additional 1:1 mapping, the virtual mapping will
         * suffice.
         */
        ldr   x0, =XEN_VIRT_START
        cmp   x19, x0
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
        get_table_slot x0, x19, 0       /* x0 := zeroeth slot */
        cmp   x0, #XEN_ZEROETH_SLOT
        beq   1f
        create_table_entry boot_pgtable, boot_first_id, x19, 0, x0, x1, x2
        b     link_from_first_id

1:
        /*
         * Find the first slot used. If the slot is not XEN_FIRST_SLOT,
         * then the 1:1 mapping will use its own set of page-tables from
         * the second level.
         */
        get_table_slot x0, x19, 1      /* x0 := first slot */
        cmp   x0, #XEN_FIRST_SLOT
        beq   1f
        create_table_entry boot_first, boot_second_id, x19, 1, x0, x1, x2
        b     link_from_second_id

1:
        /*
         * Find the second slot used. If the slot is XEN_SECOND_SLOT, then the
         * 1:1 mapping will use its own set of page-tables from the
         * third level. For slot XEN_SECOND_SLOT, Xen is not yet able to handle
         * it.
         */
        get_table_slot x0, x19, 2     /* x0 := second slot */
        cmp   x0, #XEN_SECOND_SLOT
        beq   virtphys_clash
        create_table_entry boot_second, boot_third_id, x19, 2, x0, x1, x2
        b     link_from_third_id

link_from_first_id:
        create_table_entry boot_first_id, boot_second_id, x19, 1, x0, x1, x2
link_from_second_id:
        create_table_entry boot_second_id, boot_third_id, x19, 2, x0, x1, x2
link_from_third_id:
        create_mapping_entry boot_third_id, x19, x19, x0, x1, x2

#ifdef CONFIG_EARLY_PRINTK
        /* Add UART to the fixmap table */
        ldr   x0, =EARLY_UART_VIRTUAL_ADDRESS
        /* x23: Early UART base physical address */
        create_mapping_entry xen_fixmap, x0, x23, x1, x2, x3, type=PT_DEV_L3
#endif
        /* Map fixmap into boot_second */
        ldr   x0, =FIXMAP_ADDR(0)
        create_table_entry boot_second, xen_fixmap, x0, 2, x1, x2, x3
        ret

virtphys_clash:
        /* Identity map clashes with boot_third, which we cannot handle yet */
        PRINT("- Unable to build boot page tables - virt and phys addresses clash. -\r\n")
        b     fail
END(create_page_tables)

/*
 * Turn on the Data Cache and the MMU. The function will return on the 1:1
 * mapping. In other word, the caller is responsible to switch to the runtime
 * mapping.
 *
 * Inputs:
 *   x0 : Physical address of the page tables.
 *   x1 : Extra flags of the SCTLR.
 *
 * Clobbers x0 - x5
 */
FUNC_LOCAL(enable_mmu)
        mov   x4, x0
        mov   x5, x1
        PRINT_ID("- Turning on paging -\r\n")

        /*
         * The state of the TLBs is unknown before turning on the MMU.
         * Flush them to avoid stale one.
         */
        flush_xen_tlb_local

        /* Write Xen's PT's paddr into TTBR0_EL2 */
        msr   TTBR0_EL2, x4
        isb

        mrs   x0, SCTLR_EL2
        orr   x0, x0, #SCTLR_Axx_ELx_M  /* Enable MMU */
        orr   x0, x0, #SCTLR_Axx_ELx_C  /* Enable D-cache */
        orr   x0, x0, x5                /* Enable extra flags */
        dsb   sy                     /* Flush PTE writes and finish reads */
        msr   SCTLR_EL2, x0          /* now paging is enabled */
        isb                          /* Now, flush the icache */

#ifdef CONFIG_EARLY_PRINTK
        /* Use a virtual address to access the UART. */
        ldr   x23, =EARLY_UART_VIRTUAL_ADDRESS
#endif

        PRINT_ID("- Paging turned on -\r\n")

        ret
END(enable_mmu)

/*
 * Enable mm (turn on the data cache and the MMU) for secondary CPUs.
 * The function will return to the virtual address provided in LR (e.g. the
 * runtime mapping).
 *
 * Inputs:
 *   lr : Virtual address to return to.
 *
 * Clobbers x0 - x6
 */
FUNC(enable_secondary_cpu_mm)
        mov   x6, lr

        load_paddr x0, init_ttbr
        ldr   x0, [x0]

        mov   x1, #SCTLR_Axx_ELx_WXN        /* Enable WxN from the start */
        bl    enable_mmu
        mov   lr, x6

        /* Return to the virtual address requested by the caller. */
        ret
END(enable_secondary_cpu_mm)

/*
 * Enable mm (turn on the data cache and the MMU) for the boot CPU.
 * The function will return to the virtual address provided in LR (e.g. the
 * runtime mapping).
 *
 * Inputs:
 *   lr : Virtual address to return to.
 *
 * Clobbers x0 - x6
 */
FUNC(enable_boot_cpu_mm)
        mov   x6, lr

        bl    create_page_tables
        load_paddr x0, boot_pgtable

        mov   x1, #0        /* No extra SCTLR flags */
        bl    enable_mmu

        /*
         * The MMU is turned on and we are in the 1:1 mapping. Switch
         * to the runtime mapping.
         */
        ldr   x0, =1f
        br    x0
1:
        mov   lr, x6
        /*
         * The 1:1 map may clash with other parts of the Xen virtual memory
         * layout. As it is not used anymore, remove it completely to
         * avoid having to worry about replacing existing mapping
         * afterwards. Function will return to the virtual address requested
         * by the caller.
         */
        b     remove_identity_mapping
END(enable_boot_cpu_mm)

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
FUNC_LOCAL(remove_identity_mapping)
        /*
         * Find the zeroeth slot used. Remove the entry from zeroeth
         * table if the slot is not XEN_ZEROETH_SLOT.
         */
        get_table_slot x1, x19, 0       /* x1 := zeroeth slot */
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
        get_table_slot x1, x19, 1       /* x1 := first slot */
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
        get_table_slot x1, x19, 2       /* x1 := second slot */
        cmp   x1, #XEN_SECOND_SLOT
        beq   identity_mapping_removed
        /* It is not in slot 1, remove the entry */
        ldr   x0, =boot_second          /* x0 := second table */
        str   xzr, [x0, x1, lsl #3]

identity_mapping_removed:
        flush_xen_tlb_local

        ret
END(remove_identity_mapping)

/* Fail-stop */
FUNC_LOCAL(fail)
        PRINT("- Boot failed -\r\n")
1:      wfe
        b     1b
END(fail)

/*
 * Copy Xen to new location and switch TTBR
 * x0    ttbr
 * x1    source address
 * x2    destination address
 * x3    length
 *
 * Source and destination must be word aligned, length is rounded up
 * to a 16 byte boundary.
 *
 * MUST BE VERY CAREFUL when saving things to RAM over the copy
 */
FUNC(relocate_xen)
        /*
         * Copy 16 bytes at a time using:
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

        /*
         * Flush destination from dcache using:
         *   x9: counter
         *   x10: step
         *   x11: vaddr
         *
         * This is to ensure data is visible to the instruction cache
         */
        dsb   sy

        mov   x9, x3
        ldr   x10, =dcache_line_bytes /* x10 := step */
        ldr   x10, [x10]
        mov   x11, x2

1:      dc    cvau, x11

        add   x11, x11, x10
        subs  x9, x9, x10
        bgt   1b

        /* No need for dsb/isb because they are alredy done in switch_ttbr_id */
        b switch_ttbr_id

/*
 * Switch TTBR
 *
 * x0    ttbr
 */
FUNC(switch_ttbr_id)
        /* 1) Ensure any previous read/write have completed */
        dsb    ish
        isb

        /* 2) Turn off MMU */
        mrs    x1, SCTLR_EL2
        bic    x1, x1, #SCTLR_Axx_ELx_M
        msr    SCTLR_EL2, x1
        isb

        /* 3) Flush the TLBs */
        flush_xen_tlb_local

        /* 4) Update the TTBR */
        msr   TTBR0_EL2, x0
        isb

        /*
         * 5) Flush I-cache
         * This should not be necessary in the general case, but it's needed
         * for cache coloring because code is relocated in that case.
         */
        ic     iallu
        isb

        /* 6) Turn on the MMU */
        mrs   x1, SCTLR_EL2
        orr   x1, x1, #SCTLR_Axx_ELx_M  /* Enable MMU */
        msr   SCTLR_EL2, x1
        isb

        ret
END(switch_ttbr_id)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
