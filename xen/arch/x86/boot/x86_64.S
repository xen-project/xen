        .text
        .code64

ENTRY(__high_start)
        /* Install relocated data selectors. */
        lgdt    boot_gdtr(%rip)
        mov     $(__HYPERVISOR_DS64),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss

        /* Enable minimal CR4 features. */
        mov     $XEN_MINIMAL_CR4,%rcx
        mov     %rcx,%cr4

        mov     stack_start(%rip),%rsp
        or      $(STACK_SIZE-CPUINFO_sizeof),%rsp

        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushq   $0
        popf

        /* Reload code selector. */
        pushq   $__HYPERVISOR_CS
        leaq    1f(%rip),%rax
        pushq   %rax
        lretq
1:
        test    %ebx,%ebx
        jnz     start_secondary

        /* Pass off the Multiboot info structure to C land (if applicable). */
        mov     multiboot_ptr(%rip),%edi
        call    __start_xen
        BUG     /* __start_xen() shouldn't return. */

        .data
        .align 8
multiboot_ptr:
        .long   0

GLOBAL(stack_start)
        .quad   cpu0_stack

        .section .data.page_aligned, "aw", @progbits
        .align PAGE_SIZE, 0
/*
 * Mapping of first 2 megabytes of memory. This is mapped with 4kB mappings
 * to avoid type conflicts with fixed-range MTRRs covering the lowest megabyte
 * of physical memory. In any case the VGA hole should be mapped with type UC.
 * Uses 1x 4k page.
 */
l1_identmap:
        pfn = 0
        .rept L1_PAGETABLE_ENTRIES
        /* VGA hole (0xa0000-0xc0000) should be mapped UC-. */
        .if pfn >= 0xa0 && pfn < 0xc0
        .quad (pfn << PAGE_SHIFT) | PAGE_HYPERVISOR_UCMINUS | MAP_SMALL_PAGES
        .else
        .quad (pfn << PAGE_SHIFT) | PAGE_HYPERVISOR | MAP_SMALL_PAGES
        .endif
        pfn = pfn + 1
        .endr
        .size l1_identmap, . - l1_identmap

/*
 * __page_tables_start does not cover l1_identmap because it (l1_identmap)
 * contains 1-1 mappings. This means that frame addresses of these mappings
 * are static and should not be updated at runtime.
 */
GLOBAL(__page_tables_start)

/*
 * Space for mapping the first 4GB of memory, with the first 16 megabytes
 * actualy mapped (mostly using superpages).  Uses 4x 4k pages.
 */
GLOBAL(l2_identmap)
        .quad sym_offs(l1_identmap) + __PAGE_HYPERVISOR
        idx = 1
        .rept 7
        .quad (idx << L2_PAGETABLE_SHIFT) | PAGE_HYPERVISOR | _PAGE_PSE
        idx = idx + 1
        .endr
        .fill 4 * L2_PAGETABLE_ENTRIES - 8, 8, 0
        .size l2_identmap, . - l2_identmap

/*
 * L2 mapping the 1GB Xen text/data/bss region.  At boot it maps 16MB from
 * __image_base__, and is modified when Xen relocates itself.  Uses 1x 4k
 * page.
 */
GLOBAL(l2_xenmap)
        .quad 0
        idx = 1
        .rept 7
        .quad sym_offs(__image_base__) + (idx << L2_PAGETABLE_SHIFT) + (PAGE_HYPERVISOR | _PAGE_PSE)
        idx = idx + 1
        .endr
        .fill L2_PAGETABLE_ENTRIES - 8, 8, 0
        .size l2_xenmap, . - l2_xenmap

/* L2 mapping the fixmap.  Uses 1x 4k page. */
l2_fixmap:
        idx = 0
        .rept L2_PAGETABLE_ENTRIES
        .if idx == l2_table_offset(FIXADDR_TOP - 1)
        .quad sym_offs(l1_fixmap) + __PAGE_HYPERVISOR
        .else
        .quad 0
        .endif
        idx = idx + 1
        .endr
        .size l2_fixmap, . - l2_fixmap

/* Identity map, covering the 4 l2_identmap tables.  Uses 1x 4k page. */
l3_identmap:
        idx = 0
        .rept 4
        .quad sym_offs(l2_identmap) + (idx << PAGE_SHIFT) + __PAGE_HYPERVISOR
        idx = idx + 1
        .endr
        .fill L3_PAGETABLE_ENTRIES - 4, 8, 0
        .size l3_identmap, . - l3_identmap

/* L3 mapping the fixmap.  Uses 1x 4k page. */
l3_xenmap:
        idx = 0
        .rept L3_PAGETABLE_ENTRIES
        .if idx == l3_table_offset(XEN_VIRT_START)
        .quad sym_offs(l2_xenmap) + __PAGE_HYPERVISOR
        .elseif idx == l3_table_offset(FIXADDR_TOP - 1)
        .quad sym_offs(l2_fixmap) + __PAGE_HYPERVISOR
        .else
        .quad 0
        .endif
        idx = idx + 1
        .endr
        .size l3_xenmap, . - l3_xenmap

/* Top-level master (and idle-domain) page directory. */
GLOBAL(idle_pg_table)
        .quad sym_offs(l3_bootmap) + __PAGE_HYPERVISOR
        idx = 1
        .rept L4_PAGETABLE_ENTRIES - 1
        .if idx == l4_table_offset(DIRECTMAP_VIRT_START)
        .quad sym_offs(l3_identmap) + __PAGE_HYPERVISOR
        .elseif idx == l4_table_offset(XEN_VIRT_START)
        .quad sym_offs(l3_xenmap) + __PAGE_HYPERVISOR
        .else
        .quad 0
        .endif
        idx = idx + 1
        .endr
        .size idle_pg_table, . - idle_pg_table

GLOBAL(__page_tables_end)

/* Init pagetables. Enough page directories to map into 4GB. */
        .section .init.data, "aw", @progbits
        .align PAGE_SIZE, 0

GLOBAL(l2_bootmap)
        .fill 4 * L2_PAGETABLE_ENTRIES, 8, 0
        .size l2_bootmap, . - l2_bootmap

GLOBAL(l3_bootmap)
        .fill L3_PAGETABLE_ENTRIES, 8, 0
        .size l3_bootmap, . - l3_bootmap
