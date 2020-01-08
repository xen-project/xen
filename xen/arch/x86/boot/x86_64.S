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
        .quad   cpu0_stack + STACK_SIZE - CPUINFO_sizeof

        .section .data.page_aligned, "aw", @progbits
        .align PAGE_SIZE, 0
/*
 * Mapping of first 2 megabytes of memory. This is mapped with 4kB mappings
 * to avoid type conflicts with fixed-range MTRRs covering the lowest megabyte
 * of physical memory. In any case the VGA hole should be mapped with type UC.
 * Uses 1x 4k page.
 */
l1_directmap:
        pfn = 0
        .rept L1_PAGETABLE_ENTRIES
        /* VGA hole (0xa0000-0xc0000) should be mapped UC-. */
        .if pfn >= 0xa0 && pfn < 0xc0
        .quad (pfn << PAGE_SHIFT) | __PAGE_HYPERVISOR_UCMINUS | _PAGE_GLOBAL | MAP_SMALL_PAGES
        .else
        .quad (pfn << PAGE_SHIFT) | PAGE_HYPERVISOR_RWX | MAP_SMALL_PAGES
        .endif
        pfn = pfn + 1
        .endr
        .size l1_directmap, . - l1_directmap

/*
 * __page_tables_{start,end} cover the range of pagetables which need
 * relocating as Xen moves around physical memory.  i.e. each sym_offs()
 * reference to a different pagetable in the Xen image.
 */
GLOBAL(__page_tables_start)

/*
 * Space for 4G worth of 2M mappings, first 2M actually mapped via
 * l1_directmap[].  Uses 4x 4k pages.
 */
GLOBAL(l2_directmap)
        .quad sym_offs(l1_directmap) + __PAGE_HYPERVISOR
        .fill 4 * L2_PAGETABLE_ENTRIES - 1, 8, 0
        .size l2_directmap, . - l2_directmap

/*
 * L2 mapping the Xen text/data/bss region, constructed dynamically.
 * Executable fixmap is hooked up statically.
 * Uses 1x 4k page.
 */
GLOBAL(l2_xenmap)
        idx = 0
        .rept L2_PAGETABLE_ENTRIES
        .if idx == l2_table_offset(FIXADDR_X_TOP - 1)
        .quad sym_offs(l1_fixmap_x) + __PAGE_HYPERVISOR
        .else
        .quad 0
        .endif
        idx = idx + 1
        .endr
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

/* Direct map, initially covering the 4 l2_directmap tables.  Uses 1x 4k page. */
l3_directmap:
        idx = 0
        .rept 4
        .quad sym_offs(l2_directmap) + (idx << PAGE_SHIFT) + __PAGE_HYPERVISOR
        idx = idx + 1
        .endr
        .fill L3_PAGETABLE_ENTRIES - 4, 8, 0
        .size l3_directmap, . - l3_directmap

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
        .quad sym_offs(l3_directmap) + __PAGE_HYPERVISOR
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

l1_bootmap:
        .fill L1_PAGETABLE_ENTRIES, 8, 0
        .size l1_bootmap, . - l1_bootmap

GLOBAL(l2_bootmap)
        .fill 4 * L2_PAGETABLE_ENTRIES, 8, 0
        .size l2_bootmap, . - l2_bootmap

GLOBAL(l3_bootmap)
        .fill L3_PAGETABLE_ENTRIES, 8, 0
        .size l3_bootmap, . - l3_bootmap
