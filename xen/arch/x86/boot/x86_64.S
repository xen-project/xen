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
        jz      .L_bsp

        /* APs.  Set up early exceptions and CET before entering C properly. */

        call    percpu_early_traps_init

#if defined(CONFIG_XEN_SHSTK) || defined(CONFIG_XEN_IBT)
        call    xen_msr_s_cet_value
        test    %eax, %eax
        jz      .L_ap_cet_done

        /* Set up MSR_S_CET. */
        mov     $MSR_S_CET, %ecx
        xor     %edx, %edx
        wrmsr

        /* Enable CR4.CET. */
        mov     $XEN_MINIMAL_CR4 | X86_CR4_CET, %ecx
        mov     %rcx, %cr4

        /* WARNING! call/ret now fatal (iff SHSTK) until SETSSBSY loads SSP */

#if defined(CONFIG_XEN_SHSTK)
        test    $CET_SHSTK_EN, %al
        jz      .L_ap_cet_done

        /* Derive the supervisor token address from %rsp. */
        mov     %rsp, %rdx
        and     $~(STACK_SIZE - 1), %rdx
        or      $(PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE - 8, %rdx

        /*
         * Write a new supervisor token.  Doesn't matter on boot, but for S3
         * resume this clears the busy bit.
         */
        wrssq   %rdx, (%rdx)

        /* Point MSR_PL0_SSP at the token. */
        mov     $MSR_PL0_SSP, %ecx
        mov     %edx, %eax
        shr     $32, %rdx
        wrmsr

        setssbsy

#endif /* CONFIG_XEN_SHSTK */
.L_ap_cet_done:
#endif /* CONFIG_XEN_SHSTK || CONFIG_XEN_IBT */

        tailcall start_secondary

.L_bsp:
        tailcall __start_xen

/* Around page tables the fill pattern would better be zero. */
#undef DATA_FILL
#define DATA_FILL 0

        .section .data.page_aligned, "aw", @progbits
/*
 * Mapping of first 2 megabytes of memory. This is mapped with 4kB mappings
 * to avoid type conflicts with fixed-range MTRRs covering the lowest megabyte
 * of physical memory. In any case the VGA hole should be mapped with type UC.
 * Uses 1x 4k page.
 */
DATA_LOCAL(l1_directmap, PAGE_SIZE)
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
END(l1_directmap)

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
DATA(l2_directmap, PAGE_SIZE)
        .quad sym_offs(l1_directmap) + __PAGE_HYPERVISOR
        .fill 4 * L2_PAGETABLE_ENTRIES - 1, 8, 0
END(l2_directmap)

/*
 * L2 mapping the Xen text/data/bss region, constructed dynamically.
 * Executable fixmap is hooked up statically.
 * Uses 1x 4k page.
 */
DATA(l2_xenmap, PAGE_SIZE)
        idx = 0
        .rept L2_PAGETABLE_ENTRIES
        .if idx == l2_table_offset(FIXADDR_X_TOP - 1)
        .quad sym_offs(l1_fixmap_x) + __PAGE_HYPERVISOR
        .else
        .quad 0
        .endif
        idx = idx + 1
        .endr
END(l2_xenmap)

/* L2 mapping the fixmap.  Uses 1x 4k page. */
DATA_LOCAL(l2_fixmap, PAGE_SIZE)
        idx = 0
        .rept L2_PAGETABLE_ENTRIES
        .if idx == l2_table_offset(FIXADDR_TOP - 1)
        .quad sym_offs(l1_fixmap) + __PAGE_HYPERVISOR
        .else
        .quad 0
        .endif
        idx = idx + 1
        .endr
END(l2_fixmap)

/* Direct map, initially covering the 4 l2_directmap tables.  Uses 1x 4k page. */
DATA_LOCAL(l3_directmap, PAGE_SIZE)
        idx = 0
        .rept 4
        .quad sym_offs(l2_directmap) + (idx << PAGE_SHIFT) + __PAGE_HYPERVISOR
        idx = idx + 1
        .endr
        .fill L3_PAGETABLE_ENTRIES - 4, 8, 0
END(l3_directmap)

/* L3 mapping the fixmap.  Uses 1x 4k page. */
DATA_LOCAL(l3_xenmap, PAGE_SIZE)
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
END(l3_xenmap)

/* Top-level master (and idle-domain) page directory. */
DATA(idle_pg_table, PAGE_SIZE)
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
END(idle_pg_table)

GLOBAL(__page_tables_end)

/* Init pagetables. Enough page directories to map into 4GB. */
        .section .init.data.page_aligned, "aw", @progbits

DATA_LOCAL(l1_bootmap, PAGE_SIZE)
        .fill L1_PAGETABLE_ENTRIES, 8, 0
END(l1_bootmap)

DATA(l2_bootmap, PAGE_SIZE)
        .fill 4 * L2_PAGETABLE_ENTRIES, 8, 0
END(l2_bootmap)

DATA(l3_bootmap, PAGE_SIZE)
        .fill L3_PAGETABLE_ENTRIES, 8, 0
END(l3_bootmap)
