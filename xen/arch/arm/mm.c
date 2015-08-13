/*
 * xen/arch/arm/mm.c
 *
 * MMU code for an ARMv7-A with virt extensions.
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

#include <xen/config.h>
#include <xen/compile.h>
#include <xen/types.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/preempt.h>
#include <xen/errno.h>
#include <xen/grant_table.h>
#include <xen/softirq.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <public/memory.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <xsm/xsm.h>
#include <xen/pfn.h>

struct domain *dom_xen, *dom_io, *dom_cow;

/* Static start-of-day pagetables that we use before the allocators
 * are up. These are used by all CPUs during bringup before switching
 * to the CPUs own pagetables.
 *
 * These pagetables have a very simple structure. They include:
 *  - 2MB worth of 4K mappings of xen at XEN_VIRT_START, boot_first and
 *    boot_second are used to populate the tables down to boot_third
 *    which contains the actual mapping.
 *  - a 1:1 mapping of xen at its current physical address. This uses a
 *    section mapping at whichever of boot_{pgtable,first,second}
 *    covers that physical address.
 *
 * For the boot CPU these mappings point to the address where Xen was
 * loaded by the bootloader. For secondary CPUs they point to the
 * relocated copy of Xen for the benefit of secondary CPUs.
 *
 * In addition to the above for the boot CPU the device-tree is
 * initially mapped in the boot misc slot. This mapping is not present
 * for secondary CPUs.
 *
 * Finally, if EARLY_PRINTK is enabled then xen_fixmap will be mapped
 * by the CPU once it has moved off the 1:1 mapping.
 */
lpae_t boot_pgtable[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
#ifdef CONFIG_ARM_64
lpae_t boot_first[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
lpae_t boot_first_id[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
#endif
lpae_t boot_second[LPAE_ENTRIES]  __attribute__((__aligned__(4096)));
lpae_t boot_third[LPAE_ENTRIES]  __attribute__((__aligned__(4096)));

/* Main runtime page tables */

/*
 * For arm32 xen_pgtable and xen_dommap are per-PCPU and are allocated before
 * bringing up each CPU. For arm64 xen_pgtable is common to all PCPUs.
 *
 * xen_second, xen_fixmap and xen_xenmap are always shared between all
 * PCPUs.
 */

#ifdef CONFIG_ARM_64
#define HYP_PT_ROOT_LEVEL 0
lpae_t xen_pgtable[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
lpae_t xen_first[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
#define THIS_CPU_PGTABLE xen_pgtable
#else
#define HYP_PT_ROOT_LEVEL 1
/* Per-CPU pagetable pages */
/* xen_pgtable == root of the trie (zeroeth level on 64-bit, first on 32-bit) */
static DEFINE_PER_CPU(lpae_t *, xen_pgtable);
#define THIS_CPU_PGTABLE this_cpu(xen_pgtable)
/* xen_dommap == pages used by map_domain_page, these pages contain
 * the second level pagetables which map the domheap region
 * DOMHEAP_VIRT_START...DOMHEAP_VIRT_END in 2MB chunks. */
static DEFINE_PER_CPU(lpae_t *, xen_dommap);
/* Root of the trie for cpu0, other CPU's PTs are dynamically allocated */
lpae_t cpu0_pgtable[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
/* cpu0's domheap page tables */
lpae_t cpu0_dommap[LPAE_ENTRIES*DOMHEAP_SECOND_PAGES]
    __attribute__((__aligned__(4096*DOMHEAP_SECOND_PAGES)));
#endif

#ifdef CONFIG_ARM_64
/* The first page of the first level mapping of the xenheap. The
 * subsequent xenheap first level pages are dynamically allocated, but
 * we need this one to bootstrap ourselves. */
lpae_t xenheap_first_first[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
/* The zeroeth level slot which uses xenheap_first_first. Used because
 * setup_xenheap_mappings otherwise relies on mfn_to_virt which isn't
 * valid for a non-xenheap mapping. */
static __initdata int xenheap_first_first_slot = -1;
#endif

/* Common pagetable leaves */
/* Second level page tables.
 *
 * The second-level table is 2 contiguous pages long, and covers all
 * addresses from 0 to 0x7fffffff. Offsets into it are calculated
 * with second_linear_offset(), not second_table_offset().
 */
lpae_t xen_second[LPAE_ENTRIES*2] __attribute__((__aligned__(4096*2)));
/* First level page table used for fixmap */
lpae_t xen_fixmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));
/* First level page table used to map Xen itself with the XN bit set
 * as appropriate. */
static lpae_t xen_xenmap[LPAE_ENTRIES] __attribute__((__aligned__(4096)));

/* Non-boot CPUs use this to find the correct pagetables. */
uint64_t init_ttbr;

static paddr_t phys_offset;

/* Limits of the Xen heap */
unsigned long xenheap_mfn_start __read_mostly = ~0UL;
unsigned long xenheap_mfn_end __read_mostly;
vaddr_t xenheap_virt_end __read_mostly;
#ifdef CONFIG_ARM_64
vaddr_t xenheap_virt_start __read_mostly;
#endif

unsigned long frametable_base_pdx __read_mostly;
unsigned long frametable_virt_end __read_mostly;

unsigned long max_page;
unsigned long total_pages;

extern char __init_begin[], __init_end[];

/* Checking VA memory layout alignment. */
static inline void check_memory_layout_alignment_constraints(void) {
    /* 2MB aligned regions */
    BUILD_BUG_ON(XEN_VIRT_START & ~SECOND_MASK);
    BUILD_BUG_ON(FIXMAP_ADDR(0) & ~SECOND_MASK);
    BUILD_BUG_ON(BOOT_RELOC_VIRT_START & ~SECOND_MASK);
    /* 1GB aligned regions */
#ifdef CONFIG_ARM_32
    BUILD_BUG_ON(XENHEAP_VIRT_START & ~FIRST_MASK);
#else
    BUILD_BUG_ON(DIRECTMAP_VIRT_START & ~FIRST_MASK);
#endif
    /* Page table structure constraints */
#ifdef CONFIG_ARM_64
    BUILD_BUG_ON(zeroeth_table_offset(XEN_VIRT_START));
#endif
    BUILD_BUG_ON(first_table_offset(XEN_VIRT_START));
    BUILD_BUG_ON(second_linear_offset(XEN_VIRT_START) >= LPAE_ENTRIES);
#ifdef CONFIG_DOMAIN_PAGE
    BUILD_BUG_ON(DOMHEAP_VIRT_START & ~FIRST_MASK);
#endif
}

void dump_pt_walk(paddr_t ttbr, paddr_t addr,
                  unsigned int root_level,
                  unsigned int nr_root_tables)
{
    static const char *level_strs[4] = { "0TH", "1ST", "2ND", "3RD" };
    const unsigned long root_pfn = paddr_to_pfn(ttbr);
    const unsigned int offsets[4] = {
        zeroeth_table_offset(addr),
        first_table_offset(addr),
        second_table_offset(addr),
        third_table_offset(addr)
    };
    lpae_t pte, *mapping;
    unsigned int level, root_table;

#ifdef CONFIG_ARM_32
    BUG_ON(root_level < 1);
#endif
    BUG_ON(root_level > 3);

    if ( nr_root_tables > 1 )
    {
        /*
         * Concatenated root-level tables. The table number will be
         * the offset at the previous level. It is not possible to
         * concatenate a level-0 root.
         */
        BUG_ON(root_level == 0);
        root_table = offsets[root_level - 1];
        printk("Using concatenated root table %u\n", root_table);
        if ( root_table >= nr_root_tables )
        {
            printk("Invalid root table offset\n");
            return;
        }
    }
    else
        root_table = 0;

    mapping = map_domain_page(_mfn(root_pfn + root_table));

    for ( level = root_level; ; level++ )
    {
        if ( offsets[level] > LPAE_ENTRIES )
            break;

        pte = mapping[offsets[level]];

        printk("%s[0x%x] = 0x%"PRIpaddr"\n",
               level_strs[level], offsets[level], pte.bits);

        if ( level == 3 || !pte.walk.valid || !pte.walk.table )
            break;

        /* For next iteration */
        unmap_domain_page(mapping);
        mapping = map_domain_page(_mfn(pte.walk.base));
    }

    unmap_domain_page(mapping);
}

void dump_hyp_walk(vaddr_t addr)
{
    uint64_t ttbr = READ_SYSREG64(TTBR0_EL2);
    lpae_t *pgtable = THIS_CPU_PGTABLE;

    printk("Walking Hypervisor VA 0x%"PRIvaddr" "
           "on CPU%d via TTBR 0x%016"PRIx64"\n",
           addr, smp_processor_id(), ttbr);

    if ( smp_processor_id() == 0 )
        BUG_ON( (lpae_t *)(unsigned long)(ttbr - phys_offset) != pgtable );
    else
        BUG_ON( virt_to_maddr(pgtable) != ttbr );
    dump_pt_walk(ttbr, addr, HYP_PT_ROOT_LEVEL, 1);
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, unsigned long mfn, unsigned attributes)
{
    lpae_t pte = mfn_to_xen_entry(mfn, attributes);
    pte.pt.table = 1; /* 4k mappings always have this bit set */
    pte.pt.xn = 1;
    write_pte(xen_fixmap + third_table_offset(FIXMAP_ADDR(map)), pte);
    flush_xen_data_tlb_range_va(FIXMAP_ADDR(map), PAGE_SIZE);
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{
    lpae_t pte = {0};
    write_pte(xen_fixmap + third_table_offset(FIXMAP_ADDR(map)), pte);
    flush_xen_data_tlb_range_va(FIXMAP_ADDR(map), PAGE_SIZE);
}

#ifdef CONFIG_DOMAIN_PAGE
void *map_domain_page_global(mfn_t mfn)
{
    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *va)
{
    vunmap(va);
}

/* Map a page of domheap memory */
void *map_domain_page(mfn_t mfn)
{
    unsigned long flags;
    lpae_t *map = this_cpu(xen_dommap);
    unsigned long slot_mfn = mfn_x(mfn) & ~LPAE_ENTRY_MASK;
    vaddr_t va;
    lpae_t pte;
    int i, slot;

    local_irq_save(flags);

    /* The map is laid out as an open-addressed hash table where each
     * entry is a 2MB superpage pte.  We use the available bits of each
     * PTE as a reference count; when the refcount is zero the slot can
     * be reused. */
    for ( slot = (slot_mfn >> LPAE_SHIFT) % DOMHEAP_ENTRIES, i = 0;
          i < DOMHEAP_ENTRIES;
          slot = (slot + 1) % DOMHEAP_ENTRIES, i++ )
    {
        if ( map[slot].pt.avail < 0xf &&
             map[slot].pt.base == slot_mfn &&
             map[slot].pt.valid )
        {
            /* This slot already points to the right place; reuse it */
            map[slot].pt.avail++;
            break;
        }
        else if ( map[slot].pt.avail == 0 )
        {
            /* Commandeer this 2MB slot */
            pte = mfn_to_xen_entry(slot_mfn, WRITEALLOC);
            pte.pt.avail = 1;
            write_pte(map + slot, pte);
            break;
        }

    }
    /* If the map fills up, the callers have misbehaved. */
    BUG_ON(i == DOMHEAP_ENTRIES);

#ifndef NDEBUG
    /* Searching the hash could get slow if the map starts filling up.
     * Cross that bridge when we come to it */
    {
        static int max_tries = 32;
        if ( i >= max_tries )
        {
            dprintk(XENLOG_WARNING, "Domheap map is filling: %i tries\n", i);
            max_tries *= 2;
        }
    }
#endif

    local_irq_restore(flags);

    va = (DOMHEAP_VIRT_START
          + (slot << SECOND_SHIFT)
          + ((mfn_x(mfn) & LPAE_ENTRY_MASK) << THIRD_SHIFT));

    /*
     * We may not have flushed this specific subpage at map time,
     * since we only flush the 4k page not the superpage
     */
    flush_xen_data_tlb_range_va_local(va, PAGE_SIZE);

    return (void *)va;
}

/* Release a mapping taken with map_domain_page() */
void unmap_domain_page(const void *va)
{
    unsigned long flags;
    lpae_t *map = this_cpu(xen_dommap);
    int slot = ((unsigned long) va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;

    local_irq_save(flags);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    map[slot].pt.avail--;

    local_irq_restore(flags);
}

unsigned long domain_page_map_to_mfn(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    lpae_t *map = this_cpu(xen_dommap);
    int slot = (va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;
    unsigned long offset = (va>>THIRD_SHIFT) & LPAE_ENTRY_MASK;

    if ( va >= VMAP_VIRT_START && va < VMAP_VIRT_END )
        return virt_to_mfn(va);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    return map[slot].pt.base + offset;
}
#endif

void flush_page_to_ram(unsigned long mfn)
{
    void *v = map_domain_page(_mfn(mfn));

    clean_and_invalidate_dcache_va_range(v, PAGE_SIZE);
    unmap_domain_page(v);
}

void __init arch_init_memory(void)
{
    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = domain_create(DOMID_XEN, DOMCRF_dummy, 0, NULL);
    BUG_ON(IS_ERR(dom_xen));

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = domain_create(DOMID_IO, DOMCRF_dummy, 0, NULL);
    BUG_ON(IS_ERR(dom_io));

    /*
     * Initialise our COW domain.
     * This domain owns sharable pages.
     */
    dom_cow = domain_create(DOMID_COW, DOMCRF_dummy, 0, NULL);
    BUG_ON(IS_ERR(dom_cow));
}

static inline lpae_t pte_of_xenaddr(vaddr_t va)
{
    paddr_t ma = va + phys_offset;
    unsigned long mfn = ma >> PAGE_SHIFT;
    return mfn_to_xen_entry(mfn, WRITEALLOC);
}

void __init remove_early_mappings(void)
{
    lpae_t pte = {0};
    write_pte(xen_second + second_table_offset(BOOT_FDT_VIRT_START), pte);
    flush_xen_data_tlb_range_va(BOOT_FDT_VIRT_START, SECOND_SIZE);
}

extern void relocate_xen(uint64_t ttbr, void *src, void *dst, size_t len);

/* Boot-time pagetable setup.
 * Changes here may need matching changes in head.S */
void __init setup_pagetables(unsigned long boot_phys_offset, paddr_t xen_paddr)
{
    uint64_t ttbr;
    unsigned long dest_va;
    lpae_t pte, *p;
    int i;

    /* Map the destination in the boot misc area. */
    dest_va = BOOT_RELOC_VIRT_START;
    pte = mfn_to_xen_entry(xen_paddr >> PAGE_SHIFT, WRITEALLOC);
    write_pte(xen_second + second_table_offset(dest_va), pte);
    flush_xen_data_tlb_range_va_local(dest_va, SECOND_SIZE);

    /* Calculate virt-to-phys offset for the new location */
    phys_offset = xen_paddr - (unsigned long) _start;

#ifdef CONFIG_ARM_64
    p = (void *) xen_pgtable;
    p[0] = pte_of_xenaddr((uintptr_t)xen_first);
    p[0].pt.table = 1;
    p[0].pt.xn = 0;
    p = (void *) xen_first;
#else
    p = (void *) cpu0_pgtable;
#endif

    /* Initialise first level entries, to point to second level entries */
    for ( i = 0; i < 2; i++)
    {
        p[i] = pte_of_xenaddr((uintptr_t)(xen_second+i*LPAE_ENTRIES));
        p[i].pt.table = 1;
        p[i].pt.xn = 0;
    }

#ifdef CONFIG_ARM_32
    for ( i = 0; i < DOMHEAP_SECOND_PAGES; i++ )
    {
        p[first_table_offset(DOMHEAP_VIRT_START+i*FIRST_SIZE)]
            = pte_of_xenaddr((uintptr_t)(cpu0_dommap+i*LPAE_ENTRIES));
        p[first_table_offset(DOMHEAP_VIRT_START+i*FIRST_SIZE)].pt.table = 1;
    }
#endif

    /* Initialise xen second level entries ... */
    /* ... Xen's text etc */

    pte = mfn_to_xen_entry(xen_paddr>>PAGE_SHIFT, WRITEALLOC);
    pte.pt.xn = 0;/* Contains our text mapping! */
    xen_second[second_table_offset(XEN_VIRT_START)] = pte;

    /* ... Fixmap */
    pte = pte_of_xenaddr((vaddr_t)xen_fixmap);
    pte.pt.table = 1;
    xen_second[second_table_offset(FIXMAP_ADDR(0))] = pte;

    /* ... DTB */
    pte = boot_second[second_table_offset(BOOT_FDT_VIRT_START)];
    xen_second[second_table_offset(BOOT_FDT_VIRT_START)] = pte;

    /* Map the destination in the boot misc area. */
    dest_va = BOOT_RELOC_VIRT_START;
    pte = mfn_to_xen_entry(xen_paddr >> PAGE_SHIFT, WRITEALLOC);
    write_pte(boot_second + second_table_offset(dest_va), pte);
    flush_xen_data_tlb_range_va_local(dest_va, SECOND_SIZE);
#ifdef CONFIG_ARM_64
    ttbr = (uintptr_t) xen_pgtable + phys_offset;
#else
    ttbr = (uintptr_t) cpu0_pgtable + phys_offset;
#endif

    relocate_xen(ttbr, _start, (void*)dest_va, _end - _start);

    /* Clear the copy of the boot pagetables. Each secondary CPU
     * rebuilds these itself (see head.S) */
    memset(boot_pgtable, 0x0, PAGE_SIZE);
    clean_and_invalidate_dcache(boot_pgtable);
#ifdef CONFIG_ARM_64
    memset(boot_first, 0x0, PAGE_SIZE);
    clean_and_invalidate_dcache(boot_first);
    memset(boot_first_id, 0x0, PAGE_SIZE);
    clean_and_invalidate_dcache(boot_first_id);
#endif
    memset(boot_second, 0x0, PAGE_SIZE);
    clean_and_invalidate_dcache(boot_second);
    memset(boot_third, 0x0, PAGE_SIZE);
    clean_and_invalidate_dcache(boot_third);

    /* Break up the Xen mapping into 4k pages and protect them separately. */
    for ( i = 0; i < LPAE_ENTRIES; i++ )
    {
        unsigned long mfn = paddr_to_pfn(xen_paddr) + i;
        unsigned long va = XEN_VIRT_START + (i << PAGE_SHIFT);
        if ( !is_kernel(va) )
            break;
        pte = mfn_to_xen_entry(mfn, WRITEALLOC);
        pte.pt.table = 1; /* 4k mappings always have this bit set */
        if ( is_kernel_text(va) || is_kernel_inittext(va) )
        {
            pte.pt.xn = 0;
            pte.pt.ro = 1;
        }
        if ( is_kernel_rodata(va) )
            pte.pt.ro = 1;
        write_pte(xen_xenmap + i, pte);
        /* No flush required here as page table is not hooked in yet. */
    }

    pte = pte_of_xenaddr((vaddr_t)xen_xenmap);
    pte.pt.table = 1;
    write_pte(xen_second + second_linear_offset(XEN_VIRT_START), pte);
    /* TLBFLUSH and ISB would be needed here, but wait until we set WXN */

    /* From now on, no mapping may be both writable and executable. */
    WRITE_SYSREG32(READ_SYSREG32(SCTLR_EL2) | SCTLR_WXN, SCTLR_EL2);
    /* Flush everything after setting WXN bit. */
    flush_xen_text_tlb_local();

#ifdef CONFIG_ARM_32
    per_cpu(xen_pgtable, 0) = cpu0_pgtable;
    per_cpu(xen_dommap, 0) = cpu0_dommap;

    /* Make sure it is clear */
    memset(this_cpu(xen_dommap), 0, DOMHEAP_SECOND_PAGES*PAGE_SIZE);
    clean_dcache_va_range(this_cpu(xen_dommap),
                              DOMHEAP_SECOND_PAGES*PAGE_SIZE);
#endif
}

#ifdef CONFIG_ARM_64
int init_secondary_pagetables(int cpu)
{
    /* Set init_ttbr for this CPU coming up. All CPus share a single setof
     * pagetables, but rewrite it each time for consistency with 32 bit. */
    init_ttbr = (uintptr_t) xen_pgtable + phys_offset;
    clean_dcache(init_ttbr);
    return 0;
}
#else
int init_secondary_pagetables(int cpu)
{
    lpae_t *first, *domheap, pte;
    int i;

    first = alloc_xenheap_page(); /* root == first level on 32-bit 3-level trie */
    domheap = alloc_xenheap_pages(get_order_from_pages(DOMHEAP_SECOND_PAGES), 0);

    if ( domheap == NULL || first == NULL )
    {
        printk("Not enough free memory for secondary CPU%d pagetables\n", cpu);
        free_xenheap_pages(domheap, get_order_from_pages(DOMHEAP_SECOND_PAGES));
        free_xenheap_page(first);
        return -ENOMEM;
    }

    /* Initialise root pagetable from root of boot tables */
    memcpy(first, cpu0_pgtable, PAGE_SIZE);

    /* Ensure the domheap has no stray mappings */
    memset(domheap, 0, DOMHEAP_SECOND_PAGES*PAGE_SIZE);

    /* Update the first level mapping to reference the local CPUs
     * domheap mapping pages. */
    for ( i = 0; i < DOMHEAP_SECOND_PAGES; i++ )
    {
        pte = mfn_to_xen_entry(virt_to_mfn(domheap+i*LPAE_ENTRIES), WRITEALLOC);
        pte.pt.table = 1;
        write_pte(&first[first_table_offset(DOMHEAP_VIRT_START+i*FIRST_SIZE)], pte);
    }

    clean_dcache_va_range(first, PAGE_SIZE);
    clean_dcache_va_range(domheap, DOMHEAP_SECOND_PAGES*PAGE_SIZE);

    per_cpu(xen_pgtable, cpu) = first;
    per_cpu(xen_dommap, cpu) = domheap;

    /* Set init_ttbr for this CPU coming up */
    init_ttbr = __pa(first);
    clean_dcache(init_ttbr);

    return 0;
}
#endif

/* MMU setup for secondary CPUS (which already have paging enabled) */
void __cpuinit mmu_init_secondary_cpu(void)
{
    /* From now on, no mapping may be both writable and executable. */
    WRITE_SYSREG32(READ_SYSREG32(SCTLR_EL2) | SCTLR_WXN, SCTLR_EL2);
    flush_xen_text_tlb_local();
}

/* Create Xen's mappings of memory.
 * Base and virt must be 32MB aligned and size a multiple of 32MB.
 * second must be a contiguous set of second level page tables
 * covering the region starting at virt_offset. */
static void __init create_32mb_mappings(lpae_t *second,
                                        unsigned long virt_offset,
                                        unsigned long base_mfn,
                                        unsigned long nr_mfns)
{
    unsigned long i, count;
    lpae_t pte, *p;

    ASSERT(!((virt_offset >> PAGE_SHIFT) % (16 * LPAE_ENTRIES)));
    ASSERT(!(base_mfn % (16 * LPAE_ENTRIES)));
    ASSERT(!(nr_mfns % (16 * LPAE_ENTRIES)));

    count = nr_mfns / LPAE_ENTRIES;
    p = second + second_linear_offset(virt_offset);
    pte = mfn_to_xen_entry(base_mfn, WRITEALLOC);
    pte.pt.contig = 1;  /* These maps are in 16-entry contiguous chunks. */
    for ( i = 0; i < count; i++ )
    {
        write_pte(p + i, pte);
        pte.pt.base += 1 << LPAE_SHIFT;
    }
    flush_xen_data_tlb_local();
}

#ifdef CONFIG_ARM_32
/* Set up the xenheap: up to 1GB of contiguous, always-mapped memory. */
void __init setup_xenheap_mappings(unsigned long base_mfn,
                                   unsigned long nr_mfns)
{
    create_32mb_mappings(xen_second, XENHEAP_VIRT_START, base_mfn, nr_mfns);

    /* Record where the xenheap is, for translation routines. */
    xenheap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
    xenheap_mfn_start = base_mfn;
    xenheap_mfn_end = base_mfn + nr_mfns;
}
#else /* CONFIG_ARM_64 */
void __init setup_xenheap_mappings(unsigned long base_mfn,
                                   unsigned long nr_mfns)
{
    lpae_t *first, pte;
    unsigned long mfn, end_mfn;
    vaddr_t vaddr;

    /* Align to previous 1GB boundary */
    mfn = base_mfn & ~((FIRST_SIZE>>PAGE_SHIFT)-1);

    /* First call sets the xenheap physical and virtual offset. */
    if ( xenheap_mfn_start == ~0UL )
    {
        xenheap_mfn_start = base_mfn;
        xenheap_virt_start = DIRECTMAP_VIRT_START +
            (base_mfn - mfn) * PAGE_SIZE;
    }

    if ( base_mfn < xenheap_mfn_start )
        panic("cannot add xenheap mapping at %lx below heap start %lx",
              base_mfn, xenheap_mfn_start);

    end_mfn = base_mfn + nr_mfns;

    /*
     * Virtual address aligned to previous 1GB to match physical
     * address alignment done above.
     */
    vaddr = (vaddr_t)mfn_to_virt(base_mfn) & FIRST_MASK;

    while ( mfn < end_mfn )
    {
        int slot = zeroeth_table_offset(vaddr);
        lpae_t *p = &xen_pgtable[slot];

        if ( p->pt.valid )
        {
            /* mfn_to_virt is not valid on the 1st 1st mfn, since it
             * is not within the xenheap. */
            first = slot == xenheap_first_first_slot ?
                xenheap_first_first : mfn_to_virt(p->pt.base);
        }
        else if ( xenheap_first_first_slot == -1)
        {
            /* Use xenheap_first_first to bootstrap the mappings */
            first = xenheap_first_first;

            pte = pte_of_xenaddr((vaddr_t)xenheap_first_first);
            pte.pt.table = 1;
            write_pte(p, pte);

            xenheap_first_first_slot = slot;
        }
        else
        {
            unsigned long first_mfn = alloc_boot_pages(1, 1);
            pte = mfn_to_xen_entry(first_mfn, WRITEALLOC);
            pte.pt.table = 1;
            write_pte(p, pte);
            first = mfn_to_virt(first_mfn);
        }

        pte = mfn_to_xen_entry(mfn, WRITEALLOC);
        /* TODO: Set pte.pt.contig when appropriate. */
        write_pte(&first[first_table_offset(vaddr)], pte);

        mfn += FIRST_SIZE>>PAGE_SHIFT;
        vaddr += FIRST_SIZE;
    }

    flush_xen_data_tlb_local();
}
#endif

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long nr_pages = (pe - ps) >> PAGE_SHIFT;
    unsigned long nr_pdxs = pfn_to_pdx(nr_pages);
    unsigned long frametable_size = nr_pdxs * sizeof(struct page_info);
    unsigned long base_mfn;
#ifdef CONFIG_ARM_64
    lpae_t *second, pte;
    unsigned long nr_second, second_base;
    int i;
#endif

    frametable_base_pdx = pfn_to_pdx(ps >> PAGE_SHIFT);

    /* Round up to 32M boundary */
    frametable_size = (frametable_size + 0x1ffffff) & ~0x1ffffff;
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));

#ifdef CONFIG_ARM_64
    nr_second = frametable_size >> SECOND_SHIFT;
    second_base = alloc_boot_pages(nr_second, 1);
    second = mfn_to_virt(second_base);
    for ( i = 0; i < nr_second; i++ )
    {
        pte = mfn_to_xen_entry(second_base + i, WRITEALLOC);
        pte.pt.table = 1;
        write_pte(&xen_first[first_table_offset(FRAMETABLE_VIRT_START)+i], pte);
    }
    create_32mb_mappings(second, 0, base_mfn, frametable_size >> PAGE_SHIFT);
#else
    create_32mb_mappings(xen_second, FRAMETABLE_VIRT_START, base_mfn, frametable_size >> PAGE_SHIFT);
#endif

    memset(&frame_table[0], 0, nr_pdxs * sizeof(struct page_info));
    memset(&frame_table[nr_pdxs], -1,
           frametable_size - (nr_pdxs * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pdxs * sizeof(struct page_info));
}

void *__init arch_vmap_virt_end(void)
{
    return (void *)VMAP_VIRT_END;
}

/*
 * This function should only be used to remap device address ranges
 * TODO: add a check to verify this assumption
 */
void *ioremap_attr(paddr_t pa, size_t len, unsigned int attributes)
{
    mfn_t mfn = _mfn(PFN_DOWN(pa));
    unsigned int offs = pa & (PAGE_SIZE - 1);
    unsigned int nr = PFN_UP(offs + len);
    void *ptr = __vmap(&mfn, nr, 1, 1, attributes);

    if ( ptr == NULL )
        return NULL;

    return ptr + offs;
}

void *ioremap(paddr_t pa, size_t len)
{
    return ioremap_attr(pa, len, PAGE_HYPERVISOR_NOCACHE);
}

static int create_xen_table(lpae_t *entry)
{
    void *p;
    lpae_t pte;

    p = alloc_xenheap_page();
    if ( p == NULL )
        return -ENOMEM;
    clear_page(p);
    pte = mfn_to_xen_entry(virt_to_mfn(p), WRITEALLOC);
    pte.pt.table = 1;
    write_pte(entry, pte);
    return 0;
}

enum xenmap_operation {
    INSERT,
    REMOVE,
    RESERVE
};

static int create_xen_entries(enum xenmap_operation op,
                              unsigned long virt,
                              unsigned long mfn,
                              unsigned long nr_mfns,
                              unsigned int ai)
{
    int rc;
    unsigned long addr = virt, addr_end = addr + nr_mfns * PAGE_SIZE;
    lpae_t pte;
    lpae_t *third = NULL;

    for(; addr < addr_end; addr += PAGE_SIZE, mfn++)
    {
        if ( !xen_second[second_linear_offset(addr)].pt.valid ||
             !xen_second[second_linear_offset(addr)].pt.table )
        {
            rc = create_xen_table(&xen_second[second_linear_offset(addr)]);
            if ( rc < 0 ) {
                printk("create_xen_entries: L2 failed\n");
                goto out;
            }
        }

        BUG_ON(!xen_second[second_linear_offset(addr)].pt.valid);

        third = __va(pfn_to_paddr(xen_second[second_linear_offset(addr)].pt.base));

        switch ( op ) {
            case INSERT:
            case RESERVE:
                if ( third[third_table_offset(addr)].pt.valid )
                {
                    printk("create_xen_entries: trying to replace an existing mapping addr=%lx mfn=%lx\n",
                           addr, mfn);
                    return -EINVAL;
                }
                if ( op == RESERVE )
                    break;
                pte = mfn_to_xen_entry(mfn, ai);
                pte.pt.table = 1;
                write_pte(&third[third_table_offset(addr)], pte);
                break;
            case REMOVE:
                if ( !third[third_table_offset(addr)].pt.valid )
                {
                    printk("create_xen_entries: trying to remove a non-existing mapping addr=%lx\n",
                           addr);
                    return -EINVAL;
                }
                pte.bits = 0;
                write_pte(&third[third_table_offset(addr)], pte);
                break;
            default:
                BUG();
        }
    }
    flush_xen_data_tlb_range_va(virt, PAGE_SIZE * nr_mfns);

    rc = 0;

out:
    return rc;
}

int map_pages_to_xen(unsigned long virt,
                     unsigned long mfn,
                     unsigned long nr_mfns,
                     unsigned int flags)
{
    return create_xen_entries(INSERT, virt, mfn, nr_mfns, flags);
}

int populate_pt_range(unsigned long virt, unsigned long mfn,
                      unsigned long nr_mfns)
{
    return create_xen_entries(RESERVE, virt, mfn, nr_mfns, 0);
}

void destroy_xen_mappings(unsigned long v, unsigned long e)
{
    create_xen_entries(REMOVE, v, 0, (e - v) >> PAGE_SHIFT, 0);
}

enum mg { mg_clear, mg_ro, mg_rw, mg_rx };
static void set_pte_flags_on_range(const char *p, unsigned long l, enum mg mg)
{
    lpae_t pte;
    int i;

    ASSERT(is_kernel(p) && is_kernel(p + l));

    /* Can only guard in page granularity */
    ASSERT(!((unsigned long) p & ~PAGE_MASK));
    ASSERT(!(l & ~PAGE_MASK));

    for ( i = (p - _start) / PAGE_SIZE; 
          i < (p + l - _start) / PAGE_SIZE; 
          i++ )
    {
        pte = xen_xenmap[i];
        switch ( mg )
        {
        case mg_clear:
            pte.pt.valid = 0;
            break;
        case mg_ro:
            pte.pt.valid = 1;
            pte.pt.pxn = 1;
            pte.pt.xn = 1;
            pte.pt.ro = 1;
            break;
        case mg_rw:
            pte.pt.valid = 1;
            pte.pt.pxn = 1;
            pte.pt.xn = 1;
            pte.pt.ro = 0;
            break;
        case mg_rx:
            pte.pt.valid = 1;
            pte.pt.pxn = 0;
            pte.pt.xn = 0;
            pte.pt.ro = 1;
            break;
        }
        write_pte(xen_xenmap + i, pte);
    }
    flush_xen_text_tlb_local();
}

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void)
{
    paddr_t pa = virt_to_maddr(__init_begin);
    unsigned long len = __init_end - __init_begin;
    set_pte_flags_on_range(__init_begin, len, mg_rw);
    memset(__init_begin, 0xcc, len);
    set_pte_flags_on_range(__init_begin, len, mg_clear);
    init_domheap_pages(pa, pa + len);
    printk("Freed %ldkB init memory.\n", (long)(__init_end-__init_begin)>>10);
}

void arch_dump_shared_mem_info(void)
{
}

int donate_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    ASSERT(0);
    return -ENOSYS;
}

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    return -1;
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    ASSERT(0);
    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    return d->arch.p2m.max_mapped_gfn;
}

void share_xen_page_with_guest(struct page_info *page,
                          struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;

    page_set_owner(page, d);
    smp_wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT((page->count_info & ~PGC_xen_heap) == 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !d->is_dying )
    {
        page->count_info |= PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        page_list_add_tail(page, &d->xenpage_list);
    }

    spin_unlock(&d->page_alloc_lock);
}

void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

int xenmem_add_to_physmap_one(
    struct domain *d,
    unsigned int space,
    domid_t foreign_domid,
    unsigned long idx,
    xen_pfn_t gpfn)
{
    unsigned long mfn = 0;
    int rc;
    p2m_type_t t;
    struct page_info *page = NULL;

    switch ( space )
    {
    case XENMAPSPACE_grant_table:
        write_lock(&d->grant_table->lock);

        if ( d->grant_table->gt_version == 0 )
            d->grant_table->gt_version = 1;

        if ( d->grant_table->gt_version == 2 &&
                (idx & XENMAPIDX_grant_table_status) )
        {
            idx &= ~XENMAPIDX_grant_table_status;
            if ( idx < nr_status_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->status[idx]);
            else
                return -EINVAL;
        }
        else
        {
            if ( (idx >= nr_grant_frames(d->grant_table)) &&
                 (idx < max_grant_frames) )
                gnttab_grow_table(d, idx + 1);

            if ( idx < nr_grant_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->shared_raw[idx]);
            else
                return -EINVAL;
        }
        
        d->arch.grant_table_gpfn[idx] = gpfn;

        t = p2m_ram_rw;

        write_unlock(&d->grant_table->lock);
        break;
    case XENMAPSPACE_shared_info:
        if ( idx != 0 )
            return -EINVAL;

        mfn = virt_to_mfn(d->shared_info);
        t = p2m_ram_rw;

        break;
    case XENMAPSPACE_gmfn_foreign:
    {
        struct domain *od;
        p2m_type_t p2mt;
        od = rcu_lock_domain_by_any_id(foreign_domid);
        if ( od == NULL )
            return -ESRCH;

        if ( od == d )
        {
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        rc = xsm_map_gmfn_foreign(XSM_TARGET, d, od);
        if ( rc )
        {
            rcu_unlock_domain(od);
            return rc;
        }

        /* Take reference to the foreign domain page.
         * Reference will be released in XENMEM_remove_from_physmap */
        page = get_page_from_gfn(od, idx, &p2mt, P2M_ALLOC);
        if ( !page )
        {
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        if ( !p2m_is_ram(p2mt) )
        {
            put_page(page);
            rcu_unlock_domain(od);
            return -EINVAL;
        }

        mfn = page_to_mfn(page);
        t = p2m_map_foreign;

        rcu_unlock_domain(od);
        break;
    }

    default:
        return -ENOSYS;
    }

    /* Map at new location. */
    rc = guest_physmap_add_entry(d, gpfn, mfn, 0, t);

    /* If we fail to add the mapping, we need to drop the reference we
     * took earlier on foreign pages */
    if ( rc && space == XENMAPSPACE_gmfn_foreign )
    {
        ASSERT(page != NULL);
        put_page(page);
    }

    return rc;
}

long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( op )
    {
    /* XXX: memsharing not working yet */
    case XENMEM_get_sharing_shared_pages:
    case XENMEM_get_sharing_freed_pages:
        return 0;

    default:
        return -ENOSYS;
    }

    return 0;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{
    unsigned long x, y = page->count_info;
    struct domain *owner;

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         */
        if ( unlikely(((x + 1) & PGC_count_mask) <= 1) )
            return NULL;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + 1)) != x );

    owner = page_get_owner(page);
    ASSERT(owner);

    return owner;
}

void put_page(struct page_info *page)
{
    unsigned long nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) != 0);
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        free_domheap_page(page);
    }
}

int get_page(struct page_info *page, struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return 1;

    if ( owner != NULL )
        put_page(page);

    return 0;
}

/* Common code requires get_page_type and put_page_type.
 * We don't care about typecounts so we just do the minimum to make it
 * happy. */
int get_page_type(struct page_info *page, unsigned long type)
{
    return 1;
}

void put_page_type(struct page_info *page)
{
    return;
}

void gnttab_clear_flag(unsigned long nr, uint16_t *addr)
{
    /*
     * Note that this cannot be clear_bit(), as the access must be
     * confined to the specified 2 bytes.
     */
    uint16_t mask = ~(1 << nr), old;

    do {
        old = *addr;
    } while (cmpxchg(addr, old, old & mask) != old);
}

void gnttab_mark_dirty(struct domain *d, unsigned long l)
{
    /* XXX: mark dirty */
    static int warning;
    if (!warning) {
        gdprintk(XENLOG_WARNING, "gnttab_mark_dirty not implemented yet\n");
        warning = 1;
    }
}

int create_grant_host_mapping(unsigned long addr, unsigned long frame,
                              unsigned int flags, unsigned int cache_flags)
{
    int rc;
    p2m_type_t t = p2m_grant_map_rw;

    if ( cache_flags  || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    if ( flags & GNTMAP_readonly )
        t = p2m_grant_map_ro;

    rc = guest_physmap_add_entry(current->domain, addr >> PAGE_SHIFT,
                                 frame, 0, t);

    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int replace_grant_host_mapping(unsigned long addr, unsigned long mfn,
        unsigned long new_addr, unsigned int flags)
{
    unsigned long gfn = (unsigned long)(addr >> PAGE_SHIFT);
    struct domain *d = current->domain;

    if ( new_addr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    guest_physmap_remove_page(d, gfn, mfn, 0);

    return GNTST_okay;
}

int is_iomem_page(unsigned long mfn)
{
    if ( !mfn_valid(mfn) )
        return 1;
    return 0;
}

void clear_and_clean_page(struct page_info *page)
{
    void *p = __map_domain_page(page);

    clear_page(p);
    clean_dcache_va_range(p, PAGE_SIZE);
    unmap_domain_page(p);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
