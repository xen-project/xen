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
#include <xen/sizes.h>
#include <xen/libfdt/libfdt.h>

#include <asm/setup.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))
#undef mfn_to_virt
#define mfn_to_virt(mfn) __mfn_to_virt(mfn_x(mfn))

#ifdef NDEBUG
static inline void
__attribute__ ((__format__ (__printf__, 1, 2)))
mm_printk(const char *fmt, ...) {}
#else
#define mm_printk(fmt, args...)             \
    do                                      \
    {                                       \
        dprintk(XENLOG_ERR, fmt, ## args);  \
        WARN();                             \
    } while (0);
#endif

/*
 * Macros to define page-tables:
 *  - DEFINE_BOOT_PAGE_TABLE is used to define page-table that are used
 *  in assembly code before BSS is zeroed.
 *  - DEFINE_PAGE_TABLE{,S} are used to define one or multiple
 *  page-tables to be used after BSS is zeroed (typically they are only used
 *  in C).
 */
#define DEFINE_BOOT_PAGE_TABLE(name)                                          \
lpae_t __aligned(PAGE_SIZE) __section(".data.page_aligned") name[LPAE_ENTRIES]

#define DEFINE_PAGE_TABLES(name, nr)                    \
lpae_t __aligned(PAGE_SIZE) name[LPAE_ENTRIES * (nr)]

#define DEFINE_PAGE_TABLE(name) DEFINE_PAGE_TABLES(name, 1)

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
DEFINE_BOOT_PAGE_TABLE(boot_pgtable);
#ifdef CONFIG_ARM_64
DEFINE_BOOT_PAGE_TABLE(boot_first);
DEFINE_BOOT_PAGE_TABLE(boot_first_id);
#endif
DEFINE_BOOT_PAGE_TABLE(boot_second_id);
DEFINE_BOOT_PAGE_TABLE(boot_third_id);
DEFINE_BOOT_PAGE_TABLE(boot_second);
DEFINE_BOOT_PAGE_TABLE(boot_third);

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
static DEFINE_PAGE_TABLE(xen_pgtable);
static DEFINE_PAGE_TABLE(xen_first);
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
static DEFINE_PAGE_TABLE(cpu0_pgtable);
/* cpu0's domheap page tables */
static DEFINE_PAGE_TABLES(cpu0_dommap, DOMHEAP_SECOND_PAGES);
#endif

#ifdef CONFIG_ARM_64
/* The first page of the first level mapping of the xenheap. The
 * subsequent xenheap first level pages are dynamically allocated, but
 * we need this one to bootstrap ourselves. */
static DEFINE_PAGE_TABLE(xenheap_first_first);
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
static DEFINE_PAGE_TABLES(xen_second, 2);
/* First level page table used for fixmap */
DEFINE_BOOT_PAGE_TABLE(xen_fixmap);
/* First level page table used to map Xen itself with the XN bit set
 * as appropriate. */
static DEFINE_PAGE_TABLE(xen_xenmap);

/* Non-boot CPUs use this to find the correct pagetables. */
uint64_t init_ttbr;

static paddr_t phys_offset;

/* Limits of the Xen heap */
mfn_t xenheap_mfn_start __read_mostly = INVALID_MFN_INITIALIZER;
mfn_t xenheap_mfn_end __read_mostly;
vaddr_t xenheap_virt_end __read_mostly;
#ifdef CONFIG_ARM_64
vaddr_t xenheap_virt_start __read_mostly;
unsigned long xenheap_base_pdx __read_mostly;
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
    const mfn_t root_mfn = maddr_to_mfn(ttbr);
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

    mapping = map_domain_page(mfn_add(root_mfn, root_table));

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
        mapping = map_domain_page(lpae_get_mfn(pte));
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

/*
 * Standard entry type that we'll use to build Xen's own pagetables.
 * We put the same permissions at every level, because they're ignored
 * by the walker in non-leaf entries.
 */
static inline lpae_t mfn_to_xen_entry(mfn_t mfn, unsigned attr)
{
    lpae_t e = (lpae_t) {
        .pt = {
            .valid = 1,           /* Mappings are present */
            .table = 0,           /* Set to 1 for links and 4k maps */
            .ai = attr,
            .ns = 1,              /* Hyp mode is in the non-secure world */
            .up = 1,              /* See below */
            .ro = 0,              /* Assume read-write */
            .af = 1,              /* No need for access tracking */
            .ng = 1,              /* Makes TLB flushes easier */
            .contig = 0,          /* Assume non-contiguous */
            .xn = 1,              /* No need to execute outside .text */
            .avail = 0,           /* Reference count for domheap mapping */
        }};
    /*
     * For EL2 stage-1 page table, up (aka AP[1]) is RES1 as the translation
     * regime applies to only one exception level (see D4.4.4 and G4.6.1
     * in ARM DDI 0487B.a). If this changes, remember to update the
     * hard-coded values in head.S too.
     */

    switch ( attr )
    {
    case MT_NORMAL_NC:
        /*
         * ARM ARM: Overlaying the shareability attribute (DDI
         * 0406C.b B3-1376 to 1377)
         *
         * A memory region with a resultant memory type attribute of Normal,
         * and a resultant cacheability attribute of Inner Non-cacheable,
         * Outer Non-cacheable, must have a resultant shareability attribute
         * of Outer Shareable, otherwise shareability is UNPREDICTABLE.
         *
         * On ARMv8 sharability is ignored and explicitly treated as Outer
         * Shareable for Normal Inner Non_cacheable, Outer Non-cacheable.
         */
        e.pt.sh = LPAE_SH_OUTER;
        break;
    case MT_DEVICE_nGnRnE:
    case MT_DEVICE_nGnRE:
        /*
         * Shareability is ignored for non-Normal memory, Outer is as
         * good as anything.
         *
         * On ARMv8 sharability is ignored and explicitly treated as Outer
         * Shareable for any device memory type.
         */
        e.pt.sh = LPAE_SH_OUTER;
        break;
    default:
        e.pt.sh = LPAE_SH_INNER;  /* Xen mappings are SMP coherent */
        break;
    }

    ASSERT(!(mfn_to_maddr(mfn) & ~PADDR_MASK));

    lpae_set_mfn(e, mfn);

    return e;
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, mfn_t mfn, unsigned int flags)
{
    int res;

    res = map_pages_to_xen(FIXMAP_ADDR(map), mfn, 1, flags);
    BUG_ON(res != 0);
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{
    int res;

    res = destroy_xen_mappings(FIXMAP_ADDR(map), FIXMAP_ADDR(map) + PAGE_SIZE);
    BUG_ON(res != 0);
}

/* Create Xen's mappings of memory.
 * Mapping_size must be either 2MB or 32MB.
 * Base and virt must be mapping_size aligned.
 * Size must be a multiple of mapping_size.
 * second must be a contiguous set of second level page tables
 * covering the region starting at virt_offset. */
static void __init create_mappings(lpae_t *second,
                                   unsigned long virt_offset,
                                   unsigned long base_mfn,
                                   unsigned long nr_mfns,
                                   unsigned int mapping_size)
{
    unsigned long i, count;
    const unsigned long granularity = mapping_size >> PAGE_SHIFT;
    lpae_t pte, *p;

    ASSERT((mapping_size == MB(2)) || (mapping_size == MB(32)));
    ASSERT(!((virt_offset >> PAGE_SHIFT) % granularity));
    ASSERT(!(base_mfn % granularity));
    ASSERT(!(nr_mfns % granularity));

    count = nr_mfns / LPAE_ENTRIES;
    p = second + second_linear_offset(virt_offset);
    pte = mfn_to_xen_entry(_mfn(base_mfn), MT_NORMAL);
    if ( granularity == 16 * LPAE_ENTRIES )
        pte.pt.contig = 1;  /* These maps are in 16-entry contiguous chunks. */
    for ( i = 0; i < count; i++ )
    {
        write_pte(p + i, pte);
        pte.pt.base += 1 << LPAE_SHIFT;
    }
    flush_xen_tlb_local();
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
            pte = mfn_to_xen_entry(_mfn(slot_mfn), MT_NORMAL);
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
    flush_xen_tlb_range_va_local(va, PAGE_SIZE);

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

mfn_t domain_page_map_to_mfn(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    lpae_t *map = this_cpu(xen_dommap);
    int slot = (va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;
    unsigned long offset = (va>>THIRD_SHIFT) & LPAE_ENTRY_MASK;

    if ( va >= VMAP_VIRT_START && va < VMAP_VIRT_END )
        return virt_to_mfn(va);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    return mfn_add(lpae_get_mfn(map[slot]), offset);
}
#endif

void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    void *v = map_domain_page(_mfn(mfn));

    clean_and_invalidate_dcache_va_range(v, PAGE_SIZE);
    unmap_domain_page(v);

    /*
     * For some of the instruction cache (such as VIPT), the entire I-Cache
     * needs to be flushed to guarantee that all the aliases of a given
     * physical address will be removed from the cache.
     * Invalidating the I-Cache by VA highly depends on the behavior of the
     * I-Cache (See D4.9.2 in ARM DDI 0487A.k_iss10775). Instead of using flush
     * by VA on select platforms, we just flush the entire cache here.
     */
    if ( sync_icache )
        invalidate_icache();
}

static inline lpae_t pte_of_xenaddr(vaddr_t va)
{
    paddr_t ma = va + phys_offset;

    return mfn_to_xen_entry(maddr_to_mfn(ma), MT_NORMAL);
}

void * __init early_fdt_map(paddr_t fdt_paddr)
{
    /* We are using 2MB superpage for mapping the FDT */
    paddr_t base_paddr = fdt_paddr & SECOND_MASK;
    paddr_t offset;
    void *fdt_virt;
    uint32_t size;

    /*
     * Check whether the physical FDT address is set and meets the minimum
     * alignment requirement. Since we are relying on MIN_FDT_ALIGN to be at
     * least 8 bytes so that we always access the magic and size fields
     * of the FDT header after mapping the first chunk, double check if
     * that is indeed the case.
     */
    BUILD_BUG_ON(MIN_FDT_ALIGN < 8);
    if ( !fdt_paddr || fdt_paddr % MIN_FDT_ALIGN )
        return NULL;

    /* The FDT is mapped using 2MB superpage */
    BUILD_BUG_ON(BOOT_FDT_VIRT_START % SZ_2M);

    create_mappings(xen_second, BOOT_FDT_VIRT_START, paddr_to_pfn(base_paddr),
                    SZ_2M >> PAGE_SHIFT, SZ_2M);

    offset = fdt_paddr % SECOND_SIZE;
    fdt_virt = (void *)BOOT_FDT_VIRT_START + offset;

    if ( fdt_magic(fdt_virt) != FDT_MAGIC )
        return NULL;

    size = fdt_totalsize(fdt_virt);
    if ( size > MAX_FDT_SIZE )
        return NULL;

    if ( (offset + size) > SZ_2M )
    {
        create_mappings(xen_second, BOOT_FDT_VIRT_START + SZ_2M,
                        paddr_to_pfn(base_paddr + SZ_2M),
                        SZ_2M >> PAGE_SHIFT, SZ_2M);
    }

    return fdt_virt;
}

void __init remove_early_mappings(void)
{
    lpae_t pte = {0};
    write_pte(xen_second + second_table_offset(BOOT_FDT_VIRT_START), pte);
    write_pte(xen_second + second_table_offset(BOOT_FDT_VIRT_START + SZ_2M),
              pte);
    flush_xen_tlb_range_va(BOOT_FDT_VIRT_START, BOOT_FDT_SLOT_SIZE);
}

/*
 * After boot, Xen page-tables should not contain mapping that are both
 * Writable and eXecutables.
 *
 * This should be called on each CPU to enforce the policy.
 */
static void xen_pt_enforce_wnx(void)
{
    WRITE_SYSREG32(READ_SYSREG32(SCTLR_EL2) | SCTLR_Axx_ELx_WXN, SCTLR_EL2);
    /*
     * The TLBs may cache SCTLR_EL2.WXN. So ensure it is synchronized
     * before flushing the TLBs.
     */
    isb();
    flush_xen_tlb_local();
}

extern void switch_ttbr(uint64_t ttbr);

/* Clear a translation table and clean & invalidate the cache */
static void clear_table(void *table)
{
    clear_page(table);
    clean_and_invalidate_dcache_va_range(table, PAGE_SIZE);
}

/* Boot-time pagetable setup.
 * Changes here may need matching changes in head.S */
void __init setup_pagetables(unsigned long boot_phys_offset)
{
    uint64_t ttbr;
    lpae_t pte, *p;
    int i;

    phys_offset = boot_phys_offset;

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

    /* Break up the Xen mapping into 4k pages and protect them separately. */
    for ( i = 0; i < LPAE_ENTRIES; i++ )
    {
        vaddr_t va = XEN_VIRT_START + (i << PAGE_SHIFT);

        if ( !is_kernel(va) )
            break;
        pte = pte_of_xenaddr(va);
        pte.pt.table = 1; /* 4k mappings always have this bit set */
        if ( is_kernel_text(va) || is_kernel_inittext(va) )
        {
            pte.pt.xn = 0;
            pte.pt.ro = 1;
        }
        if ( is_kernel_rodata(va) )
            pte.pt.ro = 1;
        xen_xenmap[i] = pte;
    }

    /* Initialise xen second level entries ... */
    /* ... Xen's text etc */

    pte = pte_of_xenaddr((vaddr_t)xen_xenmap);
    pte.pt.table = 1;
    xen_second[second_table_offset(XEN_VIRT_START)] = pte;

    /* ... Fixmap */
    pte = pte_of_xenaddr((vaddr_t)xen_fixmap);
    pte.pt.table = 1;
    xen_second[second_table_offset(FIXMAP_ADDR(0))] = pte;

#ifdef CONFIG_ARM_64
    ttbr = (uintptr_t) xen_pgtable + phys_offset;
#else
    ttbr = (uintptr_t) cpu0_pgtable + phys_offset;
#endif

    switch_ttbr(ttbr);

    /* Clear the copy of the boot pagetables. Each secondary CPU
     * rebuilds these itself (see head.S) */
    clear_table(boot_pgtable);
#ifdef CONFIG_ARM_64
    clear_table(boot_first);
    clear_table(boot_first_id);
#endif
    clear_table(boot_second);
    clear_table(boot_third);

    xen_pt_enforce_wnx();

#ifdef CONFIG_ARM_32
    per_cpu(xen_pgtable, 0) = cpu0_pgtable;
    per_cpu(xen_dommap, 0) = cpu0_dommap;
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
        pte = mfn_to_xen_entry(virt_to_mfn(domheap+i*LPAE_ENTRIES),
                               MT_NORMAL);
        pte.pt.table = 1;
        write_pte(&first[first_table_offset(DOMHEAP_VIRT_START+i*FIRST_SIZE)], pte);
    }

    per_cpu(xen_pgtable, cpu) = first;
    per_cpu(xen_dommap, cpu) = domheap;

    /* Set init_ttbr for this CPU coming up */
    init_ttbr = __pa(first);
    clean_dcache(init_ttbr);

    return 0;
}
#endif

/* MMU setup for secondary CPUS (which already have paging enabled) */
void mmu_init_secondary_cpu(void)
{
    xen_pt_enforce_wnx();
}

#ifdef CONFIG_ARM_32
/* Set up the xenheap: up to 1GB of contiguous, always-mapped memory. */
void __init setup_xenheap_mappings(unsigned long base_mfn,
                                   unsigned long nr_mfns)
{
    create_mappings(xen_second, XENHEAP_VIRT_START, base_mfn, nr_mfns, MB(32));

    /* Record where the xenheap is, for translation routines. */
    xenheap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
    xenheap_mfn_start = _mfn(base_mfn);
    xenheap_mfn_end = _mfn(base_mfn + nr_mfns);
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
    if ( mfn_eq(xenheap_mfn_start, INVALID_MFN) )
    {
        xenheap_mfn_start = _mfn(base_mfn);
        xenheap_base_pdx = mfn_to_pdx(_mfn(base_mfn));
        xenheap_virt_start = DIRECTMAP_VIRT_START +
            (base_mfn - mfn) * PAGE_SIZE;
    }

    if ( base_mfn < mfn_x(xenheap_mfn_start) )
        panic("cannot add xenheap mapping at %lx below heap start %lx\n",
              base_mfn, mfn_x(xenheap_mfn_start));

    end_mfn = base_mfn + nr_mfns;

    /*
     * Virtual address aligned to previous 1GB to match physical
     * address alignment done above.
     */
    vaddr = (vaddr_t)__mfn_to_virt(base_mfn) & FIRST_MASK;

    while ( mfn < end_mfn )
    {
        int slot = zeroeth_table_offset(vaddr);
        lpae_t *p = &xen_pgtable[slot];

        if ( p->pt.valid )
        {
            /* mfn_to_virt is not valid on the 1st 1st mfn, since it
             * is not within the xenheap. */
            first = slot == xenheap_first_first_slot ?
                xenheap_first_first : mfn_to_virt(lpae_get_mfn(*p));
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
            mfn_t first_mfn = alloc_boot_pages(1, 1);

            clear_page(mfn_to_virt(first_mfn));
            pte = mfn_to_xen_entry(first_mfn, MT_NORMAL);
            pte.pt.table = 1;
            write_pte(p, pte);
            first = mfn_to_virt(first_mfn);
        }

        pte = mfn_to_xen_entry(_mfn(mfn), MT_NORMAL);
        /* TODO: Set pte.pt.contig when appropriate. */
        write_pte(&first[first_table_offset(vaddr)], pte);

        mfn += FIRST_SIZE>>PAGE_SHIFT;
        vaddr += FIRST_SIZE;
    }

    flush_xen_tlb_local();
}
#endif

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long nr_pdxs = mfn_to_pdx(mfn_add(maddr_to_mfn(pe), -1)) -
                            mfn_to_pdx(maddr_to_mfn(ps)) + 1;
    unsigned long frametable_size = nr_pdxs * sizeof(struct page_info);
    mfn_t base_mfn;
    const unsigned long mapping_size = frametable_size < MB(32) ? MB(2) : MB(32);
#ifdef CONFIG_ARM_64
    lpae_t *second, pte;
    unsigned long nr_second;
    mfn_t second_base;
    int i;
#endif

    frametable_base_pdx = mfn_to_pdx(maddr_to_mfn(ps));
    /* Round up to 2M or 32M boundary, as appropriate. */
    frametable_size = ROUNDUP(frametable_size, mapping_size);
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));

#ifdef CONFIG_ARM_64
    /* Compute the number of second level pages. */
    nr_second = ROUNDUP(frametable_size, FIRST_SIZE) >> FIRST_SHIFT;
    second_base = alloc_boot_pages(nr_second, 1);
    second = mfn_to_virt(second_base);
    for ( i = 0; i < nr_second; i++ )
    {
        clear_page(mfn_to_virt(mfn_add(second_base, i)));
        pte = mfn_to_xen_entry(mfn_add(second_base, i), MT_NORMAL);
        pte.pt.table = 1;
        write_pte(&xen_first[first_table_offset(FRAMETABLE_VIRT_START)+i], pte);
    }
    create_mappings(second, 0, mfn_x(base_mfn), frametable_size >> PAGE_SHIFT,
                    mapping_size);
#else
    create_mappings(xen_second, FRAMETABLE_VIRT_START, mfn_x(base_mfn),
                    frametable_size >> PAGE_SHIFT, mapping_size);
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
    void *ptr = __vmap(&mfn, nr, 1, 1, attributes, VMAP_DEFAULT);

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
    pte = mfn_to_xen_entry(virt_to_mfn(p), MT_NORMAL);
    pte.pt.table = 1;
    write_pte(entry, pte);
    return 0;
}

static lpae_t *xen_map_table(mfn_t mfn)
{
    return map_domain_page(mfn);
}

static void xen_unmap_table(const lpae_t *table)
{
    unmap_domain_page(table);
}

#define XEN_TABLE_MAP_FAILED 0
#define XEN_TABLE_SUPER_PAGE 1
#define XEN_TABLE_NORMAL_PAGE 2

/*
 * Take the currently mapped table, find the corresponding entry,
 * and map the next table, if available.
 *
 * The read_only parameters indicates whether intermediate tables should
 * be allocated when not present.
 *
 * Return values:
 *  XEN_TABLE_MAP_FAILED: Either read_only was set and the entry
 *  was empty, or allocating a new page failed.
 *  XEN_TABLE_NORMAL_PAGE: next level mapped normally
 *  XEN_TABLE_SUPER_PAGE: The next entry points to a superpage.
 */
static int xen_pt_next_level(bool read_only, unsigned int level,
                             lpae_t **table, unsigned int offset)
{
    lpae_t *entry;
    int ret;

    entry = *table + offset;

    if ( !lpae_is_valid(*entry) )
    {
        if ( read_only )
            return XEN_TABLE_MAP_FAILED;

        ret = create_xen_table(entry);
        if ( ret )
            return XEN_TABLE_MAP_FAILED;
    }

    /* The function xen_pt_next_level is never called at the 3rd level */
    if ( lpae_is_mapping(*entry, level) )
        return XEN_TABLE_SUPER_PAGE;

    xen_unmap_table(*table);
    *table = xen_map_table(lpae_get_mfn(*entry));

    return XEN_TABLE_NORMAL_PAGE;
}

/* Sanity check of the entry */
static bool xen_pt_check_entry(lpae_t entry, mfn_t mfn, unsigned int flags)
{
    /* Sanity check when modifying a page. */
    if ( (flags & _PAGE_PRESENT) && mfn_eq(mfn, INVALID_MFN) )
    {
        /* We don't allow modifying an invalid entry. */
        if ( !lpae_is_valid(entry) )
        {
            mm_printk("Modifying invalid entry is not allowed.\n");
            return false;
        }

        /* We don't allow changing memory attributes. */
        if ( entry.pt.ai != PAGE_AI_MASK(flags) )
        {
            mm_printk("Modifying memory attributes is not allowed (0x%x -> 0x%x).\n",
                      entry.pt.ai, PAGE_AI_MASK(flags));
            return false;
        }

        /* We don't allow modifying entry with contiguous bit set. */
        if ( entry.pt.contig )
        {
            mm_printk("Modifying entry with contiguous bit set is not allowed.\n");
            return false;
        }
    }
    /* Sanity check when inserting a page */
    else if ( flags & _PAGE_PRESENT )
    {
        /* We should be here with a valid MFN. */
        ASSERT(!mfn_eq(mfn, INVALID_MFN));

        /* We don't allow replacing any valid entry. */
        if ( lpae_is_valid(entry) )
        {
            mm_printk("Changing MFN for a valid entry is not allowed (%#"PRI_mfn" -> %#"PRI_mfn").\n",
                      mfn_x(lpae_get_mfn(entry)), mfn_x(mfn));
            return false;
        }
    }
    /* Sanity check when removing a page. */
    else if ( (flags & (_PAGE_PRESENT|_PAGE_POPULATE)) == 0 )
    {
        /* We should be here with an invalid MFN. */
        ASSERT(mfn_eq(mfn, INVALID_MFN));

        /* We don't allow removing page with contiguous bit set. */
        if ( entry.pt.contig )
        {
            mm_printk("Removing entry with contiguous bit set is not allowed.\n");
            return false;
        }
    }
    /* Sanity check when populating the page-table. No check so far. */
    else
    {
        ASSERT(flags & _PAGE_POPULATE);
        /* We should be here with an invalid MFN */
        ASSERT(mfn_eq(mfn, INVALID_MFN));
    }

    return true;
}

static int xen_pt_update_entry(mfn_t root, unsigned long virt,
                               mfn_t mfn, unsigned int flags)
{
    int rc;
    unsigned int level;
    /* We only support 4KB mapping (i.e level 3) for now */
    unsigned int target = 3;
    lpae_t *table;
    /*
     * The intermediate page tables are read-only when the MFN is not valid
     * and we are not populating page table.
     * This means we either modify permissions or remove an entry.
     */
    bool read_only = mfn_eq(mfn, INVALID_MFN) && !(flags & _PAGE_POPULATE);
    lpae_t pte, *entry;

    /* convenience aliases */
    DECLARE_OFFSETS(offsets, (paddr_t)virt);

    /* _PAGE_POPULATE and _PAGE_PRESENT should never be set together. */
    ASSERT((flags & (_PAGE_POPULATE|_PAGE_PRESENT)) != (_PAGE_POPULATE|_PAGE_PRESENT));

    table = xen_map_table(root);
    for ( level = HYP_PT_ROOT_LEVEL; level < target; level++ )
    {
        rc = xen_pt_next_level(read_only, level, &table, offsets[level]);
        if ( rc == XEN_TABLE_MAP_FAILED )
        {
            /*
             * We are here because xen_pt_next_level has failed to map
             * the intermediate page table (e.g the table does not exist
             * and the pt is read-only). It is a valid case when
             * removing a mapping as it may not exist in the page table.
             * In this case, just ignore it.
             */
            if ( flags & (_PAGE_PRESENT|_PAGE_POPULATE) )
            {
                mm_printk("%s: Unable to map level %u\n", __func__, level);
                rc = -ENOENT;
                goto out;
            }
            else
            {
                rc = 0;
                goto out;
            }
        }
        else if ( rc != XEN_TABLE_NORMAL_PAGE )
            break;
    }

    if ( level != target )
    {
        mm_printk("%s: Shattering superpage is not supported\n", __func__);
        rc = -EOPNOTSUPP;
        goto out;
    }

    entry = table + offsets[level];

    rc = -EINVAL;
    if ( !xen_pt_check_entry(*entry, mfn, flags) )
        goto out;

    /* If we are only populating page-table, then we are done. */
    rc = 0;
    if ( flags & _PAGE_POPULATE )
        goto out;

    /* We are removing the page */
    if ( !(flags & _PAGE_PRESENT) )
        memset(&pte, 0x00, sizeof(pte));
    else
    {
        /* We are inserting a mapping => Create new pte. */
        if ( !mfn_eq(mfn, INVALID_MFN) )
        {
            pte = mfn_to_xen_entry(mfn, PAGE_AI_MASK(flags));

            /* Third level entries set pte.pt.table = 1 */
            pte.pt.table = 1;
        }
        else /* We are updating the permission => Copy the current pte. */
            pte = *entry;

        /* Set permission */
        pte.pt.ro = PAGE_RO_MASK(flags);
        pte.pt.xn = PAGE_XN_MASK(flags);
    }

    write_pte(entry, pte);

    rc = 0;

out:
    xen_unmap_table(table);

    return rc;
}

static DEFINE_SPINLOCK(xen_pt_lock);

static int xen_pt_update(unsigned long virt,
                         mfn_t mfn,
                         unsigned long nr_mfns,
                         unsigned int flags)
{
    int rc = 0;
    unsigned long addr = virt, addr_end = addr + nr_mfns * PAGE_SIZE;

    /*
     * For arm32, page-tables are different on each CPUs. Yet, they share
     * some common mappings. It is assumed that only common mappings
     * will be modified with this function.
     *
     * XXX: Add a check.
     */
    const mfn_t root = virt_to_mfn(THIS_CPU_PGTABLE);

    /*
     * The hardware was configured to forbid mapping both writeable and
     * executable.
     * When modifying/creating mapping (i.e _PAGE_PRESENT is set),
     * prevent any update if this happen.
     */
    if ( (flags & _PAGE_PRESENT) && !PAGE_RO_MASK(flags) &&
         !PAGE_XN_MASK(flags) )
    {
        mm_printk("Mappings should not be both Writeable and Executable.\n");
        return -EINVAL;
    }

    if ( !IS_ALIGNED(virt, PAGE_SIZE) )
    {
        mm_printk("The virtual address is not aligned to the page-size.\n");
        return -EINVAL;
    }

    spin_lock(&xen_pt_lock);

    for ( ; addr < addr_end; addr += PAGE_SIZE )
    {
        rc = xen_pt_update_entry(root, addr, mfn, flags);
        if ( rc )
            break;

        if ( !mfn_eq(mfn, INVALID_MFN) )
            mfn = mfn_add(mfn, 1);
    }

    /*
     * Flush the TLBs even in case of failure because we may have
     * partially modified the PT. This will prevent any unexpected
     * behavior afterwards.
     */
    flush_xen_tlb_range_va(virt, PAGE_SIZE * nr_mfns);

    spin_unlock(&xen_pt_lock);

    return rc;
}

int map_pages_to_xen(unsigned long virt,
                     mfn_t mfn,
                     unsigned long nr_mfns,
                     unsigned int flags)
{
    return xen_pt_update(virt, mfn, nr_mfns, flags);
}

int populate_pt_range(unsigned long virt, unsigned long nr_mfns)
{
    return xen_pt_update(virt, INVALID_MFN, nr_mfns, _PAGE_POPULATE);
}

int destroy_xen_mappings(unsigned long v, unsigned long e)
{
    ASSERT(v <= e);
    return xen_pt_update(v, INVALID_MFN, (e - v) >> PAGE_SHIFT, 0);
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int flags)
{
    ASSERT(s <= e);
    return xen_pt_update(s, INVALID_MFN, (e - s) >> PAGE_SHIFT, flags);
}

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void)
{
    paddr_t pa = virt_to_maddr(__init_begin);
    unsigned long len = __init_end - __init_begin;
    uint32_t insn;
    unsigned int i, nr = len / sizeof(insn);
    uint32_t *p;
    int rc;

    rc = modify_xen_mappings((unsigned long)__init_begin,
                             (unsigned long)__init_end, PAGE_HYPERVISOR_RW);
    if ( rc )
        panic("Unable to map RW the init section (rc = %d)\n", rc);

    /*
     * From now on, init will not be used for execution anymore,
     * so nuke the instruction cache to remove entries related to init.
     */
    invalidate_icache_local();

#ifdef CONFIG_ARM_32
    /* udf instruction i.e (see A8.8.247 in ARM DDI 0406C.c) */
    insn = 0xe7f000f0;
#else
    insn = AARCH64_BREAK_FAULT;
#endif
    p = (uint32_t *)__init_begin;
    for ( i = 0; i < nr; i++ )
        *(p + i) = insn;

    rc = destroy_xen_mappings((unsigned long)__init_begin,
                              (unsigned long)__init_end);
    if ( rc )
        panic("Unable to remove the init section (rc = %d)\n", rc);

    init_domheap_pages(pa, pa + len);
    printk("Freed %ldkB init memory.\n", (long)(__init_end-__init_begin)>>10);
}

void arch_dump_shared_mem_info(void)
{
}

int donate_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    ASSERT_UNREACHABLE();
    return -ENOSYS;
}

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    return -EOPNOTSUPP;
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    ASSERT_UNREACHABLE();
    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    return gfn_x(d->arch.p2m.max_mapped_gfn);
}

void share_xen_page_with_guest(struct page_info *page, struct domain *d,
                               enum XENSHARE_flags flags)
{
    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info =
        (flags == SHARE_ro ? PGT_none : PGT_writable_page) | 1;

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

int xenmem_add_to_physmap_one(
    struct domain *d,
    unsigned int space,
    union xen_add_to_physmap_batch_extra extra,
    unsigned long idx,
    gfn_t gfn)
{
    mfn_t mfn = INVALID_MFN;
    int rc;
    p2m_type_t t;
    struct page_info *page = NULL;

    switch ( space )
    {
    case XENMAPSPACE_grant_table:
        rc = gnttab_map_frame(d, idx, gfn, &mfn);
        if ( rc )
            return rc;

        t = p2m_ram_rw;

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

        od = get_pg_owner(extra.foreign_domid);
        if ( od == NULL )
            return -ESRCH;

        if ( od == d )
        {
            put_pg_owner(od);
            return -EINVAL;
        }

        rc = xsm_map_gmfn_foreign(XSM_TARGET, d, od);
        if ( rc )
        {
            put_pg_owner(od);
            return rc;
        }

        /* Take reference to the foreign domain page.
         * Reference will be released in XENMEM_remove_from_physmap */
        page = get_page_from_gfn(od, idx, &p2mt, P2M_ALLOC);
        if ( !page )
        {
            put_pg_owner(od);
            return -EINVAL;
        }

        if ( p2m_is_ram(p2mt) )
            t = (p2mt == p2m_ram_rw) ? p2m_map_foreign_rw : p2m_map_foreign_ro;
        else
        {
            put_page(page);
            put_pg_owner(od);
            return -EINVAL;
        }

        mfn = page_to_mfn(page);

        put_pg_owner(od);
        break;
    }
    case XENMAPSPACE_dev_mmio:
        /* extra should be 0. Reserved for future use. */
        if ( extra.res0 )
            return -EOPNOTSUPP;

        rc = map_dev_mmio_region(d, gfn, 1, _mfn(idx));
        return rc;

    default:
        return -ENOSYS;
    }

    /* Map at new location. */
    rc = guest_physmap_add_entry(d, gfn, mfn, 0, t);

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

int create_grant_host_mapping(unsigned long addr, mfn_t frame,
                              unsigned int flags, unsigned int cache_flags)
{
    int rc;
    p2m_type_t t = p2m_grant_map_rw;

    if ( cache_flags  || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    if ( flags & GNTMAP_readonly )
        t = p2m_grant_map_ro;

    rc = guest_physmap_add_entry(current->domain, gaddr_to_gfn(addr),
                                 frame, 0, t);

    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int replace_grant_host_mapping(unsigned long addr, mfn_t mfn,
                               unsigned long new_addr, unsigned int flags)
{
    gfn_t gfn = gaddr_to_gfn(addr);
    struct domain *d = current->domain;
    int rc;

    if ( new_addr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    rc = guest_physmap_remove_page(d, gfn, mfn, 0);

    return rc ? GNTST_general_error : GNTST_okay;
}

bool is_iomem_page(mfn_t mfn)
{
    return !mfn_valid(mfn);
}

void clear_and_clean_page(struct page_info *page)
{
    void *p = __map_domain_page(page);

    clear_page(p);
    clean_dcache_va_range(p, PAGE_SIZE);
    unmap_domain_page(p);
}

unsigned long get_upper_mfn_bound(void)
{
    /* No memory hotplug yet, so current memory limit is the final one. */
    return max_page - 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
