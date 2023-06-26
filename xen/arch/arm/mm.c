/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/mm.c
 *
 * MMU code for an ARMv7-A with virt extensions.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 */

#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/grant_table.h>
#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/pmap.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/types.h>
#include <xen/vmap.h>

#include <xsm/xsm.h>

#include <asm/fixmap.h>
#include <asm/setup.h>

#include <public/memory.h>

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
    } while (0)
#endif

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
 * For arm32 xen_pgtable are per-PCPU and are allocated before
 * bringing up each CPU. For arm64 xen_pgtable is common to all PCPUs.
 *
 * xen_second, xen_fixmap and xen_xenmap are always shared between all
 * PCPUs.
 */

#ifdef CONFIG_ARM_64
#define HYP_PT_ROOT_LEVEL 0
DEFINE_PAGE_TABLE(xen_pgtable);
static DEFINE_PAGE_TABLE(xen_first);
#define THIS_CPU_PGTABLE xen_pgtable
#else
#define HYP_PT_ROOT_LEVEL 1
/* Per-CPU pagetable pages */
/* xen_pgtable == root of the trie (zeroeth level on 64-bit, first on 32-bit) */
DEFINE_PER_CPU(lpae_t *, xen_pgtable);
#define THIS_CPU_PGTABLE this_cpu(xen_pgtable)
/* Root of the trie for cpu0, other CPU's PTs are dynamically allocated */
static DEFINE_PAGE_TABLE(cpu0_pgtable);
#endif

/* Common pagetable leaves */
/* Second level page table used to cover Xen virtual address space */
static DEFINE_PAGE_TABLE(xen_second);
/* Third level page table used for fixmap */
DEFINE_BOOT_PAGE_TABLE(xen_fixmap);
/*
 * Third level page table used to map Xen itself with the XN bit set
 * as appropriate.
 */
static DEFINE_PAGE_TABLE(xen_xenmap);

/* Non-boot CPUs use this to find the correct pagetables. */
uint64_t init_ttbr;

static paddr_t phys_offset;

/* Limits of the Xen heap */
mfn_t directmap_mfn_start __read_mostly = INVALID_MFN_INITIALIZER;
mfn_t directmap_mfn_end __read_mostly;
vaddr_t directmap_virt_end __read_mostly;
#ifdef CONFIG_ARM_64
vaddr_t directmap_virt_start __read_mostly;
unsigned long directmap_base_pdx __read_mostly;
#endif

unsigned long frametable_base_pdx __read_mostly;
unsigned long frametable_virt_end __read_mostly;

unsigned long max_page;
unsigned long total_pages;

extern char __init_begin[], __init_end[];

/* Checking VA memory layout alignment. */
static void __init __maybe_unused build_assertions(void)
{
    /* 2MB aligned regions */
    BUILD_BUG_ON(XEN_VIRT_START & ~SECOND_MASK);
    BUILD_BUG_ON(FIXMAP_ADDR(0) & ~SECOND_MASK);
    /* 1GB aligned regions */
#ifdef CONFIG_ARM_32
    BUILD_BUG_ON(XENHEAP_VIRT_START & ~FIRST_MASK);
#else
    BUILD_BUG_ON(DIRECTMAP_VIRT_START & ~FIRST_MASK);
#endif
    /* Page table structure constraints */
#ifdef CONFIG_ARM_64
    /*
     * The first few slots of the L0 table is reserved for the identity
     * mapping. Check that none of the other regions are overlapping
     * with it.
     */
#define CHECK_OVERLAP_WITH_IDMAP(virt) \
    BUILD_BUG_ON(zeroeth_table_offset(virt) < IDENTITY_MAPPING_AREA_NR_L0)

    CHECK_OVERLAP_WITH_IDMAP(XEN_VIRT_START);
    CHECK_OVERLAP_WITH_IDMAP(VMAP_VIRT_START);
    CHECK_OVERLAP_WITH_IDMAP(FRAMETABLE_VIRT_START);
    CHECK_OVERLAP_WITH_IDMAP(DIRECTMAP_VIRT_START);
#undef CHECK_OVERLAP_WITH_IDMAP
#endif
    BUILD_BUG_ON(first_table_offset(XEN_VIRT_START));
#ifdef CONFIG_ARCH_MAP_DOMAIN_PAGE
    BUILD_BUG_ON(DOMHEAP_VIRT_START & ~FIRST_MASK);
#endif
    /*
     * The boot code expects the regions XEN_VIRT_START, FIXMAP_ADDR(0),
     * BOOT_FDT_VIRT_START to use the same 0th (arm64 only) and 1st
     * slot in the page tables.
     */
#define CHECK_SAME_SLOT(level, virt1, virt2) \
    BUILD_BUG_ON(level##_table_offset(virt1) != level##_table_offset(virt2))

#define CHECK_DIFFERENT_SLOT(level, virt1, virt2) \
    BUILD_BUG_ON(level##_table_offset(virt1) == level##_table_offset(virt2))

#ifdef CONFIG_ARM_64
    CHECK_SAME_SLOT(zeroeth, XEN_VIRT_START, FIXMAP_ADDR(0));
    CHECK_SAME_SLOT(zeroeth, XEN_VIRT_START, BOOT_FDT_VIRT_START);
#endif
    CHECK_SAME_SLOT(first, XEN_VIRT_START, FIXMAP_ADDR(0));
    CHECK_SAME_SLOT(first, XEN_VIRT_START, BOOT_FDT_VIRT_START);

    /*
     * For arm32, the temporary mapping will re-use the domheap
     * first slot and the second slots will match.
     */
#ifdef CONFIG_ARM_32
    CHECK_SAME_SLOT(first, TEMPORARY_XEN_VIRT_START, DOMHEAP_VIRT_START);
    CHECK_DIFFERENT_SLOT(first, XEN_VIRT_START, TEMPORARY_XEN_VIRT_START);
    CHECK_SAME_SLOT(second, XEN_VIRT_START, TEMPORARY_XEN_VIRT_START);
#endif

#undef CHECK_SAME_SLOT
#undef CHECK_DIFFERENT_SLOT
}

static lpae_t *xen_map_table(mfn_t mfn)
{
    /*
     * During early boot, map_domain_page() may be unusable. Use the
     * PMAP to map temporarily a page-table.
     */
    if ( system_state == SYS_STATE_early_boot )
        return pmap_map(mfn);

    return map_domain_page(mfn);
}

static void xen_unmap_table(const lpae_t *table)
{
    /*
     * During early boot, xen_map_table() will not use map_domain_page()
     * but the PMAP.
     */
    if ( system_state == SYS_STATE_early_boot )
        pmap_unmap(table);
    else
        unmap_domain_page(table);
}

void dump_pt_walk(paddr_t ttbr, paddr_t addr,
                  unsigned int root_level,
                  unsigned int nr_root_tables)
{
    static const char *level_strs[4] = { "0TH", "1ST", "2ND", "3RD" };
    const mfn_t root_mfn = maddr_to_mfn(ttbr);
    DECLARE_OFFSETS(offsets, addr);
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

    mapping = xen_map_table(mfn_add(root_mfn, root_table));

    for ( level = root_level; ; level++ )
    {
        if ( offsets[level] > XEN_PT_LPAE_ENTRIES )
            break;

        pte = mapping[offsets[level]];

        printk("%s[0x%03x] = 0x%"PRIx64"\n",
               level_strs[level], offsets[level], pte.bits);

        if ( level == 3 || !pte.walk.valid || !pte.walk.table )
            break;

        /* For next iteration */
        xen_unmap_table(mapping);
        mapping = xen_map_table(lpae_get_mfn(pte));
    }

    xen_unmap_table(mapping);
}

void dump_hyp_walk(vaddr_t addr)
{
    uint64_t ttbr = READ_SYSREG64(TTBR0_EL2);

    printk("Walking Hypervisor VA 0x%"PRIvaddr" "
           "on CPU%d via TTBR 0x%016"PRIx64"\n",
           addr, smp_processor_id(), ttbr);

    dump_pt_walk(ttbr, addr, HYP_PT_ROOT_LEVEL, 1);
}

lpae_t mfn_to_xen_entry(mfn_t mfn, unsigned int attr)
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
void set_fixmap(unsigned int map, mfn_t mfn, unsigned int flags)
{
    int res;

    res = map_pages_to_xen(FIXMAP_ADDR(map), mfn, 1, flags);
    BUG_ON(res != 0);
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned int map)
{
    int res;

    res = destroy_xen_mappings(FIXMAP_ADDR(map), FIXMAP_ADDR(map) + PAGE_SIZE);
    BUG_ON(res != 0);
}

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

lpae_t pte_of_xenaddr(vaddr_t va)
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
    int rc;

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

    rc = map_pages_to_xen(BOOT_FDT_VIRT_START, maddr_to_mfn(base_paddr),
                          SZ_2M >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_RO | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to map the device-tree.\n");


    offset = fdt_paddr % SECOND_SIZE;
    fdt_virt = (void *)BOOT_FDT_VIRT_START + offset;

    if ( fdt_magic(fdt_virt) != FDT_MAGIC )
        return NULL;

    size = fdt_totalsize(fdt_virt);
    if ( size > MAX_FDT_SIZE )
        return NULL;

    if ( (offset + size) > SZ_2M )
    {
        rc = map_pages_to_xen(BOOT_FDT_VIRT_START + SZ_2M,
                              maddr_to_mfn(base_paddr + SZ_2M),
                              SZ_2M >> PAGE_SHIFT,
                              PAGE_HYPERVISOR_RO | _PAGE_BLOCK);
        if ( rc )
            panic("Unable to map the device-tree\n");
    }

    return fdt_virt;
}

void __init remove_early_mappings(void)
{
    int rc;

    /* destroy the _PAGE_BLOCK mapping */
    rc = modify_xen_mappings(BOOT_FDT_VIRT_START,
                             BOOT_FDT_VIRT_START + BOOT_FDT_VIRT_SIZE,
                             _PAGE_BLOCK);
    BUG_ON(rc);
}

/*
 * After boot, Xen page-tables should not contain mapping that are both
 * Writable and eXecutables.
 *
 * This should be called on each CPU to enforce the policy.
 */
static void xen_pt_enforce_wnx(void)
{
    WRITE_SYSREG(READ_SYSREG(SCTLR_EL2) | SCTLR_Axx_ELx_WXN, SCTLR_EL2);
    /*
     * The TLBs may cache SCTLR_EL2.WXN. So ensure it is synchronized
     * before flushing the TLBs.
     */
    isb();
    flush_xen_tlb_local();
}

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

    arch_setup_page_tables();

#ifdef CONFIG_ARM_64
    pte = pte_of_xenaddr((uintptr_t)xen_first);
    pte.pt.table = 1;
    pte.pt.xn = 0;
    xen_pgtable[zeroeth_table_offset(XEN_VIRT_START)] = pte;

    p = (void *) xen_first;
#else
    p = (void *) cpu0_pgtable;
#endif

    /* Map xen second level page-table */
    p[0] = pte_of_xenaddr((uintptr_t)(xen_second));
    p[0].pt.table = 1;
    p[0].pt.xn = 0;

    /* Break up the Xen mapping into 4k pages and protect them separately. */
    for ( i = 0; i < XEN_PT_LPAE_ENTRIES; i++ )
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

    xen_pt_enforce_wnx();

#ifdef CONFIG_ARM_32
    per_cpu(xen_pgtable, 0) = cpu0_pgtable;
#endif
}

static void clear_boot_pagetables(void)
{
    /*
     * Clear the copy of the boot pagetables. Each secondary CPU
     * rebuilds these itself (see head.S).
     */
    clear_table(boot_pgtable);
#ifdef CONFIG_ARM_64
    clear_table(boot_first);
    clear_table(boot_first_id);
#endif
    clear_table(boot_second);
    clear_table(boot_third);
}

#ifdef CONFIG_ARM_64
int init_secondary_pagetables(int cpu)
{
    clear_boot_pagetables();

    /* Set init_ttbr for this CPU coming up. All CPus share a single setof
     * pagetables, but rewrite it each time for consistency with 32 bit. */
    init_ttbr = (uintptr_t) xen_pgtable + phys_offset;
    clean_dcache(init_ttbr);
    return 0;
}
#else
int init_secondary_pagetables(int cpu)
{
    lpae_t *first;

    first = alloc_xenheap_page(); /* root == first level on 32-bit 3-level trie */

    if ( !first )
    {
        printk("CPU%u: Unable to allocate the first page-table\n", cpu);
        return -ENOMEM;
    }

    /* Initialise root pagetable from root of boot tables */
    memcpy(first, cpu0_pgtable, PAGE_SIZE);
    per_cpu(xen_pgtable, cpu) = first;

    if ( !init_domheap_mappings(cpu) )
    {
        printk("CPU%u: Unable to prepare the domheap page-tables\n", cpu);
        per_cpu(xen_pgtable, cpu) = NULL;
        free_xenheap_page(first);
        return -ENOMEM;
    }

    clear_boot_pagetables();

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
/*
 * Set up the direct-mapped xenheap:
 * up to 1GB of contiguous, always-mapped memory.
 */
void __init setup_directmap_mappings(unsigned long base_mfn,
                                     unsigned long nr_mfns)
{
    int rc;

    rc = map_pages_to_xen(XENHEAP_VIRT_START, _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");

    /* Record where the directmap is, for translation routines. */
    directmap_virt_end = XENHEAP_VIRT_START + nr_mfns * PAGE_SIZE;
}
#else /* CONFIG_ARM_64 */
/* Map the region in the directmap area. */
void __init setup_directmap_mappings(unsigned long base_mfn,
                                     unsigned long nr_mfns)
{
    int rc;

    /* First call sets the directmap physical and virtual offset. */
    if ( mfn_eq(directmap_mfn_start, INVALID_MFN) )
    {
        unsigned long mfn_gb = base_mfn & ~((FIRST_SIZE >> PAGE_SHIFT) - 1);

        directmap_mfn_start = _mfn(base_mfn);
        directmap_base_pdx = mfn_to_pdx(_mfn(base_mfn));
        /*
         * The base address may not be aligned to the first level
         * size (e.g. 1GB when using 4KB pages). This would prevent
         * superpage mappings for all the regions because the virtual
         * address and machine address should both be suitably aligned.
         *
         * Prevent that by offsetting the start of the directmap virtual
         * address.
         */
        directmap_virt_start = DIRECTMAP_VIRT_START +
            (base_mfn - mfn_gb) * PAGE_SIZE;
    }

    if ( base_mfn < mfn_x(directmap_mfn_start) )
        panic("cannot add directmap mapping at %lx below heap start %lx\n",
              base_mfn, mfn_x(directmap_mfn_start));

    rc = map_pages_to_xen((vaddr_t)__mfn_to_virt(base_mfn),
                          _mfn(base_mfn), nr_mfns,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the directmap mappings.\n");
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
    int rc;

    /*
     * The size of paddr_t should be sufficient for the complete range of
     * physical address.
     */
    BUILD_BUG_ON((sizeof(paddr_t) * BITS_PER_BYTE) < PADDR_BITS);
    BUILD_BUG_ON(sizeof(struct page_info) != PAGE_INFO_SIZE);

    if ( frametable_size > FRAMETABLE_SIZE )
        panic("The frametable cannot cover the physical region %#"PRIpaddr" - %#"PRIpaddr"\n",
              ps, pe);

    frametable_base_pdx = mfn_to_pdx(maddr_to_mfn(ps));
    /* Round up to 2M or 32M boundary, as appropriate. */
    frametable_size = ROUNDUP(frametable_size, mapping_size);
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));

    rc = map_pages_to_xen(FRAMETABLE_VIRT_START, base_mfn,
                          frametable_size >> PAGE_SHIFT,
                          PAGE_HYPERVISOR_RW | _PAGE_BLOCK);
    if ( rc )
        panic("Unable to setup the frametable mappings.\n");

    memset(&frame_table[0], 0, nr_pdxs * sizeof(struct page_info));
    memset(&frame_table[nr_pdxs], -1,
           frametable_size - (nr_pdxs * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pdxs * sizeof(struct page_info));
}

void *__init arch_vmap_virt_end(void)
{
    return (void *)(VMAP_VIRT_START + VMAP_VIRT_SIZE);
}

/*
 * This function should only be used to remap device address ranges
 * TODO: add a check to verify this assumption
 */
void *ioremap_attr(paddr_t start, size_t len, unsigned int attributes)
{
    mfn_t mfn = _mfn(PFN_DOWN(start));
    unsigned int offs = start & (PAGE_SIZE - 1);
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
    mfn_t mfn;
    void *p;
    lpae_t pte;

    if ( system_state != SYS_STATE_early_boot )
    {
        struct page_info *pg = alloc_domheap_page(NULL, 0);

        if ( pg == NULL )
            return -ENOMEM;

        mfn = page_to_mfn(pg);
    }
    else
        mfn = alloc_boot_pages(1, 1);

    p = xen_map_table(mfn);
    clear_page(p);
    xen_unmap_table(p);

    pte = mfn_to_xen_entry(mfn, MT_NORMAL);
    pte.pt.table = 1;
    write_pte(entry, pte);

    return 0;
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
    mfn_t mfn;

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

    mfn = lpae_get_mfn(*entry);

    xen_unmap_table(*table);
    *table = xen_map_table(mfn);

    return XEN_TABLE_NORMAL_PAGE;
}

/* Sanity check of the entry */
static bool xen_pt_check_entry(lpae_t entry, mfn_t mfn, unsigned int level,
                               unsigned int flags)
{
    /* Sanity check when modifying an entry. */
    if ( (flags & _PAGE_PRESENT) && mfn_eq(mfn, INVALID_MFN) )
    {
        /* We don't allow modifying an invalid entry. */
        if ( !lpae_is_valid(entry) )
        {
            mm_printk("Modifying invalid entry is not allowed.\n");
            return false;
        }

        /* We don't allow modifying a table entry */
        if ( !lpae_is_mapping(entry, level) )
        {
            mm_printk("Modifying a table entry is not allowed.\n");
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
    /* Sanity check when inserting a mapping */
    else if ( flags & _PAGE_PRESENT )
    {
        /* We should be here with a valid MFN. */
        ASSERT(!mfn_eq(mfn, INVALID_MFN));

        /*
         * We don't allow replacing any valid entry.
         *
         * Note that the function xen_pt_update() relies on this
         * assumption and will skip the TLB flush. The function will need
         * to be updated if the check is relaxed.
         */
        if ( lpae_is_valid(entry) )
        {
            if ( lpae_is_mapping(entry, level) )
                mm_printk("Changing MFN for a valid entry is not allowed (%#"PRI_mfn" -> %#"PRI_mfn").\n",
                          mfn_x(lpae_get_mfn(entry)), mfn_x(mfn));
            else
                mm_printk("Trying to replace a table with a mapping.\n");
            return false;
        }
    }
    /* Sanity check when removing a mapping. */
    else if ( (flags & (_PAGE_PRESENT|_PAGE_POPULATE)) == 0 )
    {
        /* We should be here with an invalid MFN. */
        ASSERT(mfn_eq(mfn, INVALID_MFN));

        /* We don't allow removing a table */
        if ( lpae_is_table(entry, level) )
        {
            mm_printk("Removing a table is not allowed.\n");
            return false;
        }

        /* We don't allow removing a mapping with contiguous bit set. */
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

/* Update an entry at the level @target. */
static int xen_pt_update_entry(mfn_t root, unsigned long virt,
                               mfn_t mfn, unsigned int target,
                               unsigned int flags)
{
    int rc;
    unsigned int level;
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
    if ( !xen_pt_check_entry(*entry, mfn, level, flags) )
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

            /*
             * First and second level pages set pte.pt.table = 0, but
             * third level entries set pte.pt.table = 1.
             */
            pte.pt.table = (level == 3);
        }
        else /* We are updating the permission => Copy the current pte. */
            pte = *entry;

        /* Set permission */
        pte.pt.ro = PAGE_RO_MASK(flags);
        pte.pt.xn = PAGE_XN_MASK(flags);
        /* Set contiguous bit */
        pte.pt.contig = !!(flags & _PAGE_CONTIG);
    }

    write_pte(entry, pte);

    rc = 0;

out:
    xen_unmap_table(table);

    return rc;
}

/* Return the level where mapping should be done */
static int xen_pt_mapping_level(unsigned long vfn, mfn_t mfn, unsigned long nr,
                                unsigned int flags)
{
    unsigned int level;
    unsigned long mask;

    /*
      * Don't take into account the MFN when removing mapping (i.e
      * MFN_INVALID) to calculate the correct target order.
      *
      * Per the Arm Arm, `vfn` and `mfn` must be both superpage aligned.
      * They are or-ed together and then checked against the size of
      * each level.
      *
      * `left` is not included and checked separately to allow
      * superpage mapping even if it is not properly aligned (the
      * user may have asked to map 2MB + 4k).
      */
     mask = !mfn_eq(mfn, INVALID_MFN) ? mfn_x(mfn) : 0;
     mask |= vfn;

     /*
      * Always use level 3 mapping unless the caller request block
      * mapping.
      */
     if ( likely(!(flags & _PAGE_BLOCK)) )
         level = 3;
     else if ( !(mask & (BIT(FIRST_ORDER, UL) - 1)) &&
               (nr >= BIT(FIRST_ORDER, UL)) )
         level = 1;
     else if ( !(mask & (BIT(SECOND_ORDER, UL) - 1)) &&
               (nr >= BIT(SECOND_ORDER, UL)) )
         level = 2;
     else
         level = 3;

     return level;
}

#define XEN_PT_4K_NR_CONTIG 16

/*
 * Check whether the contiguous bit can be set. Return the number of
 * contiguous entry allowed. If not allowed, return 1.
 */
static unsigned int xen_pt_check_contig(unsigned long vfn, mfn_t mfn,
                                        unsigned int level, unsigned long left,
                                        unsigned int flags)
{
    unsigned long nr_contig;

    /*
     * Allow the contiguous bit to set when the caller requests block
     * mapping.
     */
    if ( !(flags & _PAGE_BLOCK) )
        return 1;

    /*
     * We don't allow to remove mapping with the contiguous bit set.
     * So shortcut the logic and directly return 1.
     */
    if ( mfn_eq(mfn, INVALID_MFN) )
        return 1;

    /*
     * The number of contiguous entries varies depending on the page
     * granularity used. The logic below assumes 4KB.
     */
    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);

    /*
     * In order to enable the contiguous bit, we should have enough entries
     * to map left and both the virtual and physical address should be
     * aligned to the size of 16 translation tables entries.
     */
    nr_contig = BIT(XEN_PT_LEVEL_ORDER(level), UL) * XEN_PT_4K_NR_CONTIG;

    if ( (left < nr_contig) || ((mfn_x(mfn) | vfn) & (nr_contig - 1)) )
        return 1;

    return XEN_PT_4K_NR_CONTIG;
}

static DEFINE_SPINLOCK(xen_pt_lock);

static int xen_pt_update(unsigned long virt,
                         mfn_t mfn,
                         /* const on purpose as it is used for TLB flush */
                         const unsigned long nr_mfns,
                         unsigned int flags)
{
    int rc = 0;
    unsigned long vfn = virt >> PAGE_SHIFT;
    unsigned long left = nr_mfns;

    /*
     * For arm32, page-tables are different on each CPUs. Yet, they share
     * some common mappings. It is assumed that only common mappings
     * will be modified with this function.
     *
     * XXX: Add a check.
     */
    const mfn_t root = maddr_to_mfn(READ_SYSREG64(TTBR0_EL2));

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

    if ( flags & _PAGE_CONTIG )
    {
        mm_printk("_PAGE_CONTIG is an internal only flag.\n");
        return -EINVAL;
    }

    if ( !IS_ALIGNED(virt, PAGE_SIZE) )
    {
        mm_printk("The virtual address is not aligned to the page-size.\n");
        return -EINVAL;
    }

    spin_lock(&xen_pt_lock);

    while ( left )
    {
        unsigned int order, level, nr_contig, new_flags;

        level = xen_pt_mapping_level(vfn, mfn, left, flags);
        order = XEN_PT_LEVEL_ORDER(level);

        ASSERT(left >= BIT(order, UL));

        /*
         * Check if we can set the contiguous mapping and update the
         * flags accordingly.
         */
        nr_contig = xen_pt_check_contig(vfn, mfn, level, left, flags);
        new_flags = flags | ((nr_contig > 1) ? _PAGE_CONTIG : 0);

        for ( ; nr_contig > 0; nr_contig-- )
        {
            rc = xen_pt_update_entry(root, vfn << PAGE_SHIFT, mfn, level,
                                     new_flags);
            if ( rc )
                break;

            vfn += 1U << order;
            if ( !mfn_eq(mfn, INVALID_MFN) )
                mfn = mfn_add(mfn, 1U << order);

            left -= (1U << order);
        }

        if ( rc )
            break;
    }

    /*
     * The TLBs flush can be safely skipped when a mapping is inserted
     * as we don't allow mapping replacement (see xen_pt_check_entry()).
     *
     * For all the other cases, the TLBs will be flushed unconditionally
     * even if the mapping has failed. This is because we may have
     * partially modified the PT. This will prevent any unexpected
     * behavior afterwards.
     */
    if ( !((flags & _PAGE_PRESENT) && !mfn_eq(mfn, INVALID_MFN)) )
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

int destroy_xen_mappings(unsigned long s, unsigned long e)
{
    ASSERT(IS_ALIGNED(s, PAGE_SIZE));
    ASSERT(IS_ALIGNED(e, PAGE_SIZE));
    ASSERT(s <= e);
    return xen_pt_update(s, INVALID_MFN, (e - s) >> PAGE_SHIFT, 0);
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int flags)
{
    ASSERT(IS_ALIGNED(s, PAGE_SIZE));
    ASSERT(IS_ALIGNED(e, PAGE_SIZE));
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

    /*
     * The incremented type count pins as writable or read-only.
     *
     * Please note, the update of type_info field here is not atomic as
     * we use Read-Modify-Write operation on it. But currently it is fine
     * because the caller of page_set_xenheap_gfn() (which is another place
     * where type_info is updated) would need to acquire a reference on
     * the page. This is only possible after the count_info is updated *and*
     * there is a barrier between the type_info and count_info. So there is
     * no immediate need to use cmpxchg() here.
     */
    page->u.inuse.type_info &= ~(PGT_type_mask | PGT_count_mask);
    page->u.inuse.type_info |= (flags == SHARE_ro ? PGT_none
                                                  : PGT_writable_page) |
                                MASK_INSR(1, PGT_count_mask);

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
    union add_to_physmap_extra extra,
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

        /* Need to take care of the reference obtained in gnttab_map_frame(). */
        page = mfn_to_page(mfn);
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
        rc = map_dev_mmio_page(d, gfn, _mfn(idx));
        return rc;

    default:
        return -ENOSYS;
    }

    /*
     * Map at new location. Here we need to map xenheap RAM page differently
     * because we need to store the valid GFN and make sure that nothing was
     * mapped before (the stored GFN is invalid). And these actions need to be
     * performed with the P2M lock held. The guest_physmap_add_entry() is just
     * a wrapper on top of p2m_set_entry().
     */
    if ( !p2m_is_ram(t) || !is_xen_heap_mfn(mfn) )
        rc = guest_physmap_add_entry(d, gfn, mfn, 0, t);
    else
    {
        struct p2m_domain *p2m = p2m_get_hostp2m(d);

        p2m_write_lock(p2m);
        if ( gfn_eq(page_get_xenheap_gfn(mfn_to_page(mfn)), INVALID_GFN) )
        {
            rc = p2m_set_entry(p2m, gfn, 1, mfn, t, p2m->default_access);
            if ( !rc )
                page_set_xenheap_gfn(mfn_to_page(mfn), gfn);
        }
        else
            /*
             * Mandate the caller to first unmap the page before mapping it
             * again. This is to prevent Xen creating an unwanted hole in
             * the P2M. For instance, this could happen if the firmware stole
             * a RAM address for mapping the shared_info page into but forgot
             * to unmap it afterwards.
             */
            rc = -EBUSY;
        p2m_write_unlock(p2m);
    }

    /*
     * For XENMAPSPACE_gmfn_foreign if we failed to add the mapping, we need
     * to drop the reference we took earlier. In all other cases we need to
     * drop any reference we took earlier (perhaps indirectly).
     */
    if ( space == XENMAPSPACE_gmfn_foreign ? rc : page != NULL )
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

static struct domain *page_get_owner_and_nr_reference(struct page_info *page,
                                                      unsigned long nr)
{
    unsigned long x, y = page->count_info;
    struct domain *owner;

    /* Restrict nr to avoid "double" overflow */
    if ( nr >= PGC_count_mask )
    {
        ASSERT_UNREACHABLE();
        return NULL;
    }

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         */
        if ( unlikely(((x + nr) & PGC_count_mask) <= nr) )
            return NULL;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + nr)) != x );

    owner = page_get_owner(page);
    ASSERT(owner);

    return owner;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{
    return page_get_owner_and_nr_reference(page, 1);
}

void put_page_nr(struct page_info *page, unsigned long nr)
{
    unsigned long nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) >= nr);
        x  = y;
        nx = x - nr;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        if ( unlikely(nx & PGC_static) )
            free_domstatic_page(page);
        else
            free_domheap_page(page);
    }
}

void put_page(struct page_info *page)
{
    put_page_nr(page, 1);
}

bool get_page_nr(struct page_info *page, const struct domain *domain,
                 unsigned long nr)
{
    const struct domain *owner = page_get_owner_and_nr_reference(page, nr);

    if ( likely(owner == domain) )
        return true;

    if ( owner != NULL )
        put_page_nr(page, nr);

    return false;
}

bool get_page(struct page_info *page, const struct domain *domain)
{
    return get_page_nr(page, domain, 1);
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

int create_grant_host_mapping(unsigned long gpaddr, mfn_t frame,
                              unsigned int flags, unsigned int cache_flags)
{
    int rc;
    p2m_type_t t = p2m_grant_map_rw;

    if ( cache_flags  || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    if ( flags & GNTMAP_readonly )
        t = p2m_grant_map_ro;

    rc = guest_physmap_add_entry(current->domain, gaddr_to_gfn(gpaddr),
                                 frame, 0, t);

    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int replace_grant_host_mapping(unsigned long gpaddr, mfn_t frame,
                               unsigned long new_gpaddr, unsigned int flags)
{
    gfn_t gfn = gaddr_to_gfn(gpaddr);
    struct domain *d = current->domain;
    int rc;

    if ( new_gpaddr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    rc = guest_physmap_remove_page(d, gfn, frame, 0);

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
