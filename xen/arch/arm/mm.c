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
#include <xen/grant_table.h>
#include <xen/guest_access.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/sizes.h>

#include <xsm/xsm.h>

#include <asm/setup.h>

#include <public/memory.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))
#undef mfn_to_virt
#define mfn_to_virt(mfn) __mfn_to_virt(mfn_x(mfn))

/* Main runtime page tables */

/*
 * For arm32 xen_pgtable are per-PCPU and are allocated before
 * bringing up each CPU. For arm64 xen_pgtable is common to all PCPUs.
 *
 * xen_second, xen_fixmap and xen_xenmap are always shared between all
 * PCPUs.
 */

#ifdef CONFIG_ARM_64
DEFINE_PAGE_TABLE(xen_pgtable);
static DEFINE_PAGE_TABLE(xen_first);
#define THIS_CPU_PGTABLE xen_pgtable
#else
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
static DEFINE_PAGE_TABLES(xen_xenmap, XEN_NR_ENTRIES(2));

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

    /* Break up the Xen mapping into pages and protect them separately. */
    for ( i = 0; i < XEN_NR_ENTRIES(3); i++ )
    {
        vaddr_t va = XEN_VIRT_START + (i << PAGE_SHIFT);

        if ( !is_kernel(va) )
            break;
        pte = pte_of_xenaddr(va);
        pte.pt.table = 1; /* third level mappings always have this bit set */
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
    for ( i = 0; i < XEN_NR_ENTRIES(2); i++ )
    {
        vaddr_t va = XEN_VIRT_START + (i << XEN_PT_LEVEL_SHIFT(2));

        pte = pte_of_xenaddr((vaddr_t)(xen_xenmap + i * XEN_PT_LPAE_ENTRIES));
        pte.pt.table = 1;
        xen_second[second_table_offset(va)] = pte;
    }

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

int create_grant_host_mapping(uint64_t gpaddr, mfn_t frame,
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

int replace_grant_host_mapping(uint64_t gpaddr, mfn_t frame,
                               uint64_t new_gpaddr, unsigned int flags)
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
