/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/macros.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/paging.h>
#include <xen/rwlock.h>
#include <xen/sched.h>
#include <xen/sections.h>
#include <xen/xvmalloc.h>

#include <asm/cpufeature.h>
#include <asm/csr.h>
#include <asm/flushtlb.h>
#include <asm/p2m.h>
#include <asm/paging.h>
#include <asm/riscv_encoding.h>
#include <asm/vmid.h>

/*
 * At the moment, only 4K, 2M, and 1G mappings are supported for G-stage
 * translation. Therefore, the maximum supported page-table level is 2,
 * which corresponds to 1G mappings.
 */
#define P2M_MAX_SUPPORTED_LEVEL_MAPPING _AC(2, U)

struct md_t {
    /*
     * Describes a type stored outside PTE bits.
     * Look at the comment above definition of enum p2m_type_t.
     */
    p2m_type_t type : 4;
};

/*
 * P2M PTE context is used only when a PTE's P2M type is p2m_ext_storage.
 * In this case, the P2M type is stored separately in the metadata page.
 */
struct p2m_pte_ctx {
    struct p2m_domain *p2m;
    struct page_info *pt_page;   /* Page table page containing the PTE. */
    unsigned int index;          /* Index of the PTE within that page. */
    unsigned int level;          /* Paging level at which the PTE resides. */
};

static struct gstage_mode_desc __ro_after_init max_gstage_mode = {
    .mode = HGATP_MODE_OFF,
    .paging_levels = 0,
    .name = "Bare",
};

static void p2m_free_page(struct p2m_domain *p2m, struct page_info *pg);

static inline void p2m_free_metadata_page(struct p2m_domain *p2m,
                                          struct page_info **md_pg)
{
    if ( *md_pg )
    {
        p2m_free_page(p2m, *md_pg);
        *md_pg = NULL;
    }
}

unsigned char get_max_supported_mode(void)
{
    return max_gstage_mode.mode;
}

/*
 * If anything is changed here, it may also require updates to
 * p2m_{get,set}_type().
 */
static inline unsigned int calc_offset(const struct p2m_domain *p2m,
                                       const unsigned int lvl,
                                       const paddr_t gpa)
{
    unsigned int off = (gpa >> P2M_GFN_LEVEL_SHIFT(lvl)) &
                       P2M_TABLE_OFFSET(p2m, lvl);

    /*
     * For P2M_ROOT_LEVEL, `offset` ranges from 0 to 2047, since the root
     * page table spans 4 consecutive 4KB pages.
     * We want to return an index within one of these 4 pages.
     * The specific page to use is determined by `p2m_get_root_pointer()`.
     *
     * Example: if `offset == 512`:
     *  - A single 4KB page holds 512 entries.
     *  - Therefore, entry 512 corresponds to index 0 of the second page.
     *
     * At all other levels, only one page is allocated, and `offset` is
     * always in the range 0 to 511, since the VPN is 9 bits long.
     */
    return off & (PAGETABLE_ENTRIES - 1);
}

#define P2M_MAX_ROOT_LEVEL 5

#define P2M_BUILD_LEVEL_OFFSETS(p2m, var, addr) \
    unsigned int var[P2M_MAX_ROOT_LEVEL]; \
    BUG_ON(P2M_ROOT_LEVEL(p2m) >= P2M_MAX_ROOT_LEVEL); \
    for ( unsigned int i = 0; i <= P2M_ROOT_LEVEL(p2m); i++ ) \
        var[i] = calc_offset(p2m, i, addr);

/*
 * Map one of the four root pages of the P2M root page table.
 *
 * The P2M root page table is larger than normal (16KB instead of 4KB),
 * so it is allocated as four consecutive 4KB pages. This function selects
 * the appropriate 4KB page based on the given GFN and returns a mapping
 * to it.
 *
 * The caller is responsible for unmapping the page after use.
 *
 * Returns NULL if the calculated offset into the root table is invalid.
 *
 * If anything is changed here, it may also require updates to
 * p2m_{get,set}_type().
 */
static pte_t *p2m_get_root_pointer(struct p2m_domain *p2m, gfn_t gfn)
{
    unsigned long idx;
    unsigned long root_level = P2M_ROOT_LEVEL(p2m);

    idx = gfn_x(gfn) >> P2M_LEVEL_ORDER(root_level);
    if ( idx >= P2M_PAGETABLE_ENTRIES(p2m, root_level) )
        return NULL;

    /*
     * The P2M root page table is extended by 2 bits, making its size 16KB
     * (instead of 4KB for non-root page tables). Therefore, p2m->root is
     * allocated as four consecutive 4KB pages (since alloc_domheap_pages()
     * only allocates 4KB pages).
     *
     * Initially, `idx` is derived directly from `gfn`.
     * To locate the correct entry within a single 4KB page,
     * we rescale the offset so it falls within one of the 4 pages.
     *
     * Example: if `idx == 512`
     * - A 4KB page holds 512 entries.
     * - Thus, entry 512 corresponds to index 0 of the second page.
     */
    idx /= PAGETABLE_ENTRIES;

    return __map_domain_page(p2m->root + idx);
}

static void __init gstage_mode_detect(void)
{
    static const struct gstage_mode_desc modes[] __initconst = {
        /*
         * Based on the RISC-V spec:
         *   Bare mode is always supported, regardless of SXLEN.
         *   When SXLEN=32, the only other valid setting for MODE is Sv32.
         *   When SXLEN=64, three paged virtual-memory schemes are defined:
         *   Sv39, Sv48, and Sv57.
         */
#ifdef CONFIG_RISCV_32
        { HGATP_MODE_SV32X4, 2, "Sv32x4" }
#else
        { HGATP_MODE_SV39X4, 3, "Sv39x4" },
        { HGATP_MODE_SV48X4, 4, "Sv48x4" },
        { HGATP_MODE_SV57X4, 5, "Sv57x4" },
#endif
    };

    for ( unsigned int mode_idx = ARRAY_SIZE(modes); mode_idx-- > 0; )
    {
        unsigned long mode = modes[mode_idx].mode;

        csr_write(CSR_HGATP, MASK_INSR(mode, HGATP_MODE_MASK));

        if ( MASK_EXTR(csr_read(CSR_HGATP), HGATP_MODE_MASK) == mode )
        {
            max_gstage_mode = modes[mode_idx];

            break;
        }
    }

    if ( max_gstage_mode.mode == HGATP_MODE_OFF )
        panic("Xen expects that G-stage won't be Bare mode\n");

    printk("Max supported G-stage mode is %s\n", max_gstage_mode.name);

    csr_write(CSR_HGATP, 0);

    /* local_hfence_gvma_all() will be called at the end of guest_mm_init. */
}

void __init guest_mm_init(void)
{
    gstage_mode_detect();

    vmid_init();

    /*
     * As gstage_mode_detect() and vmid_init() are changing CSR_HGATP, it is
     * necessary to flush guest TLB because:
     *
     * From RISC-V spec:
     *   Speculative executions of the address-translation algorithm behave as
     *   non-speculative executions of the algorithm do, except that they must
     *   not set the dirty bit for a PTE, they must not trigger an exception,
     *   and they must not create address-translation cache entries if those
     *   entries would have been invalidated by any SFENCE.VMA instruction
     *   executed by the hart since the speculative execution of the algorithm
     *   began.
     *
     * Also, despite of the fact here it is mentioned that when V=0 two-stage
     * address translation is inactivated:
     *   The current virtualization mode, denoted V, indicates whether the hart
     *   is currently executing in a guest. When V=1, the hart is either in
     *   virtual S-mode (VS-mode), or in virtual U-mode (VU-mode) atop a guest
     *   OS running in VS-mode. When V=0, the hart is either in M-mode, in
     *   HS-mode, or in U-mode atop an OS running in HS-mode. The
     *   virtualization mode also indicates whether two-stage address
     *   translation is active (V=1) or inactive (V=0).
     * But on the same side, writing to hgatp register activates it:
     *   The hgatp register is considered active for the purposes of
     *   the address-translation algorithm unless the effective privilege mode
     *   is U and hstatus.HU=0.
     *
     * Thereby it leaves some room for speculation even in this stage of boot,
     * so it could be that we polluted local TLB so flush all guest TLB.
     */
    local_hfence_gvma_all();
}

/*
 * Force a synchronous P2M TLB flush.
 *
 * Must be called with the p2m lock held.
 */
static void p2m_tlb_flush(struct p2m_domain *p2m)
{
    const struct domain *d = p2m->domain;

    ASSERT(p2m_is_write_locked(p2m));

    p2m->need_flush = false;

    sbi_remote_hfence_gvma(d->dirty_cpumask, 0, 0);
}

void p2m_tlb_flush_sync(struct p2m_domain *p2m)
{
    if ( p2m->need_flush )
        p2m_tlb_flush(p2m);
}

/* Unlock the P2M and do a P2M TLB flush if necessary */
void p2m_write_unlock(struct p2m_domain *p2m)
{
    /*
     * The final flush is done with the P2M write lock taken to avoid
     * someone else modifying the P2M before the TLB invalidation has
     * completed.
     */
    p2m_tlb_flush_sync(p2m);

    write_unlock(&p2m->lock);
}

static void clear_and_clean_page(struct page_info *page, bool clean_dcache)
{
    void *p = __map_domain_page(page);

    clear_page(p);

    /*
     * If the IOMMU doesn't support coherent walks and the p2m tables are
     * shared between the CPU and IOMMU, it is necessary to clean the
     * d-cache.
     */
    if ( clean_dcache )
        clean_dcache_va_range(p, PAGE_SIZE);

    unmap_domain_page(p);
}

unsigned long construct_hgatp(const struct p2m_domain *p2m, uint16_t vmid)
{
    return MASK_INSR(mfn_x(page_to_mfn(p2m->root)), HGATP_PPN_MASK) |
           MASK_INSR(p2m->mode.mode, HGATP_MODE_MASK) |
           MASK_INSR(vmid, HGATP_VMID_MASK);
}

static int p2m_alloc_root_table(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;
    struct page_info *page;
    int rc;

    /*
     * Return back P2M_ROOT_PAGES to assure the root table memory is also
     * accounted against the P2M pool of the domain.
     */
    if ( (rc = paging_ret_to_domheap(d, P2M_ROOT_PAGES)) )
        return rc;

    /*
     * As mentioned in the Priviliged Architecture Spec (version 20240411)
     * in Section 18.5.1, for the paged virtual-memory schemes  (Sv32x4,
     * Sv39x4, Sv48x4, and Sv57x4), the root page table is 16 KiB and must
     * be aligned to a 16-KiB boundary.
     */
    page = alloc_domheap_pages(d, P2M_ROOT_ORDER, MEMF_no_owner);
    if ( !page )
    {
        /*
         * If allocation of root table pages fails, the pages acquired above
         * must be returned to the freelist to maintain proper freelist
         * balance.
         */
        paging_refill_from_domheap(d, P2M_ROOT_PAGES);

        return -ENOMEM;
    }

    for ( unsigned int i = 0; i < P2M_ROOT_PAGES; i++ )
    {
        clear_and_clean_page(page + i, p2m->clean_dcache);

        page_list_add(page + i, &p2m->pages);
    }

    p2m->root = page;

    return 0;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /*
     * "Trivial" initialisation is now complete.  Set the backpointer so the
     * users of p2m could get an access to domain structure.
     */
    p2m->domain = d;

    paging_domain_init(d);

    rwlock_init(&p2m->lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);

    p2m->max_mapped_gfn = _gfn(0);
    p2m->lowest_mapped_gfn = _gfn(ULONG_MAX);

    /*
     * Currently, the infrastructure required to enable CONFIG_HAS_PASSTHROUGH
     * is not ready for RISC-V support.
     *
     * When CONFIG_HAS_PASSTHROUGH=y, p2m->clean_dcache must be properly
     * initialized.
     * At the moment, it defaults to false because the p2m structure is
     * zero-initialized.
     */
#ifdef CONFIG_HAS_PASSTHROUGH
#   error "Add init of p2m->clean_dcache"
#endif

    /* TODO: don't hardcode used for a domain g-stage mode. */
    p2m->mode.mode = HGATP_MODE_SV39X4;
    p2m->mode.paging_levels = 2;
    safe_strcpy(p2m->mode.name, "Sv39x4");

    return 0;
}

/*
 * Set the pool of pages to the required number of pages.
 * Returns 0 for success, non-zero for failure.
 * Call with d->arch.paging.lock held.
 */
int p2m_set_allocation(struct domain *d, unsigned long pages, bool *preempted)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc;

    if ( (rc = paging_freelist_adjust(d, pages, preempted)) )
        return rc;

    /*
     * First, initialize p2m pool. Then allocate the root
     * table so that the necessary pages can be returned from the p2m pool,
     * since the root table must be allocated using alloc_domheap_pages(...)
     * to meet its specific requirements.
     */
    if ( !p2m->root )
        rc = p2m_alloc_root_table(p2m);

    return rc;
}

static struct page_info *p2m_alloc_page(struct p2m_domain *p2m)
{
    struct page_info *pg = paging_alloc_page(p2m->domain);

    if ( pg )
    {
        page_list_add(pg, &p2m->pages);
        clear_and_clean_page(pg, p2m->clean_dcache);
    }

    return pg;
}

/*
 * `pte` – PTE entry for which the type `t` will be stored.
 *
 * If `t` >= p2m_first_external, a valid `ctx` must be provided.
 */
static void p2m_set_type(pte_t *pte, p2m_type_t t,
                         const struct p2m_pte_ctx *ctx)
{
    struct page_info **md_pg;
    struct md_t *metadata = NULL;

    /*
     * It is sufficient to compare ctx->index with PAGETABLE_ENTRIES because,
     * even for the p2m root page table (which is a 16 KB page allocated as
     * four 4 KB pages), calc_offset() guarantees that the page-table index
     * will always fall within the range [0, 511].
     */
    ASSERT(ctx && ctx->index < PAGETABLE_ENTRIES && ctx->p2m);

    /*
     * At the moment, p2m_get_root_pointer() returns one of four possible p2m
     * root pages, so there is no need to search for the correct ->pt_page
     * here.
     * Non-root page tables are 4 KB pages, so simply using ->pt_page is
     * sufficient.
     */
    md_pg = &ctx->pt_page->v.md.pg;

    if ( !*md_pg && (t >= p2m_first_external) )
    {
        /*
         * Since p2m_alloc_page() initializes an allocated page with
         * zeros, p2m_invalid is expected to have the value 0 as well.
         */
        BUILD_BUG_ON(p2m_invalid);

        *md_pg = p2m_alloc_page(ctx->p2m);
        if ( !*md_pg )
        {
            printk("%pd: can't allocate metadata page\n",
                    ctx->p2m->domain);
            domain_crash(ctx->p2m->domain);

            return;
        }
    }

    if ( *md_pg )
        metadata = __map_domain_page(*md_pg);

    if ( t >= p2m_first_external )
    {
        if ( metadata[ctx->index].type == p2m_invalid )
            ctx->pt_page->u.md.used_entries++;

        metadata[ctx->index].type = t;

        t = p2m_ext_storage;
    }
    else if ( metadata )
    {
        if ( metadata[ctx->index].type != p2m_invalid )
            ctx->pt_page->u.md.used_entries--;

        metadata[ctx->index].type = p2m_invalid;
    }

    pte->pte |= MASK_INSR(t, P2M_TYPE_PTE_BITS_MASK);

    unmap_domain_page(metadata);

    if ( *md_pg && !ctx->pt_page->u.md.used_entries )
        p2m_free_metadata_page(ctx->p2m, md_pg);
}

/*
 * `pte` -> PTE entry that stores the PTE's type.
 *
 * If the PTE's type is `p2m_ext_storage`, `ctx` should be provided;
 * otherwise it could be NULL.
 */
static p2m_type_t p2m_get_type(const pte_t pte, const struct p2m_pte_ctx *ctx)
{
    p2m_type_t type = MASK_EXTR(pte.pte, P2M_TYPE_PTE_BITS_MASK);

    if ( type == p2m_ext_storage )
    {
        const struct md_t *md = __map_domain_page(ctx->pt_page->v.md.pg);

        type = md[ctx->index].type;

        /*
         * Since p2m_set_type() guarantees that the type will be greater than
         * p2m_first_external, just check that we received a valid type here.
         */
        ASSERT(type > p2m_first_external);

        unmap_domain_page(md);
    }

    return type;
}

static inline void p2m_write_pte(pte_t *p, pte_t pte, bool clean_cache)
{
    write_pte(p, pte);

    /*
     * TODO: if multiple adjacent PTEs are written without releasing
     *       the lock, this then redundant cache flushing can be a
     *       performance issue.
     */
    if ( clean_cache )
        clean_dcache_va_range(p, sizeof(*p));
}

static inline void p2m_clean_pte(pte_t *p, bool clean_cache)
{
    pte_t pte = { .pte = 0 };

    p2m_write_pte(p, pte, clean_cache);
}

static void p2m_set_permission(pte_t *e, p2m_type_t t)
{
    e->pte &= ~PTE_ACCESS_MASK;

    e->pte |= PTE_USER;

    /*
     * Two schemes to manage the A and D bits are defined:
     *   • The Svade extension: when a virtual page is accessed and the A bit
     *     is clear, or is written and the D bit is clear, a page-fault
     *     exception is raised.
     *   • When the Svade extension is not implemented, the following scheme
     *     applies.
     *     When a virtual page is accessed and the A bit is clear, the PTE is
     *     updated to set the A bit. When the virtual page is written and the
     *     D bit is clear, the PTE is updated to set the D bit. When G-stage
     *     address translation is in use and is not Bare, the G-stage virtual
     *     pages may be accessed or written by implicit accesses to VS-level
     *     memory management data structures, such as page tables.
     * Thereby to avoid a page-fault in case of Svade is available, it is
     * necessary to set A and D bits.
     *
     * TODO: For now, it’s fine to simply set the A/D bits, since OpenSBI
     *       delegates page faults to a lower privilege mode and so OpenSBI
     *       isn't expect to handle page-faults occured in lower modes.
     *       By setting the A/D bits here, page faults that would otherwise
     *       be generated due to unset A/D bits will not occur in Xen.
     *
     *       Currently, Xen on RISC-V does not make use of the information
     *       that could be obtained from handling such page faults, which
     *       could otherwise be useful for several use cases such as demand
     *       paging, cache-flushing optimizations, memory access tracking,etc.
     *
     *       To support the more general case and the optimizations mentioned
     *       above, it would be better to stop setting the A/D bits here and
     *       instead handle page faults that occur due to unset A/D bits.
     */
    if ( riscv_isa_extension_available(NULL, RISCV_ISA_EXT_svade) )
        e->pte |= PTE_ACCESSED | PTE_DIRTY;

    switch ( t )
    {
    case p2m_map_foreign_rw:
    case p2m_mmio_direct_io:
        e->pte |= PTE_READABLE | PTE_WRITABLE;
        break;

    case p2m_ram_rw:
        e->pte |= PTE_ACCESS_MASK;
        break;

    case p2m_invalid:
        e->pte &= ~PTE_VALID;
        break;

    case p2m_map_foreign_ro:
        e->pte |= PTE_READABLE;
        break;

    default:
        ASSERT_UNREACHABLE();
        break;
    }
}

/*
 * If p2m_pte_from_mfn() is called with ctx = NULL,
 * it means the function is working with a page table for which the `t`
 * should not be applicable. Otherwise, the function is handling a leaf PTE
 * for which `t` is applicable.
 */
static pte_t p2m_pte_from_mfn(mfn_t mfn, p2m_type_t t,
                              struct p2m_pte_ctx *ctx)
{
    pte_t e = (pte_t) { PTE_VALID };

    pte_set_mfn(&e, mfn);

    ASSERT(!(mfn_to_maddr(mfn) & ~PADDR_MASK) || mfn_eq(mfn, INVALID_MFN));

    if ( ctx )
    {
        switch ( t )
        {
        case p2m_mmio_direct_io:
            e.pte |= PTE_PBMT_IO;
            break;

        default:
            break;
        }

        p2m_set_permission(&e, t);
        p2m_set_type(&e, t, ctx);
    }
    else
        /*
         * According to the spec and table "Encoding of PTE R/W/X fields":
         *   X=W=R=0 -> Pointer to next level of page table.
         */
        e.pte &= ~PTE_ACCESS_MASK;

    return e;
}

/* Generate table entry with correct attributes. */
static pte_t page_to_p2m_table(const struct page_info *page)
{
    /*
     * p2m_invalid will be ignored inside p2m_pte_from_mfn() as is_table is
     * set to true and p2m_type_t shouldn't be applied for PTEs which
     * describe an intermediate table.
     */
    return p2m_pte_from_mfn(page_to_mfn(page), p2m_invalid, NULL);
}

/*
 * Free page table's page and metadata page linked to page table's page.
 */
static void p2m_free_table(struct p2m_domain *p2m, struct page_info *tbl_pg)
{
    p2m_free_metadata_page(p2m, &tbl_pg->v.md.pg);

    p2m_free_page(p2m, tbl_pg);
}

/* Allocate a new page table page and hook it in via the given entry. */
static int p2m_create_table(struct p2m_domain *p2m, pte_t *entry)
{
    struct page_info *page;

    ASSERT(!pte_is_valid(*entry));

    page = p2m_alloc_page(p2m);
    if ( page == NULL )
        return -ENOMEM;

    p2m_write_pte(entry, page_to_p2m_table(page), p2m->clean_dcache);

    return 0;
}

#define P2M_TABLE_MAP_NONE 0
#define P2M_TABLE_MAP_NOMEM 1
#define P2M_TABLE_SUPER_PAGE 2
#define P2M_TABLE_NORMAL 3

/*
 * Take the currently mapped table, find the entry corresponding to the GFN,
 * and map the next-level table if available. The previous table will be
 * unmapped if the next level was mapped (e.g., when P2M_TABLE_NORMAL is
 * returned).
 *
 * `alloc_tbl` parameter indicates whether intermediate tables should
 * be allocated when not present.
 *
 * Return values:
 *  P2M_TABLE_MAP_NONE: a table allocation isn't permitted.
 *  P2M_TABLE_MAP_NOMEM: allocating a new page failed.
 *  P2M_TABLE_SUPER_PAGE: next level or leaf mapped normally.
 *  P2M_TABLE_NORMAL: The next entry points to a superpage.
 */
static int p2m_next_level(struct p2m_domain *p2m, bool alloc_tbl,
                          unsigned int level, pte_t **table,
                          unsigned int offset)
{
    pte_t *entry;
    mfn_t mfn;

    /* The function p2m_next_level() is never called at the last level */
    ASSERT(level != 0);

    entry = *table + offset;

    if ( !pte_is_valid(*entry) )
    {
        int ret;

        if ( !alloc_tbl )
            return P2M_TABLE_MAP_NONE;

        ret = p2m_create_table(p2m, entry);
        if ( ret )
            return P2M_TABLE_MAP_NOMEM;
    }

    if ( pte_is_mapping(*entry) )
        return P2M_TABLE_SUPER_PAGE;

    mfn = mfn_from_pte(*entry);

    unmap_domain_page(*table);

    /*
     * TODO: There's an inefficiency here:
     *       In p2m_create_table(), the page is mapped to clear it.
     *       Then that mapping is torn down in p2m_create_table(),
     *       only to be re-established here.
     */
    *table = map_domain_page(mfn);

    return P2M_TABLE_NORMAL;
}

static void p2m_put_foreign_page(struct page_info *pg)
{
    /*
     * It’s safe to call put_page() here because arch_flush_tlb_mask()
     * will be invoked if the page is reallocated, which will trigger a
     * flush of the guest TLBs.
     */
    put_page(pg);
}

static void p2m_put_4k_page(mfn_t mfn, p2m_type_t type)
{
    /* TODO: Handle other p2m types */

    if ( p2m_is_foreign(type) )
    {
        ASSERT(mfn_valid(mfn));
        p2m_put_foreign_page(mfn_to_page(mfn));
    }
}

static void p2m_put_2m_superpage(mfn_t mfn, p2m_type_t type)
{
    struct page_info *pg;
    unsigned int i;

    /* TODO: Handle other p2m types */
    if ( !p2m_is_foreign(type) )
        return;

    ASSERT(mfn_valid(mfn));

    pg = mfn_to_page(mfn);

    /*
     * PAGETABLE_ENTRIES is used instead of P2M_PAGETABLE_ENTRIES(1) because
     * they are expected to be identical (this is verified in calc_offset()).
     * This avoids having to pass p2m_domain here and throughout the call stack
     * above solely for the sake of one macro.
     */
    for ( i = 0; i < PAGETABLE_ENTRIES; i++, pg++ )
        p2m_put_foreign_page(pg);
}

static void p2m_put_page(const pte_t pte, unsigned int level, p2m_type_t p2mt)
{
    mfn_t mfn = pte_get_mfn(pte);

    ASSERT(pte_is_valid(pte));

    /*
     * TODO: Currently we don't handle level 2 super-page, Xen is not
     * preemptible and therefore some work is needed to handle such
     * superpages, for which at some point Xen might end up freeing memory
     * and therefore for such a big mapping it could end up in a very long
     * operation.
     */
    switch ( level )
    {
    case 1:
        return p2m_put_2m_superpage(mfn, p2mt);

    case 0:
        return p2m_put_4k_page(mfn, p2mt);

    default:
        ASSERT_UNREACHABLE();
        break;
    }
}

static void p2m_free_page(struct p2m_domain *p2m, struct page_info *pg)
{
    page_list_del(pg, &p2m->pages);

    paging_free_page(p2m->domain, pg);
}

/* Free pte sub-tree behind an entry */
static void p2m_free_subtree(struct p2m_domain *p2m,
                             pte_t entry,
                             const struct p2m_pte_ctx *ctx)
{
    unsigned int i;
    pte_t *table;
    mfn_t mfn;
    struct page_info *pg;
    unsigned int level = ctx->level;

    /*
     * Check if the level is valid: only 4K - 2M - 1G mappings are supported.
     * To support levels > 2, the implementation of p2m_free_subtree() would
     * need to be updated, as the current recursive approach could consume
     * excessive time and memory.
     */
    ASSERT(level <= P2M_MAX_SUPPORTED_LEVEL_MAPPING);

    /* Nothing to do if the entry is invalid. */
    if ( !pte_is_valid(entry) )
        return;

    if ( pte_is_mapping(entry) )
    {
        p2m_type_t p2mt = p2m_get_type(entry, ctx);

#ifdef CONFIG_IOREQ_SERVER
        /*
         * If this gets called then either the entry was replaced by an entry
         * with a different base (valid case) or the shattering of a superpage
         * has failed (error case).
         * So, at worst, the spurious mapcache invalidation might be sent.
         */
        if ( p2m_is_ram(p2mt) &&
             domain_has_ioreq_server(p2m->domain) )
            ioreq_request_mapcache_invalidate(p2m->domain);
#endif

        p2m_put_page(entry, level, p2mt);

        return;
    }

    mfn = pte_get_mfn(entry);
    ASSERT(mfn_valid(mfn));
    table = map_domain_page(mfn);
    pg = mfn_to_page(mfn);

    for ( i = 0; i < P2M_PAGETABLE_ENTRIES(p2m, level); i++ )
    {
        struct p2m_pte_ctx tmp_ctx = {
            .pt_page = pg,
            .index = i,
            .level = level - 1,
            .p2m = p2m,
        };

        p2m_free_subtree(p2m, table[i], &tmp_ctx);
    }

    unmap_domain_page(table);

    /*
     * Make sure all the references in the TLB have been removed before
     * freing the intermediate page table.
     * XXX: Should we defer the free of the page table to avoid the
     * flush?
     */
    p2m_tlb_flush_sync(p2m);

    p2m_free_table(p2m, pg);
}

static bool p2m_split_superpage(struct p2m_domain *p2m, pte_t *entry,
                                unsigned int level, unsigned int target,
                                const unsigned int *offsets,
                                struct page_info *tbl_pg)
{
    struct page_info *page;
    unsigned long i;
    pte_t pte, *table;
    bool rv = true;

    /* Convenience aliases */
    mfn_t mfn = pte_get_mfn(*entry);
    unsigned int next_level = level - 1;
    unsigned int level_order = P2M_LEVEL_ORDER(next_level);

    struct p2m_pte_ctx p2m_pte_ctx = {
        .p2m = p2m,
        .level = level,
    };

    /* Init with p2m_invalid just to make compiler happy. */
    p2m_type_t old_type = p2m_invalid;

    /*
     * This should only be called with target != level and the entry is
     * a superpage.
     */
    ASSERT(level > target);
    ASSERT(pte_is_superpage(*entry, level));

    page = p2m_alloc_page(p2m);
    if ( !page )
    {
        /*
         * The caller is in charge to free the sub-tree.
         * As we didn't manage to allocate anything, just tell the
         * caller there is nothing to free by invalidating the PTE.
         */
        memset(entry, 0, sizeof(*entry));
        return false;
    }

    table = __map_domain_page(page);

    if ( MASK_EXTR(entry->pte, P2M_TYPE_PTE_BITS_MASK) == p2m_ext_storage )
    {
        p2m_pte_ctx.pt_page = tbl_pg;
        p2m_pte_ctx.index = offsets[level];

        old_type = p2m_get_type(*entry, &p2m_pte_ctx);
    }

    p2m_pte_ctx.pt_page = page;
    p2m_pte_ctx.level = next_level;

    for ( i = 0; i < P2M_PAGETABLE_ENTRIES(p2m, next_level); i++ )
    {
        pte_t *new_entry = table + i;

        /*
         * Use the content of the superpage entry and override
         * the necessary fields. So the correct attributes are kept.
         */
        pte = *entry;
        pte_set_mfn(&pte, mfn_add(mfn, i << level_order));

        if ( MASK_EXTR(pte.pte, P2M_TYPE_PTE_BITS_MASK) == p2m_ext_storage )
        {
            p2m_pte_ctx.index = i;

            p2m_set_type(&pte, old_type, &p2m_pte_ctx);
        }

        write_pte(new_entry, pte);
    }

    /*
     * Shatter superpage in the page to the level we want to make the
     * changes.
     * This is done outside the loop to avoid checking the offset
     * for every entry to know whether the entry should be shattered.
     */
    if ( next_level != target )
        rv = p2m_split_superpage(p2m, table + offsets[next_level],
                                 next_level, target, offsets, page);

    if ( p2m->clean_dcache )
        clean_dcache_va_range(table, PAGE_SIZE);

    /*
     * TODO: an inefficiency here: the caller almost certainly wants to map
     *       the same page again, to update the one entry that caused the
     *       request to shatter the page.
     */
    unmap_domain_page(table);

    /*
     * Even if we failed, we should (according to the current implemetation
     * of a way how sub-tree is freed if p2m_split_superpage hasn't been
     * finished fully) install the newly allocated PTE
     * entry.
     * The caller will be in charge to free the sub-tree.
     */
    p2m_write_pte(entry, page_to_p2m_table(page), p2m->clean_dcache);

    return rv;
}

/* Insert an entry in the p2m. */
static int p2m_set_entry(struct p2m_domain *p2m,
                         gfn_t gfn,
                         unsigned long page_order,
                         mfn_t mfn,
                         p2m_type_t t)
{
    unsigned int level;
    unsigned int target = page_order / PAGETABLE_ORDER;
    pte_t *entry, *table, orig_pte;
    int rc;
    /*
     * A mapping is removed only if the MFN is explicitly set to INVALID_MFN.
     * Other MFNs that are considered invalid by mfn_valid() (e.g., MMIO)
     * are still allowed.
     */
    bool removing_mapping = mfn_eq(mfn, INVALID_MFN);
    struct p2m_pte_ctx tmp_ctx = {
        .p2m = p2m,
    };
    P2M_BUILD_LEVEL_OFFSETS(p2m, offsets, gfn_to_gaddr(gfn));

    ASSERT(p2m_is_write_locked(p2m));

    /*
     * Check if the level target is valid: we only support
     * 4K - 2M - 1G mapping.
     */
    ASSERT(target <= P2M_MAX_SUPPORTED_LEVEL_MAPPING);

    table = p2m_get_root_pointer(p2m, gfn);
    if ( !table )
        return -EINVAL;

    for ( level = P2M_ROOT_LEVEL(p2m); level > target; level-- )
    {
        /*
         * Don't try to allocate intermediate page table if the mapping
         * is about to be removed.
         */
        rc = p2m_next_level(p2m, !removing_mapping,
                            level, &table, offsets[level]);
        if ( (rc == P2M_TABLE_MAP_NONE) || (rc == P2M_TABLE_MAP_NOMEM) )
        {
            rc = (rc == P2M_TABLE_MAP_NONE) ? -ENOENT : -ENOMEM;
            /*
             * We are here because p2m_next_level has failed to map
             * the intermediate page table (e.g the table does not exist
             * and none should be allocated). It is a valid case
             * when removing a mapping as it may not exist in the
             * page table. In this case, just ignore lookup failure.
             */
            rc = removing_mapping ? 0 : rc;
            goto out;
        }

        if ( rc != P2M_TABLE_NORMAL )
            break;
    }

    entry = table + offsets[level];

    /*
     * If we are here with level > target, we must be at a leaf node,
     * and we need to break up the superpage.
     */
    if ( level > target )
    {
        /* We need to split the original page. */
        pte_t split_pte = *entry;
        struct page_info *tbl_pg = mfn_to_page(domain_page_map_to_mfn(table));

        ASSERT(pte_is_superpage(*entry, level));

        if ( !p2m_split_superpage(p2m, &split_pte, level, target, offsets,
                                  tbl_pg) )
        {
            tmp_ctx.pt_page = tbl_pg;
            tmp_ctx.index = offsets[level];
            tmp_ctx.level = level;

            /* Free the allocated sub-tree */
            p2m_free_subtree(p2m, split_pte, &tmp_ctx);

            rc = -ENOMEM;
            goto out;
        }

        p2m_write_pte(entry, split_pte, p2m->clean_dcache);

        p2m->need_flush = true;

        /* Then move to the level we want to make real changes */
        for ( ; level > target; level-- )
        {
            rc = p2m_next_level(p2m, true, level, &table, offsets[level]);

            /*
             * The entry should be found and either be a table
             * or a superpage if level 0 is not targeted
             */
            ASSERT(rc == P2M_TABLE_NORMAL ||
                   (rc == P2M_TABLE_SUPER_PAGE && target > 0));
        }

        entry = table + offsets[level];
    }

    tmp_ctx.pt_page = mfn_to_page(domain_page_map_to_mfn(table));
    tmp_ctx.index = offsets[level];
    tmp_ctx.level = level;

    /*
     * We should always be there with the correct level because all the
     * intermediate tables have been installed if necessary.
     */
    ASSERT(level == target);

    orig_pte = *entry;

    if ( removing_mapping )
        p2m_clean_pte(entry, p2m->clean_dcache);
    else
    {
        pte_t pte = p2m_pte_from_mfn(mfn, t, &tmp_ctx);

        p2m_write_pte(entry, pte, p2m->clean_dcache);

        p2m->max_mapped_gfn = gfn_max(p2m->max_mapped_gfn,
                                      gfn_add(gfn, BIT(page_order, UL) - 1));
        p2m->lowest_mapped_gfn = gfn_min(p2m->lowest_mapped_gfn, gfn);
    }

    p2m->need_flush = true;

    /*
     * Currently, the infrastructure required to enable CONFIG_HAS_PASSTHROUGH
     * is not ready for RISC-V support.
     *
     * When CONFIG_HAS_PASSTHROUGH=y, iommu_iotlb_flush() should be done
     * here.
     */
#ifdef CONFIG_HAS_PASSTHROUGH
#   error "add code to flush IOMMU TLB"
#endif

    rc = 0;

    /*
     * In case of a VALID -> INVALID transition, the original PTE should
     * always be freed.
     *
     * In case of a VALID -> VALID transition, the original PTE should be
     * freed only if the MFNs are different. If the MFNs are the same
     * (i.e., only permissions differ), there is no need to free the
     * original PTE.
     */
    if ( pte_is_valid(orig_pte) &&
         (!pte_is_valid(*entry) ||
          !mfn_eq(pte_get_mfn(*entry), pte_get_mfn(orig_pte))) )
        p2m_free_subtree(p2m, orig_pte, &tmp_ctx);

 out:
    unmap_domain_page(table);

    return rc;
}

/* Return mapping order for given gfn, mfn and nr */
static unsigned long p2m_mapping_order(const struct p2m_domain *p2m, gfn_t gfn,
                                       mfn_t mfn, unsigned long nr)
{
    unsigned long mask;
    /* 1gb, 2mb, 4k mappings are supported */
    unsigned int level = min(P2M_ROOT_LEVEL(p2m), P2M_MAX_SUPPORTED_LEVEL_MAPPING);
    unsigned long order = 0;

    mask = !mfn_eq(mfn, INVALID_MFN) ? mfn_x(mfn) : 0;
    mask |= gfn_x(gfn);

    for ( ; level != 0; level-- )
    {
        if ( !(mask & (BIT(P2M_LEVEL_ORDER(level), UL) - 1)) &&
             (nr >= BIT(P2M_LEVEL_ORDER(level), UL)) )
        {
            order = P2M_LEVEL_ORDER(level);
            break;
        }
    }

    return order;
}

static int p2m_set_range(struct p2m_domain *p2m,
                         gfn_t sgfn,
                         unsigned long nr,
                         mfn_t smfn,
                         p2m_type_t t)
{
    int rc = 0;
    unsigned long left = nr;

    /*
     * Any reference taken by the P2M mappings (e.g. foreign mapping) will
     * be dropped in relinquish_p2m_mapping(). As the P2M will still
     * be accessible after, we need to prevent mapping to be added when the
     * domain is dying.
     */
    if ( unlikely(p2m->domain->is_dying) )
        return -EACCES;

    while ( left )
    {
        unsigned long order = p2m_mapping_order(p2m, sgfn, smfn, left);

        rc = p2m_set_entry(p2m, sgfn, order, smfn, t);
        if ( rc )
            break;

        sgfn = gfn_add(sgfn, BIT(order, UL));
        if ( !mfn_eq(smfn, INVALID_MFN) )
            smfn = mfn_add(smfn, BIT(order, UL));

        left -= BIT(order, UL);
    }

    if ( left > INT_MAX )
        rc = -EOVERFLOW;

    return !left ? rc : left;
}

int map_regions_p2mt(struct domain *d,
                     gfn_t gfn,
                     unsigned long nr,
                     mfn_t mfn,
                     p2m_type_t p2mt)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc;

    p2m_write_lock(p2m);
    rc = p2m_set_range(p2m, gfn, nr, mfn, p2mt);
    p2m_write_unlock(p2m);

    return rc;
}

/*
 * p2m_get_entry() should always return the correct order value, even if an
 * entry is not present (i.e. the GFN is outside the range):
 *   [p2m->lowest_mapped_gfn, p2m->max_mapped_gfn]    (1)
 *
 * This ensures that callers of p2m_get_entry() can determine what range of
 * address space would be altered by a corresponding p2m_set_entry().
 * Also, it would help to avoid costly page walks for GFNs outside range (1).
 *
 * Therefore, this function returns true for GFNs outside range (1), and in
 * that case the corresponding level is returned via the level_out argument.
 * Otherwise, it returns false and p2m_get_entry() performs a page walk to
 * find the proper entry.
 */
static bool check_outside_boundary(const struct p2m_domain *p2m, gfn_t gfn,
                                   gfn_t boundary, bool is_lower,
                                   unsigned int *level_out)
{
    unsigned int level = P2M_MAX_ROOT_LEVEL + 1;
    bool ret = false;

    ASSERT(p2m);

    if ( is_lower ? gfn_x(gfn) < gfn_x(boundary)
                  : gfn_x(gfn) > gfn_x(boundary) )
    {
        for ( level = P2M_ROOT_LEVEL(p2m) ; level; level-- )
        {
            unsigned long mask = BIT(P2M_GFN_LEVEL_SHIFT(level), UL) - 1;

            if ( is_lower ? (gfn_x(gfn) | mask) < gfn_x(boundary)
                          : (gfn_x(gfn) & ~mask) > gfn_x(boundary) )
                break;
        }

        ret = true;
    }

    if ( level_out )
        *level_out = level;

    return ret;
}

/*
 * Get the details of a given gfn.
 *
 * If the entry is present, the associated MFN, the p2m type of the mapping,
 * and the page order of the mapping in the page table (i.e., it could be a
 * superpage) will be returned.
 *
 * If the entry is not present, INVALID_MFN will be returned, page_order will
 * be set according to the order of the invalid range, and the type will be
 * p2m_invalid.
 */
static mfn_t p2m_get_entry(struct p2m_domain *p2m, gfn_t gfn,
                           p2m_type_t *t,
                           unsigned int *page_order)
{
    unsigned int level = P2M_ROOT_LEVEL(p2m);
    unsigned int gfn_limit_bits =
        P2M_LEVEL_ORDER(level + 1) + P2M_ROOT_EXTRA_BITS(p2m, level);
    pte_t entry, *table;
    int rc;
    mfn_t mfn = INVALID_MFN;

    P2M_BUILD_LEVEL_OFFSETS(p2m, offsets, gfn_to_gaddr(gfn));

    ASSERT(p2m_is_locked(p2m));

    *t = p2m_invalid;

    if ( gfn_x(gfn) > (BIT(gfn_limit_bits, UL) - 1) )
    {
        if ( page_order )
            *page_order = gfn_limit_bits;

        return mfn;
    }

    if ( check_outside_boundary(p2m, gfn, p2m->lowest_mapped_gfn, true,
                                &level) )
        goto out;

    if ( check_outside_boundary(p2m, gfn, p2m->max_mapped_gfn, false, &level) )
        goto out;

    table = p2m_get_root_pointer(p2m, gfn);

    /*
     * The table should always be non-NULL because the gfn is below
     * p2m->max_mapped_gfn and the root table pages are always present.
     */
    if ( !table )
    {
        ASSERT_UNREACHABLE();
        goto out;
    }

    for ( level = P2M_ROOT_LEVEL(p2m); level; level-- )
    {
        rc = p2m_next_level(p2m, false, level, &table, offsets[level]);
        if ( rc == P2M_TABLE_MAP_NONE )
            goto out_unmap;

        if ( rc != P2M_TABLE_NORMAL )
            break;
    }

    entry = table[offsets[level]];

    if ( pte_is_valid(entry) )
    {
        struct p2m_pte_ctx p2m_pte_ctx = {
            .pt_page = mfn_to_page(domain_page_map_to_mfn(table)),
            .index = offsets[level],
            .level = level,
            .p2m = p2m,
        };

        *t = p2m_get_type(entry, &p2m_pte_ctx);

        mfn = pte_get_mfn(entry);

        ASSERT(!(mfn_x(mfn) & (BIT(P2M_LEVEL_ORDER(level), UL) - 1)));

        /*
         * The entry may point to a superpage. Find the MFN associated
         * to the GFN.
         */
        mfn = mfn_add(mfn,
                      gfn_x(gfn) & (BIT(P2M_LEVEL_ORDER(level), UL) - 1));
    }

 out_unmap:
    unmap_domain_page(table);

 out:
    if ( page_order )
        *page_order = P2M_LEVEL_ORDER(level);

    return mfn;
}

struct page_info *p2m_get_page_from_gfn(struct p2m_domain *p2m, gfn_t gfn,
                                        p2m_type_t *t)
{
    struct page_info *page;
    p2m_type_t p2mt;
    mfn_t mfn;

    p2m_read_lock(p2m);
    mfn = p2m_get_entry(p2m, gfn, &p2mt, NULL);

    if ( t )
        *t = p2mt;

    if ( !mfn_valid(mfn) )
    {
        p2m_read_unlock(p2m);
        return NULL;
    }

    page = mfn_to_page(mfn);

    /*
     * get_page won't work on foreign mapping because the page doesn't
     * belong to the current domain.
     */
    if ( unlikely(p2m_is_foreign(p2mt)) )
    {
        const struct domain *fdom = page_get_owner_and_reference(page);

        p2m_read_unlock(p2m);

        if ( fdom )
        {
            if ( likely(fdom != p2m->domain) )
                return page;

            ASSERT_UNREACHABLE();
            put_page(page);
        }

        return NULL;
    }

    p2m_read_unlock(p2m);

    return get_page(page, p2m->domain) ? page : NULL;
}
