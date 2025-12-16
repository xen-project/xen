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

#include <asm/csr.h>
#include <asm/flushtlb.h>
#include <asm/p2m.h>
#include <asm/paging.h>
#include <asm/riscv_encoding.h>
#include <asm/vmid.h>

static struct gstage_mode_desc __ro_after_init max_gstage_mode = {
    .mode = HGATP_MODE_OFF,
    .paging_levels = 0,
    .name = "Bare",
};

unsigned char get_max_supported_mode(void)
{
    return max_gstage_mode.mode;
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
