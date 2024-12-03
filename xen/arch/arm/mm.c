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
#include <xen/mm.h>

#include <xsm/xsm.h>

#include <public/memory.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

unsigned long frametable_base_pdx __read_mostly;

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

    nrspin_lock(&d->page_alloc_lock);

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

    nrspin_unlock(&d->page_alloc_lock);
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

    ASSERT_UNREACHABLE();
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
