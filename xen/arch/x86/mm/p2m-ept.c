/*
 * ept-p2m.c: use the EPT page table as p2m
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/paging.h>
#include <asm/types.h>
#include <asm/domain.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <xen/iommu.h>
#include <asm/mtrr.h>
#include <asm/hvm/cacheattr.h>
#include <xen/keyhandler.h>
#include <xen/softirq.h>

#include "mm-locks.h"

#define atomic_read_ept_entry(__pepte)                              \
    ( (ept_entry_t) { .epte = read_atomic(&(__pepte)->epte) } )
#define atomic_write_ept_entry(__pepte, __epte)                     \
    write_atomic(&(__pepte)->epte, (__epte).epte)

#define is_epte_present(ept_entry)      ((ept_entry)->epte & 0x7)
#define is_epte_superpage(ept_entry)    ((ept_entry)->sp)
static inline bool_t is_epte_valid(ept_entry_t *e)
{
    return (e->epte != 0 && e->sa_p2mt != p2m_invalid);
}

/* Non-ept "lock-and-check" wrapper */
static int ept_pod_check_and_populate(struct p2m_domain *p2m, unsigned long gfn,
                                      ept_entry_t *entry, int order,
                                      p2m_query_t q)
{
    int r;

    /* This is called from the p2m lookups, which can happen with or 
     * without the lock hed. */
    p2m_lock_recursive(p2m);

    /* Check to make sure this is still PoD */
    if ( entry->sa_p2mt != p2m_populate_on_demand )
    {
        p2m_unlock(p2m);
        return 0;
    }

    r = p2m_pod_demand_populate(p2m, gfn, order, q);

    p2m_unlock(p2m);

    return r;
}

static void ept_p2m_type_to_flags(ept_entry_t *entry, p2m_type_t type, p2m_access_t access)
{
    /* First apply type permissions */
    switch(type)
    {
        case p2m_invalid:
        case p2m_mmio_dm:
        case p2m_populate_on_demand:
        case p2m_ram_paging_out:
        case p2m_ram_paged:
        case p2m_ram_paging_in:
        default:
            entry->r = entry->w = entry->x = 0;
            break;
        case p2m_ram_rw:
            entry->r = entry->w = entry->x = 1;
            break;
        case p2m_mmio_direct:
            entry->r = entry->x = 1;
            entry->w = !rangeset_contains_singleton(mmio_ro_ranges,
                                                    entry->mfn);
            break;
        case p2m_ram_logdirty:
        case p2m_ram_ro:
        case p2m_ram_shared:
            entry->r = entry->x = 1;
            entry->w = 0;
            break;
        case p2m_grant_map_rw:
            entry->r = entry->w = 1;
            entry->x = 0;
            break;
        case p2m_grant_map_ro:
            entry->r = 1;
            entry->w = entry->x = 0;
            break;
    }


    /* Then restrict with access permissions */
    switch (access) 
    {
        case p2m_access_n:
        case p2m_access_n2rwx:
            entry->r = entry->w = entry->x = 0;
            break;
        case p2m_access_r:
            entry->w = entry->x = 0;
            break;
        case p2m_access_w:
            entry->r = entry->x = 0;
            break;
        case p2m_access_x:
            entry->r = entry->w = 0;
            break;
        case p2m_access_rx:
        case p2m_access_rx2rw:
            entry->w = 0;
            break;
        case p2m_access_wx:
            entry->r = 0;
            break;
        case p2m_access_rw:
            entry->x = 0;
            break;           
        case p2m_access_rwx:
            break;
    }
    
}

#define GUEST_TABLE_MAP_FAILED  0
#define GUEST_TABLE_NORMAL_PAGE 1
#define GUEST_TABLE_SUPER_PAGE  2
#define GUEST_TABLE_POD_PAGE    3

/* Fill in middle levels of ept table */
static int ept_set_middle_entry(struct p2m_domain *p2m, ept_entry_t *ept_entry)
{
    struct page_info *pg;

    pg = p2m_alloc_ptp(p2m, 0);
    if ( pg == NULL )
        return 0;

    ept_entry->epte = 0;
    ept_entry->mfn = page_to_mfn(pg);
    ept_entry->access = p2m->default_access;

    ept_entry->r = ept_entry->w = ept_entry->x = 1;

    return 1;
}

/* free ept sub tree behind an entry */
static void ept_free_entry(struct p2m_domain *p2m, ept_entry_t *ept_entry, int level)
{
    /* End if the entry is a leaf entry. */
    if ( level == 0 || !is_epte_present(ept_entry) ||
         is_epte_superpage(ept_entry) )
        return;

    if ( level > 1 )
    {
        ept_entry_t *epte = map_domain_page(ept_entry->mfn);
        for ( int i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
            ept_free_entry(p2m, epte + i, level - 1);
        unmap_domain_page(epte);
    }
    
    p2m_free_ptp(p2m, mfn_to_page(ept_entry->mfn));
}

static int ept_split_super_page(struct p2m_domain *p2m, ept_entry_t *ept_entry,
                                int level, int target)
{
    ept_entry_t new_ept, *table;
    uint64_t trunk;
    int rv = 1;

    /* End if the entry is a leaf entry or reaches the target level. */
    if ( level == 0 || level == target )
        return rv;

    ASSERT(is_epte_superpage(ept_entry));

    if ( !ept_set_middle_entry(p2m, &new_ept) )
        return 0;

    table = map_domain_page(new_ept.mfn);
    trunk = 1UL << ((level - 1) * EPT_TABLE_ORDER);

    for ( int i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
    {
        ept_entry_t *epte = table + i;

        epte->epte = 0;
        epte->emt = ept_entry->emt;
        epte->ipat = ept_entry->ipat;
        epte->sp = (level > 1) ? 1 : 0;
        epte->access = ept_entry->access;
        epte->sa_p2mt = ept_entry->sa_p2mt;
        epte->mfn = ept_entry->mfn + i * trunk;
        epte->rsvd2_snp = ( iommu_enabled && iommu_snoop ) ? 1 : 0;

        ept_p2m_type_to_flags(epte, epte->sa_p2mt, epte->access);

        if ( (level - 1) == target )
            continue;

        ASSERT(is_epte_superpage(epte));

        if ( !(rv = ept_split_super_page(p2m, epte, level - 1, target)) )
            break;
    }

    unmap_domain_page(table);

    /* Even failed we should install the newly allocated ept page. */
    *ept_entry = new_ept;

    return rv;
}

/* Take the currently mapped table, find the corresponding gfn entry,
 * and map the next table, if available.  If the entry is empty
 * and read_only is set, 
 * Return values:
 *  0: Failed to map.  Either read_only was set and the entry was
 *   empty, or allocating a new page failed.
 *  GUEST_TABLE_NORMAL_PAGE: next level mapped normally
 *  GUEST_TABLE_SUPER_PAGE:
 *   The next entry points to a superpage, and caller indicates
 *   that they are going to the superpage level, or are only doing
 *   a read.
 *  GUEST_TABLE_POD:
 *   The next entry is marked populate-on-demand.
 */
static int ept_next_level(struct p2m_domain *p2m, bool_t read_only,
                          ept_entry_t **table, unsigned long *gfn_remainder,
                          int next_level)
{
    unsigned long mfn;
    ept_entry_t *ept_entry, e;
    u32 shift, index;

    shift = next_level * EPT_TABLE_ORDER;

    index = *gfn_remainder >> shift;

    /* index must be falling into the page */
    ASSERT(index < EPT_PAGETABLE_ENTRIES);

    ept_entry = (*table) + index;

    /* ept_next_level() is called (sometimes) without a lock.  Read
     * the entry once, and act on the "cached" entry after that to
     * avoid races. */
    e = atomic_read_ept_entry(ept_entry);

    if ( !is_epte_present(&e) )
    {
        if ( e.sa_p2mt == p2m_populate_on_demand )
            return GUEST_TABLE_POD_PAGE;

        if ( read_only )
            return GUEST_TABLE_MAP_FAILED;

        if ( !ept_set_middle_entry(p2m, ept_entry) )
            return GUEST_TABLE_MAP_FAILED;
        else
            e = atomic_read_ept_entry(ept_entry); /* Refresh */
    }

    /* The only time sp would be set here is if we had hit a superpage */
    if ( is_epte_superpage(&e) )
        return GUEST_TABLE_SUPER_PAGE;

    mfn = e.mfn;
    unmap_domain_page(*table);
    *table = map_domain_page(mfn);
    *gfn_remainder &= (1UL << shift) - 1;
    return GUEST_TABLE_NORMAL_PAGE;
}

/*
 * ept_set_entry() computes 'need_modify_vtd_table' for itself,
 * by observing whether any gfn->mfn translations are modified.
 */
static int
ept_set_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
              unsigned int order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    ept_entry_t *table, *ept_entry = NULL;
    unsigned long gfn_remainder = gfn;
    unsigned long offset = 0;
    u32 index;
    int i, target = order / EPT_TABLE_ORDER;
    int rv = 0;
    int ret = 0;
    bool_t direct_mmio = (p2mt == p2m_mmio_direct);
    uint8_t ipat = 0;
    int need_modify_vtd_table = 1;
    int vtd_pte_present = 0;
    int needs_sync = 1;
    struct domain *d = p2m->domain;
    ept_entry_t old_entry = { .epte = 0 };

    /*
     * the caller must make sure:
     * 1. passing valid gfn and mfn at order boundary.
     * 2. gfn not exceeding guest physical address width.
     * 3. passing a valid order.
     */
    if ( ((gfn | mfn_x(mfn)) & ((1UL << order) - 1)) ||
         ((u64)gfn >> ((ept_get_wl(d) + 1) * EPT_TABLE_ORDER)) ||
         (order % EPT_TABLE_ORDER) )
        return 0;

    ASSERT((target == 2 && hvm_hap_has_1gb(d)) ||
           (target == 1 && hvm_hap_has_2mb(d)) ||
           (target == 0));

    table = map_domain_page(ept_get_asr(d));

    for ( i = ept_get_wl(d); i > target; i-- )
    {
        ret = ept_next_level(p2m, 0, &table, &gfn_remainder, i);
        if ( !ret )
            goto out;
        else if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    ASSERT(ret != GUEST_TABLE_POD_PAGE || i != target);

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    offset = gfn_remainder & ((1UL << (i * EPT_TABLE_ORDER)) - 1);

    ept_entry = table + index;

    /* In case VT-d uses same page table, this flag is needed by VT-d */ 
    vtd_pte_present = is_epte_present(ept_entry) ? 1 : 0;

    /*
     * If we're here with i > target, we must be at a leaf node, and
     * we need to break up the superpage.
     *
     * If we're here with i == target and i > 0, we need to check to see
     * if we're replacing a non-leaf entry (i.e., pointing to an N-1 table)
     * with a leaf entry (a 1GiB or 2MiB page), and handle things appropriately.
     */

    if ( i == target )
    {
        /* We reached the target level. */
        ept_entry_t new_entry = { .epte = 0 };

        /* No need to flush if the old entry wasn't valid */
        if ( !is_epte_present(ept_entry) )
            needs_sync = 0;

        /* If we're replacing a non-leaf entry with a leaf entry (1GiB or 2MiB),
         * the intermediate tables will be freed below after the ept flush
         *
         * Read-then-write is OK because we hold the p2m lock. */
        old_entry = *ept_entry;

        if ( mfn_valid(mfn_x(mfn)) || direct_mmio || p2m_is_paged(p2mt) ||
             (p2mt == p2m_ram_paging_in) )
        {
            /* Construct the new entry, and then write it once */
            new_entry.emt = epte_get_entry_emt(p2m->domain, gfn, mfn, &ipat,
                                                direct_mmio);

            new_entry.ipat = ipat;
            new_entry.sp = order ? 1 : 0;
            new_entry.sa_p2mt = p2mt;
            new_entry.access = p2ma;
            new_entry.rsvd2_snp = (iommu_enabled && iommu_snoop);

            new_entry.mfn = mfn_x(mfn);

            if ( old_entry.mfn == new_entry.mfn )
                need_modify_vtd_table = 0;

            ept_p2m_type_to_flags(&new_entry, p2mt, p2ma);
        }

        atomic_write_ept_entry(ept_entry, new_entry);
    }
    else
    {
        /* We need to split the original page. */
        ept_entry_t split_ept_entry;
        ept_entry_t new_entry = { .epte = 0 };

        ASSERT(is_epte_superpage(ept_entry));

        split_ept_entry = atomic_read_ept_entry(ept_entry);

        if ( !ept_split_super_page(p2m, &split_ept_entry, i, target) )
        {
            ept_free_entry(p2m, &split_ept_entry, i);
            goto out;
        }

        /* now install the newly split ept sub-tree */
        /* NB: please make sure domian is paused and no in-fly VT-d DMA. */
        atomic_write_ept_entry(ept_entry, split_ept_entry);

        /* then move to the level we want to make real changes */
        for ( ; i > target; i-- )
            ept_next_level(p2m, 0, &table, &gfn_remainder, i);

        ASSERT(i == target);

        index = gfn_remainder >> (i * EPT_TABLE_ORDER);
        offset = gfn_remainder & ((1UL << (i * EPT_TABLE_ORDER)) - 1);

        ept_entry = table + index;

        new_entry.emt = epte_get_entry_emt(d, gfn, mfn, &ipat, direct_mmio);
        new_entry.ipat = ipat;
        new_entry.sp = i ? 1 : 0;
        new_entry.sa_p2mt = p2mt;
        new_entry.access = p2ma;
        new_entry.rsvd2_snp = (iommu_enabled && iommu_snoop);

        /* the caller should take care of the previous page */
        new_entry.mfn = mfn_x(mfn);

        /* Safe to read-then-write because we hold the p2m lock */
        if ( ept_entry->mfn == new_entry.mfn )
             need_modify_vtd_table = 0;

        ept_p2m_type_to_flags(&new_entry, p2mt, p2ma);

        atomic_write_ept_entry(ept_entry, new_entry);
    }

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( mfn_valid(mfn_x(mfn)) &&
         (gfn + (1UL << order) - 1 > p2m->max_mapped_pfn) )
        p2m->max_mapped_pfn = gfn + (1UL << order) - 1;

    /* Success */
    rv = 1;

out:
    unmap_domain_page(table);

    if ( needs_sync )
        ept_sync_domain(p2m->domain);

    if ( rv && iommu_enabled && need_iommu(p2m->domain) && need_modify_vtd_table )
    {
        if ( iommu_hap_pt_share )
            iommu_pte_flush(d, gfn, (u64*)ept_entry, order, vtd_pte_present);
        else
        {
            if ( p2mt == p2m_ram_rw )
            {
                if ( order > 0 )
                {
                    for ( i = 0; i < (1 << order); i++ )
                        iommu_map_page(
                            p2m->domain, gfn - offset + i, mfn_x(mfn) - offset + i,
                            IOMMUF_readable | IOMMUF_writable);
                }
                else if ( !order )
                    iommu_map_page(
                        p2m->domain, gfn, mfn_x(mfn), IOMMUF_readable | IOMMUF_writable);
            }
            else
            {
                if ( order > 0 )
                {
                    for ( i = 0; i < (1 << order); i++ )
                        iommu_unmap_page(p2m->domain, gfn - offset + i);
                }
                else if ( !order )
                    iommu_unmap_page(p2m->domain, gfn);
            }
        }
    }

    /* Release the old intermediate tables, if any.  This has to be the
       last thing we do, after the ept_sync_domain() and removal
       from the iommu tables, so as to avoid a potential
       use-after-free. */
    if ( is_epte_present(&old_entry) )
        ept_free_entry(p2m, &old_entry, target);

    return rv;
}

/* Read ept p2m entries */
static mfn_t ept_get_entry(struct p2m_domain *p2m,
                           unsigned long gfn, p2m_type_t *t, p2m_access_t* a,
                           p2m_query_t q, unsigned int *page_order)
{
    struct domain *d = p2m->domain;
    ept_entry_t *table = map_domain_page(ept_get_asr(d));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    u32 index;
    int i;
    int ret = 0;
    mfn_t mfn = _mfn(INVALID_MFN);

    *t = p2m_mmio_dm;
    *a = p2m_access_n;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
        goto out;

    /* Should check if gfn obeys GAW here. */

    for ( i = ept_get_wl(d); i > 0; i-- )
    {
    retry:
        ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
        if ( !ret )
            goto out;
        else if ( ret == GUEST_TABLE_POD_PAGE )
        {
            if ( q == p2m_query )
            {
                *t = p2m_populate_on_demand;
                goto out;
            }

            /* Populate this superpage */
            ASSERT(i == 1);

            index = gfn_remainder >> ( i * EPT_TABLE_ORDER);
            ept_entry = table + index;

            if ( !ept_pod_check_and_populate(p2m, gfn,
                                             ept_entry, 9, q) )
                goto retry;
            else
                goto out;
        }
        else if ( ret == GUEST_TABLE_SUPER_PAGE )
            break;
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    ept_entry = table + index;

    if ( ept_entry->sa_p2mt == p2m_populate_on_demand )
    {
        if ( q == p2m_query )
        {
            *t = p2m_populate_on_demand;
            goto out;
        }

        ASSERT(i == 0);
        
        if ( ept_pod_check_and_populate(p2m, gfn,
                                        ept_entry, 0, q) )
            goto out;
    }

    /* Need to check for all-zeroes because typecode 0 is p2m_ram and an
     * entirely empty entry shouldn't have RAM type. */
    if ( ept_entry->epte != 0 && ept_entry->sa_p2mt != p2m_invalid )
    {
        *t = ept_entry->sa_p2mt;
        *a = ept_entry->access;

        mfn = _mfn(ept_entry->mfn);
        if ( i )
        {
            /* 
             * We may meet super pages, and to split into 4k pages
             * to emulate p2m table
             */
            unsigned long split_mfn = mfn_x(mfn) +
                (gfn_remainder &
                 ((1 << (i * EPT_TABLE_ORDER)) - 1));
            mfn = _mfn(split_mfn);
        }

        if ( page_order )
            *page_order = i * EPT_TABLE_ORDER;
    }

out:
    unmap_domain_page(table);
    return mfn;
}

/* WARNING: Only caller doesn't care about PoD pages.  So this function will
 * always return 0 for PoD pages, not populate them.  If that becomes necessary,
 * pass a p2m_query_t type along to distinguish. */
static ept_entry_t ept_get_entry_content(struct p2m_domain *p2m,
    unsigned long gfn, int *level)
{
    ept_entry_t *table = map_domain_page(ept_get_asr(p2m->domain));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    ept_entry_t content = { .epte = 0 };
    u32 index;
    int i;
    int ret=0;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
        goto out;

    for ( i = ept_get_wl(p2m->domain); i > 0; i-- )
    {
        ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
        if ( !ret || ret == GUEST_TABLE_POD_PAGE )
            goto out;
        else if ( ret == GUEST_TABLE_SUPER_PAGE )
            break;
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    ept_entry = table + index;
    content = *ept_entry;
    *level = i;

 out:
    unmap_domain_page(table);
    return content;
}

void ept_walk_table(struct domain *d, unsigned long gfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    ept_entry_t *table = map_domain_page(ept_get_asr(d));
    unsigned long gfn_remainder = gfn;

    int i;

    gdprintk(XENLOG_ERR, "Walking EPT tables for domain %d gfn %lx\n",
           d->domain_id, gfn);

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
    {
        gdprintk(XENLOG_ERR, " gfn exceeds max_mapped_pfn %lx\n",
               p2m->max_mapped_pfn);
        goto out;
    }

    for ( i = ept_get_wl(d); i >= 0; i-- )
    {
        ept_entry_t *ept_entry, *next;
        u32 index;

        /* Stolen from ept_next_level */
        index = gfn_remainder >> (i*EPT_TABLE_ORDER);
        ept_entry = table + index;

        gdprintk(XENLOG_ERR, " epte %"PRIx64"\n", ept_entry->epte);

        if ( (i == 0) || !is_epte_present(ept_entry) ||
             is_epte_superpage(ept_entry) )
            goto out;
        else
        {
            gfn_remainder &= (1UL << (i*EPT_TABLE_ORDER)) - 1;

            next = map_domain_page(ept_entry->mfn);

            unmap_domain_page(table);

            table = next;
        }
    }

out:
    unmap_domain_page(table);
    return;
}

/*
 * To test if the new emt type is the same with old,
 * return 1 to not to reset ept entry.
 */
static int need_modify_ept_entry(struct p2m_domain *p2m, unsigned long gfn,
                                 mfn_t mfn, uint8_t o_ipat, uint8_t o_emt,
                                 p2m_type_t p2mt)
{
    uint8_t ipat;
    uint8_t emt;
    bool_t direct_mmio = (p2mt == p2m_mmio_direct);

    emt = epte_get_entry_emt(p2m->domain, gfn, mfn, &ipat, direct_mmio);

    if ( (emt == o_emt) && (ipat == o_ipat) )
        return 0;

    return 1;
}

void ept_change_entry_emt_with_range(struct domain *d,
                                     unsigned long start_gfn,
                                     unsigned long end_gfn)
{
    unsigned long gfn;
    ept_entry_t e;
    mfn_t mfn;
    int order = 0;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_lock(p2m);
    for ( gfn = start_gfn; gfn <= end_gfn; gfn++ )
    {
        int level = 0;
        uint64_t trunk = 0;

        e = ept_get_entry_content(p2m, gfn, &level);
        if ( !is_epte_present(&e) || !p2m_has_emt(e.sa_p2mt) )
            continue;

        order = 0;
        mfn = _mfn(e.mfn);

        if ( is_epte_superpage(&e) )
        {
            while ( level )
            {
                trunk = (1UL << (level * EPT_TABLE_ORDER)) - 1;
                if ( !(gfn & trunk) && (gfn + trunk <= end_gfn) )
                {
                    /* gfn assigned with 2M or 1G, and the end covers more than
                     * the super page areas.
                     * Set emt for super page.
                     */
                    order = level * EPT_TABLE_ORDER;
                    if ( need_modify_ept_entry(p2m, gfn, mfn, 
                          e.ipat, e.emt, e.sa_p2mt) )
                        ept_set_entry(p2m, gfn, mfn, order, e.sa_p2mt, e.access);
                    gfn += trunk;
                    break;
                }
                level--;
             }
        }
        else /* gfn assigned with 4k */
        {
            if ( need_modify_ept_entry(p2m, gfn, mfn, e.ipat, e.emt, e.sa_p2mt) )
                ept_set_entry(p2m, gfn, mfn, order, e.sa_p2mt, e.access);
        }
    }
    p2m_unlock(p2m);
}

/*
 * Walk the whole p2m table, changing any entries of the old type
 * to the new type.  This is used in hardware-assisted paging to
 * quickly enable or diable log-dirty tracking
 */
static void ept_change_entry_type_page(mfn_t ept_page_mfn, int ept_page_level,
                                       p2m_type_t ot, p2m_type_t nt)
{
    ept_entry_t e, *epte = map_domain_page(mfn_x(ept_page_mfn));

    for ( int i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
    {
        if ( !is_epte_valid(epte + i) )
            continue;

        if ( (ept_page_level > 0) && !is_epte_superpage(epte + i) )
            ept_change_entry_type_page(_mfn(epte[i].mfn),
                                       ept_page_level - 1, ot, nt);
        else
        {
            e = atomic_read_ept_entry(&epte[i]);
            if ( e.sa_p2mt != ot )
                continue;

            e.sa_p2mt = nt;
            ept_p2m_type_to_flags(&e, nt, e.access);
            atomic_write_ept_entry(&epte[i], e);
        }
    }

    unmap_domain_page(epte);
}

static void ept_change_entry_type_global(struct p2m_domain *p2m,
                                         p2m_type_t ot, p2m_type_t nt)
{
    struct domain *d = p2m->domain;
    if ( ept_get_asr(d) == 0 )
        return;

    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));
    BUG_ON(ot != nt && (ot == p2m_mmio_direct || nt == p2m_mmio_direct));

    ept_change_entry_type_page(_mfn(ept_get_asr(d)), ept_get_wl(d), ot, nt);

    ept_sync_domain(d);
}

void ept_p2m_init(struct p2m_domain *p2m)
{
    p2m->set_entry = ept_set_entry;
    p2m->get_entry = ept_get_entry;
    p2m->change_entry_type_global = ept_change_entry_type_global;
    p2m->audit_p2m = NULL;
}

static void ept_dump_p2m_table(unsigned char key)
{
    struct domain *d;
    ept_entry_t *table, *ept_entry;
    mfn_t mfn;
    int order;
    int i;
    int is_pod;
    int ret = 0;
    unsigned long index;
    unsigned long gfn, gfn_remainder;
    unsigned long record_counter = 0;
    struct p2m_domain *p2m;

    for_each_domain(d)
    {
        if ( !hap_enabled(d) )
            continue;

        p2m = p2m_get_hostp2m(d);
        printk("\ndomain%d EPT p2m table: \n", d->domain_id);

        for ( gfn = 0; gfn <= p2m->max_mapped_pfn; gfn += (1 << order) )
        {
            gfn_remainder = gfn;
            mfn = _mfn(INVALID_MFN);
            table = map_domain_page(ept_get_asr(d));

            for ( i = ept_get_wl(d); i > 0; i-- )
            {
                ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
                if ( ret != GUEST_TABLE_NORMAL_PAGE )
                    break;
            }

            order = i * EPT_TABLE_ORDER;

            if ( ret == GUEST_TABLE_MAP_FAILED )
                goto out;

            index = gfn_remainder >> order;
            ept_entry = table + index;
            if ( ept_entry->sa_p2mt != p2m_invalid )
            {
                ( ept_entry->sa_p2mt == p2m_populate_on_demand ) ? 
                ( mfn = _mfn(INVALID_MFN), is_pod = 1 ) :
                ( mfn = _mfn(ept_entry->mfn), is_pod = 0 );

                printk("gfn: %-16lx  mfn: %-16lx  order: %2d  is_pod: %d\n",
                       gfn, mfn_x(mfn), order, is_pod);

                if ( !(record_counter++ % 100) )
                    process_pending_softirqs();
            }
out:
            unmap_domain_page(table);
        }
    }
}

static struct keyhandler ept_p2m_table = {
    .diagnostic = 0,
    .u.fn = ept_dump_p2m_table,
    .desc = "dump ept p2m table"
};

void setup_ept_dump(void)
{
    register_keyhandler('D', &ept_p2m_table);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
