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

/* Non-ept "lock-and-check" wrapper */
static int ept_pod_check_and_populate(struct domain *d, unsigned long gfn,
                                      ept_entry_t *entry, int order,
                                      p2m_query_t q)
{
    int r;
    p2m_lock(d->arch.p2m);

    /* Check to make sure this is still PoD */
    if ( entry->avail1 != p2m_populate_on_demand )
    {
        p2m_unlock(d->arch.p2m);
        return 0;
    }

    r = p2m_pod_demand_populate(d, gfn, order, q);

    p2m_unlock(d->arch.p2m);

    return r;
}

static void ept_p2m_type_to_flags(ept_entry_t *entry, p2m_type_t type)
{
    switch(type)
    {
        case p2m_invalid:
        case p2m_mmio_dm:
        case p2m_populate_on_demand:
        case p2m_ram_paging_out:
        case p2m_ram_paged:
        case p2m_ram_paging_in:
        case p2m_ram_paging_in_start:
        default:
            entry->r = entry->w = entry->x = 0;
            return;
        case p2m_ram_rw:
        case p2m_mmio_direct:
            entry->r = entry->w = entry->x = 1;
            return;
        case p2m_ram_logdirty:
        case p2m_ram_ro:
        case p2m_ram_shared:
            entry->r = entry->x = 1;
            entry->w = 0;
            return;
        case p2m_grant_map_rw:
            entry->r = entry->w = 1;
            entry->x = 0;
            return;
        case p2m_grant_map_ro:
            entry->r = 1;
            entry->w = entry->x = 0;
            return;
    }
}

#define GUEST_TABLE_MAP_FAILED  0
#define GUEST_TABLE_NORMAL_PAGE 1
#define GUEST_TABLE_SUPER_PAGE  2
#define GUEST_TABLE_POD_PAGE    3

/* Fill in middle levels of ept table */
static int ept_set_middle_entry(struct domain *d, ept_entry_t *ept_entry)
{
    struct page_info *pg;

    pg = p2m_alloc_ptp(d, 0);
    if ( pg == NULL )
        return 0;

    ept_entry->emt = 0;
    ept_entry->ipat = 0;
    ept_entry->sp_avail = 0;
    ept_entry->avail1 = 0;
    ept_entry->mfn = page_to_mfn(pg);
    ept_entry->avail2 = 0;

    ept_entry->r = ept_entry->w = ept_entry->x = 1;

    return 1;
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
static int ept_next_level(struct domain *d, bool_t read_only,
                          ept_entry_t **table, unsigned long *gfn_remainder,
                          u32 shift)
{
    ept_entry_t *ept_entry;
    ept_entry_t *next;
    u32 index;

    index = *gfn_remainder >> shift;

    ept_entry = (*table) + index;

    if ( !(ept_entry->epte & 0x7) )
    {
        if ( ept_entry->avail1 == p2m_populate_on_demand )
            return GUEST_TABLE_POD_PAGE;

        if ( read_only )
            return GUEST_TABLE_MAP_FAILED;

        if ( !ept_set_middle_entry(d, ept_entry) )
            return GUEST_TABLE_MAP_FAILED;
    }

    /* The only time sp_avail would be set here is if we had hit a superpage */
    if ( ept_entry->sp_avail )
        return GUEST_TABLE_SUPER_PAGE;
    else
    {
        *gfn_remainder &= (1UL << shift) - 1;
        next = map_domain_page(ept_entry->mfn);
        unmap_domain_page(*table);
        *table = next;
        return GUEST_TABLE_NORMAL_PAGE;
    }
}

/* It's super page before and we should break down it now. */
static int ept_split_large_page(struct domain *d,
                                ept_entry_t **table, u32 *index,
                                unsigned long gfn, int level)
{
    ept_entry_t *prev_table = *table;
    ept_entry_t *split_table = NULL;
    ept_entry_t *split_entry = NULL;
    ept_entry_t *ept_entry = (*table) + (*index);
    ept_entry_t temp_ept_entry;
    unsigned long s_gfn, s_mfn;
    unsigned long offset, trunk;
    int i;

    /* alloc new page for new ept middle level entry which is
     * before a leaf super entry
     */

    if ( !ept_set_middle_entry(d, &temp_ept_entry) )
        return 0;

    /* split the super page to small next level pages */
    split_table = map_domain_page(temp_ept_entry.mfn);
    offset = gfn & ((1UL << (level * EPT_TABLE_ORDER)) - 1);
    trunk = (1UL << ((level-1) * EPT_TABLE_ORDER));

    for ( i = 0; i < (1UL << EPT_TABLE_ORDER); i++ )
    {
        s_gfn = gfn - offset + i * trunk;
        s_mfn = ept_entry->mfn + i * trunk;

        split_entry = split_table + i;
        split_entry->emt = ept_entry->emt;
        split_entry->ipat = ept_entry->ipat;

        split_entry->sp_avail =  (level > 1) ? 1 : 0;

        split_entry->mfn = s_mfn;

        split_entry->avail1 = ept_entry->avail1;
        split_entry->avail2 = 0;
        /* last step */
        split_entry->r = split_entry->w = split_entry->x = 1;
        ept_p2m_type_to_flags(split_entry, ept_entry->avail1);
    }

    *ept_entry = temp_ept_entry;
    
    *index = offset / trunk;
    *table = split_table;
    unmap_domain_page(prev_table);

    return 1;
}

/*
 * ept_set_entry() computes 'need_modify_vtd_table' for itself,
 * by observing whether any gfn->mfn translations are modified.
 */
static int
ept_set_entry(struct domain *d, unsigned long gfn, mfn_t mfn, 
              unsigned int order, p2m_type_t p2mt)
{
    ept_entry_t *table = NULL;
    unsigned long gfn_remainder = gfn;
    unsigned long offset = 0;
    ept_entry_t *ept_entry = NULL;
    u32 index;
    int i;
    int rv = 0;
    int ret = 0;
    int split_level = 0;
    int walk_level = order / EPT_TABLE_ORDER;
    int direct_mmio = (p2mt == p2m_mmio_direct);
    uint8_t ipat = 0;
    int need_modify_vtd_table = 1;
    int needs_sync = 1;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if (  order != 0 )
        if ( (gfn & ((1UL << order) - 1)) )
            return 1;

    table = map_domain_page(mfn_x(pagetable_get_mfn(p2m_get_pagetable(p2m))));

    ASSERT(table != NULL);

    for ( i = EPT_DEFAULT_GAW; i > walk_level; i-- )
    {
        ret = ept_next_level(d, 0, &table, &gfn_remainder, i * EPT_TABLE_ORDER);
        if ( !ret )
            goto out;
        else if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    /* If order == 0, we should only get POD if we have a POD superpage.
     * If i > walk_level, we need to split the page; otherwise,
     * just behave as normal. */
    ASSERT(ret != GUEST_TABLE_POD_PAGE || i != walk_level);

    index = gfn_remainder >> ( i ?  (i * EPT_TABLE_ORDER): order);
    offset = (gfn_remainder & ( ((1 << (i*EPT_TABLE_ORDER)) - 1)));

    split_level = i;

    ept_entry = table + index;

    if ( i == walk_level )
    {
        /* We reached the level we're looking for */

        /* No need to flush if the old entry wasn't valid */
        if ( !(ept_entry->epte & 7) )
            needs_sync = 0;

        if ( mfn_valid(mfn_x(mfn)) || direct_mmio || p2m_is_paged(p2mt) ||
             (p2mt == p2m_ram_paging_in_start) )
        {
            ept_entry->emt = epte_get_entry_emt(d, gfn, mfn, &ipat,
                                                direct_mmio);
            ept_entry->ipat = ipat;
            ept_entry->sp_avail = order ? 1 : 0;

            if ( ept_entry->mfn == mfn_x(mfn) )
                need_modify_vtd_table = 0;
            else
                ept_entry->mfn = mfn_x(mfn);

            ept_entry->avail1 = p2mt;
            ept_entry->avail2 = 0;

            ept_p2m_type_to_flags(ept_entry, p2mt);
        }
        else
            ept_entry->epte = 0;
    }
    else
    {
        int num = order / EPT_TABLE_ORDER;
        int level;
        ept_entry_t *split_ept_entry;
    
        if ( num >= cpu_vmx_ept_super_page_level_limit )
            num = cpu_vmx_ept_super_page_level_limit;
        for ( level = split_level; level > num ; level-- )
        {
            rv = ept_split_large_page(d, &table, &index, gfn, level);
            if ( !rv )
                goto out;
        }

        split_ept_entry = table + index;
        split_ept_entry->avail1 = p2mt;
        ept_p2m_type_to_flags(split_ept_entry, p2mt);
        split_ept_entry->emt = epte_get_entry_emt(d, gfn, mfn, &ipat,
                                                  direct_mmio);
        split_ept_entry->ipat = ipat;

        if ( split_ept_entry->mfn == mfn_x(mfn) )
            need_modify_vtd_table = 0;
        else
            split_ept_entry->mfn = mfn_x(mfn);
    }

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( mfn_valid(mfn_x(mfn))
         && (gfn + (1UL << order) - 1 > d->arch.p2m->max_mapped_pfn) )
        d->arch.p2m->max_mapped_pfn = gfn + (1UL << order) - 1;

    /* Success */
    rv = 1;

out:
    unmap_domain_page(table);

    if ( needs_sync )
        ept_sync_domain(d);

    /* Now the p2m table is not shared with vt-d page table */
    if ( rv && iommu_enabled && need_iommu(d) && need_modify_vtd_table )
    {
        if ( p2mt == p2m_ram_rw )
        {
            if ( order == EPT_TABLE_ORDER )
            {
                for ( i = 0; i < (1 << order); i++ )
                    iommu_map_page(d, gfn - offset + i, mfn_x(mfn) - offset + i);
            }
            else if ( !order )
                iommu_map_page(d, gfn, mfn_x(mfn));
        }
        else
        {
            if ( order == EPT_TABLE_ORDER )
            {
                for ( i = 0; i < (1 << order); i++ )
                    iommu_unmap_page(d, gfn - offset + i);
            }
            else if ( !order )
                iommu_unmap_page(d, gfn);
        }
    }

    return rv;
}

/* Read ept p2m entries */
static mfn_t ept_get_entry(struct domain *d, unsigned long gfn, p2m_type_t *t,
                           p2m_query_t q)
{
    ept_entry_t *table =
        map_domain_page(mfn_x(pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)))));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    u32 index;
    int i;
    int ret = 0;
    mfn_t mfn = _mfn(INVALID_MFN);

    *t = p2m_mmio_dm;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > d->arch.p2m->max_mapped_pfn )
        goto out;

    /* Should check if gfn obeys GAW here. */

    for ( i = EPT_DEFAULT_GAW; i > 0; i-- )
    {
    retry:
        ret = ept_next_level(d, 1, &table, &gfn_remainder,
                             i * EPT_TABLE_ORDER);
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

            if ( !ept_pod_check_and_populate(d, gfn,
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

    if ( ept_entry->avail1 == p2m_populate_on_demand )
    {
        if ( q == p2m_query )
        {
            *t = p2m_populate_on_demand;
            goto out;
        }

        ASSERT(i == 0);
        
        if ( ept_pod_check_and_populate(d, gfn,
                                        ept_entry, 0, q) )
            goto out;
    }


    if ( ept_entry->avail1 != p2m_invalid )
    {
        *t = ept_entry->avail1;
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
    }

out:
    unmap_domain_page(table);
    return mfn;
}

/* WARNING: Only caller doesn't care about PoD pages.  So this function will
 * always return 0 for PoD pages, not populate them.  If that becomes necessary,
 * pass a p2m_query_t type along to distinguish. */
static ept_entry_t ept_get_entry_content(struct domain *d, unsigned long gfn, int *level)
{
    ept_entry_t *table =
        map_domain_page(mfn_x(pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)))));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    ept_entry_t content = { .epte = 0 };
    u32 index;
    int i;
    int ret=0;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > d->arch.p2m->max_mapped_pfn )
        goto out;

    for ( i = EPT_DEFAULT_GAW; i > 0; i-- )
    {
        ret = ept_next_level(d, 1, &table, &gfn_remainder,
                             i * EPT_TABLE_ORDER);
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
    ept_entry_t *table =
        map_domain_page(mfn_x(pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)))));
    unsigned long gfn_remainder = gfn;

    int i;

    gdprintk(XENLOG_ERR, "Walking EPT tables for domain %d gfn %lx\n",
           d->domain_id, gfn);

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > d->arch.p2m->max_mapped_pfn )
    {
        gdprintk(XENLOG_ERR, " gfn exceeds max_mapped_pfn %lx\n",
               d->arch.p2m->max_mapped_pfn);
        goto out;
    }

    for ( i = EPT_DEFAULT_GAW; i >= 0; i-- )
    {
        ept_entry_t *ept_entry, *next;
        u32 index;

        /* Stolen from ept_next_level */
        index = gfn_remainder >> (i*EPT_TABLE_ORDER);
        ept_entry = table + index;

        gdprintk(XENLOG_ERR, " epte %"PRIx64"\n", ept_entry->epte);

        if ( i==0 || !(ept_entry->epte & 0x7) || ept_entry->sp_avail)
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

static mfn_t ept_get_entry_current(unsigned long gfn, p2m_type_t *t,
                                   p2m_query_t q)
{
    return ept_get_entry(current->domain, gfn, t, q);
}

/* 
 * To test if the new emt type is the same with old,
 * return 1 to not to reset ept entry.
 */
static int need_modify_ept_entry(struct domain *d, unsigned long gfn,
                                 mfn_t mfn, uint8_t o_ipat, uint8_t o_emt,
                                 p2m_type_t p2mt)
{
    uint8_t ipat;
    uint8_t emt;
    int direct_mmio = (p2mt == p2m_mmio_direct);

    emt = epte_get_entry_emt(d, gfn, mfn, &ipat, direct_mmio);

    if ( (emt == o_emt) && (ipat == o_ipat) )
        return 0;

    return 1; 
}

void ept_change_entry_emt_with_range(struct domain *d, unsigned long start_gfn,
                                     unsigned long end_gfn)
{
    unsigned long gfn;
    ept_entry_t e;
    mfn_t mfn;
    int order = 0;

    p2m_lock(d->arch.p2m);
    for ( gfn = start_gfn; gfn <= end_gfn; gfn++ )
    {
        int level = 0;
        uint64_t trunk = 0;

        e = ept_get_entry_content(d, gfn, &level);
        if ( !p2m_has_emt(e.avail1) )
            continue;

        order = 0;
        mfn = _mfn(e.mfn);

        if ( e.sp_avail )
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
                    if ( need_modify_ept_entry(d, gfn, mfn, 
                          e.ipat, e.emt, e.avail1) )
                        ept_set_entry(d, gfn, mfn, order, e.avail1);
                    gfn += trunk;
                    break;
                }
                level--;
             }
        }
        else /* gfn assigned with 4k */
        {
            if ( need_modify_ept_entry(d, gfn, mfn, e.ipat, e.emt, e.avail1) )
                ept_set_entry(d, gfn, mfn, order, e.avail1);
        }
    }
    p2m_unlock(d->arch.p2m);
}

/* 
 * Walk the whole p2m table, changing any entries of the old type
 * to the new type.  This is used in hardware-assisted paging to
 * quickly enable or diable log-dirty tracking
 */
static void ept_change_entry_type_global(struct domain *d, p2m_type_t ot,
                                         p2m_type_t nt)
{
    ept_entry_t *l4e;
    ept_entry_t *l3e;
    ept_entry_t *l2e;
    ept_entry_t *l1e;
    int i4;
    int i3;
    int i2;
    int i1;

    if ( pagetable_get_pfn(p2m_get_pagetable(p2m_get_hostp2m(d))) == 0 )
        return;

    BUG_ON(EPT_DEFAULT_GAW != 3);

    l4e = map_domain_page(mfn_x(pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)))));
    for (i4 = 0; i4 < EPT_PAGETABLE_ENTRIES; i4++ )
    {
        if ( !l4e[i4].epte )
            continue;

        if ( !l4e[i4].sp_avail )
        {
            l3e = map_domain_page(l4e[i4].mfn);
            for ( i3 = 0; i3 < EPT_PAGETABLE_ENTRIES; i3++ )
            {
                if ( !l3e[i3].epte )
                    continue;

                if ( !l3e[i3].sp_avail )
                {
                    l2e = map_domain_page(l3e[i3].mfn);
                    for ( i2 = 0; i2 < EPT_PAGETABLE_ENTRIES; i2++ )
                    {
                        if ( !l2e[i2].epte )
                            continue;

                        if ( !l2e[i2].sp_avail )
                        {
                            l1e = map_domain_page(l2e[i2].mfn);

                            for ( i1  = 0; i1 < EPT_PAGETABLE_ENTRIES; i1++ )
                            {
                                if ( !l1e[i1].epte )
                                    continue;

                                if ( l1e[i1].avail1 != ot )
                                    continue;
                                l1e[i1].avail1 = nt;
                                ept_p2m_type_to_flags(l1e+i1, nt);
                            }

                            unmap_domain_page(l1e);
                        }
                        else
                        {
                            if ( l2e[i2].avail1 != ot )
                                continue;
                            l2e[i2].avail1 = nt;
                            ept_p2m_type_to_flags(l2e+i2, nt);
                        }
                    }

                    unmap_domain_page(l2e);
                }
                else
                {
                    if ( l3e[i3].avail1 != ot )
                        continue;
                    l3e[i3].avail1 = nt;
                    ept_p2m_type_to_flags(l3e+i3, nt);
                }
            }

            unmap_domain_page(l3e);
        }
        else
        {
            if ( l4e[i4].avail1 != ot )
                continue;
            l4e[i4].avail1 = nt;
            ept_p2m_type_to_flags(l4e+i4, nt);
        }
    }

    unmap_domain_page(l4e);

    ept_sync_domain(d);
}

void ept_p2m_init(struct domain *d)
{
    d->arch.p2m->set_entry = ept_set_entry;
    d->arch.p2m->get_entry = ept_get_entry;
    d->arch.p2m->get_entry_current = ept_get_entry_current;
    d->arch.p2m->change_entry_type_global = ept_change_entry_type_global;
}

static void ept_dump_p2m_table(unsigned char key)
{
    struct domain *d;
    ept_entry_t *table, *ept_entry;
    mfn_t mfn;
    int order;
    int i;
    int is_pod;
    int ret;
    unsigned long index;
    unsigned long gfn, gfn_remainder;
    unsigned long record_counter = 0;
    struct p2m_domain *p2m;

    for_each_domain(d)
    {
        if ( !(is_hvm_domain(d) && d->arch.hvm_domain.hap_enabled) )
            continue;

        p2m = p2m_get_hostp2m(d);
        printk("\ndomain%d EPT p2m table: \n", d->domain_id);

        for ( gfn = 0; gfn <= d->arch.p2m->max_mapped_pfn; gfn += (1 << order) )
        {
            gfn_remainder = gfn;
            mfn = _mfn(INVALID_MFN);
            table =
                map_domain_page(mfn_x(pagetable_get_mfn(p2m_get_pagetable(p2m))));

            for ( i = EPT_DEFAULT_GAW; i > 0; i-- )
            {
                ret = ept_next_level(d, 1, &table, &gfn_remainder,
                                     i * EPT_TABLE_ORDER);
                if ( ret != GUEST_TABLE_NORMAL_PAGE )
                    break;
            }

            order = i * EPT_TABLE_ORDER;

            if ( ret == GUEST_TABLE_MAP_FAILED )
                goto out;

            index = gfn_remainder >> order;
            ept_entry = table + index;
            if ( ept_entry->avail1 != p2m_invalid )
            {
                ( ept_entry->avail1 == p2m_populate_on_demand ) ? 
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
