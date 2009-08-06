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
#include <xen/iommu.h>
#include <asm/mtrr.h>
#include <asm/hvm/cacheattr.h>

static void ept_p2m_type_to_flags(ept_entry_t *entry, p2m_type_t type)
{
    switch(type)
    {
        case p2m_invalid:
        case p2m_mmio_dm:
        default:
            entry->r = entry->w = entry->x = 0;
            return;
        case p2m_ram_rw:
        case p2m_mmio_direct:
        case p2m_grant_map_rw:
            entry->r = entry->w = entry->x = 1;
            return;
        case p2m_ram_logdirty:
        case p2m_ram_ro:
        case p2m_grant_map_ro:
            entry->r = entry->x = 1;
            entry->w = 0;
            return;
    }
}

#define GUEST_TABLE_NORMAL_PAGE 1
#define GUEST_TABLE_SUPER_PAGE  2
#define GUEST_TABLE_SPLIT_PAGE  3

static int ept_set_middle_entry(struct domain *d, ept_entry_t *ept_entry)
{
    struct page_info *pg;

    pg = d->arch.p2m->alloc_page(d);
    if ( pg == NULL )
        return 0;

    pg->count_info = 1;
    pg->u.inuse.type_info = 1 | PGT_validated;
    page_list_add_tail(pg, &d->arch.p2m->pages);

    ept_entry->emt = 0;
    ept_entry->igmt = 0;
    ept_entry->sp_avail = 0;
    ept_entry->avail1 = 0;
    ept_entry->mfn = page_to_mfn(pg);
    ept_entry->rsvd = 0;
    ept_entry->avail2 = 0;

    ept_entry->r = ept_entry->w = ept_entry->x = 1;

    return 1;
}

static int ept_next_level(struct domain *d, bool_t read_only,
                          ept_entry_t **table, unsigned long *gfn_remainder,
                          u32 shift, int order)
{
    ept_entry_t *ept_entry;
    ept_entry_t *next;
    u32 index;

    index = *gfn_remainder >> shift;

    ept_entry = (*table) + index;

    if ( !(ept_entry->epte & 0x7) )
    {
        if ( read_only )
            return 0;

        if ( !ept_set_middle_entry(d, ept_entry) )
            return 0;
    }

    if ( !ept_entry->sp_avail )
    {
        *gfn_remainder &= (1UL << shift) - 1;
        next = map_domain_page(ept_entry->mfn);
        unmap_domain_page(*table);
        *table = next;
        return GUEST_TABLE_NORMAL_PAGE;
    }
    else
    {
        if ( order == shift || read_only )
            return GUEST_TABLE_SUPER_PAGE;
        else
            return GUEST_TABLE_SPLIT_PAGE;
    }
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
    int walk_level = order / EPT_TABLE_ORDER;
    int direct_mmio = (p2mt == p2m_mmio_direct);
    uint8_t igmt = 0;
    int need_modify_vtd_table = 1;

    /* We only support 4k and 2m pages now */
    BUG_ON(order && order != EPT_TABLE_ORDER);

    if (  order != 0 )
        if ( (gfn & ((1UL << order) - 1)) )
            return 1;

    table = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));

    ASSERT(table != NULL);

    for ( i = EPT_DEFAULT_GAW; i > walk_level; i-- )
    {
        ret = ept_next_level(d, 0, &table, &gfn_remainder,
          i * EPT_TABLE_ORDER, order);
        if ( !ret )
            goto out;
        else if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    index = gfn_remainder >> ( i ?  (i * EPT_TABLE_ORDER): order);
    walk_level = ( i ? ( i * EPT_TABLE_ORDER) : order) / EPT_TABLE_ORDER;
    offset = (gfn_remainder & ( ((1 << (i*EPT_TABLE_ORDER)) - 1)));

    ept_entry = table + index;

    if ( ret != GUEST_TABLE_SPLIT_PAGE )
    {
        if ( mfn_valid(mfn_x(mfn)) || direct_mmio )
        {
            ept_entry->emt = epte_get_entry_emt(d, gfn, mfn, &igmt,
                                                direct_mmio);
            ept_entry->igmt = igmt;
            ept_entry->sp_avail = walk_level ? 1 : 0;

            if ( ret == GUEST_TABLE_SUPER_PAGE )
            {
                if ( ept_entry->mfn == (mfn_x(mfn) - offset) )
                    need_modify_vtd_table = 0;  
                else                  
                    ept_entry->mfn = mfn_x(mfn) - offset;

                if ( (ept_entry->avail1 == p2m_ram_logdirty) &&
                     (p2mt == p2m_ram_rw) )
                    for ( i = 0; i < 512; i++ )
                        paging_mark_dirty(d, mfn_x(mfn) - offset + i);
            }
            else
            {
                if ( ept_entry->mfn == mfn_x(mfn) )
                    need_modify_vtd_table = 0;
                else
                    ept_entry->mfn = mfn_x(mfn);
            }

            ept_entry->avail1 = p2mt;
            ept_entry->rsvd = 0;
            ept_entry->avail2 = 0;

            ept_p2m_type_to_flags(ept_entry, p2mt);
        }
        else
            ept_entry->epte = 0;
    }
    else
    {
        /* 
         * It's super page before, now set one of the 4k pages, so
         * we should split the 2m page to 4k pages now.
         */
        ept_entry_t *split_table = NULL;
        ept_entry_t *split_ept_entry = NULL;
        unsigned long split_mfn = ept_entry->mfn;
        p2m_type_t split_p2mt = ept_entry->avail1;
        ept_entry_t new_ept_entry;

        /* 
         * Allocate new page for new ept middle level entry which is
         * before a leaf super entry
         */
        if ( !ept_set_middle_entry(d, &new_ept_entry) )
            goto out;

        /* Split the super page before to 4k pages */
        split_table = map_domain_page(new_ept_entry.mfn);
        offset = gfn & ((1 << EPT_TABLE_ORDER) - 1);

        for ( i = 0; i < 512; i++ )
        {
            split_ept_entry = split_table + i;
            split_ept_entry->emt = epte_get_entry_emt(d, gfn - offset + i,
                                                      _mfn(split_mfn + i),
                                                      &igmt, direct_mmio);
            split_ept_entry->igmt = igmt;
            split_ept_entry->sp_avail =  0;
            split_ept_entry->mfn = split_mfn + i;
            split_ept_entry->avail1 = split_p2mt;
            split_ept_entry->rsvd = 0;
            split_ept_entry->avail2 = 0;

            ept_p2m_type_to_flags(split_ept_entry, split_p2mt);
        }

        /* Set the destinated 4k page as normal */
        split_ept_entry = split_table + offset;
        split_ept_entry->emt = epte_get_entry_emt(d, gfn, mfn, &igmt,
                                                  direct_mmio);
        split_ept_entry->igmt = igmt;

        if ( split_ept_entry->mfn == mfn_x(mfn) )
            need_modify_vtd_table = 0;
        else
            split_ept_entry->mfn = mfn_x(mfn);

        split_ept_entry->avail1 = p2mt;
        ept_p2m_type_to_flags(split_ept_entry, p2mt);

        unmap_domain_page(split_table);
        *ept_entry = new_ept_entry;
    }

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( mfn_valid(mfn_x(mfn))
         && (gfn + (1UL << order) - 1 > d->arch.p2m->max_mapped_pfn) )
        d->arch.p2m->max_mapped_pfn = gfn + (1UL << order) - 1;

    /* Success */
    rv = 1;

out:
    unmap_domain_page(table);

    ept_sync_domain(d);

    /* Now the p2m table is not shared with vt-d page table */
    if ( iommu_enabled && is_hvm_domain(d) && need_modify_vtd_table )
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
        map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
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
        ret = ept_next_level(d, 1, &table, &gfn_remainder,
                             i * EPT_TABLE_ORDER, 0);
        if ( !ret )
            goto out;
        else if ( ret == GUEST_TABLE_SUPER_PAGE )
            break;
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    ept_entry = table + index;

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

static uint64_t ept_get_entry_content(struct domain *d, unsigned long gfn)
{
    ept_entry_t *table =
        map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    uint64_t content = 0;
    u32 index;
    int i;
    int ret=0;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > d->arch.p2m->max_mapped_pfn )
        goto out;

    for ( i = EPT_DEFAULT_GAW; i > 0; i-- )
    {
        ret = ept_next_level(d, 1, &table, &gfn_remainder,
                             i * EPT_TABLE_ORDER, 0);
        if ( !ret )
            goto out;
        else if ( ret == GUEST_TABLE_SUPER_PAGE )
            break;
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    ept_entry = table + index;
    content = ept_entry->epte;

 out:
    unmap_domain_page(table);
    return content;
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
                                 mfn_t mfn, uint8_t o_igmt, uint8_t o_emt,
                                 p2m_type_t p2mt)
{
    uint8_t igmt;
    uint8_t emt;
    int direct_mmio = (p2mt == p2m_mmio_direct);

    emt = epte_get_entry_emt(d, gfn, mfn, &igmt, direct_mmio);

    if ( (emt == o_emt) && (igmt == o_igmt) )
        return 0;

    return 1; 
}

void ept_change_entry_emt_with_range(struct domain *d, unsigned long start_gfn,
                                     unsigned long end_gfn)
{
    unsigned long gfn;
    uint64_t epte;
    p2m_type_t p2mt;
    int order = 0;
    mfn_t mfn;
    uint8_t o_igmt;
    uint8_t o_emt;

    for ( gfn = start_gfn; gfn <= end_gfn; gfn++ )
    {
        epte = ept_get_entry_content(d, gfn);
        if ( epte == 0 )
            continue;

        mfn = _mfn((epte & EPTE_MFN_MASK) >> PAGE_SHIFT);
        if ( !mfn_valid(mfn_x(mfn)) )
            continue;

        p2mt = (epte & EPTE_AVAIL1_MASK) >> EPTE_AVAIL1_SHIFT;
        o_igmt = (epte & EPTE_IGMT_MASK) >> EPTE_IGMT_SHIFT;
        o_emt = (epte & EPTE_EMT_MASK) >> EPTE_EMT_SHIFT;
        order = 0;

        if ( epte & EPTE_SUPER_PAGE_MASK )
        {
            if ( !(gfn & ((1 << EPT_TABLE_ORDER) - 1)) &&
                 ((gfn + 0x1FF) <= end_gfn) )
            {
                /* 
                 * gfn assigned with 2M, and the end covers more than 2m areas.
                 * Set emt for super page.
                 */
                order = EPT_TABLE_ORDER;
                if ( need_modify_ept_entry(d, gfn, mfn, o_igmt, o_emt, p2mt) )
                    ept_set_entry(d, gfn, mfn, order, p2mt);
                gfn += 0x1FF;
            }
            else
            {
                /* Change emt for partial entries of the 2m area. */
                if ( need_modify_ept_entry(d, gfn, mfn, o_igmt, o_emt, p2mt) )
                    ept_set_entry(d, gfn, mfn, order, p2mt);
                gfn = ((gfn >> EPT_TABLE_ORDER) << EPT_TABLE_ORDER) + 0x1FF;
            }
        }
        else /* gfn assigned with 4k */
        {
            if ( need_modify_ept_entry(d, gfn, mfn, o_igmt, o_emt, p2mt) )
                ept_set_entry(d, gfn, mfn, order, p2mt);
        }
    }
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

    if ( pagetable_get_pfn(d->arch.phys_table) == 0 )
        return;

    BUG_ON(EPT_DEFAULT_GAW != 3);

    l4e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
