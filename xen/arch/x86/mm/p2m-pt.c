/******************************************************************************
 * arch/x86/mm/p2m-pt.c
 *
 * Implementation of p2m datastructures as pagetables, for use by 
 * NPT and shadow-pagetable code
 *
 * Parts of this code are Copyright (c) 2009-2011 by Citrix Systems, Inc.
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/iommu.h>
#include <xen/vm_event.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <public/vm_event.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mem_sharing.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

#include "mm-locks.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

/*
 * We may store INVALID_MFN in PTEs.  We need to clip this to avoid trampling
 * over higher-order bits (NX, p2m type, IOMMU flags).  We seem to not need
 * to unclip on the read path, as callers are concerned only with p2m type in
 * such cases.
 */
#define p2m_l1e_from_pfn(pfn, flags)    \
    l1e_from_pfn((pfn) & (PADDR_MASK >> PAGE_SHIFT), (flags))
#define p2m_l2e_from_pfn(pfn, flags)    \
    l2e_from_pfn((pfn) & ((PADDR_MASK & ~(_PAGE_PSE_PAT | 0UL)) \
                          >> PAGE_SHIFT), (flags) | _PAGE_PSE)
#define p2m_l3e_from_pfn(pfn, flags)    \
    l3e_from_pfn((pfn) & ((PADDR_MASK & ~(_PAGE_PSE_PAT | 0UL)) \
                          >> PAGE_SHIFT), (flags) | _PAGE_PSE)

/* PTE flags for the various types of p2m entry */
#define P2M_BASE_FLAGS \
        (_PAGE_PRESENT | _PAGE_USER | _PAGE_DIRTY | _PAGE_ACCESSED)

#define RECALC_FLAGS (_PAGE_USER|_PAGE_ACCESSED)
#define set_recalc(level, ent) level##e_remove_flags(ent, RECALC_FLAGS)
#define clear_recalc(level, ent) level##e_add_flags(ent, RECALC_FLAGS)
#define _needs_recalc(flags) (!((flags) & _PAGE_USER))
#define needs_recalc(level, ent) _needs_recalc(level##e_get_flags(ent))
#define valid_recalc(level, ent) (!(level##e_get_flags(ent) & _PAGE_ACCESSED))

static unsigned long p2m_type_to_flags(const struct p2m_domain *p2m,
                                       p2m_type_t t,
                                       mfn_t mfn,
                                       unsigned int level)
{
    unsigned long flags;
    /*
     * AMD IOMMU: When we share p2m table with iommu, bit 9 - bit 11 will be
     * used for iommu hardware to encode next io page level. Bit 59 - bit 62
     * are used for iommu flags, We could not use these bits to store p2m types.
     */
    flags = (unsigned long)(t & 0x7f) << 12;

    switch(t)
    {
    case p2m_invalid:
    case p2m_mmio_dm:
    case p2m_populate_on_demand:
    case p2m_ram_paging_out:
    case p2m_ram_paged:
    case p2m_ram_paging_in:
    default:
        return flags | _PAGE_NX_BIT;
    case p2m_grant_map_ro:
        return flags | P2M_BASE_FLAGS | _PAGE_NX_BIT;
    case p2m_ioreq_server:
        flags |= P2M_BASE_FLAGS | _PAGE_RW | _PAGE_NX_BIT;
        if ( p2m->ioreq.flags & XEN_DMOP_IOREQ_MEM_ACCESS_WRITE )
            return flags & ~_PAGE_RW;
        return flags;
    case p2m_ram_ro:
    case p2m_ram_logdirty:
    case p2m_ram_shared:
        return flags | P2M_BASE_FLAGS;
    case p2m_ram_rw:
        return flags | P2M_BASE_FLAGS | _PAGE_RW;
    case p2m_grant_map_rw:
    case p2m_map_foreign:
        return flags | P2M_BASE_FLAGS | _PAGE_RW | _PAGE_NX_BIT;
    case p2m_mmio_direct:
        if ( !rangeset_contains_singleton(mmio_ro_ranges, mfn_x(mfn)) )
            flags |= _PAGE_RW;
        else
        {
            flags |= _PAGE_PWT;
            ASSERT(!level);
        }
        return flags | P2M_BASE_FLAGS | _PAGE_PCD;
    }
}


// Find the next level's P2M entry, checking for out-of-range gfn's...
// Returns NULL on error.
//
static l1_pgentry_t *
p2m_find_entry(void *table, unsigned long *gfn_remainder,
                   unsigned long gfn, uint32_t shift, uint32_t max)
{
    u32 index;

    index = *gfn_remainder >> shift;
    if ( index >= max )
    {
        P2M_DEBUG("gfn=%#lx out of range "
                  "(gfn_remainder=%#lx shift=%d index=%#x max=%#x)\n",
                  gfn, *gfn_remainder, shift, index, max);
        return NULL;
    }
    *gfn_remainder &= (1 << shift) - 1;
    return (l1_pgentry_t *)table + index;
}

/* Free intermediate tables from a p2m sub-tree */
static void
p2m_free_entry(struct p2m_domain *p2m, l1_pgentry_t *p2m_entry, int page_order)
{
    /* End if the entry is a leaf entry. */
    if ( page_order == PAGE_ORDER_4K 
         || !(l1e_get_flags(*p2m_entry) & _PAGE_PRESENT)
         || (l1e_get_flags(*p2m_entry) & _PAGE_PSE) )
        return;

    if ( page_order > PAGE_ORDER_2M )
    {
        l1_pgentry_t *l3_table = map_domain_page(l1e_get_mfn(*p2m_entry));

        for ( int i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
            p2m_free_entry(p2m, l3_table + i, page_order - 9);
        unmap_domain_page(l3_table);
    }

    p2m_free_ptp(p2m, l1e_get_page(*p2m_entry));
}

// Walk one level of the P2M table, allocating a new table if required.
// Returns 0 on error.
//

/* AMD IOMMU: Convert next level bits and r/w bits into 24 bits p2m flags */
#define iommu_nlevel_to_flags(nl, f) ((((nl) & 0x7) << 9 )|(((f) & 0x3) << 21))

static void p2m_add_iommu_flags(l1_pgentry_t *p2m_entry,
                                unsigned int nlevel, unsigned int flags)
{
    if ( iommu_hap_pt_share )
        l1e_add_flags(*p2m_entry, iommu_nlevel_to_flags(nlevel, flags));
}

/* Returns: 0 for success, -errno for failure */
static int
p2m_next_level(struct p2m_domain *p2m, void **table,
               unsigned long *gfn_remainder, unsigned long gfn, u32 shift,
               u32 max, unsigned int level, bool_t unmap)
{
    l1_pgentry_t *p2m_entry, new_entry;
    void *next;
    unsigned int flags;

    if ( !(p2m_entry = p2m_find_entry(*table, gfn_remainder, gfn,
                                      shift, max)) )
        return -ENOENT;

    flags = l1e_get_flags(*p2m_entry);

    /* PoD/paging: Not present doesn't imply empty. */
    if ( !flags )
    {
        mfn_t mfn = p2m_alloc_ptp(p2m, level);

        if ( mfn_eq(mfn, INVALID_MFN) )
            return -ENOMEM;

        new_entry = l1e_from_mfn(mfn, P2M_BASE_FLAGS | _PAGE_RW);

        p2m_add_iommu_flags(&new_entry, level, IOMMUF_readable|IOMMUF_writable);
        p2m->write_p2m_entry(p2m, gfn, p2m_entry, new_entry, level + 1);
    }
    else if ( flags & _PAGE_PSE )
    {
        /* Split superpages pages into smaller ones. */
        unsigned long pfn = l1e_get_pfn(*p2m_entry);
        mfn_t mfn;
        l1_pgentry_t *l1_entry;
        unsigned int i;

        switch ( level )
        {
        case 2:
            break;

        case 1:
            /*
             * New splintered mappings inherit the flags of the old superpage,
             * with a little reorganisation for the _PAGE_PSE_PAT bit.
             */
            if ( pfn & 1 )           /* ==> _PAGE_PSE_PAT was set */
                pfn -= 1;            /* Clear it; _PAGE_PSE becomes _PAGE_PAT */
            else
                flags &= ~_PAGE_PSE; /* Clear _PAGE_PSE (== _PAGE_PAT) */
            break;

        default:
            ASSERT_UNREACHABLE();
            return -EINVAL;
        }

        mfn = p2m_alloc_ptp(p2m, level);
        if ( mfn_eq(mfn, INVALID_MFN) )
            return -ENOMEM;

        l1_entry = map_domain_page(mfn);

        /* Inherit original IOMMU permissions, but update Next Level. */
        if ( iommu_hap_pt_share )
        {
            flags &= ~iommu_nlevel_to_flags(~0, 0);
            flags |= iommu_nlevel_to_flags(level - 1, 0);
        }

        for ( i = 0; i < (1u << PAGETABLE_ORDER); i++ )
        {
            new_entry = l1e_from_pfn(pfn | (i << ((level - 1) * PAGETABLE_ORDER)),
                                     flags);
            p2m->write_p2m_entry(p2m, gfn, l1_entry + i, new_entry, level);
        }

        unmap_domain_page(l1_entry);

        new_entry = l1e_from_mfn(mfn, P2M_BASE_FLAGS | _PAGE_RW);
        p2m_add_iommu_flags(&new_entry, level, IOMMUF_readable|IOMMUF_writable);
        p2m->write_p2m_entry(p2m, gfn, p2m_entry, new_entry, level + 1);
    }
    else
        ASSERT(flags & _PAGE_PRESENT);

    next = map_domain_page(l1e_get_mfn(*p2m_entry));
    if ( unmap )
        unmap_domain_page(*table);
    *table = next;

    return 0;
}

/*
 * Mark (via clearing the U flag) as needing P2M type re-calculation all valid
 * present entries at the targeted level for the passed in GFN range, which is
 * guaranteed to not cross a page (table) boundary at that level.
 */
static int p2m_pt_set_recalc_range(struct p2m_domain *p2m,
                                   unsigned int level,
                                   unsigned long first_gfn,
                                   unsigned long last_gfn)
{
    void *table;
    unsigned long gfn_remainder = first_gfn, remainder;
    unsigned int i;
    l1_pgentry_t *pent, *plast;
    int err = 0;

    table = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    for ( i = 4; i-- > level; )
    {
        remainder = gfn_remainder;
        pent = p2m_find_entry(table, &remainder, first_gfn,
                              i * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER);
        if ( !pent )
        {
            err = -EINVAL;
            goto out;
        }

        if ( !(l1e_get_flags(*pent) & _PAGE_PRESENT) )
            goto out;

        err = p2m_next_level(p2m, &table, &gfn_remainder, first_gfn,
                             i * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER,
                             i, 1);
        if ( err )
            goto out;
    }

    remainder = gfn_remainder + (last_gfn - first_gfn);
    pent = p2m_find_entry(table, &gfn_remainder, first_gfn,
                          i * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER);
    plast = p2m_find_entry(table, &remainder, last_gfn,
                           i * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER);
    if ( pent && plast )
        for ( ; pent <= plast; ++pent )
        {
            l1_pgentry_t e = *pent;

            if ( (l1e_get_flags(e) & _PAGE_PRESENT) && !needs_recalc(l1, e) )
            {
                set_recalc(l1, e);
                p2m->write_p2m_entry(p2m, first_gfn, pent, e, level);
            }
            first_gfn += 1UL << (i * PAGETABLE_ORDER);
        }
    else
        err = -EIO;

 out:
    unmap_domain_page(table);

    return err;
}

/*
 * Handle possibly necessary P2M type re-calculation (U flag clear for a
 * present entry) for the entries in the page table hierarchy for the given
 * GFN. Propagate the re-calculation flag down to the next page table level
 * for entries not involved in the translation of the given GFN.
 */
static int do_recalc(struct p2m_domain *p2m, unsigned long gfn)
{
    void *table;
    unsigned long gfn_remainder = gfn;
    unsigned int level = 4;
    l1_pgentry_t *pent;
    int err = 0;

    table = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    while ( --level )
    {
        unsigned long remainder = gfn_remainder;

        pent = p2m_find_entry(table, &remainder, gfn,
                              level * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER);
        if ( !pent || !(l1e_get_flags(*pent) & _PAGE_PRESENT) )
            goto out;

        if ( l1e_get_flags(*pent) & _PAGE_PSE )
        {
            unsigned long mask = ~0UL << (level * PAGETABLE_ORDER);

            ASSERT(p2m_flags_to_type(l1e_get_flags(*pent)) != p2m_ioreq_server);
            if ( !needs_recalc(l1, *pent) ||
                 !p2m_is_changeable(p2m_flags_to_type(l1e_get_flags(*pent))) ||
                 p2m_is_logdirty_range(p2m, gfn & mask, gfn | ~mask) >= 0 )
                break;
        }

        err = p2m_next_level(p2m, &table, &gfn_remainder, gfn,
                             level * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER,
                             level, 0);
        if ( err )
            goto out;

        if ( needs_recalc(l1, *pent) )
        {
            l1_pgentry_t e = *pent, *ptab = table;
            unsigned int i;

            if ( !valid_recalc(l1, e) )
                P2M_DEBUG("bogus recalc state at d%d:%lx:%u\n",
                          p2m->domain->domain_id, gfn, level);
            remainder = gfn_remainder;
            for ( i = 0; i < (1 << PAGETABLE_ORDER); ++i )
            {
                l1_pgentry_t ent = ptab[i];

                if ( (l1e_get_flags(ent) & _PAGE_PRESENT) &&
                     !needs_recalc(l1, ent) )
                {
                    set_recalc(l1, ent);
                    p2m->write_p2m_entry(p2m, gfn - remainder, &ptab[i],
                                         ent, level);
                }
                remainder -= 1UL << ((level - 1) * PAGETABLE_ORDER);
            }
            smp_wmb();
            clear_recalc(l1, e);
            p2m->write_p2m_entry(p2m, gfn, pent, e, level + 1);
        }
        unmap_domain_page((void *)((unsigned long)pent & PAGE_MASK));
    }

    pent = p2m_find_entry(table, &gfn_remainder, gfn,
                          level * PAGETABLE_ORDER, 1 << PAGETABLE_ORDER);
    if ( pent && (l1e_get_flags(*pent) & _PAGE_PRESENT) &&
         needs_recalc(l1, *pent) )
    {
        l1_pgentry_t e = *pent;
        p2m_type_t ot, nt;
        unsigned long mask = ~0UL << (level * PAGETABLE_ORDER);

        if ( !valid_recalc(l1, e) )
            P2M_DEBUG("bogus recalc leaf at d%d:%lx:%u\n",
                      p2m->domain->domain_id, gfn, level);
        ot = p2m_flags_to_type(l1e_get_flags(e));
        nt = p2m_recalc_type_range(true, ot, p2m, gfn & mask, gfn | ~mask);
        if ( nt != ot )
        {
            unsigned long mfn = l1e_get_pfn(e);
            unsigned long flags = p2m_type_to_flags(p2m, nt,
                                                    _mfn(mfn), level);

            if ( level )
            {
                if ( flags & _PAGE_PAT )
                {
                     BUILD_BUG_ON(_PAGE_PAT != _PAGE_PSE);
                     mfn |= _PAGE_PSE_PAT >> PAGE_SHIFT;
                }
                else
                     mfn &= ~((unsigned long)_PAGE_PSE_PAT >> PAGE_SHIFT);
                flags |= _PAGE_PSE;
            }

            if ( ot == p2m_ioreq_server )
            {
                ASSERT(p2m->ioreq.entry_count > 0);
                ASSERT(level == 0);
                p2m->ioreq.entry_count--;
            }

            e = l1e_from_pfn(mfn, flags);
            p2m_add_iommu_flags(&e, level,
                                (nt == p2m_ram_rw)
                                ? IOMMUF_readable|IOMMUF_writable : 0);
            ASSERT(!needs_recalc(l1, e));
        }
        else
            clear_recalc(l1, e);
        p2m->write_p2m_entry(p2m, gfn, pent, e, level + 1);
    }

 out:
    unmap_domain_page(table);

    return err;
}

int p2m_pt_handle_deferred_changes(uint64_t gpa)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(current->domain);
    int rc;

    p2m_lock(p2m);
    rc = do_recalc(p2m, PFN_DOWN(gpa));
    p2m_unlock(p2m);

    return rc;
}

/* Returns: 0 for success, -errno for failure */
static int
p2m_pt_set_entry(struct p2m_domain *p2m, gfn_t gfn_, mfn_t mfn,
                 unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma,
                 int sve)
{
    /* XXX -- this might be able to be faster iff current->domain == d */
    void *table;
    unsigned long gfn = gfn_x(gfn_);
    unsigned long i, gfn_remainder = gfn;
    l1_pgentry_t *p2m_entry, entry_content;
    /* Intermediate table to free if we're replacing it with a superpage. */
    l1_pgentry_t intermediate_entry = l1e_empty();
    l2_pgentry_t l2e_content;
    l3_pgentry_t l3e_content;
    int rc;
    unsigned int iommu_pte_flags = p2m_get_iommu_flags(p2mt, mfn);
    /*
     * old_mfn and iommu_old_flags control possible flush/update needs on the
     * IOMMU: We need to flush when MFN or flags (i.e. permissions) change.
     * iommu_old_flags being initialized to zero covers the case of the entry
     * getting replaced being a non-present (leaf or intermediate) one. For
     * present leaf entries the real value will get calculated below, while
     * for present intermediate entries ~0 (guaranteed != iommu_pte_flags)
     * will be used (to cover all cases of what the leaf entries underneath
     * the intermediate one might be).
     */
    unsigned int flags, iommu_old_flags = 0;
    unsigned long old_mfn = mfn_x(INVALID_MFN);

    ASSERT(sve != 0);

    if ( tb_init_done )
    {
        struct {
            u64 gfn, mfn;
            int p2mt;
            int d:16,order:16;
        } t;

        t.gfn = gfn;
        t.mfn = mfn_x(mfn);
        t.p2mt = p2mt;
        t.d = p2m->domain->domain_id;
        t.order = page_order;

        __trace_var(TRC_MEM_SET_P2M_ENTRY, 0, sizeof(t), &t);
    }

    if ( unlikely(p2m_is_foreign(p2mt)) )
    {
        /* hvm fixme: foreign types are only supported on ept at present */
        gdprintk(XENLOG_WARNING, "Unimplemented foreign p2m type.\n");
        return -EINVAL;
    }

    /* Carry out any eventually pending earlier changes first. */
    rc = do_recalc(p2m, gfn);
    if ( rc < 0 )
        return rc;

    table = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    rc = p2m_next_level(p2m, &table, &gfn_remainder, gfn,
                        L4_PAGETABLE_SHIFT - PAGE_SHIFT,
                        L4_PAGETABLE_ENTRIES, 3, 1);
    if ( rc )
        goto out;

    /*
     * Try to allocate 1GB page table if this feature is supported.
     */
    if ( page_order == PAGE_ORDER_1G )
    {
        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                                   L3_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        flags = l1e_get_flags(*p2m_entry);
        if ( flags & _PAGE_PRESENT )
        {
            if ( flags & _PAGE_PSE )
            {
                old_mfn = l1e_get_pfn(*p2m_entry);
                iommu_old_flags =
                    p2m_get_iommu_flags(p2m_flags_to_type(flags),
                                        _mfn(old_mfn));
            }
            else
            {
                iommu_old_flags = ~0;
                intermediate_entry = *p2m_entry;
            }
        }

        ASSERT(p2m_flags_to_type(flags) != p2m_ioreq_server);
        ASSERT(!mfn_valid(mfn) || p2mt != p2m_mmio_direct);
        l3e_content = mfn_valid(mfn) || p2m_allows_invalid_mfn(p2mt)
            ? p2m_l3e_from_pfn(mfn_x(mfn),
                               p2m_type_to_flags(p2m, p2mt, mfn, 2))
            : l3e_empty();
        entry_content.l1 = l3e_content.l3;

        if ( entry_content.l1 != 0 )
            p2m_add_iommu_flags(&entry_content, 0, iommu_pte_flags);

        p2m->write_p2m_entry(p2m, gfn, p2m_entry, entry_content, 3);
        /* NB: paging_write_p2m_entry() handles tlb flushes properly */
    }
    else 
    {
        rc = p2m_next_level(p2m, &table, &gfn_remainder, gfn,
                            L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                            L3_PAGETABLE_ENTRIES, 2, 1);
        if ( rc )
            goto out;
    }

    if ( page_order == PAGE_ORDER_4K )
    {
        p2m_type_t p2mt_old;

        rc = p2m_next_level(p2m, &table, &gfn_remainder, gfn,
                            L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                            L2_PAGETABLE_ENTRIES, 1, 1);
        if ( rc )
            goto out;

        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   0, L1_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        old_mfn = l1e_get_pfn(*p2m_entry);
        iommu_old_flags =
            p2m_get_iommu_flags(p2m_flags_to_type(l1e_get_flags(*p2m_entry)),
                                _mfn(old_mfn));

        if ( mfn_valid(mfn) || p2m_allows_invalid_mfn(p2mt) )
            entry_content = p2m_l1e_from_pfn(mfn_x(mfn),
                                         p2m_type_to_flags(p2m, p2mt, mfn, 0));
        else
            entry_content = l1e_empty();

        if ( entry_content.l1 != 0 )
            p2m_add_iommu_flags(&entry_content, 0, iommu_pte_flags);

        p2mt_old = p2m_flags_to_type(l1e_get_flags(*p2m_entry));

        /*
         * p2m_ioreq_server is only used for 4K pages, so
         * the count is only done for level 1 entries.
         */
        if ( p2mt == p2m_ioreq_server )
            p2m->ioreq.entry_count++;

        if ( p2mt_old == p2m_ioreq_server )
        {
            ASSERT(p2m->ioreq.entry_count > 0);
            p2m->ioreq.entry_count--;
        }

        /* level 1 entry */
        p2m->write_p2m_entry(p2m, gfn, p2m_entry, entry_content, 1);
        /* NB: paging_write_p2m_entry() handles tlb flushes properly */
    }
    else if ( page_order == PAGE_ORDER_2M )
    {
        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                                   L2_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        flags = l1e_get_flags(*p2m_entry);
        if ( flags & _PAGE_PRESENT )
        {
            if ( flags & _PAGE_PSE )
            {
                old_mfn = l1e_get_pfn(*p2m_entry);
                iommu_old_flags =
                    p2m_get_iommu_flags(p2m_flags_to_type(flags),
                                        _mfn(old_mfn));
            }
            else
            {
                iommu_old_flags = ~0;
                intermediate_entry = *p2m_entry;
            }
        }

        ASSERT(p2m_flags_to_type(flags) != p2m_ioreq_server);
        ASSERT(!mfn_valid(mfn) || p2mt != p2m_mmio_direct);
        l2e_content = mfn_valid(mfn) || p2m_allows_invalid_mfn(p2mt)
            ? p2m_l2e_from_pfn(mfn_x(mfn),
                               p2m_type_to_flags(p2m, p2mt, mfn, 1))
            : l2e_empty();
        entry_content.l1 = l2e_content.l2;

        if ( entry_content.l1 != 0 )
            p2m_add_iommu_flags(&entry_content, 0, iommu_pte_flags);

        p2m->write_p2m_entry(p2m, gfn, p2m_entry, entry_content, 2);
        /* NB: paging_write_p2m_entry() handles tlb flushes properly */
    }

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( p2mt != p2m_invalid
         && (gfn + (1UL << page_order) - 1 > p2m->max_mapped_pfn) )
        p2m->max_mapped_pfn = gfn + (1UL << page_order) - 1;

    if ( iommu_enabled && need_iommu(p2m->domain) &&
         (iommu_old_flags != iommu_pte_flags || old_mfn != mfn_x(mfn)) )
    {
        ASSERT(rc == 0);

        if ( iommu_use_hap_pt(p2m->domain) )
        {
            if ( iommu_old_flags )
                amd_iommu_flush_pages(p2m->domain, gfn, page_order);
        }
        else if ( iommu_pte_flags )
            for ( i = 0; i < (1UL << page_order); i++ )
            {
                rc = iommu_map_page(p2m->domain, gfn + i, mfn_x(mfn) + i,
                                    iommu_pte_flags);
                if ( unlikely(rc) )
                {
                    while ( i-- )
                        /* If statement to satisfy __must_check. */
                        if ( iommu_unmap_page(p2m->domain, gfn + i) )
                            continue;

                    break;
                }
            }
        else
            for ( i = 0; i < (1UL << page_order); i++ )
            {
                int ret = iommu_unmap_page(p2m->domain, gfn + i);

                if ( !rc )
                    rc = ret;
            }
    }

    /*
     * Free old intermediate tables if necessary.  This has to be the
     * last thing we do, after removal from the IOMMU tables, so as to
     * avoid a potential use-after-free.
     */
    if ( l1e_get_flags(intermediate_entry) & _PAGE_PRESENT )
        p2m_free_entry(p2m, &intermediate_entry, page_order);

 out:
    unmap_domain_page(table);
    return rc;
}

static mfn_t
p2m_pt_get_entry(struct p2m_domain *p2m, gfn_t gfn_,
                 p2m_type_t *t, p2m_access_t *a, p2m_query_t q,
                 unsigned int *page_order, bool_t *sve)
{
    mfn_t mfn;
    unsigned long gfn = gfn_x(gfn_);
    paddr_t addr = ((paddr_t)gfn) << PAGE_SHIFT;
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;
    unsigned int flags;
    p2m_type_t l1t;
    bool_t recalc;

    ASSERT(paging_mode_translate(p2m->domain));

    if ( sve )
        *sve = 1;

    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */
    *t = p2m_mmio_dm;
    /* Not implemented except with EPT */
    *a = p2m_access_rwx; 

    if ( gfn > p2m->max_mapped_pfn )
    {
        /* This pfn is higher than the highest the p2m map currently holds */
        if ( page_order )
        {
            for ( *page_order = 3 * PAGETABLE_ORDER; *page_order;
                  *page_order -= PAGETABLE_ORDER )
                if ( (gfn & ~((1UL << *page_order) - 1)) >
                     p2m->max_mapped_pfn )
                    break;
        }
        return INVALID_MFN;
    }

    mfn = pagetable_get_mfn(p2m_get_pagetable(p2m));

    {
        l4_pgentry_t *l4e = map_domain_page(mfn);
        l4e += l4_table_offset(addr);
        if ( page_order )
            *page_order = 3 * PAGETABLE_ORDER;
        if ( (l4e_get_flags(*l4e) & _PAGE_PRESENT) == 0 )
        {
            unmap_domain_page(l4e);
            return INVALID_MFN;
        }
        mfn = l4e_get_mfn(*l4e);
        recalc = needs_recalc(l4, *l4e);
        unmap_domain_page(l4e);
    }
    {
        l3_pgentry_t *l3e = map_domain_page(mfn);
        l3e += l3_table_offset(addr);
        if ( page_order )
            *page_order = 2 * PAGETABLE_ORDER;

pod_retry_l3:
        flags = l3e_get_flags(*l3e);
        if ( !(flags & _PAGE_PRESENT) )
        {
            if ( p2m_flags_to_type(flags) == p2m_populate_on_demand )
            {
                if ( q & P2M_ALLOC )
                {
                    if ( p2m_pod_demand_populate(p2m, gfn_, PAGE_ORDER_1G) )
                        goto pod_retry_l3;
                    gdprintk(XENLOG_ERR, "%s: Allocate 1GB failed!\n", __func__);
                }
                else
                    *t = p2m_populate_on_demand;
            }
            unmap_domain_page(l3e);
            return INVALID_MFN;
        }
        if ( flags & _PAGE_PSE )
        {
            mfn = _mfn(l3e_get_pfn(*l3e) +
                       l2_table_offset(addr) * L1_PAGETABLE_ENTRIES +
                       l1_table_offset(addr));
            *t = p2m_recalc_type(recalc || _needs_recalc(flags),
                                 p2m_flags_to_type(flags), p2m, gfn);
            unmap_domain_page(l3e);

            ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t));
            return (p2m_is_valid(*t)) ? mfn : INVALID_MFN;
        }

        mfn = l3e_get_mfn(*l3e);
        if ( _needs_recalc(flags) )
            recalc = 1;
        unmap_domain_page(l3e);
    }

    l2e = map_domain_page(mfn);
    l2e += l2_table_offset(addr);
    if ( page_order )
        *page_order = PAGETABLE_ORDER;

pod_retry_l2:
    flags = l2e_get_flags(*l2e);
    if ( !(flags & _PAGE_PRESENT) )
    {
        /* PoD: Try to populate a 2-meg chunk */
        if ( p2m_flags_to_type(flags) == p2m_populate_on_demand )
        {
            if ( q & P2M_ALLOC ) {
                if ( p2m_pod_demand_populate(p2m, gfn_, PAGE_ORDER_2M) )
                    goto pod_retry_l2;
            } else
                *t = p2m_populate_on_demand;
        }
    
        unmap_domain_page(l2e);
        return INVALID_MFN;
    }
    if ( flags & _PAGE_PSE )
    {
        mfn = _mfn(l2e_get_pfn(*l2e) + l1_table_offset(addr));
        *t = p2m_recalc_type(recalc || _needs_recalc(flags),
                             p2m_flags_to_type(flags), p2m, gfn);
        unmap_domain_page(l2e);
        
        ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t));
        return (p2m_is_valid(*t)) ? mfn : INVALID_MFN;
    }

    mfn = l2e_get_mfn(*l2e);
    if ( needs_recalc(l2, *l2e) )
        recalc = 1;
    unmap_domain_page(l2e);

    l1e = map_domain_page(mfn);
    l1e += l1_table_offset(addr);
    if ( page_order )
        *page_order = 0;

pod_retry_l1:
    flags = l1e_get_flags(*l1e);
    l1t = p2m_flags_to_type(flags);
    if ( !(flags & _PAGE_PRESENT) && !p2m_is_paging(l1t) )
    {
        /* PoD: Try to populate */
        if ( l1t == p2m_populate_on_demand )
        {
            if ( q & P2M_ALLOC ) {
                if ( p2m_pod_demand_populate(p2m, gfn_, PAGE_ORDER_4K) )
                    goto pod_retry_l1;
            } else
                *t = p2m_populate_on_demand;
        }
    
        unmap_domain_page(l1e);
        return INVALID_MFN;
    }
    mfn = l1e_get_mfn(*l1e);
    *t = p2m_recalc_type(recalc || _needs_recalc(flags), l1t, p2m, gfn);
    unmap_domain_page(l1e);

    ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t) || p2m_is_paging(*t));
    return (p2m_is_valid(*t) || p2m_is_grant(*t)) ? mfn : INVALID_MFN;
}

static void p2m_pt_change_entry_type_global(struct p2m_domain *p2m,
                                            p2m_type_t ot, p2m_type_t nt)
{
    l1_pgentry_t *tab;
    unsigned long gfn = 0;
    unsigned int i, changed;

    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) == 0 )
        return;

    ASSERT(hap_enabled(p2m->domain));

    tab = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    for ( changed = i = 0; i < (1 << PAGETABLE_ORDER); ++i )
    {
        l1_pgentry_t e = tab[i];

        if ( (l1e_get_flags(e) & _PAGE_PRESENT) &&
             !needs_recalc(l1, e) )
        {
            set_recalc(l1, e);
            p2m->write_p2m_entry(p2m, gfn, &tab[i], e, 4);
            ++changed;
        }
        gfn += 1UL << (L4_PAGETABLE_SHIFT - PAGE_SHIFT);
    }
    unmap_domain_page(tab);

    if ( changed )
         flush_tlb_mask(p2m->domain->dirty_cpumask);
}

static int p2m_pt_change_entry_type_range(struct p2m_domain *p2m,
                                          p2m_type_t ot, p2m_type_t nt,
                                          unsigned long first_gfn,
                                          unsigned long last_gfn)
{
    unsigned long mask = (1 << PAGETABLE_ORDER) - 1;
    unsigned int i;
    int err = 0;

    ASSERT(hap_enabled(p2m->domain));

    for ( i = 1; i <= 4; )
    {
        if ( first_gfn & mask )
        {
            unsigned long end_gfn = min(first_gfn | mask, last_gfn);

            err = p2m_pt_set_recalc_range(p2m, i, first_gfn, end_gfn);
            if ( err || end_gfn >= last_gfn )
                break;
            first_gfn = end_gfn + 1;
        }
        else if ( (last_gfn & mask) != mask )
        {
            unsigned long start_gfn = max(first_gfn, last_gfn & ~mask);

            err = p2m_pt_set_recalc_range(p2m, i, start_gfn, last_gfn);
            if ( err || start_gfn <= first_gfn )
                break;
            last_gfn = start_gfn - 1;
        }
        else
        {
            ++i;
            mask |= mask << PAGETABLE_ORDER;
        }
    }

    return err;
}

#if P2M_AUDIT
long p2m_pt_audit_p2m(struct p2m_domain *p2m)
{
    unsigned long entry_count = 0, pmbad = 0;
    unsigned long mfn, gfn, m2pfn;

    ASSERT(p2m_locked_by_me(p2m));
    ASSERT(pod_locked_by_me(p2m));

    /* Audit part one: walk the domain's p2m table, checking the entries. */
    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) != 0 )
    {
        l2_pgentry_t *l2e;
        l1_pgentry_t *l1e;
        int i1, i2;

        l4_pgentry_t *l4e;
        l3_pgentry_t *l3e;
        int i4, i3;
        l4e = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));

        gfn = 0;
        for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
        {
            if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
            {
                gfn += 1 << (L4_PAGETABLE_SHIFT - PAGE_SHIFT);
                continue;
            }
            l3e = map_l3t_from_l4e(l4e[i4]);
            for ( i3 = 0;
                  i3 < L3_PAGETABLE_ENTRIES;
                  i3++ )
            {
                if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
                {
                    gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                    continue;
                }

                /* check for 1GB super page */
                if ( l3e_get_flags(l3e[i3]) & _PAGE_PSE )
                {
                    mfn = l3e_get_pfn(l3e[i3]);
                    ASSERT(mfn_valid(_mfn(mfn)));
                    /* we have to cover 512x512 4K pages */
                    for ( i2 = 0; 
                          i2 < (L2_PAGETABLE_ENTRIES * L1_PAGETABLE_ENTRIES);
                          i2++)
                    {
                        m2pfn = get_gpfn_from_mfn(mfn+i2);
                        if ( m2pfn != (gfn + i2) )
                        {
                            pmbad++;
                            P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                       " -> gfn %#lx\n", gfn+i2, mfn+i2,
                                       m2pfn);
                            BUG();
                        }
                        gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                }

                l2e = map_l2t_from_l3e(l3e[i3]);
                for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
                {
                    if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                    {
                        if ( (l2e_get_flags(l2e[i2]) & _PAGE_PSE)
                             && ( p2m_flags_to_type(l2e_get_flags(l2e[i2]))
                                  == p2m_populate_on_demand ) )
                            entry_count+=SUPERPAGE_PAGES;
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                    
                    /* check for super page */
                    if ( l2e_get_flags(l2e[i2]) & _PAGE_PSE )
                    {
                        mfn = l2e_get_pfn(l2e[i2]);
                        ASSERT(mfn_valid(_mfn(mfn)));
                        for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++)
                        {
                            m2pfn = get_gpfn_from_mfn(mfn+i1);
                            /* Allow shared M2Ps */
                            if ( (m2pfn != (gfn + i1)) &&
                                 (m2pfn != SHARED_M2P_ENTRY) )
                            {
                                pmbad++;
                                P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                           " -> gfn %#lx\n", gfn+i1, mfn+i1,
                                           m2pfn);
                                BUG();
                            }
                        }
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }

                    l1e = map_l1t_from_l2e(l2e[i2]);

                    for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                    {
                        p2m_type_t type;

                        type = p2m_flags_to_type(l1e_get_flags(l1e[i1]));
                        if ( !(l1e_get_flags(l1e[i1]) & _PAGE_PRESENT) )
                        {
                            if ( type == p2m_populate_on_demand )
                                entry_count++;
                            continue;
                        }
                        mfn = l1e_get_pfn(l1e[i1]);
                        ASSERT(mfn_valid(_mfn(mfn)));
                        m2pfn = get_gpfn_from_mfn(mfn);
                        if ( m2pfn != gfn &&
                             type != p2m_mmio_direct &&
                             !p2m_is_grant(type) &&
                             !p2m_is_shared(type) )
                        {
                            pmbad++;
                            printk("mismatch: gfn %#lx -> mfn %#lx"
                                   " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                       " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            BUG();
                        }
                    }
                    unmap_domain_page(l1e);
                }
                unmap_domain_page(l2e);
            }
            unmap_domain_page(l3e);
        }

        unmap_domain_page(l4e);
    }

    if ( entry_count != p2m->pod.entry_count )
    {
        printk("%s: refcounted entry count %ld, audit count %lu!\n",
               __func__,
               p2m->pod.entry_count,
               entry_count);
        BUG();
    }

    return pmbad;
}
#endif /* P2M_AUDIT */

/* Set up the p2m function pointers for pagetable format */
void p2m_pt_init(struct p2m_domain *p2m)
{
    p2m->set_entry = p2m_pt_set_entry;
    p2m->get_entry = p2m_pt_get_entry;
    p2m->recalc = do_recalc;
    p2m->change_entry_type_global = p2m_pt_change_entry_type_global;
    p2m->change_entry_type_range = p2m_pt_change_entry_type_range;
    p2m->write_p2m_entry = paging_write_p2m_entry;
#if P2M_AUDIT
    p2m->audit_p2m = p2m_pt_audit_p2m;
#else
    p2m->audit_p2m = NULL;
#endif
}


