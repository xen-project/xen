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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <asm/hvm/nestedhvm.h>
#include <xen/iommu.h>
#include <asm/mtrr.h>
#include <asm/hvm/cacheattr.h>
#include <xen/keyhandler.h>
#include <xen/softirq.h>

#include "mm-locks.h"

#define atomic_read_ept_entry(__pepte)                              \
    ( (ept_entry_t) { .epte = read_atomic(&(__pepte)->epte) } )

#define is_epte_present(ept_entry)      ((ept_entry)->epte & 0x7)
#define is_epte_superpage(ept_entry)    ((ept_entry)->sp)
static inline bool_t is_epte_valid(ept_entry_t *e)
{
    /* suppress_ve alone is not considered valid, so mask it off */
    return ((e->epte & ~(1ul << 63)) != 0 && e->sa_p2mt != p2m_invalid);
}

/* returns : 0 for success, -errno otherwise */
static int atomic_write_ept_entry(ept_entry_t *entryptr, ept_entry_t new,
                                  int level)
{
    int rc;
    unsigned long oldmfn = mfn_x(INVALID_MFN);
    bool_t check_foreign = (new.mfn != entryptr->mfn ||
                            new.sa_p2mt != entryptr->sa_p2mt);

    if ( level )
    {
        ASSERT(!is_epte_superpage(&new) || !p2m_is_foreign(new.sa_p2mt));
        write_atomic(&entryptr->epte, new.epte);
        return 0;
    }

    if ( unlikely(p2m_is_foreign(new.sa_p2mt)) )
    {
        rc = -EINVAL;
        if ( !is_epte_present(&new) )
                goto out;

        if ( check_foreign )
        {
            struct domain *fdom;

            if ( !mfn_valid(new.mfn) )
                goto out;

            rc = -ESRCH;
            fdom = page_get_owner(mfn_to_page(new.mfn));
            if ( fdom == NULL )
                goto out;

            /* get refcount on the page */
            rc = -EBUSY;
            if ( !get_page(mfn_to_page(new.mfn), fdom) )
                goto out;
        }
    }

    if ( unlikely(p2m_is_foreign(entryptr->sa_p2mt)) && check_foreign )
        oldmfn = entryptr->mfn;

    write_atomic(&entryptr->epte, new.epte);

    if ( unlikely(oldmfn != mfn_x(INVALID_MFN)) )
        put_page(mfn_to_page(oldmfn));

    rc = 0;

 out:
    if ( rc )
        gdprintk(XENLOG_ERR, "epte o:%"PRIx64" n:%"PRIx64" rc:%d\n",
                 entryptr->epte, new.epte, rc);
    return rc;
}

static void ept_p2m_type_to_flags(struct p2m_domain *p2m, ept_entry_t *entry,
                                  p2m_type_t type, p2m_access_t access)
{
    /*
     * First apply type permissions.
     *
     * A/D bits are also manually set to avoid overhead of MMU having to set
     * them later. Both A/D bits are safe to be updated directly as they are
     * ignored by processor if EPT A/D bits is not turned on.
     *
     * A bit is set for all present p2m types in middle and leaf EPT entries.
     * D bit is set for all writable types in EPT leaf entry, except for
     * log-dirty type with PML.
     */
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
            entry->a = entry->d = !!cpu_has_vmx_ept_ad;
            break;
        case p2m_mmio_direct:
            entry->r = entry->x = 1;
            entry->w = !rangeset_contains_singleton(mmio_ro_ranges,
                                                    entry->mfn);
            ASSERT(entry->w || !is_epte_superpage(entry));
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = entry->w && cpu_has_vmx_ept_ad;
            break;
        case p2m_ram_logdirty:
            entry->r = entry->x = 1;
            /*
             * In case of PML, we don't have to write protect 4K page, but
             * only need to clear D-bit for it, but we still need to write
             * protect super page in order to split it to 4K pages in EPT
             * violation.
             */
            if ( vmx_domain_pml_enabled(p2m->domain) &&
                 !is_epte_superpage(entry) )
                entry->w = 1;
            else
                entry->w = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            /* For both PML or non-PML cases we clear D bit anyway */
            entry->d = 0;
            break;
        case p2m_ram_ro:
        case p2m_ram_shared:
            entry->r = entry->x = 1;
            entry->w = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = 0;
            break;
        case p2m_grant_map_rw:
        case p2m_map_foreign:
            entry->r = entry->w = 1;
            entry->x = 0;
            entry->a = entry->d = !!cpu_has_vmx_ept_ad;
            break;
        case p2m_grant_map_ro:
        case p2m_ioreq_server:
            entry->r = 1;
            entry->w = entry->x = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = 0;
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
    ept_entry_t *table;
    unsigned int i;

    pg = p2m_alloc_ptp(p2m, 0);
    if ( pg == NULL )
        return 0;

    ept_entry->epte = 0;
    ept_entry->mfn = page_to_mfn(pg);
    ept_entry->access = p2m->default_access;

    ept_entry->r = ept_entry->w = ept_entry->x = 1;
    /* Manually set A bit to avoid overhead of MMU having to write it later. */
    ept_entry->a = !!cpu_has_vmx_ept_ad;

    ept_entry->suppress_ve = 1;

    table = __map_domain_page(pg);

    for ( i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
        table[i].suppress_ve = 1;

    unmap_domain_page(table);

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
        ept_entry_t *epte = map_domain_page(_mfn(ept_entry->mfn));
        for ( int i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
            ept_free_entry(p2m, epte + i, level - 1);
        unmap_domain_page(epte);
    }
    
    p2m_tlb_flush_sync(p2m);
    p2m_free_ptp(p2m, mfn_to_page(ept_entry->mfn));
}

static bool_t ept_split_super_page(struct p2m_domain *p2m,
                                   ept_entry_t *ept_entry,
                                   unsigned int level, unsigned int target)
{
    ept_entry_t new_ept, *table;
    uint64_t trunk;
    unsigned int i;
    bool_t rv = 1;

    /* End if the entry is a leaf entry or reaches the target level. */
    if ( level <= target )
        return 1;

    ASSERT(is_epte_superpage(ept_entry));

    if ( !ept_set_middle_entry(p2m, &new_ept) )
        return 0;

    table = map_domain_page(_mfn(new_ept.mfn));
    trunk = 1UL << ((level - 1) * EPT_TABLE_ORDER);

    for ( i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
    {
        ept_entry_t *epte = table + i;

        *epte = *ept_entry;
        epte->sp = (level > 1);
        epte->mfn += i * trunk;
        epte->snp = (iommu_enabled && iommu_snoop);
        epte->suppress_ve = 1;

        ept_p2m_type_to_flags(p2m, epte, epte->sa_p2mt, epte->access);

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
    *table = map_domain_page(_mfn(mfn));
    *gfn_remainder &= (1UL << shift) - 1;
    return GUEST_TABLE_NORMAL_PAGE;
}

/*
 * Invalidate (via setting the EMT field to an invalid value) all valid
 * present entries in the given page table, optionally marking the entries
 * also for their subtrees needing P2M type re-calculation.
 */
static bool_t ept_invalidate_emt(mfn_t mfn, bool_t recalc, int level)
{
    int rc;
    ept_entry_t *epte = map_domain_page(mfn);
    unsigned int i;
    bool_t changed = 0;

    for ( i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
    {
        ept_entry_t e = atomic_read_ept_entry(&epte[i]);

        if ( !is_epte_valid(&e) || !is_epte_present(&e) ||
             (e.emt == MTRR_NUM_TYPES && (e.recalc || !recalc)) )
            continue;

        e.emt = MTRR_NUM_TYPES;
        if ( recalc )
            e.recalc = 1;
        rc = atomic_write_ept_entry(&epte[i], e, level);
        ASSERT(rc == 0);
        changed = 1;
    }

    unmap_domain_page(epte);

    return changed;
}

/*
 * Just like ept_invalidate_emt() except that
 * - not all entries at the targeted level may need processing,
 * - the re-calculation flag gets always set.
 * The passed in range is guaranteed to not cross a page (table)
 * boundary at the targeted level.
 */
static int ept_invalidate_emt_range(struct p2m_domain *p2m,
                                    unsigned int target,
                                    unsigned long first_gfn,
                                    unsigned long last_gfn)
{
    ept_entry_t *table;
    unsigned long gfn_remainder = first_gfn;
    unsigned int i, index;
    int wrc, rc = 0, ret = GUEST_TABLE_MAP_FAILED;

    table = map_domain_page(_mfn(pagetable_get_pfn(p2m_get_pagetable(p2m))));
    for ( i = ept_get_wl(&p2m->ept); i > target; --i )
    {
        ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
        if ( ret == GUEST_TABLE_MAP_FAILED )
            goto out;
        if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    if ( i > target )
    {
        /* We need to split the original page. */
        ept_entry_t split_ept_entry;

        index = gfn_remainder >> (i * EPT_TABLE_ORDER);
        split_ept_entry = atomic_read_ept_entry(&table[index]);
        ASSERT(is_epte_superpage(&split_ept_entry));
        if ( !ept_split_super_page(p2m, &split_ept_entry, i, target) )
        {
            ept_free_entry(p2m, &split_ept_entry, i);
            rc = -ENOMEM;
            goto out;
        }
        wrc = atomic_write_ept_entry(&table[index], split_ept_entry, i);
        ASSERT(wrc == 0);

        for ( ; i > target; --i )
            if ( !ept_next_level(p2m, 1, &table, &gfn_remainder, i) )
                break;
        ASSERT(i == target);
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    i = (last_gfn >> (i * EPT_TABLE_ORDER)) & (EPT_PAGETABLE_ENTRIES - 1);
    for ( ; index <= i; ++index )
    {
        ept_entry_t e = atomic_read_ept_entry(&table[index]);

        if ( is_epte_valid(&e) && is_epte_present(&e) &&
             (e.emt != MTRR_NUM_TYPES || !e.recalc) )
        {
            e.emt = MTRR_NUM_TYPES;
            e.recalc = 1;
            wrc = atomic_write_ept_entry(&table[index], e, target);
            ASSERT(wrc == 0);
            rc = 1;
        }
    }

 out:
    unmap_domain_page(table);

    return rc;
}

/*
 * Resolve deliberately mis-configured (EMT field set to an invalid value)
 * entries in the page table hierarchy for the given GFN:
 * - calculate the correct value for the EMT field,
 * - if marked so, re-calculate the P2M type,
 * - propagate EMT and re-calculation flag down to the next page table level
 *   for entries not involved in the translation of the given GFN.
 * Returns:
 * - negative errno values in error,
 * - zero if no adjustment was done,
 * - a positive value if at least one adjustment was done.
 */
static int resolve_misconfig(struct p2m_domain *p2m, unsigned long gfn)
{
    struct ept_data *ept = &p2m->ept;
    unsigned int level = ept_get_wl(ept);
    unsigned long mfn = ept_get_asr(ept);
    ept_entry_t *epte;
    int wrc, rc = 0;

    if ( !mfn )
        return 0;

    for ( ; ; --level )
    {
        ept_entry_t e;
        unsigned int i;

        epte = map_domain_page(_mfn(mfn));
        i = (gfn >> (level * EPT_TABLE_ORDER)) & (EPT_PAGETABLE_ENTRIES - 1);
        e = atomic_read_ept_entry(&epte[i]);

        if ( level == 0 || is_epte_superpage(&e) )
        {
            uint8_t ipat = 0;

            if ( e.emt != MTRR_NUM_TYPES )
                break;

            if ( level == 0 )
            {
                for ( gfn -= i, i = 0; i < EPT_PAGETABLE_ENTRIES; ++i )
                {
                    e = atomic_read_ept_entry(&epte[i]);
                    if ( e.emt == MTRR_NUM_TYPES )
                        e.emt = 0;
                    if ( !is_epte_valid(&e) || !is_epte_present(&e) )
                        continue;
                    e.emt = epte_get_entry_emt(p2m->domain, gfn + i,
                                               _mfn(e.mfn), 0, &ipat,
                                               e.sa_p2mt == p2m_mmio_direct);
                    e.ipat = ipat;
                    if ( e.recalc && p2m_is_changeable(e.sa_p2mt) )
                    {
                         e.sa_p2mt = p2m_is_logdirty_range(p2m, gfn + i, gfn + i)
                                     ? p2m_ram_logdirty : p2m_ram_rw;
                         ept_p2m_type_to_flags(p2m, &e, e.sa_p2mt, e.access);
                    }
                    e.recalc = 0;
                    wrc = atomic_write_ept_entry(&epte[i], e, level);
                    ASSERT(wrc == 0);
                }
            }
            else
            {
                int emt = epte_get_entry_emt(p2m->domain, gfn, _mfn(e.mfn),
                                             level * EPT_TABLE_ORDER, &ipat,
                                             e.sa_p2mt == p2m_mmio_direct);
                bool_t recalc = e.recalc;

                if ( recalc && p2m_is_changeable(e.sa_p2mt) )
                {
                     unsigned long mask = ~0UL << (level * EPT_TABLE_ORDER);

                     switch ( p2m_is_logdirty_range(p2m, gfn & mask,
                                                    gfn | ~mask) )
                     {
                     case 0:
                          e.sa_p2mt = p2m_ram_rw;
                          e.recalc = 0;
                          break;
                     case 1:
                          e.sa_p2mt = p2m_ram_logdirty;
                          e.recalc = 0;
                          break;
                     default: /* Force split. */
                          emt = -1;
                          break;
                     }
                }
                if ( unlikely(emt < 0) )
                {
                    if ( ept_split_super_page(p2m, &e, level, level - 1) )
                    {
                        wrc = atomic_write_ept_entry(&epte[i], e, level);
                        ASSERT(wrc == 0);
                        unmap_domain_page(epte);
                        mfn = e.mfn;
                        continue;
                    }
                    ept_free_entry(p2m, &e, level);
                    rc = -ENOMEM;
                    break;
                }
                e.emt = emt;
                e.ipat = ipat;
                e.recalc = 0;
                if ( recalc && p2m_is_changeable(e.sa_p2mt) )
                    ept_p2m_type_to_flags(p2m, &e, e.sa_p2mt, e.access);
                wrc = atomic_write_ept_entry(&epte[i], e, level);
                ASSERT(wrc == 0);
            }

            rc = 1;
            break;
        }

        if ( e.emt == MTRR_NUM_TYPES )
        {
            ASSERT(is_epte_present(&e));
            ept_invalidate_emt(_mfn(e.mfn), e.recalc, level);
            smp_wmb();
            e.emt = 0;
            e.recalc = 0;
            wrc = atomic_write_ept_entry(&epte[i], e, level);
            ASSERT(wrc == 0);
            unmap_domain_page(epte);
            rc = 1;
        }
        else if ( is_epte_present(&e) && !e.emt )
            unmap_domain_page(epte);
        else
            break;

        mfn = e.mfn;
    }

    unmap_domain_page(epte);
    if ( rc )
    {
        struct vcpu *v;

        for_each_vcpu ( p2m->domain, v )
            v->arch.hvm_vmx.ept_spurious_misconfig = 1;
    }

    return rc;
}

bool_t ept_handle_misconfig(uint64_t gpa)
{
    struct vcpu *curr = current;
    struct p2m_domain *p2m = p2m_get_hostp2m(curr->domain);
    bool_t spurious;
    int rc;

    p2m_lock(p2m);

    spurious = curr->arch.hvm_vmx.ept_spurious_misconfig;
    rc = resolve_misconfig(p2m, PFN_DOWN(gpa));
    curr->arch.hvm_vmx.ept_spurious_misconfig = 0;

    p2m_unlock(p2m);

    return spurious ? (rc >= 0) : (rc > 0);
}

/*
 * ept_set_entry() computes 'need_modify_vtd_table' for itself,
 * by observing whether any gfn->mfn translations are modified.
 *
 * Returns: 0 for success, -errno for failure
 */
static int
ept_set_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
              unsigned int order, p2m_type_t p2mt, p2m_access_t p2ma,
              int sve)
{
    ept_entry_t *table, *ept_entry = NULL;
    unsigned long gfn_remainder = gfn;
    unsigned int i, target = order / EPT_TABLE_ORDER;
    unsigned long fn_mask = !mfn_eq(mfn, INVALID_MFN) ? (gfn | mfn_x(mfn)) : gfn;
    int ret, rc = 0;
    bool_t entry_written = 0;
    bool_t direct_mmio = (p2mt == p2m_mmio_direct);
    uint8_t ipat = 0;
    bool_t need_modify_vtd_table = 1;
    bool_t vtd_pte_present = 0;
    unsigned int iommu_flags = p2m_get_iommu_flags(p2mt);
    bool_t needs_sync = 1;
    ept_entry_t old_entry = { .epte = 0 };
    ept_entry_t new_entry = { .epte = 0 };
    struct ept_data *ept = &p2m->ept;
    struct domain *d = p2m->domain;

    ASSERT(ept);
    /*
     * the caller must make sure:
     * 1. passing valid gfn and mfn at order boundary.
     * 2. gfn not exceeding guest physical address width.
     * 3. passing a valid order.
     */
    if ( (fn_mask & ((1UL << order) - 1)) ||
         ((u64)gfn >> ((ept_get_wl(ept) + 1) * EPT_TABLE_ORDER)) ||
         (order % EPT_TABLE_ORDER) )
        return -EINVAL;

    /* Carry out any eventually pending earlier changes first. */
    ret = resolve_misconfig(p2m, gfn);
    if ( ret < 0 )
        return ret;

    ASSERT((target == 2 && hap_has_1gb) ||
           (target == 1 && hap_has_2mb) ||
           (target == 0));
    ASSERT(!p2m_is_foreign(p2mt) || target == 0);

    table = map_domain_page(_mfn(pagetable_get_pfn(p2m_get_pagetable(p2m))));

    ret = GUEST_TABLE_MAP_FAILED;
    for ( i = ept_get_wl(ept); i > target; i-- )
    {
        ret = ept_next_level(p2m, 0, &table, &gfn_remainder, i);
        if ( !ret )
        {
            rc = -ENOENT;
            goto out;
        }
        else if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    ASSERT(ret != GUEST_TABLE_POD_PAGE || i != target);

    ept_entry = table + (gfn_remainder >> (i * EPT_TABLE_ORDER));

    /* In case VT-d uses same page table, this flag is needed by VT-d */ 
    vtd_pte_present = is_epte_present(ept_entry);

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

        /* No need to flush if the old entry wasn't valid */
        if ( !is_epte_present(ept_entry) )
            needs_sync = 0;

        /* If we're replacing a non-leaf entry with a leaf entry (1GiB or 2MiB),
         * the intermediate tables will be freed below after the ept flush
         *
         * Read-then-write is OK because we hold the p2m lock. */
        old_entry = *ept_entry;
    }
    else
    {
        /* We need to split the original page. */
        ept_entry_t split_ept_entry;

        ASSERT(is_epte_superpage(ept_entry));

        split_ept_entry = atomic_read_ept_entry(ept_entry);

        if ( !ept_split_super_page(p2m, &split_ept_entry, i, target) )
        {
            ept_free_entry(p2m, &split_ept_entry, i);
            rc = -ENOMEM;
            goto out;
        }

        /* now install the newly split ept sub-tree */
        /* NB: please make sure domian is paused and no in-fly VT-d DMA. */
        rc = atomic_write_ept_entry(ept_entry, split_ept_entry, i);
        ASSERT(rc == 0);

        /* then move to the level we want to make real changes */
        for ( ; i > target; i-- )
            if ( !ept_next_level(p2m, 0, &table, &gfn_remainder, i) )
                break;
        /* We just installed the pages we need. */
        ASSERT(i == target);

        ept_entry = table + (gfn_remainder >> (i * EPT_TABLE_ORDER));
    }

    if ( mfn_valid(mfn_x(mfn)) || p2m_allows_invalid_mfn(p2mt) )
    {
        int emt = epte_get_entry_emt(p2m->domain, gfn, mfn,
                                     i * EPT_TABLE_ORDER, &ipat, direct_mmio);

        if ( emt >= 0 )
            new_entry.emt = emt;
        else /* ept_handle_misconfig() will need to take care of this. */
            new_entry.emt = MTRR_NUM_TYPES;

        new_entry.ipat = ipat;
        new_entry.sp = !!i;
        new_entry.sa_p2mt = p2mt;
        new_entry.access = p2ma;
        new_entry.snp = (iommu_enabled && iommu_snoop);

        /* the caller should take care of the previous page */
        new_entry.mfn = mfn_x(mfn);

        /* Safe to read-then-write because we hold the p2m lock */
        if ( ept_entry->mfn == new_entry.mfn &&
             p2m_get_iommu_flags(ept_entry->sa_p2mt) == iommu_flags )
            need_modify_vtd_table = 0;

        ept_p2m_type_to_flags(p2m, &new_entry, p2mt, p2ma);
    }

    if ( sve != -1 )
        new_entry.suppress_ve = !!sve;
    else
        new_entry.suppress_ve = is_epte_valid(&old_entry) ?
                                    old_entry.suppress_ve : 1;

    rc = atomic_write_ept_entry(ept_entry, new_entry, target);
    if ( unlikely(rc) )
        old_entry.epte = 0;
    else
    {
        entry_written = 1;

        if ( p2mt != p2m_invalid &&
             (gfn + (1UL << order) - 1 > p2m->max_mapped_pfn) )
            /* Track the highest gfn for which we have ever had a valid mapping */
            p2m->max_mapped_pfn = gfn + (1UL << order) - 1;
    }

out:
    if ( needs_sync )
        ept_sync_domain(p2m);

    /* For host p2m, may need to change VT-d page table.*/
    if ( rc == 0 && p2m_is_hostp2m(p2m) && need_iommu(d) &&
         need_modify_vtd_table )
    {
        if ( iommu_hap_pt_share )
            rc = iommu_pte_flush(d, gfn, &ept_entry->epte, order, vtd_pte_present);
        else
        {
            if ( iommu_flags )
                for ( i = 0; i < (1 << order); i++ )
                {
                    rc = iommu_map_page(d, gfn + i, mfn_x(mfn) + i, iommu_flags);
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
                for ( i = 0; i < (1 << order); i++ )
                {
                    ret = iommu_unmap_page(d, gfn + i);
                    if ( !rc )
                        rc = ret;
                }
        }
    }

    unmap_domain_page(table);

    /* Release the old intermediate tables, if any.  This has to be the
       last thing we do, after the ept_sync_domain() and removal
       from the iommu tables, so as to avoid a potential
       use-after-free. */
    if ( is_epte_present(&old_entry) )
        ept_free_entry(p2m, &old_entry, target);

    if ( entry_written && p2m_is_hostp2m(p2m) )
        p2m_altp2m_propagate_change(d, _gfn(gfn), mfn, order, p2mt, p2ma);

    return rc;
}

/* Read ept p2m entries */
static mfn_t ept_get_entry(struct p2m_domain *p2m,
                           unsigned long gfn, p2m_type_t *t, p2m_access_t* a,
                           p2m_query_t q, unsigned int *page_order,
                           bool_t *sve)
{
    ept_entry_t *table = map_domain_page(_mfn(pagetable_get_pfn(p2m_get_pagetable(p2m))));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    u32 index;
    int i;
    int ret = 0;
    bool_t recalc = 0;
    mfn_t mfn = INVALID_MFN;
    struct ept_data *ept = &p2m->ept;

    *t = p2m_mmio_dm;
    *a = p2m_access_n;
    if ( sve )
        *sve = 1;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
    {
        for ( i = ept_get_wl(ept); i > 0; --i )
            if ( (gfn & ~((1UL << (i * EPT_TABLE_ORDER)) - 1)) >
                 p2m->max_mapped_pfn )
                break;
        goto out;
    }

    /* Should check if gfn obeys GAW here. */

    for ( i = ept_get_wl(ept); i > 0; i-- )
    {
    retry:
        if ( table[gfn_remainder >> (i * EPT_TABLE_ORDER)].recalc )
            recalc = 1;
        ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
        if ( !ret )
            goto out;
        else if ( ret == GUEST_TABLE_POD_PAGE )
        {
            if ( !(q & P2M_ALLOC) )
            {
                *t = p2m_populate_on_demand;
                goto out;
            }

            /* Populate this superpage */
            ASSERT(i <= 2);

            index = gfn_remainder >> ( i * EPT_TABLE_ORDER);
            ept_entry = table + index;

            if ( !p2m_pod_demand_populate(p2m, gfn, i * EPT_TABLE_ORDER, q) )
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
        if ( !(q & P2M_ALLOC) )
        {
            *t = p2m_populate_on_demand;
            goto out;
        }

        ASSERT(i == 0);
        
        if ( p2m_pod_demand_populate(p2m, gfn, 
                                        PAGE_ORDER_4K, q) )
            goto out;
    }

    if ( is_epte_valid(ept_entry) )
    {
        if ( (recalc || ept_entry->recalc) &&
             p2m_is_changeable(ept_entry->sa_p2mt) )
            *t = p2m_is_logdirty_range(p2m, gfn, gfn) ? p2m_ram_logdirty
                                                      : p2m_ram_rw;
        else
            *t = ept_entry->sa_p2mt;
        *a = ept_entry->access;
        if ( sve )
            *sve = ept_entry->suppress_ve;

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
    if ( page_order )
        *page_order = i * EPT_TABLE_ORDER;

    unmap_domain_page(table);
    return mfn;
}

void ept_walk_table(struct domain *d, unsigned long gfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct ept_data *ept = &p2m->ept;
    ept_entry_t *table = map_domain_page(_mfn(pagetable_get_pfn(p2m_get_pagetable(p2m))));
    unsigned long gfn_remainder = gfn;

    int i;

    gprintk(XENLOG_ERR, "Walking EPT tables for GFN %lx:\n", gfn);

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
    {
        gprintk(XENLOG_ERR, " gfn exceeds max_mapped_pfn %lx\n",
                p2m->max_mapped_pfn);
        goto out;
    }

    for ( i = ept_get_wl(ept); i >= 0; i-- )
    {
        ept_entry_t *ept_entry, *next;
        u32 index;

        /* Stolen from ept_next_level */
        index = gfn_remainder >> (i*EPT_TABLE_ORDER);
        ept_entry = table + index;

        gprintk(XENLOG_ERR, " epte %"PRIx64"\n", ept_entry->epte);

        if ( (i == 0) || !is_epte_present(ept_entry) ||
             is_epte_superpage(ept_entry) )
            goto out;
        else
        {
            gfn_remainder &= (1UL << (i*EPT_TABLE_ORDER)) - 1;

            next = map_domain_page(_mfn(ept_entry->mfn));

            unmap_domain_page(table);

            table = next;
        }
    }

out:
    unmap_domain_page(table);
    return;
}

static void ept_change_entry_type_global(struct p2m_domain *p2m,
                                         p2m_type_t ot, p2m_type_t nt)
{
    unsigned long mfn = ept_get_asr(&p2m->ept);

    if ( !mfn )
        return;

    if ( ept_invalidate_emt(_mfn(mfn), 1, ept_get_wl(&p2m->ept)) )
        ept_sync_domain(p2m);
}

static int ept_change_entry_type_range(struct p2m_domain *p2m,
                                       p2m_type_t ot, p2m_type_t nt,
                                       unsigned long first_gfn,
                                       unsigned long last_gfn)
{
    unsigned int i, wl = ept_get_wl(&p2m->ept);
    unsigned long mask = (1 << EPT_TABLE_ORDER) - 1;
    int rc = 0, sync = 0;

    if ( !ept_get_asr(&p2m->ept) )
        return -EINVAL;

    for ( i = 0; i <= wl; )
    {
        if ( first_gfn & mask )
        {
            unsigned long end_gfn = min(first_gfn | mask, last_gfn);

            rc = ept_invalidate_emt_range(p2m, i, first_gfn, end_gfn);
            sync |= rc;
            if ( rc < 0 || end_gfn >= last_gfn )
                break;
            first_gfn = end_gfn + 1;
        }
        else if ( (last_gfn & mask) != mask )
        {
            unsigned long start_gfn = max(first_gfn, last_gfn & ~mask);

            rc = ept_invalidate_emt_range(p2m, i, start_gfn, last_gfn);
            sync |= rc;
            if ( rc < 0 || start_gfn <= first_gfn )
                break;
            last_gfn = start_gfn - 1;
        }
        else
        {
            ++i;
            mask |= mask << EPT_TABLE_ORDER;
        }
    }

    if ( sync )
        ept_sync_domain(p2m);

    return rc < 0 ? rc : 0;
}

static void ept_memory_type_changed(struct p2m_domain *p2m)
{
    unsigned long mfn = ept_get_asr(&p2m->ept);

    if ( !mfn )
        return;

    if ( ept_invalidate_emt(_mfn(mfn), 0, ept_get_wl(&p2m->ept)) )
        ept_sync_domain(p2m);
}

static void __ept_sync_domain(void *info)
{
    /*
     * The invalidation will be done before VMENTER (see
     * vmx_vmenter_helper()).
     */
}

static void ept_sync_domain_prepare(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;
    struct ept_data *ept = &p2m->ept;

    if ( nestedhvm_enabled(d) && !p2m_is_nestedp2m(p2m) )
        p2m_flush_nestedp2m(d);

    /*
     * Need to invalidate on all PCPUs because either:
     *
     * a) A VCPU has run and some translations may be cached.
     * b) A VCPU has not run and and the initial invalidation in case
     *    of an EP4TA reuse is still needed.
     */
    cpumask_setall(ept->invalidate);
}

static void ept_sync_domain_mask(struct p2m_domain *p2m, const cpumask_t *mask)
{
    on_selected_cpus(mask, __ept_sync_domain, p2m, 1);
}

void ept_sync_domain(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;

    /* Only if using EPT and this domain has some VCPUs to dirty. */
    if ( !paging_mode_hap(d) || !d->vcpu || !d->vcpu[0] )
        return;

    ept_sync_domain_prepare(p2m);

    if ( p2m->defer_flush )
    {
        p2m->need_flush = 1;
        return;
    }

    ept_sync_domain_mask(p2m, d->domain_dirty_cpumask);
}

static void ept_tlb_flush(struct p2m_domain *p2m)
{
    ept_sync_domain_mask(p2m, p2m->domain->domain_dirty_cpumask);
}

static void ept_enable_pml(struct p2m_domain *p2m)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&p2m->domain->pause_count));

    /*
     * No need to return whether vmx_domain_enable_pml has succeeded, as
     * ept_p2m_type_to_flags will do the check, and write protection will be
     * used if PML is not enabled.
     */
    if ( vmx_domain_enable_pml(p2m->domain) )
        return;

    /* Enable EPT A/D bit for PML */
    p2m->ept.ept_ad = 1;
    vmx_domain_update_eptp(p2m->domain);
}

static void ept_disable_pml(struct p2m_domain *p2m)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&p2m->domain->pause_count));

    vmx_domain_disable_pml(p2m->domain);

    /* Disable EPT A/D bit */
    p2m->ept.ept_ad = 0;
    vmx_domain_update_eptp(p2m->domain);
}

static void ept_flush_pml_buffers(struct p2m_domain *p2m)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&p2m->domain->pause_count));

    vmx_domain_flush_pml_buffers(p2m->domain);
}

int ept_p2m_init(struct p2m_domain *p2m)
{
    struct ept_data *ept = &p2m->ept;

    p2m->set_entry = ept_set_entry;
    p2m->get_entry = ept_get_entry;
    p2m->change_entry_type_global = ept_change_entry_type_global;
    p2m->change_entry_type_range = ept_change_entry_type_range;
    p2m->memory_type_changed = ept_memory_type_changed;
    p2m->audit_p2m = NULL;
    p2m->tlb_flush = ept_tlb_flush;

    /* Set the memory type used when accessing EPT paging structures. */
    ept->ept_mt = EPT_DEFAULT_MT;

    /* set EPT page-walk length, now it's actual walk length - 1, i.e. 3 */
    ept->ept_wl = 3;

    if ( cpu_has_vmx_pml )
    {
        p2m->enable_hardware_log_dirty = ept_enable_pml;
        p2m->disable_hardware_log_dirty = ept_disable_pml;
        p2m->flush_hardware_cached_dirty = ept_flush_pml_buffers;
    }

    if ( !zalloc_cpumask_var(&ept->invalidate) )
        return -ENOMEM;

    /*
     * Assume an initial invalidation is required, in case an EP4TA is
     * reused.
     */
    cpumask_setall(ept->invalidate);

    return 0;
}

void ept_p2m_uninit(struct p2m_domain *p2m)
{
    struct ept_data *ept = &p2m->ept;
    free_cpumask_var(ept->invalidate);
}

static const char *memory_type_to_str(unsigned int x)
{
    static const char memory_types[8][3] = {
        [MTRR_TYPE_UNCACHABLE]     = "UC",
        [MTRR_TYPE_WRCOMB]         = "WC",
        [MTRR_TYPE_WRTHROUGH]      = "WT",
        [MTRR_TYPE_WRPROT]         = "WP",
        [MTRR_TYPE_WRBACK]         = "WB",
        [MTRR_NUM_TYPES]           = "??"
    };

    ASSERT(x < ARRAY_SIZE(memory_types));
    return memory_types[x][0] ? memory_types[x] : "?";
}

static void ept_dump_p2m_table(unsigned char key)
{
    struct domain *d;
    ept_entry_t *table, *ept_entry;
    int order;
    int i;
    int ret = 0;
    unsigned long gfn, gfn_remainder;
    unsigned long record_counter = 0;
    struct p2m_domain *p2m;
    struct ept_data *ept;

    for_each_domain(d)
    {
        if ( !hap_enabled(d) )
            continue;

        p2m = p2m_get_hostp2m(d);
        ept = &p2m->ept;
        printk("\ndomain%d EPT p2m table:\n", d->domain_id);

        for ( gfn = 0; gfn <= p2m->max_mapped_pfn; gfn += 1UL << order )
        {
            char c = 0;

            gfn_remainder = gfn;
            table = map_domain_page(_mfn(pagetable_get_pfn(p2m_get_pagetable(p2m))));

            for ( i = ept_get_wl(ept); i > 0; i-- )
            {
                ept_entry = table + (gfn_remainder >> (i * EPT_TABLE_ORDER));
                if ( ept_entry->emt == MTRR_NUM_TYPES )
                    c = '?';
                ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
                if ( ret != GUEST_TABLE_NORMAL_PAGE )
                    break;
            }

            order = i * EPT_TABLE_ORDER;
            ept_entry = table + (gfn_remainder >> order);
            if ( ret != GUEST_TABLE_MAP_FAILED && is_epte_valid(ept_entry) )
            {
                if ( ept_entry->sa_p2mt == p2m_populate_on_demand )
                    printk("gfn: %13lx order: %2d PoD\n", gfn, order);
                else
                    printk("gfn: %13lx order: %2d mfn: %13lx %c%c%c %c%c%c\n",
                           gfn, order, ept_entry->mfn + 0UL,
                           ept_entry->r ? 'r' : ' ',
                           ept_entry->w ? 'w' : ' ',
                           ept_entry->x ? 'x' : ' ',
                           memory_type_to_str(ept_entry->emt)[0],
                           memory_type_to_str(ept_entry->emt)[1]
                           ?: ept_entry->emt + '0',
                           c ?: ept_entry->ipat ? '!' : ' ');

                if ( !(record_counter++ % 100) )
                    process_pending_softirqs();
            }
            unmap_domain_page(table);
        }
    }
}

void setup_ept_dump(void)
{
    register_keyhandler('D', ept_dump_p2m_table, "dump VT-x EPT tables", 0);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
