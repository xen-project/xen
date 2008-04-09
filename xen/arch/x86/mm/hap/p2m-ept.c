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
#include <asm/types.h>
#include <asm/domain.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h>
#include <xen/iommu.h>

static int ept_next_level(struct domain *d, bool_t read_only,
                          ept_entry_t **table, unsigned long *gfn_remainder,
                          u32 shift)
{
    ept_entry_t *ept_entry, *next;
    u32 index;

    index = *gfn_remainder >> shift;
    *gfn_remainder &= (1UL << shift) - 1;

    ept_entry = (*table) + index;

    if ( !(ept_entry->epte & 0x7) )
    {
        struct page_info *pg;

        if ( read_only )
            return 0;

        pg = d->arch.p2m->alloc_page(d);
        if ( pg == NULL )
            return 0;

        pg->count_info = 1;
        pg->u.inuse.type_info = 1 | PGT_validated;
        list_add_tail(&pg->list, &d->arch.p2m->pages);

        ept_entry->emt = 0;
        ept_entry->sp_avail = 0;
        ept_entry->avail1 = 0;
        ept_entry->mfn = page_to_mfn(pg);
        ept_entry->rsvd = 0;
        ept_entry->avail2 = 0;
        /* last step */
        ept_entry->r = ept_entry->w = ept_entry->x = 1;
    }

    next = map_domain_page(ept_entry->mfn);
    unmap_domain_page(*table);
    *table = next;

    return 1;
}

static int
ept_set_entry(struct domain *d, unsigned long gfn, mfn_t mfn, p2m_type_t p2mt)
{
    ept_entry_t *table =
        map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry = NULL;
    u32 index;
    int i, rv = 0;

    /* Should check if gfn obeys GAW here */

    for ( i = EPT_DEFAULT_GAW; i > 0; i-- )
        if ( !ept_next_level(d, 0, &table, &gfn_remainder,
                             i * EPT_TABLE_ORDER) )
            goto out;

    index = gfn_remainder;
    ept_entry = table + index;

    if ( mfn_valid(mfn_x(mfn)) || (p2mt == p2m_mmio_direct) )
    {
        /* Track the highest gfn for which we have ever had a valid mapping */
        if ( gfn > d->arch.p2m->max_mapped_pfn )
            d->arch.p2m->max_mapped_pfn = gfn;

        ept_entry->emt = EPT_DEFAULT_MT;
        ept_entry->sp_avail = 0;
        ept_entry->avail1 = p2mt;
        ept_entry->mfn = mfn_x(mfn);
        ept_entry->rsvd = 0;
        ept_entry->avail2 = 0;
        /* last step */
        ept_entry->r = ept_entry->w = ept_entry->x = 1;
    }
    else
        ept_entry->epte = 0;

    /* Success */
    rv = 1;

 out:
    unmap_domain_page(table);

    ept_sync_domain(d);

    /* If p2m table is shared with vtd page-table. */
    if ( iommu_enabled && is_hvm_domain(d) && (p2mt == p2m_mmio_direct) )
        iommu_flush(d, gfn, (u64*)ept_entry);

    return rv;
}

/* Read ept p2m entries */
static mfn_t ept_get_entry(struct domain *d, unsigned long gfn, p2m_type_t *t)
{
    ept_entry_t *table =
        map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    u32 index;
    int i;
    mfn_t mfn = _mfn(INVALID_MFN);

    *t = p2m_mmio_dm;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > d->arch.p2m->max_mapped_pfn )
        goto out;

    /* Should check if gfn obeys GAW here. */

    for ( i = EPT_DEFAULT_GAW; i > 0; i-- )
        if ( !ept_next_level(d, 1, &table, &gfn_remainder,
                             i * EPT_TABLE_ORDER) )
            goto out;

    index = gfn_remainder;
    ept_entry = table + index;

    if ( (ept_entry->epte & 0x7) == 0x7 )
    {
        if ( ept_entry->avail1 != p2m_invalid )
        {
            *t = ept_entry->avail1;
            mfn = _mfn(ept_entry->mfn);
        }
    }

 out:
    unmap_domain_page(table);
    return mfn;
}

static mfn_t ept_get_entry_current(unsigned long gfn, p2m_type_t *t)
{
    return ept_get_entry(current->domain, gfn, t);
}

void ept_p2m_init(struct domain *d)
{
    d->arch.p2m->set_entry = ept_set_entry;
    d->arch.p2m->get_entry = ept_get_entry;
    d->arch.p2m->get_entry_current = ept_get_entry_current;
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
