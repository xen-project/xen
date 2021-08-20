/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
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

#include <xen/acpi.h>

#include "iommu.h"

/* Given pfn and page table level, return pde index */
static unsigned int pfn_to_pde_idx(unsigned long pfn, unsigned int level)
{
    unsigned int idx;

    idx = pfn >> (PTE_PER_TABLE_SHIFT * (--level));
    idx &= ~PTE_PER_TABLE_MASK;
    return idx;
}

static unsigned int clear_iommu_pte_present(unsigned long l1_mfn,
                                            unsigned long dfn)
{
    union amd_iommu_pte *table, *pte;
    unsigned int flush_flags;

    table = map_domain_page(_mfn(l1_mfn));
    pte = &table[pfn_to_pde_idx(dfn, 1)];

    flush_flags = pte->pr ? IOMMU_FLUSHF_modified : 0;
    write_atomic(&pte->raw, 0);

    unmap_domain_page(table);

    return flush_flags;
}

static unsigned int set_iommu_pde_present(union amd_iommu_pte *pte,
                                          unsigned long next_mfn,
                                          unsigned int next_level, bool iw,
                                          bool ir)
{
    union amd_iommu_pte new = {}, old;
    unsigned int flush_flags = IOMMU_FLUSHF_added;

    /*
     * FC bit should be enabled in PTE, this helps to solve potential
     * issues with ATS devices
     */
    new.fc = !next_level;

    new.mfn = next_mfn;
    new.iw = iw;
    new.ir = ir;
    new.next_level = next_level;
    new.pr = true;

    old.raw = read_atomic(&pte->raw);
    old.ign0 = 0;
    old.ign1 = 0;
    old.ign2 = 0;

    if ( old.pr && old.raw != new.raw )
        flush_flags |= IOMMU_FLUSHF_modified;

    write_atomic(&pte->raw, new.raw);

    return flush_flags;
}

static unsigned int set_iommu_ptes_present(unsigned long pt_mfn,
                                           unsigned long dfn,
                                           unsigned long next_mfn,
                                           unsigned int nr_ptes,
                                           unsigned int pde_level,
                                           bool iw, bool ir)
{
    union amd_iommu_pte *table, *pde;
    unsigned int page_sz, flush_flags = 0;

    table = map_domain_page(_mfn(pt_mfn));
    pde = &table[pfn_to_pde_idx(dfn, pde_level)];
    page_sz = 1U << (PTE_PER_TABLE_SHIFT * (pde_level - 1));

    if ( (void *)(pde + nr_ptes) > (void *)table + PAGE_SIZE )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    while ( nr_ptes-- )
    {
        flush_flags |= set_iommu_pde_present(pde, next_mfn, 0, iw, ir);

        ++pde;
        next_mfn += page_sz;
    }

    unmap_domain_page(table);

    return flush_flags;
}

void amd_iommu_set_root_page_table(struct amd_iommu_dte *dte,
                                   uint64_t root_ptr, uint16_t domain_id,
                                   uint8_t paging_mode, bool valid)
{
    if ( valid || dte->v )
    {
        dte->tv = false;
        dte->v = true;
        smp_wmb();
    }
    dte->domain_id = domain_id;
    dte->pt_root = paddr_to_pfn(root_ptr);
    dte->iw = true;
    dte->ir = true;
    dte->paging_mode = paging_mode;
    smp_wmb();
    dte->tv = true;
    dte->v = valid;
}

void amd_iommu_set_intremap_table(
    struct amd_iommu_dte *dte, const void *ptr,
    const struct amd_iommu *iommu, bool valid)
{
    if ( ptr )
    {
        dte->it_root = virt_to_maddr(ptr) >> 6;
        dte->int_tab_len = amd_iommu_intremap_table_order(ptr, iommu);
        dte->int_ctl = IOMMU_DEV_TABLE_INT_CONTROL_TRANSLATED;
    }
    else
    {
        dte->it_root = 0;
        dte->int_tab_len = 0;
        dte->int_ctl = IOMMU_DEV_TABLE_INT_CONTROL_ABORTED;
    }

    dte->ig = false; /* unmapped interrupts result in i/o page faults */
    smp_wmb();
    dte->iv = valid;
}

void __init iommu_dte_add_device_entry(struct amd_iommu_dte *dte,
                                       const struct ivrs_mappings *ivrs_dev)
{
    uint8_t flags = ivrs_dev->device_flags;

    *dte = (struct amd_iommu_dte){
        .init_pass = flags & ACPI_IVHD_INIT_PASS,
        .ext_int_pass = flags & ACPI_IVHD_EINT_PASS,
        .nmi_pass = flags & ACPI_IVHD_NMI_PASS,
        .lint0_pass = flags & ACPI_IVHD_LINT0_PASS,
        .lint1_pass = flags & ACPI_IVHD_LINT1_PASS,
        .ioctl = IOMMU_DEV_TABLE_IO_CONTROL_ABORTED,
        .sys_mgt = MASK_EXTR(flags, ACPI_IVHD_SYSTEM_MGMT),
        .ex = ivrs_dev->dte_allow_exclusion,
    };
}

/* Walk io page tables and build level page tables if necessary
 * {Re, un}mapping super page frames causes re-allocation of io
 * page tables.
 */
static int iommu_pde_from_dfn(struct domain *d, unsigned long dfn,
                              unsigned long pt_mfn[], bool map)
{
    union amd_iommu_pte *pde, *next_table_vaddr;
    unsigned long  next_table_mfn;
    unsigned int level;
    struct page_info *table;
    const struct domain_iommu *hd = dom_iommu(d);

    table = hd->arch.amd.root_table;
    level = hd->arch.amd.paging_mode;

    BUG_ON( table == NULL || level < 1 || level > 6 );

    /*
     * A frame number past what the current page tables can represent can't
     * possibly have a mapping.
     */
    if ( dfn >> (PTE_PER_TABLE_SHIFT * level) )
        return 0;

    next_table_mfn = mfn_x(page_to_mfn(table));

    while ( level > 1 )
    {
        unsigned int next_level = level - 1;
        pt_mfn[level] = next_table_mfn;

        next_table_vaddr = map_domain_page(_mfn(next_table_mfn));
        pde = &next_table_vaddr[pfn_to_pde_idx(dfn, level)];

        /* Here might be a super page frame */
        next_table_mfn = pde->mfn;

        /* Split super page frame into smaller pieces.*/
        if ( pde->pr && !pde->next_level && next_table_mfn )
        {
            unsigned long mfn, pfn;

            pfn =  dfn & ~((1 << (PTE_PER_TABLE_SHIFT * next_level)) - 1);
            mfn = next_table_mfn;

            /* allocate lower level page table */
            table = iommu_alloc_pgtable(d);
            if ( table == NULL )
            {
                AMD_IOMMU_DEBUG("Cannot allocate I/O page table\n");
                unmap_domain_page(next_table_vaddr);
                return 1;
            }

            next_table_mfn = mfn_x(page_to_mfn(table));

            set_iommu_ptes_present(next_table_mfn, pfn, mfn, PTE_PER_TABLE_SIZE,
                                   next_level, pde->iw, pde->ir);
            smp_wmb();
            set_iommu_pde_present(pde, next_table_mfn, next_level, true,
                                  true);

            amd_iommu_flush_all_pages(d);
        }

        /* Install lower level page table for non-present entries */
        else if ( !pde->pr )
        {
            if ( !map )
            {
                unmap_domain_page(next_table_vaddr);
                return 0;
            }

            if ( next_table_mfn == 0 )
            {
                table = iommu_alloc_pgtable(d);
                if ( table == NULL )
                {
                    AMD_IOMMU_DEBUG("Cannot allocate I/O page table\n");
                    unmap_domain_page(next_table_vaddr);
                    return 1;
                }
                next_table_mfn = mfn_x(page_to_mfn(table));
                set_iommu_pde_present(pde, next_table_mfn, next_level, true,
                                      true);
            }
            else /* should never reach here */
            {
                unmap_domain_page(next_table_vaddr);
                return 1;
            }
        }

        unmap_domain_page(next_table_vaddr);
        level--;
    }

    /* mfn of level 1 page table */
    pt_mfn[level] = next_table_mfn;
    return 0;
}

int amd_iommu_map_page(struct domain *d, dfn_t dfn, mfn_t mfn,
                       unsigned int flags, unsigned int *flush_flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    int rc;
    unsigned long pt_mfn[7];

    memset(pt_mfn, 0, sizeof(pt_mfn));

    spin_lock(&hd->arch.mapping_lock);

    /*
     * IOMMU mapping request can be safely ignored when the domain is dying.
     *
     * hd->arch.mapping_lock guarantees that d->is_dying will be observed
     * before any page tables are freed (see iommu_free_pgtables()).
     */
    if ( d->is_dying )
    {
        spin_unlock(&hd->arch.mapping_lock);
        return 0;
    }

    rc = amd_iommu_alloc_root(d);
    if ( rc )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_DEBUG("Root table alloc failed, dfn = %"PRI_dfn"\n",
                        dfn_x(dfn));
        domain_crash(d);
        return rc;
    }

    if ( iommu_pde_from_dfn(d, dfn_x(dfn), pt_mfn, true) || (pt_mfn[1] == 0) )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_DEBUG("Invalid IO pagetable entry dfn = %"PRI_dfn"\n",
                        dfn_x(dfn));
        domain_crash(d);
        return -EFAULT;
    }

    /* Install 4k mapping */
    *flush_flags |= set_iommu_ptes_present(pt_mfn[1], dfn_x(dfn), mfn_x(mfn),
                                           1, 1, (flags & IOMMUF_writable),
                                           (flags & IOMMUF_readable));

    spin_unlock(&hd->arch.mapping_lock);

    return 0;
}

int amd_iommu_unmap_page(struct domain *d, dfn_t dfn,
                         unsigned int *flush_flags)
{
    unsigned long pt_mfn[7];
    struct domain_iommu *hd = dom_iommu(d);

    memset(pt_mfn, 0, sizeof(pt_mfn));

    spin_lock(&hd->arch.mapping_lock);

    if ( !hd->arch.amd.root_table )
    {
        spin_unlock(&hd->arch.mapping_lock);
        return 0;
    }

    if ( iommu_pde_from_dfn(d, dfn_x(dfn), pt_mfn, false) )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_DEBUG("Invalid IO pagetable entry dfn = %"PRI_dfn"\n",
                        dfn_x(dfn));
        domain_crash(d);
        return -EFAULT;
    }

    if ( pt_mfn[1] )
    {
        /* Mark PTE as 'page not present'. */
        *flush_flags |= clear_iommu_pte_present(pt_mfn[1], dfn_x(dfn));
    }

    spin_unlock(&hd->arch.mapping_lock);

    return 0;
}

static unsigned long flush_count(unsigned long dfn, unsigned long page_count,
                                 unsigned int order)
{
    unsigned long start = dfn >> order;
    unsigned long end = ((dfn + page_count - 1) >> order) + 1;

    ASSERT(end > start);
    return end - start;
}

int amd_iommu_flush_iotlb_pages(struct domain *d, dfn_t dfn,
                                unsigned long page_count,
                                unsigned int flush_flags)
{
    unsigned long dfn_l = dfn_x(dfn);

    ASSERT(page_count && !dfn_eq(dfn, INVALID_DFN));
    ASSERT(flush_flags);

    /* Unless a PTE was modified, no flush is required */
    if ( !(flush_flags & IOMMU_FLUSHF_modified) )
        return 0;

    /* If the range wraps then just flush everything */
    if ( dfn_l + page_count < dfn_l )
    {
        amd_iommu_flush_all_pages(d);
        return 0;
    }

    /*
     * Flushes are expensive so find the minimal single flush that will
     * cover the page range.
     *
     * NOTE: It is unnecessary to round down the DFN value to align with
     *       the flush order here. This is done by the internals of the
     *       flush code.
     */
    if ( page_count == 1 ) /* order 0 flush count */
        amd_iommu_flush_pages(d, dfn_l, 0);
    else if ( flush_count(dfn_l, page_count, 9) == 1 )
        amd_iommu_flush_pages(d, dfn_l, 9);
    else if ( flush_count(dfn_l, page_count, 18) == 1 )
        amd_iommu_flush_pages(d, dfn_l, 18);
    else
        amd_iommu_flush_all_pages(d);

    return 0;
}

int amd_iommu_flush_iotlb_all(struct domain *d)
{
    amd_iommu_flush_all_pages(d);

    return 0;
}

int amd_iommu_reserve_domain_unity_map(struct domain *domain,
                                       paddr_t phys_addr,
                                       unsigned long size, int iw, int ir)
{
    unsigned long npages, i;
    unsigned long gfn;
    unsigned int flags = !!ir;
    unsigned int flush_flags = 0;
    int rt = 0;

    if ( iw )
        flags |= IOMMUF_writable;

    npages = region_to_pages(phys_addr, size);
    gfn = phys_addr >> PAGE_SHIFT;
    for ( i = 0; i < npages; i++ )
    {
        unsigned long frame = gfn + i;

        rt = amd_iommu_map_page(domain, _dfn(frame), _mfn(frame), flags,
                                &flush_flags);
        if ( rt != 0 )
            break;
    }

    /* Use while-break to avoid compiler warning */
    while ( flush_flags &&
            amd_iommu_flush_iotlb_pages(domain, _dfn(gfn),
                                        npages, flush_flags) )
        break;

    return rt;
}

int __init amd_iommu_quarantine_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long end_gfn =
        1ul << (DEFAULT_DOMAIN_ADDRESS_WIDTH - PAGE_SHIFT);
    unsigned int level = amd_iommu_get_paging_mode(end_gfn);
    union amd_iommu_pte *table;

    if ( hd->arch.amd.root_table )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    spin_lock(&hd->arch.mapping_lock);

    hd->arch.amd.root_table = iommu_alloc_pgtable(d);
    if ( !hd->arch.amd.root_table )
        goto out;

    table = __map_domain_page(hd->arch.amd.root_table);
    while ( level )
    {
        struct page_info *pg;
        unsigned int i;

        /*
         * The pgtable allocator is fine for the leaf page, as well as
         * page table pages, and the resulting allocations are always
         * zeroed.
         */
        pg = iommu_alloc_pgtable(d);
        if ( !pg )
            break;

        for ( i = 0; i < PTE_PER_TABLE_SIZE; i++ )
        {
            union amd_iommu_pte *pde = &table[i];

            /*
             * PDEs are essentially a subset of PTEs, so this function
             * is fine to use even at the leaf.
             */
            set_iommu_pde_present(pde, mfn_x(page_to_mfn(pg)), level - 1,
                                  false, true);
        }

        unmap_domain_page(table);
        table = __map_domain_page(pg);
        level--;
    }
    unmap_domain_page(table);

 out:
    spin_unlock(&hd->arch.mapping_lock);

    amd_iommu_flush_all_pages(d);

    /* Pages leaked in failure case */
    return level ? -ENOMEM : 0;
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
