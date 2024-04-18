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

#define CONTIG_MASK IOMMU_PTE_CONTIG_MASK
#include <asm/pt-contig-markers.h>

/* Given pfn and page table level, return pde index */
static unsigned int pfn_to_pde_idx(unsigned long pfn, unsigned int level)
{
    unsigned int idx;

    idx = pfn >> (PTE_PER_TABLE_SHIFT * (--level));
    idx &= ~PTE_PER_TABLE_MASK;
    return idx;
}

static union amd_iommu_pte clear_iommu_pte_present(unsigned long l1_mfn,
                                                   unsigned long dfn,
                                                   unsigned int level,
                                                   bool *free)
{
    union amd_iommu_pte *table, *pte, old;
    unsigned int idx = pfn_to_pde_idx(dfn, level);

    table = map_domain_page(_mfn(l1_mfn));
    pte = &table[idx];
    old = *pte;

    write_atomic(&pte->raw, 0);

    *free = pt_update_contig_markers(&table->raw, idx, level, PTE_kind_null);

    unmap_domain_page(table);

    return old;
}

static void set_iommu_pde_present(union amd_iommu_pte *pte,
                                  unsigned long next_mfn,
                                  unsigned int next_level,
                                  bool iw, bool ir)
{
    union amd_iommu_pte new = {};

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

    write_atomic(&pte->raw, new.raw);
}

static union amd_iommu_pte set_iommu_pte_present(unsigned long pt_mfn,
                                                 unsigned long dfn,
                                                 unsigned long next_mfn,
                                                 unsigned int level,
                                                 bool iw, bool ir,
                                                 bool *contig)
{
    union amd_iommu_pte *table, *pde, old;

    table = map_domain_page(_mfn(pt_mfn));
    pde = &table[pfn_to_pde_idx(dfn, level)];

    old = *pde;
    if ( !old.pr || old.next_level ||
         old.mfn != next_mfn ||
         old.iw != iw || old.ir != ir )
    {
        set_iommu_pde_present(pde, next_mfn, 0, iw, ir);
        *contig = pt_update_contig_markers(&table->raw,
                                           pfn_to_pde_idx(dfn, level),
                                           level, PTE_kind_leaf);
    }
    else
    {
        old.pr = false; /* signal "no change" to the caller */
        *contig = false;
    }

    unmap_domain_page(table);

    return old;
}

static void set_iommu_ptes_present(unsigned long pt_mfn,
                                   unsigned long dfn,
                                   unsigned long next_mfn,
                                   unsigned int nr_ptes,
                                   unsigned int pde_level,
                                   bool iw, bool ir)
{
    union amd_iommu_pte *table, *pde;
    unsigned long page_sz = 1UL << (PTE_PER_TABLE_SHIFT * (pde_level - 1));

    table = map_domain_page(_mfn(pt_mfn));
    pde = &table[pfn_to_pde_idx(dfn, pde_level)];

    if ( (void *)(pde + nr_ptes) > (void *)table + PAGE_SIZE )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    ASSERT(!(next_mfn & (page_sz - 1)));

    while ( nr_ptes-- )
    {
        ASSERT(!pde->next_level);
        ASSERT(!pde->u);

        if ( pde > table )
            ASSERT(pde->ign0 == ffs(pde - table) - 1);
        else
            ASSERT(pde->ign0 == CONTIG_LEVEL_SHIFT);

        pde->iw = iw;
        pde->ir = ir;
        pde->fc = true; /* See set_iommu_pde_present(). */
        pde->mfn = next_mfn;
        pde->pr = true;

        ++pde;
        next_mfn += page_sz;
    }

    unmap_domain_page(table);
}

/*
 * This function returns
 * - -errno for errors,
 * - 0 for a successful update, atomic when necessary
 * - 1 for a successful but non-atomic update, which may need to be warned
 *   about by the caller.
 */
int amd_iommu_set_root_page_table(struct amd_iommu_dte *dte,
                                  uint64_t root_ptr, uint16_t domain_id,
                                  uint8_t paging_mode, unsigned int flags)
{
    bool valid = flags & SET_ROOT_VALID;

    if ( dte->v && dte->tv )
    {
        union {
            struct amd_iommu_dte dte;
            uint64_t raw64[4];
            __uint128_t raw128[2];
        } ldte = { .dte = *dte };
        __uint128_t res, old = ldte.raw128[0];
        int ret = 0;

        ldte.dte.domain_id = domain_id;
        ldte.dte.pt_root = paddr_to_pfn(root_ptr);
        ldte.dte.iw = true;
        ldte.dte.ir = true;
        ldte.dte.paging_mode = paging_mode;
        ldte.dte.v = valid;

        res = cmpxchg16b(dte, &old, &ldte.raw128[0]);

        /*
         * Hardware does not update the DTE behind our backs, so the
         * return value should match "old".
         */
        if ( res != old )
        {
            printk(XENLOG_ERR
                   "Dom%d: unexpected DTE %016lx_%016lx (expected %016lx_%016lx)\n",
                   domain_id,
                   (uint64_t)(res >> 64), (uint64_t)res,
                   (uint64_t)(old >> 64), (uint64_t)old);
            ret = -EILSEQ;
        }

        return ret;
    }

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

    return 0;
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
                              unsigned int target, unsigned long *pt_mfn,
                              unsigned int *flush_flags, bool map)
{
    union amd_iommu_pte *pde, *next_table_vaddr;
    unsigned long  next_table_mfn;
    unsigned int level;
    struct page_info *table;
    struct domain_iommu *hd = dom_iommu(d);

    table = hd->arch.amd.root_table;
    level = hd->arch.amd.paging_mode;

    if ( !table || target < 1 || level < target || level > 6 )
    {
        ASSERT_UNREACHABLE();
        return 1;
    }

    /*
     * A frame number past what the current page tables can represent can't
     * possibly have a mapping.
     */
    if ( dfn >> (PTE_PER_TABLE_SHIFT * level) )
        return 0;

    next_table_mfn = mfn_x(page_to_mfn(table));

    while ( level > target )
    {
        unsigned int next_level = level - 1;

        next_table_vaddr = map_domain_page(_mfn(next_table_mfn));
        pde = &next_table_vaddr[pfn_to_pde_idx(dfn, level)];

        /* Here might be a super page frame */
        next_table_mfn = pde->mfn;

        /* Split super page frame into smaller pieces.*/
        if ( pde->pr && !pde->next_level && next_table_mfn )
        {
            unsigned long mfn, pfn;

            pfn = dfn & ~((1UL << (PTE_PER_TABLE_SHIFT * next_level)) - 1);
            mfn = next_table_mfn;

            /* allocate lower level page table */
            table = iommu_alloc_pgtable(hd, IOMMU_PTE_CONTIG_MASK);
            if ( table == NULL )
            {
                AMD_IOMMU_ERROR("cannot allocate I/O page table\n");
                unmap_domain_page(next_table_vaddr);
                return 1;
            }

            next_table_mfn = mfn_x(page_to_mfn(table));

            set_iommu_ptes_present(next_table_mfn, pfn, mfn, PTE_PER_TABLE_SIZE,
                                   next_level, pde->iw, pde->ir);
            smp_wmb();
            set_iommu_pde_present(pde, next_table_mfn, next_level, true,
                                  true);
            pt_update_contig_markers(&next_table_vaddr->raw,
                                     pfn_to_pde_idx(dfn, level),
                                     level, PTE_kind_table);

            *flush_flags |= IOMMU_FLUSHF_modified;

            perfc_incr(iommu_pt_shatters);
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
                table = iommu_alloc_pgtable(hd, IOMMU_PTE_CONTIG_MASK);
                if ( table == NULL )
                {
                    AMD_IOMMU_ERROR("cannot allocate I/O page table\n");
                    unmap_domain_page(next_table_vaddr);
                    return 1;
                }
                next_table_mfn = mfn_x(page_to_mfn(table));
                set_iommu_pde_present(pde, next_table_mfn, next_level, true,
                                      true);
                pt_update_contig_markers(&next_table_vaddr->raw,
                                         pfn_to_pde_idx(dfn, level),
                                         level, PTE_kind_table);
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

    /* mfn of target level page table */
    *pt_mfn = next_table_mfn;
    return 0;
}

static void queue_free_pt(struct domain_iommu *hd, mfn_t mfn, unsigned int level)
{
    if ( level > 1 )
    {
        union amd_iommu_pte *pt = map_domain_page(mfn);
        unsigned int i;

        for ( i = 0; i < PTE_PER_TABLE_SIZE; ++i )
            if ( pt[i].pr && pt[i].next_level )
            {
                ASSERT(pt[i].next_level < level);
                queue_free_pt(hd, _mfn(pt[i].mfn), pt[i].next_level);
            }

        unmap_domain_page(pt);
    }

    iommu_queue_free_pgtable(hd, mfn_to_page(mfn));
}

int cf_check amd_iommu_map_page(
    struct domain *d, dfn_t dfn, mfn_t mfn, unsigned int flags,
    unsigned int *flush_flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned int level = (IOMMUF_order(flags) / PTE_PER_TABLE_SHIFT) + 1;
    bool contig;
    int rc;
    unsigned long pt_mfn = 0;
    union amd_iommu_pte old;

    ASSERT((hd->platform_ops->page_sizes >> IOMMUF_order(flags)) &
           PAGE_SIZE_4K);

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
        AMD_IOMMU_ERROR("root table alloc failed, dfn = %"PRI_dfn"\n",
                        dfn_x(dfn));
        domain_crash(d);
        return rc;
    }

    if ( iommu_pde_from_dfn(d, dfn_x(dfn), level, &pt_mfn, flush_flags, true) ||
         !pt_mfn )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_ERROR("invalid IO pagetable entry dfn = %"PRI_dfn"\n",
                        dfn_x(dfn));
        domain_crash(d);
        return -EFAULT;
    }

    /* Install mapping */
    old = set_iommu_pte_present(pt_mfn, dfn_x(dfn), mfn_x(mfn), level,
                                flags & IOMMUF_writable,
                                flags & IOMMUF_readable, &contig);

    while ( unlikely(contig) && ++level < hd->arch.amd.paging_mode )
    {
        struct page_info *pg = mfn_to_page(_mfn(pt_mfn));
        unsigned long next_mfn;

        if ( iommu_pde_from_dfn(d, dfn_x(dfn), level, &pt_mfn, flush_flags,
                                false) )
            BUG();
        BUG_ON(!pt_mfn);

        next_mfn = mfn_x(mfn) & (~0UL << (PTE_PER_TABLE_SHIFT * (level - 1)));
        set_iommu_pte_present(pt_mfn, dfn_x(dfn), next_mfn, level,
                              flags & IOMMUF_writable,
                              flags & IOMMUF_readable, &contig);
        *flush_flags |= IOMMU_FLUSHF_modified | IOMMU_FLUSHF_all;
        iommu_queue_free_pgtable(hd, pg);
        perfc_incr(iommu_pt_coalesces);
    }

    spin_unlock(&hd->arch.mapping_lock);

    *flush_flags |= IOMMU_FLUSHF_added;
    if ( old.pr )
    {
        *flush_flags |= IOMMU_FLUSHF_modified;

        if ( IOMMUF_order(flags) && old.next_level )
            queue_free_pt(hd, _mfn(old.mfn), old.next_level);
    }

    return 0;
}

int cf_check amd_iommu_unmap_page(
    struct domain *d, dfn_t dfn, unsigned int order, unsigned int *flush_flags)
{
    unsigned long pt_mfn = 0;
    struct domain_iommu *hd = dom_iommu(d);
    unsigned int level = (order / PTE_PER_TABLE_SHIFT) + 1;
    union amd_iommu_pte old = {};

    /*
     * While really we could unmap at any granularity, for now we assume unmaps
     * are issued by common code only at the same granularity as maps.
     */
    ASSERT((hd->platform_ops->page_sizes >> order) & PAGE_SIZE_4K);

    spin_lock(&hd->arch.mapping_lock);

    if ( !hd->arch.amd.root_table )
    {
        spin_unlock(&hd->arch.mapping_lock);
        return 0;
    }

    if ( iommu_pde_from_dfn(d, dfn_x(dfn), level, &pt_mfn, flush_flags, false) )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_ERROR("invalid IO pagetable entry dfn = %"PRI_dfn"\n",
                        dfn_x(dfn));
        domain_crash(d);
        return -EFAULT;
    }

    if ( pt_mfn )
    {
        bool free;

        /* Mark PTE as 'page not present'. */
        old = clear_iommu_pte_present(pt_mfn, dfn_x(dfn), level, &free);

        while ( unlikely(free) && ++level < hd->arch.amd.paging_mode )
        {
            struct page_info *pg = mfn_to_page(_mfn(pt_mfn));

            if ( iommu_pde_from_dfn(d, dfn_x(dfn), level, &pt_mfn,
                                    flush_flags, false) )
                BUG();
            BUG_ON(!pt_mfn);

            clear_iommu_pte_present(pt_mfn, dfn_x(dfn), level, &free);
            *flush_flags |= IOMMU_FLUSHF_all;
            iommu_queue_free_pgtable(hd, pg);
            perfc_incr(iommu_pt_coalesces);
        }
    }

    spin_unlock(&hd->arch.mapping_lock);

    if ( old.pr )
    {
        *flush_flags |= IOMMU_FLUSHF_modified;

        if ( order && old.next_level )
            queue_free_pt(hd, _mfn(old.mfn), old.next_level);
    }

    return 0;
}

void amd_iommu_print_entries(const struct amd_iommu *iommu, unsigned int dev_id,
                             dfn_t dfn)
{
    mfn_t pt_mfn;
    unsigned int level;
    const struct amd_iommu_dte *dt = iommu->dev_table.buffer;

    if ( !dt[dev_id].tv )
    {
        printk("%pp: no root\n", &PCI_SBDF(iommu->seg, dev_id));
        return;
    }

    pt_mfn = _mfn(dt[dev_id].pt_root);
    level = dt[dev_id].paging_mode;
    printk("%pp root @ %"PRI_mfn" (%u levels) dfn=%"PRI_dfn"\n",
           &PCI_SBDF(iommu->seg, dev_id), mfn_x(pt_mfn), level, dfn_x(dfn));

    while ( level )
    {
        const union amd_iommu_pte *pt = map_domain_page(pt_mfn);
        unsigned int idx = pfn_to_pde_idx(dfn_x(dfn), level);
        union amd_iommu_pte pte = pt[idx];

        unmap_domain_page(pt);

        printk("  L%u[%03x] = %"PRIx64" %c%c\n", level, idx, pte.raw,
               pte.pr ? pte.ir ? 'r' : '-' : 'n',
               pte.pr ? pte.iw ? 'w' : '-' : 'p');

        if ( !pte.pr )
            break;

        if ( pte.next_level >= level )
        {
            printk("  L%u[%03x]: next: %u\n", level, idx, pte.next_level);
            break;
        }

        pt_mfn = _mfn(pte.mfn);
        level = pte.next_level;
    }
}

static unsigned long flush_count(unsigned long dfn, unsigned long page_count,
                                 unsigned int order)
{
    unsigned long start = dfn >> order;
    unsigned long end = ((dfn + page_count - 1) >> order) + 1;

    ASSERT(end > start);
    return end - start;
}

int cf_check amd_iommu_flush_iotlb_pages(
    struct domain *d, dfn_t dfn, unsigned long page_count,
    unsigned int flush_flags)
{
    unsigned long dfn_l = dfn_x(dfn);

    if ( !(flush_flags & IOMMU_FLUSHF_all) )
    {
        ASSERT(page_count && !dfn_eq(dfn, INVALID_DFN));
        ASSERT(flush_flags);
    }

    /* Unless a PTE was modified, no flush is required */
    if ( !(flush_flags & IOMMU_FLUSHF_modified) )
        return 0;

    /* If so requested or if the range wraps then just flush everything. */
    if ( (flush_flags & IOMMU_FLUSHF_all) || dfn_l + page_count < dfn_l )
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

int amd_iommu_reserve_domain_unity_map(struct domain *d,
                                       const struct ivrs_unity_map *map,
                                       unsigned int flag)
{
    int rc;

    if ( d == dom_io )
        return 0;

    for ( rc = 0; !rc && map; map = map->next )
    {
        p2m_access_t p2ma = p2m_access_n;

        if ( map->read )
            p2ma |= p2m_access_r;
        if ( map->write )
            p2ma |= p2m_access_w;

        rc = iommu_identity_mapping(d, p2ma, map->addr,
                                    map->addr + map->length - 1, flag);
    }

    return rc;
}

int amd_iommu_reserve_domain_unity_unmap(struct domain *d,
                                         const struct ivrs_unity_map *map)
{
    int rc;

    if ( d == dom_io )
        return 0;

    for ( rc = 0; map; map = map->next )
    {
        int ret = iommu_identity_mapping(d, p2m_access_x, map->addr,
                                         map->addr + map->length - 1, 0);

        if ( ret && ret != -ENOENT && !rc )
            rc = ret;
    }

    return rc;
}

int cf_check amd_iommu_get_reserved_device_memory(
    iommu_grdm_t *func, void *ctxt)
{
    unsigned int seg = 0 /* XXX */, bdf;
    const struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(seg);
    /* At least for global entries, avoid reporting them multiple times. */
    enum { pending, processing, done } global = pending;

    for ( bdf = 0; bdf < ivrs_bdf_entries; ++bdf )
    {
        pci_sbdf_t sbdf = PCI_SBDF(seg, bdf);
        const struct ivrs_unity_map *um = ivrs_mappings[bdf].unity_map;
        unsigned int req = ivrs_mappings[bdf].dte_requestor_id;
        const struct amd_iommu *iommu = ivrs_mappings[bdf].iommu;
        int rc;

        if ( !iommu )
        {
            /* May need to trigger the workaround in find_iommu_for_device(). */
            const struct pci_dev *pdev;

            pcidevs_lock();
            pdev = pci_get_pdev(NULL, sbdf);
            pcidevs_unlock();

            if ( pdev )
                iommu = find_iommu_for_device(seg, bdf);
            if ( !iommu )
                continue;
        }

        if ( func(0, 0, sbdf.sbdf, ctxt) )
        {
            /*
             * When the caller processes a XENMEM_RDM_ALL request, don't report
             * multiple times the same range(s) for perhaps many devices with
             * the same alias ID.
             */
            if ( bdf != req && ivrs_mappings[req].iommu &&
                 func(0, 0, PCI_SBDF(seg, req).sbdf, ctxt) )
                continue;

            if ( global == pending )
                global = processing;
        }

        if ( iommu->exclusion_enable &&
             (iommu->exclusion_allow_all ?
              global == processing :
              ivrs_mappings[bdf].dte_allow_exclusion) )
        {
            rc = func(PFN_DOWN(iommu->exclusion_base),
                      PFN_UP(iommu->exclusion_limit | 1) -
                      PFN_DOWN(iommu->exclusion_base), sbdf.sbdf, ctxt);
            if ( unlikely(rc < 0) )
                return rc;
        }

        for ( ; um; um = um->next )
        {
            if ( um->global && global != processing )
                continue;

            rc = func(PFN_DOWN(um->addr), PFN_DOWN(um->length),
                      sbdf.sbdf, ctxt);
            if ( unlikely(rc < 0) )
                return rc;
        }

        if ( global == processing )
            global = done;
    }

    return 0;
}

static int fill_qpt(union amd_iommu_pte *this, unsigned int level,
                    struct page_info *pgs[IOMMU_MAX_PT_LEVELS])
{
    struct domain_iommu *hd = dom_iommu(dom_io);
    unsigned int i;
    int rc = 0;

    for ( i = 0; !rc && i < PTE_PER_TABLE_SIZE; ++i )
    {
        union amd_iommu_pte *pte = &this[i], *next;

        if ( !pte->pr )
        {
            if ( !pgs[level] )
            {
                /*
                 * The pgtable allocator is fine for the leaf page, as well as
                 * page table pages, and the resulting allocations are always
                 * zeroed.
                 */
                pgs[level] = iommu_alloc_pgtable(hd, 0);
                if ( !pgs[level] )
                {
                    rc = -ENOMEM;
                    break;
                }

                if ( level )
                {
                    next = __map_domain_page(pgs[level]);
                    rc = fill_qpt(next, level - 1, pgs);
                    unmap_domain_page(next);
                }
            }

            /*
             * PDEs are essentially a subset of PTEs, so this function
             * is fine to use even at the leaf.
             */
            set_iommu_pde_present(pte, mfn_x(page_to_mfn(pgs[level])), level,
                                  true, true);
        }
        else if ( level && pte->next_level )
        {
            next = map_domain_page(_mfn(pte->mfn));
            rc = fill_qpt(next, level - 1, pgs);
            unmap_domain_page(next);
        }
    }

    return rc;
}

int cf_check amd_iommu_quarantine_init(struct pci_dev *pdev, bool scratch_page)
{
    struct domain_iommu *hd = dom_iommu(dom_io);
    unsigned int level = hd->arch.amd.paging_mode;
    unsigned int req_id = get_dma_requestor_id(pdev->seg, pdev->sbdf.bdf);
    const struct ivrs_mappings *ivrs_mappings = get_ivrs_mappings(pdev->seg);
    int rc;

    ASSERT(pcidevs_locked());
    ASSERT(!hd->arch.amd.root_table);
    ASSERT(page_list_empty(&hd->arch.pgtables.list));

    if ( !scratch_page && !ivrs_mappings[req_id].unity_map )
        return 0;

    ASSERT(pdev->arch.pseudo_domid != DOMID_INVALID);

    if ( pdev->arch.amd.root_table )
    {
        clear_domain_page(pdev->arch.leaf_mfn);
        return 0;
    }

    pdev->arch.amd.root_table = iommu_alloc_pgtable(hd, 0);
    if ( !pdev->arch.amd.root_table )
        return -ENOMEM;

    /* Transiently install the root into DomIO, for iommu_identity_mapping(). */
    hd->arch.amd.root_table = pdev->arch.amd.root_table;

    rc = amd_iommu_reserve_domain_unity_map(dom_io,
                                            ivrs_mappings[req_id].unity_map,
                                            0);

    iommu_identity_map_teardown(dom_io);
    hd->arch.amd.root_table = NULL;

    if ( rc )
        AMD_IOMMU_WARN("%pp: quarantine unity mapping failed\n", &pdev->sbdf);
    else if ( scratch_page )
    {
        union amd_iommu_pte *root;
        struct page_info *pgs[IOMMU_MAX_PT_LEVELS] = {};

        root = __map_domain_page(pdev->arch.amd.root_table);
        rc = fill_qpt(root, level - 1, pgs);
        unmap_domain_page(root);

        pdev->arch.leaf_mfn = page_to_mfn(pgs[0]);
    }

    page_list_move(&pdev->arch.pgtables_list, &hd->arch.pgtables.list);

    if ( rc )
        amd_iommu_quarantine_teardown(pdev);

    return rc;
}

void amd_iommu_quarantine_teardown(struct pci_dev *pdev)
{
    struct domain_iommu *hd = dom_iommu(dom_io);

    ASSERT(pcidevs_locked());

    if ( !pdev->arch.amd.root_table )
        return;

    ASSERT(page_list_empty(&hd->arch.pgtables.list));
    page_list_move(&hd->arch.pgtables.list, &pdev->arch.pgtables_list);
    while ( iommu_free_pgtables(dom_io) == -ERESTART )
        /* nothing */;
    pdev->arch.amd.root_table = NULL;
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
