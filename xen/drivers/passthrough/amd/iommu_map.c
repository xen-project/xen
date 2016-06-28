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

#include <xen/config.h>
#include <xen/acpi.h>
#include <xen/sched.h>
#include <asm/p2m.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include "../ats.h"
#include <xen/pci.h>

/* Given pfn and page table level, return pde index */
static unsigned int pfn_to_pde_idx(unsigned long pfn, unsigned int level)
{
    unsigned int idx;

    idx = pfn >> (PTE_PER_TABLE_SHIFT * (--level));
    idx &= ~PTE_PER_TABLE_MASK;
    return idx;
}

void clear_iommu_pte_present(unsigned long l1_mfn, unsigned long gfn)
{
    u64 *table, *pte;

    table = map_domain_page(_mfn(l1_mfn));
    pte = table + pfn_to_pde_idx(gfn, IOMMU_PAGING_MODE_LEVEL_1);
    *pte = 0;
    unmap_domain_page(table);
}

static bool_t set_iommu_pde_present(u32 *pde, unsigned long next_mfn, 
                                    unsigned int next_level,
                                    bool_t iw, bool_t ir)
{
    u64 addr_lo, addr_hi, maddr_old, maddr_next;
    u32 entry;
    bool_t need_flush = 0;

    maddr_next = (u64)next_mfn << PAGE_SHIFT;

    addr_hi = get_field_from_reg_u32(pde[1],
                                     IOMMU_PTE_ADDR_HIGH_MASK,
                                     IOMMU_PTE_ADDR_HIGH_SHIFT);
    addr_lo = get_field_from_reg_u32(pde[0],
                                     IOMMU_PTE_ADDR_LOW_MASK,
                                     IOMMU_PTE_ADDR_LOW_SHIFT);

    maddr_old = (addr_hi << 32) | (addr_lo << PAGE_SHIFT);

    if ( maddr_old != maddr_next )
        need_flush = 1;

    addr_lo = maddr_next & DMA_32BIT_MASK;
    addr_hi = maddr_next >> 32;

    /* enable read/write permissions,which will be enforced at the PTE */
    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_PDE_ADDR_HIGH_MASK,
                         IOMMU_PDE_ADDR_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(iw, entry,
                         IOMMU_PDE_IO_WRITE_PERMISSION_MASK,
                         IOMMU_PDE_IO_WRITE_PERMISSION_SHIFT, &entry);
    set_field_in_reg_u32(ir, entry,
                         IOMMU_PDE_IO_READ_PERMISSION_MASK,
                         IOMMU_PDE_IO_READ_PERMISSION_SHIFT, &entry);

    /* FC bit should be enabled in PTE, this helps to solve potential
     * issues with ATS devices
     */
    if ( next_level == IOMMU_PAGING_MODE_LEVEL_0 )
        set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                             IOMMU_PTE_FC_MASK, IOMMU_PTE_FC_SHIFT, &entry);
    pde[1] = entry;

    /* mark next level as 'present' */
    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_PDE_ADDR_LOW_MASK,
                         IOMMU_PDE_ADDR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(next_level, entry,
                         IOMMU_PDE_NEXT_LEVEL_MASK,
                         IOMMU_PDE_NEXT_LEVEL_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PDE_PRESENT_MASK,
                         IOMMU_PDE_PRESENT_SHIFT, &entry);
    pde[0] = entry;

    return need_flush;
}

static bool_t set_iommu_pte_present(unsigned long pt_mfn, unsigned long gfn, 
                                    unsigned long next_mfn, int pde_level, 
                                    bool_t iw, bool_t ir)
{
    u64 *table;
    u32 *pde;
    bool_t need_flush = 0;

    table = map_domain_page(_mfn(pt_mfn));

    pde = (u32*)(table + pfn_to_pde_idx(gfn, pde_level));

    need_flush = set_iommu_pde_present(pde, next_mfn, 
                                       IOMMU_PAGING_MODE_LEVEL_0, iw, ir);
    unmap_domain_page(table);
    return need_flush;
}

void amd_iommu_set_root_page_table(
    u32 *dte, u64 root_ptr, u16 domain_id, u8 paging_mode, u8 valid)
{
    u64 addr_hi, addr_lo;
    u32 entry;
    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_DEV_TABLE_DOMAIN_ID_MASK,
                         IOMMU_DEV_TABLE_DOMAIN_ID_SHIFT, &entry);
    dte[2] = entry;

    addr_lo = root_ptr & DMA_32BIT_MASK;
    addr_hi = root_ptr >> 32;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_MASK,
                         IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IO_READ_PERMISSION_MASK,
                         IOMMU_DEV_TABLE_IO_READ_PERMISSION_SHIFT, &entry);
    dte[1] = entry;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_MASK,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(paging_mode, entry,
                         IOMMU_DEV_TABLE_PAGING_MODE_MASK,
                         IOMMU_DEV_TABLE_PAGING_MODE_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                         IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT, &entry);
    set_field_in_reg_u32(valid ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_VALID_MASK,
                         IOMMU_DEV_TABLE_VALID_SHIFT, &entry);
    dte[0] = entry;
}

void iommu_dte_set_iotlb(u32 *dte, u8 i)
{
    u32 entry;

    entry = dte[3];
    set_field_in_reg_u32(!!i, entry,
                         IOMMU_DEV_TABLE_IOTLB_SUPPORT_MASK,
                         IOMMU_DEV_TABLE_IOTLB_SUPPORT_SHIFT, &entry);
    dte[3] = entry;
}

void __init amd_iommu_set_intremap_table(
    u32 *dte, u64 intremap_ptr, u8 int_valid)
{
    u64 addr_hi, addr_lo;
    u32 entry;

    addr_lo = intremap_ptr & DMA_32BIT_MASK;
    addr_hi = intremap_ptr >> 32;

    entry = dte[5];
    set_field_in_reg_u32((u32)addr_hi, entry,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_HIGH_MASK,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_HIGH_SHIFT, &entry);
    /* Fixed and arbitrated interrupts remapepd */
    set_field_in_reg_u32(2, entry,
                        IOMMU_DEV_TABLE_INT_CONTROL_MASK,
                        IOMMU_DEV_TABLE_INT_CONTROL_SHIFT, &entry);
    dte[5] = entry;

    set_field_in_reg_u32((u32)addr_lo >> 6, 0,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_LOW_MASK,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_LOW_SHIFT, &entry);
    /* 2048 entries */
    set_field_in_reg_u32(0xB, entry,
                         IOMMU_DEV_TABLE_INT_TABLE_LENGTH_MASK,
                         IOMMU_DEV_TABLE_INT_TABLE_LENGTH_SHIFT, &entry);

    /* unmapped interrupt results io page faults*/
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_INT_TABLE_IGN_UNMAPPED_MASK,
                         IOMMU_DEV_TABLE_INT_TABLE_IGN_UNMAPPED_SHIFT, &entry);
    set_field_in_reg_u32(int_valid ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_INT_VALID_MASK,
                         IOMMU_DEV_TABLE_INT_VALID_SHIFT, &entry);
    dte[4] = entry;
}

void __init iommu_dte_add_device_entry(u32 *dte, struct ivrs_mappings *ivrs_dev)
{
    u32 entry;
    u8 sys_mgt, dev_ex, flags;
    u8 mask = ~(0x7 << 3);

    dte[7] = dte[6] = dte[4] = dte[2] = dte[1] = dte[0] = 0;

    flags = ivrs_dev->device_flags;
    sys_mgt = get_field_from_byte(flags, ACPI_IVHD_SYSTEM_MGMT);
    dev_ex = ivrs_dev->dte_allow_exclusion;

    flags &= mask;
    set_field_in_reg_u32(flags, 0,
                         IOMMU_DEV_TABLE_IVHD_FLAGS_MASK,
                         IOMMU_DEV_TABLE_IVHD_FLAGS_SHIFT, &entry);
    dte[5] = entry;

    set_field_in_reg_u32(sys_mgt, 0,
                         IOMMU_DEV_TABLE_SYS_MGT_MSG_ENABLE_MASK,
                         IOMMU_DEV_TABLE_SYS_MGT_MSG_ENABLE_SHIFT, &entry);
    set_field_in_reg_u32(dev_ex, entry,
                         IOMMU_DEV_TABLE_ALLOW_EXCLUSION_MASK,
                         IOMMU_DEV_TABLE_ALLOW_EXCLUSION_SHIFT, &entry);
    dte[3] = entry;
}

void iommu_dte_set_guest_cr3(u32 *dte, u16 dom_id, u64 gcr3,
                             int gv, unsigned int glx)
{
    u32 entry, gcr3_1, gcr3_2, gcr3_3;

    gcr3_3 = gcr3 >> 31;
    gcr3_2 = (gcr3 >> 15) & 0xFFFF;
    gcr3_1 = (gcr3 >> PAGE_SHIFT) & 0x7;

    /* I bit must be set when gcr3 is enabled */
    entry = dte[3];
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IOTLB_SUPPORT_MASK,
                         IOMMU_DEV_TABLE_IOTLB_SUPPORT_SHIFT, &entry);
    /* update gcr3 */
    set_field_in_reg_u32(gcr3_3, entry,
                         IOMMU_DEV_TABLE_GCR3_3_MASK,
                         IOMMU_DEV_TABLE_GCR3_3_SHIFT, &entry);
    dte[3] = entry;

    set_field_in_reg_u32(dom_id, entry,
                         IOMMU_DEV_TABLE_DOMAIN_ID_MASK,
                         IOMMU_DEV_TABLE_DOMAIN_ID_SHIFT, &entry);
    /* update gcr3 */
    entry = dte[2];
    set_field_in_reg_u32(gcr3_2, entry,
                         IOMMU_DEV_TABLE_GCR3_2_MASK,
                         IOMMU_DEV_TABLE_GCR3_2_SHIFT, &entry);
    dte[2] = entry;

    entry = dte[1];
    /* Enable GV bit */
    set_field_in_reg_u32(!!gv, entry,
                         IOMMU_DEV_TABLE_GV_MASK,
                         IOMMU_DEV_TABLE_GV_SHIFT, &entry);

    /* 1 level guest cr3 table  */
    set_field_in_reg_u32(glx, entry,
                         IOMMU_DEV_TABLE_GLX_MASK,
                         IOMMU_DEV_TABLE_GLX_SHIFT, &entry);
    /* update gcr3 */
    set_field_in_reg_u32(gcr3_1, entry,
                         IOMMU_DEV_TABLE_GCR3_1_MASK,
                         IOMMU_DEV_TABLE_GCR3_1_SHIFT, &entry);
    dte[1] = entry;
}

u64 amd_iommu_get_next_table_from_pte(u32 *entry)
{
    u64 addr_lo, addr_hi, ptr;

    addr_lo = get_field_from_reg_u32(
        entry[0],
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_MASK,
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_SHIFT);

    addr_hi = get_field_from_reg_u32(
        entry[1],
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT);

    ptr = (addr_hi << 32) | (addr_lo << PAGE_SHIFT);
    return ptr;
}

/* For each pde, We use ignored bits (bit 1 - bit 8 and bit 63)
 * to save pde count, pde count = 511 is a candidate of page coalescing.
 */
static unsigned int get_pde_count(u64 pde)
{
    unsigned int count;
    u64 upper_mask = 1ULL << 63 ;
    u64 lower_mask = 0xFF << 1;

    count = ((pde & upper_mask) >> 55) | ((pde & lower_mask) >> 1);
    return count;
}

/* Convert pde count into iommu pte ignored bits */
static void set_pde_count(u64 *pde, unsigned int count)
{
    u64 upper_mask = 1ULL << 8 ;
    u64 lower_mask = 0xFF;
    u64 pte_mask = (~(1ULL << 63)) & (~(0xFF << 1));

    *pde &= pte_mask;
    *pde |= ((count & upper_mask ) << 55) | ((count & lower_mask ) << 1);
}

/* Return 1, if pages are suitable for merging at merge_level.
 * otherwise increase pde count if mfn is contigous with mfn - 1
 */
static int iommu_update_pde_count(struct domain *d, unsigned long pt_mfn,
                                  unsigned long gfn, unsigned long mfn,
                                  unsigned int merge_level)
{
    unsigned int pde_count, next_level;
    unsigned long first_mfn;
    u64 *table, *pde, *ntable;
    u64 ntable_maddr, mask;
    struct domain_iommu *hd = dom_iommu(d);
    bool_t ok = 0;

    ASSERT( spin_is_locked(&hd->arch.mapping_lock) && pt_mfn );

    next_level = merge_level - 1;

    /* get pde at merge level */
    table = map_domain_page(_mfn(pt_mfn));
    pde = table + pfn_to_pde_idx(gfn, merge_level);

    /* get page table of next level */
    ntable_maddr = amd_iommu_get_next_table_from_pte((u32*)pde);
    ntable = map_domain_page(_mfn(paddr_to_pfn(ntable_maddr)));

    /* get the first mfn of next level */
    first_mfn = amd_iommu_get_next_table_from_pte((u32*)ntable) >> PAGE_SHIFT;

    if ( first_mfn == 0 )
        goto out;

    mask = (1ULL<< (PTE_PER_TABLE_SHIFT * next_level)) - 1;

    if ( ((first_mfn & mask) == 0) &&
         (((gfn & mask) | first_mfn) == mfn) )
    {
        pde_count = get_pde_count(*pde);

        if ( pde_count == (PTE_PER_TABLE_SIZE - 1) )
            ok = 1;
        else if ( pde_count < (PTE_PER_TABLE_SIZE - 1))
        {
            pde_count++;
            set_pde_count(pde, pde_count);
        }
    }

    else
        /* non-contiguous mapping */
        set_pde_count(pde, 0);

out:
    unmap_domain_page(ntable);
    unmap_domain_page(table);

    return ok;
}

static int iommu_merge_pages(struct domain *d, unsigned long pt_mfn,
                             unsigned long gfn, unsigned int flags,
                             unsigned int merge_level)
{
    u64 *table, *pde, *ntable;
    u64 ntable_mfn;
    unsigned long first_mfn;
    struct domain_iommu *hd = dom_iommu(d);

    ASSERT( spin_is_locked(&hd->arch.mapping_lock) && pt_mfn );

    table = map_domain_page(_mfn(pt_mfn));
    pde = table + pfn_to_pde_idx(gfn, merge_level);

    /* get first mfn */
    ntable_mfn = amd_iommu_get_next_table_from_pte((u32*)pde) >> PAGE_SHIFT;

    if ( ntable_mfn == 0 )
    {
        unmap_domain_page(table);
        return 1;
    }

    ntable = map_domain_page(_mfn(ntable_mfn));
    first_mfn = amd_iommu_get_next_table_from_pte((u32*)ntable) >> PAGE_SHIFT;

    if ( first_mfn == 0 )
    {
        unmap_domain_page(ntable);
        unmap_domain_page(table);
        return 1;
    }

    /* setup super page mapping, next level = 0 */
    set_iommu_pde_present((u32*)pde, first_mfn,
                          IOMMU_PAGING_MODE_LEVEL_0,
                          !!(flags & IOMMUF_writable),
                          !!(flags & IOMMUF_readable));

    amd_iommu_flush_all_pages(d);

    unmap_domain_page(ntable);
    unmap_domain_page(table);
    return 0;
}

/* Walk io page tables and build level page tables if necessary
 * {Re, un}mapping super page frames causes re-allocation of io
 * page tables.
 */
static int iommu_pde_from_gfn(struct domain *d, unsigned long pfn, 
                              unsigned long pt_mfn[])
{
    u64 *pde, *next_table_vaddr;
    unsigned long  next_table_mfn;
    unsigned int level;
    struct page_info *table;
    const struct domain_iommu *hd = dom_iommu(d);

    table = hd->arch.root_table;
    level = hd->arch.paging_mode;

    BUG_ON( table == NULL || level < IOMMU_PAGING_MODE_LEVEL_1 || 
            level > IOMMU_PAGING_MODE_LEVEL_6 );

    next_table_mfn = page_to_mfn(table);

    if ( level == IOMMU_PAGING_MODE_LEVEL_1 )
    {
        pt_mfn[level] = next_table_mfn;
        return 0;
    }

    while ( level > IOMMU_PAGING_MODE_LEVEL_1 )
    {
        unsigned int next_level = level - 1;
        pt_mfn[level] = next_table_mfn;

        next_table_vaddr = map_domain_page(_mfn(next_table_mfn));
        pde = next_table_vaddr + pfn_to_pde_idx(pfn, level);

        /* Here might be a super page frame */
        next_table_mfn = amd_iommu_get_next_table_from_pte((uint32_t*)pde) 
                         >> PAGE_SHIFT;

        /* Split super page frame into smaller pieces.*/
        if ( iommu_is_pte_present((u32*)pde) &&
             (iommu_next_level((u32*)pde) == 0) &&
             next_table_mfn != 0 )
        {
            int i;
            unsigned long mfn, gfn;
            unsigned int page_sz;

            page_sz = 1 << (PTE_PER_TABLE_SHIFT * (next_level - 1));
            gfn =  pfn & ~((1 << (PTE_PER_TABLE_SHIFT * next_level)) - 1);
            mfn = next_table_mfn;

            /* allocate lower level page table */
            table = alloc_amd_iommu_pgtable();
            if ( table == NULL )
            {
                AMD_IOMMU_DEBUG("Cannot allocate I/O page table\n");
                unmap_domain_page(next_table_vaddr);
                return 1;
            }

            next_table_mfn = page_to_mfn(table);
            set_iommu_pde_present((u32*)pde, next_table_mfn, next_level, 
                                  !!IOMMUF_writable, !!IOMMUF_readable);

            for ( i = 0; i < PTE_PER_TABLE_SIZE; i++ )
            {
                set_iommu_pte_present(next_table_mfn, gfn, mfn, next_level,
                                      !!IOMMUF_writable, !!IOMMUF_readable);
                mfn += page_sz;
                gfn += page_sz;
             }

            amd_iommu_flush_all_pages(d);
        }

        /* Install lower level page table for non-present entries */
        else if ( !iommu_is_pte_present((u32*)pde) )
        {
            if ( next_table_mfn == 0 )
            {
                table = alloc_amd_iommu_pgtable();
                if ( table == NULL )
                {
                    AMD_IOMMU_DEBUG("Cannot allocate I/O page table\n");
                    unmap_domain_page(next_table_vaddr);
                    return 1;
                }
                next_table_mfn = page_to_mfn(table);
                set_iommu_pde_present((u32*)pde, next_table_mfn, next_level,
                                      !!IOMMUF_writable, !!IOMMUF_readable);
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

static int update_paging_mode(struct domain *d, unsigned long gfn)
{
    u16 bdf;
    void *device_entry;
    unsigned int req_id, level, offset;
    unsigned long flags;
    struct pci_dev *pdev;
    struct amd_iommu *iommu = NULL;
    struct page_info *new_root = NULL;
    struct page_info *old_root = NULL;
    void *new_root_vaddr;
    unsigned long old_root_mfn;
    struct domain_iommu *hd = dom_iommu(d);

    if ( gfn == gfn_x(INVALID_GFN) )
        return -EADDRNOTAVAIL;
    ASSERT(!(gfn >> DEFAULT_DOMAIN_ADDRESS_WIDTH));

    level = hd->arch.paging_mode;
    old_root = hd->arch.root_table;
    offset = gfn >> (PTE_PER_TABLE_SHIFT * (level - 1));

    ASSERT(spin_is_locked(&hd->arch.mapping_lock) && is_hvm_domain(d));

    while ( offset >= PTE_PER_TABLE_SIZE )
    {
        /* Allocate and install a new root table.
         * Only upper I/O page table grows, no need to fix next level bits */
        new_root = alloc_amd_iommu_pgtable();
        if ( new_root == NULL )
        {
            AMD_IOMMU_DEBUG("%s Cannot allocate I/O page table\n",
                            __func__);
            return -ENOMEM;
        }

        new_root_vaddr = __map_domain_page(new_root);
        old_root_mfn = page_to_mfn(old_root);
        set_iommu_pde_present(new_root_vaddr, old_root_mfn, level,
                              !!IOMMUF_writable, !!IOMMUF_readable);
        level++;
        old_root = new_root;
        offset >>= PTE_PER_TABLE_SHIFT;
        unmap_domain_page(new_root_vaddr);
    }

    if ( new_root != NULL )
    {
        hd->arch.paging_mode = level;
        hd->arch.root_table = new_root;

        if ( !pcidevs_locked() )
            AMD_IOMMU_DEBUG("%s Try to access pdev_list "
                            "without aquiring pcidevs_lock.\n", __func__);

        /* Update device table entries using new root table and paging mode */
        for_each_pdev( d, pdev )
        {
            bdf = PCI_BDF2(pdev->bus, pdev->devfn);
            iommu = find_iommu_for_device(pdev->seg, bdf);
            if ( !iommu )
            {
                AMD_IOMMU_DEBUG("%s Fail to find iommu.\n", __func__);
                return -ENODEV;
            }

            spin_lock_irqsave(&iommu->lock, flags);
            do {
                req_id = get_dma_requestor_id(pdev->seg, bdf);
                device_entry = iommu->dev_table.buffer +
                               (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

                /* valid = 0 only works for dom0 passthrough mode */
                amd_iommu_set_root_page_table((u32 *)device_entry,
                                              page_to_maddr(hd->arch.root_table),
                                              d->domain_id,
                                              hd->arch.paging_mode, 1);

                amd_iommu_flush_device(iommu, req_id);
                bdf += pdev->phantom_stride;
            } while ( PCI_DEVFN2(bdf) != pdev->devfn &&
                      PCI_SLOT(bdf) == PCI_SLOT(pdev->devfn) );
            spin_unlock_irqrestore(&iommu->lock, flags);
        }

        /* For safety, invalidate all entries */
        amd_iommu_flush_all_pages(d);
    }
    return 0;
}

int amd_iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                       unsigned int flags)
{
    bool_t need_flush = 0;
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long pt_mfn[7];
    unsigned int merge_level;

    BUG_ON( !hd->arch.root_table );

    if ( iommu_use_hap_pt(d) )
        return 0;

    memset(pt_mfn, 0, sizeof(pt_mfn));

    spin_lock(&hd->arch.mapping_lock);

    /* Since HVM domain is initialized with 2 level IO page table,
     * we might need a deeper page table for lager gfn now */
    if ( is_hvm_domain(d) )
    {
        if ( update_paging_mode(d, gfn) )
        {
            spin_unlock(&hd->arch.mapping_lock);
            AMD_IOMMU_DEBUG("Update page mode failed gfn = %lx\n", gfn);
            domain_crash(d);
            return -EFAULT;
        }
    }

    if ( iommu_pde_from_gfn(d, gfn, pt_mfn) || (pt_mfn[1] == 0) )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_DEBUG("Invalid IO pagetable entry gfn = %lx\n", gfn);
        domain_crash(d);
        return -EFAULT;
    }

    /* Install 4k mapping first */
    need_flush = set_iommu_pte_present(pt_mfn[1], gfn, mfn, 
                                       IOMMU_PAGING_MODE_LEVEL_1,
                                       !!(flags & IOMMUF_writable),
                                       !!(flags & IOMMUF_readable));

    /* Do not increase pde count if io mapping has not been changed */
    if ( !need_flush )
        goto out;

    /* 4K mapping for PV guests never changes, 
     * no need to flush if we trust non-present bits */
    if ( is_hvm_domain(d) )
        amd_iommu_flush_pages(d, gfn, 0);

    for ( merge_level = IOMMU_PAGING_MODE_LEVEL_2;
          merge_level <= hd->arch.paging_mode; merge_level++ )
    {
        if ( pt_mfn[merge_level] == 0 )
            break;
        if ( !iommu_update_pde_count(d, pt_mfn[merge_level],
                                     gfn, mfn, merge_level) )
            break;

        if ( iommu_merge_pages(d, pt_mfn[merge_level], gfn, 
                               flags, merge_level) )
        {
            spin_unlock(&hd->arch.mapping_lock);
            AMD_IOMMU_DEBUG("Merge iommu page failed at level %d, "
                            "gfn = %lx mfn = %lx\n", merge_level, gfn, mfn);
            domain_crash(d);
            return -EFAULT;
        }

        /* Deallocate lower level page table */
        free_amd_iommu_pgtable(mfn_to_page(pt_mfn[merge_level - 1]));
    }

out:
    spin_unlock(&hd->arch.mapping_lock);
    return 0;
}

int amd_iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    unsigned long pt_mfn[7];
    struct domain_iommu *hd = dom_iommu(d);

    BUG_ON( !hd->arch.root_table );

    if ( iommu_use_hap_pt(d) )
        return 0;

    memset(pt_mfn, 0, sizeof(pt_mfn));

    spin_lock(&hd->arch.mapping_lock);

    /* Since HVM domain is initialized with 2 level IO page table,
     * we might need a deeper page table for lager gfn now */
    if ( is_hvm_domain(d) )
    {
        int rc = update_paging_mode(d, gfn);

        if ( rc )
        {
            spin_unlock(&hd->arch.mapping_lock);
            AMD_IOMMU_DEBUG("Update page mode failed gfn = %lx\n", gfn);
            if ( rc != -EADDRNOTAVAIL )
                domain_crash(d);
            return rc;
        }
    }

    if ( iommu_pde_from_gfn(d, gfn, pt_mfn) || (pt_mfn[1] == 0) )
    {
        spin_unlock(&hd->arch.mapping_lock);
        AMD_IOMMU_DEBUG("Invalid IO pagetable entry gfn = %lx\n", gfn);
        domain_crash(d);
        return -EFAULT;
    }

    /* mark PTE as 'page not present' */
    clear_iommu_pte_present(pt_mfn[1], gfn);
    spin_unlock(&hd->arch.mapping_lock);

    amd_iommu_flush_pages(d, gfn, 0);

    return 0;
}

int amd_iommu_reserve_domain_unity_map(struct domain *domain,
                                       u64 phys_addr,
                                       unsigned long size, int iw, int ir)
{
    unsigned long npages, i;
    unsigned long gfn;
    unsigned int flags = !!ir;
    int rt = 0;

    if ( iw )
        flags |= IOMMUF_writable;

    npages = region_to_pages(phys_addr, size);
    gfn = phys_addr >> PAGE_SHIFT;
    for ( i = 0; i < npages; i++ )
    {
        rt = amd_iommu_map_page(domain, gfn +i, gfn +i, flags);
        if ( rt != 0 )
            return rt;
    }
    return 0;
}

/* Share p2m table with iommu. */
void amd_iommu_share_p2m(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct page_info *p2m_table;
    mfn_t pgd_mfn;

    pgd_mfn = pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)));
    p2m_table = mfn_to_page(mfn_x(pgd_mfn));

    if ( hd->arch.root_table != p2m_table )
    {
        free_amd_iommu_pgtable(hd->arch.root_table);
        hd->arch.root_table = p2m_table;

        /* When sharing p2m with iommu, paging mode = 4 */
        hd->arch.paging_mode = IOMMU_PAGING_MODE_LEVEL_4;
        AMD_IOMMU_DEBUG("Share p2m table with iommu: p2m table = %#lx\n",
                        mfn_x(pgd_mfn));
    }
}
