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

static unsigned int clear_iommu_pte_present(unsigned long l1_mfn,
                                            unsigned long dfn)
{
    uint64_t *table, *pte;
    unsigned int flush_flags;

    table = map_domain_page(_mfn(l1_mfn));

    pte = (table + pfn_to_pde_idx(dfn, 1));

    flush_flags = get_field_from_reg_u32(*pte, IOMMU_PTE_PRESENT_MASK,
                                         IOMMU_PTE_PRESENT_SHIFT) ?
                                         IOMMU_FLUSHF_modified : 0;

    write_atomic(pte, 0);
    unmap_domain_page(table);

    return flush_flags;
}

static unsigned int set_iommu_pde_present(uint32_t *pde,
                                          unsigned long next_mfn,
                                          unsigned int next_level, bool iw,
                                          bool ir)
{
    uint64_t maddr_next, full;
    uint32_t addr_lo, addr_hi, entry;
    bool old_present;
    unsigned int flush_flags = IOMMU_FLUSHF_added;

    maddr_next = __pfn_to_paddr(next_mfn);

    old_present = get_field_from_reg_u32(pde[0], IOMMU_PTE_PRESENT_MASK,
                                         IOMMU_PTE_PRESENT_SHIFT);
    if ( old_present )
    {
        bool old_r, old_w;
        unsigned int old_level;
        uint64_t maddr_old;

        addr_hi = get_field_from_reg_u32(pde[1],
                                         IOMMU_PTE_ADDR_HIGH_MASK,
                                         IOMMU_PTE_ADDR_HIGH_SHIFT);
        addr_lo = get_field_from_reg_u32(pde[0],
                                         IOMMU_PTE_ADDR_LOW_MASK,
                                         IOMMU_PTE_ADDR_LOW_SHIFT);
        old_level = get_field_from_reg_u32(pde[0],
                                           IOMMU_PDE_NEXT_LEVEL_MASK,
                                           IOMMU_PDE_NEXT_LEVEL_SHIFT);
        old_w = get_field_from_reg_u32(pde[1],
                                       IOMMU_PTE_IO_WRITE_PERMISSION_MASK,
                                       IOMMU_PTE_IO_WRITE_PERMISSION_SHIFT);
        old_r = get_field_from_reg_u32(pde[1],
                                       IOMMU_PTE_IO_READ_PERMISSION_MASK,
                                       IOMMU_PTE_IO_READ_PERMISSION_SHIFT);

        maddr_old = ((uint64_t)addr_hi << 32) |
                    ((uint64_t)addr_lo << PAGE_SHIFT);

        if ( maddr_old != maddr_next || iw != old_w || ir != old_r ||
             old_level != next_level )
            flush_flags |= IOMMU_FLUSHF_modified;
    }

    addr_lo = maddr_next & DMA_32BIT_MASK;
    addr_hi = maddr_next >> 32;

    /* enable read/write permissions,which will be enforced at the PTE */
    set_field_in_reg_u32(addr_hi, 0,
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
    if ( next_level == 0 )
        set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                             IOMMU_PTE_FC_MASK, IOMMU_PTE_FC_SHIFT, &entry);
    full = (uint64_t)entry << 32;

    /* mark next level as 'present' */
    set_field_in_reg_u32(addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_PDE_ADDR_LOW_MASK,
                         IOMMU_PDE_ADDR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(next_level, entry,
                         IOMMU_PDE_NEXT_LEVEL_MASK,
                         IOMMU_PDE_NEXT_LEVEL_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PDE_PRESENT_MASK,
                         IOMMU_PDE_PRESENT_SHIFT, &entry);
    full |= entry;

    write_atomic((uint64_t *)pde, full);

    return flush_flags;
}

static unsigned int set_iommu_pte_present(unsigned long pt_mfn,
                                          unsigned long dfn,
                                          unsigned long next_mfn,
                                          int pde_level,
                                          bool iw, bool ir)
{
    uint64_t *table;
    uint32_t *pde;
    unsigned int flush_flags;

    table = map_domain_page(_mfn(pt_mfn));

    pde = (uint32_t *)(table + pfn_to_pde_idx(dfn, pde_level));

    flush_flags = set_iommu_pde_present(pde, next_mfn, 0, iw, ir);
    unmap_domain_page(table);

    return flush_flags;
}

/*
 * This function returns
 * - -errno for errors,
 * - 0 for a successful update, atomic when necessary
 * - 1 for a successful but non-atomic update, which may need to be warned
 *   about by the caller.
 */
int amd_iommu_set_root_page_table(uint32_t *dte, uint64_t root_ptr,
                                  uint16_t domain_id, uint8_t paging_mode,
                                  unsigned int flags)
{
    bool valid = flags & SET_ROOT_VALID;
    uint32_t addr_hi, addr_lo, entry, dte0 = dte[0];

    addr_lo = root_ptr & DMA_32BIT_MASK;
    addr_hi = root_ptr >> 32;

    if ( get_field_from_reg_u32(dte0, IOMMU_DEV_TABLE_VALID_MASK,
                                IOMMU_DEV_TABLE_VALID_SHIFT) &&
         get_field_from_reg_u32(dte0, IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                                IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT) &&
         (cpu_has_cx16 || (flags & SET_ROOT_WITH_UNITY_MAP)) )
    {
        union {
            uint32_t dte[4];
            uint64_t raw64[2];
            __uint128_t raw128;
        } ldte;
        __uint128_t old;
        int ret = 0;

        memcpy(ldte.dte, dte, sizeof(ldte));
        old = ldte.raw128;

        set_field_in_reg_u32(domain_id, ldte.dte[2],
                             IOMMU_DEV_TABLE_DOMAIN_ID_MASK,
                             IOMMU_DEV_TABLE_DOMAIN_ID_SHIFT, &ldte.dte[2]);

        set_field_in_reg_u32(addr_hi, ldte.dte[1],
                             IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
                             IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT,
                             &ldte.dte[1]);
        set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, ldte.dte[1],
                             IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_MASK,
                             IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_SHIFT,
                             &ldte.dte[1]);
        set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, ldte.dte[1],
                             IOMMU_DEV_TABLE_IO_READ_PERMISSION_MASK,
                             IOMMU_DEV_TABLE_IO_READ_PERMISSION_SHIFT,
                             &ldte.dte[1]);

        set_field_in_reg_u32(addr_lo >> PAGE_SHIFT, ldte.dte[0],
                             IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_MASK,
                             IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_SHIFT,
                             &ldte.dte[0]);
        set_field_in_reg_u32(paging_mode, ldte.dte[0],
                             IOMMU_DEV_TABLE_PAGING_MODE_MASK,
                             IOMMU_DEV_TABLE_PAGING_MODE_SHIFT, &ldte.dte[0]);
        set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, ldte.dte[0],
                             IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                             IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT,
                             &ldte.dte[0]);
        set_field_in_reg_u32(valid ? IOMMU_CONTROL_ENABLED
                                   : IOMMU_CONTROL_DISABLED,
                             ldte.dte[0], IOMMU_DEV_TABLE_VALID_MASK,
                             IOMMU_DEV_TABLE_VALID_SHIFT, &ldte.dte[0]);

        if ( cpu_has_cx16 )
        {
            __uint128_t res = cmpxchg16b(dte, &old, &ldte.raw128);

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
        }
        else /* Best effort, updating domain_id last. */
        {
            uint64_t *ptr = (void *)dte;

            write_atomic(ptr + 0, ldte.raw64[0]);
            /* No barrier should be needed between these two. */
            write_atomic(ptr + 1, ldte.raw64[1]);

            ret = 1;
        }

        return ret;
    }

    if ( valid ||
         get_field_from_reg_u32(dte0, IOMMU_DEV_TABLE_VALID_MASK,
                                IOMMU_DEV_TABLE_VALID_SHIFT) )
    {
        set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, dte0,
                             IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                             IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT, &dte0);
        set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, dte0,
                             IOMMU_DEV_TABLE_VALID_MASK,
                             IOMMU_DEV_TABLE_VALID_SHIFT, &dte0);
        dte[0] = dte0;
        smp_wmb();
    }

    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_DEV_TABLE_DOMAIN_ID_MASK,
                         IOMMU_DEV_TABLE_DOMAIN_ID_SHIFT, &entry);
    dte[2] = entry;

    set_field_in_reg_u32(addr_hi, 0,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_MASK,
                         IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IO_READ_PERMISSION_MASK,
                         IOMMU_DEV_TABLE_IO_READ_PERMISSION_SHIFT, &entry);
    dte[1] = entry;
    smp_wmb();

    set_field_in_reg_u32(addr_lo >> PAGE_SHIFT, dte0,
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
    write_atomic(&dte[0], entry);

    return 0;
}

paddr_t amd_iommu_get_root_page_table(const uint32_t *dte)
{
    uint32_t lo = get_field_from_reg_u32(
                      dte[0], IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_MASK,
                      IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_SHIFT);
    uint32_t hi = get_field_from_reg_u32(
                      dte[1], IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
                      IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT);

    return ((paddr_t)hi << 32) | (lo << PAGE_SHIFT);
}

void iommu_dte_set_iotlb(uint32_t *dte, uint8_t i)
{
    uint32_t entry;

    entry = dte[3];
    set_field_in_reg_u32(!!i, entry,
                         IOMMU_DEV_TABLE_IOTLB_SUPPORT_MASK,
                         IOMMU_DEV_TABLE_IOTLB_SUPPORT_SHIFT, &entry);
    dte[3] = entry;
}

void __init amd_iommu_set_intremap_table(
    uint32_t *dte, uint64_t intremap_ptr, uint8_t int_valid)
{
    uint32_t addr_hi, addr_lo, entry;

    addr_lo = intremap_ptr & DMA_32BIT_MASK;
    addr_hi = intremap_ptr >> 32;

    entry = dte[5];
    set_field_in_reg_u32(addr_hi, entry,
                         IOMMU_DEV_TABLE_INT_TABLE_PTR_HIGH_MASK,
                         IOMMU_DEV_TABLE_INT_TABLE_PTR_HIGH_SHIFT, &entry);
    /* Fixed and arbitrated interrupts remapepd */
    set_field_in_reg_u32(2, entry,
                         IOMMU_DEV_TABLE_INT_CONTROL_MASK,
                         IOMMU_DEV_TABLE_INT_CONTROL_SHIFT, &entry);
    dte[5] = entry;
    smp_wmb();

    set_field_in_reg_u32(addr_lo >> 6, 0,
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
    write_atomic(&dte[4], entry);
}

void __init iommu_dte_add_device_entry(uint32_t *dte,
                                       struct ivrs_mappings *ivrs_dev)
{
    uint32_t entry;
    uint8_t sys_mgt, dev_ex, flags;
    uint8_t mask = ~(0x7 << 3);

    dte[7] = dte[6] = dte[4] = dte[2] = dte[1] = dte[0] = 0;

    flags = ivrs_dev->device_flags;
    sys_mgt = MASK_EXTR(flags, ACPI_IVHD_SYSTEM_MGMT);
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

void iommu_dte_set_guest_cr3(uint32_t *dte, uint16_t dom_id, uint64_t gcr3,
                             int gv, unsigned int glx)
{
    uint32_t entry, gcr3_1, gcr3_2, gcr3_3;

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

uint64_t amd_iommu_get_address_from_pte(void *pte)
{
    uint32_t *entry = pte;
    uint32_t addr_lo, addr_hi;
    uint64_t ptr;

    addr_lo = get_field_from_reg_u32(entry[0],
                                     IOMMU_PTE_ADDR_LOW_MASK,
                                     IOMMU_PTE_ADDR_LOW_SHIFT);

    addr_hi = get_field_from_reg_u32(entry[1],
                                     IOMMU_PTE_ADDR_HIGH_MASK,
                                     IOMMU_PTE_ADDR_HIGH_SHIFT);

    ptr = ((uint64_t)addr_hi << 32) |
          ((uint64_t)addr_lo << PAGE_SHIFT);
    return ptr;
}

/* Walk io page tables and build level page tables if necessary
 * {Re, un}mapping super page frames causes re-allocation of io
 * page tables.
 */
static int iommu_pde_from_dfn(struct domain *d, unsigned long dfn,
                              unsigned long pt_mfn[], bool map)
{
    uint64_t *pde, *next_table_vaddr;
    unsigned long  next_table_mfn;
    unsigned int level;
    struct page_info *table;
    const struct domain_iommu *hd = dom_iommu(d);

    table = hd->arch.root_table;
    level = hd->arch.paging_mode;

    BUG_ON( table == NULL || level < 1 || level > 6 );

    /*
     * A frame number past what the current page tables can represent can't
     * possibly have a mapping.
     */
    if ( dfn >> (PTE_PER_TABLE_SHIFT * level) )
        return 0;

    next_table_mfn = mfn_x(page_to_mfn(table));

    if ( level == 1 )
    {
        pt_mfn[level] = next_table_mfn;
        return 0;
    }

    while ( level > 1 )
    {
        unsigned int next_level = level - 1;
        pt_mfn[level] = next_table_mfn;

        next_table_vaddr = map_domain_page(_mfn(next_table_mfn));
        pde = next_table_vaddr + pfn_to_pde_idx(dfn, level);

        /* Here might be a super page frame */
        next_table_mfn = amd_iommu_get_address_from_pte(pde) >> PAGE_SHIFT;

        /* Split super page frame into smaller pieces.*/
        if ( iommu_is_pte_present((uint32_t *)pde) &&
             (iommu_next_level((uint32_t *)pde) == 0) &&
             next_table_mfn != 0 )
        {
            int i;
            unsigned long mfn, pfn;
            unsigned int page_sz;

            page_sz = 1 << (PTE_PER_TABLE_SHIFT * (next_level - 1));
            pfn =  dfn & ~((1 << (PTE_PER_TABLE_SHIFT * next_level)) - 1);
            mfn = next_table_mfn;

            /* allocate lower level page table */
            table = alloc_amd_iommu_pgtable();
            if ( table == NULL )
            {
                AMD_IOMMU_DEBUG("Cannot allocate I/O page table\n");
                unmap_domain_page(next_table_vaddr);
                return 1;
            }

            next_table_mfn = mfn_x(page_to_mfn(table));
            set_iommu_pde_present((uint32_t *)pde, next_table_mfn, next_level,
                                  !!IOMMUF_writable, !!IOMMUF_readable);

            for ( i = 0; i < PTE_PER_TABLE_SIZE; i++ )
            {
                set_iommu_pte_present(next_table_mfn, pfn, mfn, next_level,
                                      !!IOMMUF_writable, !!IOMMUF_readable);
                mfn += page_sz;
                pfn += page_sz;
             }

            amd_iommu_flush_all_pages(d);
        }

        /* Install lower level page table for non-present entries */
        else if ( !iommu_is_pte_present((uint32_t *)pde) )
        {
            if ( !map )
                return 0;

            if ( next_table_mfn == 0 )
            {
                table = alloc_amd_iommu_pgtable();
                if ( table == NULL )
                {
                    AMD_IOMMU_DEBUG("Cannot allocate I/O page table\n");
                    unmap_domain_page(next_table_vaddr);
                    return 1;
                }
                next_table_mfn = mfn_x(page_to_mfn(table));
                set_iommu_pde_present((uint32_t *)pde, next_table_mfn,
                                      next_level, !!IOMMUF_writable,
                                      !!IOMMUF_readable);
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

    if ( iommu_use_hap_pt(d) )
        return 0;

    memset(pt_mfn, 0, sizeof(pt_mfn));

    spin_lock(&hd->arch.mapping_lock);

    rc = amd_iommu_alloc_root(hd);
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
    *flush_flags |= set_iommu_pte_present(pt_mfn[1], dfn_x(dfn), mfn_x(mfn),
                                          1, (flags & IOMMUF_writable),
                                          (flags & IOMMUF_readable));

    spin_unlock(&hd->arch.mapping_lock);

    return 0;
}

int amd_iommu_unmap_page(struct domain *d, dfn_t dfn,
                         unsigned int *flush_flags)
{
    unsigned long pt_mfn[7];
    struct domain_iommu *hd = dom_iommu(d);

    if ( iommu_use_hap_pt(d) )
        return 0;

    memset(pt_mfn, 0, sizeof(pt_mfn));

    spin_lock(&hd->arch.mapping_lock);

    if ( !hd->arch.root_table )
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

static unsigned long flush_count(unsigned long dfn, unsigned int page_count,
                                 unsigned int order)
{
    unsigned long start = dfn >> order;
    unsigned long end = ((dfn + page_count - 1) >> order) + 1;

    ASSERT(end > start);
    return end - start;
}

int amd_iommu_flush_iotlb_pages(struct domain *d, dfn_t dfn,
                                unsigned int page_count,
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

/* Share p2m table with iommu. */
void amd_iommu_share_p2m(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct page_info *p2m_table;
    mfn_t pgd_mfn;

    pgd_mfn = pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)));
    p2m_table = mfn_to_page(pgd_mfn);

    if ( hd->arch.root_table != p2m_table )
    {
        free_amd_iommu_pgtable(hd->arch.root_table);
        hd->arch.root_table = p2m_table;

        /* When sharing p2m with iommu, paging mode = 4 */
        hd->arch.paging_mode = 4;
        AMD_IOMMU_DEBUG("Share p2m table with iommu: p2m table = %#lx\n",
                        mfn_x(pgd_mfn));
    }
}

int __init amd_iommu_quarantine_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long end_gfn =
        1ul << (DEFAULT_DOMAIN_ADDRESS_WIDTH - PAGE_SHIFT);
    unsigned int level = amd_iommu_get_paging_mode(end_gfn);
    uint64_t *table;

    if ( hd->arch.root_table )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    spin_lock(&hd->arch.mapping_lock);

    hd->arch.root_table = alloc_amd_iommu_pgtable();
    if ( !hd->arch.root_table )
        goto out;

    table = __map_domain_page(hd->arch.root_table);
    while ( level )
    {
        struct page_info *pg;
        unsigned int i;

        /*
         * The pgtable allocator is fine for the leaf page, as well as
         * page table pages, and the resulting allocations are always
         * zeroed.
         */
        pg = alloc_amd_iommu_pgtable();
        if ( !pg )
            break;

        for ( i = 0; i < PTE_PER_TABLE_SIZE; i++ )
        {
            uint32_t *pde = (uint32_t *)&table[i];

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
