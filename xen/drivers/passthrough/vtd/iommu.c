/*
 * Copyright (c) 2006, Intel Corporation.
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
 *
 * Copyright (C) Ashok Raj <ashok.raj@intel.com>
 * Copyright (C) Shaohua Li <shaohua.li@intel.com>
 * Copyright (C) Allen Kay <allen.m.kay@intel.com> - adapted to xen
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/domain_page.h>
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/numa.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/keyhandler.h>
#include <asm/msi.h>
#include <asm/irq.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/p2m.h>
#include <mach_apic.h>
#include "iommu.h"
#include "dmar.h"
#include "extern.h"
#include "vtd.h"
#include "../ats.h"

struct mapped_rmrr {
    struct list_head list;
    u64 base, end;
    unsigned int count;
};

/* Possible unfiltered LAPIC/MSI messages from untrusted sources? */
bool __read_mostly untrusted_msi;

int nr_iommus;

static struct tasklet vtd_fault_tasklet;

static int setup_hwdom_device(u8 devfn, struct pci_dev *);
static void setup_hwdom_rmrr(struct domain *d);

static int domain_iommu_domid(struct domain *d,
                              struct vtd_iommu *iommu)
{
    unsigned long nr_dom, i;

    nr_dom = cap_ndoms(iommu->cap);
    i = find_first_bit(iommu->domid_bitmap, nr_dom);
    while ( i < nr_dom )
    {
        if ( iommu->domid_map[i] == d->domain_id )
            return i;

        i = find_next_bit(iommu->domid_bitmap, nr_dom, i+1);
    }

    dprintk(XENLOG_ERR VTDPREFIX,
            "Cannot get valid iommu domid: domid=%d iommu->index=%d\n",
            d->domain_id, iommu->index);
    return -1;
}

#define DID_FIELD_WIDTH 16
#define DID_HIGH_OFFSET 8
static int context_set_domain_id(struct context_entry *context,
                                 struct domain *d,
                                 struct vtd_iommu *iommu)
{
    unsigned long nr_dom, i;
    int found = 0;

    ASSERT(spin_is_locked(&iommu->lock));

    nr_dom = cap_ndoms(iommu->cap);
    i = find_first_bit(iommu->domid_bitmap, nr_dom);
    while ( i < nr_dom )
    {
        if ( iommu->domid_map[i] == d->domain_id )
        {
            found = 1;
            break;
        }
        i = find_next_bit(iommu->domid_bitmap, nr_dom, i+1);
    }

    if ( found == 0 )
    {
        i = find_first_zero_bit(iommu->domid_bitmap, nr_dom);
        if ( i >= nr_dom )
        {
            dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: no free domain ids\n");
            return -EFAULT;
        }
        iommu->domid_map[i] = d->domain_id;
    }

    set_bit(i, iommu->domid_bitmap);
    context->hi |= (i & ((1 << DID_FIELD_WIDTH) - 1)) << DID_HIGH_OFFSET;
    return 0;
}

static int context_get_domain_id(struct context_entry *context,
                                 struct vtd_iommu *iommu)
{
    unsigned long dom_index, nr_dom;
    int domid = -1;

    if (iommu && context)
    {
        nr_dom = cap_ndoms(iommu->cap);

        dom_index = context_domain_id(*context);

        if ( dom_index < nr_dom && iommu->domid_map )
            domid = iommu->domid_map[dom_index];
        else
            dprintk(XENLOG_DEBUG VTDPREFIX,
                    "dom_index %lu exceeds nr_dom %lu or iommu has no domid_map\n",
                    dom_index, nr_dom);
    }
    return domid;
}

static int iommus_incoherent;
static void __iommu_flush_cache(void *addr, unsigned int size)
{
    int i;
    static unsigned int clflush_size = 0;

    if ( !iommus_incoherent )
        return;

    if ( clflush_size == 0 )
        clflush_size = get_cache_line_size();

    for ( i = 0; i < size; i += clflush_size )
        cacheline_flush((char *)addr + i);
}

void iommu_flush_cache_entry(void *addr, unsigned int size)
{
    __iommu_flush_cache(addr, size);
}

void iommu_flush_cache_page(void *addr, unsigned long npages)
{
    __iommu_flush_cache(addr, PAGE_SIZE * npages);
}

/* Allocate page table, return its machine address */
uint64_t alloc_pgtable_maddr(unsigned long npages, nodeid_t node)
{
    struct page_info *pg, *cur_pg;
    u64 *vaddr;
    unsigned int i;

    pg = alloc_domheap_pages(NULL, get_order_from_pages(npages),
                             (node == NUMA_NO_NODE) ? 0 : MEMF_node(node));
    if ( !pg )
        return 0;

    cur_pg = pg;
    for ( i = 0; i < npages; i++ )
    {
        vaddr = __map_domain_page(cur_pg);
        memset(vaddr, 0, PAGE_SIZE);

        iommu_flush_cache_page(vaddr, 1);
        unmap_domain_page(vaddr);
        cur_pg++;
    }

    return page_to_maddr(pg);
}

void free_pgtable_maddr(u64 maddr)
{
    if ( maddr != 0 )
        free_domheap_page(maddr_to_page(maddr));
}

/* context entry handling */
static u64 bus_to_context_maddr(struct vtd_iommu *iommu, u8 bus)
{
    struct root_entry *root, *root_entries;
    u64 maddr;

    ASSERT(spin_is_locked(&iommu->lock));
    root_entries = (struct root_entry *)map_vtd_domain_page(iommu->root_maddr);
    root = &root_entries[bus];
    if ( !root_present(*root) )
    {
        maddr = alloc_pgtable_maddr(1, iommu->node);
        if ( maddr == 0 )
        {
            unmap_vtd_domain_page(root_entries);
            return 0;
        }
        set_root_value(*root, maddr);
        set_root_present(*root);
        iommu_flush_cache_entry(root, sizeof(struct root_entry));
    }
    maddr = (u64) get_context_addr(*root);
    unmap_vtd_domain_page(root_entries);
    return maddr;
}

static u64 addr_to_dma_page_maddr(struct domain *domain, u64 addr, int alloc)
{
    struct domain_iommu *hd = dom_iommu(domain);
    int addr_width = agaw_to_width(hd->arch.agaw);
    struct dma_pte *parent, *pte = NULL;
    int level = agaw_to_level(hd->arch.agaw);
    int offset;
    u64 pte_maddr = 0;

    addr &= (((u64)1) << addr_width) - 1;
    ASSERT(spin_is_locked(&hd->arch.mapping_lock));
    if ( !hd->arch.pgd_maddr &&
         (!alloc ||
          ((hd->arch.pgd_maddr = alloc_pgtable_maddr(1, hd->node)) == 0)) )
        goto out;

    parent = (struct dma_pte *)map_vtd_domain_page(hd->arch.pgd_maddr);
    while ( level > 1 )
    {
        offset = address_level_offset(addr, level);
        pte = &parent[offset];

        pte_maddr = dma_pte_addr(*pte);
        if ( !pte_maddr )
        {
            if ( !alloc )
                break;

            pte_maddr = alloc_pgtable_maddr(1, hd->node);
            if ( !pte_maddr )
                break;

            dma_set_pte_addr(*pte, pte_maddr);

            /*
             * high level table always sets r/w, last level
             * page table control read/write
             */
            dma_set_pte_readable(*pte);
            dma_set_pte_writable(*pte);
            iommu_flush_cache_entry(pte, sizeof(struct dma_pte));
        }

        if ( level == 2 )
            break;

        unmap_vtd_domain_page(parent);
        parent = map_vtd_domain_page(pte_maddr);
        level--;
    }

    unmap_vtd_domain_page(parent);
 out:
    return pte_maddr;
}

static void iommu_flush_write_buffer(struct vtd_iommu *iommu)
{
    u32 val;
    unsigned long flags;

    if ( !rwbf_quirk && !cap_rwbf(iommu->cap) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    val = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, val | DMA_GCMD_WBF);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(val & DMA_GSTS_WBFS), val);

    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

/* return value determine if we need a write buffer flush */
static int __must_check flush_context_reg(struct vtd_iommu *iommu, u16 did,
                                          u16 source_id, u8 function_mask,
                                          u64 type,
                                          bool flush_non_present_entry)
{
    u64 val = 0;
    unsigned long flags;

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entry we do nothing and if hardware cache non-present
     * entry, we flush entries of domain 0 (the domain id is used to cache
     * any non-present entries)
     */
    if ( flush_non_present_entry )
    {
        if ( !cap_caching_mode(iommu->cap) )
            return 1;
        else
            did = 0;
    }

    /* use register invalidation */
    switch ( type )
    {
    case DMA_CCMD_GLOBAL_INVL:
        val = DMA_CCMD_GLOBAL_INVL;
        break;
    case DMA_CCMD_DOMAIN_INVL:
        val = DMA_CCMD_DOMAIN_INVL|DMA_CCMD_DID(did);
        break;
    case DMA_CCMD_DEVICE_INVL:
        val = DMA_CCMD_DEVICE_INVL|DMA_CCMD_DID(did)
            |DMA_CCMD_SID(source_id)|DMA_CCMD_FM(function_mask);
        break;
    default:
        BUG();
    }
    val |= DMA_CCMD_ICC;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writeq(iommu->reg, DMAR_CCMD_REG, val);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_CCMD_REG, dmar_readq,
                  !(val & DMA_CCMD_ICC), val);

    spin_unlock_irqrestore(&iommu->register_lock, flags);
    /* flush context entry will implicitly flush write buffer */
    return 0;
}

static int __must_check iommu_flush_context_global(struct vtd_iommu *iommu,
                                                   bool flush_non_present_entry)
{
    return iommu->flush.context(iommu, 0, 0, 0, DMA_CCMD_GLOBAL_INVL,
                                flush_non_present_entry);
}

static int __must_check iommu_flush_context_device(struct vtd_iommu *iommu,
                                                   u16 did, u16 source_id,
                                                   u8 function_mask,
                                                   bool flush_non_present_entry)
{
    return iommu->flush.context(iommu, did, source_id, function_mask,
                                DMA_CCMD_DEVICE_INVL, flush_non_present_entry);
}

/* return value determine if we need a write buffer flush */
static int __must_check flush_iotlb_reg(struct vtd_iommu *iommu, u16 did,
                                        u64 addr,
                                        unsigned int size_order, u64 type,
                                        bool flush_non_present_entry,
                                        bool flush_dev_iotlb)
{
    int tlb_offset = ecap_iotlb_offset(iommu->ecap);
    u64 val = 0;
    unsigned long flags;

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entry we do nothing and if hardware cache non-present
     * entry, we flush entries of domain 0 (the domain id is used to cache
     * any non-present entries)
     */
    if ( flush_non_present_entry )
    {
        if ( !cap_caching_mode(iommu->cap) )
            return 1;
        else
            did = 0;
    }

    /* use register invalidation */
    switch ( type )
    {
    case DMA_TLB_GLOBAL_FLUSH:
        val = DMA_TLB_GLOBAL_FLUSH|DMA_TLB_IVT;
        break;
    case DMA_TLB_DSI_FLUSH:
        val = DMA_TLB_DSI_FLUSH|DMA_TLB_IVT|DMA_TLB_DID(did);
        break;
    case DMA_TLB_PSI_FLUSH:
        val = DMA_TLB_PSI_FLUSH|DMA_TLB_IVT|DMA_TLB_DID(did);
        break;
    default:
        BUG();
    }
    /* Note: set drain read/write */
    if ( cap_read_drain(iommu->cap) )
        val |= DMA_TLB_READ_DRAIN;
    if ( cap_write_drain(iommu->cap) )
        val |= DMA_TLB_WRITE_DRAIN;

    spin_lock_irqsave(&iommu->register_lock, flags);
    /* Note: Only uses first TLB reg currently */
    if ( type == DMA_TLB_PSI_FLUSH )
    {
        /* Note: always flush non-leaf currently. */
        dmar_writeq(iommu->reg, tlb_offset, size_order | addr);
    }
    dmar_writeq(iommu->reg, tlb_offset + 8, val);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, (tlb_offset + 8), dmar_readq,
                  !(val & DMA_TLB_IVT), val);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* check IOTLB invalidation granularity */
    if ( DMA_TLB_IAIG(val) == 0 )
        dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: flush IOTLB failed\n");

    /* flush iotlb entry will implicitly flush write buffer */
    return 0;
}

static int __must_check iommu_flush_iotlb_global(struct vtd_iommu *iommu,
                                                 bool flush_non_present_entry,
                                                 bool flush_dev_iotlb)
{
    int status;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    status = iommu->flush.iotlb(iommu, 0, 0, 0, DMA_TLB_GLOBAL_FLUSH,
                                flush_non_present_entry, flush_dev_iotlb);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    return status;
}

static int __must_check iommu_flush_iotlb_dsi(struct vtd_iommu *iommu, u16 did,
                                              bool_t flush_non_present_entry,
                                              bool_t flush_dev_iotlb)
{
    int status;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    status = iommu->flush.iotlb(iommu, did, 0, 0, DMA_TLB_DSI_FLUSH,
                                flush_non_present_entry, flush_dev_iotlb);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    return status;
}

static int __must_check iommu_flush_iotlb_psi(struct vtd_iommu *iommu, u16 did,
                                              u64 addr, unsigned int order,
                                              bool_t flush_non_present_entry,
                                              bool_t flush_dev_iotlb)
{
    int status;

    ASSERT(!(addr & (~PAGE_MASK_4K)));

    /* Fallback to domain selective flush if no PSI support */
    if ( !cap_pgsel_inv(iommu->cap) )
        return iommu_flush_iotlb_dsi(iommu, did, flush_non_present_entry,
                                     flush_dev_iotlb);

    /* Fallback to domain selective flush if size is too big */
    if ( order > cap_max_amask_val(iommu->cap) )
        return iommu_flush_iotlb_dsi(iommu, did, flush_non_present_entry,
                                     flush_dev_iotlb);

    addr >>= PAGE_SHIFT_4K + order;
    addr <<= PAGE_SHIFT_4K + order;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    status = iommu->flush.iotlb(iommu, did, addr, order, DMA_TLB_PSI_FLUSH,
                                flush_non_present_entry, flush_dev_iotlb);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    return status;
}

static int __must_check iommu_flush_all(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    bool_t flush_dev_iotlb;
    int rc = 0;

    flush_all_cache();
    for_each_drhd_unit ( drhd )
    {
        int context_rc, iotlb_rc;

        iommu = drhd->iommu;
        context_rc = iommu_flush_context_global(iommu, 0);
        flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
        iotlb_rc = iommu_flush_iotlb_global(iommu, 0, flush_dev_iotlb);

        /*
         * The current logic for returns:
         *   - positive  invoke iommu_flush_write_buffer to flush cache.
         *   - zero      on success.
         *   - negative  on failure. Continue to flush IOMMU IOTLB on a
         *               best effort basis.
         */
        if ( context_rc > 0 || iotlb_rc > 0 )
            iommu_flush_write_buffer(iommu);
        if ( rc >= 0 )
            rc = context_rc;
        if ( rc >= 0 )
            rc = iotlb_rc;
    }

    if ( rc > 0 )
        rc = 0;

    return rc;
}

static int __must_check iommu_flush_iotlb(struct domain *d, dfn_t dfn,
                                          bool_t dma_old_pte_present,
                                          unsigned int page_count)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    bool_t flush_dev_iotlb;
    int iommu_domid;
    int rc = 0;

    /*
     * No need pcideves_lock here because we have flush
     * when assign/deassign device
     */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;

        if ( !test_bit(iommu->index, &hd->arch.iommu_bitmap) )
            continue;

        flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
        iommu_domid= domain_iommu_domid(d, iommu);
        if ( iommu_domid == -1 )
            continue;

        if ( page_count != 1 || dfn_eq(dfn, INVALID_DFN) )
            rc = iommu_flush_iotlb_dsi(iommu, iommu_domid,
                                       0, flush_dev_iotlb);
        else
            rc = iommu_flush_iotlb_psi(iommu, iommu_domid,
                                       dfn_to_daddr(dfn),
                                       PAGE_ORDER_4K,
                                       !dma_old_pte_present,
                                       flush_dev_iotlb);

        if ( rc > 0 )
        {
            iommu_flush_write_buffer(iommu);
            rc = 0;
        }
    }

    return rc;
}

static int __must_check iommu_flush_iotlb_pages(struct domain *d,
                                                dfn_t dfn,
                                                unsigned int page_count,
                                                unsigned int flush_flags)
{
    ASSERT(page_count && !dfn_eq(dfn, INVALID_DFN));
    ASSERT(flush_flags);

    return iommu_flush_iotlb(d, dfn, flush_flags & IOMMU_FLUSHF_modified,
                             page_count);
}

static int __must_check iommu_flush_iotlb_all(struct domain *d)
{
    return iommu_flush_iotlb(d, INVALID_DFN, 0, 0);
}

/* clear one page's page table */
static int __must_check dma_pte_clear_one(struct domain *domain, u64 addr,
                                          unsigned int *flush_flags)
{
    struct domain_iommu *hd = dom_iommu(domain);
    struct dma_pte *page = NULL, *pte = NULL;
    u64 pg_maddr;
    int rc = 0;

    spin_lock(&hd->arch.mapping_lock);
    /* get last level pte */
    pg_maddr = addr_to_dma_page_maddr(domain, addr, 0);
    if ( pg_maddr == 0 )
    {
        spin_unlock(&hd->arch.mapping_lock);
        return 0;
    }

    page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
    pte = page + address_level_offset(addr, 1);

    if ( !dma_pte_present(*pte) )
    {
        spin_unlock(&hd->arch.mapping_lock);
        unmap_vtd_domain_page(page);
        return 0;
    }

    dma_clear_pte(*pte);
    *flush_flags |= IOMMU_FLUSHF_modified;

    spin_unlock(&hd->arch.mapping_lock);
    iommu_flush_cache_entry(pte, sizeof(struct dma_pte));

    unmap_vtd_domain_page(page);

    return rc;
}

static void iommu_free_pagetable(u64 pt_maddr, int level)
{
    struct page_info *pg = maddr_to_page(pt_maddr);

    if ( pt_maddr == 0 )
        return;

    PFN_ORDER(pg) = level;
    spin_lock(&iommu_pt_cleanup_lock);
    page_list_add_tail(pg, &iommu_pt_cleanup_list);
    spin_unlock(&iommu_pt_cleanup_lock);
}

static void iommu_free_page_table(struct page_info *pg)
{
    unsigned int i, next_level = PFN_ORDER(pg) - 1;
    u64 pt_maddr = page_to_maddr(pg);
    struct dma_pte *pt_vaddr, *pte;

    PFN_ORDER(pg) = 0;
    pt_vaddr = (struct dma_pte *)map_vtd_domain_page(pt_maddr);

    for ( i = 0; i < PTE_NUM; i++ )
    {
        pte = &pt_vaddr[i];
        if ( !dma_pte_present(*pte) )
            continue;

        if ( next_level >= 1 )
            iommu_free_pagetable(dma_pte_addr(*pte), next_level);

        dma_clear_pte(*pte);
        iommu_flush_cache_entry(pte, sizeof(struct dma_pte));
    }

    unmap_vtd_domain_page(pt_vaddr);
    free_pgtable_maddr(pt_maddr);
}

static int iommu_set_root_entry(struct vtd_iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writeq(iommu->reg, DMAR_RTADDR_REG, iommu->root_maddr);

    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts | DMA_GCMD_SRTP);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_RTPS), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return 0;
}

static void iommu_enable_translation(struct acpi_drhd_unit *drhd)
{
    u32 sts;
    unsigned long flags;
    struct vtd_iommu *iommu = drhd->iommu;

    if ( is_igd_drhd(drhd) )
    {
        if ( !iommu_igfx )
        {
            printk(XENLOG_INFO VTDPREFIX
                   "Passed iommu=no-igfx option.  Disabling IGD VT-d engine.\n");
            return;
        }

        if ( !is_igd_vt_enabled_quirk() )
        {
            if ( force_iommu )
                panic("BIOS did not enable IGD for VT properly, crash Xen for security purpose\n");

            printk(XENLOG_WARNING VTDPREFIX
                   "BIOS did not enable IGD for VT properly.  Disabling IGD VT-d engine.\n");
            return;
        }
    }

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    if ( iommu_verbose )
        printk(VTDPREFIX "iommu_enable_translation: iommu->reg = %p\n",
               iommu->reg);
    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts | DMA_GCMD_TE);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_TES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    /* Disable PMRs when VT-d engine takes effect per spec definition */
    disable_pmr(iommu);
}

static void iommu_disable_translation(struct vtd_iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts & (~DMA_GCMD_TE));

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(sts & DMA_GSTS_TES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);
}

enum faulttype {
    DMA_REMAP,
    INTR_REMAP,
    UNKNOWN,
};

static const char *dma_remap_fault_reasons[] =
{
    "Software",
    "Present bit in root entry is clear",
    "Present bit in context entry is clear",
    "Invalid context entry",
    "Access beyond MGAW",
    "PTE Write access is not set",
    "PTE Read access is not set",
    "Next page table ptr is invalid",
    "Root table address invalid",
    "Context table ptr is invalid",
    "non-zero reserved fields in RTP",
    "non-zero reserved fields in CTP",
    "non-zero reserved fields in PTE",
    "Blocked a DMA translation request",
};

static const char *intr_remap_fault_reasons[] =
{
    "Detected reserved fields in the decoded interrupt-remapped request",
    "Interrupt index exceeded the interrupt-remapping table size",
    "Present field in the IRTE entry is clear",
    "Error accessing interrupt-remapping table pointed by IRTA_REG",
    "Detected reserved fields in the IRTE entry",
    "Blocked a compatibility format interrupt request",
    "Blocked an interrupt request due to source-id verification failure",
};

static const char *iommu_get_fault_reason(u8 fault_reason,
                                          enum faulttype *fault_type)
{
    if ( fault_reason >= 0x20 && ( fault_reason < 0x20 +
                ARRAY_SIZE(intr_remap_fault_reasons)) )
    {
        *fault_type = INTR_REMAP;
        return intr_remap_fault_reasons[fault_reason - 0x20];
    }
    else if ( fault_reason < ARRAY_SIZE(dma_remap_fault_reasons) )
    {
        *fault_type = DMA_REMAP;
        return dma_remap_fault_reasons[fault_reason];
    }
    else
    {
        *fault_type = UNKNOWN;
        return "Unknown";
    }
}

static int iommu_page_fault_do_one(struct vtd_iommu *iommu, int type,
                                   u8 fault_reason, u16 source_id, u64 addr)
{
    const char *reason, *kind;
    enum faulttype fault_type;
    u16 seg = iommu->drhd->segment;

    reason = iommu_get_fault_reason(fault_reason, &fault_type);
    switch ( fault_type )
    {
    case DMA_REMAP:
        printk(XENLOG_G_WARNING VTDPREFIX
               "DMAR:[%s] Request device [%04x:%02x:%02x.%u] "
               "fault addr %"PRIx64"\n",
               (type ? "DMA Read" : "DMA Write"),
               seg, PCI_BUS(source_id), PCI_SLOT(source_id),
               PCI_FUNC(source_id), addr);
        kind = "DMAR";
        break;
    case INTR_REMAP:
        printk(XENLOG_G_WARNING VTDPREFIX
               "INTR-REMAP: Request device [%04x:%02x:%02x.%u] "
               "fault index %"PRIx64"\n",
               seg, PCI_BUS(source_id), PCI_SLOT(source_id),
               PCI_FUNC(source_id), addr >> 48);
        kind = "INTR-REMAP";
        break;
    default:
        printk(XENLOG_G_WARNING VTDPREFIX
               "UNKNOWN: Request device [%04x:%02x:%02x.%u] "
               "fault addr %"PRIx64"\n",
               seg, PCI_BUS(source_id), PCI_SLOT(source_id),
               PCI_FUNC(source_id), addr);
        kind = "UNKNOWN";
        break;
    }

    printk(XENLOG_G_WARNING VTDPREFIX "%s: reason %02x - %s\n",
           kind, fault_reason, reason);

    if ( iommu_verbose && fault_type == DMA_REMAP )
        print_vtd_entries(iommu, PCI_BUS(source_id), PCI_DEVFN2(source_id),
                          addr >> PAGE_SHIFT);

    return 0;
}

static void iommu_fault_status(u32 fault_status)
{
    if ( fault_status & DMA_FSTS_PFO )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Fault Overflow\n");
    if ( fault_status & DMA_FSTS_PPF )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Primary Pending Fault\n");
    if ( fault_status & DMA_FSTS_AFO )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Advanced Fault Overflow\n");
    if ( fault_status & DMA_FSTS_APF )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Advanced Pending Fault\n");
    if ( fault_status & DMA_FSTS_IQE )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Invalidation Queue Error\n");
    if ( fault_status & DMA_FSTS_ICE )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Invalidation Completion Error\n");
    if ( fault_status & DMA_FSTS_ITE )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Invalidation Time-out Error\n");
}

#define PRIMARY_FAULT_REG_LEN (16)
static void __do_iommu_page_fault(struct vtd_iommu *iommu)
{
    int reg, fault_index;
    u32 fault_status;
    unsigned long flags;

    fault_status = dmar_readl(iommu->reg, DMAR_FSTS_REG);

    iommu_fault_status(fault_status);

    /* FIXME: ignore advanced fault log */
    if ( !(fault_status & DMA_FSTS_PPF) )
        goto clear_overflow;

    fault_index = dma_fsts_fault_record_index(fault_status);
    reg = cap_fault_reg_offset(iommu->cap);
    while (1)
    {
        u8 fault_reason;
        u16 source_id;
        u32 data;
        u64 guest_addr;
        int type;

        /* highest 32 bits */
        spin_lock_irqsave(&iommu->register_lock, flags);
        data = dmar_readl(iommu->reg, reg +
                          fault_index * PRIMARY_FAULT_REG_LEN + 12);
        if ( !(data & DMA_FRCD_F) )
        {
            spin_unlock_irqrestore(&iommu->register_lock, flags);
            break;
        }

        fault_reason = dma_frcd_fault_reason(data);
        type = dma_frcd_type(data);

        data = dmar_readl(iommu->reg, reg +
                          fault_index * PRIMARY_FAULT_REG_LEN + 8);
        source_id = dma_frcd_source_id(data);

        guest_addr = dmar_readq(iommu->reg, reg +
                                fault_index * PRIMARY_FAULT_REG_LEN);
        guest_addr = dma_frcd_page_addr(guest_addr);
        /* clear the fault */
        dmar_writel(iommu->reg, reg +
                    fault_index * PRIMARY_FAULT_REG_LEN + 12, DMA_FRCD_F);
        spin_unlock_irqrestore(&iommu->register_lock, flags);

        iommu_page_fault_do_one(iommu, type, fault_reason,
                                source_id, guest_addr);

        pci_check_disable_device(iommu->drhd->segment,
                                 PCI_BUS(source_id), PCI_DEVFN2(source_id));

        fault_index++;
        if ( fault_index > cap_num_fault_regs(iommu->cap) )
            fault_index = 0;
    }
clear_overflow:
    /* clear primary fault overflow */
    fault_status = readl(iommu->reg + DMAR_FSTS_REG);
    if ( fault_status & DMA_FSTS_PFO )
    {
        spin_lock_irqsave(&iommu->register_lock, flags);
        dmar_writel(iommu->reg, DMAR_FSTS_REG, DMA_FSTS_PFO);
        spin_unlock_irqrestore(&iommu->register_lock, flags);
    }
}

static void do_iommu_page_fault(unsigned long data)
{
    struct acpi_drhd_unit *drhd;

    if ( list_empty(&acpi_drhd_units) )
    {
       INTEL_IOMMU_DEBUG("no device found, something must be very wrong!\n");
       return;
    }

    /*
     * No matter from whom the interrupt came from, check all the
     * IOMMUs present in the system. This allows for having just one
     * tasklet (instead of one per each IOMMUs) and should be more than
     * fine, considering how rare the event of a fault should be.
     */
    for_each_drhd_unit ( drhd )
        __do_iommu_page_fault(drhd->iommu);
}

static void iommu_page_fault(int irq, void *dev_id,
                             struct cpu_user_regs *regs)
{
    /*
     * Just flag the tasklet as runnable. This is fine, according to VT-d
     * specs since a new interrupt won't be generated until we clear all
     * the faults that caused this one to happen.
     */
    tasklet_schedule(&vtd_fault_tasklet);
}

static void dma_msi_unmask(struct irq_desc *desc)
{
    struct vtd_iommu *iommu = desc->action->dev_id;
    unsigned long flags;
    u32 sts;

    /* unmask it */
    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_FECTL_REG);
    sts &= ~DMA_FECTL_IM;
    dmar_writel(iommu->reg, DMAR_FECTL_REG, sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
    iommu->msi.msi_attrib.host_masked = 0;
}

static void dma_msi_mask(struct irq_desc *desc)
{
    unsigned long flags;
    struct vtd_iommu *iommu = desc->action->dev_id;
    u32 sts;

    /* mask it */
    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_FECTL_REG);
    sts |= DMA_FECTL_IM;
    dmar_writel(iommu->reg, DMAR_FECTL_REG, sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
    iommu->msi.msi_attrib.host_masked = 1;
}

static unsigned int dma_msi_startup(struct irq_desc *desc)
{
    dma_msi_unmask(desc);
    return 0;
}

static void dma_msi_ack(struct irq_desc *desc)
{
    irq_complete_move(desc);
    dma_msi_mask(desc);
    move_masked_irq(desc);
}

static void dma_msi_end(struct irq_desc *desc, u8 vector)
{
    dma_msi_unmask(desc);
    ack_APIC_irq();
}

static void dma_msi_set_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    struct msi_msg msg;
    unsigned int dest;
    unsigned long flags;
    struct vtd_iommu *iommu = desc->action->dev_id;

    dest = set_desc_affinity(desc, mask);
    if (dest == BAD_APICID){
        dprintk(XENLOG_ERR VTDPREFIX, "Set iommu interrupt affinity error!\n");
        return;
    }

    msi_compose_msg(desc->arch.vector, NULL, &msg);
    msg.dest32 = dest;
    if (x2apic_enabled)
        msg.address_hi = dest & 0xFFFFFF00;
    ASSERT(!(msg.address_lo & MSI_ADDR_DEST_ID_MASK));
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);
    iommu->msi.msg = msg;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_FEDATA_REG, msg.data);
    dmar_writel(iommu->reg, DMAR_FEADDR_REG, msg.address_lo);
    /*
     * When x2APIC is not enabled, DMAR_FEUADDR_REG is reserved and
     * it's not necessary to update it.
     */
    if ( x2apic_enabled )
        dmar_writel(iommu->reg, DMAR_FEUADDR_REG, msg.address_hi);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static hw_irq_controller dma_msi_type = {
    .typename = "DMA_MSI",
    .startup = dma_msi_startup,
    .shutdown = dma_msi_mask,
    .enable = dma_msi_unmask,
    .disable = dma_msi_mask,
    .ack = dma_msi_ack,
    .end = dma_msi_end,
    .set_affinity = dma_msi_set_affinity,
};

static int __init iommu_set_interrupt(struct acpi_drhd_unit *drhd)
{
    int irq, ret;
    struct acpi_rhsa_unit *rhsa = drhd_to_rhsa(drhd);
    struct vtd_iommu *iommu = drhd->iommu;
    struct irq_desc *desc;

    irq = create_irq(rhsa ? pxm_to_node(rhsa->proximity_domain)
                          : NUMA_NO_NODE,
                     false);
    if ( irq <= 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: no irq available!\n");
        return -EINVAL;
    }

    desc = irq_to_desc(irq);
    desc->handler = &dma_msi_type;
    ret = request_irq(irq, 0, iommu_page_fault, "dmar", iommu);
    if ( ret )
    {
        desc->handler = &no_irq_type;
        destroy_irq(irq);
        dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: can't request irq\n");
        return ret;
    }

    iommu->msi.irq = irq;
    iommu->msi.msi_attrib.pos = MSI_TYPE_IOMMU;
    iommu->msi.msi_attrib.maskbit = 1;
    iommu->msi.msi_attrib.is_64 = 1;
    desc->msi_desc = &iommu->msi;

    return 0;
}

int __init iommu_alloc(struct acpi_drhd_unit *drhd)
{
    struct vtd_iommu *iommu;
    unsigned long sagaw, nr_dom;
    int agaw;

    if ( nr_iommus > MAX_IOMMUS )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                 "IOMMU: nr_iommus %d > MAX_IOMMUS\n", nr_iommus);
        return -ENOMEM;
    }

    iommu = xzalloc(struct vtd_iommu);
    if ( iommu == NULL )
        return -ENOMEM;

    iommu->msi.irq = -1; /* No irq assigned yet. */
    iommu->node = NUMA_NO_NODE;
    INIT_LIST_HEAD(&iommu->ats_devices);
    spin_lock_init(&iommu->intremap.lock);

    iommu->drhd = drhd;
    drhd->iommu = iommu;

    iommu->reg = ioremap(drhd->address, PAGE_SIZE);
    if ( !iommu->reg )
        return -ENOMEM;
    iommu->index = nr_iommus++;

    iommu->cap = dmar_readq(iommu->reg, DMAR_CAP_REG);
    iommu->ecap = dmar_readq(iommu->reg, DMAR_ECAP_REG);

    if ( iommu_verbose )
    {
        printk(VTDPREFIX "drhd->address = %"PRIx64" iommu->reg = %p\n",
               drhd->address, iommu->reg);
        printk(VTDPREFIX "cap = %"PRIx64" ecap = %"PRIx64"\n",
               iommu->cap, iommu->ecap);
    }
    if ( !(iommu->cap + 1) || !(iommu->ecap + 1) )
        return -ENODEV;

    if ( cap_fault_reg_offset(iommu->cap) +
         cap_num_fault_regs(iommu->cap) * PRIMARY_FAULT_REG_LEN >= PAGE_SIZE ||
         ecap_iotlb_offset(iommu->ecap) >= PAGE_SIZE )
    {
        printk(XENLOG_ERR VTDPREFIX "IOMMU: unsupported\n");
        print_iommu_regs(drhd);
        return -ENODEV;
    }

    /* Calculate number of pagetable levels: between 2 and 4. */
    sagaw = cap_sagaw(iommu->cap);
    for ( agaw = level_to_agaw(4); agaw >= 0; agaw-- )
        if ( test_bit(agaw, &sagaw) )
            break;
    if ( agaw < 0 )
    {
        printk(XENLOG_ERR VTDPREFIX "IOMMU: unsupported sagaw %lx\n", sagaw);
        print_iommu_regs(drhd);
        return -ENODEV;
    }
    iommu->nr_pt_levels = agaw_to_level(agaw);

    if ( !ecap_coherent(iommu->ecap) )
        iommus_incoherent = 1;

    /* allocate domain id bitmap */
    nr_dom = cap_ndoms(iommu->cap);
    iommu->domid_bitmap = xzalloc_array(unsigned long, BITS_TO_LONGS(nr_dom));
    if ( !iommu->domid_bitmap )
        return -ENOMEM ;

    /*
     * if Caching mode is set, then invalid translations are tagged with
     * domain id 0, Hence reserve bit 0 for it
     */
    if ( cap_caching_mode(iommu->cap) )
        set_bit(0, iommu->domid_bitmap);

    iommu->domid_map = xzalloc_array(u16, nr_dom);
    if ( !iommu->domid_map )
        return -ENOMEM ;

    spin_lock_init(&iommu->lock);
    spin_lock_init(&iommu->register_lock);

    return 0;
}

void __init iommu_free(struct acpi_drhd_unit *drhd)
{
    struct vtd_iommu *iommu = drhd->iommu;

    if ( iommu == NULL )
        return;

    drhd->iommu = NULL;

    if ( iommu->root_maddr != 0 )
    {
        free_pgtable_maddr(iommu->root_maddr);
        iommu->root_maddr = 0;
    }

    if ( iommu->reg )
        iounmap(iommu->reg);

    xfree(iommu->domid_bitmap);
    xfree(iommu->domid_map);

    if ( iommu->msi.irq >= 0 )
        destroy_irq(iommu->msi.irq);
    xfree(iommu);
}

#define guestwidth_to_adjustwidth(gaw) ({       \
    int agaw, r = (gaw - 12) % 9;               \
    agaw = (r == 0) ? gaw : (gaw + 9 - r);      \
    if ( agaw > 64 )                            \
        agaw = 64;                              \
    agaw; })

static int intel_iommu_domain_init(struct domain *d)
{
    dom_iommu(d)->arch.agaw = width_to_agaw(DEFAULT_DOMAIN_ADDRESS_WIDTH);

    return 0;
}

static void __hwdom_init intel_iommu_hwdom_init(struct domain *d)
{
    struct acpi_drhd_unit *drhd;

    setup_hwdom_pci_devices(d, setup_hwdom_device);
    setup_hwdom_rmrr(d);
    /* Make sure workarounds are applied before enabling the IOMMU(s). */
    arch_iommu_hwdom_init(d);

    if ( iommu_flush_all() )
        printk(XENLOG_WARNING VTDPREFIX
               " IOMMU flush all failed for hardware domain\n");

    for_each_drhd_unit ( drhd )
    {
        if ( iomem_deny_access(d, PFN_DOWN(drhd->address),
                               PFN_DOWN(drhd->address)) )
            BUG();
        iommu_enable_translation(drhd);
    }
}

int domain_context_mapping_one(
    struct domain *domain,
    struct vtd_iommu *iommu,
    u8 bus, u8 devfn, const struct pci_dev *pdev)
{
    struct domain_iommu *hd = dom_iommu(domain);
    struct context_entry *context, *context_entries;
    u64 maddr, pgd_maddr;
    u16 seg = iommu->drhd->segment;
    int agaw, rc, ret;
    bool_t flush_dev_iotlb;

    ASSERT(pcidevs_locked());
    spin_lock(&iommu->lock);
    maddr = bus_to_context_maddr(iommu, bus);
    context_entries = (struct context_entry *)map_vtd_domain_page(maddr);
    context = &context_entries[devfn];

    if ( context_present(*context) )
    {
        int res = 0;

        /* Try to get domain ownership from device structure.  If that's
         * not available, try to read it from the context itself. */
        if ( pdev )
        {
            if ( pdev->domain != domain )
            {
                printk(XENLOG_G_INFO VTDPREFIX
                       "d%d: %04x:%02x:%02x.%u owned by d%d!",
                       domain->domain_id,
                       seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                       pdev->domain ? pdev->domain->domain_id : -1);
                res = -EINVAL;
            }
        }
        else
        {
            int cdomain;
            cdomain = context_get_domain_id(context, iommu);
            
            if ( cdomain < 0 )
            {
                printk(XENLOG_G_WARNING VTDPREFIX
                       "d%d: %04x:%02x:%02x.%u mapped, but can't find owner!\n",
                       domain->domain_id,
                       seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
                res = -EINVAL;
            }
            else if ( cdomain != domain->domain_id )
            {
                printk(XENLOG_G_INFO VTDPREFIX
                       "d%d: %04x:%02x:%02x.%u already mapped to d%d!",
                       domain->domain_id,
                       seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                       cdomain);
                res = -EINVAL;
            }
        }

        unmap_vtd_domain_page(context_entries);
        spin_unlock(&iommu->lock);
        return res;
    }

    if ( iommu_hwdom_passthrough && is_hardware_domain(domain) )
    {
        context_set_translation_type(*context, CONTEXT_TT_PASS_THRU);
        agaw = level_to_agaw(iommu->nr_pt_levels);
    }
    else
    {
        spin_lock(&hd->arch.mapping_lock);

        /* Ensure we have pagetables allocated down to leaf PTE. */
        if ( hd->arch.pgd_maddr == 0 )
        {
            addr_to_dma_page_maddr(domain, 0, 1);
            if ( hd->arch.pgd_maddr == 0 )
            {
            nomem:
                spin_unlock(&hd->arch.mapping_lock);
                spin_unlock(&iommu->lock);
                unmap_vtd_domain_page(context_entries);
                return -ENOMEM;
            }
        }

        /* Skip top levels of page tables for 2- and 3-level DRHDs. */
        pgd_maddr = hd->arch.pgd_maddr;
        for ( agaw = level_to_agaw(4);
              agaw != level_to_agaw(iommu->nr_pt_levels);
              agaw-- )
        {
            struct dma_pte *p = map_vtd_domain_page(pgd_maddr);
            pgd_maddr = dma_pte_addr(*p);
            unmap_vtd_domain_page(p);
            if ( pgd_maddr == 0 )
                goto nomem;
        }

        context_set_address_root(*context, pgd_maddr);
        if ( ats_enabled && ecap_dev_iotlb(iommu->ecap) )
            context_set_translation_type(*context, CONTEXT_TT_DEV_IOTLB);
        else
            context_set_translation_type(*context, CONTEXT_TT_MULTI_LEVEL);

        spin_unlock(&hd->arch.mapping_lock);
    }

    if ( context_set_domain_id(context, domain, iommu) )
    {
        spin_unlock(&iommu->lock);
        unmap_vtd_domain_page(context_entries);
        return -EFAULT;
    }

    context_set_address_width(*context, agaw);
    context_set_fault_enable(*context);
    context_set_present(*context);
    iommu_flush_cache_entry(context, sizeof(struct context_entry));
    spin_unlock(&iommu->lock);

    /* Context entry was previously non-present (with domid 0). */
    rc = iommu_flush_context_device(iommu, 0, PCI_BDF2(bus, devfn),
                                    DMA_CCMD_MASK_NOBIT, 1);
    flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
    ret = iommu_flush_iotlb_dsi(iommu, 0, 1, flush_dev_iotlb);

    /*
     * The current logic for returns:
     *   - positive  invoke iommu_flush_write_buffer to flush cache.
     *   - zero      on success.
     *   - negative  on failure. Continue to flush IOMMU IOTLB on a
     *               best effort basis.
     */
    if ( rc > 0 || ret > 0 )
        iommu_flush_write_buffer(iommu);
    if ( rc >= 0 )
        rc = ret;
    if ( rc > 0 )
        rc = 0;

    set_bit(iommu->index, &hd->arch.iommu_bitmap);

    unmap_vtd_domain_page(context_entries);

    if ( !seg && !rc )
        rc = me_wifi_quirk(domain, bus, devfn, MAP_ME_PHANTOM_FUNC);

    return rc;
}

static int domain_context_mapping(struct domain *domain, u8 devfn,
                                  struct pci_dev *pdev)
{
    struct acpi_drhd_unit *drhd;
    int ret = 0;
    u8 seg = pdev->seg, bus = pdev->bus, secbus;

    drhd = acpi_find_matched_drhd_unit(pdev);
    if ( !drhd )
        return -ENODEV;

    /*
     * Generally we assume only devices from one node to get assigned to a
     * given guest.  But even if not, by replacing the prior value here we
     * guarantee that at least some basic allocations for the device being
     * added will get done against its node.  Any further allocations for
     * this or other devices may be penalized then, but some would also be
     * if we left other than NUMA_NO_NODE untouched here.
     */
    if ( drhd->iommu->node != NUMA_NO_NODE )
        dom_iommu(domain)->node = drhd->iommu->node;

    ASSERT(pcidevs_locked());

    switch ( pdev->type )
    {
    case DEV_TYPE_PCI_HOST_BRIDGE:
        if ( iommu_debug )
            printk(VTDPREFIX "d%d:Hostbridge: skip %04x:%02x:%02x.%u map\n",
                   domain->domain_id, seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
        if ( !is_hardware_domain(domain) )
            return -EPERM;
        break;

    case DEV_TYPE_PCIe_BRIDGE:
    case DEV_TYPE_PCIe2PCI_BRIDGE:
    case DEV_TYPE_LEGACY_PCI_BRIDGE:
        break;

    case DEV_TYPE_PCIe_ENDPOINT:
        if ( iommu_debug )
            printk(VTDPREFIX "d%d:PCIe: map %04x:%02x:%02x.%u\n",
                   domain->domain_id, seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
        ret = domain_context_mapping_one(domain, drhd->iommu, bus, devfn,
                                         pdev);
        if ( !ret && devfn == pdev->devfn && ats_device(pdev, drhd) > 0 )
            enable_ats_device(pdev, &drhd->iommu->ats_devices);

        break;

    case DEV_TYPE_PCI:
        if ( iommu_debug )
            printk(VTDPREFIX "d%d:PCI: map %04x:%02x:%02x.%u\n",
                   domain->domain_id, seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));

        ret = domain_context_mapping_one(domain, drhd->iommu, bus, devfn,
                                         pdev);
        if ( ret )
            break;

        if ( find_upstream_bridge(seg, &bus, &devfn, &secbus) < 1 )
            break;

        ret = domain_context_mapping_one(domain, drhd->iommu, bus, devfn,
                                         pci_get_pdev(seg, bus, devfn));

        /*
         * Devices behind PCIe-to-PCI/PCIx bridge may generate different
         * requester-id. It may originate from devfn=0 on the secondary bus
         * behind the bridge. Map that id as well if we didn't already.
         */
        if ( !ret && pdev_type(seg, bus, devfn) == DEV_TYPE_PCIe2PCI_BRIDGE &&
             (secbus != pdev->bus || pdev->devfn != 0) )
            ret = domain_context_mapping_one(domain, drhd->iommu, secbus, 0,
                                             pci_get_pdev(seg, secbus, 0));

        break;

    default:
        dprintk(XENLOG_ERR VTDPREFIX, "d%d:unknown(%u): %04x:%02x:%02x.%u\n",
                domain->domain_id, pdev->type,
                seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        ret = -EINVAL;
        break;
    }

    if ( !ret && devfn == pdev->devfn )
        pci_vtd_quirk(pdev);

    return ret;
}

int domain_context_unmap_one(
    struct domain *domain,
    struct vtd_iommu *iommu,
    u8 bus, u8 devfn)
{
    struct context_entry *context, *context_entries;
    u64 maddr;
    int iommu_domid, rc, ret;
    bool_t flush_dev_iotlb;

    ASSERT(pcidevs_locked());
    spin_lock(&iommu->lock);

    maddr = bus_to_context_maddr(iommu, bus);
    context_entries = (struct context_entry *)map_vtd_domain_page(maddr);
    context = &context_entries[devfn];

    if ( !context_present(*context) )
    {
        spin_unlock(&iommu->lock);
        unmap_vtd_domain_page(context_entries);
        return 0;
    }

    context_clear_present(*context);
    context_clear_entry(*context);
    iommu_flush_cache_entry(context, sizeof(struct context_entry));

    iommu_domid= domain_iommu_domid(domain, iommu);
    if ( iommu_domid == -1 )
    {
        spin_unlock(&iommu->lock);
        unmap_vtd_domain_page(context_entries);
        return -EINVAL;
    }

    rc = iommu_flush_context_device(iommu, iommu_domid,
                                    PCI_BDF2(bus, devfn),
                                    DMA_CCMD_MASK_NOBIT, 0);

    flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
    ret = iommu_flush_iotlb_dsi(iommu, iommu_domid, 0, flush_dev_iotlb);

    /*
     * The current logic for returns:
     *   - positive  invoke iommu_flush_write_buffer to flush cache.
     *   - zero      on success.
     *   - negative  on failure. Continue to flush IOMMU IOTLB on a
     *               best effort basis.
     */
    if ( rc > 0 || ret > 0 )
        iommu_flush_write_buffer(iommu);
    if ( rc >= 0 )
        rc = ret;
    if ( rc > 0 )
        rc = 0;

    spin_unlock(&iommu->lock);
    unmap_vtd_domain_page(context_entries);

    if ( !iommu->drhd->segment && !rc )
        rc = me_wifi_quirk(domain, bus, devfn, UNMAP_ME_PHANTOM_FUNC);

    return rc;
}

static int domain_context_unmap(struct domain *domain, u8 devfn,
                                struct pci_dev *pdev)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    int ret = 0;
    u8 seg = pdev->seg, bus = pdev->bus, tmp_bus, tmp_devfn, secbus;
    int found = 0;

    drhd = acpi_find_matched_drhd_unit(pdev);
    if ( !drhd )
        return -ENODEV;
    iommu = drhd->iommu;

    switch ( pdev->type )
    {
    case DEV_TYPE_PCI_HOST_BRIDGE:
        if ( iommu_debug )
            printk(VTDPREFIX "d%d:Hostbridge: skip %04x:%02x:%02x.%u unmap\n",
                   domain->domain_id, seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
        if ( !is_hardware_domain(domain) )
            return -EPERM;
        goto out;

    case DEV_TYPE_PCIe_BRIDGE:
    case DEV_TYPE_PCIe2PCI_BRIDGE:
    case DEV_TYPE_LEGACY_PCI_BRIDGE:
        goto out;

    case DEV_TYPE_PCIe_ENDPOINT:
        if ( iommu_debug )
            printk(VTDPREFIX "d%d:PCIe: unmap %04x:%02x:%02x.%u\n",
                   domain->domain_id, seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
        ret = domain_context_unmap_one(domain, iommu, bus, devfn);
        if ( !ret && devfn == pdev->devfn && ats_device(pdev, drhd) > 0 )
            disable_ats_device(pdev);

        break;

    case DEV_TYPE_PCI:
        if ( iommu_debug )
            printk(VTDPREFIX "d%d:PCI: unmap %04x:%02x:%02x.%u\n",
                   domain->domain_id, seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        ret = domain_context_unmap_one(domain, iommu, bus, devfn);
        if ( ret )
            break;

        tmp_bus = bus;
        tmp_devfn = devfn;
        if ( find_upstream_bridge(seg, &tmp_bus, &tmp_devfn, &secbus) < 1 )
            break;

        /* PCIe to PCI/PCIx bridge */
        if ( pdev_type(seg, tmp_bus, tmp_devfn) == DEV_TYPE_PCIe2PCI_BRIDGE )
        {
            ret = domain_context_unmap_one(domain, iommu, tmp_bus, tmp_devfn);
            if ( ret )
                return ret;

            ret = domain_context_unmap_one(domain, iommu, secbus, 0);
        }
        else /* Legacy PCI bridge */
            ret = domain_context_unmap_one(domain, iommu, tmp_bus, tmp_devfn);

        break;

    default:
        dprintk(XENLOG_ERR VTDPREFIX, "d%d:unknown(%u): %04x:%02x:%02x.%u\n",
                domain->domain_id, pdev->type,
                seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        ret = -EINVAL;
        goto out;
    }

    /*
     * if no other devices under the same iommu owned by this domain,
     * clear iommu in iommu_bitmap and clear domain_id in domid_bitmp
     */
    for_each_pdev ( domain, pdev )
    {
        if ( pdev->seg == seg && pdev->bus == bus && pdev->devfn == devfn )
            continue;

        drhd = acpi_find_matched_drhd_unit(pdev);
        if ( drhd && drhd->iommu == iommu )
        {
            found = 1;
            break;
        }
    }

    if ( found == 0 )
    {
        int iommu_domid;

        clear_bit(iommu->index, &dom_iommu(domain)->arch.iommu_bitmap);

        iommu_domid = domain_iommu_domid(domain, iommu);
        if ( iommu_domid == -1 )
        {
            ret = -EINVAL;
            goto out;
        }

        clear_bit(iommu_domid, iommu->domid_bitmap);
        iommu->domid_map[iommu_domid] = 0;
    }

out:
    return ret;
}

static void iommu_domain_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct mapped_rmrr *mrmrr, *tmp;

    if ( list_empty(&acpi_drhd_units) )
        return;

    list_for_each_entry_safe ( mrmrr, tmp, &hd->arch.mapped_rmrrs, list )
    {
        list_del(&mrmrr->list);
        xfree(mrmrr);
    }

    ASSERT(is_iommu_enabled(d));

    if ( iommu_use_hap_pt(d) )
        return;

    spin_lock(&hd->arch.mapping_lock);
    iommu_free_pagetable(hd->arch.pgd_maddr, agaw_to_level(hd->arch.agaw));
    hd->arch.pgd_maddr = 0;
    spin_unlock(&hd->arch.mapping_lock);
}

static int __must_check intel_iommu_map_page(struct domain *d, dfn_t dfn,
                                             mfn_t mfn, unsigned int flags,
                                             unsigned int *flush_flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct dma_pte *page, *pte, old, new = {};
    u64 pg_maddr;
    int rc = 0;

    /* Do nothing if VT-d shares EPT page table */
    if ( iommu_use_hap_pt(d) )
        return 0;

    /* Do nothing if hardware domain and iommu supports pass thru. */
    if ( iommu_hwdom_passthrough && is_hardware_domain(d) )
        return 0;

    spin_lock(&hd->arch.mapping_lock);

    pg_maddr = addr_to_dma_page_maddr(d, dfn_to_daddr(dfn), 1);
    if ( !pg_maddr )
    {
        spin_unlock(&hd->arch.mapping_lock);
        return -ENOMEM;
    }

    page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
    pte = &page[dfn_x(dfn) & LEVEL_MASK];
    old = *pte;

    dma_set_pte_addr(new, mfn_to_maddr(mfn));
    dma_set_pte_prot(new,
                     ((flags & IOMMUF_readable) ? DMA_PTE_READ  : 0) |
                     ((flags & IOMMUF_writable) ? DMA_PTE_WRITE : 0));

    /* Set the SNP on leaf page table if Snoop Control available */
    if ( iommu_snoop )
        dma_set_pte_snp(new);

    if ( old.val == new.val )
    {
        spin_unlock(&hd->arch.mapping_lock);
        unmap_vtd_domain_page(page);
        return 0;
    }

    *pte = new;

    iommu_flush_cache_entry(pte, sizeof(struct dma_pte));
    spin_unlock(&hd->arch.mapping_lock);
    unmap_vtd_domain_page(page);

    *flush_flags |= IOMMU_FLUSHF_added;
    if ( dma_pte_present(old) )
        *flush_flags |= IOMMU_FLUSHF_modified;

    return rc;
}

static int __must_check intel_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                               unsigned int *flush_flags)
{
    /* Do nothing if VT-d shares EPT page table */
    if ( iommu_use_hap_pt(d) )
        return 0;

    /* Do nothing if hardware domain and iommu supports pass thru. */
    if ( iommu_hwdom_passthrough && is_hardware_domain(d) )
        return 0;

    return dma_pte_clear_one(d, dfn_to_daddr(dfn), flush_flags);
}

static int intel_iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                                   unsigned int *flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct dma_pte *page, val;
    u64 pg_maddr;

    /*
     * If VT-d shares EPT page table or if the domain is the hardware
     * domain and iommu_passthrough is set then pass back the dfn.
     */
    if ( iommu_use_hap_pt(d) ||
         (iommu_hwdom_passthrough && is_hardware_domain(d)) )
        return -EOPNOTSUPP;

    spin_lock(&hd->arch.mapping_lock);

    pg_maddr = addr_to_dma_page_maddr(d, dfn_to_daddr(dfn), 0);
    if ( !pg_maddr )
    {
        spin_unlock(&hd->arch.mapping_lock);
        return -ENOENT;
    }

    page = map_vtd_domain_page(pg_maddr);
    val = page[dfn_x(dfn) & LEVEL_MASK];

    unmap_vtd_domain_page(page);
    spin_unlock(&hd->arch.mapping_lock);

    if ( !dma_pte_present(val) )
        return -ENOENT;

    *mfn = maddr_to_mfn(dma_pte_addr(val));
    *flags = dma_pte_read(val) ? IOMMUF_readable : 0;
    *flags |= dma_pte_write(val) ? IOMMUF_writable : 0;

    return 0;
}

int iommu_pte_flush(struct domain *d, uint64_t dfn, uint64_t *pte,
                    int order, int present)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu = NULL;
    struct domain_iommu *hd = dom_iommu(d);
    bool_t flush_dev_iotlb;
    int iommu_domid;
    int rc = 0;

    iommu_flush_cache_entry(pte, sizeof(struct dma_pte));

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( !test_bit(iommu->index, &hd->arch.iommu_bitmap) )
            continue;

        flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
        iommu_domid= domain_iommu_domid(d, iommu);
        if ( iommu_domid == -1 )
            continue;

        rc = iommu_flush_iotlb_psi(iommu, iommu_domid,
                                   __dfn_to_daddr(dfn),
                                   order, !present, flush_dev_iotlb);
        if ( rc > 0 )
        {
            iommu_flush_write_buffer(iommu);
            rc = 0;
        }
    }

    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR VTDPREFIX
                   " d%d: IOMMU pages flush failed: %d\n",
                   d->domain_id, rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

static int __init vtd_ept_page_compatible(struct vtd_iommu *iommu)
{
    u64 ept_cap, vtd_cap = iommu->cap;

    /* EPT is not initialised yet, so we must check the capability in
     * the MSR explicitly rather than use cpu_has_vmx_ept_*() */
    if ( rdmsr_safe(MSR_IA32_VMX_EPT_VPID_CAP, ept_cap) != 0 ) 
        return 0;

    return (ept_has_2mb(ept_cap) && opt_hap_2mb) == cap_sps_2mb(vtd_cap) &&
           (ept_has_1gb(ept_cap) && opt_hap_1gb) == cap_sps_1gb(vtd_cap);
}

/*
 * set VT-d page table directory to EPT table if allowed
 */
static void iommu_set_pgd(struct domain *d)
{
    mfn_t pgd_mfn;

    pgd_mfn = pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)));
    dom_iommu(d)->arch.pgd_maddr =
        pagetable_get_paddr(pagetable_from_mfn(pgd_mfn));
}

static int rmrr_identity_mapping(struct domain *d, bool_t map,
                                 const struct acpi_rmrr_unit *rmrr,
                                 u32 flag)
{
    unsigned long base_pfn = rmrr->base_address >> PAGE_SHIFT_4K;
    unsigned long end_pfn = PAGE_ALIGN_4K(rmrr->end_address) >> PAGE_SHIFT_4K;
    struct mapped_rmrr *mrmrr;
    struct domain_iommu *hd = dom_iommu(d);

    ASSERT(pcidevs_locked());
    ASSERT(rmrr->base_address < rmrr->end_address);

    /*
     * No need to acquire hd->arch.mapping_lock: Both insertion and removal
     * get done while holding pcidevs_lock.
     */
    list_for_each_entry( mrmrr, &hd->arch.mapped_rmrrs, list )
    {
        if ( mrmrr->base == rmrr->base_address &&
             mrmrr->end == rmrr->end_address )
        {
            int ret = 0;

            if ( map )
            {
                ++mrmrr->count;
                return 0;
            }

            if ( --mrmrr->count )
                return 0;

            while ( base_pfn < end_pfn )
            {
                if ( clear_identity_p2m_entry(d, base_pfn) )
                    ret = -ENXIO;
                base_pfn++;
            }

            list_del(&mrmrr->list);
            xfree(mrmrr);
            return ret;
        }
    }

    if ( !map )
        return -ENOENT;

    while ( base_pfn < end_pfn )
    {
        int err = set_identity_p2m_entry(d, base_pfn, p2m_access_rw, flag);

        if ( err )
            return err;
        base_pfn++;
    }

    mrmrr = xmalloc(struct mapped_rmrr);
    if ( !mrmrr )
        return -ENOMEM;
    mrmrr->base = rmrr->base_address;
    mrmrr->end = rmrr->end_address;
    mrmrr->count = 1;
    list_add_tail(&mrmrr->list, &hd->arch.mapped_rmrrs);

    return 0;
}

static int intel_iommu_add_device(u8 devfn, struct pci_dev *pdev)
{
    struct acpi_rmrr_unit *rmrr;
    u16 bdf;
    int ret, i;

    ASSERT(pcidevs_locked());

    if ( !pdev->domain )
        return -EINVAL;

    ret = domain_context_mapping(pdev->domain, devfn, pdev);
    if ( ret )
    {
        dprintk(XENLOG_ERR VTDPREFIX, "d%d: context mapping failed\n",
                pdev->domain->domain_id);
        return ret;
    }

    for_each_rmrr_device ( rmrr, bdf, i )
    {
        if ( rmrr->segment == pdev->seg &&
             PCI_BUS(bdf) == pdev->bus &&
             PCI_DEVFN2(bdf) == devfn )
        {
            /*
             * iommu_add_device() is only called for the hardware
             * domain (see xen/drivers/passthrough/pci.c:pci_add_device()).
             * Since RMRRs are always reserved in the e820 map for the hardware
             * domain, there shouldn't be a conflict.
             */
            ret = rmrr_identity_mapping(pdev->domain, 1, rmrr, 0);
            if ( ret )
                dprintk(XENLOG_ERR VTDPREFIX, "d%d: RMRR mapping failed\n",
                        pdev->domain->domain_id);
        }
    }

    return 0;
}

static int intel_iommu_enable_device(struct pci_dev *pdev)
{
    struct acpi_drhd_unit *drhd = acpi_find_matched_drhd_unit(pdev);
    int ret = drhd ? ats_device(pdev, drhd) : -ENODEV;

    pci_vtd_quirk(pdev);

    if ( ret <= 0 )
        return ret;

    ret = enable_ats_device(pdev, &drhd->iommu->ats_devices);

    return ret >= 0 ? 0 : ret;
}

static int intel_iommu_remove_device(u8 devfn, struct pci_dev *pdev)
{
    struct acpi_rmrr_unit *rmrr;
    u16 bdf;
    int i;

    if ( !pdev->domain )
        return -EINVAL;

    for_each_rmrr_device ( rmrr, bdf, i )
    {
        if ( rmrr->segment != pdev->seg ||
             PCI_BUS(bdf) != pdev->bus ||
             PCI_DEVFN2(bdf) != devfn )
            continue;

        /*
         * Any flag is nothing to clear these mappings but here
         * its always safe and strict to set 0.
         */
        rmrr_identity_mapping(pdev->domain, 0, rmrr, 0);
    }

    return domain_context_unmap(pdev->domain, devfn, pdev);
}

static int __hwdom_init setup_hwdom_device(u8 devfn, struct pci_dev *pdev)
{
    return domain_context_mapping(pdev->domain, devfn, pdev);
}

void clear_fault_bits(struct vtd_iommu *iommu)
{
    u64 val;
    unsigned long flags;

    spin_lock_irqsave(&iommu->register_lock, flags);
    val = dmar_readq(iommu->reg, cap_fault_reg_offset(iommu->cap) + 8);
    dmar_writeq(iommu->reg, cap_fault_reg_offset(iommu->cap) + 8, val);
    dmar_writel(iommu->reg, DMAR_FSTS_REG, DMA_FSTS_FAULTS);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void adjust_irq_affinity(struct acpi_drhd_unit *drhd)
{
    const struct acpi_rhsa_unit *rhsa = drhd_to_rhsa(drhd);
    unsigned int node = rhsa ? pxm_to_node(rhsa->proximity_domain)
                             : NUMA_NO_NODE;
    const cpumask_t *cpumask = NULL;
    struct irq_desc *desc;
    unsigned long flags;

    if ( node < MAX_NUMNODES && node_online(node) &&
         cpumask_intersects(&node_to_cpumask(node), &cpu_online_map) )
        cpumask = &node_to_cpumask(node);

    desc = irq_to_desc(drhd->iommu->msi.irq);
    spin_lock_irqsave(&desc->lock, flags);
    dma_msi_set_affinity(desc, cpumask);
    spin_unlock_irqrestore(&desc->lock, flags);
}

static int adjust_vtd_irq_affinities(void)
{
    struct acpi_drhd_unit *drhd;

    if ( !iommu_enabled )
        return 0;

    for_each_drhd_unit ( drhd )
        adjust_irq_affinity(drhd);

    return 0;
}
__initcall(adjust_vtd_irq_affinities);

static int __must_check init_vtd_hw(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    int ret;
    unsigned long flags;
    u32 sts;

    /*
     * Basic VT-d HW init: set VT-d interrupt, clear VT-d faults.  
     */
    for_each_drhd_unit ( drhd )
    {
        adjust_irq_affinity(drhd);

        iommu = drhd->iommu;

        clear_fault_bits(iommu);

        spin_lock_irqsave(&iommu->register_lock, flags);
        sts = dmar_readl(iommu->reg, DMAR_FECTL_REG);
        sts &= ~DMA_FECTL_IM;
        dmar_writel(iommu->reg, DMAR_FECTL_REG, sts);
        spin_unlock_irqrestore(&iommu->register_lock, flags);
    }

    /*
     * Enable queue invalidation
     */   
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        /*
         * If queued invalidation not enabled, use regiser based
         * invalidation
         */
        if ( enable_qinval(iommu) != 0 )
        {
            iommu->flush.context = flush_context_reg;
            iommu->flush.iotlb   = flush_iotlb_reg;
        }
    }

    /*
     * Enable interrupt remapping
     */  
    if ( iommu_intremap )
    {
        int apic;
        for ( apic = 0; apic < nr_ioapics; apic++ )
        {
            if ( ioapic_to_iommu(IO_APIC_ID(apic)) == NULL )
            {
                iommu_intremap = 0;
                dprintk(XENLOG_ERR VTDPREFIX,
                    "ioapic_to_iommu: ioapic %#x (id: %#x) is NULL! "
                    "Will not try to enable Interrupt Remapping.\n",
                    apic, IO_APIC_ID(apic));
                break;
            }
        }
    }
    if ( iommu_intremap )
    {
        for_each_drhd_unit ( drhd )
        {
            iommu = drhd->iommu;
            if ( enable_intremap(iommu, 0) != 0 )
            {
                iommu_intremap = 0;
                dprintk(XENLOG_WARNING VTDPREFIX,
                        "Interrupt Remapping not enabled\n");

                break;
            }
        }
        if ( !iommu_intremap )
            for_each_drhd_unit ( drhd )
                disable_intremap(drhd->iommu);
    }

    /*
     * Set root entries for each VT-d engine.  After set root entry,
     * must globally invalidate context cache, and then globally
     * invalidate IOTLB
     */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        ret = iommu_set_root_entry(iommu);
        if ( ret )
        {
            dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: set root entry failed\n");
            return -EIO;
        }
    }

    return iommu_flush_all();
}

static void __hwdom_init setup_hwdom_rmrr(struct domain *d)
{
    struct acpi_rmrr_unit *rmrr;
    u16 bdf;
    int ret, i;

    pcidevs_lock();
    for_each_rmrr_device ( rmrr, bdf, i )
    {
        /*
         * Here means we're add a device to the hardware domain.
         * Since RMRRs are always reserved in the e820 map for the hardware
         * domain, there shouldn't be a conflict. So its always safe and
         * strict to set 0.
         */
        ret = rmrr_identity_mapping(d, 1, rmrr, 0);
        if ( ret )
            dprintk(XENLOG_ERR VTDPREFIX,
                     "IOMMU: mapping reserved region failed\n");
    }
    pcidevs_unlock();
}

static int __init vtd_setup(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    int ret;

    if ( list_empty(&acpi_drhd_units) )
    {
        ret = -ENODEV;
        goto error;
    }

    if ( unlikely(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI) )
    {
        ret = -EPERM;
        goto error;
    }

    platform_quirks_init();
    if ( !iommu_enable )
    {
        ret = -ENODEV;
        goto error;
    }

    /* We enable the following features only if they are supported by all VT-d
     * engines: Snoop Control, DMA passthrough, Queued Invalidation, Interrupt
     * Remapping, and Posted Interrupt
     */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;

        printk("Intel VT-d iommu %"PRIu32" supported page sizes: 4kB",
               iommu->index);
        if (cap_sps_2mb(iommu->cap))
            printk(", 2MB");

        if (cap_sps_1gb(iommu->cap))
            printk(", 1GB");

        printk(".\n");

        if ( iommu_snoop && !ecap_snp_ctl(iommu->ecap) )
            iommu_snoop = 0;

        if ( iommu_hwdom_passthrough && !ecap_pass_thru(iommu->ecap) )
            iommu_hwdom_passthrough = false;

        if ( iommu_qinval && !ecap_queued_inval(iommu->ecap) )
            iommu_qinval = 0;

        if ( iommu_intremap && !ecap_intr_remap(iommu->ecap) )
            iommu_intremap = 0;

        /*
         * We cannot use posted interrupt if X86_FEATURE_CX16 is
         * not supported, since we count on this feature to
         * atomically update 16-byte IRTE in posted format.
         */
        if ( !cap_intr_post(iommu->cap) || !iommu_intremap || !cpu_has_cx16 )
            iommu_intpost = 0;

        if ( !vtd_ept_page_compatible(iommu) )
            clear_iommu_hap_pt_share();

        ret = iommu_set_interrupt(drhd);
        if ( ret )
        {
            dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: interrupt setup failed\n");
            goto error;
        }
    }

    softirq_tasklet_init(&vtd_fault_tasklet, do_iommu_page_fault, 0);

    if ( !iommu_qinval && iommu_intremap )
    {
        iommu_intremap = 0;
        dprintk(XENLOG_WARNING VTDPREFIX, "Interrupt Remapping disabled "
            "since Queued Invalidation isn't supported or enabled.\n");
    }

#define P(p,s) printk("Intel VT-d %s %senabled.\n", s, (p)? "" : "not ")
    P(iommu_snoop, "Snoop Control");
    P(iommu_hwdom_passthrough, "Dom0 DMA Passthrough");
    P(iommu_qinval, "Queued Invalidation");
    P(iommu_intremap, "Interrupt Remapping");
    P(iommu_intpost, "Posted Interrupt");
    P(iommu_hap_pt_share, "Shared EPT tables");
#undef P

    ret = init_vtd_hw();
    if ( ret )
        goto error;

    register_keyhandler('V', vtd_dump_iommu_info, "dump iommu info", 1);

    return 0;

 error:
    iommu_enabled = 0;
    iommu_snoop = 0;
    iommu_hwdom_passthrough = false;
    iommu_qinval = 0;
    iommu_intremap = 0;
    iommu_intpost = 0;
    return ret;
}

static int reassign_device_ownership(
    struct domain *source,
    struct domain *target,
    u8 devfn, struct pci_dev *pdev)
{
    int ret;

    /*
     * Devices assigned to untrusted domains (here assumed to be any domU)
     * can attempt to send arbitrary LAPIC/MSI messages. We are unprotected
     * by the root complex unless interrupt remapping is enabled.
     */
    if ( (target != hardware_domain) && !iommu_intremap )
        untrusted_msi = true;

    /*
     * If the device belongs to the hardware domain, and it has RMRR, don't
     * remove it from the hardware domain, because BIOS may use RMRR at
     * booting time.
     */
    if ( !is_hardware_domain(source) )
    {
        const struct acpi_rmrr_unit *rmrr;
        u16 bdf;
        unsigned int i;

        for_each_rmrr_device( rmrr, bdf, i )
            if ( rmrr->segment == pdev->seg &&
                 PCI_BUS(bdf) == pdev->bus &&
                 PCI_DEVFN2(bdf) == devfn )
            {
                /*
                 * Any RMRR flag is always ignored when remove a device,
                 * but its always safe and strict to set 0.
                 */
                ret = rmrr_identity_mapping(source, 0, rmrr, 0);
                if ( ret != -ENOENT )
                    return ret;
            }
    }

    ret = domain_context_unmap(source, devfn, pdev);
    if ( ret )
        return ret;

    if ( !has_arch_pdevs(target) )
        vmx_pi_hooks_assign(target);

    ret = domain_context_mapping(target, devfn, pdev);
    if ( ret )
    {
        if ( !has_arch_pdevs(target) )
            vmx_pi_hooks_deassign(target);

        return ret;
    }

    if ( devfn == pdev->devfn )
    {
        list_move(&pdev->domain_list, &target->pdev_list);
        pdev->domain = target;
    }

    if ( !has_arch_pdevs(source) )
        vmx_pi_hooks_deassign(source);

    return ret;
}

static int intel_iommu_assign_device(
    struct domain *d, u8 devfn, struct pci_dev *pdev, u32 flag)
{
    struct acpi_rmrr_unit *rmrr;
    int ret = 0, i;
    u16 bdf, seg;
    u8 bus;

    if ( list_empty(&acpi_drhd_units) )
        return -ENODEV;

    seg = pdev->seg;
    bus = pdev->bus;
    /*
     * In rare cases one given rmrr is shared by multiple devices but
     * obviously this would put the security of a system at risk. So
     * we would prevent from this sort of device assignment. But this
     * can be permitted if user set
     *      "pci = [ 'sbdf, rdm_policy=relaxed' ]"
     *
     * TODO: in the future we can introduce group device assignment
     * interface to make sure devices sharing RMRR are assigned to the
     * same domain together.
     */
    for_each_rmrr_device( rmrr, bdf, i )
    {
        if ( rmrr->segment == seg &&
             PCI_BUS(bdf) == bus &&
             PCI_DEVFN2(bdf) == devfn &&
             rmrr->scope.devices_cnt > 1 )
        {
            bool_t relaxed = !!(flag & XEN_DOMCTL_DEV_RDM_RELAXED);

            printk(XENLOG_GUEST "%s" VTDPREFIX
                   " It's %s to assign %04x:%02x:%02x.%u"
                   " with shared RMRR at %"PRIx64" for Dom%d.\n",
                   relaxed ? XENLOG_WARNING : XENLOG_ERR,
                   relaxed ? "risky" : "disallowed",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   rmrr->base_address, d->domain_id);
            if ( !relaxed )
                return -EPERM;
        }
    }

    ret = reassign_device_ownership(hardware_domain, d, devfn, pdev);
    if ( ret )
        return ret;

    /* Setup rmrr identity mapping */
    for_each_rmrr_device( rmrr, bdf, i )
    {
        if ( rmrr->segment == seg &&
             PCI_BUS(bdf) == bus &&
             PCI_DEVFN2(bdf) == devfn )
        {
            ret = rmrr_identity_mapping(d, 1, rmrr, flag);
            if ( ret )
            {
                reassign_device_ownership(d, hardware_domain, devfn, pdev);
                printk(XENLOG_G_ERR VTDPREFIX
                       " cannot map reserved region (%"PRIx64",%"PRIx64"] for Dom%d (%d)\n",
                       rmrr->base_address, rmrr->end_address,
                       d->domain_id, ret);
                break;
            }
        }
    }

    return ret;
}

static int intel_iommu_group_id(u16 seg, u8 bus, u8 devfn)
{
    u8 secbus;
    if ( find_upstream_bridge(seg, &bus, &devfn, &secbus) < 0 )
        return -1;
    else
        return PCI_BDF2(bus, devfn);
}

static u32 iommu_state[MAX_IOMMUS][MAX_IOMMU_REGS];

static int __must_check vtd_suspend(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    u32    i;
    int rc;

    if ( !iommu_enabled )
        return 0;

    rc = iommu_flush_all();
    if ( unlikely(rc) )
    {
        printk(XENLOG_WARNING VTDPREFIX
               " suspend: IOMMU flush all failed: %d\n", rc);

        return rc;
    }

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        i = iommu->index;

        iommu_state[i][DMAR_FECTL_REG] =
            (u32) dmar_readl(iommu->reg, DMAR_FECTL_REG);
        iommu_state[i][DMAR_FEDATA_REG] =
            (u32) dmar_readl(iommu->reg, DMAR_FEDATA_REG);
        iommu_state[i][DMAR_FEADDR_REG] =
            (u32) dmar_readl(iommu->reg, DMAR_FEADDR_REG);
        iommu_state[i][DMAR_FEUADDR_REG] =
            (u32) dmar_readl(iommu->reg, DMAR_FEUADDR_REG);

        /* don't disable VT-d engine when force_iommu is set. */
        if ( force_iommu )
            continue;

        iommu_disable_translation(iommu);

        /* If interrupt remapping is enabled, queued invalidation
         * will be disabled following interupt remapping disabling
         * in local apic suspend
         */
        if ( !iommu_intremap && iommu_qinval )
            disable_qinval(iommu);
    }

    return 0;
}

static void vtd_crash_shutdown(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;

    if ( !iommu_enabled )
        return;

    if ( iommu_flush_all() )
        printk(XENLOG_WARNING VTDPREFIX
               " crash shutdown: IOMMU flush all failed\n");

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        iommu_disable_translation(iommu);
        disable_intremap(drhd->iommu);
        disable_qinval(drhd->iommu);
    }
}

static void vtd_resume(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    u32 i;
    unsigned long flags;

    if ( !iommu_enabled )
        return;

    if ( init_vtd_hw() != 0  && force_iommu )
         panic("IOMMU setup failed, crash Xen for security purpose\n");

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        i = iommu->index;

        spin_lock_irqsave(&iommu->register_lock, flags);
        dmar_writel(iommu->reg, DMAR_FECTL_REG,
                    (u32) iommu_state[i][DMAR_FECTL_REG]);
        dmar_writel(iommu->reg, DMAR_FEDATA_REG,
                    (u32) iommu_state[i][DMAR_FEDATA_REG]);
        dmar_writel(iommu->reg, DMAR_FEADDR_REG,
                    (u32) iommu_state[i][DMAR_FEADDR_REG]);
        dmar_writel(iommu->reg, DMAR_FEUADDR_REG,
                    (u32) iommu_state[i][DMAR_FEUADDR_REG]);
        spin_unlock_irqrestore(&iommu->register_lock, flags);

        iommu_enable_translation(drhd);
    }
}

static void vtd_dump_p2m_table_level(paddr_t pt_maddr, int level, paddr_t gpa, 
                                     int indent)
{
    paddr_t address;
    int i;
    struct dma_pte *pt_vaddr, *pte;
    int next_level;

    if ( level < 1 )
        return;

    pt_vaddr = map_vtd_domain_page(pt_maddr);
    if ( pt_vaddr == NULL )
    {
        printk("Failed to map VT-D domain page %"PRIpaddr"\n", pt_maddr);
        return;
    }

    next_level = level - 1;
    for ( i = 0; i < PTE_NUM; i++ )
    {
        if ( !(i % 2) )
            process_pending_softirqs();

        pte = &pt_vaddr[i];
        if ( !dma_pte_present(*pte) )
            continue;

        address = gpa + offset_level_address(i, level);
        if ( next_level >= 1 ) 
            vtd_dump_p2m_table_level(dma_pte_addr(*pte), next_level, 
                                     address, indent + 1);
        else
            printk("%*sdfn: %08lx mfn: %08lx\n",
                   indent, "",
                   (unsigned long)(address >> PAGE_SHIFT_4K),
                   (unsigned long)(dma_pte_addr(*pte) >> PAGE_SHIFT_4K));
    }

    unmap_vtd_domain_page(pt_vaddr);
}

static void vtd_dump_p2m_table(struct domain *d)
{
    const struct domain_iommu *hd;

    if ( list_empty(&acpi_drhd_units) )
        return;

    hd = dom_iommu(d);
    printk("p2m table has %d levels\n", agaw_to_level(hd->arch.agaw));
    vtd_dump_p2m_table_level(hd->arch.pgd_maddr, agaw_to_level(hd->arch.agaw), 0, 0);
}

const struct iommu_ops __initconstrel intel_iommu_ops = {
    .init = intel_iommu_domain_init,
    .hwdom_init = intel_iommu_hwdom_init,
    .add_device = intel_iommu_add_device,
    .enable_device = intel_iommu_enable_device,
    .remove_device = intel_iommu_remove_device,
    .assign_device  = intel_iommu_assign_device,
    .teardown = iommu_domain_teardown,
    .map_page = intel_iommu_map_page,
    .unmap_page = intel_iommu_unmap_page,
    .lookup_page = intel_iommu_lookup_page,
    .free_page_table = iommu_free_page_table,
    .reassign_device = reassign_device_ownership,
    .get_device_group_id = intel_iommu_group_id,
    .enable_x2apic = intel_iommu_enable_eim,
    .disable_x2apic = intel_iommu_disable_eim,
    .update_ire_from_apic = io_apic_write_remap_rte,
    .update_ire_from_msi = msi_msg_write_remap_rte,
    .read_apic_from_ire = io_apic_read_remap_rte,
    .read_msi_from_ire = msi_msg_read_remap_rte,
    .setup_hpet_msi = intel_setup_hpet_msi,
    .adjust_irq_affinities = adjust_vtd_irq_affinities,
    .suspend = vtd_suspend,
    .resume = vtd_resume,
    .share_p2m = iommu_set_pgd,
    .crash_shutdown = vtd_crash_shutdown,
    .iotlb_flush = iommu_flush_iotlb_pages,
    .iotlb_flush_all = iommu_flush_iotlb_all,
    .get_reserved_device_memory = intel_iommu_get_reserved_device_memory,
    .dump_p2m_table = vtd_dump_p2m_table,
};

const struct iommu_init_ops __initconstrel intel_iommu_init_ops = {
    .ops = &intel_iommu_ops,
    .setup = vtd_setup,
    .supports_x2apic = intel_iommu_supports_eim,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
