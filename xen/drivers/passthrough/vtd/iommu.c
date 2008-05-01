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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Copyright (C) Ashok Raj <ashok.raj@intel.com>
 * Copyright (C) Shaohua Li <shaohua.li@intel.com>
 * Copyright (C) Allen Kay <allen.m.kay@intel.com> - adapted to xen
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <xen/numa.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/paging.h>
#include "iommu.h"
#include "dmar.h"
#include "msi.h"
#include "extern.h"
#include "vtd.h"

#define domain_iommu_domid(d) ((d)->arch.hvm_domain.hvm_iommu.iommu_domid)

static spinlock_t domid_bitmap_lock;    /* protect domain id bitmap */
static int domid_bitmap_size;           /* domain id bitmap size in bits */
static unsigned long *domid_bitmap;     /* iommu domain id bitmap */

static void setup_dom0_devices(struct domain *d);
static void setup_dom0_rmrr(struct domain *d);

#define DID_FIELD_WIDTH 16
#define DID_HIGH_OFFSET 8
static void context_set_domain_id(struct context_entry *context,
                                  struct domain *d)
{
    unsigned long flags;
    domid_t iommu_domid = domain_iommu_domid(d);

    if ( iommu_domid == 0 )
    {
        spin_lock_irqsave(&domid_bitmap_lock, flags);
        iommu_domid = find_first_zero_bit(domid_bitmap, domid_bitmap_size);
        set_bit(iommu_domid, domid_bitmap);
        spin_unlock_irqrestore(&domid_bitmap_lock, flags);
        d->arch.hvm_domain.hvm_iommu.iommu_domid = iommu_domid;
    }

    context->hi &= (1 << DID_HIGH_OFFSET) - 1;
    context->hi |= iommu_domid << DID_HIGH_OFFSET;
}

static void iommu_domid_release(struct domain *d)
{
    domid_t iommu_domid = domain_iommu_domid(d);

    if ( iommu_domid != 0 )
    {
        d->arch.hvm_domain.hvm_iommu.iommu_domid = 0;
        clear_bit(iommu_domid, domid_bitmap);
    }
}

static struct intel_iommu *alloc_intel_iommu(void)
{
    struct intel_iommu *intel;

    intel = xmalloc(struct intel_iommu);
    if ( intel == NULL )
        return NULL;
    memset(intel, 0, sizeof(struct intel_iommu));

    spin_lock_init(&intel->qi_ctrl.qinval_lock);
    spin_lock_init(&intel->qi_ctrl.qinval_poll_lock);
    spin_lock_init(&intel->ir_ctrl.iremap_lock);

    return intel;
}

static void free_intel_iommu(struct intel_iommu *intel)
{
    xfree(intel);
}

struct qi_ctrl *iommu_qi_ctrl(struct iommu *iommu)
{
    return iommu ? &iommu->intel->qi_ctrl : NULL;
}

struct ir_ctrl *iommu_ir_ctrl(struct iommu *iommu)
{
    return iommu ? &iommu->intel->ir_ctrl : NULL;
}

struct iommu_flush *iommu_get_flush(struct iommu *iommu)
{
    return iommu ? &iommu->intel->flush : NULL;
}

unsigned int clflush_size;
void clflush_cache_range(void *adr, int size)
{
    int i;
    for ( i = 0; i < size; i += clflush_size )
        clflush(adr + i);
}

static void __iommu_flush_cache(struct iommu *iommu, void *addr, int size)
{
    if ( !ecap_coherent(iommu->ecap) )
        clflush_cache_range(addr, size);
}

void iommu_flush_cache_entry(struct iommu *iommu, void *addr)
{
    __iommu_flush_cache(iommu, addr, 8);
}

void iommu_flush_cache_page(struct iommu *iommu, void *addr)
{
    __iommu_flush_cache(iommu, addr, PAGE_SIZE_4K);
}

int nr_iommus;
/* context entry handling */
static u64 bus_to_context_maddr(struct iommu *iommu, u8 bus)
{
    struct root_entry *root, *root_entries;
    unsigned long flags;
    u64 maddr;

    spin_lock_irqsave(&iommu->lock, flags);
    root_entries = (struct root_entry *)map_vtd_domain_page(iommu->root_maddr);
    root = &root_entries[bus];
    if ( !root_present(*root) )
    {
        maddr = alloc_pgtable_maddr();
        if ( maddr == 0 )
        {
            spin_unlock_irqrestore(&iommu->lock, flags);
            return 0;
        }
        set_root_value(*root, maddr);
        set_root_present(*root);
        iommu_flush_cache_entry(iommu, root);
    }
    maddr = (u64) get_context_addr(*root);
    unmap_vtd_domain_page(root_entries);
    spin_unlock_irqrestore(&iommu->lock, flags);
    return maddr;
}

static int device_context_mapped(struct iommu *iommu, u8 bus, u8 devfn)
{
    struct root_entry *root, *root_entries;
    struct context_entry *context;
    u64 context_maddr;
    int ret;
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);
    root_entries = (struct root_entry *)map_vtd_domain_page(iommu->root_maddr);
    root = &root_entries[bus];
    if ( !root_present(*root) )
    {
        ret = 0;
        goto out;
    }
    context_maddr = get_context_addr(*root);
    context = (struct context_entry *)map_vtd_domain_page(context_maddr);
    ret = context_present(context[devfn]);
    unmap_vtd_domain_page(context);
 out:
    unmap_vtd_domain_page(root_entries);
    spin_unlock_irqrestore(&iommu->lock, flags);
    return ret;
}

static u64 addr_to_dma_page_maddr(struct domain *domain, u64 addr)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    int addr_width = agaw_to_width(hd->agaw);
    struct dma_pte *parent, *pte = NULL;
    int level = agaw_to_level(hd->agaw);
    int offset;
    unsigned long flags;
    u64 pte_maddr = 0;
    u64 *vaddr = NULL;

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;

    addr &= (((u64)1) << addr_width) - 1;
    spin_lock_irqsave(&hd->mapping_lock, flags);
    if ( hd->pgd_maddr == 0 )
    {
        hd->pgd_maddr = alloc_pgtable_maddr();
        if ( hd->pgd_maddr == 0 )
            return 0;
    }

    parent = (struct dma_pte *)map_vtd_domain_page(hd->pgd_maddr);
    while ( level > 1 )
    {
        offset = address_level_offset(addr, level);
        pte = &parent[offset];

        if ( dma_pte_addr(*pte) == 0 )
        {
            u64 maddr = alloc_pgtable_maddr();
            dma_set_pte_addr(*pte, maddr);
            vaddr = map_vtd_domain_page(maddr);
            if ( !vaddr )
                break;

            /*
             * high level table always sets r/w, last level
             * page table control read/write
             */
            dma_set_pte_readable(*pte);
            dma_set_pte_writable(*pte);
            iommu_flush_cache_entry(iommu, pte);
        }
        else
        {
            vaddr = map_vtd_domain_page(pte->val);
            if ( !vaddr )
                break;
        }

        if ( level == 2 )
        {
            pte_maddr = pte->val & PAGE_MASK_4K;
            unmap_vtd_domain_page(vaddr);
            break;
        }

        unmap_vtd_domain_page(parent);
        parent = (struct dma_pte *)vaddr;
        vaddr = NULL;
        level--;
    }

    unmap_vtd_domain_page(parent);
    spin_unlock_irqrestore(&hd->mapping_lock, flags);
    return pte_maddr;
}

/* return address's page at specific level */
static u64 dma_addr_level_page_maddr(
    struct domain *domain, u64 addr, int level)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);
    struct dma_pte *parent, *pte = NULL;
    int total = agaw_to_level(hd->agaw);
    int offset;
    u64 pg_maddr = hd->pgd_maddr;

    if ( pg_maddr == 0 )
        return 0;

    parent = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
    while ( level <= total )
    {
        offset = address_level_offset(addr, total);
        pte = &parent[offset];
        if ( dma_pte_addr(*pte) == 0 )
            break;

        pg_maddr = pte->val & PAGE_MASK_4K;
        unmap_vtd_domain_page(parent);

        if ( level == total )
            return pg_maddr;

        parent = map_vtd_domain_page(pte->val);
        total--;
    }

    unmap_vtd_domain_page(parent);
    return 0;
}

static void iommu_flush_write_buffer(struct iommu *iommu)
{
    u32 val;
    unsigned long flag;
    s_time_t start_time;

    if ( !cap_rwbf(iommu->cap) )
        return;
    val = iommu->gcmd | DMA_GCMD_WBF;

    spin_lock_irqsave(&iommu->register_lock, flag);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, val);

    /* Make sure hardware complete it */
    start_time = NOW();
    for ( ; ; )
    {
        val = dmar_readl(iommu->reg, DMAR_GSTS_REG);
        if ( !(val & DMA_GSTS_WBFS) )
            break;
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("DMAR hardware is malfunctional,"
                  " please disable IOMMU\n");
        cpu_relax();
    }
    spin_unlock_irqrestore(&iommu->register_lock, flag);
}

/* return value determine if we need a write buffer flush */
static int flush_context_reg(
    void *_iommu,
    u16 did, u16 source_id, u8 function_mask, u64 type,
    int non_present_entry_flush)
{
    struct iommu *iommu = (struct iommu *) _iommu;
    u64 val = 0;
    unsigned long flag;
    s_time_t start_time;

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entry we do nothing and if hardware cache non-present
     * entry, we flush entries of domain 0 (the domain id is used to cache
     * any non-present entries)
     */
    if ( non_present_entry_flush )
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

    spin_lock_irqsave(&iommu->register_lock, flag);
    dmar_writeq(iommu->reg, DMAR_CCMD_REG, val);

    /* Make sure hardware complete it */
    start_time = NOW();
    for ( ; ; )
    {
        val = dmar_readq(iommu->reg, DMAR_CCMD_REG);
        if ( !(val & DMA_CCMD_ICC) )
            break;
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("DMAR hardware is malfunctional, please disable IOMMU\n");
        cpu_relax();
    }
    spin_unlock_irqrestore(&iommu->register_lock, flag);
    /* flush context entry will implictly flush write buffer */
    return 0;
}

static int inline iommu_flush_context_global(
    struct iommu *iommu, int non_present_entry_flush)
{
    struct iommu_flush *flush = iommu_get_flush(iommu);
    return flush->context(iommu, 0, 0, 0, DMA_CCMD_GLOBAL_INVL,
                                 non_present_entry_flush);
}

static int inline iommu_flush_context_domain(
    struct iommu *iommu, u16 did, int non_present_entry_flush)
{
    struct iommu_flush *flush = iommu_get_flush(iommu);
    return flush->context(iommu, did, 0, 0, DMA_CCMD_DOMAIN_INVL,
                                 non_present_entry_flush);
}

static int inline iommu_flush_context_device(
    struct iommu *iommu, u16 did, u16 source_id,
    u8 function_mask, int non_present_entry_flush)
{
    struct iommu_flush *flush = iommu_get_flush(iommu);
    return flush->context(iommu, did, source_id, function_mask,
                                 DMA_CCMD_DEVICE_INVL,
                                 non_present_entry_flush);
}

/* return value determine if we need a write buffer flush */
static int flush_iotlb_reg(void *_iommu, u16 did,
                               u64 addr, unsigned int size_order, u64 type,
                               int non_present_entry_flush)
{
    struct iommu *iommu = (struct iommu *) _iommu;
    int tlb_offset = ecap_iotlb_offset(iommu->ecap);
    u64 val = 0, val_iva = 0;
    unsigned long flag;
    s_time_t start_time;

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entry we do nothing and if hardware cache non-present
     * entry, we flush entries of domain 0 (the domain id is used to cache
     * any non-present entries)
     */
    if ( non_present_entry_flush )
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
        /* global flush doesn't need set IVA_REG */
        val = DMA_TLB_GLOBAL_FLUSH|DMA_TLB_IVT;
        break;
    case DMA_TLB_DSI_FLUSH:
        val = DMA_TLB_DSI_FLUSH|DMA_TLB_IVT|DMA_TLB_DID(did);
        break;
    case DMA_TLB_PSI_FLUSH:
        val = DMA_TLB_PSI_FLUSH|DMA_TLB_IVT|DMA_TLB_DID(did);
        /* Note: always flush non-leaf currently */
        val_iva = size_order | addr;
        break;
    default:
        BUG();
    }
    /* Note: set drain read/write */
    if ( cap_read_drain(iommu->cap) )
        val |= DMA_TLB_READ_DRAIN;
    if ( cap_write_drain(iommu->cap) )
        val |= DMA_TLB_WRITE_DRAIN;

    spin_lock_irqsave(&iommu->register_lock, flag);
    /* Note: Only uses first TLB reg currently */
    if ( val_iva )
        dmar_writeq(iommu->reg, tlb_offset, val_iva);
    dmar_writeq(iommu->reg, tlb_offset + 8, val);

    /* Make sure hardware complete it */
    start_time = NOW();
    for ( ; ; )
    {
        val = dmar_readq(iommu->reg, tlb_offset + 8);
        if ( !(val & DMA_TLB_IVT) )
            break;
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("DMAR hardware is malfunctional, please disable IOMMU\n");
        cpu_relax();
    }
    spin_unlock_irqrestore(&iommu->register_lock, flag);

    /* check IOTLB invalidation granularity */
    if ( DMA_TLB_IAIG(val) == 0 )
        printk(KERN_ERR VTDPREFIX "IOMMU: flush IOTLB failed\n");
    if ( DMA_TLB_IAIG(val) != DMA_TLB_IIRG(type) )
        printk(KERN_ERR VTDPREFIX "IOMMU: tlb flush request %x, actual %x\n",
               (u32)DMA_TLB_IIRG(type), (u32)DMA_TLB_IAIG(val));
    /* flush context entry will implictly flush write buffer */
    return 0;
}

static int inline iommu_flush_iotlb_global(struct iommu *iommu,
                                           int non_present_entry_flush)
{
    struct iommu_flush *flush = iommu_get_flush(iommu);
    return flush->iotlb(iommu, 0, 0, 0, DMA_TLB_GLOBAL_FLUSH,
                               non_present_entry_flush);
}

static int inline iommu_flush_iotlb_dsi(struct iommu *iommu, u16 did,
                                        int non_present_entry_flush)
{
    struct iommu_flush *flush = iommu_get_flush(iommu);
    return flush->iotlb(iommu, did, 0, 0, DMA_TLB_DSI_FLUSH,
                               non_present_entry_flush);
}

static int inline get_alignment(u64 base, unsigned int size)
{
    int t = 0;
    u64 end;

    end = base + size - 1;
    while ( base != end )
    {
        t++;
        base >>= 1;
        end >>= 1;
    }
    return t;
}

static int inline iommu_flush_iotlb_psi(
    struct iommu *iommu, u16 did,
    u64 addr, unsigned int pages, int non_present_entry_flush)
{
    unsigned int align;
    struct iommu_flush *flush = iommu_get_flush(iommu);

    BUG_ON(addr & (~PAGE_MASK_4K));
    BUG_ON(pages == 0);

    /* Fallback to domain selective flush if no PSI support */
    if ( !cap_pgsel_inv(iommu->cap) )
        return iommu_flush_iotlb_dsi(iommu, did,
                                     non_present_entry_flush);

    /*
     * PSI requires page size is 2 ^ x, and the base address is naturally
     * aligned to the size
     */
    align = get_alignment(addr >> PAGE_SHIFT_4K, pages);
    /* Fallback to domain selective flush if size is too big */
    if ( align > cap_max_amask_val(iommu->cap) )
        return iommu_flush_iotlb_dsi(iommu, did,
                                     non_present_entry_flush);

    addr >>= PAGE_SHIFT_4K + align;
    addr <<= PAGE_SHIFT_4K + align;

    return flush->iotlb(iommu, did, addr, align,
                               DMA_TLB_PSI_FLUSH, non_present_entry_flush);
}

void iommu_flush_all(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;

    wbinvd();
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        iommu_flush_context_global(iommu, 0);
        iommu_flush_iotlb_global(iommu, 0);
    }
}

/* clear one page's page table */
static void dma_pte_clear_one(struct domain *domain, u64 addr)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    struct dma_pte *page = NULL, *pte = NULL;
    u64 pg_maddr;

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);

    /* get last level pte */
    pg_maddr = dma_addr_level_page_maddr(domain, addr, 1);
    if ( pg_maddr == 0 )
        return;
    page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
    pte = page + address_level_offset(addr, 1);
    if ( pte )
    {
        dma_clear_pte(*pte);
        iommu_flush_cache_entry(drhd->iommu, pte);

        for_each_drhd_unit ( drhd )
        {
            iommu = drhd->iommu;
            if ( cap_caching_mode(iommu->cap) )
                iommu_flush_iotlb_psi(iommu, domain_iommu_domid(domain),
                                      addr, 1, 0);
            else if (cap_rwbf(iommu->cap))
                iommu_flush_write_buffer(iommu);
        }
    }
    unmap_vtd_domain_page(page);
}

/* clear last level pte, a tlb flush should be followed */
static void dma_pte_clear_range(struct domain *domain, u64 start, u64 end)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);
    int addr_width = agaw_to_width(hd->agaw);

    start &= (((u64)1) << addr_width) - 1;
    end &= (((u64)1) << addr_width) - 1;
    /* in case it's partial page */
    start = PAGE_ALIGN_4K(start);
    end &= PAGE_MASK_4K;

    /* we don't need lock here, nobody else touches the iova range */
    while ( start < end )
    {
        dma_pte_clear_one(domain, start);
        start += PAGE_SIZE_4K;
    }
}

/* free page table pages. last level pte should already be cleared */
void dma_pte_free_pagetable(struct domain *domain, u64 start, u64 end)
{
    struct acpi_drhd_unit *drhd;
    struct hvm_iommu *hd = domain_hvm_iommu(domain);
    struct iommu *iommu;
    int addr_width = agaw_to_width(hd->agaw);
    struct dma_pte *page, *pte;
    int total = agaw_to_level(hd->agaw);
    int level;
    u64 tmp;
    u64 pg_maddr;

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;

    start &= (((u64)1) << addr_width) - 1;
    end &= (((u64)1) << addr_width) - 1;

    /* we don't need lock here, nobody else touches the iova range */
    level = 2;
    while ( level <= total )
    {
        tmp = align_to_level(start, level);
        if ( (tmp >= end) || ((tmp + level_size(level)) > end) )
            return;

        while ( tmp < end )
        {
            pg_maddr = dma_addr_level_page_maddr(domain, tmp, level);
            if ( pg_maddr == 0 )
            {
                tmp += level_size(level);
                continue;
            }
            page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
            pte = page + address_level_offset(tmp, level);
            dma_clear_pte(*pte);
            iommu_flush_cache_entry(iommu, pte);
            unmap_vtd_domain_page(page);
            free_pgtable_maddr(pg_maddr);

            tmp += level_size(level);
        }
        level++;
    }

    /* free pgd */
    if ( start == 0 && end >= ((((u64)1) << addr_width) - 1) )
    {
        free_pgtable_maddr(hd->pgd_maddr);
        hd->pgd_maddr = 0;
    }
}

 /* free all VT-d page tables when shut down or destroy domain. */
static void iommu_free_pagetable(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);
    int addr_width = agaw_to_width(hd->agaw);
    u64 start, end;

    start = 0;
    end = (((u64)1) << addr_width) - 1;

    dma_pte_free_pagetable(domain, start, end);
}

static int iommu_set_root_entry(struct iommu *iommu)
{
    u32 cmd, sts;
    unsigned long flags;
    s_time_t start_time;

    if ( iommu->root_maddr != 0 )
    {
        free_pgtable_maddr(iommu->root_maddr);
        iommu->root_maddr = 0;
    }

    spin_lock_irqsave(&iommu->register_lock, flags);

    iommu->root_maddr = alloc_pgtable_maddr();
    if ( iommu->root_maddr == 0 )
        return -ENOMEM;

    dmar_writeq(iommu->reg, DMAR_RTADDR_REG, iommu->root_maddr);
    cmd = iommu->gcmd | DMA_GCMD_SRTP;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, cmd);

    /* Make sure hardware complete it */
    start_time = NOW();
    for ( ; ; )
    {
        sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
        if ( sts & DMA_GSTS_RTPS )
            break;
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("DMAR hardware is malfunctional, please disable IOMMU\n");
        cpu_relax();
    }

    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return 0;
}

static int iommu_enable_translation(struct iommu *iommu)
{
    u32 sts;
    unsigned long flags;
    s_time_t start_time;

    dprintk(XENLOG_INFO VTDPREFIX,
            "iommu_enable_translation: iommu->reg = %p\n", iommu->reg);
    spin_lock_irqsave(&iommu->register_lock, flags);
    iommu->gcmd |= DMA_GCMD_TE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);
    /* Make sure hardware complete it */
    start_time = NOW();
    for ( ; ; )
    {
        sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
        if ( sts & DMA_GSTS_TES )
            break;
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("DMAR hardware is malfunctional, please disable IOMMU\n");
        cpu_relax();
    }

    /* Disable PMRs when VT-d engine takes effect per spec definition */
    disable_pmr(iommu);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
    return 0;
}

int iommu_disable_translation(struct iommu *iommu)
{
    u32 sts;
    unsigned long flags;
    s_time_t start_time;

    spin_lock_irqsave(&iommu->register_lock, flags);
    iommu->gcmd &= ~ DMA_GCMD_TE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, iommu->gcmd);

    /* Make sure hardware complete it */
    start_time = NOW();
    for ( ; ; )
    {
        sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
        if ( !(sts & DMA_GSTS_TES) )
            break;
        if ( NOW() > start_time + DMAR_OPERATION_TIMEOUT )
            panic("DMAR hardware is malfunctional, please disable IOMMU\n");
        cpu_relax();
    }
    spin_unlock_irqrestore(&iommu->register_lock, flags);
    return 0;
}

static struct iommu *vector_to_iommu[NR_VECTORS];
static int iommu_page_fault_do_one(struct iommu *iommu, int type,
                                   u8 fault_reason, u16 source_id, u32 addr)
{
    dprintk(XENLOG_WARNING VTDPREFIX,
            "iommu_fault:%s: %x:%x.%x addr %x REASON %x iommu->reg = %p\n",
            (type ? "DMA Read" : "DMA Write"), (source_id >> 8),
            PCI_SLOT(source_id & 0xFF), PCI_FUNC(source_id & 0xFF), addr,
            fault_reason, iommu->reg);

    if ( fault_reason < 0x20 )
        print_vtd_entries(current->domain, iommu, (source_id >> 8),
                          (source_id & 0xff), (addr >> PAGE_SHIFT));

    return 0;
}

static void iommu_fault_status(u32 fault_status)
{
    if ( fault_status & DMA_FSTS_PFO )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Fault Overflow\n");
    else if ( fault_status & DMA_FSTS_PPF )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Primary Pending Fault\n");
    else if ( fault_status & DMA_FSTS_AFO )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Advanced Fault Overflow\n");
    else if ( fault_status & DMA_FSTS_APF )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Advanced Pending Fault\n");
    else if ( fault_status & DMA_FSTS_IQE )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Invalidation Queue Error\n");
    else if ( fault_status & DMA_FSTS_ICE )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Invalidation Completion Error\n");
    else if ( fault_status & DMA_FSTS_ITE )
        dprintk(XENLOG_ERR VTDPREFIX,
            "iommu_fault_status: Invalidation Time-out Error\n");
}

#define PRIMARY_FAULT_REG_LEN (16)
static void iommu_page_fault(int vector, void *dev_id,
                             struct cpu_user_regs *regs)
{
    struct iommu *iommu = dev_id;
    int reg, fault_index;
    u32 fault_status;
    unsigned long flags;

    dprintk(XENLOG_WARNING VTDPREFIX,
            "iommu_page_fault: iommu->reg = %p\n", iommu->reg);

    spin_lock_irqsave(&iommu->register_lock, flags);
    fault_status = dmar_readl(iommu->reg, DMAR_FSTS_REG);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    iommu_fault_status(fault_status);

    /* FIXME: ignore advanced fault log */
    if ( !(fault_status & DMA_FSTS_PPF) )
        return;
    fault_index = dma_fsts_fault_record_index(fault_status);
    reg = cap_fault_reg_offset(iommu->cap);
    for ( ; ; )
    {
        u8 fault_reason;
        u16 source_id;
        u32 guest_addr, data;
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

        fault_index++;
        if ( fault_index > cap_num_fault_regs(iommu->cap) )
            fault_index = 0;
    }

    /* clear primary fault overflow */
    if ( fault_status & DMA_FSTS_PFO )
    {
        spin_lock_irqsave(&iommu->register_lock, flags);
        dmar_writel(iommu->reg, DMAR_FSTS_REG, DMA_FSTS_PFO);
        spin_unlock_irqrestore(&iommu->register_lock, flags);
    }
}

static void dma_msi_unmask(unsigned int vector)
{
    struct iommu *iommu = vector_to_iommu[vector];
    unsigned long flags;

    /* unmask it */
    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_FECTL_REG, 0);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void dma_msi_mask(unsigned int vector)
{
    unsigned long flags;
    struct iommu *iommu = vector_to_iommu[vector];

    /* mask it */
    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_FECTL_REG, DMA_FECTL_IM);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static unsigned int dma_msi_startup(unsigned int vector)
{
    dma_msi_unmask(vector);
    return 0;
}

static void dma_msi_end(unsigned int vector)
{
    dma_msi_unmask(vector);
    ack_APIC_irq();
}

static void dma_msi_data_init(struct iommu *iommu, int vector)
{
    u32 msi_data = 0;
    unsigned long flags;

    /* Fixed, edge, assert mode. Follow MSI setting */
    msi_data |= vector & 0xff;
    msi_data |= 1 << 14;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_FEDATA_REG, msi_data);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void dma_msi_addr_init(struct iommu *iommu, int phy_cpu)
{
    u64 msi_address;
    unsigned long flags;

    /* Physical, dedicated cpu. Follow MSI setting */
    msi_address = (MSI_ADDRESS_HEADER << (MSI_ADDRESS_HEADER_SHIFT + 8));
    msi_address |= MSI_PHYSICAL_MODE << 2;
    msi_address |= MSI_REDIRECTION_HINT_MODE << 3;
    msi_address |= phy_cpu << MSI_TARGET_CPU_SHIFT;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_FEADDR_REG, (u32)msi_address);
    dmar_writel(iommu->reg, DMAR_FEUADDR_REG, (u32)(msi_address >> 32));
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void dma_msi_set_affinity(unsigned int vector, cpumask_t dest)
{
    struct iommu *iommu = vector_to_iommu[vector];
    dma_msi_addr_init(iommu, cpu_physical_id(first_cpu(dest)));
}

static struct hw_interrupt_type dma_msi_type = {
    .typename = "DMA_MSI",
    .startup = dma_msi_startup,
    .shutdown = dma_msi_mask,
    .enable = dma_msi_unmask,
    .disable = dma_msi_mask,
    .ack = dma_msi_mask,
    .end = dma_msi_end,
    .set_affinity = dma_msi_set_affinity,
};

int iommu_set_interrupt(struct iommu *iommu)
{
    int vector, ret;

    vector = assign_irq_vector(AUTO_ASSIGN);
    vector_to_iommu[vector] = iommu;

    /* VT-d fault is a MSI, make irq == vector */
    irq_vector[vector] = vector;
    vector_irq[vector] = vector;

    if ( !vector )
    {
        gdprintk(XENLOG_ERR VTDPREFIX, "IOMMU: no vectors\n");
        return -EINVAL;
    }

    irq_desc[vector].handler = &dma_msi_type;
    ret = request_irq(vector, iommu_page_fault, 0, "dmar", iommu);
    if ( ret )
        gdprintk(XENLOG_ERR VTDPREFIX, "IOMMU: can't request irq\n");
    return vector;
}

static int iommu_alloc(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu;

    if ( nr_iommus > MAX_IOMMUS )
    {
        gdprintk(XENLOG_ERR VTDPREFIX,
                 "IOMMU: nr_iommus %d > MAX_IOMMUS\n", nr_iommus);
        return -ENOMEM;
    }

    iommu = xmalloc(struct iommu);
    if ( iommu == NULL )
        return -ENOMEM;
    memset(iommu, 0, sizeof(struct iommu));

    iommu->intel = alloc_intel_iommu();
    if ( iommu->intel == NULL )
    {
        xfree(iommu);
        return -ENOMEM;
    }

    set_fixmap_nocache(FIX_IOMMU_REGS_BASE_0 + nr_iommus, drhd->address);
    iommu->reg = (void *)fix_to_virt(FIX_IOMMU_REGS_BASE_0 + nr_iommus);
    nr_iommus++;

    iommu->cap = dmar_readq(iommu->reg, DMAR_CAP_REG);
    iommu->ecap = dmar_readq(iommu->reg, DMAR_ECAP_REG);

    spin_lock_init(&iommu->lock);
    spin_lock_init(&iommu->register_lock);

    drhd->iommu = iommu;
    return 0;
}

static void iommu_free(struct acpi_drhd_unit *drhd)
{
    struct iommu *iommu = drhd->iommu;

    if ( iommu == NULL )
        return;

    if ( iommu->root_maddr != 0 )
    {
        free_pgtable_maddr(iommu->root_maddr);
        iommu->root_maddr = 0;
    }

    if ( iommu->reg )
        iounmap(iommu->reg);

    free_intel_iommu(iommu->intel);
    free_irq(iommu->vector);
    xfree(iommu);

    drhd->iommu = NULL;
}

#define guestwidth_to_adjustwidth(gaw) ({       \
    int agaw, r = (gaw - 12) % 9;               \
    agaw = (r == 0) ? gaw : (gaw + 9 - r);      \
    if ( agaw > 64 )                            \
        agaw = 64;                              \
    agaw; })

static int intel_iommu_domain_init(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct iommu *iommu = NULL;
    int guest_width = DEFAULT_DOMAIN_ADDRESS_WIDTH;
    int i, adjust_width, agaw;
    unsigned long sagaw;
    struct acpi_drhd_unit *drhd;

    INIT_LIST_HEAD(&hd->pdev_list);

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;

    /* Calculate AGAW. */
    if ( guest_width > cap_mgaw(iommu->cap) )
        guest_width = cap_mgaw(iommu->cap);
    adjust_width = guestwidth_to_adjustwidth(guest_width);
    agaw = width_to_agaw(adjust_width);
    /* FIXME: hardware doesn't support it, choose a bigger one? */
    sagaw = cap_sagaw(iommu->cap);
    if ( !test_bit(agaw, &sagaw) )
    {
        gdprintk(XENLOG_ERR VTDPREFIX,
                 "IOMMU: hardware doesn't support the agaw\n");
        agaw = find_next_bit(&sagaw, 5, agaw);
        if ( agaw >= 5 )
            return -ENODEV;
    }
    hd->agaw = agaw;

    if ( d->domain_id == 0 )
    {
        /* Set up 1:1 page table for dom0. */
        for ( i = 0; i < max_page; i++ )
            iommu_map_page(d, i, i);

        setup_dom0_devices(d);
        setup_dom0_rmrr(d);

        iommu_flush_all();

        for_each_drhd_unit ( drhd )
        {
            iommu = drhd->iommu;
            if ( iommu_enable_translation(iommu) )
                return -EIO;
        }
    }

    return 0;
}

static int domain_context_mapping_one(
    struct domain *domain,
    struct iommu *iommu,
    u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);
    struct context_entry *context, *context_entries;
    unsigned long flags;
    u64 maddr;

    maddr = bus_to_context_maddr(iommu, bus);
    context_entries = (struct context_entry *)map_vtd_domain_page(maddr);
    context = &context_entries[devfn];

    if ( context_present(*context) )
    {
        unmap_vtd_domain_page(context_entries);
        return 0;
    }

    spin_lock_irqsave(&iommu->lock, flags);
    /*
     * domain_id 0 is not valid on Intel's IOMMU, force domain_id to
     * be 1 based as required by intel's iommu hw.
     */
    context_set_domain_id(context, domain);
    context_set_address_width(*context, hd->agaw);

    if ( ecap_pass_thru(iommu->ecap) )
        context_set_translation_type(*context, CONTEXT_TT_PASS_THRU);
#ifdef CONTEXT_PASSTHRU
    else
    {
#endif
        ASSERT(hd->pgd_maddr != 0);
        context_set_address_root(*context, hd->pgd_maddr);
        context_set_translation_type(*context, CONTEXT_TT_MULTI_LEVEL);
#ifdef CONTEXT_PASSTHRU
    }
#endif

    context_set_fault_enable(*context);
    context_set_present(*context);
    iommu_flush_cache_entry(iommu, context);

    unmap_vtd_domain_page(context_entries);

    if ( iommu_flush_context_device(iommu, domain_iommu_domid(domain),
                                    (((u16)bus) << 8) | devfn,
                                    DMA_CCMD_MASK_NOBIT, 1) )
        iommu_flush_write_buffer(iommu);
    else
        iommu_flush_iotlb_dsi(iommu, domain_iommu_domid(domain), 0);
    spin_unlock_irqrestore(&iommu->lock, flags);

    return 0;
}

#define PCI_BASE_CLASS_BRIDGE    0x06
#define PCI_CLASS_BRIDGE_PCI     0x0604

#define DEV_TYPE_PCIe_ENDPOINT   1
#define DEV_TYPE_PCI_BRIDGE      2
#define DEV_TYPE_PCI             3

int pdev_type(struct pci_dev *dev)
{
    u16 class_device;
    u16 status;

    class_device = pci_conf_read16(dev->bus, PCI_SLOT(dev->devfn),
                                   PCI_FUNC(dev->devfn), PCI_CLASS_DEVICE);
    if ( class_device == PCI_CLASS_BRIDGE_PCI )
        return DEV_TYPE_PCI_BRIDGE;

    status = pci_conf_read16(dev->bus, PCI_SLOT(dev->devfn),
                             PCI_FUNC(dev->devfn), PCI_STATUS);

    if ( !(status & PCI_STATUS_CAP_LIST) )
        return DEV_TYPE_PCI;

    if ( pci_find_next_cap(dev->bus, dev->devfn,
                            PCI_CAPABILITY_LIST, PCI_CAP_ID_EXP) )
        return DEV_TYPE_PCIe_ENDPOINT;

    return DEV_TYPE_PCI;
}

#define MAX_BUSES 256
struct pci_dev bus2bridge[MAX_BUSES];

static int domain_context_mapping(
    struct domain *domain,
    struct iommu *iommu,
    struct pci_dev *pdev)
{
    int ret = 0;
    int dev, func, sec_bus, sub_bus;
    u32 type;

    type = pdev_type(pdev);
    switch ( type )
    {
    case DEV_TYPE_PCI_BRIDGE:
        sec_bus = pci_conf_read8(
            pdev->bus, PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn), PCI_SECONDARY_BUS);

        if ( bus2bridge[sec_bus].bus == 0 )
        {
            bus2bridge[sec_bus].bus   =  pdev->bus;
            bus2bridge[sec_bus].devfn =  pdev->devfn;
        }

        sub_bus = pci_conf_read8(
            pdev->bus, PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn), PCI_SUBORDINATE_BUS);

        if ( sec_bus != sub_bus )
            gdprintk(XENLOG_WARNING VTDPREFIX,
                     "context_context_mapping: nested PCI bridge not "
                     "supported: bdf = %x:%x:%x sec_bus = %x sub_bus = %x\n",
                     pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
                     sec_bus, sub_bus);
        break;
    case DEV_TYPE_PCIe_ENDPOINT:
        gdprintk(XENLOG_INFO VTDPREFIX,
                 "domain_context_mapping:PCIe : bdf = %x:%x:%x\n",
                 pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
        ret = domain_context_mapping_one(domain, iommu,
                                         (u8)(pdev->bus), (u8)(pdev->devfn));
        break;
    case DEV_TYPE_PCI:
        gdprintk(XENLOG_INFO VTDPREFIX,
                 "domain_context_mapping:PCI: bdf = %x:%x:%x\n",
                 pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

        if ( pdev->bus == 0 )
            ret = domain_context_mapping_one(
                domain, iommu, (u8)(pdev->bus), (u8)(pdev->devfn));
        else
        {
            if ( bus2bridge[pdev->bus].bus != 0 )
                gdprintk(XENLOG_WARNING VTDPREFIX,
                         "domain_context_mapping:bus2bridge"
                         "[%d].bus != 0\n", pdev->bus);

            ret = domain_context_mapping_one(
                domain, iommu,
                (u8)(bus2bridge[pdev->bus].bus),
                (u8)(bus2bridge[pdev->bus].devfn));

            /* now map everything behind the PCI bridge */
            for ( dev = 0; dev < 32; dev++ )
            {
                for ( func = 0; func < 8; func++ )
                {
                    ret = domain_context_mapping_one(
                        domain, iommu,
                        pdev->bus, (u8)PCI_DEVFN(dev, func));
                    if ( ret )
                        return ret;
                }
            }
        }
        break;
    default:
        gdprintk(XENLOG_ERR VTDPREFIX,
                 "domain_context_mapping:unknown type : bdf = %x:%x:%x\n",
                 pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
        ret = -EINVAL;
        break;
    }

    return ret;
}

static int domain_context_unmap_one(
    struct domain *domain,
    struct iommu *iommu,
    u8 bus, u8 devfn)
{
    struct context_entry *context, *context_entries;
    unsigned long flags;
    u64 maddr;

    maddr = bus_to_context_maddr(iommu, bus);
    context_entries = (struct context_entry *)map_vtd_domain_page(maddr);
    context = &context_entries[devfn];

    if ( !context_present(*context) )
    {
        unmap_vtd_domain_page(context_entries);
        return 0;
    }

    spin_lock_irqsave(&iommu->lock, flags);
    context_clear_present(*context);
    context_clear_entry(*context);
    iommu_flush_cache_entry(iommu, context);
    iommu_flush_context_global(iommu, 0);
    iommu_flush_iotlb_global(iommu, 0);
    unmap_vtd_domain_page(context_entries);
    spin_unlock_irqrestore(&iommu->lock, flags);

    return 0;
}

static int domain_context_unmap(
    struct domain *domain,
    struct iommu *iommu,
    struct pci_dev *pdev)
{
    int ret = 0;
    int dev, func, sec_bus, sub_bus;
    u32 type;

    type = pdev_type(pdev);
    switch ( type )
    {
    case DEV_TYPE_PCI_BRIDGE:
        sec_bus = pci_conf_read8(
            pdev->bus, PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn), PCI_SECONDARY_BUS);
        sub_bus = pci_conf_read8(
            pdev->bus, PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn), PCI_SUBORDINATE_BUS);
        break;
    case DEV_TYPE_PCIe_ENDPOINT:
        ret = domain_context_unmap_one(domain, iommu,
                                       (u8)(pdev->bus), (u8)(pdev->devfn));
        break;
    case DEV_TYPE_PCI:
        if ( pdev->bus == 0 )
            ret = domain_context_unmap_one(
                domain, iommu,
                (u8)(pdev->bus), (u8)(pdev->devfn));
        else
        {
            if ( bus2bridge[pdev->bus].bus != 0 )
                gdprintk(XENLOG_WARNING VTDPREFIX,
                         "domain_context_unmap:"
                         "bus2bridge[%d].bus != 0\n", pdev->bus);

            ret = domain_context_unmap_one(domain, iommu,
                                           (u8)(bus2bridge[pdev->bus].bus),
                                           (u8)(bus2bridge[pdev->bus].devfn));

            /* Unmap everything behind the PCI bridge */
            for ( dev = 0; dev < 32; dev++ )
            {
                for ( func = 0; func < 8; func++ )
                {
                    ret = domain_context_unmap_one(
                        domain, iommu,
                        pdev->bus, (u8)PCI_DEVFN(dev, func));
                    if ( ret )
                        return ret;
                }
            }
        }
        break;
    default:
        gdprintk(XENLOG_ERR VTDPREFIX,
                 "domain_context_unmap:unknown type: bdf = %x:%x:%x\n",
                 pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
        ret = -EINVAL;
        break;
    }

    return ret;
}

void reassign_device_ownership(
    struct domain *source,
    struct domain *target,
    u8 bus, u8 devfn)
{
    struct hvm_iommu *source_hd = domain_hvm_iommu(source);
    struct hvm_iommu *target_hd = domain_hvm_iommu(target);
    struct pci_dev *pdev;
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    int status;
    unsigned long flags;

    pdev_flr(bus, devfn);

    for_each_pdev( source, pdev )
        if ( (pdev->bus == bus) && (pdev->devfn == devfn) )
            goto found;

    return;

 found:
    drhd = acpi_find_matched_drhd_unit(pdev);
    iommu = drhd->iommu;
    domain_context_unmap(source, iommu, pdev);

    /* Move pci device from the source domain to target domain. */
    spin_lock_irqsave(&source_hd->iommu_list_lock, flags);
    spin_lock_irqsave(&target_hd->iommu_list_lock, flags);
    list_move(&pdev->list, &target_hd->pdev_list);
    spin_unlock_irqrestore(&target_hd->iommu_list_lock, flags);
    spin_unlock_irqrestore(&source_hd->iommu_list_lock, flags);

    status = domain_context_mapping(target, iommu, pdev);
    if ( status != 0 )
        gdprintk(XENLOG_ERR VTDPREFIX, "domain_context_mapping failed\n");
}

void return_devices_to_dom0(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct pci_dev *pdev;

    while ( !list_empty(&hd->pdev_list) )
    {
        pdev = list_entry(hd->pdev_list.next, typeof(*pdev), list);
        reassign_device_ownership(d, dom0, pdev->bus, pdev->devfn);
    }

#ifdef VTD_DEBUG
    for_each_pdev ( dom0, pdev )
        dprintk(XENLOG_INFO VTDPREFIX,
                "return_devices_to_dom0:%x: bdf = %x:%x:%x\n",
                dom0->domain_id, pdev->bus,
                PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
#endif
}

void iommu_domain_teardown(struct domain *d)
{
    if ( list_empty(&acpi_drhd_units) )
        return;

    iommu_free_pagetable(d);
    return_devices_to_dom0(d);
    iommu_domid_release(d);
}

static int domain_context_mapped(struct pci_dev *pdev)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    int ret;

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        ret = device_context_mapped(iommu, pdev->bus, pdev->devfn);
        if ( ret )
            return ret;
    }

    return 0;
}

int intel_iommu_map_page(
    struct domain *d, unsigned long gfn, unsigned long mfn)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    struct dma_pte *page = NULL, *pte = NULL;
    u64 pg_maddr;

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;

#ifdef CONTEXT_PASSTHRU
    /* do nothing if dom0 and iommu supports pass thru */
    if ( ecap_pass_thru(iommu->ecap) && (d->domain_id == 0) )
        return 0;
#endif

    pg_maddr = addr_to_dma_page_maddr(d, (paddr_t)gfn << PAGE_SHIFT_4K);
    if ( pg_maddr == 0 )
        return -ENOMEM;
    page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
    pte = page + (gfn & LEVEL_MASK);
    dma_set_pte_addr(*pte, (paddr_t)mfn << PAGE_SHIFT_4K);
    dma_set_pte_prot(*pte, DMA_PTE_READ | DMA_PTE_WRITE);
    iommu_flush_cache_entry(iommu, pte);
    unmap_vtd_domain_page(page);

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( cap_caching_mode(iommu->cap) )
            iommu_flush_iotlb_psi(iommu, domain_iommu_domid(d),
                                  (paddr_t)gfn << PAGE_SHIFT_4K, 1, 0);
        else if ( cap_rwbf(iommu->cap) )
            iommu_flush_write_buffer(iommu);
    }

    return 0;
}

int intel_iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;

#ifdef CONTEXT_PASSTHRU
    /* do nothing if dom0 and iommu supports pass thru */
    if ( ecap_pass_thru(iommu->ecap) && (d->domain_id == 0) )
        return 0;
#endif

    dma_pte_clear_one(d, (paddr_t)gfn << PAGE_SHIFT_4K);

    return 0;
}

int iommu_page_mapping(struct domain *domain, paddr_t iova,
                       paddr_t hpa, size_t size, int prot)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    u64 start_pfn, end_pfn;
    struct dma_pte *page = NULL, *pte = NULL;
    int index;
    u64 pg_maddr;

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;
    if ( (prot & (DMA_PTE_READ|DMA_PTE_WRITE)) == 0 )
        return -EINVAL;
    iova = (iova >> PAGE_SHIFT_4K) << PAGE_SHIFT_4K;
    start_pfn = hpa >> PAGE_SHIFT_4K;
    end_pfn = (PAGE_ALIGN_4K(hpa + size)) >> PAGE_SHIFT_4K;
    index = 0;
    while ( start_pfn < end_pfn )
    {
        pg_maddr = addr_to_dma_page_maddr(domain, iova + PAGE_SIZE_4K * index);
        if ( pg_maddr == 0 )
            return -ENOMEM;
        page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
        pte = page + (start_pfn & LEVEL_MASK);
        dma_set_pte_addr(*pte, (paddr_t)start_pfn << PAGE_SHIFT_4K);
        dma_set_pte_prot(*pte, prot);
        iommu_flush_cache_entry(iommu, pte);
        unmap_vtd_domain_page(page);
        start_pfn++;
        index++;
    }

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( cap_caching_mode(iommu->cap) )
            iommu_flush_iotlb_psi(iommu, domain_iommu_domid(domain),
                                  iova, index, 0);
        else if ( cap_rwbf(iommu->cap) )
            iommu_flush_write_buffer(iommu);
    }

    return 0;
}

int iommu_page_unmapping(struct domain *domain, paddr_t addr, size_t size)
{
    dma_pte_clear_range(domain, addr, addr + size);

    return 0;
}

void iommu_flush(struct domain *d, unsigned long gfn, u64 *p2m_entry)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu = NULL;
    struct dma_pte *pte = (struct dma_pte *) p2m_entry;

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( cap_caching_mode(iommu->cap) )
            iommu_flush_iotlb_psi(iommu, domain_iommu_domid(d),
                                  (paddr_t)gfn << PAGE_SHIFT_4K, 1, 0);
        else if ( cap_rwbf(iommu->cap) )
            iommu_flush_write_buffer(iommu);
    }

    iommu_flush_cache_entry(iommu, pte);
}

static int iommu_prepare_rmrr_dev(
    struct domain *d,
    struct acpi_rmrr_unit *rmrr,
    struct pci_dev *pdev)
{
    struct acpi_drhd_unit *drhd;
    unsigned long size;
    int ret;

    /* page table init */
    size = rmrr->end_address - rmrr->base_address + 1;
    ret = iommu_page_mapping(d, rmrr->base_address,
                             rmrr->base_address, size,
                             DMA_PTE_READ|DMA_PTE_WRITE);
    if ( ret )
        return ret;

    if ( domain_context_mapped(pdev) == 0 )
    {
        drhd = acpi_find_matched_drhd_unit(pdev);
        ret = domain_context_mapping(d, drhd->iommu, pdev);
        if ( !ret )
            return 0;
    }

    return ret;
}

static void setup_dom0_devices(struct domain *d)
{
    struct hvm_iommu *hd;
    struct acpi_drhd_unit *drhd;
    struct pci_dev *pdev;
    int bus, dev, func, ret;
    u32 l;

    hd = domain_hvm_iommu(d);

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( dev = 0; dev < 32; dev++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                l = pci_conf_read32(bus, dev, func, PCI_VENDOR_ID);
                /* some broken boards return 0 or ~0 if a slot is empty: */
                if ( (l == 0xffffffff) || (l == 0x00000000) ||
                     (l == 0x0000ffff) || (l == 0xffff0000) )
                    continue;
                pdev = xmalloc(struct pci_dev);
                pdev->bus = bus;
                pdev->devfn = PCI_DEVFN(dev, func);
                list_add_tail(&pdev->list, &hd->pdev_list);

                drhd = acpi_find_matched_drhd_unit(pdev);
                ret = domain_context_mapping(d, drhd->iommu, pdev);
                if ( ret != 0 )
                    gdprintk(XENLOG_ERR VTDPREFIX,
                             "domain_context_mapping failed\n");
            }
        }
    }
}

void clear_fault_bits(struct iommu *iommu)
{
    u64 val;

    val = dmar_readq(
        iommu->reg,
        cap_fault_reg_offset(dmar_readq(iommu->reg,DMAR_CAP_REG))+0x8);
    dmar_writeq(
        iommu->reg,
        cap_fault_reg_offset(dmar_readq(iommu->reg,DMAR_CAP_REG))+8,
        val);
    dmar_writel(iommu->reg, DMAR_FSTS_REG, DMA_FSTS_FAULTS);
}

static int init_vtd_hw(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    struct iommu_flush *flush = NULL;
    int vector;
    int ret;

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        ret = iommu_set_root_entry(iommu);
        if ( ret )
        {
            gdprintk(XENLOG_ERR VTDPREFIX, "IOMMU: set root entry failed\n");
            return -EIO;
        }

        vector = iommu_set_interrupt(iommu);
        dma_msi_data_init(iommu, vector);
        dma_msi_addr_init(iommu, cpu_physical_id(first_cpu(cpu_online_map)));
        iommu->vector = vector;
        clear_fault_bits(iommu);
        dmar_writel(iommu->reg, DMAR_FECTL_REG, 0);

        /* initialize flush functions */
        flush = iommu_get_flush(iommu);
        flush->context = flush_context_reg;
        flush->iotlb = flush_iotlb_reg;
    }

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( qinval_setup(iommu) != 0 )
            dprintk(XENLOG_ERR VTDPREFIX,
                    "Queued Invalidation hardware not found\n");
    }

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( intremap_setup(iommu) != 0 )
            dprintk(XENLOG_ERR VTDPREFIX,
                    "Interrupt Remapping hardware not found\n");
    }

    return 0;
}

static void setup_dom0_rmrr(struct domain *d)
{
    struct acpi_rmrr_unit *rmrr;
    struct pci_dev *pdev;
    int ret;

    for_each_rmrr_device ( rmrr, pdev )
        ret = iommu_prepare_rmrr_dev(d, rmrr, pdev);
        if ( ret )
            gdprintk(XENLOG_ERR VTDPREFIX,
                     "IOMMU: mapping reserved region failed\n");
    end_for_each_rmrr_device ( rmrr, pdev )
}

int intel_vtd_setup(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;

    if ( !vtd_enabled )
        return -ENODEV;

    spin_lock_init(&domid_bitmap_lock);
    clflush_size = get_clflush_size();

    for_each_drhd_unit ( drhd )
        if ( iommu_alloc(drhd) != 0 )
            goto error;

    /* Allocate IO page directory page for the domain. */
    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;

    /* Allocate domain id bitmap, and set bit 0 as reserved */
    domid_bitmap_size = cap_ndoms(iommu->cap);
    domid_bitmap = xmalloc_array(unsigned long,
                                 BITS_TO_LONGS(domid_bitmap_size));
    if ( domid_bitmap == NULL )
        goto error;
    memset(domid_bitmap, 0, domid_bitmap_size / 8);
    set_bit(0, domid_bitmap);

    init_vtd_hw();

    return 0;

 error:
    for_each_drhd_unit ( drhd )
        iommu_free(drhd);
    vtd_enabled = 0;
    return -ENOMEM;
}

/*
 * If the device isn't owned by dom0, it means it already
 * has been assigned to other domain, or it's not exist.
 */
int device_assigned(u8 bus, u8 devfn)
{
    struct pci_dev *pdev;

    for_each_pdev( dom0, pdev )
        if ( (pdev->bus == bus ) && (pdev->devfn == devfn) )
            return 0;

    return 1;
}

int intel_iommu_assign_device(struct domain *d, u8 bus, u8 devfn)
{
    struct acpi_rmrr_unit *rmrr;
    struct pci_dev *pdev;
    int ret = 0;

    if ( list_empty(&acpi_drhd_units) )
        return ret;

    reassign_device_ownership(dom0, d, bus, devfn);

    /* Setup rmrr identify mapping */
    for_each_rmrr_device( rmrr, pdev )
        if ( pdev->bus == bus && pdev->devfn == devfn )
        {
            /* FIXME: Because USB RMRR conflicts with guest bios region,
             * ignore USB RMRR temporarily.
             */
            if ( is_usb_device(pdev) )
                return 0;

            ret = iommu_prepare_rmrr_dev(d, rmrr, pdev);
            if ( ret )
            {
                gdprintk(XENLOG_ERR VTDPREFIX,
                         "IOMMU: mapping reserved region failed\n");
                return ret;
            }
        }
    end_for_each_rmrr_device(rmrr, pdev)

    return ret;
}

u8 iommu_state[MAX_IOMMU_REGS * MAX_IOMMUS];
int iommu_suspend(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    int i = 0;

    iommu_flush_all();

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        iommu_state[DMAR_RTADDR_REG * i] =
            (u64) dmar_readq(iommu->reg, DMAR_RTADDR_REG);
        iommu_state[DMAR_FECTL_REG * i] =
            (u32) dmar_readl(iommu->reg, DMAR_FECTL_REG);
        iommu_state[DMAR_FEDATA_REG * i] =
            (u32) dmar_readl(iommu->reg, DMAR_FEDATA_REG);
        iommu_state[DMAR_FEADDR_REG * i] =
            (u32) dmar_readl(iommu->reg, DMAR_FEADDR_REG);
        iommu_state[DMAR_FEUADDR_REG * i] =
            (u32) dmar_readl(iommu->reg, DMAR_FEUADDR_REG);
        iommu_state[DMAR_PLMBASE_REG * i] =
            (u32) dmar_readl(iommu->reg, DMAR_PLMBASE_REG);
        iommu_state[DMAR_PLMLIMIT_REG * i] =
            (u32) dmar_readl(iommu->reg, DMAR_PLMLIMIT_REG);
        iommu_state[DMAR_PHMBASE_REG * i] =
            (u64) dmar_readq(iommu->reg, DMAR_PHMBASE_REG);
        iommu_state[DMAR_PHMLIMIT_REG * i] =
            (u64) dmar_readq(iommu->reg, DMAR_PHMLIMIT_REG);
        i++;
    }

    return 0;
}

int iommu_resume(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;
    int i = 0;

    iommu_flush_all();

    init_vtd_hw();
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        dmar_writeq( iommu->reg, DMAR_RTADDR_REG,
                     (u64) iommu_state[DMAR_RTADDR_REG * i]);
        dmar_writel(iommu->reg, DMAR_FECTL_REG,
                    (u32) iommu_state[DMAR_FECTL_REG * i]);
        dmar_writel(iommu->reg, DMAR_FEDATA_REG,
                    (u32) iommu_state[DMAR_FEDATA_REG * i]);
        dmar_writel(iommu->reg, DMAR_FEADDR_REG,
                    (u32) iommu_state[DMAR_FEADDR_REG * i]);
        dmar_writel(iommu->reg, DMAR_FEUADDR_REG,
                    (u32) iommu_state[DMAR_FEUADDR_REG * i]);
        dmar_writel(iommu->reg, DMAR_PLMBASE_REG,
                    (u32) iommu_state[DMAR_PLMBASE_REG * i]);
        dmar_writel(iommu->reg, DMAR_PLMLIMIT_REG,
                    (u32) iommu_state[DMAR_PLMLIMIT_REG * i]);
        dmar_writeq(iommu->reg, DMAR_PHMBASE_REG,
                    (u64) iommu_state[DMAR_PHMBASE_REG * i]);
        dmar_writeq(iommu->reg, DMAR_PHMLIMIT_REG,
                    (u64) iommu_state[DMAR_PHMLIMIT_REG * i]);

        if ( iommu_enable_translation(iommu) )
            return -EIO;
        i++;
    }
    return 0;
}

struct iommu_ops intel_iommu_ops = {
    .init = intel_iommu_domain_init,
    .assign_device  = intel_iommu_assign_device,
    .teardown = iommu_domain_teardown,
    .map_page = intel_iommu_map_page,
    .unmap_page = intel_iommu_unmap_page,
    .reassign_device = reassign_device_ownership,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
