/*
 * Copyright (c) 2008, Intel Corporation.
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
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#include <xen/sched.h>
#include <xen/domain_page.h>
#include <asm/paging.h>
#include <xen/iommu.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"

void *map_vtd_domain_page(u64 maddr)
{
    return map_domain_page(maddr >> PAGE_SHIFT_4K);
}

void unmap_vtd_domain_page(void *va)
{
    unmap_domain_page(va);
}

/* Allocate page table, return its machine address */
u64 alloc_pgtable_maddr(void)
{
    struct page_info *pg;
    u64 *vaddr;
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;

    pg = alloc_domheap_page(NULL, 0);
    vaddr = map_domain_page(page_to_mfn(pg));
    if ( !vaddr )
        return 0;
    memset(vaddr, 0, PAGE_SIZE);

    drhd = list_entry(acpi_drhd_units.next, typeof(*drhd), list);
    iommu = drhd->iommu;
    iommu_flush_cache_page(iommu, vaddr);
    unmap_domain_page(vaddr);

    return page_to_maddr(pg);
}

void free_pgtable_maddr(u64 maddr)
{
    if ( maddr != 0 )
        free_domheap_page(maddr_to_page(maddr));
}

unsigned int get_clflush_size(void)
{
    return ((cpuid_ebx(1) >> 8) & 0xff) * 8;
}

struct hvm_irq_dpci *domain_get_irq_dpci(struct domain *domain)
{
    if ( !domain )
        return NULL;

    return domain->arch.hvm_domain.irq.dpci;
}

int domain_set_irq_dpci(struct domain *domain, struct hvm_irq_dpci *dpci)
{
    if ( !domain || !dpci )
        return 0;

    domain->arch.hvm_domain.irq.dpci = dpci;
    return 1;
}

void hvm_dpci_isairq_eoi(struct domain *d, unsigned int isairq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    struct hvm_irq_dpci *dpci = domain_get_irq_dpci(d);
    struct dev_intx_gsi_link *digl, *tmp;
    int i;

    ASSERT(isairq < NR_ISAIRQS);
    if ( !vtd_enabled || !dpci ||
         !test_bit(isairq, dpci->isairq_map) )
        return;

    /* Multiple mirq may be mapped to one isa irq */
    for ( i = 0; i < NR_IRQS; i++ )
    {
        if ( !dpci->mirq[i].valid )
            continue;

        list_for_each_entry_safe ( digl, tmp,
            &dpci->mirq[i].digl_list, list )
        {
            if ( hvm_irq->pci_link.route[digl->link] == isairq )
            {
                hvm_pci_intx_deassert(d, digl->device, digl->intx);
                spin_lock(&dpci->dirq_lock);
                if ( --dpci->mirq[i].pending == 0 )
                {
                    spin_unlock(&dpci->dirq_lock);
                    stop_timer(&dpci->hvm_timer[domain_irq_to_vector(d, i)]);
                    pirq_guest_eoi(d, i);
                }
                else
                    spin_unlock(&dpci->dirq_lock);
            }
        }
    }
}

void iommu_set_pgd(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    unsigned long p2m_table;

    p2m_table = mfn_x(pagetable_get_mfn(d->arch.phys_table));

    if ( paging_mode_hap(d) )
    {
        int level = agaw_to_level(hd->agaw);
        struct dma_pte *dpte = NULL;
        mfn_t pgd_mfn;

        switch ( level )
        {
        case VTD_PAGE_TABLE_LEVEL_3:
            dpte = map_domain_page(p2m_table);
            if ( !dma_pte_present(*dpte) )
            {
                gdprintk(XENLOG_ERR VTDPREFIX,
                         "iommu_set_pgd: second level wasn't there\n");
                unmap_domain_page(dpte);
                return;
            }
            pgd_mfn = _mfn(dma_pte_addr(*dpte) >> PAGE_SHIFT_4K);
            hd->pgd_maddr = (paddr_t)(mfn_x(pgd_mfn)) << PAGE_SHIFT_4K;
            unmap_domain_page(dpte);
            break;
        case VTD_PAGE_TABLE_LEVEL_4:
            pgd_mfn = _mfn(p2m_table);
            hd->pgd_maddr = (paddr_t)(mfn_x(pgd_mfn)) << PAGE_SHIFT_4K;
            break;
        default:
            gdprintk(XENLOG_ERR VTDPREFIX,
                     "iommu_set_pgd:Unsupported p2m table sharing level!\n");
            break;
        }
    }
    else
    {
#if CONFIG_PAGING_LEVELS == 3
        struct dma_pte *pte = NULL, *pgd_vaddr = NULL, *pmd_vaddr = NULL;
        int i;
        u64 pmd_maddr;
        unsigned long flags;
        l3_pgentry_t *l3e;
        int level = agaw_to_level(hd->agaw);

        spin_lock_irqsave(&hd->mapping_lock, flags);
        hd->pgd_maddr = alloc_pgtable_maddr();
        if ( hd->pgd_maddr == 0 )
        {
            spin_unlock_irqrestore(&hd->mapping_lock, flags);
            gdprintk(XENLOG_ERR VTDPREFIX,
                     "Allocate pgd memory failed!\n");
            return;
        }

        pgd_vaddr = map_vtd_domain_page(hd->pgd_maddr);
        l3e = map_domain_page(p2m_table);
        switch ( level )
        {
        case VTD_PAGE_TABLE_LEVEL_3:        /* Weybridge */
            /* We only support 8 entries for the PAE L3 p2m table */
            for ( i = 0; i < 8 ; i++ )
            {
                /* Don't create new L2 entry, use ones from p2m table */
                pgd_vaddr[i].val = l3e[i].l3 | _PAGE_PRESENT | _PAGE_RW;
            }
            break;

        case VTD_PAGE_TABLE_LEVEL_4:        /* Stoakley */
            /* We allocate one more page for the top vtd page table. */
            pmd_maddr = alloc_pgtable_maddr();
            if ( pmd_maddr == 0 )
            {
                unmap_vtd_domain_page(pgd_vaddr);
                unmap_domain_page(l3e);
                spin_unlock_irqrestore(&hd->mapping_lock, flags);
                gdprintk(XENLOG_ERR VTDPREFIX,
                         "Allocate pmd memory failed!\n");
                return;
            }

            pte = &pgd_vaddr[0];
            dma_set_pte_addr(*pte, pmd_maddr);
            dma_set_pte_readable(*pte);
            dma_set_pte_writable(*pte);

            pmd_vaddr = map_vtd_domain_page(pmd_maddr);
            for ( i = 0; i < 8; i++ )
            {
                /* Don't create new L2 entry, use ones from p2m table */
                pmd_vaddr[i].val = l3e[i].l3 | _PAGE_PRESENT | _PAGE_RW;
            }

            unmap_vtd_domain_page(pmd_vaddr);
            break;
        default:
            gdprintk(XENLOG_ERR VTDPREFIX,
                     "iommu_set_pgd:Unsupported p2m table sharing level!\n");
            break;
        }

        unmap_vtd_domain_page(pgd_vaddr);
        unmap_domain_page(l3e);
        spin_unlock_irqrestore(&hd->mapping_lock, flags);

#elif CONFIG_PAGING_LEVELS == 4
        mfn_t pgd_mfn;
        l3_pgentry_t *l3e;
        int level = agaw_to_level(hd->agaw);

        switch ( level )
        {
        case VTD_PAGE_TABLE_LEVEL_3:
            l3e = map_domain_page(p2m_table);
            if ( (l3e_get_flags(*l3e) & _PAGE_PRESENT) == 0 )
            {
                gdprintk(XENLOG_ERR VTDPREFIX,
                         "iommu_set_pgd: second level wasn't there\n");
                unmap_domain_page(l3e);
                return;
            }

            pgd_mfn = _mfn(l3e_get_pfn(*l3e));
            hd->pgd_maddr = (paddr_t)(mfn_x(pgd_mfn)) << PAGE_SHIFT_4K;
            unmap_domain_page(l3e);
            break;
        case VTD_PAGE_TABLE_LEVEL_4:
            pgd_mfn = _mfn(p2m_table);
            hd->pgd_maddr = (paddr_t)(mfn_x(pgd_mfn)) << PAGE_SHIFT_4K;
            break;
        default:
            gdprintk(XENLOG_ERR VTDPREFIX,
                     "iommu_set_pgd:Unsupported p2m table sharing level!\n");
            break;
        }
#endif
    }
}

void iommu_free_pgd(struct domain *d)
{
#if CONFIG_PAGING_LEVELS == 3
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    int level = agaw_to_level(hd->agaw);
    struct dma_pte *pgd_vaddr = NULL;

    switch ( level )
    {
    case VTD_PAGE_TABLE_LEVEL_3:
        if ( hd->pgd_maddr != 0 )
        {
            free_pgtable_maddr(hd->pgd_maddr);
            hd->pgd_maddr = 0;
        }
        break;
    case VTD_PAGE_TABLE_LEVEL_4:
        if ( hd->pgd_maddr != 0 )
        {
            pgd_vaddr = (struct dma_pte*)map_vtd_domain_page(hd->pgd_maddr);
            if ( pgd_vaddr[0].val != 0 )
                free_pgtable_maddr(pgd_vaddr[0].val);
            unmap_vtd_domain_page(pgd_vaddr);
            free_pgtable_maddr(hd->pgd_maddr);
            hd->pgd_maddr = 0;
        }
        break;
    default:
        gdprintk(XENLOG_ERR VTDPREFIX,
                 "Unsupported p2m table sharing level!\n");
        break;
    }
#endif
}

