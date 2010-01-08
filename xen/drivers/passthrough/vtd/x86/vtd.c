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
#include <xen/numa.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"

/*
 * iommu_inclusive_mapping: when set, all memory below 4GB is included in dom0
 * 1:1 iommu mappings except xen and unusable regions.
 */
static int iommu_inclusive_mapping;
boolean_param("iommu_inclusive_mapping", iommu_inclusive_mapping);

void *map_vtd_domain_page(u64 maddr)
{
    return map_domain_page(maddr >> PAGE_SHIFT_4K);
}

void unmap_vtd_domain_page(void *va)
{
    unmap_domain_page(va);
}

void free_pgtable_maddr(u64 maddr)
{
    if ( maddr != 0 )
        free_domheap_page(maddr_to_page(maddr));
}

unsigned int get_cache_line_size(void)
{
    return ((cpuid_ebx(1) >> 8) & 0xff) * 8;
}

void cacheline_flush(char * addr)
{
    clflush(addr);
}

void flush_all_cache()
{
    wbinvd();
}

void *map_to_nocache_virt(int nr_iommus, u64 maddr)
{
    set_fixmap_nocache(FIX_IOMMU_REGS_BASE_0 + nr_iommus, maddr);
    return (void *)fix_to_virt(FIX_IOMMU_REGS_BASE_0 + nr_iommus);
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
    struct hvm_irq_dpci *dpci = NULL;
    struct dev_intx_gsi_link *digl, *tmp;
    int i;

    ASSERT(isairq < NR_ISAIRQS);
    if ( !iommu_enabled)
        return;

    spin_lock(&d->event_lock);

    dpci = domain_get_irq_dpci(d);

    if ( !dpci || !test_bit(isairq, dpci->isairq_map) )
    {
        spin_unlock(&d->event_lock);
        return;
    }
    /* Multiple mirq may be mapped to one isa irq */
    for ( i = find_first_bit(dpci->mapping, d->nr_pirqs);
          i < d->nr_pirqs;
          i = find_next_bit(dpci->mapping, d->nr_pirqs, i + 1) )
    {
        list_for_each_entry_safe ( digl, tmp,
            &dpci->mirq[i].digl_list, list )
        {
            if ( hvm_irq->pci_link.route[digl->link] == isairq )
            {
                hvm_pci_intx_deassert(d, digl->device, digl->intx);
                if ( --dpci->mirq[i].pending == 0 )
                {
                    stop_timer(&dpci->hvm_timer[domain_pirq_to_irq(d, i)]);
                    pirq_guest_eoi(d, i);
                }
            }
        }
    }
    spin_unlock(&d->event_lock);
}

void iommu_set_dom0_mapping(struct domain *d)
{
    u64 i, j, tmp, max_pfn;
    extern int xen_in_range(paddr_t start, paddr_t end);

    BUG_ON(d->domain_id != 0);

    max_pfn = max_t(u64, max_page, 0x100000000ull >> PAGE_SHIFT);

    for ( i = 0; i < max_pfn; i++ )
    {
        /*
         * Set up 1:1 mapping for dom0. Default to use only conventional RAM
         * areas and let RMRRs include needed reserved regions. When set, the
         * inclusive mapping maps in everything below 4GB except unusable
         * ranges.
         */
        if ( !page_is_ram_type(i, RAM_TYPE_CONVENTIONAL) &&
             (!iommu_inclusive_mapping ||
              page_is_ram_type(i, RAM_TYPE_UNUSABLE)) )
            continue;

        /* Exclude Xen bits */
        if ( xen_in_range(i << PAGE_SHIFT, (i + 1) << PAGE_SHIFT) )
            continue;

        tmp = 1 << (PAGE_SHIFT - PAGE_SHIFT_4K);
        for ( j = 0; j < tmp; j++ )
            iommu_map_page(d, (i*tmp+j), (i*tmp+j));
    }
}

