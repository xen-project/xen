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
    unsigned long mfn;

    pg = alloc_domheap_page(NULL, 0);
    if ( !pg )
        return 0;
    mfn = page_to_mfn(pg);
    vaddr = map_domain_page(mfn);
    memset(vaddr, 0, PAGE_SIZE);

    iommu_flush_cache_page(vaddr);
    unmap_domain_page(vaddr);

    return (u64)mfn << PAGE_SHIFT_4K;
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
    if ( !vtd_enabled)
        return;

    spin_lock(&d->event_lock);

    dpci = domain_get_irq_dpci(d);

    if ( !dpci || !test_bit(isairq, dpci->isairq_map) )
    {
        spin_unlock(&d->event_lock);
        return;
    }
    /* Multiple mirq may be mapped to one isa irq */
    for ( i = find_first_bit(dpci->mapping, NR_IRQS);
          i < NR_IRQS;
          i = find_next_bit(dpci->mapping, NR_IRQS, i + 1) )
    {
        list_for_each_entry_safe ( digl, tmp,
            &dpci->mirq[i].digl_list, list )
        {
            if ( hvm_irq->pci_link.route[digl->link] == isairq )
            {
                hvm_pci_intx_deassert(d, digl->device, digl->intx);
                if ( --dpci->mirq[i].pending == 0 )
                {
                    stop_timer(&dpci->hvm_timer[domain_irq_to_vector(d, i)]);
                    pirq_guest_eoi(d, i);
                }
            }
        }
    }
    spin_unlock(&d->event_lock);
}
