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
#include <xen/iommu.h>
#include <xen/numa.h>
#include <asm/xensystem.h>
#include <asm/sal.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"


int vector_irq[NR_VECTORS] __read_mostly = {
    [0 ... NR_VECTORS - 1] = FREE_TO_ASSIGN_IRQ
};
/* irq_vectors is indexed by the sum of all RTEs in all I/O APICs. */
u8 irq_vector[NR_IRQS] __read_mostly;

void *map_vtd_domain_page(u64 maddr)
{
    return (void *)((u64)map_domain_page(maddr >> PAGE_SHIFT) |
            (maddr & (PAGE_SIZE - PAGE_SIZE_4K)));
}

void unmap_vtd_domain_page(void *va)
{
    unmap_domain_page(va);
}

/* Allocate page table, return its machine address */
u64 alloc_pgtable_maddr(struct domain *d, unsigned long npages)
{
    struct page_info *pg;
    u64 *vaddr;

    pg = alloc_domheap_pages(NULL, get_order_from_pages(npages),
                             d ? MEMF_node(domain_to_node(d)) : 0);
    vaddr = map_domain_page(page_to_mfn(pg));
    if ( !vaddr )
        return 0;
    memset(vaddr, 0, PAGE_SIZE * npages);

    iommu_flush_cache_page(vaddr, npages);
    unmap_domain_page(vaddr);

    return page_to_maddr(pg);
}

void free_pgtable_maddr(u64 maddr)
{
    if ( maddr != 0 )
        free_domheap_page(maddr_to_page(maddr));
}

unsigned int get_cache_line_size(void)
{
    return L1_CACHE_BYTES;
}

void cacheline_flush(char * addr)
{
    ia64_fc(addr);
    ia64_sync_i();
    ia64_srlz_i();
}

void flush_all_cache()
{
    ia64_sal_cache_flush(3);
}

void * map_to_nocache_virt(int nr_iommus, u64 maddr)
{
  return (void *) ( maddr + __IA64_UNCACHED_OFFSET);
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
    /* dummy */
}
