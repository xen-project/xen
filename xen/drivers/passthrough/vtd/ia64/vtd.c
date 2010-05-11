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
#include <xen/softirq.h>
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

static int do_dom0_iommu_mapping(unsigned long start, unsigned long end,
				void *arg)
{
    unsigned long tmp, pfn, j, page_addr = start;
    struct domain *d = (struct domain *)arg;

    extern int xen_in_range(paddr_t start, paddr_t end);
    /* Set up 1:1 page table for dom0 for all Ram except Xen bits.*/

    while (page_addr < end)
    {
	if (xen_in_range(page_addr, page_addr + PAGE_SIZE))
            continue;

        pfn = page_addr >> PAGE_SHIFT;
        tmp = 1 << (PAGE_SHIFT - PAGE_SHIFT_4K);
        for ( j = 0; j < tmp; j++ )
            iommu_map_page(d, (pfn*tmp+j), (pfn*tmp+j));

	page_addr += PAGE_SIZE;

        if (!(pfn & (0xfffff >> (PAGE_SHIFT - PAGE_SHIFT_4K))))
            process_pending_softirqs();
    }
    return 0;
}

void iommu_set_dom0_mapping(struct domain *d)
{
	if (dom0)
	    BUG_ON(d != dom0);
	efi_memmap_walk(do_dom0_iommu_mapping, d);
}
