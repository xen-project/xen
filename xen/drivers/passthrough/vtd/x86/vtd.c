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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#include <xen/param.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <asm/paging.h>
#include <xen/iommu.h>
#include <xen/irq.h>
#include <xen/numa.h>
#include <asm/fixmap.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"
#include "../extern.h"

/*
 * iommu_inclusive_mapping: when set, all memory below 4GB is included in dom0
 * 1:1 iommu mappings except xen and unusable regions.
 */
boolean_param("iommu_inclusive_mapping", iommu_hwdom_inclusive);

void *map_vtd_domain_page(u64 maddr)
{
    return map_domain_page(_mfn(paddr_to_pfn(maddr)));
}

void unmap_vtd_domain_page(void *va)
{
    unmap_domain_page(va);
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
