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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#ifndef _ASM_X86_64_AMD_IOMMU_H
#define _ASM_X86_64_AMD_IOMMU_H

#include <xen/init.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <asm/hvm/svm/amd-iommu-defs.h>

#define iommu_found()           (!list_empty(&amd_iommu_head))

extern int amd_iommu_enabled;
extern struct list_head amd_iommu_head;

extern int __init amd_iommu_detect(void);

struct table_struct {
    void *buffer;
    unsigned long entries;
    unsigned long alloc_size;
};

struct amd_iommu {
    struct list_head list;
    spinlock_t lock; /* protect iommu */

    int iotlb_support;
    int ht_tunnel_support;
    int not_present_cached;
    u8  revision;

    u8  root_bus;
    u8  first_devfn;
    u8  last_devfn;

    int last_downstream_bus;
    int downstream_bus_present[PCI_MAX_BUS_COUNT];

    void *mmio_base;
    unsigned long mmio_base_phys;

    struct table_struct dev_table;
    struct table_struct cmd_buffer;
    u32 cmd_buffer_tail;

    int exclusion_enabled;
    unsigned long exclusion_base;
    unsigned long exclusion_limit;
};

#endif /* _ASM_X86_64_AMD_IOMMU_H */
