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
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 */

#ifndef __XEN_HVM_IOMMU_H__
#define __XEN_HVM_IOMMU_H__

#include <xen/iommu.h>

struct g2m_ioport {
    struct list_head list;
    unsigned int gport;
    unsigned int mport;
    unsigned int np;
};

struct mapped_rmrr {
    struct list_head list;
    u64 base;
    u64 end;
};

struct hvm_iommu {
    u64 pgd_maddr;                 /* io page directory machine address */
    spinlock_t mapping_lock;       /* io page table lock */
    int agaw;     /* adjusted guest address width, 0 is level 2 30-bit */
    struct list_head g2m_ioport_list;  /* guest to machine ioport mapping */
    u64 iommu_bitmap;              /* bitmap of iommu(s) that the domain uses */
    struct list_head mapped_rmrrs;

    /* amd iommu support */
    int domain_id;
    int paging_mode;
    struct page_info *root_table;
    struct guest_iommu *g_iommu;

    /* iommu_ops */
    const struct iommu_ops *platform_ops;
};

#endif /* __XEN_HVM_IOMMU_H__ */
