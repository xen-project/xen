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

#ifndef __ASM_X86_HVM_IOMMU_H__
#define __ASM_X86_HVM_IOMMU_H__

#include <xen/iommu.h>
#include <asm/hvm/irq.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/io.h>
#include <public/hvm/params.h>
#include <public/hvm/save.h>

struct g2m_ioport {
    struct list_head list;
    unsigned int gport;
    unsigned int mport;
    unsigned int np;
};

struct hvm_iommu {
    spinlock_t iommu_list_lock;    /* protect iommu specific lists */
    struct list_head pdev_list;    /* direct accessed pci devices */
    struct dma_pte *pgd;           /* io page directory root */
    spinlock_t mapping_lock;       /* io page table lock */
    int agaw;     /* adjusted guest address width, 0 is level 2 30-bit */
    struct list_head g2m_ioport_list;  /* guest to machine ioport mapping */
    domid_t iommu_domid;           /* domain id stored in iommu */

    /* amd iommu support */
    int domain_id;
    int paging_mode;
    void *root_table;
    bool_t p2m_synchronized;

    /* iommu_ops */
    struct iommu_ops *platform_ops;
};

#endif /* __ASM_X86_HVM_IOMMU_H__ */
