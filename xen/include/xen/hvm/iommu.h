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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 */

#ifndef __XEN_HVM_IOMMU_H__
#define __XEN_HVM_IOMMU_H__

#include <xen/iommu.h>
#include <xen/list.h>
#include <asm/hvm/iommu.h>

struct hvm_iommu {
    struct arch_hvm_iommu arch;

    /* iommu_ops */
    const struct iommu_ops *platform_ops;

#ifdef HAS_DEVICE_TREE
    /* List of DT devices assigned to this domain */
    struct list_head dt_devices;
#endif

    /* Features supported by the IOMMU */
    DECLARE_BITMAP(features, IOMMU_FEAT_count);
};

#define iommu_set_feature(d, f)   set_bit((f), domain_hvm_iommu(d)->features)
#define iommu_clear_feature(d, f) clear_bit((f), domain_hvm_iommu(d)->features)

#endif /* __XEN_HVM_IOMMU_H__ */
