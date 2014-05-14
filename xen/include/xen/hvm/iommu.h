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
#include <asm/hvm/iommu.h>

struct hvm_iommu {
    struct arch_hvm_iommu arch;

    /* iommu_ops */
    const struct iommu_ops *platform_ops;
};

#endif /* __XEN_HVM_IOMMU_H__ */
