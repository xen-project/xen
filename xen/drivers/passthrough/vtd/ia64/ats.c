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
 * Author: Allen Kay <allen.m.kay@intel.com>
 */

#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/msi.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"
#include "../extern.h"

struct pci_ats_dev;

int ats_enabled = 0;

struct acpi_drhd_unit * find_ats_dev_drhd(struct iommu *iommu)
{
    return NULL;
}

int ats_device(int seg, int bus, int devfn)
{
    return 0;
}

int enable_ats_device(int seg, int bus, int devfn)
{
    return 0;
}

int dev_invalidate_iotlb(struct iommu *iommu, u16 did,
    u64 addr, unsigned int size_order, u64 type)
{
    return 0;
}
