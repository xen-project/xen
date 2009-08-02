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
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#ifndef _VTD_EXTERN_H_
#define _VTD_EXTERN_H_

#include "dmar.h"
#include <xen/keyhandler.h>

extern int qinval_enabled;
extern int ats_enabled;

void print_iommu_regs(struct acpi_drhd_unit *drhd);
void print_vtd_entries(struct iommu *iommu, int bus, int devfn, u64 gmfn);
extern struct keyhandler dump_iommu_info_keyhandler;

int enable_qinval(struct iommu *iommu);
void disable_qinval(struct iommu *iommu);
int enable_intremap(struct iommu *iommu);
void disable_intremap(struct iommu *iommu);
int queue_invalidate_context(struct iommu *iommu,
    u16 did, u16 source_id, u8 function_mask, u8 granu);
int queue_invalidate_iotlb(struct iommu *iommu,
    u8 granu, u8 dr, u8 dw, u16 did, u8 am, u8 ih, u64 addr);
int queue_invalidate_iec(struct iommu *iommu,
    u8 granu, u8 im, u16 iidx);
int invalidate_sync(struct iommu *iommu);
int iommu_flush_iec_global(struct iommu *iommu);
int iommu_flush_iec_index(struct iommu *iommu, u8 im, u16 iidx);
struct iommu * ioapic_to_iommu(unsigned int apic_id);
struct acpi_drhd_unit * ioapic_to_drhd(unsigned int apic_id);
struct acpi_drhd_unit * iommu_to_drhd(struct iommu *iommu);
struct acpi_rhsa_unit * drhd_to_rhsa(struct acpi_drhd_unit *drhd);
void clear_fault_bits(struct iommu *iommu);
int ats_device(int seg, int bus, int devfn);
int enable_ats_device(int seg, int bus, int devfn);
int disable_ats_device(int seg, int bus, int devfn);
int invalidate_ats_tcs(struct iommu *iommu);
int qinval_device_iotlb(struct iommu *iommu,
                        u32 max_invs_pend, u16 sid, u16 size, u64 addr);
int dev_invalidate_iotlb(struct iommu *iommu, u16 did,
                         u64 addr, unsigned int size_order, u64 type);
struct acpi_drhd_unit * find_ats_dev_drhd(struct iommu *iommu);

#endif // _VTD_EXTERN_H_
