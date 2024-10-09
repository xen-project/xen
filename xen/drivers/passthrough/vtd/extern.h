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
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#ifndef DRIVERS__PASSTHROUGH__VTD__EXTERN_H
#define DRIVERS__PASSTHROUGH__VTD__EXTERN_H

#include "dmar.h"
#include <xen/keyhandler.h>

#define VTDPREFIX "[VT-D]"

struct pci_ats_dev;
extern bool rwbf_quirk;
extern const struct iommu_init_ops intel_iommu_init_ops;

void print_iommu_regs(struct acpi_drhd_unit *drhd);
void print_vtd_entries(struct vtd_iommu *iommu, int bus, int devfn, u64 gmfn);
keyhandler_fn_t cf_check vtd_dump_iommu_info;

bool cf_check intel_iommu_supports_eim(void);
int cf_check intel_iommu_enable_eim(void);
void cf_check intel_iommu_disable_eim(void);

int enable_qinval(struct vtd_iommu *iommu);
void disable_qinval(struct vtd_iommu *iommu);
int enable_intremap(struct vtd_iommu *iommu, int eim);
void disable_intremap(struct vtd_iommu *iommu);

int iommu_alloc(struct acpi_drhd_unit *drhd);
void iommu_free(struct acpi_drhd_unit *drhd);

domid_t did_to_domain_id(const struct vtd_iommu *iommu, unsigned int did);

int iommu_flush_iec_global(struct vtd_iommu *iommu);
int iommu_flush_iec_index(struct vtd_iommu *iommu, u8 im, u16 iidx);
void clear_fault_bits(struct vtd_iommu *iommu);

int __must_check cf_check vtd_flush_context_reg(
    struct vtd_iommu *iommu, uint16_t did, uint16_t source_id,
    uint8_t function_mask, uint64_t type, bool flush_non_present_entry);
int __must_check cf_check vtd_flush_iotlb_reg(
    struct vtd_iommu *iommu, uint16_t did, uint64_t addr,
    unsigned int size_order, uint64_t type, bool flush_non_present_entry,
    bool flush_dev_iotlb);

struct vtd_iommu *ioapic_to_iommu(unsigned int apic_id);
struct vtd_iommu *hpet_to_iommu(unsigned int hpet_id);
struct acpi_drhd_unit *ioapic_to_drhd(unsigned int apic_id);
struct acpi_drhd_unit *hpet_to_drhd(unsigned int hpet_id);
struct acpi_rhsa_unit *drhd_to_rhsa(const struct acpi_drhd_unit *drhd);

struct acpi_drhd_unit *find_ats_dev_drhd(struct vtd_iommu *iommu);

int ats_device(const struct pci_dev *, const struct acpi_drhd_unit *);

int dev_invalidate_iotlb(struct vtd_iommu *iommu, u16 did,
                         u64 addr, unsigned int size_order, u64 type);

int __must_check qinval_device_iotlb_sync(struct vtd_iommu *iommu,
                                          struct pci_dev *pdev,
                                          u16 did, u16 size, u64 addr);

uint64_t alloc_pgtable_maddr(unsigned long npages, nodeid_t node);
void free_pgtable_maddr(u64 maddr);
void *map_vtd_domain_page(u64 maddr);
void unmap_vtd_domain_page(const void *va);
int domain_context_mapping_one(struct domain *domain, struct vtd_iommu *iommu,
                               uint8_t bus, uint8_t devfn,
                               const struct pci_dev *pdev, domid_t domid,
                               paddr_t pgd_maddr, unsigned int mode);
int domain_context_unmap_one(struct domain *domain, struct vtd_iommu *iommu,
                             uint8_t bus, uint8_t devfn);
int cf_check intel_iommu_get_reserved_device_memory(
    iommu_grdm_t *func, void *ctxt);

unsigned int cf_check io_apic_read_remap_rte(
    unsigned int apic, unsigned int reg);
void cf_check io_apic_write_remap_rte(
    unsigned int apic, unsigned int pin, uint64_t rte);

struct msi_desc;
struct msi_msg;
int cf_check msi_msg_write_remap_rte(struct msi_desc *, struct msi_msg *);

int cf_check intel_setup_hpet_msi(struct msi_desc *);

int is_igd_vt_enabled_quirk(void);
bool is_azalia_tlb_enabled(const struct acpi_drhd_unit *);
void platform_quirks_init(void);
void vtd_ops_preamble_quirk(struct vtd_iommu *iommu);
void vtd_ops_postamble_quirk(struct vtd_iommu *iommu);
int __must_check me_wifi_quirk(struct domain *domain, uint8_t bus,
                               uint8_t devfn, domid_t domid, paddr_t pgd_maddr,
                               unsigned int mode);
void pci_vtd_quirk(const struct pci_dev *);
void quirk_iommu_caps(struct vtd_iommu *iommu);

bool platform_supports_intremap(void);
bool platform_supports_x2apic(void);

#endif // DRIVERS__PASSTHROUGH__VTD__EXTERN_H
