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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASM_X86_64_AMD_IOMMU_PROTO_H
#define _ASM_X86_64_AMD_IOMMU_PROTO_H

#include <xen/sched.h>
#include <asm/amd-iommu.h>
#include <asm/apicdef.h>
#include <xen/domain_page.h>

struct acpi_ivrs_hardware;

#define for_each_amd_iommu(amd_iommu) \
    list_for_each_entry(amd_iommu, \
        &amd_iommu_head, list)

#define DMA_32BIT_MASK  0x00000000ffffffffULL

#define AMD_IOMMU_DEBUG(fmt, args...) \
    do  \
    {   \
        if ( iommu_debug )  \
            printk(XENLOG_INFO "AMD-Vi: " fmt, ## args);    \
    } while(0)

/* amd-iommu-detect functions */
int amd_iommu_get_ivrs_dev_entries(void);
int amd_iommu_get_supported_ivhd_type(void);
int amd_iommu_detect_one_acpi(const struct acpi_ivrs_hardware *);
int amd_iommu_detect_acpi(void);
void get_iommu_features(struct amd_iommu *iommu);

/* amd-iommu-init functions */
int amd_iommu_prepare(bool xt);
int amd_iommu_init(bool xt);
int amd_iommu_init_late(void);
int amd_iommu_update_ivrs_mapping_acpi(void);
int iov_adjust_irq_affinities(void);

/* mapping functions */
int __must_check amd_iommu_map_page(struct domain *d, dfn_t dfn,
                                    mfn_t mfn, unsigned int flags,
                                    unsigned int *flush_flags);
int __must_check amd_iommu_unmap_page(struct domain *d, dfn_t dfn,
                                      unsigned int *flush_flags);
int __must_check amd_iommu_alloc_root(struct domain_iommu *hd);
int amd_iommu_reserve_domain_unity_map(struct domain *domain,
                                       paddr_t phys_addr, unsigned long size,
                                       int iw, int ir);
int __must_check amd_iommu_flush_iotlb_pages(struct domain *d, dfn_t dfn,
                                             unsigned int page_count,
                                             unsigned int flush_flags);
int __must_check amd_iommu_flush_iotlb_all(struct domain *d);

/* device table functions */
int get_dma_requestor_id(uint16_t seg, uint16_t bdf);
void amd_iommu_set_intremap_table(struct amd_iommu_dte *dte,
                                  const void *ptr,
                                  const struct amd_iommu *iommu,
                                  bool valid);
void amd_iommu_set_root_page_table(struct amd_iommu_dte *dte,
				   uint64_t root_ptr, uint16_t domain_id,
				   uint8_t paging_mode, bool valid);
void iommu_dte_add_device_entry(struct amd_iommu_dte *dte,
                                const struct ivrs_mappings *ivrs_dev);
void iommu_dte_set_guest_cr3(struct amd_iommu_dte *dte, uint16_t dom_id,
                             uint64_t gcr3_mfn, bool gv, uint8_t glx);

/* send cmd to iommu */
void amd_iommu_flush_all_pages(struct domain *d);
void amd_iommu_flush_pages(struct domain *d, unsigned long dfn,
                           unsigned int order);
void amd_iommu_flush_iotlb(u8 devfn, const struct pci_dev *pdev,
                           uint64_t gaddr, unsigned int order);
void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf);
void amd_iommu_flush_intremap(struct amd_iommu *iommu, uint16_t bdf);
void amd_iommu_flush_all_caches(struct amd_iommu *iommu);

/* find iommu for bdf */
struct amd_iommu *find_iommu_for_device(int seg, int bdf);

/* interrupt remapping */
bool iov_supports_xt(void);
int amd_iommu_setup_ioapic_remapping(void);
void *amd_iommu_alloc_intremap_table(
    const struct amd_iommu *, unsigned long **, unsigned int nr);
int amd_iommu_free_intremap_table(
    const struct amd_iommu *, struct ivrs_mappings *, uint16_t);
unsigned int amd_iommu_intremap_table_order(
    const void *irt, const struct amd_iommu *iommu);
void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value);
unsigned int amd_iommu_read_ioapic_from_ire(
    unsigned int apic, unsigned int reg);
int amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
void amd_iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
int amd_setup_hpet_msi(struct msi_desc *msi_desc);
void amd_iommu_dump_intremap_tables(unsigned char key);

extern struct ioapic_sbdf {
    u16 bdf, seg;
    u8 id;
    bool cmdline;
    u16 *pin_2_idx;
} ioapic_sbdf[MAX_IO_APICS];

extern unsigned int nr_ioapic_sbdf;
unsigned int ioapic_id_to_index(unsigned int apic_id);
unsigned int get_next_ioapic_sbdf_index(void);

extern struct hpet_sbdf {
    u16 bdf, seg, id;
    enum {
        HPET_NONE,
        HPET_CMDL,
        HPET_IVHD,
    } init;
} hpet_sbdf;

extern void *shared_intremap_table;
extern unsigned long *shared_intremap_inuse;

/* power management support */
void amd_iommu_resume(void);
int __must_check amd_iommu_suspend(void);
void amd_iommu_crash_shutdown(void);

/* guest iommu support */
void amd_iommu_send_guest_cmd(struct amd_iommu *iommu, u32 cmd[]);
void guest_iommu_add_ppr_log(struct domain *d, u32 entry[]);
void guest_iommu_add_event_log(struct domain *d, u32 entry[]);
int guest_iommu_init(struct domain* d);
void guest_iommu_destroy(struct domain *d);
int guest_iommu_set_base(struct domain *d, uint64_t base);

static inline u32 get_field_from_reg_u32(u32 reg_value, u32 mask, u32 shift)
{
    u32 field;
    field = (reg_value & mask) >> shift;
    return field;
}

static inline u32 set_field_in_reg_u32(u32 field, u32 reg_value,
        u32 mask, u32 shift, u32 *reg)
{
    reg_value &= ~mask;
    reg_value |= (field << shift) & mask;
    if (reg)
        *reg = reg_value;
    return reg_value;
}

static inline unsigned long region_to_pages(unsigned long addr, unsigned long size)
{
    return (PAGE_ALIGN(addr + size) - (addr & PAGE_MASK)) >> PAGE_SHIFT;
}

static inline struct page_info* alloc_amd_iommu_pgtable(void)
{
    struct page_info *pg;
    void *vaddr;

    pg = alloc_domheap_page(NULL, 0);
    if ( pg == NULL )
        return 0;
    vaddr = __map_domain_page(pg);
    memset(vaddr, 0, PAGE_SIZE);
    unmap_domain_page(vaddr);
    return pg;
}

static inline void free_amd_iommu_pgtable(struct page_info *pg)
{
    if ( pg != 0 )
        free_domheap_page(pg);
}

static inline void* __alloc_amd_iommu_tables(int order)
{
    void *buf;
    buf = alloc_xenheap_pages(order, 0);
    return buf;
}

static inline void __free_amd_iommu_tables(void *table, int order)
{
    free_xenheap_pages(table, order);
}

static inline void iommu_set_bit(uint32_t *reg, uint32_t bit)
{
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, *reg, 1U << bit, bit, reg);
}

static inline void iommu_clear_bit(uint32_t *reg, uint32_t bit)
{
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, *reg, 1U << bit, bit, reg);
}

static inline uint32_t iommu_get_bit(uint32_t reg, uint32_t bit)
{
    return get_field_from_reg_u32(reg, 1U << bit, bit);
}

static inline int iommu_has_cap(struct amd_iommu *iommu, uint32_t bit)
{
    return !!(iommu->cap.header & (1u << bit));
}

/* access tail or head pointer of ring buffer */
static inline uint32_t iommu_get_rb_pointer(uint32_t reg)
{
    return get_field_from_reg_u32(reg, IOMMU_RING_BUFFER_PTR_MASK,
                                  IOMMU_RING_BUFFER_PTR_SHIFT);
}

static inline void iommu_set_rb_pointer(uint32_t *reg, uint32_t val)
{
    set_field_in_reg_u32(val, *reg, IOMMU_RING_BUFFER_PTR_MASK,
                         IOMMU_RING_BUFFER_PTR_SHIFT, reg);
}

/* access device id field from iommu cmd */
static inline uint16_t iommu_get_devid_from_cmd(uint32_t cmd)
{
    return get_field_from_reg_u32(cmd, IOMMU_CMD_DEVICE_ID_MASK,
                                  IOMMU_CMD_DEVICE_ID_SHIFT);
}

static inline void iommu_set_devid_to_cmd(uint32_t *cmd, uint16_t id)
{
    set_field_in_reg_u32(id, *cmd, IOMMU_CMD_DEVICE_ID_MASK,
                         IOMMU_CMD_DEVICE_ID_SHIFT, cmd);
}

/* access address field from iommu cmd */
static inline uint32_t iommu_get_addr_lo_from_cmd(uint32_t cmd)
{
    return get_field_from_reg_u32(cmd, IOMMU_CMD_ADDR_LOW_MASK,
                                  IOMMU_CMD_ADDR_LOW_SHIFT);
}

static inline uint32_t iommu_get_addr_hi_from_cmd(uint32_t cmd)
{
    return get_field_from_reg_u32(cmd, IOMMU_CMD_ADDR_LOW_MASK,
                                  IOMMU_CMD_ADDR_HIGH_SHIFT);
}

/* access address field from event log entry */
#define iommu_get_devid_from_event          iommu_get_devid_from_cmd

/* access iommu base addresses field from mmio regs */
static inline void iommu_set_addr_lo_to_reg(uint32_t *reg, uint32_t addr)
{
    set_field_in_reg_u32(addr, *reg, IOMMU_REG_BASE_ADDR_LOW_MASK,
                         IOMMU_REG_BASE_ADDR_LOW_SHIFT, reg);
}

static inline void iommu_set_addr_hi_to_reg(uint32_t *reg, uint32_t addr)
{
    set_field_in_reg_u32(addr, *reg, IOMMU_REG_BASE_ADDR_HIGH_MASK,
                         IOMMU_REG_BASE_ADDR_HIGH_SHIFT, reg);
}

#endif /* _ASM_X86_64_AMD_IOMMU_PROTO_H */
