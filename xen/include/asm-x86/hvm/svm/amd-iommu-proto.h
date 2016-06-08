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
int amd_iommu_init(void);
int amd_iommu_update_ivrs_mapping_acpi(void);

/* mapping functions */
int amd_iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                       unsigned int flags);
int amd_iommu_unmap_page(struct domain *d, unsigned long gfn);
u64 amd_iommu_get_next_table_from_pte(u32 *entry);
int amd_iommu_reserve_domain_unity_map(struct domain *domain,
                                       u64 phys_addr, unsigned long size,
                                       int iw, int ir);

/* Share p2m table with iommu */
void amd_iommu_share_p2m(struct domain *d);

/* device table functions */
int get_dma_requestor_id(u16 seg, u16 bdf);
void amd_iommu_set_intremap_table(
    u32 *dte, u64 intremap_ptr, u8 int_valid);
void amd_iommu_set_root_page_table(
    u32 *dte, u64 root_ptr, u16 domain_id, u8 paging_mode, u8 valid);
void iommu_dte_set_iotlb(u32 *dte, u8 i);
void iommu_dte_add_device_entry(u32 *dte, struct ivrs_mappings *ivrs_dev);
void iommu_dte_set_guest_cr3(u32 *dte, u16 dom_id, u64 gcr3,
                             int gv, unsigned int glx);

/* send cmd to iommu */
void amd_iommu_flush_all_pages(struct domain *d);
void amd_iommu_flush_pages(struct domain *d, unsigned long gfn,
                           unsigned int order);
void amd_iommu_flush_iotlb(u8 devfn, const struct pci_dev *pdev,
                           uint64_t gaddr, unsigned int order);
void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf);
void amd_iommu_flush_intremap(struct amd_iommu *iommu, uint16_t bdf);
void amd_iommu_flush_all_caches(struct amd_iommu *iommu);

/* find iommu for bdf */
struct amd_iommu *find_iommu_for_device(int seg, int bdf);

/* interrupt remapping */
int amd_iommu_setup_ioapic_remapping(void);
void *amd_iommu_alloc_intremap_table(unsigned long **);
int amd_iommu_free_intremap_table(u16 seg, struct ivrs_mappings *);
void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value);
unsigned int amd_iommu_read_ioapic_from_ire(
    unsigned int apic, unsigned int reg);
int amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
void amd_iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
int amd_setup_hpet_msi(struct msi_desc *msi_desc);

extern struct ioapic_sbdf {
    u16 bdf, seg;
    u16 *pin_2_idx;
} ioapic_sbdf[MAX_IO_APICS];

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
void amd_iommu_suspend(void);
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

static inline u8 get_field_from_byte(u8 value, u8 mask)
{
    return (value & mask) / (mask & -mask);
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

static inline int amd_iommu_has_feature(struct amd_iommu *iommu, uint32_t bit)
{
    if ( !iommu_has_cap(iommu, PCI_CAP_EFRSUP_SHIFT) )
        return 0;
    return !!(iommu->features & (1U << bit));
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

static inline int iommu_is_pte_present(const u32 *entry)
{
    return get_field_from_reg_u32(entry[0],
                                  IOMMU_PDE_PRESENT_MASK,
                                  IOMMU_PDE_PRESENT_SHIFT);
}

static inline unsigned int iommu_next_level(const u32 *entry)
{
    return get_field_from_reg_u32(entry[0],
                                  IOMMU_PDE_NEXT_LEVEL_MASK,
                                  IOMMU_PDE_NEXT_LEVEL_SHIFT);
}

#endif /* _ASM_X86_64_AMD_IOMMU_PROTO_H */
