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
#ifndef DRIVERS__PASSTHROUGH__AMD__IOMMU_H
#define DRIVERS__PASSTHROUGH__AMD__IOMMU_H

#include <xen/init.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/tasklet.h>
#include <xen/sched.h>
#include <xen/domain_page.h>

#include <asm/msi.h>
#include <asm/apicdef.h>

#include "iommu-defs.h"

#define iommu_found()           (!list_empty(&amd_iommu_head))

extern struct list_head amd_iommu_head;

typedef struct event_entry
{
    uint32_t data[4];
} event_entry_t;

typedef struct ppr_entry
{
    uint32_t data[4];
} ppr_entry_t;

typedef struct cmd_entry
{
    uint32_t data[4];
} cmd_entry_t;

struct table_struct {
    void *buffer;
    unsigned long entries;
    unsigned long alloc_size;
};

struct ring_buffer {
    spinlock_t lock;    /* protect buffer pointers */
    void *buffer;
    uint32_t tail;
    uint32_t head;
    uint32_t size;
};

typedef struct iommu_cap {
    uint32_t header;                    /* offset 00h */
    uint32_t base_low;                  /* offset 04h */
    uint32_t base_hi;                   /* offset 08h */
    uint32_t range;                     /* offset 0Ch */
    uint32_t misc;                      /* offset 10h */
} iommu_cap_t;

struct amd_iommu {
    struct list_head list;
    spinlock_t lock; /* protect iommu */

    u16 seg;
    u16 bdf;
    struct msi_desc msi;

    u16 cap_offset;
    iommu_cap_t cap;

    u8 ht_flags;
    union amd_iommu_ext_features features;

    void *mmio_base;
    unsigned long mmio_base_phys;

    union amd_iommu_control ctrl;

    struct table_struct dev_table;
    struct ring_buffer cmd_buffer;
    struct ring_buffer event_log;
    struct ring_buffer ppr_log;
    unsigned long *domid_map;

    int exclusion_enable;
    int exclusion_allow_all;
    uint64_t exclusion_base;
    uint64_t exclusion_limit;

    int enabled;

    struct list_head ats_devices;
};

struct ivrs_unity_map {
    bool read:1;
    bool write:1;
    bool global:1;
    paddr_t addr;
    unsigned long length;
    struct ivrs_unity_map *next;
};

struct ivrs_mappings {
    uint16_t dte_requestor_id;
    bool valid:1;
    bool dte_allow_exclusion:1;
    bool block_ats:1;

    /* ivhd device data settings */
    uint8_t device_flags;

    struct amd_iommu *iommu;
    struct ivrs_unity_map *unity_map;

    /* per device interrupt remapping table */
    void *intremap_table;
    unsigned long *intremap_inuse;
    spinlock_t intremap_lock;
};

extern unsigned int ivrs_bdf_entries;
extern u8 ivhd_type;

struct ivrs_mappings *get_ivrs_mappings(uint16_t seg);
int iterate_ivrs_mappings(int (*handler)(uint16_t seg,
                                         struct ivrs_mappings *map));
int iterate_ivrs_entries(int (*handler)(const struct amd_iommu *iommu,
                                        struct ivrs_mappings *map,
                                        uint16_t bdf));

extern bool iommuv2_enabled;

struct acpi_ivrs_hardware;

#define for_each_amd_iommu(amd_iommu) \
    list_for_each_entry(amd_iommu, \
        &amd_iommu_head, list)

#define DMA_32BIT_MASK  0x00000000ffffffffULL

#define AMD_IOMMU_ERROR(fmt, args...) \
    printk(XENLOG_ERR "AMD-Vi: Error: " fmt, ## args)

#define AMD_IOMMU_WARN(fmt, args...) \
    printk(XENLOG_WARNING "AMD-Vi: Warning: " fmt, ## args)

#define AMD_IOMMU_VERBOSE(fmt, args...) \
    do { \
        if ( iommu_verbose ) \
            printk(XENLOG_INFO "AMD-Vi: " fmt, ## args); \
    } while ( false )

#define AMD_IOMMU_DEBUG(fmt, args...) \
    do  \
    {   \
        if ( iommu_debug )  \
            printk(XENLOG_INFO "AMD-Vi: " fmt, ## args);    \
    } while(0)

/* amd-iommu-detect functions */
int amd_iommu_get_ivrs_dev_entries(void);
int amd_iommu_get_supported_ivhd_type(void);
int amd_iommu_detect_one_acpi(const struct acpi_ivrs_hardware *ivhd_block);
int amd_iommu_detect_acpi(void);
void get_iommu_features(struct amd_iommu *iommu);

/* amd-iommu-init functions */
int amd_iommu_prepare(bool xt);
int amd_iommu_init(bool xt);
int amd_iommu_init_late(void);
int amd_iommu_update_ivrs_mapping_acpi(void);
void cf_check iov_adjust_irq_affinities(void);

int cf_check amd_iommu_quarantine_init(struct pci_dev *pdev, bool scratch_page);
void amd_iommu_quarantine_teardown(struct pci_dev *pdev);

/* mapping functions */
int __must_check cf_check amd_iommu_map_page(
    struct domain *d, dfn_t dfn, mfn_t mfn, unsigned int flags,
    unsigned int *flush_flags);
int __must_check cf_check amd_iommu_unmap_page(
    struct domain *d, dfn_t dfn, unsigned int order,
    unsigned int *flush_flags);
int __must_check amd_iommu_alloc_root(struct domain *d);
int amd_iommu_reserve_domain_unity_map(struct domain *d,
                                       const struct ivrs_unity_map *map,
                                       unsigned int flag);
int amd_iommu_reserve_domain_unity_unmap(struct domain *d,
                                         const struct ivrs_unity_map *map);
int cf_check amd_iommu_get_reserved_device_memory(
    iommu_grdm_t *func, void *ctxt);
int __must_check cf_check amd_iommu_flush_iotlb_pages(
    struct domain *d, dfn_t dfn, unsigned long page_count,
    unsigned int flush_flags);
void amd_iommu_print_entries(const struct amd_iommu *iommu, unsigned int dev_id,
                             dfn_t dfn);

/* device table functions */
int get_dma_requestor_id(uint16_t seg, uint16_t bdf);
void amd_iommu_set_intremap_table(struct amd_iommu_dte *dte,
                                  const void *ptr,
                                  const struct amd_iommu *iommu,
                                  bool valid);
#define SET_ROOT_VALID          (1u << 0)
#define SET_ROOT_WITH_UNITY_MAP (1u << 1)
int __must_check amd_iommu_set_root_page_table(struct amd_iommu_dte *dte,
                                               uint64_t root_ptr,
                                               uint16_t domain_id,
                                               uint8_t paging_mode,
                                               unsigned int flags);
void iommu_dte_add_device_entry(struct amd_iommu_dte *dte,
                                const struct ivrs_mappings *ivrs_dev);

/* send cmd to iommu */
void amd_iommu_flush_all_pages(struct domain *d);
void amd_iommu_flush_pages(struct domain *d, unsigned long dfn,
                           unsigned int order);
void amd_iommu_flush_iotlb(u8 devfn, const struct pci_dev *pdev,
                           daddr_t daddr, unsigned int order);
void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf,
                            domid_t domid);
void amd_iommu_flush_intremap(struct amd_iommu *iommu, uint16_t bdf);
void amd_iommu_flush_all_caches(struct amd_iommu *iommu);

/* find iommu for bdf */
struct amd_iommu *find_iommu_for_device(int seg, int bdf);

/* interrupt remapping */
bool cf_check iov_supports_xt(void);
int amd_iommu_setup_ioapic_remapping(void);
void *amd_iommu_alloc_intremap_table(
    const struct amd_iommu *iommu, unsigned long **inuse_map, unsigned int nr);
int cf_check amd_iommu_free_intremap_table(
    const struct amd_iommu *iommu, struct ivrs_mappings *ivrs_mapping,
    uint16_t bdf);
unsigned int amd_iommu_intremap_table_order(
    const void *irt, const struct amd_iommu *iommu);
void cf_check amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int pin, uint64_t rte);
unsigned int cf_check amd_iommu_read_ioapic_from_ire(
    unsigned int apic, unsigned int reg);
int cf_check amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
int cf_check amd_setup_hpet_msi(struct msi_desc *msi_desc);
void cf_check amd_iommu_dump_intremap_tables(unsigned char key);

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

extern unsigned int amd_iommu_acpi_info;
extern unsigned int amd_iommu_max_paging_mode;
extern int amd_iommu_min_paging_mode;

extern void *shared_intremap_table;
extern unsigned long *shared_intremap_inuse;

/* power management support */
void cf_check amd_iommu_resume(void);
int __must_check cf_check amd_iommu_suspend(void);
void cf_check amd_iommu_crash_shutdown(void);
void cf_check amd_iommu_quiesce(void);

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

static inline int amd_iommu_get_paging_mode(unsigned long max_frames)
{
    int level = 1;

    BUG_ON(!max_frames);

    while ( max_frames > PTE_PER_TABLE_SIZE )
    {
        max_frames = PTE_PER_TABLE_ALIGN(max_frames) >> PTE_PER_TABLE_SHIFT;
        if ( ++level > amd_iommu_max_paging_mode )
            return -ENOMEM;
    }

    return level;
}

static inline void *__alloc_amd_iommu_tables(unsigned int order)
{
    return alloc_xenheap_pages(order, 0);
}

static inline void __free_amd_iommu_tables(void *table, unsigned int order)
{
    free_xenheap_pages(table, order);
}

static inline bool iommu_has_cap(const struct amd_iommu *iommu, unsigned int bit)
{
    return iommu->cap.header & (1u << bit);
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

#endif /* DRIVERS__PASSTHROUGH__AMD__IOMMU_H */
