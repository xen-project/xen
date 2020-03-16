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
#ifndef AMD_IOMMU_H
#define AMD_IOMMU_H

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

    int exclusion_enable;
    int exclusion_allow_all;
    uint64_t exclusion_base;
    uint64_t exclusion_limit;

    int enabled;

    struct list_head ats_devices;
};

struct ivrs_mappings {
    uint16_t dte_requestor_id;
    bool valid:1;
    bool dte_allow_exclusion:1;
    bool unity_map_enable:1;
    bool write_permission:1;
    bool read_permission:1;

    /* ivhd device data settings */
    uint8_t device_flags;

    unsigned long addr_range_start;
    unsigned long addr_range_length;
    struct amd_iommu *iommu;

    /* per device interrupt remapping table */
    void *intremap_table;
    unsigned long *intremap_inuse;
    spinlock_t intremap_lock;
};

extern unsigned int ivrs_bdf_entries;
extern u8 ivhd_type;

struct ivrs_mappings *get_ivrs_mappings(u16 seg);
int iterate_ivrs_mappings(int (*)(u16 seg, struct ivrs_mappings *));
int iterate_ivrs_entries(int (*)(const struct amd_iommu *,
                                 struct ivrs_mappings *, uint16_t));

/* iommu tables in guest space */
struct mmio_reg {
    uint32_t    lo;
    uint32_t    hi;
};

struct guest_dev_table {
    struct mmio_reg         reg_base;
    uint32_t                size;
};

struct guest_buffer {
    struct mmio_reg         reg_base;
    struct mmio_reg         reg_tail;
    struct mmio_reg         reg_head;
    uint32_t                size;
};

struct guest_iommu_msi {
    uint8_t                 vector;
    uint8_t                 dest;
    uint8_t                 dest_mode;
    uint8_t                 delivery_mode;
    uint8_t                 trig_mode;
};

/* virtual IOMMU structure */
struct guest_iommu {

    struct domain          *domain;
    spinlock_t              lock;
    bool_t                  enabled;

    struct guest_dev_table  dev_table;
    struct guest_buffer     cmd_buffer;
    struct guest_buffer     event_log;
    struct guest_buffer     ppr_log;

    struct tasklet          cmd_buffer_tasklet;

    uint64_t                mmio_base;             /* MMIO base address */

    /* MMIO regs */
    union amd_iommu_control reg_ctrl;              /* MMIO offset 0018h */
    struct mmio_reg         reg_status;            /* MMIO offset 2020h */
    union amd_iommu_ext_features reg_ext_feature;  /* MMIO offset 0030h */

    /* guest interrupt settings */
    struct guest_iommu_msi  msi;
};

extern bool_t iommuv2_enabled;

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

int amd_iommu_quarantine_init(struct domain *d);

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

static inline int amd_iommu_get_paging_mode(unsigned long max_frames)
{
    int level = 1;

    BUG_ON(!max_frames);

    while ( max_frames > PTE_PER_TABLE_SIZE )
    {
        max_frames = PTE_PER_TABLE_ALIGN(max_frames) >> PTE_PER_TABLE_SHIFT;
        if ( ++level > 6 )
            return -ENOMEM;
    }

    return level;
}

static inline struct page_info *alloc_amd_iommu_pgtable(void)
{
    struct page_info *pg = alloc_domheap_page(NULL, 0);

    if ( pg )
        clear_domain_page(page_to_mfn(pg));

    return pg;
}

static inline void free_amd_iommu_pgtable(struct page_info *pg)
{
    if ( pg )
        free_domheap_page(pg);
}

static inline void *__alloc_amd_iommu_tables(unsigned int order)
{
    return alloc_xenheap_pages(order, 0);
}

static inline void __free_amd_iommu_tables(void *table, unsigned int order)
{
    free_xenheap_pages(table, order);
}

static inline int iommu_has_cap(struct amd_iommu *iommu, uint32_t bit)
{
    return !!(iommu->cap.header & (1u << bit));
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

#endif /* AMD_IOMMU_H */
