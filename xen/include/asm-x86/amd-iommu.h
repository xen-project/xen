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
#ifndef _ASM_X86_64_AMD_IOMMU_H
#define _ASM_X86_64_AMD_IOMMU_H

#include <xen/init.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/tasklet.h>
#include <asm/msi.h>
#include <asm/hvm/svm/amd-iommu-defs.h>

#define iommu_found()           (!list_empty(&amd_iommu_head))

extern struct list_head amd_iommu_head;

#pragma pack(1)
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
#pragma pack()

struct table_struct {
    void *buffer;
    unsigned long entries;
    unsigned long alloc_size;
};

struct ring_buffer {
    void *buffer;
    unsigned long entries;
    unsigned long alloc_size;
    uint32_t tail;
    uint32_t head;
    spinlock_t lock;    /* protect buffer pointers */
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
    uint32_t                entries;
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

#endif /* _ASM_X86_64_AMD_IOMMU_H */
