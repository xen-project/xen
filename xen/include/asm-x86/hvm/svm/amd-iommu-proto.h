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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef _ASM_X86_64_AMD_IOMMU_PROTO_H
#define _ASM_X86_64_AMD_IOMMU_PROTO_H

#include <xen/sched.h>
#include <asm/amd-iommu.h>

#define for_each_amd_iommu(amd_iommu) \
    list_for_each_entry(amd_iommu, \
        &amd_iommu_head, list)

#define for_each_pdev(domain, pdev) \
    list_for_each_entry(pdev, \
         &(domain->arch.hvm_domain.hvm_iommu.pdev_list), list)

#define DMA_32BIT_MASK  0x00000000ffffffffULL
#define PAGE_ALIGN(addr)    (((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#ifdef AMD_IOV_DEBUG
#define amd_iov_info(fmt, args...) \
    printk(XENLOG_INFO "AMD_IOV: " fmt, ## args)
#define amd_iov_warning(fmt, args...) \
    printk(XENLOG_WARNING "AMD_IOV: " fmt, ## args)
#define amd_iov_error(fmt, args...) \
    printk(XENLOG_ERR "AMD_IOV: %s:%d: " fmt, __FILE__ , __LINE__ , ## args)
#else
#define amd_iov_info(fmt, args...)
#define amd_iov_warning(fmt, args...)
#define amd_iov_error(fmt, args...)
#endif

typedef int (*iommu_detect_callback_ptr_t)(
    u8 bus, u8 dev, u8 func, u8 cap_ptr);

/* amd-iommu-detect functions */
int __init scan_for_iommu(iommu_detect_callback_ptr_t iommu_detect_callback);
int __init get_iommu_capabilities(u8 bus, u8 dev, u8 func, u8 cap_ptr,
           struct amd_iommu *iommu);
int __init get_iommu_last_downstream_bus(struct amd_iommu *iommu);

/* amd-iommu-init functions */
int __init map_iommu_mmio_region(struct amd_iommu *iommu);
void __init unmap_iommu_mmio_region(struct amd_iommu *iommu);
void __init register_iommu_dev_table_in_mmio_space(struct amd_iommu *iommu);
void __init register_iommu_cmd_buffer_in_mmio_space(struct amd_iommu *iommu);
void __init register_iommu_event_log_in_mmio_space(struct amd_iommu *iommu);
void __init enable_iommu(struct amd_iommu *iommu);

/* mapping functions */
int amd_iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn);
int amd_iommu_unmap_page(struct domain *d, unsigned long gfn);
void *amd_iommu_get_vptr_from_page_table_entry(u32 *entry);
int amd_iommu_reserve_domain_unity_map(struct domain *domain,
        unsigned long phys_addr, unsigned long size, int iw, int ir);
int amd_iommu_sync_p2m(struct domain *d);

/* device table functions */
void amd_iommu_set_dev_table_entry(u32 *dte, u64 root_ptr,
        u16 domain_id, u8 sys_mgt, u8 dev_ex, u8 paging_mode);
int amd_iommu_is_dte_page_translation_valid(u32 *entry);
void invalidate_dev_table_entry(struct amd_iommu *iommu,
            u16 devic_id);

/* send cmd to iommu */
int send_iommu_command(struct amd_iommu *iommu, u32 cmd[]);
void flush_command_buffer(struct amd_iommu *iommu);

/* find iommu for bdf */
struct amd_iommu *find_iommu_for_device(int bus, int devfn);

/* amd-iommu-acpi functions */
int __init parse_ivrs_table(struct acpi_table_header *table);

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

static inline u8 get_field_from_byte(u8 value, u8 mask, u8 shift)
{
    u8 field;
    field = (value & mask) >> shift;
    return field;
}

static inline unsigned long region_to_pages(unsigned long addr, unsigned long size)
{
    return (PAGE_ALIGN(addr + size) - (addr & PAGE_MASK)) >> PAGE_SHIFT;
}

#endif /* _ASM_X86_64_AMD_IOMMU_PROTO_H */
