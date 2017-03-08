/*
 *  efi-dom0.c - Domain0 EFI Boot Support
 *
 *  Copyright (C) 2016 Shannon Zhao <shannon.zhao@linaro.org>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include "efi.h"
#include <xen/sched.h>
#include <xen/pfn.h>
#include <xen/libfdt/libfdt.h>
#include <asm/setup.h>
#include <asm/acpi.h>
#include "../../../common/decompress.h"
#define XZ_EXTERN STATIC
#include "../../../common/xz/crc32.c"

/* Constant to indicate "Xen" in unicode u16 format */
static const CHAR16 xen_efi_fw_vendor[] = {0x0058, 0x0065, 0x006E, 0x0000};

size_t __init estimate_efi_size(int mem_nr_banks)
{
    size_t size;
    size_t est_size = sizeof(EFI_SYSTEM_TABLE);
    size_t ect_size = sizeof(EFI_CONFIGURATION_TABLE);
    size_t emd_size = sizeof(EFI_MEMORY_DESCRIPTOR);
    size_t fw_vendor_size = sizeof(xen_efi_fw_vendor);
    int acpi_mem_nr_banks = 0;

    if ( !acpi_disabled )
        acpi_mem_nr_banks = bootinfo.acpi.nr_banks;

    size = ROUNDUP(est_size + ect_size + fw_vendor_size, 8);
    /* plus 1 for new created tables */
    size += ROUNDUP(emd_size * (mem_nr_banks + acpi_mem_nr_banks + 1), 8);

    return size;
}

void __init acpi_create_efi_system_table(struct domain *d,
                                         struct membank tbl_add[])
{
    u64 table_addr, table_size, offset = 0;
    u8 *base_ptr;
    EFI_CONFIGURATION_TABLE *efi_conf_tbl;
    EFI_SYSTEM_TABLE *efi_sys_tbl;

    table_addr = d->arch.efi_acpi_gpa
                 + acpi_get_table_offset(tbl_add, TBL_EFIT);
    table_size = sizeof(EFI_SYSTEM_TABLE) + sizeof(EFI_CONFIGURATION_TABLE)
                 + sizeof(xen_efi_fw_vendor);
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_EFIT);
    efi_sys_tbl = (EFI_SYSTEM_TABLE *)base_ptr;

    efi_sys_tbl->Hdr.Signature = EFI_SYSTEM_TABLE_SIGNATURE;
    /* Specify the revision as 2.5 */
    efi_sys_tbl->Hdr.Revision = (2 << 16 | 50);
    efi_sys_tbl->Hdr.HeaderSize = table_size;

    efi_sys_tbl->FirmwareRevision = 1;
    efi_sys_tbl->NumberOfTableEntries = 1;
    offset += sizeof(EFI_SYSTEM_TABLE);
    memcpy(base_ptr + offset, xen_efi_fw_vendor, sizeof(xen_efi_fw_vendor));
    efi_sys_tbl->FirmwareVendor = (CHAR16 *)(table_addr + offset);

    offset += sizeof(xen_efi_fw_vendor);
    efi_conf_tbl = (EFI_CONFIGURATION_TABLE *)(base_ptr + offset);
    efi_conf_tbl->VendorGuid = (EFI_GUID)ACPI_20_TABLE_GUID;
    efi_conf_tbl->VendorTable = (VOID *)tbl_add[TBL_RSDP].start;
    efi_sys_tbl->ConfigurationTable = (EFI_CONFIGURATION_TABLE *)(table_addr
                                                                  + offset);
    xz_crc32_init();
    efi_sys_tbl->Hdr.CRC32 = xz_crc32((uint8_t *)efi_sys_tbl,
                                      efi_sys_tbl->Hdr.HeaderSize, 0);

    tbl_add[TBL_EFIT].start = table_addr;
    tbl_add[TBL_EFIT].size = table_size;
}

static void __init fill_efi_memory_descriptor(EFI_MEMORY_DESCRIPTOR *desc,
                                              UINT32 type,
                                              EFI_PHYSICAL_ADDRESS start,
                                              UINT64 size)
{
    desc->Type = type;
    desc->PhysicalStart = start;
    BUG_ON(size & EFI_PAGE_MASK);
    desc->NumberOfPages = EFI_SIZE_TO_PAGES(size);
    desc->Attribute = EFI_MEMORY_WB;
}

void __init acpi_create_efi_mmap_table(struct domain *d,
                                       const struct meminfo *mem,
                                       struct membank tbl_add[])
{
    EFI_MEMORY_DESCRIPTOR *desc;
    unsigned int i;
    u8 *base_ptr;

    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_MMAP);
    desc = (EFI_MEMORY_DESCRIPTOR *)base_ptr;

    for ( i = 0; i < mem->nr_banks; i++, desc++ )
        fill_efi_memory_descriptor(desc, EfiConventionalMemory,
                                   mem->bank[i].start, mem->bank[i].size);

    for ( i = 0; i < bootinfo.acpi.nr_banks; i++, desc++ )
        fill_efi_memory_descriptor(desc, EfiACPIReclaimMemory,
                                   bootinfo.acpi.bank[i].start,
                                   bootinfo.acpi.bank[i].size);

    fill_efi_memory_descriptor(desc, EfiACPIReclaimMemory,
                               d->arch.efi_acpi_gpa, d->arch.efi_acpi_len);

    tbl_add[TBL_MMAP].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_MMAP);
    tbl_add[TBL_MMAP].size = sizeof(EFI_MEMORY_DESCRIPTOR)
                             * (mem->nr_banks + bootinfo.acpi.nr_banks + 1);
}

/* Create /hypervisor/uefi node for efi properties. */
int __init acpi_make_efi_nodes(void *fdt, struct membank tbl_add[])
{
    int res;

    res = fdt_begin_node(fdt, "uefi");
    if ( res )
        return res;

    res = fdt_property_u64(fdt, "xen,uefi-system-table",
                           tbl_add[TBL_EFIT].start);
    if ( res )
        return res;

    res = fdt_property_u64(fdt, "xen,uefi-mmap-start",
                           tbl_add[TBL_MMAP].start);
    if ( res )
        return res;

    res = fdt_property_u32(fdt, "xen,uefi-mmap-size",
                           tbl_add[TBL_MMAP].size);
    if ( res )
        return res;

    res = fdt_property_u32(fdt, "xen,uefi-mmap-desc-size",
                           sizeof(EFI_MEMORY_DESCRIPTOR));
    if ( res )
        return res;

    res = fdt_property_u32(fdt, "xen,uefi-mmap-desc-ver", 1);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
