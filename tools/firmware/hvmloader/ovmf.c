/*
 * HVM OVMF UEFI support.
 *
 * Bei Guan, gbtju85@gmail.com
 * Andrei Warkentin, andreiw@motorola.com
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
 * Copyright (c) 2011, Citrix Inc.
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
 */

#include "config.h"
#include "smbios_types.h"
#include "libacpi.h"
#include "apic_regs.h"
#include "../rombios/config.h"
#include "util.h"
#include "pci_regs.h"
#include "hypercall.h"

#include <xen/hvm/params.h>
#include <xen/hvm/ioreq.h>
#include <xen/memory.h>

#define OVMF_MAXOFFSET          0x000FFFFFULL
#define OVMF_END                0x100000000ULL
#define LOWCHUNK_BEGIN          0x000F0000
#define LOWCHUNK_SIZE           0x00010000
#define LOWCHUNK_MAXOFFSET      0x0000FFFF
#define OVMF_INFO_PHYSICAL_ADDRESS 0x00001000

#define OVMF_INFO_MAX_TABLES 4
struct ovmf_info {
    char signature[14]; /* XenHVMOVMF\0\0\0\0 */
    uint8_t length;     /* Length of this struct */
    uint8_t checksum;   /* Set such that the sum over bytes 0..length == 0 */
    /*
     * Physical address of an array of tables_nr elements.
     *
     * Each element is a 64 bit value containing the physical address
     * of a BIOS table.
     */
    uint64_t tables;
    uint32_t tables_nr;
    /*
     * Physical address of the e820 table, contains e820_nr entries.
     */
    uint64_t e820;
    uint32_t e820_nr;
} __attribute__ ((packed));

static void ovmf_setup_bios_info(void)
{
    struct ovmf_info *info = (void *)OVMF_INFO_PHYSICAL_ADDRESS;

    *info = (struct ovmf_info) {
        .signature = "XenHVMOVMF",
        .length = sizeof(*info)
    };
}

static void ovmf_finish_bios_info(void)
{
    struct ovmf_info *info = (void *)OVMF_INFO_PHYSICAL_ADDRESS;
    uint32_t i;
    uint8_t checksum;

    checksum = 0;
    for ( i = 0; i < info->length; i++ )
        checksum += ((uint8_t *)(info))[i];

    info->checksum = -checksum;
}

static void ovmf_load(const struct bios_config *config,
                      void *bios_addr, uint32_t bios_length)
{
    xen_pfn_t mfn;
    uint64_t addr = OVMF_END
        - ((bios_length + OVMF_MAXOFFSET) & ~OVMF_MAXOFFSET);
    uint64_t ovmf_end = addr + bios_length;

    ovmf_config.bios_address = addr;
    ovmf_config.image_size = bios_length;

    /* Copy low-reset vector portion. */
    memcpy((void *)LOWCHUNK_BEGIN,
           (uint8_t *)bios_addr + bios_length - LOWCHUNK_SIZE,
           LOWCHUNK_SIZE);

    /* Ensure we have backing page prior to moving FD. */
    while ( (addr >> PAGE_SHIFT) != (ovmf_end >> PAGE_SHIFT) )
    {
        mfn = (uint32_t) (addr >> PAGE_SHIFT);
        addr += PAGE_SIZE;
        mem_hole_populate_ram(mfn, 1);
    }

    /* Check that source and destination does not overlaps. */
    BUG_ON(addr + bios_length > (unsigned)bios_addr &&
           addr < (unsigned)bios_addr + bios_length);
    /* Copy FD. */
    memcpy((void *)ovmf_config.bios_address, bios_addr, bios_length);
}

static void ovmf_acpi_build_tables(void)
{
    struct acpi_config config = {
        .dsdt_anycpu = dsdt_anycpu_qemu_xen,
        .dsdt_anycpu_len = dsdt_anycpu_qemu_xen_len,
        .dsdt_15cpu = NULL, 
        .dsdt_15cpu_len = 0
    };

    hvmloader_acpi_build_tables(&config, ACPI_PHYSICAL_ADDRESS);
}

static void ovmf_create_smbios_tables(void)
{
    hvm_write_smbios_tables(
        SMBIOS_PHYSICAL_ADDRESS,
        SMBIOS_PHYSICAL_ADDRESS + sizeof(struct smbios_entry_point),
        SMBIOS_PHYSICAL_END);
}

static void ovmf_setup_e820(void)
{
    struct ovmf_info *info = (void *)OVMF_INFO_PHYSICAL_ADDRESS;
    struct e820entry *e820 = scratch_alloc(sizeof(struct e820entry)*16, 0);
    info->e820 = (uint32_t)e820;

    /* Reserve LOWCHUNK_BEGIN to 0x100000 as well, that's reset vector. */
    info->e820_nr = build_e820_table(e820, 0, LOWCHUNK_BEGIN);
    dump_e820_table(e820, info->e820_nr);
}

struct bios_config ovmf_config =  {
    .name = "OVMF",

    .bios_load = ovmf_load,

    .load_roms = 0,

    .bios_info_setup = ovmf_setup_bios_info,
    .bios_info_finish = ovmf_finish_bios_info,

    .e820_setup = ovmf_setup_e820,

    .acpi_build_tables = ovmf_acpi_build_tables,
    .create_mp_tables = NULL,
    .create_smbios_tables = ovmf_create_smbios_tables,
    .create_pir_tables = NULL,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
