/*
 * HVM SeaBIOS support.
 *
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
#include "config-seabios.h"

#include "util.h"

#include "smbios_types.h"

#include <acpi2_0.h>
#include <libacpi.h>

struct seabios_info {
    char signature[14]; /* XenHVMSeaBIOS\0 */
    uint8_t length;     /* Length of this struct */
    uint8_t checksum;   /* Set such that the sum over bytes 0..length == 0 */
    /*
     * Physical address of an array of tables_nr elements.
     *
     * Each element is a 32 bit value contianing the physical address
     * of a BIOS table.
     */
    uint32_t tables;
    uint32_t tables_nr;
    /*
     * Physical address of the e820 table, contains e820_nr entries.
     */
    uint32_t e820;
    uint32_t e820_nr;
} __attribute__ ((packed));

#define MAX_TABLES 4

static void seabios_setup_bios_info(void)
{
    struct seabios_info *info = (void *)BIOS_INFO_PHYSICAL_ADDRESS;

    *info = (struct seabios_info) {
        .signature = "XenHVMSeaBIOS",
        .length = sizeof(*info)
    };

    info->tables = (uint32_t)scratch_alloc(MAX_TABLES*sizeof(uint32_t), 0);
}

static void seabios_finish_bios_info(void)
{
    struct seabios_info *info = (void *)BIOS_INFO_PHYSICAL_ADDRESS;
    uint32_t i;
    uint8_t checksum;

    checksum = 0;
    for ( i = 0; i < info->length; i++ )
        checksum += ((uint8_t *)(info))[i];

    info->checksum = -checksum;
}

static void add_table(uint32_t t)
{
    struct seabios_info *info = (void *)BIOS_INFO_PHYSICAL_ADDRESS;
    uint32_t *ts = (uint32_t *)info->tables;

    ASSERT(info->tables_nr < MAX_TABLES);

    ts[info->tables_nr] = t;
    info->tables_nr++;
}

static void seabios_acpi_build_tables(void)
{
    uint32_t rsdp = (uint32_t)scratch_alloc(sizeof(struct acpi_20_rsdp), 0);
    struct acpi_config config = {
        .dsdt_anycpu = dsdt_anycpu_qemu_xen,
        .dsdt_anycpu_len = dsdt_anycpu_qemu_xen_len,
        .dsdt_15cpu = NULL,
        .dsdt_15cpu_len = 0,
    };

    hvmloader_acpi_build_tables(&config, rsdp);
    add_table(rsdp);
}

static void seabios_create_mp_tables(void)
{
    add_table(create_mp_tables(NULL));
}

static void seabios_create_smbios_tables(void)
{
    uint32_t ep = (uint32_t)scratch_alloc(sizeof(struct smbios_entry_point), 0);
    hvm_write_smbios_tables(ep, 0UL, 0UL);
    add_table(ep);
}

static void seabios_create_pir_tables(void)
{
    add_table(create_pir_tables());
}

static void seabios_setup_e820(void)
{
    struct seabios_info *info = (void *)BIOS_INFO_PHYSICAL_ADDRESS;
    struct e820entry *e820 = scratch_alloc(sizeof(struct e820entry)*16, 0);
    info->e820 = (uint32_t)e820;

    /* Upper boundary already checked by seabios_load(). */
    BUG_ON(seabios_config.bios_address < 0x000c0000);
    /* SeaBIOS reserves memory in e820 as necessary so no low reservation. */
    info->e820_nr = build_e820_table(e820, 0, seabios_config.bios_address);
    dump_e820_table(e820, info->e820_nr);
}

static void seabios_load(const struct bios_config *bios,
                         void *bios_addr, uint32_t bios_length)
{
    unsigned int bios_dest = 0x100000 - bios_length;

    BUG_ON(bios_dest + bios_length > HVMLOADER_PHYSICAL_ADDRESS);
    memcpy((void *)bios_dest, bios_addr, bios_length);
    seabios_config.bios_address = bios_dest;
    seabios_config.image_size = bios_length;
}

struct bios_config seabios_config = {
    .name = "SeaBIOS",

    .load_roms = NULL,

    .bios_load = seabios_load,

    .bios_info_setup = seabios_setup_bios_info,
    .bios_info_finish = seabios_finish_bios_info,

    .e820_setup = seabios_setup_e820,

    .acpi_build_tables = seabios_acpi_build_tables,
    .create_mp_tables = seabios_create_mp_tables,
    .create_smbios_tables = seabios_create_smbios_tables,
    .create_pir_tables = seabios_create_pir_tables,
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
