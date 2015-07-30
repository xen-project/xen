/*
 * HVM ROMBIOS support.
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

#include "../rombios/config.h"

#include "smbios_types.h"
#include "acpi/acpi2_0.h"
#include "pci_regs.h"
#include "util.h"
#include "hypercall.h"
#include "option_rom.h"

#include <xen/hvm/params.h>

#define ROM_INCLUDE_ROMBIOS
#define ROM_INCLUDE_VGABIOS
#define ROM_INCLUDE_ETHERBOOT
#include "roms.inc"

#define ROMBIOS_BEGIN          0x000F0000
#define ROMBIOS_SIZE           0x00010000
#define ROMBIOS_MAXOFFSET      0x0000FFFF
#define ROMBIOS_END            (ROMBIOS_BEGIN + ROMBIOS_SIZE)

extern unsigned char dsdt_anycpu[], dsdt_15cpu[];
extern int dsdt_anycpu_len, dsdt_15cpu_len;

static void rombios_setup_e820(void)
{
    /*
     * 0x9E000-0x09F000: Stack.
     * 0x9FC00-0x0A0000: Extended BIOS Data Area (EBDA).
     * ...
     * 0xE0000-0x0F0000: PC-specific area. We place various tables here.
     * 0xF0000-0x100000: System BIOS.
     */
    *E820_NR = build_e820_table(E820, 0x9E000, 0xE0000);
    dump_e820_table(E820, *E820_NR);
}

static void rombios_setup_bios_info(void)
{
    struct rombios_info *info;

    info = (struct rombios_info *)BIOS_INFO_PHYSICAL_ADDRESS;
    memset(info, 0, sizeof(*info));
}

static void rombios_load_roms(void)
{
    int option_rom_sz = 0, vgabios_sz = 0, etherboot_sz = 0;
    uint32_t etherboot_phys_addr = 0, option_rom_phys_addr = 0;

    switch ( virtual_vga )
    {
    case VGA_cirrus:
        printf("Loading Cirrus VGABIOS ...\n");
        memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
               vgabios_cirrusvga, sizeof(vgabios_cirrusvga));
        vgabios_sz = round_option_rom(sizeof(vgabios_cirrusvga));
        break;
    case VGA_std:
        printf("Loading Standard VGABIOS ...\n");
        memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
               vgabios_stdvga, sizeof(vgabios_stdvga));
        vgabios_sz = round_option_rom(sizeof(vgabios_stdvga));
        break;
    case VGA_pt:
        printf("Loading VGABIOS of passthroughed gfx ...\n");
        vgabios_sz = round_option_rom(
            (*(uint8_t *)(VGABIOS_PHYSICAL_ADDRESS+2)) * 512);
        break;
    default:
        printf("No emulated VGA adaptor ...\n");
        break;
    }

    etherboot_phys_addr = VGABIOS_PHYSICAL_ADDRESS + vgabios_sz;
    if ( etherboot_phys_addr < OPTIONROM_PHYSICAL_ADDRESS )
        etherboot_phys_addr = OPTIONROM_PHYSICAL_ADDRESS;
    etherboot_sz = scan_etherboot_nic(OPTIONROM_PHYSICAL_END,
                                      etherboot_phys_addr,
                                      etherboot);

    option_rom_phys_addr = etherboot_phys_addr + etherboot_sz;
    option_rom_sz = pci_load_option_roms(OPTIONROM_PHYSICAL_END,
                                         option_rom_phys_addr);

    printf("Option ROMs:\n");
    if ( vgabios_sz )
        printf(" %05x-%05x: VGA BIOS\n",
               VGABIOS_PHYSICAL_ADDRESS,
               VGABIOS_PHYSICAL_ADDRESS + vgabios_sz - 1);
    if ( etherboot_sz )
        printf(" %05x-%05x: Etherboot ROM\n",
               etherboot_phys_addr,
               etherboot_phys_addr + etherboot_sz - 1);
    if ( option_rom_sz )
        printf(" %05x-%05x: PCI Option ROMs\n",
               option_rom_phys_addr,
               option_rom_phys_addr + option_rom_sz - 1);
}

static void rombios_load(const struct bios_config *config)
{
    uint32_t bioshigh;
    struct rombios_info *info;

    BUILD_BUG_ON(sizeof(rombios) > 0x100000 - ROMBIOS_PHYSICAL_ADDRESS);

    memcpy((void *)config->bios_address, config->image,
           config->image_size);

    bioshigh = rombios_highbios_setup();

    info = (struct rombios_info *)BIOS_INFO_PHYSICAL_ADDRESS;
    info->bios32_entry = bioshigh;
}

/*
 * find_mp_table_start - searchs through BIOS memory for '___HVMMP' signature
 *
 * The '___HVMMP' signature is created by the ROMBIOS and designates a chunk
 * of space inside the ROMBIOS that is safe for us to write our MP table info
 */
static void *get_mp_table_start(void)
{
    char *bios_mem;

    for ( bios_mem = (char *)ROMBIOS_BEGIN;
          bios_mem != (char *)ROMBIOS_END;
          bios_mem++ )
    {
        if ( strncmp(bios_mem, "___HVMMP", 8) == 0 )
            return bios_mem;
    }

    return NULL;
}

/* recalculate the new ROMBIOS checksum after adding MP tables */
static void reset_bios_checksum(void)
{
    uint32_t i;
    uint8_t checksum;

    checksum = 0;
    for ( i = 0; i < ROMBIOS_MAXOFFSET; i++ )
        checksum += ((uint8_t *)(ROMBIOS_BEGIN))[i];

    *((uint8_t *)(ROMBIOS_BEGIN + ROMBIOS_MAXOFFSET)) = -checksum;
}

static void rombios_acpi_build_tables(void)
{
    struct acpi_config config = {
        .dsdt_anycpu = dsdt_anycpu,
        .dsdt_anycpu_len = dsdt_anycpu_len,
        .dsdt_15cpu = dsdt_15cpu,
        .dsdt_15cpu_len = dsdt_15cpu_len,
    };

    acpi_build_tables(&config, ACPI_PHYSICAL_ADDRESS);
}

static void rombios_create_mp_tables(void)
{
    /* Find the 'safe' place in ROMBIOS for the MP tables. */
    void *table = get_mp_table_start();

    if ( table == NULL )
    {
        printf("Couldn't find start point for MP tables\n");
        return;
    }

    create_mp_tables(table);

    reset_bios_checksum();
}

static void rombios_create_smbios_tables(void)
{
    hvm_write_smbios_tables(
        SMBIOS_PHYSICAL_ADDRESS,
        SMBIOS_PHYSICAL_ADDRESS + sizeof(struct smbios_entry_point),
        SMBIOS_PHYSICAL_END);
}

struct bios_config rombios_config =  {
    .name = "ROMBIOS",

    .image = rombios,
    .image_size = sizeof(rombios),

    .bios_address = ROMBIOS_PHYSICAL_ADDRESS,

    .load_roms = rombios_load_roms,

    .bios_load = rombios_load,

    .bios_info_setup = rombios_setup_bios_info,
    .bios_info_finish = NULL,

    .e820_setup = rombios_setup_e820,

    .acpi_build_tables = rombios_acpi_build_tables,
    .create_mp_tables = rombios_create_mp_tables,
    .create_smbios_tables = rombios_create_smbios_tables,
    .create_pir_tables = NULL, /* embedded in ROMBIOS */
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
