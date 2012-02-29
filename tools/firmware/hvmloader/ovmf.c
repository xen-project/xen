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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "config.h"
#include "smbios_types.h"
#include "acpi/acpi2_0.h"
#include "apic_regs.h"
#include "../rombios/config.h"
#include "util.h"
#include "pci_regs.h"
#include "hypercall.h"

#include <xen/hvm/params.h>
#include <xen/hvm/ioreq.h>
#include <xen/memory.h>

#define ROM_INCLUDE_OVMF
#include "roms.inc"

#define OVMF_BEGIN              0xFFF00000ULL
#define OVMF_SIZE               0x00100000ULL
#define OVMF_MAXOFFSET          0x000FFFFFULL
#define OVMF_END                (OVMF_BEGIN + OVMF_SIZE)
#define LOWCHUNK_BEGIN          0x000F0000
#define LOWCHUNK_SIZE           0x00010000
#define LOWCHUNK_MAXOFFSET      0x0000FFFF
#define LOWCHUNK_END            (OVMF_BEGIN + OVMF_SIZE)

extern unsigned char dsdt_anycpu[];
extern int dsdt_anycpu_len;

static void ovmf_load(const struct bios_config *config)
{
    xen_pfn_t mfn;
    uint64_t addr = OVMF_BEGIN;

    /* Copy low-reset vector portion. */
    memcpy((void *) LOWCHUNK_BEGIN, (uint8_t *) config->image
           + OVMF_SIZE
           - LOWCHUNK_SIZE,
           LOWCHUNK_SIZE);

    /* Ensure we have backing page prior to moving FD. */
    while ( (addr >> PAGE_SHIFT) != (OVMF_END >> PAGE_SHIFT) )
    {
        mfn = (uint32_t) (addr >> PAGE_SHIFT);
        addr += PAGE_SIZE;
        mem_hole_populate_ram(mfn, 1);
    }

    /* Copy FD. */
    memcpy((void *) OVMF_BEGIN, config->image, OVMF_SIZE);
}

static void ovmf_acpi_build_tables(void)
{
    struct acpi_config config = {
        .dsdt_anycpu = dsdt_anycpu,
        .dsdt_anycpu_len = dsdt_anycpu_len,
        .dsdt_15cpu = NULL, 
        .dsdt_15cpu_len = 0
    };

    acpi_build_tables(&config, ACPI_PHYSICAL_ADDRESS);
}

static void ovmf_create_smbios_tables(void)
{
    hvm_write_smbios_tables(
        SMBIOS_PHYSICAL_ADDRESS,
        SMBIOS_PHYSICAL_ADDRESS + sizeof(struct smbios_entry_point),
        SMBIOS_PHYSICAL_END);
}

struct bios_config ovmf_config =  {
    .name = "OVMF",

    .image = ovmf,
    .image_size = sizeof(ovmf),

    .bios_address = 0,
    .bios_load = ovmf_load,

    .load_roms = 0,

    .bios_info_setup = NULL,
    .bios_info_finish = NULL,

    .e820_setup = NULL,

    .acpi_build_tables = ovmf_acpi_build_tables,
    .create_mp_tables = NULL,
    .create_smbios_tables = ovmf_create_smbios_tables,
    .create_pir_tables = NULL,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
