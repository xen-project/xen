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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "config.h"

#include "../rombios/config.h"

#include "acpi/acpi2_0.h"
#include "pci_regs.h"
#include "util.h"
#include "hypercall.h"

#include <xen/hvm/params.h>

#define ROM_INCLUDE_ROMBIOS
#include "roms.inc"

#define ROMBIOS_BEGIN          0x000F0000
#define ROMBIOS_SIZE           0x00010000
#define ROMBIOS_MAXOFFSET      0x0000FFFF
#define ROMBIOS_END            (ROMBIOS_BEGIN + ROMBIOS_SIZE)

/*
 * Set up an empty TSS area for virtual 8086 mode to use. 
 * The only important thing is that it musn't have any bits set 
 * in the interrupt redirection bitmap, so all zeros will do.
 */
static void rombios_init_vm86_tss(void)
{
    void *tss;
    struct xen_hvm_param p;

    tss = mem_alloc(128, 128);
    memset(tss, 0, 128);
    p.domid = DOMID_SELF;
    p.index = HVM_PARAM_VM86_TSS;
    p.value = virt_to_phys(tss);
    hypercall_hvm_op(HVMOP_set_param, &p);
    printf("vm86 TSS at %08lx\n", virt_to_phys(tss));
}

static void rombios_setup_e820(void)
{
    *E820_NR = build_e820_table(E820);
    dump_e820_table(E820, *E820_NR);
}

static void rombios_setup_bios_info(uint32_t bioshigh)
{
    struct bios_info *bios_info;

    bios_info = (struct bios_info *)BIOS_INFO_PHYSICAL_ADDRESS;
    memset(bios_info, 0, sizeof(*bios_info));
    bios_info->com1_present = uart_exists(0x3f8);
    bios_info->com2_present = uart_exists(0x2f8);
    bios_info->lpt1_present = lpt_exists(0x378);
    bios_info->hpet_present = hpet_exists(ACPI_HPET_ADDRESS);
    bios_info->pci_min = pci_mem_start;
    bios_info->pci_len = pci_mem_end - pci_mem_start;
    bios_info->madt_csum_addr = madt_csum_addr;
    bios_info->madt_lapic0_addr = madt_lapic0_addr;
    bios_info->bios32_entry = bioshigh;
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
        if ( strncmp(bios_mem, "___HVMMP", 8) == 0)
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
    for (i = 0; i < ROMBIOS_MAXOFFSET; ++i)
        checksum += ((uint8_t *)(ROMBIOS_BEGIN))[i];

    *((uint8_t *)(ROMBIOS_BEGIN + ROMBIOS_MAXOFFSET)) = -checksum;
}

static void rombios_acpi_build_tables(void)
{
    acpi_build_tables(ACPI_PHYSICAL_ADDRESS);
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
    hvm_write_smbios_tables(scratch_start,
                            SMBIOS_PHYSICAL_ADDRESS,
                            SMBIOS_PHYSICAL_END);
}

//BUILD_BUG_ON(sizeof(rombios) > (0x00100000U - ROMBIOS_PHYSICAL_ADDRESS));

struct bios_config rombios_config =  {
    .name = "ROMBIOS",

    .image = rombios,
    .image_size = sizeof(rombios),

    .bios_address = ROMBIOS_PHYSICAL_ADDRESS,

    .load_roms = 1,

    .optionrom_start = OPTIONROM_PHYSICAL_ADDRESS,
    .optionrom_end = OPTIONROM_PHYSICAL_END,

    .bios_high_setup = rombios_highbios_setup,
    .bios_info_setup = rombios_setup_bios_info,

    .vm86_setup = rombios_init_vm86_tss,
    .e820_setup = rombios_setup_e820,

    .acpi_build_tables = rombios_acpi_build_tables,
    .create_mp_tables = rombios_create_mp_tables,
    .create_smbios_tables = rombios_create_smbios_tables,
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
