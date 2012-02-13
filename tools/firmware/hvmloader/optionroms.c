/*
 * optionroms.c: Option ROM loading support.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
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
#include "option_rom.h"
#include "util.h"
#include "pci_regs.h"

/*
 * Scan the list of Option ROMs at @roms for one which supports 
 * PCI (@vendor_id, @device_id) found at slot @devfn. If one is found,
 * copy it to @dest and return its size rounded up to a multiple 2kB. This
 * function will not copy ROMs beyond address option_rom_end.
 */
static int scan_option_rom(
    unsigned int option_rom_end,
    uint8_t devfn, uint16_t vendor_id, uint16_t device_id,
    void *roms, uint32_t dest)
{
    struct option_rom_header *rom;
    struct option_rom_pnp_header *pnph;
    struct option_rom_pci_header *pcih;
    uint8_t csum;
    int i;

    static uint32_t orom_ids[64];
    static int nr_roms;

    /* Avoid duplicate ROMs. */
    for ( i = 0; i < nr_roms; i++ )
        if ( orom_ids[i] == (vendor_id | ((uint32_t)device_id << 16)) )
            return 0;

    rom = roms;
    for ( ; ; )
    {
        /* Invalid signature means we're out of option ROMs. */
        if ( strncmp((char *)rom->signature, "\x55\xaa", 2) ||
             (rom->rom_size == 0) )
            break;

        /* Invalid checksum means we're out of option ROMs. */
        csum = 0;
        for ( i = 0; i < (rom->rom_size * 512); i++ )
            csum += ((uint8_t *)rom)[i];
        if ( csum != 0 )
            break;

        /* Check the PCI PnP header (if any) for a match. */
        pcih = (struct option_rom_pci_header *)
            ((char *)rom + rom->pci_header_offset);
        if ( (rom->pci_header_offset != 0) &&
             !strncmp((char *)pcih->signature, "PCIR", 4) &&
             (pcih->vendor_id == vendor_id) &&
             (pcih->device_id == device_id) )
            goto found;

        rom = (struct option_rom_header *)
            ((char *)rom + rom->rom_size * 512);
    }

    return 0;

 found:
    /* Find the PnP expansion header (if any). */
    pnph = ((rom->expansion_header_offset != 0)
            ? ((struct option_rom_pnp_header *)
               ((char *)rom + rom->expansion_header_offset))
            : ((struct option_rom_pnp_header *)NULL));
    while ( (pnph != NULL) && strncmp((char *)pnph->signature, "$PnP", 4) )
        pnph = ((pnph->next_header_offset != 0)
                ? ((struct option_rom_pnp_header *)
                   ((char *)rom + pnph->next_header_offset))
                : ((struct option_rom_pnp_header *)NULL));

    printf("Loading PCI Option ROM ...\n");
    if ( (pnph != NULL) && (pnph->manufacturer_name_offset != 0) )
        printf(" - Manufacturer: %s\n",
               (char *)rom + pnph->manufacturer_name_offset);
    if ( (pnph != NULL) && (pnph->product_name_offset != 0) )
        printf(" - Product name: %s\n",
               (char *)rom + pnph->product_name_offset);

    if ( (dest + rom->rom_size * 512 + 1) > option_rom_end )
    {
        printf("Option ROM size %x exceeds available space\n",
               rom->rom_size * 512);
        return 0;
    }

    orom_ids[nr_roms++] = vendor_id | ((uint32_t)device_id << 16);
    memcpy((void *)dest, rom, rom->rom_size * 512);
    *(uint8_t *)(dest + rom->rom_size * 512) = devfn;
    return round_option_rom(rom->rom_size * 512 + 1);
}

/*
 * Scan the PCI bus for the first NIC supported by etherboot, and copy
 * the corresponding rom data to *copy_rom_dest. Returns the length of the
 * selected rom, or 0 if no NIC found.
 */
int scan_etherboot_nic(unsigned int option_rom_end,
                       uint32_t copy_rom_dest,
                       void *etherboot_rom)
{
    uint16_t class, vendor_id, device_id, devfn;
    int rom_size = 0;

    for ( devfn = 0; (devfn < 256) && !rom_size; devfn++ )
    {
        class     = pci_readw(devfn, PCI_CLASS_DEVICE);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);

        /* We're only interested in NICs. */
        if ( (vendor_id != 0xffff) &&
             (device_id != 0xffff) &&
             (class == 0x0200) )
            rom_size = scan_option_rom(
                option_rom_end,
                devfn, vendor_id, device_id, etherboot_rom, copy_rom_dest);
    }

    return rom_size;
}

/*
 * Scan the PCI bus for the devices that have an option ROM, and copy
 * the corresponding rom data to rom_phys_addr.
 */
int pci_load_option_roms(unsigned int option_rom_end,
                         uint32_t rom_base_addr)
{
    uint32_t option_rom_addr, rom_phys_addr = rom_base_addr;
    uint16_t vendor_id, device_id, devfn, class;

    for ( devfn = 0; devfn < 256; devfn++ )
    {
        class     = pci_readb(devfn, PCI_CLASS_DEVICE + 1);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);

        if ( (vendor_id == 0xffff) && (device_id == 0xffff) )
            continue;

        /*
         * Currently only scan options from mass storage devices and serial
         * bus controller (Fibre Channel included).
         */
        if ( (class != 0x1) && (class != 0xc) )
            continue;

        option_rom_addr = pci_readl(devfn, PCI_ROM_ADDRESS);
        if ( !option_rom_addr )
            continue;

        /* Ensure Expansion Bar is enabled before copying */
        pci_writel(devfn, PCI_ROM_ADDRESS, option_rom_addr | 0x1);

        rom_phys_addr += scan_option_rom(
            option_rom_end,
            devfn, vendor_id, device_id,
            (void *)(option_rom_addr & ~2047), rom_phys_addr);

        /* Restore the default original value of Expansion Bar */
        pci_writel(devfn, PCI_ROM_ADDRESS, option_rom_addr);
    }

    return rom_phys_addr - rom_base_addr;
}
