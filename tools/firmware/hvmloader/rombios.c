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
#include "apic_regs.h"
#include "pci_regs.h"
#include "util.h"
#include "hypercall.h"

#include <xen/hvm/params.h>
#include <xen/hvm/ioreq.h>
#include <xen/memory.h>

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

static void rombios_apic_setup(void)
{
    /* Set the IOAPIC ID to the static value used in the MP/ACPI tables. */
    ioapic_write(0x00, IOAPIC_ID);

    /* NMIs are delivered direct to the BSP. */
    lapic_write(APIC_SPIV, APIC_SPIV_APIC_ENABLED | 0xFF);
    lapic_write(APIC_LVT0, (APIC_MODE_EXTINT << 8) | APIC_LVT_MASKED);
    lapic_write(APIC_LVT1, APIC_MODE_NMI << 8);

    /* 8259A ExtInts are delivered through IOAPIC pin 0 (Virtual Wire Mode). */
    ioapic_write(0x10, APIC_DM_EXTINT);
    ioapic_write(0x11, SET_APIC_ID(LAPIC_ID(0)));
}

static void rombios_pci_setup(void)
{
    uint32_t base, devfn, bar_reg, bar_data, bar_sz, cmd, mmio_total = 0;
    uint16_t class, vendor_id, device_id;
    unsigned int bar, pin, link, isa_irq;

    /* Resources assignable to PCI devices via BARs. */
    struct resource {
        uint32_t base, max;
    } *resource, mem_resource, io_resource;

    /* Create a list of device BARs in descending order of size. */
    struct bars {
        uint32_t devfn, bar_reg, bar_sz;
    } *bars = (struct bars *)SCRATCH_PHYSICAL_ADDRESS;
    unsigned int i, nr_bars = 0;

    /* Program PCI-ISA bridge with appropriate link routes. */
    isa_irq = 0;
    for ( link = 0; link < 4; link++ )
    {
        do { isa_irq = (isa_irq + 1) & 15;
        } while ( !(PCI_ISA_IRQ_MASK & (1U << isa_irq)) );
        pci_writeb(PCI_ISA_DEVFN, 0x60 + link, isa_irq);
        printf("PCI-ISA link %u routed to IRQ%u\n", link, isa_irq);
    }

    /* Program ELCR to match PCI-wired IRQs. */
    outb(0x4d0, (uint8_t)(PCI_ISA_IRQ_MASK >> 0));
    outb(0x4d1, (uint8_t)(PCI_ISA_IRQ_MASK >> 8));

    /* Scan the PCI bus and map resources. */
    for ( devfn = 0; devfn < 256; devfn++ )
    {
        class     = pci_readw(devfn, PCI_CLASS_DEVICE);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);
        if ( (vendor_id == 0xffff) && (device_id == 0xffff) )
            continue;

        ASSERT((devfn != PCI_ISA_DEVFN) ||
               ((vendor_id == 0x8086) && (device_id == 0x7000)));

        switch ( class )
        {
        case 0x0300:
            /* If emulated VGA is found, preserve it as primary VGA. */
            if ( (vendor_id == 0x1234) && (device_id == 0x1111) )
                virtual_vga = VGA_std;
            else if ( (vendor_id == 0x1013) && (device_id == 0xb8) )
                virtual_vga = VGA_cirrus;
            else if ( virtual_vga == VGA_none )
                virtual_vga = VGA_pt;
            break;
        case 0x0680:
            /* PIIX4 ACPI PM. Special device with special PCI config space. */
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7113));
            pci_writew(devfn, 0x20, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0xd2, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0x22, 0x0000);
            pci_writew(devfn, 0x3c, 0x0009); /* Hardcoded IRQ9 */
            pci_writew(devfn, 0x3d, 0x0001);
            pci_writel(devfn, 0x40, ACPI_PM1A_EVT_BLK_ADDRESS_V1 | 1);
            pci_writeb(devfn, 0x80, 0x01); /* enable PM io space */
            break;
        case 0x0101:
            if ( vendor_id == 0x8086 )
            {
                /* Intel ICHs since PIIX3: enable IDE legacy mode. */
                pci_writew(devfn, 0x40, 0x8000); /* enable IDE0 */
                pci_writew(devfn, 0x42, 0x8000); /* enable IDE1 */
            }
            break;
        }

        /* Map the I/O memory and port resources. */
        for ( bar = 0; bar < 7; bar++ )
        {
            bar_reg = PCI_BASE_ADDRESS_0 + 4*bar;
            if ( bar == 6 )
                bar_reg = PCI_ROM_ADDRESS;

            bar_data = pci_readl(devfn, bar_reg);
            pci_writel(devfn, bar_reg, ~0);
            bar_sz = pci_readl(devfn, bar_reg);
            pci_writel(devfn, bar_reg, bar_data);
            if ( bar_sz == 0 )
                continue;

            bar_sz &= (((bar_data & PCI_BASE_ADDRESS_SPACE) ==
                        PCI_BASE_ADDRESS_SPACE_MEMORY) ?
                       PCI_BASE_ADDRESS_MEM_MASK :
                       (PCI_BASE_ADDRESS_IO_MASK & 0xffff));
            bar_sz &= ~(bar_sz - 1);

            for ( i = 0; i < nr_bars; i++ )
                if ( bars[i].bar_sz < bar_sz )
                    break;

            if ( i != nr_bars )
                memmove(&bars[i+1], &bars[i], (nr_bars-i) * sizeof(*bars));

            bars[i].devfn   = devfn;
            bars[i].bar_reg = bar_reg;
            bars[i].bar_sz  = bar_sz;

            if ( (bar_data & PCI_BASE_ADDRESS_SPACE) ==
                 PCI_BASE_ADDRESS_SPACE_MEMORY )
                mmio_total += bar_sz;

            nr_bars++;

            /* Skip the upper-half of the address for a 64-bit BAR. */
            if ( (bar_data & (PCI_BASE_ADDRESS_SPACE |
                              PCI_BASE_ADDRESS_MEM_TYPE_MASK)) == 
                 (PCI_BASE_ADDRESS_SPACE_MEMORY | 
                  PCI_BASE_ADDRESS_MEM_TYPE_64) )
                bar++;
        }

        /* Map the interrupt. */
        pin = pci_readb(devfn, PCI_INTERRUPT_PIN);
        if ( pin != 0 )
        {
            /* This is the barber's pole mapping used by Xen. */
            link = ((pin - 1) + (devfn >> 3)) & 3;
            isa_irq = pci_readb(PCI_ISA_DEVFN, 0x60 + link);
            pci_writeb(devfn, PCI_INTERRUPT_LINE, isa_irq);
            printf("pci dev %02x:%x INT%c->IRQ%u\n",
                   devfn>>3, devfn&7, 'A'+pin-1, isa_irq);
        }

        /* Enable bus mastering. */
        cmd = pci_readw(devfn, PCI_COMMAND);
        cmd |= PCI_COMMAND_MASTER;
        pci_writew(devfn, PCI_COMMAND, cmd);
    }

    while ( (mmio_total > (pci_mem_end - pci_mem_start)) &&
            ((pci_mem_start << 1) != 0) )
        pci_mem_start <<= 1;

    while ( (pci_mem_start >> PAGE_SHIFT) < hvm_info->low_mem_pgend )
    {
        struct xen_add_to_physmap xatp;
        if ( hvm_info->high_mem_pgend == 0 )
            hvm_info->high_mem_pgend = 1ull << (32 - PAGE_SHIFT);
        xatp.domid = DOMID_SELF;
        xatp.space = XENMAPSPACE_gmfn;
        xatp.idx   = --hvm_info->low_mem_pgend;
        xatp.gpfn  = hvm_info->high_mem_pgend++;
        if ( hypercall_memory_op(XENMEM_add_to_physmap, &xatp) != 0 )
            BUG();
    }

    mem_resource.base = pci_mem_start;
    mem_resource.max = pci_mem_end;
    io_resource.base = 0xc000;
    io_resource.max = 0x10000;

    /* Assign iomem and ioport resources in descending order of size. */
    for ( i = 0; i < nr_bars; i++ )
    {
        devfn   = bars[i].devfn;
        bar_reg = bars[i].bar_reg;
        bar_sz  = bars[i].bar_sz;

        bar_data = pci_readl(devfn, bar_reg);

        if ( (bar_data & PCI_BASE_ADDRESS_SPACE) ==
             PCI_BASE_ADDRESS_SPACE_MEMORY )
        {
            resource = &mem_resource;
            bar_data &= ~PCI_BASE_ADDRESS_MEM_MASK;
        }
        else
        {
            resource = &io_resource;
            bar_data &= ~PCI_BASE_ADDRESS_IO_MASK;
        }

        base = (resource->base + bar_sz - 1) & ~(bar_sz - 1);
        bar_data |= base;
        base += bar_sz;

        if ( (base < resource->base) || (base > resource->max) )
        {
            printf("pci dev %02x:%x bar %02x size %08x: no space for "
                   "resource!\n", devfn>>3, devfn&7, bar_reg, bar_sz);
            continue;
        }

        resource->base = base;

        pci_writel(devfn, bar_reg, bar_data);
        printf("pci dev %02x:%x bar %02x size %08x: %08x\n",
               devfn>>3, devfn&7, bar_reg, bar_sz, bar_data);

        /* Now enable the memory or I/O mapping. */
        cmd = pci_readw(devfn, PCI_COMMAND);
        if ( (bar_reg == PCI_ROM_ADDRESS) ||
             ((bar_data & PCI_BASE_ADDRESS_SPACE) ==
              PCI_BASE_ADDRESS_SPACE_MEMORY) )
            cmd |= PCI_COMMAND_MEMORY;
        else
            cmd |= PCI_COMMAND_IO;
        pci_writew(devfn, PCI_COMMAND, cmd);
    }
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

//BUILD_BUG_ON(sizeof(rombios) > (0x00100000U - ROMBIOS_PHYSICAL_ADDRESS));

struct bios_config rombios_config =  {
    .name = "ROMBIOS",

    .image = rombios,
    .image_size = sizeof(rombios),

    .bios_address = ROMBIOS_PHYSICAL_ADDRESS,

    .smbios_start = SMBIOS_PHYSICAL_ADDRESS,
    .smbios_end = SMBIOS_PHYSICAL_END,

    .optionrom_start = OPTIONROM_PHYSICAL_ADDRESS,
    .optionrom_end = OPTIONROM_PHYSICAL_END,

    .acpi_start = ACPI_PHYSICAL_ADDRESS,

    .apic_setup = rombios_apic_setup,
    .pci_setup = rombios_pci_setup,
    .smp_setup = smp_initialise,

    .bios_high_setup = rombios_highbios_setup,
    .bios_info_setup = rombios_setup_bios_info,

    .vm86_setup = rombios_init_vm86_tss,
    .e820_setup = rombios_setup_e820,

    .acpi_build_tables = acpi_build_tables,
    .create_mp_tables = rombios_create_mp_tables,
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
