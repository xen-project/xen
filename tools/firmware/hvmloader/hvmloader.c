/*
 * hvmloader.c: HVM bootloader.
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

#include "roms.h"
#include "acpi/acpi2_0.h"
#include "util.h"
#include "hypercall.h"
#include "config.h"
#include "apic_regs.h"
#include "pci_regs.h"
#include "e820.h"
#include "option_rom.h"
#include <xen/version.h>
#include <xen/hvm/params.h>
#include <xen/memory.h>

asm (
    "    .text                       \n"
    "    .globl _start               \n"
    "_start:                         \n"
    /* C runtime kickoff. */
    "    cld                         \n"
    "    cli                         \n"
    "    lgdt gdt_desr               \n"
    "    mov  $"STR(SEL_DATA32)",%ax \n"
    "    mov  %ax,%ds                \n"
    "    mov  %ax,%es                \n"
    "    mov  %ax,%fs                \n"
    "    mov  %ax,%gs                \n"
    "    mov  %ax,%ss                \n"
    "    ljmp $"STR(SEL_CODE32)",$1f \n"
    "1:  movl $stack_top,%esp        \n"
    "    movl %esp,%ebp              \n"
    "    call main                   \n"
    /* Relocate real-mode trampoline to 0x0. */
    "    mov  $trampoline_start,%esi \n"
    "    xor  %edi,%edi              \n"
    "    mov  $trampoline_end,%ecx   \n"
    "    sub  %esi,%ecx              \n"
    "    rep  movsb                  \n"
    /* Load real-mode compatible segment state (base 0x0000, limit 0xffff). */
    "    mov  $"STR(SEL_DATA16)",%ax \n"
    "    mov  %ax,%ds                \n"
    "    mov  %ax,%es                \n"
    "    mov  %ax,%fs                \n"
    "    mov  %ax,%gs                \n"
    "    mov  %ax,%ss                \n"
    /* Initialise all 32-bit GPRs to zero. */
    "    xor  %eax,%eax              \n"
    "    xor  %ebx,%ebx              \n"
    "    xor  %ecx,%ecx              \n"
    "    xor  %edx,%edx              \n"
    "    xor  %esp,%esp              \n"
    "    xor  %ebp,%ebp              \n"
    "    xor  %esi,%esi              \n"
    "    xor  %edi,%edi              \n"
    /* Enter real mode, reload all segment registers and IDT. */
    "    ljmp $"STR(SEL_CODE16)",$0x0\n"
    "trampoline_start: .code16       \n"
    "    mov  %eax,%cr0              \n"
    "    ljmp $0,$1f-trampoline_start\n"
    "1:  mov  %ax,%ds                \n"
    "    mov  %ax,%es                \n"
    "    mov  %ax,%fs                \n"
    "    mov  %ax,%gs                \n"
    "    mov  %ax,%ss                \n"
    "    lidt 1f-trampoline_start    \n"
    "    ljmp $0xf000,$0xfff0        \n"
    "1:  .word 0x3ff,0,0             \n"
    "trampoline_end:   .code32       \n"
    "                                \n"
    "gdt_desr:                       \n"
    "    .word gdt_end - gdt - 1     \n"
    "    .long gdt                   \n"
    "                                \n"
    "    .align 8                    \n"
    "gdt:                            \n"
    "    .quad 0x0000000000000000    \n"
    "    .quad 0x008f9a000000ffff    \n" /* Ring 0 16b code, base 0 limit 4G */
    "    .quad 0x008f92000000ffff    \n" /* Ring 0 16b data, base 0 limit 4G */
    "    .quad 0x00cf9a000000ffff    \n" /* Ring 0 32b code, base 0 limit 4G */
    "    .quad 0x00cf92000000ffff    \n" /* Ring 0 32b data, base 0 limit 4G */
    "    .quad 0x00af9a000000ffff    \n" /* Ring 0 64b code */
    "gdt_end:                        \n"
    "                                \n"
    "    .bss                        \n"
    "    .align    8                 \n"
    "stack:                          \n"
    "    .skip    0x4000             \n"
    "stack_top:                      \n"
    "    .text                       \n"
    );

unsigned long pci_mem_start = PCI_MEM_START;
unsigned long pci_mem_end = PCI_MEM_END;

static enum { VGA_none, VGA_std, VGA_cirrus, VGA_pt } virtual_vga = VGA_none;

static void init_hypercalls(void)
{
    uint32_t eax, ebx, ecx, edx;
    unsigned long i;
    char signature[13];
    xen_extraversion_t extraversion;
    uint32_t base;

    for ( base = 0x40000000; base < 0x40001000; base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx);

        *(uint32_t *)(signature + 0) = ebx;
        *(uint32_t *)(signature + 4) = ecx;
        *(uint32_t *)(signature + 8) = edx;
        signature[12] = '\0';

        if ( !strcmp("XenVMMXenVMM", signature) )
            break;
    }

    BUG_ON(strcmp("XenVMMXenVMM", signature) || ((eax - base) < 2));

    /* Fill in hypercall transfer pages. */
    cpuid(base + 2, &eax, &ebx, &ecx, &edx);
    for ( i = 0; i < eax; i++ )
        wrmsr(ebx, HYPERCALL_PHYSICAL_ADDRESS + (i << 12) + i);

    /* Print version information. */
    cpuid(base + 1, &eax, &ebx, &ecx, &edx);
    hypercall_xen_version(XENVER_extraversion, extraversion);
    printf("Detected Xen v%u.%u%s\n", eax >> 16, eax & 0xffff, extraversion);
}

static void apic_setup(void)
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

static void pci_setup(void)
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
    for ( devfn = 0; devfn < 128; devfn++ )
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
            if ( (vendor_id == 0x1234) && (device_id == 0x1111) )
                virtual_vga = VGA_std;
            else if ( (vendor_id == 0x1013) && (device_id == 0xb8) )
                virtual_vga = VGA_cirrus;
            else
                virtual_vga = VGA_pt;
            break;
        case 0x0680:
            /* PIIX4 ACPI PM. Special device with special PCI config space. */
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7113));
            pci_writew(devfn, 0x20, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0x22, 0x0000);
            pci_writew(devfn, 0x3c, 0x0009); /* Hardcoded IRQ9 */
            pci_writew(devfn, 0x3d, 0x0001);
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
 * Scan the list of Option ROMs at @roms for one which supports 
 * PCI (@vendor_id, @device_id) found at slot @devfn. If one is found,
 * copy it to @dest and return its size rounded up to a multiple 2kB. This
 * function will not copy ROMs beyond address OPTIONROM_PHYSICAL_END.
 */
#define round_option_rom(x) (((x) + 2047) & ~2047)
static int scan_option_rom(
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

    if ( (dest + rom->rom_size * 512 + 1) > OPTIONROM_PHYSICAL_END )
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
static int scan_etherboot_nic(uint32_t copy_rom_dest)
{
    uint8_t devfn;
    uint16_t class, vendor_id, device_id;
    int rom_size = 0;

    for ( devfn = 0; (devfn < 128) && !rom_size; devfn++ )
    {
        class     = pci_readw(devfn, PCI_CLASS_DEVICE);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);

        /* We're only interested in NICs. */
        if ( (vendor_id != 0xffff) &&
             (device_id != 0xffff) &&
             (class == 0x0200) )
            rom_size = scan_option_rom(
                devfn, vendor_id, device_id, etherboot, copy_rom_dest);
    }

    return rom_size;
}

/*
 * Scan the PCI bus for the devices that have an option ROM, and copy
 * the corresponding rom data to rom_phys_addr.
 */
static int pci_load_option_roms(uint32_t rom_base_addr)
{
    uint32_t option_rom_addr, rom_phys_addr = rom_base_addr;
    uint16_t vendor_id, device_id;
    uint8_t devfn, class;

    for ( devfn = 0; devfn < 128; devfn++ )
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
            devfn, vendor_id, device_id,
            (void *)(option_rom_addr & ~2047), rom_phys_addr);

        /* Restore the default original value of Expansion Bar */
        pci_writel(devfn, PCI_ROM_ADDRESS, option_rom_addr);
    }

    return rom_phys_addr - rom_base_addr;
}

/* Replace possibly erroneous memory-size CMOS fields with correct values. */
static void cmos_write_memory_size(void)
{
    uint32_t base_mem = 640, ext_mem, alt_mem;

    alt_mem = ext_mem = hvm_info->low_mem_pgend << PAGE_SHIFT;
    ext_mem = (ext_mem > 0x0100000) ? (ext_mem - 0x0100000) >> 10 : 0;
    if ( ext_mem > 0xffff )
        ext_mem = 0xffff;
    alt_mem = (alt_mem > 0x1000000) ? (alt_mem - 0x1000000) >> 16 : 0;

    /* All BIOSes: conventional memory (CMOS *always* reports 640kB). */
    cmos_outb(0x15, (uint8_t)(base_mem >> 0));
    cmos_outb(0x16, (uint8_t)(base_mem >> 8));

    /* All BIOSes: extended memory (1kB chunks above 1MB). */
    cmos_outb(0x17, (uint8_t)( ext_mem >> 0));
    cmos_outb(0x18, (uint8_t)( ext_mem >> 8));
    cmos_outb(0x30, (uint8_t)( ext_mem >> 0));
    cmos_outb(0x31, (uint8_t)( ext_mem >> 8));

    /* Some BIOSes: alternative extended memory (64kB chunks above 16MB). */
    cmos_outb(0x34, (uint8_t)( alt_mem >> 0));
    cmos_outb(0x35, (uint8_t)( alt_mem >> 8));
}

/*
 * Set up an empty TSS area for virtual 8086 mode to use. 
 * The only important thing is that it musn't have any bits set 
 * in the interrupt redirection bitmap, so all zeros will do.
 */
static void init_vm86_tss(void)
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

/* Create an E820 table based on memory parameters provided in hvm_info. */
static void build_e820_table(void)
{
    struct e820entry *e820 = E820;
    unsigned int nr = 0;

    /* 0x0-0x9FC00: Ordinary RAM. */
    e820[nr].addr = 0x0;
    e820[nr].size = 0x9FC00;
    e820[nr].type = E820_RAM;
    nr++;

    /* 0x9FC00-0xA0000: Extended BIOS Data Area (EBDA). */
    e820[nr].addr = 0x9FC00;
    e820[nr].size = 0x400;
    e820[nr].type = E820_RESERVED;
    nr++;

    /*
     * Following regions are standard regions of the PC memory map.
     * They are not covered by e820 regions. OSes will not use as RAM.
     * 0xA0000-0xC0000: VGA memory-mapped I/O. Not covered by E820.
     * 0xC0000-0xE0000: 16-bit devices, expansion ROMs (inc. vgabios).
     * TODO: free pages which turn out to be unused.
     */

    /*
     * 0xE0000-0x0F0000: PC-specific area. We place various tables here.
     * 0xF0000-0x100000: System BIOS.
     * TODO: free pages which turn out to be unused.
     */
    e820[nr].addr = 0xE0000;
    e820[nr].size = 0x20000;
    e820[nr].type = E820_RESERVED;
    nr++;

    /* Low RAM goes here. Reserve space for special pages. */
    BUG_ON((hvm_info->low_mem_pgend << PAGE_SHIFT) < (2u << 20));
    e820[nr].addr = 0x100000;
    e820[nr].size = (hvm_info->low_mem_pgend << PAGE_SHIFT) - e820[nr].addr;
    e820[nr].type = E820_RAM;
    nr++;

    /*
     * Explicitly reserve space for special pages.
     * This space starts at RESERVED_MEMBASE an extends to cover various
     * fixed hardware mappings (e.g., LAPIC, IOAPIC, default SVGA framebuffer).
     */
    e820[nr].addr = RESERVED_MEMBASE;
    e820[nr].size = (uint32_t)-e820[nr].addr;
    e820[nr].type = E820_RESERVED;
    nr++;

    if ( hvm_info->high_mem_pgend )
    {
        e820[nr].addr = ((uint64_t)1 << 32);
        e820[nr].size =
            ((uint64_t)hvm_info->high_mem_pgend << PAGE_SHIFT) - e820[nr].addr;
        e820[nr].type = E820_RAM;
        nr++;
    }

    *E820_NR = nr;
}

int main(void)
{
    int option_rom_sz = 0, vgabios_sz = 0, etherboot_sz = 0;
    int rombios_sz, smbios_sz;
    uint32_t etherboot_phys_addr, option_rom_phys_addr, bios32_addr;
    struct bios_info *bios_info;

    printf("HVM Loader\n");

    init_hypercalls();

    printf("CPU speed is %u MHz\n", get_cpu_mhz());

    apic_setup();
    pci_setup();

    smp_initialise();

    perform_tests();

    printf("Writing SMBIOS tables ...\n");
    smbios_sz = hvm_write_smbios_tables();

    printf("Loading ROMBIOS ...\n");
    rombios_sz = sizeof(rombios);
    if ( rombios_sz > 0x10000 )
        rombios_sz = 0x10000;
    memcpy((void *)ROMBIOS_PHYSICAL_ADDRESS, rombios, rombios_sz);
    bios32_addr = highbios_setup();

    if ( (hvm_info->nr_vcpus > 1) || hvm_info->apic_mode )
        create_mp_tables();

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
        vgabios_sz =
            round_option_rom((*(uint8_t *)(VGABIOS_PHYSICAL_ADDRESS+2)) * 512);
        break;
    default:
        printf("No emulated VGA adaptor ...\n");
        break;
    }

    etherboot_phys_addr = VGABIOS_PHYSICAL_ADDRESS + vgabios_sz;
    if ( etherboot_phys_addr < OPTIONROM_PHYSICAL_ADDRESS )
        etherboot_phys_addr = OPTIONROM_PHYSICAL_ADDRESS;
    etherboot_sz = scan_etherboot_nic(etherboot_phys_addr);

    option_rom_phys_addr = etherboot_phys_addr + etherboot_sz;
    option_rom_sz = pci_load_option_roms(option_rom_phys_addr);

    if ( hvm_info->acpi_enabled )
    {
        printf("Loading ACPI ...\n");
        acpi_build_tables();
    }

    init_vm86_tss();

    cmos_write_memory_size();

    printf("BIOS map:\n");
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
    if ( smbios_sz )
        printf(" %05x-%05x: SMBIOS tables\n",
               SMBIOS_PHYSICAL_ADDRESS,
               SMBIOS_PHYSICAL_ADDRESS + smbios_sz - 1);
    if ( rombios_sz )
        printf(" %05x-%05x: Main BIOS\n",
               ROMBIOS_PHYSICAL_ADDRESS,
               ROMBIOS_PHYSICAL_ADDRESS + rombios_sz - 1);

    build_e820_table();

    bios_info = (struct bios_info *)BIOS_INFO_PHYSICAL_ADDRESS;
    memset(bios_info, 0, sizeof(*bios_info));
    bios_info->com1_present = uart_exists(0x3f8);
    bios_info->com2_present = uart_exists(0x2f8);
    bios_info->hpet_present = hpet_exists(ACPI_HPET_ADDRESS);
    bios_info->pci_min = pci_mem_start;
    bios_info->pci_len = pci_mem_end - pci_mem_start;
    bios_info->bios32_entry = bios32_addr;

    printf("Invoking ROMBIOS ...\n");
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
