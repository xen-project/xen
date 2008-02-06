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
#include "hypercall.h"
#include "util.h"
#include "config.h"
#include "apic_regs.h"
#include "pci_regs.h"
#include "e820.h"
#include <xen/version.h>
#include <xen/hvm/params.h>

asm(
    "    .text                       \n"
    "    .globl _start               \n"
    "_start:                         \n"
    /* C runtime kickoff. */
    "    cld                         \n"
    "    cli                         \n"
    "    movl $stack_top,%esp        \n"
    "    movl %esp,%ebp              \n"
    "    call main                   \n"
    /* Relocate real-mode trampoline to 0x0. */
    "    mov  $trampoline_start,%esi \n"
    "    xor  %edi,%edi              \n"
    "    mov  $trampoline_end,%ecx   \n"
    "    sub  %esi,%ecx              \n"
    "    rep  movsb                  \n"
    /* Load real-mode compatible segment state (base 0x0000, limit 0xffff). */
    "    lgdt gdt_desr               \n"
    "    mov  $0x0010,%ax            \n"
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
    "    ljmp $0x8,$0x0              \n"
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
    "    .quad 0x00009a000000ffff    \n" /* Ring 0 code, base 0 limit 0xffff */
    "    .quad 0x000092000000ffff    \n" /* Ring 0 data, base 0 limit 0xffff */
    "gdt_end:                        \n"
    "                                \n"
    "    .bss                        \n"
    "    .align    8                 \n"
    "stack:                          \n"
    "    .skip    0x4000             \n"
    "stack_top:                      \n"
    );

void create_mp_tables(void);
int hvm_write_smbios_tables(void);

static int
cirrus_check(void)
{
    outw(0x3C4, 0x9206);
    return inb(0x3C5) == 0x12;
}

static int
check_amd(void)
{
    char id[12];

    __asm__ __volatile__ (
        "cpuid" 
        : "=b" (*(int *)(&id[0])),
        "=c" (*(int *)(&id[8])),
        "=d" (*(int *)(&id[4]))
        : "a" (0) );
    return __builtin_memcmp(id, "AuthenticAMD", 12) == 0;
}

static void
wrmsr(uint32_t idx, uint64_t v)
{
    __asm__ __volatile__ (
        "wrmsr"
        : : "c" (idx), "a" ((uint32_t)v), "d" ((uint32_t)(v>>32)) );
}

static void
init_hypercalls(void)
{
    uint32_t eax, ebx, ecx, edx;
    unsigned long i;
    char signature[13];
    xen_extraversion_t extraversion;

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);

    *(uint32_t *)(signature + 0) = ebx;
    *(uint32_t *)(signature + 4) = ecx;
    *(uint32_t *)(signature + 8) = edx;
    signature[12] = '\0';

    if ( strcmp("XenVMMXenVMM", signature) || (eax < 0x40000002) )
    {
        printf("FATAL: Xen hypervisor not detected\n");
        __asm__ __volatile__( "ud2" );
    }

    /* Fill in hypercall transfer pages. */
    cpuid(0x40000002, &eax, &ebx, &ecx, &edx);
    for ( i = 0; i < eax; i++ )
        wrmsr(ebx, HYPERCALL_PHYSICAL_ADDRESS + (i << 12) + i);

    /* Print version information. */
    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);
    hypercall_xen_version(XENVER_extraversion, extraversion);
    printf("Detected Xen v%u.%u%s\n", eax >> 16, eax & 0xffff, extraversion);
}

static void apic_setup(void)
{
    /* Set the IOAPIC ID to tha static value used in the MP/ACPI tables. */
    ioapic_write(0x00, IOAPIC_ID);

    /* Set up Virtual Wire mode. */
    lapic_write(APIC_SPIV, APIC_SPIV_APIC_ENABLED | 0xFF);
    lapic_write(APIC_LVT0, APIC_MODE_EXTINT << 8);
    lapic_write(APIC_LVT1, APIC_MODE_NMI    << 8);
}

static void pci_setup(void)
{
    uint32_t base, devfn, bar_reg, bar_data, bar_sz, cmd;
    uint16_t class, vendor_id, device_id;
    unsigned int bar, pin, link, isa_irq;

    /* Resources assignable to PCI devices via BARs. */
    struct resource {
        uint32_t base, max;
    } *resource;
    struct resource mem_resource = { 0xf0000000, 0xfc000000 };
    struct resource io_resource  = { 0xc000, 0x10000 };

    /* Create a list of device BARs in descending order of size. */
    struct bars {
        uint32_t devfn, bar_reg, bar_sz;
    } *bars = (struct bars *)0xc0000;
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
        case 0x0680:
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7113));
            /*
             * PIIX4 ACPI PM. Special device with special PCI config space.
             * No ordinary BARs.
             */
            pci_writew(devfn, 0x20, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0x22, 0x0000);
            pci_writew(devfn, 0x3c, 0x0009); /* Hardcoded IRQ9 */
            pci_writew(devfn, 0x3d, 0x0001);
            break;
        case 0x0101:
            /* PIIX3 IDE */
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7010));
            pci_writew(devfn, 0x40, 0x8000); /* enable IDE0 */
            pci_writew(devfn, 0x42, 0x8000); /* enable IDE1 */
            /* fall through */
        default:
            /* Default memory mappings. */
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

                nr_bars++;
            }
            break;
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
    }

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

static int must_load_extboot(void)
{
    return (inb(0x404) == 1);
}

/*
 * Scan the PCI bus for the first NIC supported by etherboot, and copy
 * the corresponding rom data to *copy_rom_dest. Returns the length of the
 * selected rom, or 0 if no NIC found.
 */
static int scan_etherboot_nic(void *copy_rom_dest)
{
    static struct etherboots_table_entry {
        char *name;
        void *etherboot_rom;
        int etherboot_sz;
        uint16_t vendor, device;
    } etherboots_table[] = {
#define ETHERBOOT_ROM(name, vendor, device) \
  { #name, etherboot_##name, sizeof(etherboot_##name), vendor, device },
        ETHERBOOT_ROM_LIST
        { 0 }
    };

    uint32_t devfn;
    uint16_t class, vendor_id, device_id;
    struct etherboots_table_entry *eb;

    for ( devfn = 0; devfn < 128; devfn++ )
    {
        class     = pci_readw(devfn, PCI_CLASS_DEVICE);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);

        if ( (vendor_id == 0xffff) && (device_id == 0xffff) )
            continue;

        if ( class != 0x0200 ) /* Not a NIC */
            continue;

        for ( eb = etherboots_table; eb->name; eb++ )
            if (eb->vendor == vendor_id &&
                eb->device == device_id)
                goto found;
    }

    return 0;

 found:
    printf("Loading %s Etherboot PXE ROM ...\n", eb->name);
    memcpy(copy_rom_dest, eb->etherboot_rom, eb->etherboot_sz);
    return eb->etherboot_sz;
}

/* Replace possibly erroneous memory-size CMOS fields with correct values. */
static void cmos_write_memory_size(void)
{
    struct e820entry *map = HVM_E820;
    int i, nr = *HVM_E820_NR;
    uint32_t base_mem = 640, ext_mem = 0, alt_mem = 0;

    for ( i = 0; i < nr; i++ )
        if ( (map[i].addr >= 0x100000) && (map[i].type == E820_RAM) )
            break;

    if ( i != nr )
    {
        alt_mem = ext_mem = map[i].addr + map[i].size;
        ext_mem = (ext_mem > 0x0100000) ? (ext_mem - 0x0100000) >> 10 : 0;
        if ( ext_mem > 0xffff )
            ext_mem = 0xffff;
        alt_mem = (alt_mem > 0x1000000) ? (alt_mem - 0x1000000) >> 16 : 0;
    }

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

int main(void)
{
    int acpi_sz = 0, vgabios_sz = 0, etherboot_sz = 0, rombios_sz, smbios_sz;
    int extboot_sz = 0;

    printf("HVM Loader\n");

    init_hypercalls();

    printf("Writing SMBIOS tables ...\n");
    smbios_sz = hvm_write_smbios_tables();

    printf("Loading ROMBIOS ...\n");
    rombios_sz = sizeof(rombios);
    if ( rombios_sz > 0x10000 )
        rombios_sz = 0x10000;
    memcpy((void *)ROMBIOS_PHYSICAL_ADDRESS, rombios, rombios_sz);
    highbios_setup();

    apic_setup();
    pci_setup();

    if ( (get_vcpu_nr() > 1) || get_apic_mode() )
        create_mp_tables();

    if ( cirrus_check() )
    {
        printf("Loading Cirrus VGABIOS ...\n");
        memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
               vgabios_cirrusvga, sizeof(vgabios_cirrusvga));
        vgabios_sz = sizeof(vgabios_cirrusvga);
    }
    else
    {
        printf("Loading Standard VGABIOS ...\n");
        memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
               vgabios_stdvga, sizeof(vgabios_stdvga));
        vgabios_sz = sizeof(vgabios_stdvga);
    }

    etherboot_sz = scan_etherboot_nic((void*)ETHERBOOT_PHYSICAL_ADDRESS);

    if ( must_load_extboot() )
    {
        printf("Loading EXTBOOT ...\n");
        memcpy((void *)EXTBOOT_PHYSICAL_ADDRESS,
               extboot, sizeof(extboot));
        extboot_sz = sizeof(extboot);
    }

    if ( get_acpi_enabled() )
    {
        printf("Loading ACPI ...\n");
        acpi_sz = acpi_build_tables((uint8_t *)ACPI_PHYSICAL_ADDRESS);
        ASSERT((ACPI_PHYSICAL_ADDRESS + acpi_sz) <= 0xF0000);
    }

    cmos_write_memory_size();

    printf("BIOS map:\n");
    if ( vgabios_sz )
        printf(" %05x-%05x: VGA BIOS\n",
               VGABIOS_PHYSICAL_ADDRESS,
               VGABIOS_PHYSICAL_ADDRESS + vgabios_sz - 1);
    if ( etherboot_sz )
        printf(" %05x-%05x: Etherboot ROM\n",
               ETHERBOOT_PHYSICAL_ADDRESS,
               ETHERBOOT_PHYSICAL_ADDRESS + etherboot_sz - 1);
    if ( extboot_sz )
        printf(" %05x-%05x: Extboot ROM\n",
               EXTBOOT_PHYSICAL_ADDRESS,
               EXTBOOT_PHYSICAL_ADDRESS + extboot_sz - 1);
    if ( smbios_sz )
        printf(" %05x-%05x: SMBIOS tables\n",
               SMBIOS_PHYSICAL_ADDRESS,
               SMBIOS_PHYSICAL_ADDRESS + smbios_sz - 1);
    if ( acpi_sz )
        printf(" %05x-%05x: ACPI tables\n",
               ACPI_PHYSICAL_ADDRESS,
               ACPI_PHYSICAL_ADDRESS + acpi_sz - 1);
    if ( rombios_sz )
        printf(" %05x-%05x: Main BIOS\n",
               ROMBIOS_PHYSICAL_ADDRESS,
               ROMBIOS_PHYSICAL_ADDRESS + rombios_sz - 1);

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
