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

#include "util.h"
#include "hypercall.h"
#include "config.h"
#include "pci_regs.h"
#include "option_rom.h"
#include "apic_regs.h"
#include <xen/version.h>
#include <xen/hvm/params.h>

#define ROM_INCLUDE_VGABIOS
#define ROM_INCLUDE_ETHERBOOT
#include "roms.inc"

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

unsigned long scratch_start = SCRATCH_PHYSICAL_ADDRESS;

static void init_hypercalls(void)
{
    uint32_t eax, ebx, ecx, edx;
    unsigned long i;
    char signature[13];
    xen_extraversion_t extraversion;
    uint32_t base;

    for ( base = 0x40000000; base < 0x40010000; base += 0x100 )
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

/*
 * Scan the list of Option ROMs at @roms for one which supports 
 * PCI (@vendor_id, @device_id) found at slot @devfn. If one is found,
 * copy it to @dest and return its size rounded up to a multiple 2kB. This
 * function will not copy ROMs beyond address option_rom_end.
 */
#define round_option_rom(x) (((x) + 2047) & ~2047)
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
static int scan_etherboot_nic(unsigned int option_rom_end,
                              uint32_t copy_rom_dest)
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
                devfn, vendor_id, device_id, etherboot, copy_rom_dest);
    }

    return rom_size;
}

/*
 * Scan the PCI bus for the devices that have an option ROM, and copy
 * the corresponding rom data to rom_phys_addr.
 */
static int pci_load_option_roms(unsigned int option_rom_end,
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

struct bios_info {
    const char *key;
    const struct bios_config *bios;
} bios_configs[] = {
#ifdef ENABLE_ROMBIOS
    { "rombios", &rombios_config, },
#endif
#ifdef ENABLE_SEABIOS
    { "seabios", &seabios_config, },
#endif
    { NULL, NULL }
};

static const struct bios_config *detect_bios(void)
{
    const struct bios_info *b;
    const char *bios;

    bios = xenstore_read("hvmloader/bios");
    if ( !bios )
        bios = "rombios";

    for ( b = &bios_configs[0]; b->key != NULL; b++ )
        if ( !strcmp(bios, b->key) )
            return b->bios;

    printf("Unknown BIOS %s, no ROM image found\n", bios);
    BUG();
    return NULL;
}

int main(void)
{
    const struct bios_config *bios;
    int option_rom_sz = 0, vgabios_sz = 0, etherboot_sz = 0;
    uint32_t etherboot_phys_addr = 0, option_rom_phys_addr = 0;

    /* Initialise hypercall stubs with RET, rendering them no-ops. */
    memset((void *)HYPERCALL_PHYSICAL_ADDRESS, 0xc3 /* RET */, PAGE_SIZE);

    printf("HVM Loader\n");

    init_hypercalls();

    xenbus_setup();

    bios = detect_bios();
    printf("System requested %s\n", bios->name);

    printf("CPU speed is %u MHz\n", get_cpu_mhz());

    apic_setup();
    pci_setup();

    smp_initialise();

    perform_tests();

    if ( bios->bios_info_setup )
        bios->bios_info_setup();

    if ( bios->create_smbios_tables )
    {
        printf("Writing SMBIOS tables ...\n");
        bios->create_smbios_tables();
    }

    printf("Loading %s ...\n", bios->name);
    if ( bios->bios_load )
        bios->bios_load(bios);
    else
        memcpy((void *)bios->bios_address, bios->image,
               bios->image_size);

    if ( (hvm_info->nr_vcpus > 1) || hvm_info->apic_mode )
    {
        if ( bios->create_mp_tables )
            bios->create_mp_tables();
        if ( bios->create_pir_tables )
            bios->create_pir_tables();
    }

    if ( bios->load_roms )
    {
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
        if ( etherboot_phys_addr < bios->optionrom_start )
            etherboot_phys_addr = bios->optionrom_start;
        etherboot_sz = scan_etherboot_nic(bios->optionrom_end,
                                          etherboot_phys_addr);

        option_rom_phys_addr = etherboot_phys_addr + etherboot_sz;
        option_rom_sz = pci_load_option_roms(bios->optionrom_end,
                                             option_rom_phys_addr);
    }

    if ( hvm_info->acpi_enabled )
    {
        struct xen_hvm_param p = {
            .domid = DOMID_SELF,
            .index = HVM_PARAM_ACPI_IOPORTS_LOCATION,
            .value = 1,
        };

        if ( bios->acpi_build_tables )
        {
            printf("Loading ACPI ...\n");
            bios->acpi_build_tables();
        }

        hypercall_hvm_op(HVMOP_set_param, &p);
    }

    if ( bios->vm86_setup )
        bios->vm86_setup();

    cmos_write_memory_size();

    printf("BIOS map:\n");
    if ( SCRATCH_PHYSICAL_ADDRESS != scratch_start )
        printf(" %05x-%05lx: Scratch space\n",
               SCRATCH_PHYSICAL_ADDRESS, scratch_start);
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
    printf(" %05x-%05x: Main BIOS\n",
           bios->bios_address,
           bios->bios_address + bios->image_size - 1);

    if ( bios->e820_setup )
        bios->e820_setup();

    if ( bios->bios_info_finish )
        bios->bios_info_finish();

    xenbus_shutdown();

    printf("Invoking %s ...\n", bios->name);
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
