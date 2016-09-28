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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "util.h"
#include "hypercall.h"
#include "config.h"
#include "pci_regs.h"
#include "apic_regs.h"
#include "vnuma.h"
#include <acpi2_0.h>
#include <xen/version.h>
#include <xen/hvm/params.h>
#include <xen/arch-x86/hvm/start_info.h>

const struct hvm_start_info *hvm_start_info;

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
    /* store HVM start info ptr */
    "    mov  %ebx, hvm_start_info   \n"
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

uint32_t ioapic_base_address = 0xfec00000;
uint8_t ioapic_version;

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

    tss = mem_alloc(128, 128);
    memset(tss, 0, 128);
    hvm_param_set(HVM_PARAM_VM86_TSS, virt_to_phys(tss));
    printf("vm86 TSS at %08lx\n", virt_to_phys(tss));
}

static void apic_setup(void)
{
    /*
     * This would the The Right Thing To Do (tm), if only qemu negotiated
     * with Xen where the IO-APIC actually sits (which is currently hard
     * coded in Xen and can't be controlled externally). Uncomment this code
     * once that changed.
    ioapic_base_address |= (pci_readb(PCI_ISA_DEVFN, 0x80) & 0x3f) << 10;
     */
    ioapic_version = ioapic_read(0x01) & 0xff;

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
    { "seabios", &seabios_config, },
    { "ovmf", &ovmf_config, },
    { NULL, NULL }
};

static const struct bios_config *detect_bios(void)
{
    const struct bios_info *b;
    const char *bios;

    bios = xenstore_read("hvmloader/bios", "rombios");

    for ( b = &bios_configs[0]; b->key != NULL; b++ )
        if ( !strcmp(bios, b->key) )
            return b->bios;

    printf("Unknown BIOS %s, no ROM image found\n", bios);
    BUG();
    return NULL;
}

static void acpi_enable_sci(void)
{
    uint8_t pm1a_cnt_val;

#define PIIX4_SMI_CMD_IOPORT 0xb2
#define PIIX4_ACPI_ENABLE    0xf1

    /*
     * PIIX4 emulation in QEMU has SCI_EN=0 by default. We have no legacy
     * SMM implementation, so give ACPI control to the OSPM immediately.
     */
    pm1a_cnt_val = inb(ACPI_PM1A_CNT_BLK_ADDRESS_V1);
    if ( !(pm1a_cnt_val & ACPI_PM1C_SCI_EN) )
        outb(PIIX4_SMI_CMD_IOPORT, PIIX4_ACPI_ENABLE);

    pm1a_cnt_val = inb(ACPI_PM1A_CNT_BLK_ADDRESS_V1);
    BUG_ON(!(pm1a_cnt_val & ACPI_PM1C_SCI_EN));
}

const struct hvm_modlist_entry *get_module_entry(
    const struct hvm_start_info *info,
    const char *name)
{
    const struct hvm_modlist_entry *modlist =
        (struct hvm_modlist_entry *)(uintptr_t)info->modlist_paddr;
    unsigned int i;

    if ( !modlist ||
         info->modlist_paddr > UINTPTR_MAX ||
         (UINTPTR_MAX - (uintptr_t)info->modlist_paddr) / sizeof(*modlist)
         < info->nr_modules )
        return NULL;

    for ( i = 0; i < info->nr_modules; i++ )
    {
        char *module_name = (char*)(uintptr_t)modlist[i].cmdline_paddr;

        /* Skip if the module or its cmdline is missing. */
        if ( !module_name || !modlist[i].paddr )
            continue;

        /* Skip if the cmdline cannot be read. */
        if ( modlist[i].cmdline_paddr > UINTPTR_MAX ||
             (modlist[i].cmdline_paddr + strlen(name)) > UINTPTR_MAX )
            continue;

        if ( !strcmp(name, module_name) )
        {
            if ( modlist[i].paddr > UINTPTR_MAX ||
                 modlist[i].size > UINTPTR_MAX ||
                 (modlist[i].paddr + modlist[i].size - 1) > UINTPTR_MAX )
            {
                printf("Cannot load \"%s\" from 0x"PRIllx" (0x"PRIllx")\n",
                       name, PRIllx_arg(modlist[i].paddr),
                       PRIllx_arg(modlist[i].size));
                BUG();
            }
            return &modlist[i];
        }
    }

    return NULL;
}

int main(void)
{
    const struct bios_config *bios;
    int acpi_enabled;
    const struct hvm_modlist_entry *bios_module;

    /* Initialise hypercall stubs with RET, rendering them no-ops. */
    memset((void *)HYPERCALL_PHYSICAL_ADDRESS, 0xc3 /* RET */, PAGE_SIZE);

    printf("HVM Loader\n");
    BUG_ON(hvm_start_info->magic != XEN_HVM_START_MAGIC_VALUE);

    init_hypercalls();

    memory_map_setup();

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
    bios_module = get_module_entry(hvm_start_info, "firmware");
    if ( bios_module )
    {
        uint32_t paddr = bios_module->paddr;

        bios->bios_load(bios, (void*)paddr, bios_module->size);
    }
#ifdef ENABLE_ROMBIOS
    else if ( bios == &rombios_config )
    {
        bios->bios_load(bios, NULL, 0);
    }
#endif
    else
    {
        /*
         * If there is no BIOS module supplied and if there is no embeded BIOS
         * image, then we failed. Only rombios might have an embedded bios blob.
         */
        printf("no BIOS ROM image found\n");
        BUG();
    }

    if ( (hvm_info->nr_vcpus > 1) || hvm_info->apic_mode )
    {
        if ( bios->create_mp_tables )
            bios->create_mp_tables();
        if ( bios->create_pir_tables )
            bios->create_pir_tables();
    }

    if ( bios->load_roms )
        bios->load_roms();

    acpi_enabled = !strncmp(xenstore_read("platform/acpi", "1"), "1", 1);

    if ( acpi_enabled )
    {
        init_vnuma_info();

        if ( bios->acpi_build_tables )
        {
            printf("Loading ACPI ...\n");
            bios->acpi_build_tables();
        }

        acpi_enable_sci();

        hvm_param_set(HVM_PARAM_ACPI_IOPORTS_LOCATION, 1);
    }

    init_vm86_tss();

    cmos_write_memory_size();

    printf("BIOS map:\n");
    if ( SCRATCH_PHYSICAL_ADDRESS != scratch_start )
        printf(" %05x-%05lx: Scratch space\n",
               SCRATCH_PHYSICAL_ADDRESS, scratch_start);
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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
