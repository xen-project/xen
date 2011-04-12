#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

#include <stdint.h>

enum virtual_vga { VGA_none, VGA_std, VGA_cirrus, VGA_pt } virtual_vga;
extern enum virtual_vga virtual_vga;

struct bios_config {
    const char *name;

    /* BIOS ROM image bits */
    void *image;
    unsigned int image_size;

    /* Physical address to load at */
    unsigned int bios_address;

    /* SMBIOS */
    unsigned int smbios_start, smbios_end;

    /* Option ROMs */
    unsigned int optionrom_start, optionrom_end;

    /* ACPI tables */
    unsigned int acpi_start;

    void (*apic_setup)(void);
    void (*pci_setup)(void);
    void (*smp_setup)(void);

    uint32_t (*bios_high_setup)(void);
    void (*bios_info_setup)(uint32_t);
};

extern struct bios_config rombios_config;

#define PAGE_SHIFT 12
#define PAGE_SIZE  (1ul << PAGE_SHIFT)

#define IOAPIC_BASE_ADDRESS 0xfec00000
#define IOAPIC_ID           0x01
#define IOAPIC_VERSION      0x11

#define LAPIC_BASE_ADDRESS  0xfee00000
#define LAPIC_ID(vcpu_id)   ((vcpu_id) * 2)

#define PCI_ISA_DEVFN       0x08    /* dev 1, fn 0 */
#define PCI_ISA_IRQ_MASK    0x0c20U /* ISA IRQs 5,10,11 are PCI connected */

/* MMIO hole: Hardcoded defaults, which can be dynamically expanded. */
#define PCI_MEM_START       0xf0000000
#define PCI_MEM_END         0xfc000000
extern unsigned long pci_mem_start, pci_mem_end;

/* We reserve 16MB for special BIOS mappings, etc. */
#define RESERVED_MEMBASE    0xfc000000
#define RESERVED_MEMSIZE    0x01000000

#define ROMBIOS_BEGIN          0x000F0000
#define ROMBIOS_SIZE           0x00010000
#define ROMBIOS_MAXOFFSET      0x0000FFFF
#define ROMBIOS_END            (ROMBIOS_BEGIN + ROMBIOS_SIZE)

#include "e820.h"
#include "../rombios/config.h"

#define SCRATCH_PHYSICAL_ADDRESS      0x00010000
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000

#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000

#endif /* __HVMLOADER_CONFIG_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
