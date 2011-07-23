#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

#include <stdint.h>

enum virtual_vga { VGA_none, VGA_std, VGA_cirrus, VGA_pt };
extern enum virtual_vga virtual_vga;

struct bios_config {
    const char *name;

    /* BIOS ROM image bits */
    void *image;
    unsigned int image_size;

    /* Physical address to load at */
    unsigned int bios_address;

    /* ROMS */
    int load_roms;
    unsigned int optionrom_start, optionrom_end;

    void (*bios_info_setup)(void);
    void (*bios_info_finish)(void);

    void (*bios_relocate)(void);

    void (*vm86_setup)(void);
    void (*e820_setup)(void);

    void (*acpi_build_tables)(void);
    void (*create_mp_tables)(void);
    void (*create_smbios_tables)(void);
    void (*create_pir_tables)(void);
};

extern struct bios_config rombios_config;
extern struct bios_config seabios_config;

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

/* Reserved for special BIOS mappings, etc. */
#define RESERVED_MEMBASE    0xfc000000

/* Memory map. */
#define SCRATCH_PHYSICAL_ADDRESS      0x00010000
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000
#define ACPI_INFO_PHYSICAL_ADDRESS    0x0009F000
#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000
#define HVMLOADER_PHYSICAL_ADDRESS    0x00100000

#define ACPI_INFO_SIZE                     0xC00
#define ACPI_INFO_PHYSICAL_END (ACPI_INFO_PHYSICAL_ADDRESS + ACPI_INFO_SIZE)

extern unsigned long scratch_start;

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
