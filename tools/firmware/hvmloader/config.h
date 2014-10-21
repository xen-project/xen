#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

#include <stdint.h>

enum virtual_vga { VGA_none, VGA_std, VGA_cirrus, VGA_pt };
extern enum virtual_vga virtual_vga;

extern unsigned long igd_opregion_pgbase;
#define IGD_OPREGION_PAGES 3

struct bios_config {
    const char *name;

    /* BIOS ROM image bits */
    void *image;
    unsigned int image_size;

    /* Physical address to load at */
    unsigned int bios_address;

    /* ROMS */
    void (*load_roms)(void);

    void (*bios_load)(const struct bios_config *config);

    void (*bios_info_setup)(void);
    void (*bios_info_finish)(void);

    void (*e820_setup)(void);

    void (*acpi_build_tables)(void);
    void (*create_mp_tables)(void);
    void (*create_smbios_tables)(void);
    void (*create_pir_tables)(void);
};

extern struct bios_config rombios_config;
extern struct bios_config seabios_config;
extern struct bios_config ovmf_config;

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
#define PCI_MEM_END         0xfc000000

extern unsigned long pci_mem_start, pci_mem_end;
extern uint64_t pci_hi_mem_start, pci_hi_mem_end;

/* Memory map. */
#define SCRATCH_PHYSICAL_ADDRESS      0x00010000
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000
#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000
#define HVMLOADER_PHYSICAL_ADDRESS    0x00100000
/* Special BIOS mappings, etc. are allocated from here upwards... */
#define RESERVED_MEMBASE              0xFC000000
/* NB. ACPI_INFO_PHYSICAL_ADDRESS *MUST* match definition in acpi/dsdt.asl! */
#define ACPI_INFO_PHYSICAL_ADDRESS    0xFC000000
#define RESERVED_MEMORY_DYNAMIC_START 0xFC001000
#define RESERVED_MEMORY_DYNAMIC_END   0xFE000000
/*
 * GUEST_RESERVED: Physical address space reserved for guest use.
 * This is not dynamically advertised to guests, so this range must *never*
 * be used for any purpose by us, in future. It must always be marked as
 * reserved in the memory map (e.g., E820_RESERVED) so that mechanisms such
 * as PCI BAR remapping do not allocate from this region.
 */
#define GUEST_RESERVED_START          0xFE700000
#define GUEST_RESERVED_END            0xFE800000

extern unsigned long scratch_start;

#endif /* __HVMLOADER_CONFIG_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
