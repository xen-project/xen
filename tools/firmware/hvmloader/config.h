#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

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

#define ROMBIOS_SEG            0xF000
#define ROMBIOS_BEGIN          0x000F0000
#define ROMBIOS_SIZE           0x00010000
#define ROMBIOS_MAXOFFSET      0x0000FFFF
#define ROMBIOS_END            (ROMBIOS_BEGIN + ROMBIOS_SIZE)

/* Memory map. */
#define SCRATCH_PHYSICAL_ADDRESS      0x00010000
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000
#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000
#define OPTIONROM_PHYSICAL_ADDRESS    0x000C8000
#define OPTIONROM_PHYSICAL_END        0x000EA000
#define BIOS_INFO_PHYSICAL_ADDRESS    0x000EA000
#define ACPI_PHYSICAL_ADDRESS         0x000EA020
#define E820_PHYSICAL_ADDRESS         0x000EA100
#define SMBIOS_PHYSICAL_ADDRESS       0x000EB000
#define SMBIOS_MAXIMUM_SIZE           0x00005000
#define ROMBIOS_PHYSICAL_ADDRESS      0x000F0000

/* Offsets from E820_PHYSICAL_ADDRESS. */
#define E820_NR_OFFSET                0x0
#define E820_OFFSET                   0x8

/* Xen Platform Device */
#define XEN_PF_IOBASE   0x10
#define PFFLAG_ROM_LOCK 1 /* Sets whether ROM memory area is RW or RO */

/* Maximum we can support with current vLAPIC ID mapping. */
#define MAX_VCPUS 128

/* Located at BIOS_INFO_PHYSICAL_ADDRESS. */
struct bios_info {
    uint8_t  com1_present:1;    /* 0[0] - System has COM1? */
    uint8_t  com2_present:1;    /* 0[1] - System has COM2? */
    uint8_t  hpet_present:1;    /* 0[2] - System has HPET? */
    uint32_t pci_min, pci_len;  /* 4, 8 - PCI I/O hole boundaries */
    uint32_t madt_csum_addr;    /* 12   - Address of MADT checksum */
    uint32_t madt_lapic0_addr;  /* 16   - Address of first MADT LAPIC struct */
    uint32_t bios32_entry;      /* 20   - Entry point for 32-bit BIOS */
};
#define BIOSINFO_OFF_bios32_entry 20

#endif /* __HVMLOADER_CONFIG_H__ */
