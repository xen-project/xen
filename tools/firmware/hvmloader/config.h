#ifndef __HVMLOADER_CONFIG_H__
#define __HVMLOADER_CONFIG_H__

#define IOAPIC_BASE_ADDRESS 0xfec00000
#define IOAPIC_ID           0x01
#define IOAPIC_VERSION      0x11

#define LAPIC_BASE_ADDRESS  0xfee00000
#define LAPIC_ID(vcpu_id)   ((vcpu_id) * 2)

#define PCI_ISA_DEVFN       0x08    /* dev 1, fn 0 */
#define PCI_ISA_IRQ_MASK    0x0c20U /* ISA IRQs 5,10,11 are PCI connected */

#define PCI_MEMBASE         0xf0000000
#define PCI_MEMSIZE         0x0c000000

#define ROMBIOS_SEG            0xF000
#define ROMBIOS_BEGIN          0x000F0000
#define ROMBIOS_SIZE           0x00010000
#define ROMBIOS_MAXOFFSET      0x0000FFFF
#define ROMBIOS_END            (ROMBIOS_BEGIN + ROMBIOS_SIZE)

/* Memory map. */
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000
#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000
#define ETHERBOOT_PHYSICAL_ADDRESS    0x000D0000
#define EXTBOOT_PHYSICAL_ADDRESS      0x000DF800
#define SMBIOS_PHYSICAL_ADDRESS       0x000E9000
#define SMBIOS_MAXIMUM_SIZE           0x00001000
#define ACPI_PHYSICAL_ADDRESS         0x000EA000
#define ROMBIOS_PHYSICAL_ADDRESS      0x000F0000
#define SCRATCH_PHYSICAL_ADDRESS      0x00010000

/* Xen Platform Device */
#define PFFLAG_ROM_LOCK 1 /* Sets whether ROM memory area is RW or RO */

struct bios_info {
    uint8_t  com1_present:1;
    uint8_t  com2_present:1;
    uint8_t  hpet_present:1;
    uint32_t pci_min, pci_len;
    uint16_t xen_pfiob;
};

#endif /* __HVMLOADER_CONFIG_H__ */
