#ifndef _ROMBIOS_CONFIG_H
#define _ROMBIOS_CONFIG_H

/* Memory map. */
#define LOWHEAP_PHYSICAL_ADDRESS      0x00010000
#define LOWHEAP_SIZE                  0x00070000

#define OPTIONROM_PHYSICAL_ADDRESS    0x000C8000
#define OPTIONROM_PHYSICAL_END        0x000EA000
#define BIOS_INFO_PHYSICAL_ADDRESS    0x000EA000
#define ACPI_PHYSICAL_ADDRESS         0x000EA020
#define E820_PHYSICAL_ADDRESS         0x000EA100
#define SMBIOS_PHYSICAL_ADDRESS       0x000EB000
#define SMBIOS_PHYSICAL_END           0x000F0000

#define ROMBIOS_PHYSICAL_ADDRESS      0x000F0000

/* Offsets from E820_PHYSICAL_ADDRESS. */
#define E820_NR_OFFSET                0x0
#define E820_OFFSET                   0x8

#define E820_NR ((uint16_t *)(E820_PHYSICAL_ADDRESS + E820_NR_OFFSET))
#define E820    ((struct e820entry *)(E820_PHYSICAL_ADDRESS + E820_OFFSET))

/* Xen Platform Device */
#define XEN_PF_IOBASE   0x10
#define PFFLAG_ROM_LOCK 1 /* Sets whether ROM memory area is RW or RO */

/* Located at BIOS_INFO_PHYSICAL_ADDRESS. */
struct bios_info {
    uint8_t  com1_present:1;    /* 0[0] - System has COM1? */
    uint8_t  com2_present:1;    /* 0[1] - System has COM2? */
    uint8_t  lpt1_present:1;    /* 0[2] - System has LPT1? */
    uint8_t  hpet_present:1;    /* 0[3] - System has HPET? */
    uint32_t pci_min, pci_len;  /* 4, 8 - PCI I/O hole boundaries */
    uint32_t madt_csum_addr;    /* 12   - Address of MADT checksum */
    uint32_t madt_lapic0_addr;  /* 16   - Address of first MADT LAPIC struct */
    uint32_t bios32_entry;      /* 20   - Entry point for 32-bit BIOS */
};
#define BIOSINFO_OFF_bios32_entry 20

#endif

