#ifndef __HVMLOADER_OPTION_ROM_H__
#define __HVMLOADER_OPTION_ROM_H__

#include <stdint.h>

struct option_rom_header {
    uint8_t signature[2]; /* "\x55\xaa" */
    uint8_t rom_size; /* 512-byte increments */
    uint32_t entry_point;
    uint8_t reserved[17];
    uint16_t pci_header_offset;
    uint16_t expansion_header_offset;
} __attribute__ ((packed));

struct option_rom_pnp_header {
    uint8_t signature[4]; /* "$PnP" */
    uint8_t structure_revision;
    uint8_t structure_length; /* 16-byte increments */
    uint16_t next_header_offset;
    uint8_t reserved;
    uint8_t checksum;
    uint32_t device_id;
    uint16_t manufacturer_name_offset;
    uint16_t product_name_offset;
    uint8_t device_type_code[3];
    uint8_t device_indicators;
    uint16_t boot_connection_vector;
    uint16_t disconnect_vector;
    uint16_t bootstap_entry_vector;
    uint16_t reserved2;
    uint16_t static_resource_information_vector;
} __attribute__ ((packed));
        

struct option_rom_pci_header {
    uint8_t signature[4]; /* "PCIR" */
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t vital_product_data_offset;
    uint16_t structure_length;
    uint8_t structure_revision;
    uint8_t class_code[3];
    uint16_t image_length;
    uint16_t image_revision;
    uint8_t code_type;
    uint8_t indicator;
    uint16_t reserved;
} __attribute__ ((packed));

#define round_option_rom(x) (((x) + 2047) & ~2047)
int scan_etherboot_nic(unsigned int option_rom_end,
                       uint32_t copy_rom_dest,
                       void *etherboot_rom);
int pci_load_option_roms(unsigned int option_rom_end,
                         uint32_t rom_base_addr);

#endif /* __HVMLOADER_OPTION_ROM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
