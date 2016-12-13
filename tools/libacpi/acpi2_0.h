/*
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */
#ifndef _ACPI_2_0_H_
#define _ACPI_2_0_H_

#include <stdint.h>
#include <xen/xen.h>
#include <xen/hvm/ioreq.h>

#define ASCII32(a,b,c,d)         \
    (((a) <<  0) | ((b) <<  8) | ((c) << 16) | ((d) << 24))
#define ASCII64(a,b,c,d,e,f,g,h) \
    (((uint64_t)ASCII32(a,b,c,d)) | (((uint64_t)ASCII32(e,f,g,h)) << 32))

#pragma pack (1)

/*
 * Common ACPI header.
 */
struct acpi_header {
    uint32_t signature;
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
};

#define ACPI_OEM_ID             "Xen"
#define ACPI_OEM_TABLE_ID       "HVM"
#define ACPI_OEM_REVISION       0

#define ACPI_CREATOR_ID         ASCII32('H','V','M','L') /* HVMLoader */
#define ACPI_CREATOR_REVISION   0

/*
 * ACPI 2.0 Generic Address Space definition.
 */
struct acpi_20_generic_address {
    uint8_t  address_space_id;
    uint8_t  register_bit_width;
    uint8_t  register_bit_offset;
    uint8_t  reserved;
    uint64_t address;
};

/*
 * Generic Address Space Address IDs.
 */
#define ACPI_SYSTEM_MEMORY 0
#define ACPI_SYSTEM_IO 1
#define ACPI_PCI_CONFIGURATION_SPACE 2
#define ACPI_EMBEDDED_CONTROLLER 3
#define ACPI_SMBUS 4
#define ACPI_FUNCTIONAL_FIXED_HARDWARE 0x7F

/*
 * Root System Description Pointer Structure in ACPI 1.0.
 */
struct acpi_10_rsdp {
    uint64_t signature;
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  reserved;
    uint32_t rsdt_address;
};

/*
 * Root System Description Pointer Structure.
 */
struct acpi_20_rsdp {
    uint64_t signature;
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t  extended_checksum;
    uint8_t  reserved[3];
};

/*
 * Root System Description Table (RSDT).
 */
struct acpi_20_rsdt {
    struct acpi_header header;
    uint32_t entry[1];
};

/*
 * Extended System Description Table (XSDT).
 */
struct acpi_20_xsdt {
    struct acpi_header header;
    uint64_t entry[1];
};

/*
 * TCG Hardware Interface Table (TCPA)
 */
struct acpi_20_tcpa {
    struct acpi_header header;
    uint16_t platform_class;
    uint32_t laml;
    uint64_t lasa;
};
#define ACPI_2_0_TCPA_LAML_SIZE (64*1024)

/*
 * Fixed ACPI Description Table Structure (FADT) in ACPI 1.0.
 */
struct acpi_10_fadt {
    struct acpi_header header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t  reserved0;
    uint8_t  preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t  acpi_enable;
    uint8_t  acpi_disable;
    uint8_t  s4bios_req;
    uint8_t  pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t  pm1_evt_len;
    uint8_t  pm1_cnt_len;
    uint8_t  pm2_cnt_len;
    uint8_t  pm_tmr_len;
    uint8_t  gpe0_blk_len;
    uint8_t  gpe1_blk_len;
    uint8_t  gpe1_base;
    uint8_t  cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t  duty_offset;
    uint8_t  duty_width;
    uint8_t  day_alrm;
    uint8_t  mon_alrm;
    uint8_t  century;
    uint16_t iapc_boot_arch;
    uint8_t  reserved1;
    uint32_t flags;
};

/*
 * Fixed ACPI Description Table Structure (FADT).
 */
struct acpi_fadt {
    struct acpi_header header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t  reserved0;
    uint8_t  preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t  acpi_enable;
    uint8_t  acpi_disable;
    uint8_t  s4bios_req;
    uint8_t  pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t  pm1_evt_len;
    uint8_t  pm1_cnt_len;
    uint8_t  pm2_cnt_len;
    uint8_t  pm_tmr_len;
    uint8_t  gpe0_blk_len;
    uint8_t  gpe1_blk_len;
    uint8_t  gpe1_base;
    uint8_t  cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t  duty_offset;
    uint8_t  duty_width;
    uint8_t  day_alrm;
    uint8_t  mon_alrm;
    uint8_t  century;
    uint16_t iapc_boot_arch;
    uint8_t  reserved1;
    uint32_t flags;
    struct acpi_20_generic_address reset_reg;
    uint8_t  reset_value;
    uint8_t  reserved2[3];
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    struct acpi_20_generic_address x_pm1a_evt_blk;
    struct acpi_20_generic_address x_pm1b_evt_blk;
    struct acpi_20_generic_address x_pm1a_cnt_blk;
    struct acpi_20_generic_address x_pm1b_cnt_blk;
    struct acpi_20_generic_address x_pm2_cnt_blk;
    struct acpi_20_generic_address x_pm_tmr_blk;
    struct acpi_20_generic_address x_gpe0_blk;
    struct acpi_20_generic_address x_gpe1_blk;
    /* Only available starting from FADT revision 5. */
    struct acpi_20_generic_address sleep_control;
    struct acpi_20_generic_address sleep_status;
};

/*
 * FADT Boot Architecture Flags.
 */
#define ACPI_FADT_LEGACY_DEVICES    (1 << 0)
#define ACPI_FADT_8042              (1 << 1)
#define ACPI_FADT_NO_VGA            (1 << 2)
#define ACPI_FADT_NO_CMOS_RTC       (1 << 5)

/*
 * FADT Fixed Feature Flags.
 */
#define ACPI_WBINVD         (1 << 0)
#define ACPI_WBINVD_FLUSH   (1 << 1)
#define ACPI_PROC_C1        (1 << 2)
#define ACPI_P_LVL2_UP      (1 << 3)
#define ACPI_PWR_BUTTON     (1 << 4)
#define ACPI_SLP_BUTTON     (1 << 5)
#define ACPI_FIX_RTC        (1 << 6)
#define ACPI_RTC_S4         (1 << 7)
#define ACPI_TMR_VAL_EXT    (1 << 8)
#define ACPI_DCK_CAP        (1 << 9)
#define ACPI_RESET_REG_SUP  (1 << 10)
#define ACPI_SEALED_CASE    (1 << 11)
#define ACPI_HEADLESS       (1 << 12)
#define ACPI_CPU_SW_SLP     (1 << 13)
#define ACPI_USE_PLATFORM_CLOCK (1 << 15)

/* PM1 Control Register Bits */
#define ACPI_PM1C_SCI_EN    (1 << 0)

/*
 * Firmware ACPI Control Structure (FACS).
 */
struct acpi_20_facs {
    uint32_t signature;
    uint32_t length;
    uint32_t hardware_signature;
    uint32_t firmware_waking_vector;
    uint32_t global_lock;
    uint32_t flags;
    uint64_t x_firmware_waking_vector;
    uint8_t  version;
    uint8_t  reserved[31];
};

#define ACPI_2_0_FACS_VERSION 0x01

/*
 * Multiple APIC Description Table header definition (MADT).
 */
struct acpi_20_madt {
    struct acpi_header header;
    uint32_t lapic_addr;
    uint32_t flags;
};


/*
 * HPET Description Table
 */
struct acpi_20_hpet {
    struct acpi_header header;
    uint32_t           timer_block_id;
    struct acpi_20_generic_address addr;
    uint8_t            hpet_number;
    uint16_t           min_tick;
    uint8_t            page_protect;
};
#define ACPI_HPET_ADDRESS 0xFED00000UL

/*
 * WAET Description Table
 */
struct acpi_20_waet {
    struct acpi_header header;
    uint32_t           flags;
};

/*
 * Multiple APIC Flags.
 */
#define ACPI_PCAT_COMPAT (1 << 0)

/*
 * Multiple APIC Description Table APIC structure types.
 */
#define ACPI_PROCESSOR_LOCAL_APIC           0x00
#define ACPI_IO_APIC                        0x01
#define ACPI_INTERRUPT_SOURCE_OVERRIDE      0x02
#define ACPI_NON_MASKABLE_INTERRUPT_SOURCE  0x03
#define ACPI_LOCAL_APIC_NMI                 0x04
#define ACPI_LOCAL_APIC_ADDRESS_OVERRIDE    0x05
#define ACPI_IO_SAPIC                       0x06
#define ACPI_PROCESSOR_LOCAL_SAPIC          0x07
#define ACPI_PLATFORM_INTERRUPT_SOURCES     0x08

/*
 * APIC Structure Definitions.
 */

/*
 * Processor Local APIC Structure Definition.
 */
struct acpi_20_madt_lapic {
    uint8_t  type;
    uint8_t  length;
    uint8_t  acpi_processor_id;
    uint8_t  apic_id;
    uint32_t flags;
};

/*
 * Local APIC Flags.  All other bits are reserved and must be 0.
 */
#define ACPI_LOCAL_APIC_ENABLED (1 << 0)

/*
 * IO APIC Structure.
 */
struct acpi_20_madt_ioapic {
    uint8_t  type;
    uint8_t  length;
    uint8_t  ioapic_id;
    uint8_t  reserved;
    uint32_t ioapic_addr;
    uint32_t gsi_base;
};

struct acpi_20_madt_intsrcovr {
    uint8_t  type;
    uint8_t  length;
    uint8_t  bus;
    uint8_t  source;
    uint32_t gsi;
    uint16_t flags;
};

/*
 * System Resource Affinity Table header definition (SRAT)
 */
struct acpi_20_srat {
    struct acpi_header header;
    uint32_t table_revision;
    uint32_t reserved2[2];
};

#define ACPI_SRAT_TABLE_REVISION 1

/*
 * System Resource Affinity Table structure types.
 */
#define ACPI_PROCESSOR_AFFINITY 0x0
#define ACPI_MEMORY_AFFINITY    0x1
struct acpi_20_srat_processor {
    uint8_t type;
    uint8_t length;
    uint8_t domain;
    uint8_t apic_id;
    uint32_t flags;
    uint8_t sapic_id;
    uint8_t domain_hi[3];
    uint32_t reserved;
};

/*
 * Local APIC Affinity Flags.  All other bits are reserved and must be 0.
 */
#define ACPI_LOCAL_APIC_AFFIN_ENABLED (1 << 0)

struct acpi_20_srat_memory {
    uint8_t type;
    uint8_t length;
    uint32_t domain;
    uint16_t reserved;
    uint64_t base_address;
    uint64_t mem_length;
    uint32_t reserved2;
    uint32_t flags;
    uint64_t reserved3;
};

/*
 * Memory Affinity Flags.  All other bits are reserved and must be 0.
 */
#define ACPI_MEM_AFFIN_ENABLED (1 << 0)
#define ACPI_MEM_AFFIN_HOTPLUGGABLE (1 << 1)
#define ACPI_MEM_AFFIN_NONVOLATILE (1 << 2)

struct acpi_20_slit {
    struct acpi_header header;
    uint64_t localities;
    uint8_t entry[0];
};

/*
 * Table Signatures.
 */
#define ACPI_2_0_RSDP_SIGNATURE ASCII64('R','S','D',' ','P','T','R',' ')
#define ACPI_2_0_FACS_SIGNATURE ASCII32('F','A','C','S')
#define ACPI_FADT_SIGNATURE     ASCII32('F','A','C','P')
#define ACPI_2_0_MADT_SIGNATURE ASCII32('A','P','I','C')
#define ACPI_2_0_RSDT_SIGNATURE ASCII32('R','S','D','T')
#define ACPI_2_0_XSDT_SIGNATURE ASCII32('X','S','D','T')
#define ACPI_2_0_TCPA_SIGNATURE ASCII32('T','C','P','A')
#define ACPI_2_0_HPET_SIGNATURE ASCII32('H','P','E','T')
#define ACPI_2_0_WAET_SIGNATURE ASCII32('W','A','E','T')
#define ACPI_2_0_SRAT_SIGNATURE ASCII32('S','R','A','T')
#define ACPI_2_0_SLIT_SIGNATURE ASCII32('S','L','I','T')

/*
 * Table revision numbers.
 */
#define ACPI_2_0_RSDP_REVISION 0x02
#define ACPI_2_0_MADT_REVISION 0x02
#define ACPI_2_0_RSDT_REVISION 0x01
#define ACPI_2_0_XSDT_REVISION 0x01
#define ACPI_2_0_TCPA_REVISION 0x02
#define ACPI_2_0_HPET_REVISION 0x01
#define ACPI_2_0_WAET_REVISION 0x01
#define ACPI_1_0_FADT_REVISION 0x01
#define ACPI_2_0_SRAT_REVISION 0x01
#define ACPI_2_0_SLIT_REVISION 0x01

#pragma pack ()

#endif /* _ACPI_2_0_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
