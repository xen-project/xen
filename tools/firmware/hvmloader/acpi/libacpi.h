/******************************************************************************
 * libacpi.h
 * 
 * libacpi interfaces
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
 *
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */


#ifndef __LIBACPI_H__
#define __LIBACPI_H__

#define ACPI_HAS_COM1        (1<<0)
#define ACPI_HAS_COM2        (1<<1)
#define ACPI_HAS_LPT1        (1<<2)
#define ACPI_HAS_HPET        (1<<3)
#define ACPI_HAS_SSDT_PM     (1<<4)
#define ACPI_HAS_SSDT_S3     (1<<5)
#define ACPI_HAS_SSDT_S4     (1<<6)


struct acpi_config {
    const unsigned char *dsdt_anycpu;
    unsigned int dsdt_anycpu_len;
    const unsigned char *dsdt_15cpu;
    unsigned int dsdt_15cpu_len;

    /* PCI I/O hole */
    uint32_t pci_start, pci_len;
    uint64_t pci_hi_start, pci_hi_len;

    uint32_t table_flags;

    uint64_t vm_gid[2];
    unsigned long vm_gid_addr; /* OUT parameter */

    /*
     * Address where acpi_info should be placed.
     * This must match the OperationRegion(BIOS, SystemMemory, ....)
     * definition in the DSDT
     */
    unsigned int infop;

    /* RSDP address */
    unsigned int rsdp;
};

void acpi_build_tables(const struct acpi_config *config);

#endif /* __LIBACPI_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
