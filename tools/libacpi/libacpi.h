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

#define ACPI_HAS_COM1              (1<<0)
#define ACPI_HAS_COM2              (1<<1)
#define ACPI_HAS_LPT1              (1<<2)
#define ACPI_HAS_HPET              (1<<3)
#define ACPI_HAS_SSDT_PM           (1<<4)
#define ACPI_HAS_SSDT_S3           (1<<5)
#define ACPI_HAS_SSDT_S4           (1<<6)
#define ACPI_HAS_TCPA              (1<<7)
#define ACPI_HAS_IOAPIC            (1<<8)
#define ACPI_HAS_WAET              (1<<9)
#define ACPI_HAS_PMTIMER           (1<<10)
#define ACPI_HAS_BUTTONS           (1<<11)
#define ACPI_HAS_VGA               (1<<12)
#define ACPI_HAS_8042              (1<<13)
#define ACPI_HAS_CMOS_RTC          (1<<14)
#define ACPI_HAS_SSDT_LAPTOP_SLATE (1<<15)

struct xen_vmemrange;
struct acpi_numa {
    uint32_t nr_vmemranges;
    uint32_t nr_vnodes;
    const unsigned int *vcpu_to_vnode;
    const unsigned int *vdistance;
    const struct xen_vmemrange *vmemrange;
};

struct acpi_ctxt {
    struct acpi_mem_ops {
        void *(*alloc)(struct acpi_ctxt *ctxt, uint32_t size, uint32_t align);
        void (*free)(struct acpi_ctxt *ctxt, void *v, uint32_t size);
        unsigned long (*v2p)(struct acpi_ctxt *ctxt, void *v);
    } mem_ops;
};

struct acpi_config {
    const unsigned char *dsdt_anycpu;
    unsigned int dsdt_anycpu_len;
    const unsigned char *dsdt_15cpu;
    unsigned int dsdt_15cpu_len;

    /* PCI I/O hole */
    uint32_t pci_start, pci_len;
    uint64_t pci_hi_start, pci_hi_len;

    uint32_t table_flags;
    uint8_t acpi_revision;

    uint64_t vm_gid[2];
    unsigned long vm_gid_addr; /* OUT parameter */

    struct {
        uint32_t addr;
        uint32_t length;
    } pt;

    struct acpi_numa numa;
    const struct hvm_info_table *hvminfo;

    const uint16_t *tis_hdr;

    /*
     * Address where acpi_info should be placed.
     * This must match the OperationRegion(BIOS, SystemMemory, ....)
     * definition in the DSDT
     */
    unsigned long infop;

    /* RSDP address */
    unsigned long rsdp;

    /* x86-specific parameters */
    uint32_t (*lapic_id)(unsigned cpu);
    uint32_t lapic_base_address;
    uint32_t ioapic_base_address;
    uint16_t pci_isa_irq_mask;
    uint8_t ioapic_id;
};

int acpi_build_tables(struct acpi_ctxt *ctxt, struct acpi_config *config);

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
