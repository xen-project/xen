/*
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License, version 
 * 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "acpi2_0.h"
#include "../config.h"
#include "../util.h"

extern struct acpi_20_rsdp Rsdp;
extern struct acpi_20_rsdt Rsdt;
extern struct acpi_20_xsdt Xsdt;
extern struct acpi_20_fadt Fadt;
extern struct acpi_20_facs Facs;
extern unsigned char AmlCode[];
extern int DsdtLen;

static void set_checksum(
    void *table, uint32_t checksum_offset, uint32_t length)
{
    uint8_t *p, sum = 0;

    p = table;
    p[checksum_offset] = 0;

    while ( length-- )
        sum = sum + *p++;

    p = table;
    p[checksum_offset] = -sum;
}

int construct_madt(struct acpi_20_madt *madt)
{
    struct acpi_20_madt_intsrcovr *intsrcovr;
    struct acpi_20_madt_ioapic    *io_apic;
    struct acpi_20_madt_lapic     *lapic;
    int i, offset = 0;

    memset(madt, 0, sizeof(*madt));
    madt->header.signature    = ACPI_2_0_MADT_SIGNATURE;
    madt->header.revision     = ACPI_2_0_MADT_REVISION;
    strncpy(madt->header.oem_id, "INTEL ", 6);
    madt->header.oem_table_id = ACPI_OEM_TABLE_ID;
    madt->header.oem_revision = ACPI_OEM_REVISION;
    madt->header.creator_id   = ACPI_CREATOR_ID;
    madt->header.creator_revision = ACPI_CREATOR_REVISION;
    madt->lapic_addr = LAPIC_BASE_ADDRESS;
    madt->flags      = ACPI_PCAT_COMPAT;
    offset += sizeof(*madt);

    intsrcovr = (struct acpi_20_madt_intsrcovr *)(madt + 1);
    for ( i = 0; i < 16; i++ )
    {
        if ( !(PCI_ISA_IRQ_MASK & (1U << i)) )
            continue;

        /* PCI: active-low level-triggered */
        memset(intsrcovr, 0, sizeof(*intsrcovr));
        intsrcovr->type   = ACPI_INTERRUPT_SOURCE_OVERRIDE;
        intsrcovr->length = sizeof(*intsrcovr);
        intsrcovr->source = i;
        intsrcovr->gsi    = i;
        intsrcovr->flags  = 0xf;

        offset += sizeof(*intsrcovr);
        intsrcovr++;
    }

    io_apic = (struct acpi_20_madt_ioapic *)intsrcovr;
    memset(io_apic, 0, sizeof(*io_apic));
    io_apic->type        = ACPI_IO_APIC;
    io_apic->length      = sizeof(*io_apic);
    io_apic->ioapic_id   = IOAPIC_ID;
    io_apic->ioapic_addr = IOAPIC_BASE_ADDRESS;
    offset += sizeof(*io_apic);

    lapic = (struct acpi_20_madt_lapic *)io_apic;
    for ( i = 0; i < get_vcpu_nr(); i++ )
    {
        memset(lapic, 0, sizeof(*lapic));
        lapic->type    = ACPI_PROCESSOR_LOCAL_APIC;
        lapic->length  = sizeof(*lapic);
        lapic->acpi_processor_id = i;
        lapic->apic_id = i;
        lapic->flags   = ACPI_LOCAL_APIC_ENABLED;
        offset += sizeof(*lapic);
        lapic++;
    }

    madt->header.length = offset;
    set_checksum(madt, offsetof(struct acpi_header, checksum), offset);

    return offset;
}

/*
 * Copy all the ACPI table to buffer.
 * Buffer layout: FACS, DSDT, FADT, MADT, XSDT, RSDT, RSDP.
 */
int acpi_build_tables(uint8_t *buf)
{
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_rsdt *rsdt;
    struct acpi_20_xsdt *xsdt;
    struct acpi_20_fadt *fadt;
    struct acpi_20_madt *madt = 0;
    struct acpi_20_facs *facs;
    unsigned char       *dsdt;
    int offset = 0, nr_vcpus = get_vcpu_nr();

#define inc_offset(sz)  (offset = (offset + (sz) + 15) & ~15)
#define requires_madt() (nr_vcpus > 1)

    facs = (struct acpi_20_facs *)&buf[offset];
    memcpy(facs, &Facs, sizeof(struct acpi_20_facs));
    inc_offset(sizeof(struct acpi_20_facs));

    dsdt = (unsigned char *)&buf[offset];
    memcpy(dsdt, &AmlCode, DsdtLen);
    inc_offset(DsdtLen);

    fadt = (struct acpi_20_fadt *)&buf[offset];
    memcpy(fadt, &Fadt, sizeof(struct acpi_20_fadt));
    inc_offset(sizeof(struct acpi_20_fadt));
    fadt->dsdt   = (unsigned long)dsdt;
    fadt->x_dsdt = (unsigned long)dsdt;
    fadt->firmware_ctrl   = (unsigned long)facs;
    fadt->x_firmware_ctrl = (unsigned long)facs;
    set_checksum(fadt,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_20_fadt));

    if ( requires_madt() )
    {
        madt = (struct acpi_20_madt *)&buf[offset];
        inc_offset(construct_madt(madt));
    }

    xsdt = (struct acpi_20_xsdt *)&buf[offset];
    memcpy(xsdt, &Xsdt, sizeof(struct acpi_20_xsdt));
    inc_offset(sizeof(struct acpi_20_xsdt));
    xsdt->entry[0] = (unsigned long)fadt;
    xsdt->header.length = sizeof(struct acpi_header) + sizeof(uint64_t);
    if ( requires_madt() )
    {
        xsdt->entry[1] = (unsigned long)madt;
        xsdt->header.length += sizeof(uint64_t);
    }
    set_checksum(xsdt,
                 offsetof(struct acpi_header, checksum),
                 xsdt->header.length);

    rsdt = (struct acpi_20_rsdt *)&buf[offset];
    memcpy(rsdt, &Rsdt, sizeof(struct acpi_20_rsdt));
    inc_offset(sizeof(struct acpi_20_rsdt));
    rsdt->entry[0] = (unsigned long)fadt;
    rsdt->header.length = sizeof(struct acpi_header) + sizeof(uint32_t);
    if ( requires_madt() )
    {
        rsdt->entry[1] = (unsigned long)madt;
        rsdt->header.length += sizeof(uint32_t);
    }
    set_checksum(rsdt,
                 offsetof(struct acpi_header, checksum),
                 rsdt->header.length);

    rsdp = (struct acpi_20_rsdp *)&buf[offset];
    memcpy(rsdp, &Rsdp, sizeof(struct acpi_20_rsdp));
    inc_offset(sizeof(struct acpi_20_rsdp));
    rsdp->rsdt_address = (unsigned long)rsdt;
    rsdp->xsdt_address = (unsigned long)xsdt;
    set_checksum(rsdp,
                 offsetof(struct acpi_10_rsdp, checksum),
                 sizeof(struct acpi_10_rsdp));
    set_checksum(rsdp,
                 offsetof(struct acpi_20_rsdp, extended_checksum),
                 sizeof(struct acpi_20_rsdp));

    return offset;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
