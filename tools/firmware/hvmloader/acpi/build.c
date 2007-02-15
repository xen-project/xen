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
#include "ssdt_tpm.h"
#include "../config.h"
#include "../util.h"
#include <xen/hvm/e820.h>

#define align16(sz) (((sz) + 15) & ~15)

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
    strncpy(madt->header.oem_id, ACPI_OEM_ID, 6);
    strncpy(madt->header.oem_table_id, ACPI_OEM_TABLE_ID, 8);
    madt->header.oem_revision = ACPI_OEM_REVISION;
    madt->header.creator_id   = ACPI_CREATOR_ID;
    madt->header.creator_revision = ACPI_CREATOR_REVISION;
    madt->lapic_addr = LAPIC_BASE_ADDRESS;
    madt->flags      = ACPI_PCAT_COMPAT;
    offset += sizeof(*madt);

    intsrcovr = (struct acpi_20_madt_intsrcovr *)(madt + 1);
    for ( i = 0; i < 16; i++ )
    {
        memset(intsrcovr, 0, sizeof(*intsrcovr));
        intsrcovr->type   = ACPI_INTERRUPT_SOURCE_OVERRIDE;
        intsrcovr->length = sizeof(*intsrcovr);
        intsrcovr->source = i;

        if ( i == 0 )
        {
            /* ISA IRQ0 routed to IOAPIC GSI 2. */
            intsrcovr->gsi    = 2;
            intsrcovr->flags  = 0x0;
        }
        else if ( PCI_ISA_IRQ_MASK & (1U << i) )
        {
            /* PCI: active-low level-triggered. */
            intsrcovr->gsi    = i;
            intsrcovr->flags  = 0xf;
        }
        else
        {
            /* No need for a INT source override structure. */
            continue;
        }

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

    lapic = (struct acpi_20_madt_lapic *)(io_apic + 1);
    for ( i = 0; i < get_vcpu_nr(); i++ )
    {
        memset(lapic, 0, sizeof(*lapic));
        lapic->type    = ACPI_PROCESSOR_LOCAL_APIC;
        lapic->length  = sizeof(*lapic);
        /* Processor ID must match processor-object IDs in the DSDT. */
        lapic->acpi_processor_id = i;
        lapic->apic_id = LAPIC_ID(i);
        lapic->flags   = ACPI_LOCAL_APIC_ENABLED;
        offset += sizeof(*lapic);
        lapic++;
    }

    madt->header.length = offset;
    set_checksum(madt, offsetof(struct acpi_header, checksum), offset);

    return align16(offset);
}

int construct_hpet(struct acpi_20_hpet *hpet)
{
    int offset;

    memset(hpet, 0, sizeof(*hpet));
    hpet->header.signature    = ACPI_2_0_HPET_SIGNATURE;
    hpet->header.revision     = ACPI_2_0_HPET_REVISION;
    strncpy(hpet->header.oem_id, ACPI_OEM_ID, 6);
    strncpy(hpet->header.oem_table_id, ACPI_OEM_TABLE_ID, 8);
    hpet->header.oem_revision = ACPI_OEM_REVISION;
    hpet->header.creator_id   = ACPI_CREATOR_ID;
    hpet->header.creator_revision = ACPI_CREATOR_REVISION;
    hpet->timer_block_id      = 0x8086a201;
    hpet->addr.address        = ACPI_HPET_ADDRESS;
    offset = sizeof(*hpet);

    hpet->header.length = offset;
    set_checksum(hpet, offsetof(struct acpi_header, checksum), offset);

    return offset;
}

int construct_secondary_tables(uint8_t *buf, unsigned long *table_ptrs)
{
    int offset = 0, nr_tables = 0;
    struct acpi_20_madt *madt;
    struct acpi_20_hpet *hpet;
    struct acpi_20_tcpa *tcpa;
    static const uint16_t tis_signature[] = {0x0001, 0x0001, 0x0001};
    uint16_t *tis_hdr;

    /* MADT. */
    if ( (get_vcpu_nr() > 1) || get_apic_mode() )
    {
        madt = (struct acpi_20_madt *)&buf[offset];
        offset += construct_madt(madt);
        table_ptrs[nr_tables++] = (unsigned long)madt;
    }

    /* HPET. */
    hpet = (struct acpi_20_hpet *)&buf[offset];
    offset += construct_hpet(hpet);
    table_ptrs[nr_tables++] = (unsigned long)hpet;

    /* TPM TCPA and SSDT. */
    tis_hdr = (uint16_t *)0xFED40F00;
    if ( (tis_hdr[0] == tis_signature[0]) &&
         (tis_hdr[1] == tis_signature[1]) &&
         (tis_hdr[2] == tis_signature[2]) )
    {
        memcpy(&buf[offset], AmlCode_TPM, sizeof(AmlCode_TPM));
        table_ptrs[nr_tables++] = (unsigned long)&buf[offset];
        offset += align16(sizeof(AmlCode_TPM));

        tcpa = (struct acpi_20_tcpa *)&buf[offset];
        memset(tcpa, 0, sizeof(*tcpa));
        offset += align16(sizeof(*tcpa));
        table_ptrs[nr_tables++] = (unsigned long)tcpa;

        tcpa->header.signature = ACPI_2_0_TCPA_SIGNATURE;
        tcpa->header.length    = sizeof(*tcpa);
        tcpa->header.revision  = ACPI_2_0_TCPA_REVISION;
        strncpy(tcpa->header.oem_id, ACPI_OEM_ID, 6);
        strncpy(tcpa->header.oem_table_id, ACPI_OEM_TABLE_ID, 8);
        tcpa->header.oem_revision = ACPI_OEM_REVISION;
        tcpa->header.creator_id   = ACPI_CREATOR_ID;
        tcpa->header.creator_revision = ACPI_CREATOR_REVISION;
        tcpa->lasa = e820_malloc(
            ACPI_2_0_TCPA_LAML_SIZE, E820_RESERVED, (uint32_t)~0);
        if ( tcpa->lasa )
        {
            tcpa->laml = ACPI_2_0_TCPA_LAML_SIZE;
            memset((char *)(unsigned long)tcpa->lasa, 0, tcpa->laml);
            set_checksum(tcpa,
                         offsetof(struct acpi_header, checksum),
                         tcpa->header.length);
        }
    }

    table_ptrs[nr_tables] = 0;
    return align16(offset);
}

/* Copy all the ACPI table to buffer. */
int acpi_build_tables(uint8_t *buf)
{
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_rsdt *rsdt;
    struct acpi_20_xsdt *xsdt;
    struct acpi_20_fadt *fadt;
    struct acpi_20_facs *facs;
    unsigned char       *dsdt;
    unsigned long        secondary_tables[16];
    int                  offset = 0, i;

    facs = (struct acpi_20_facs *)&buf[offset];
    memcpy(facs, &Facs, sizeof(struct acpi_20_facs));
    offset += align16(sizeof(struct acpi_20_facs));

    dsdt = (unsigned char *)&buf[offset];
    memcpy(dsdt, &AmlCode, DsdtLen);
    offset += align16(DsdtLen);

    fadt = (struct acpi_20_fadt *)&buf[offset];
    memcpy(fadt, &Fadt, sizeof(struct acpi_20_fadt));
    offset += align16(sizeof(struct acpi_20_fadt));
    fadt->dsdt   = (unsigned long)dsdt;
    fadt->x_dsdt = (unsigned long)dsdt;
    fadt->firmware_ctrl   = (unsigned long)facs;
    fadt->x_firmware_ctrl = (unsigned long)facs;
    set_checksum(fadt,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_20_fadt));

    offset += construct_secondary_tables(&buf[offset], secondary_tables);

    xsdt = (struct acpi_20_xsdt *)&buf[offset];
    memcpy(xsdt, &Xsdt, sizeof(struct acpi_header));
    xsdt->entry[0] = (unsigned long)fadt;
    for ( i = 0; secondary_tables[i]; i++ )
        xsdt->entry[i+1] = secondary_tables[i];
    xsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint64_t);
    offset += align16(xsdt->header.length);
    set_checksum(xsdt,
                 offsetof(struct acpi_header, checksum),
                 xsdt->header.length);

    rsdt = (struct acpi_20_rsdt *)&buf[offset];
    memcpy(rsdt, &Rsdt, sizeof(struct acpi_header));
    rsdt->entry[0] = (unsigned long)fadt;
    for ( i = 0; secondary_tables[i]; i++ )
        rsdt->entry[i+1] = secondary_tables[i];
    rsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint32_t);
    offset += align16(rsdt->header.length);
    set_checksum(rsdt,
                 offsetof(struct acpi_header, checksum),
                 rsdt->header.length);

    rsdp = (struct acpi_20_rsdp *)&buf[offset];
    memcpy(rsdp, &Rsdp, sizeof(struct acpi_20_rsdp));
    offset += align16(sizeof(struct acpi_20_rsdp));
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
