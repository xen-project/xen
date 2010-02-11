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
#include "ssdt_pm.h"
#include "../config.h"
#include "../util.h"

#define align16(sz)        (((sz) + 15) & ~15)
#define fixed_strcpy(d, s) strncpy((d), (s), sizeof(d))

/* MADT parameters for filling in bios_info structure for DSDT. */
uint32_t madt_csum_addr, madt_lapic0_addr;

extern struct acpi_20_rsdp Rsdp;
extern struct acpi_20_rsdt Rsdt;
extern struct acpi_20_xsdt Xsdt;
extern struct acpi_20_fadt Fadt;
extern struct acpi_20_facs Facs;
extern unsigned char Dsdt[];
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

static uint8_t battery_port_exists(void)
{
    return (inb(0x88) == 0x1F);
}

static int construct_madt(struct acpi_20_madt *madt)
{
    struct acpi_20_madt_intsrcovr *intsrcovr;
    struct acpi_20_madt_ioapic    *io_apic;
    struct acpi_20_madt_lapic     *lapic;
    int i, offset = 0;

    memset(madt, 0, sizeof(*madt));
    madt->header.signature    = ACPI_2_0_MADT_SIGNATURE;
    madt->header.revision     = ACPI_2_0_MADT_REVISION;
    fixed_strcpy(madt->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(madt->header.oem_table_id, ACPI_OEM_TABLE_ID);
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
    madt_lapic0_addr = (uint32_t)lapic;
    for ( i = 0; i < HVM_MAX_VCPUS; i++ )
    {
        memset(lapic, 0, sizeof(*lapic));
        lapic->type    = ACPI_PROCESSOR_LOCAL_APIC;
        lapic->length  = sizeof(*lapic);
        /* Processor ID must match processor-object IDs in the DSDT. */
        lapic->acpi_processor_id = i;
        lapic->apic_id = LAPIC_ID(i);
        lapic->flags = ((i < hvm_info->nr_vcpus) &&
                        test_bit(i, hvm_info->vcpu_online)
                        ? ACPI_LOCAL_APIC_ENABLED : 0);
        offset += sizeof(*lapic);
        lapic++;
    }

    madt->header.length = offset;
    set_checksum(madt, offsetof(struct acpi_header, checksum), offset);
    madt_csum_addr = (uint32_t)&madt->header.checksum;

    return align16(offset);
}

static int construct_hpet(struct acpi_20_hpet *hpet)
{
    int offset;

    memset(hpet, 0, sizeof(*hpet));
    hpet->header.signature    = ACPI_2_0_HPET_SIGNATURE;
    hpet->header.revision     = ACPI_2_0_HPET_REVISION;
    fixed_strcpy(hpet->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(hpet->header.oem_table_id, ACPI_OEM_TABLE_ID);
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

static int construct_secondary_tables(uint8_t *buf, unsigned long *table_ptrs)
{
    int offset = 0, nr_tables = 0;
    struct acpi_20_madt *madt;
    struct acpi_20_hpet *hpet;
    struct acpi_20_tcpa *tcpa;
    static const uint16_t tis_signature[] = {0x0001, 0x0001, 0x0001};
    uint16_t *tis_hdr;
    void *lasa;

    /* MADT. */
    if ( (hvm_info->nr_vcpus > 1) || hvm_info->apic_mode )
    {
        madt = (struct acpi_20_madt *)&buf[offset];
        offset += construct_madt(madt);
        table_ptrs[nr_tables++] = (unsigned long)madt;
    }

    /* HPET. */
    if ( hpet_exists(ACPI_HPET_ADDRESS) )
    {
        hpet = (struct acpi_20_hpet *)&buf[offset];
        offset += construct_hpet(hpet);
        table_ptrs[nr_tables++] = (unsigned long)hpet;
    }

    if ( battery_port_exists() ) 
    {
        table_ptrs[nr_tables++] = (unsigned long)&buf[offset];
        memcpy(&buf[offset], ssdt_pm, sizeof(ssdt_pm));
        offset += align16(sizeof(ssdt_pm));
    }

    /* TPM TCPA and SSDT. */
    tis_hdr = (uint16_t *)0xFED40F00;
    if ( (tis_hdr[0] == tis_signature[0]) &&
         (tis_hdr[1] == tis_signature[1]) &&
         (tis_hdr[2] == tis_signature[2]) )
    {
        memcpy(&buf[offset], ssdt_tpm, sizeof(ssdt_tpm));
        table_ptrs[nr_tables++] = (unsigned long)&buf[offset];
        offset += align16(sizeof(ssdt_tpm));

        tcpa = (struct acpi_20_tcpa *)&buf[offset];
        memset(tcpa, 0, sizeof(*tcpa));
        offset += align16(sizeof(*tcpa));
        table_ptrs[nr_tables++] = (unsigned long)tcpa;

        tcpa->header.signature = ACPI_2_0_TCPA_SIGNATURE;
        tcpa->header.length    = sizeof(*tcpa);
        tcpa->header.revision  = ACPI_2_0_TCPA_REVISION;
        fixed_strcpy(tcpa->header.oem_id, ACPI_OEM_ID);
        fixed_strcpy(tcpa->header.oem_table_id, ACPI_OEM_TABLE_ID);
        tcpa->header.oem_revision = ACPI_OEM_REVISION;
        tcpa->header.creator_id   = ACPI_CREATOR_ID;
        tcpa->header.creator_revision = ACPI_CREATOR_REVISION;
        if ( (lasa = mem_alloc(ACPI_2_0_TCPA_LAML_SIZE, 0)) != NULL )
        {
            tcpa->lasa = virt_to_phys(lasa);
            tcpa->laml = ACPI_2_0_TCPA_LAML_SIZE;
            memset(lasa, 0, tcpa->laml);
            set_checksum(tcpa,
                         offsetof(struct acpi_header, checksum),
                         tcpa->header.length);
        }
    }

    table_ptrs[nr_tables] = 0;
    return align16(offset);
}

static void __acpi_build_tables(uint8_t *buf, int *low_sz, int *high_sz)
{
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_rsdt *rsdt;
    struct acpi_20_xsdt *xsdt;
    struct acpi_20_fadt *fadt;
    struct acpi_10_fadt *fadt_10;
    struct acpi_20_facs *facs;
    unsigned char       *dsdt;
    unsigned long        secondary_tables[16];
    int                  offset = 0, i;

    /*
     * Fill in high-memory data structures, starting at @buf.
     */

    facs = (struct acpi_20_facs *)&buf[offset];
    memcpy(facs, &Facs, sizeof(struct acpi_20_facs));
    offset += align16(sizeof(struct acpi_20_facs));

    dsdt = (unsigned char *)&buf[offset];
    memcpy(dsdt, &Dsdt, DsdtLen);
    offset += align16(DsdtLen);

    /*
     * N.B. ACPI 1.0 operating systems may not handle FADT with revision 2
     * or above properly, notably Windows 2000, which tries to copy FADT
     * into a 116 bytes buffer thus causing an overflow. The solution is to
     * link the higher revision FADT with the XSDT only and introduce a
     * compatible revision 1 FADT that is linked with the RSDT. Refer to:
     *     http://www.acpi.info/presentations/S01USMOBS169_OS%20new.ppt
     */
    fadt_10 = (struct acpi_10_fadt *)&buf[offset];
    memcpy(fadt_10, &Fadt, sizeof(struct acpi_10_fadt));
    offset += align16(sizeof(struct acpi_10_fadt));
    fadt_10->header.length = sizeof(struct acpi_10_fadt);
    fadt_10->header.revision = ACPI_1_0_FADT_REVISION;
    fadt_10->dsdt          = (unsigned long)dsdt;
    fadt_10->firmware_ctrl = (unsigned long)facs;
    set_checksum(fadt_10,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_10_fadt));

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
    rsdt->entry[0] = (unsigned long)fadt_10;
    for ( i = 0; secondary_tables[i]; i++ )
        rsdt->entry[i+1] = secondary_tables[i];
    rsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint32_t);
    offset += align16(rsdt->header.length);
    set_checksum(rsdt,
                 offsetof(struct acpi_header, checksum),
                 rsdt->header.length);

    *high_sz = offset;

    /*
     * Fill in low-memory data structures: bios_info_table and RSDP.
     */

    buf = (uint8_t *)ACPI_PHYSICAL_ADDRESS;
    offset = 0;

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

    *low_sz = offset;
}

void acpi_build_tables(void)
{
    int high_sz, low_sz;
    uint8_t *buf;

    /* Find out size of high-memory ACPI data area. */
    buf = (uint8_t *)&_end;
    __acpi_build_tables(buf, &low_sz, &high_sz);
    memset(buf, 0, high_sz);

    /* Allocate data area and set up ACPI tables there. */
    buf = mem_alloc(high_sz, 0);
    __acpi_build_tables(buf, &low_sz, &high_sz);

    printf(" - Lo data: %08lx-%08lx\n"
           " - Hi data: %08lx-%08lx\n",
           (unsigned long)ACPI_PHYSICAL_ADDRESS,
           (unsigned long)ACPI_PHYSICAL_ADDRESS + low_sz - 1,
           (unsigned long)buf, (unsigned long)buf + high_sz - 1);
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
