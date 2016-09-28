/*
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
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

#include LIBACPI_STDUTILS
#include "acpi2_0.h"
#include "libacpi.h"
#include "ssdt_s3.h"
#include "ssdt_s4.h"
#include "ssdt_tpm.h"
#include "ssdt_pm.h"
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/hvm_xs_strings.h>
#include <xen/hvm/params.h>
#include <xen/memory.h>

#define ACPI_MAX_SECONDARY_TABLES 16

#define align16(sz)        (((sz) + 15) & ~15)
#define fixed_strcpy(d, s) strncpy((d), (s), sizeof(d))

extern struct acpi_20_rsdp Rsdp;
extern struct acpi_20_rsdt Rsdt;
extern struct acpi_20_xsdt Xsdt;
extern struct acpi_20_fadt Fadt;
extern struct acpi_20_facs Facs;
extern struct acpi_20_waet Waet;

/*
 * Located at ACPI_INFO_PHYSICAL_ADDRESS.
 *
 * This must match the Field("BIOS"....) definition in the DSDT.
 */
struct acpi_info {
    uint8_t  com1_present:1;    /* 0[0] - System has COM1? */
    uint8_t  com2_present:1;    /* 0[1] - System has COM2? */
    uint8_t  lpt1_present:1;    /* 0[2] - System has LPT1? */
    uint8_t  hpet_present:1;    /* 0[3] - System has HPET? */
    uint16_t nr_cpus;           /* 2    - Number of CPUs */
    uint32_t pci_min, pci_len;  /* 4, 8 - PCI I/O hole boundaries */
    uint32_t madt_csum_addr;    /* 12   - Address of MADT checksum */
    uint32_t madt_lapic0_addr;  /* 16   - Address of first MADT LAPIC struct */
    uint32_t vm_gid_addr;       /* 20   - Address of VM generation id buffer */
    uint64_t pci_hi_min, pci_hi_len; /* 24, 32 - PCI I/O hole boundaries */
};

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

static struct acpi_20_madt *construct_madt(struct acpi_ctxt *ctxt,
                                           const struct acpi_config *config,
                                           struct acpi_info *info)
{
    struct acpi_20_madt           *madt;
    struct acpi_20_madt_intsrcovr *intsrcovr;
    struct acpi_20_madt_ioapic    *io_apic;
    struct acpi_20_madt_lapic     *lapic;
    const struct hvm_info_table   *hvminfo = config->hvminfo;
    int i, sz;

    if ( config->lapic_id == NULL )
        return NULL;

    sz  = sizeof(struct acpi_20_madt);
    sz += sizeof(struct acpi_20_madt_intsrcovr) * 16;
    sz += sizeof(struct acpi_20_madt_ioapic);
    sz += sizeof(struct acpi_20_madt_lapic) * hvminfo->nr_vcpus;

    madt = ctxt->mem_ops.alloc(ctxt, sz, 16);
    if (!madt) return NULL;

    memset(madt, 0, sizeof(*madt));
    madt->header.signature    = ACPI_2_0_MADT_SIGNATURE;
    madt->header.revision     = ACPI_2_0_MADT_REVISION;
    fixed_strcpy(madt->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(madt->header.oem_table_id, ACPI_OEM_TABLE_ID);
    madt->header.oem_revision = ACPI_OEM_REVISION;
    madt->header.creator_id   = ACPI_CREATOR_ID;
    madt->header.creator_revision = ACPI_CREATOR_REVISION;
    madt->lapic_addr = config->lapic_base_address;
    madt->flags      = ACPI_PCAT_COMPAT;

    if ( config->table_flags & ACPI_HAS_IOAPIC )
    {     
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
            else if ( config->pci_isa_irq_mask & (1U << i) )
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

            intsrcovr++;
        }

        io_apic = (struct acpi_20_madt_ioapic *)intsrcovr;
        memset(io_apic, 0, sizeof(*io_apic));
        io_apic->type        = ACPI_IO_APIC;
        io_apic->length      = sizeof(*io_apic);
        io_apic->ioapic_id   = config->ioapic_id;
        io_apic->ioapic_addr = config->ioapic_base_address;

        lapic = (struct acpi_20_madt_lapic *)(io_apic + 1);
    }
    else
        lapic = (struct acpi_20_madt_lapic *)(madt + 1);

    info->nr_cpus = hvminfo->nr_vcpus;
    info->madt_lapic0_addr = ctxt->mem_ops.v2p(ctxt, lapic);
    for ( i = 0; i < hvminfo->nr_vcpus; i++ )
    {
        memset(lapic, 0, sizeof(*lapic));
        lapic->type    = ACPI_PROCESSOR_LOCAL_APIC;
        lapic->length  = sizeof(*lapic);
        /* Processor ID must match processor-object IDs in the DSDT. */
        lapic->acpi_processor_id = i;
        lapic->apic_id = config->lapic_id(i);
        lapic->flags = (test_bit(i, hvminfo->vcpu_online)
                        ? ACPI_LOCAL_APIC_ENABLED : 0);
        lapic++;
    }

    madt->header.length = (unsigned char *)lapic - (unsigned char *)madt;
    set_checksum(madt, offsetof(struct acpi_header, checksum),
                 madt->header.length);
    info->madt_csum_addr =
        ctxt->mem_ops.v2p(ctxt, &madt->header.checksum);

    return madt;
}

static struct acpi_20_hpet *construct_hpet(struct acpi_ctxt *ctxt,
                                           const struct acpi_config *config)
{
    struct acpi_20_hpet *hpet;

    hpet = ctxt->mem_ops.alloc(ctxt, sizeof(*hpet), 16);
    if (!hpet) return NULL;

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

    hpet->header.length = sizeof(*hpet);
    set_checksum(hpet, offsetof(struct acpi_header, checksum), sizeof(*hpet));
    return hpet;
}

static struct acpi_20_waet *construct_waet(struct acpi_ctxt *ctxt,
                                           const struct acpi_config *config)
{
    struct acpi_20_waet *waet;

    waet = ctxt->mem_ops.alloc(ctxt, sizeof(*waet), 16);
    if (!waet) return NULL;

    memcpy(waet, &Waet, sizeof(*waet));

    waet->header.length = sizeof(*waet);
    set_checksum(waet, offsetof(struct acpi_header, checksum), sizeof(*waet));

    return waet;
}

static struct acpi_20_srat *construct_srat(struct acpi_ctxt *ctxt,
                                           const struct acpi_config *config)
{
    struct acpi_20_srat *srat;
    struct acpi_20_srat_processor *processor;
    struct acpi_20_srat_memory *memory;
    unsigned int size;
    void *p;
    unsigned int i;

    size = sizeof(*srat) + sizeof(*processor) * config->hvminfo->nr_vcpus +
           sizeof(*memory) * config->numa.nr_vmemranges;

    p = ctxt->mem_ops.alloc(ctxt, size, 16);
    if ( !p )
        return NULL;

    srat = memset(p, 0, size);
    srat->header.signature    = ACPI_2_0_SRAT_SIGNATURE;
    srat->header.revision     = ACPI_2_0_SRAT_REVISION;
    fixed_strcpy(srat->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(srat->header.oem_table_id, ACPI_OEM_TABLE_ID);
    srat->header.oem_revision = ACPI_OEM_REVISION;
    srat->header.creator_id   = ACPI_CREATOR_ID;
    srat->header.creator_revision = ACPI_CREATOR_REVISION;
    srat->table_revision      = ACPI_SRAT_TABLE_REVISION;

    processor = (struct acpi_20_srat_processor *)(srat + 1);
    for ( i = 0; i < config->hvminfo->nr_vcpus; i++ )
    {
        processor->type     = ACPI_PROCESSOR_AFFINITY;
        processor->length   = sizeof(*processor);
        processor->domain   = config->numa.vcpu_to_vnode[i];
        processor->apic_id  = config->lapic_id(i);
        processor->flags    = ACPI_LOCAL_APIC_AFFIN_ENABLED;
        processor++;
    }

    memory = (struct acpi_20_srat_memory *)processor;
    for ( i = 0; i < config->numa.nr_vmemranges; i++ )
    {
        memory->type          = ACPI_MEMORY_AFFINITY;
        memory->length        = sizeof(*memory);
        memory->domain        = config->numa.vmemrange[i].nid;
        memory->flags         = ACPI_MEM_AFFIN_ENABLED;
        memory->base_address  = config->numa.vmemrange[i].start;
        memory->mem_length    = config->numa.vmemrange[i].end -
                                config->numa.vmemrange[i].start;
        memory++;
    }

    ASSERT(((unsigned long)memory) - ((unsigned long)p) == size);

    srat->header.length = size;
    set_checksum(srat, offsetof(struct acpi_header, checksum), size);

    return srat;
}

static struct acpi_20_slit *construct_slit(struct acpi_ctxt *ctxt,
                                           const struct acpi_config *config)
{
    struct acpi_20_slit *slit;
    unsigned int i, num, size;

    num = config->numa.nr_vnodes * config->numa.nr_vnodes;
    size = sizeof(*slit) + num * sizeof(uint8_t);

    slit = ctxt->mem_ops.alloc(ctxt, size, 16);
    if ( !slit )
        return NULL;

    memset(slit, 0, size);
    slit->header.signature    = ACPI_2_0_SLIT_SIGNATURE;
    slit->header.revision     = ACPI_2_0_SLIT_REVISION;
    fixed_strcpy(slit->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(slit->header.oem_table_id, ACPI_OEM_TABLE_ID);
    slit->header.oem_revision = ACPI_OEM_REVISION;
    slit->header.creator_id   = ACPI_CREATOR_ID;
    slit->header.creator_revision = ACPI_CREATOR_REVISION;

    for ( i = 0; i < num; i++ )
        slit->entry[i] = config->numa.vdistance[i];

    slit->localities = config->numa.nr_vnodes;

    slit->header.length = size;
    set_checksum(slit, offsetof(struct acpi_header, checksum), size);

    return slit;
}

static int construct_passthrough_tables(struct acpi_ctxt *ctxt,
                                        unsigned long *table_ptrs,
                                        int nr_tables,
                                        struct acpi_config *config)
{
    unsigned long pt_addr;
    struct acpi_header *header;
    int nr_added;
    int nr_max = (ACPI_MAX_SECONDARY_TABLES - nr_tables - 1);
    uint32_t total = 0;
    uint8_t *buffer;

    if ( config->pt.addr == 0 )
        return 0;

    pt_addr = config->pt.addr;

    for ( nr_added = 0; nr_added < nr_max; nr_added++ )
    {        
        if ( (config->pt.length - total) < sizeof(struct acpi_header) )
            break;

        header = (struct acpi_header*)pt_addr;

        buffer = ctxt->mem_ops.alloc(ctxt, header->length, 16);
        if ( buffer == NULL )
            break;
        memcpy(buffer, header, header->length);

        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, buffer);
        total += header->length;
        pt_addr += header->length;
    }

    return nr_added;
}

static int construct_secondary_tables(struct acpi_ctxt *ctxt,
                                      unsigned long *table_ptrs,
                                      struct acpi_config *config,
                                      struct acpi_info *info)
{
    int nr_tables = 0;
    struct acpi_20_madt *madt;
    struct acpi_20_hpet *hpet;
    struct acpi_20_waet *waet;
    struct acpi_20_tcpa *tcpa;
    unsigned char *ssdt;
    static const uint16_t tis_signature[] = {0x0001, 0x0001, 0x0001};
    void *lasa;

    /* MADT. */
    if ( (config->hvminfo->nr_vcpus > 1) || config->hvminfo->apic_mode )
    {
        madt = construct_madt(ctxt, config, info);
        if (!madt) return -1;
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, madt);
    }

    /* HPET. */
    if ( info->hpet_present )
    {
        hpet = construct_hpet(ctxt, config);
        if (!hpet) return -1;
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, hpet);
    }

    /* WAET. */
    if ( config->table_flags & ACPI_HAS_WAET )
    {
        waet = construct_waet(ctxt, config);
        if ( !waet )
            return -1;
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, waet);
    }

    if ( config->table_flags & ACPI_HAS_SSDT_PM )
    {
        ssdt = ctxt->mem_ops.alloc(ctxt, sizeof(ssdt_pm), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_pm, sizeof(ssdt_pm));
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, ssdt);
    }

    if ( config->table_flags & ACPI_HAS_SSDT_S3 )
    {
        ssdt = ctxt->mem_ops.alloc(ctxt, sizeof(ssdt_s3), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_s3, sizeof(ssdt_s3));
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, ssdt);
    } else {
        printf("S3 disabled\n");
    }

    if ( config->table_flags & ACPI_HAS_SSDT_S4 )
    {
        ssdt = ctxt->mem_ops.alloc(ctxt, sizeof(ssdt_s4), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_s4, sizeof(ssdt_s4));
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, ssdt);
    } else {
        printf("S4 disabled\n");
    }

    /* TPM TCPA and SSDT. */
    if ( (config->table_flags & ACPI_HAS_TCPA) &&
         (config->tis_hdr[0] == tis_signature[0]) &&
         (config->tis_hdr[1] == tis_signature[1]) &&
         (config->tis_hdr[2] == tis_signature[2]) )
    {
        ssdt = ctxt->mem_ops.alloc(ctxt, sizeof(ssdt_tpm), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_tpm, sizeof(ssdt_tpm));
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, ssdt);

        tcpa = ctxt->mem_ops.alloc(ctxt, sizeof(struct acpi_20_tcpa), 16);
        if (!tcpa) return -1;
        memset(tcpa, 0, sizeof(*tcpa));
        table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, tcpa);

        tcpa->header.signature = ACPI_2_0_TCPA_SIGNATURE;
        tcpa->header.length    = sizeof(*tcpa);
        tcpa->header.revision  = ACPI_2_0_TCPA_REVISION;
        fixed_strcpy(tcpa->header.oem_id, ACPI_OEM_ID);
        fixed_strcpy(tcpa->header.oem_table_id, ACPI_OEM_TABLE_ID);
        tcpa->header.oem_revision = ACPI_OEM_REVISION;
        tcpa->header.creator_id   = ACPI_CREATOR_ID;
        tcpa->header.creator_revision = ACPI_CREATOR_REVISION;
        if ( (lasa = ctxt->mem_ops.alloc(ctxt, ACPI_2_0_TCPA_LAML_SIZE, 16)) != NULL )
        {
            tcpa->lasa = ctxt->mem_ops.v2p(ctxt, lasa);
            tcpa->laml = ACPI_2_0_TCPA_LAML_SIZE;
            memset(lasa, 0, tcpa->laml);
            set_checksum(tcpa,
                         offsetof(struct acpi_header, checksum),
                         tcpa->header.length);
        }
    }

    /* SRAT and SLIT */
    if ( config->numa.nr_vnodes > 0 )
    {
        struct acpi_20_srat *srat = construct_srat(ctxt, config);
        struct acpi_20_slit *slit = construct_slit(ctxt, config);

        if ( srat )
            table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, srat);
        else
            printf("Failed to build SRAT, skipping...\n");
        if ( slit )
            table_ptrs[nr_tables++] = ctxt->mem_ops.v2p(ctxt, slit);
        else
            printf("Failed to build SLIT, skipping...\n");
    }

    /* Load any additional tables passed through. */
    nr_tables += construct_passthrough_tables(ctxt, table_ptrs,
                                              nr_tables, config);

    table_ptrs[nr_tables] = 0;
    return nr_tables;
}

/**
 * Allocate and initialize Windows Generation ID
 * If value is not present in the XenStore or if all zeroes
 * the device will be not active
 *
 * Return 0 if memory failure, != 0 if success
 */
static int new_vm_gid(struct acpi_ctxt *ctxt,
                      struct acpi_config *config,
                      struct acpi_info *info)
{
    uint64_t *buf;

    info->vm_gid_addr = 0;

    /* check for 0 ID*/
    if ( !config->vm_gid[0] && !config->vm_gid[1] )
        return 1;

    /* copy to allocate BIOS memory */
    buf = ctxt->mem_ops.alloc(ctxt, sizeof(config->vm_gid), 8);
    if ( !buf )
        return 0;
    memcpy(buf, config->vm_gid, sizeof(config->vm_gid));

    /* set the address into ACPI table and also pass it back to the caller */
    info->vm_gid_addr = ctxt->mem_ops.v2p(ctxt, buf);
    config->vm_gid_addr = info->vm_gid_addr;

    return 1;
}

int acpi_build_tables(struct acpi_ctxt *ctxt, struct acpi_config *config)
{
    struct acpi_info *acpi_info;
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_rsdt *rsdt;
    struct acpi_20_xsdt *xsdt;
    struct acpi_20_fadt *fadt;
    struct acpi_10_fadt *fadt_10;
    struct acpi_20_facs *facs;
    unsigned char       *dsdt;
    unsigned long        secondary_tables[ACPI_MAX_SECONDARY_TABLES];
    int                  nr_secondaries, i;

    acpi_info = (struct acpi_info *)config->infop;
    memset(acpi_info, 0, sizeof(*acpi_info));
    acpi_info->com1_present = !!(config->table_flags & ACPI_HAS_COM1);
    acpi_info->com2_present = !!(config->table_flags & ACPI_HAS_COM2);
    acpi_info->lpt1_present = !!(config->table_flags & ACPI_HAS_LPT1);
    acpi_info->hpet_present = !!(config->table_flags & ACPI_HAS_HPET);
    acpi_info->pci_min = config->pci_start;
    acpi_info->pci_len = config->pci_len;
    if ( config->pci_hi_len )
    {
        acpi_info->pci_hi_min = config->pci_hi_start;
        acpi_info->pci_hi_len = config->pci_hi_len;
    }

    /*
     * Fill in high-memory data structures, starting at @buf.
     */

    facs = ctxt->mem_ops.alloc(ctxt, sizeof(struct acpi_20_facs), 16);
    if (!facs) goto oom;
    memcpy(facs, &Facs, sizeof(struct acpi_20_facs));

    /*
     * Alternative DSDTs we get linked against. A cover-all DSDT for up to the
     * implementation-defined maximum number of VCPUs, and an alternative for use
     * when a guest can only have up to 15 VCPUs.
     *
     * The latter is required for Windows 2000, which experiences a BSOD of
     * KMODE_EXCEPTION_NOT_HANDLED if it sees more than 15 processor objects.
     */
    if ( config->hvminfo->nr_vcpus <= 15 && config->dsdt_15cpu)
    {
        dsdt = ctxt->mem_ops.alloc(ctxt, config->dsdt_15cpu_len, 16);
        if (!dsdt) goto oom;
        memcpy(dsdt, config->dsdt_15cpu, config->dsdt_15cpu_len);
    }
    else
    {
        dsdt = ctxt->mem_ops.alloc(ctxt, config->dsdt_anycpu_len, 16);
        if (!dsdt) goto oom;
        memcpy(dsdt, config->dsdt_anycpu, config->dsdt_anycpu_len);
    }

    /*
     * N.B. ACPI 1.0 operating systems may not handle FADT with revision 2
     * or above properly, notably Windows 2000, which tries to copy FADT
     * into a 116 bytes buffer thus causing an overflow. The solution is to
     * link the higher revision FADT with the XSDT only and introduce a
     * compatible revision 1 FADT that is linked with the RSDT. Refer to:
     *     http://www.acpi.info/presentations/S01USMOBS169_OS%20new.ppt
     */
    fadt_10 = ctxt->mem_ops.alloc(ctxt, sizeof(struct acpi_10_fadt), 16);
    if (!fadt_10) goto oom;
    memcpy(fadt_10, &Fadt, sizeof(struct acpi_10_fadt));
    fadt_10->header.length = sizeof(struct acpi_10_fadt);
    fadt_10->header.revision = ACPI_1_0_FADT_REVISION;
    fadt_10->dsdt          = ctxt->mem_ops.v2p(ctxt, dsdt);
    fadt_10->firmware_ctrl = ctxt->mem_ops.v2p(ctxt, facs);
    set_checksum(fadt_10,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_10_fadt));

    fadt = ctxt->mem_ops.alloc(ctxt, sizeof(struct acpi_20_fadt), 16);
    if (!fadt) goto oom;
    memcpy(fadt, &Fadt, sizeof(struct acpi_20_fadt));
    fadt->dsdt   = ctxt->mem_ops.v2p(ctxt, dsdt);
    fadt->x_dsdt = ctxt->mem_ops.v2p(ctxt, dsdt);
    fadt->firmware_ctrl   = ctxt->mem_ops.v2p(ctxt, facs);
    fadt->x_firmware_ctrl = ctxt->mem_ops.v2p(ctxt, facs);
    set_checksum(fadt,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_20_fadt));

    nr_secondaries = construct_secondary_tables(ctxt, secondary_tables,
                 config, acpi_info);
    if ( nr_secondaries < 0 )
        goto oom;

    xsdt = ctxt->mem_ops.alloc(ctxt, sizeof(struct acpi_20_xsdt) + 
                               sizeof(uint64_t) * nr_secondaries,
                               16);
    if (!xsdt) goto oom;
    memcpy(xsdt, &Xsdt, sizeof(struct acpi_header));
    xsdt->entry[0] = ctxt->mem_ops.v2p(ctxt, fadt);
    for ( i = 0; secondary_tables[i]; i++ )
        xsdt->entry[i+1] = secondary_tables[i];
    xsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint64_t);
    set_checksum(xsdt,
                 offsetof(struct acpi_header, checksum),
                 xsdt->header.length);

    rsdt = ctxt->mem_ops.alloc(ctxt, sizeof(struct acpi_20_rsdt) +
                               sizeof(uint32_t) * nr_secondaries,
                               16);
    if (!rsdt) goto oom;
    memcpy(rsdt, &Rsdt, sizeof(struct acpi_header));
    rsdt->entry[0] = ctxt->mem_ops.v2p(ctxt, fadt_10);
    for ( i = 0; secondary_tables[i]; i++ )
        rsdt->entry[i+1] = secondary_tables[i];
    rsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint32_t);
    set_checksum(rsdt,
                 offsetof(struct acpi_header, checksum),
                 rsdt->header.length);

    /*
     * Fill in low-memory data structures: acpi_info and RSDP.
     */
    rsdp = (struct acpi_20_rsdp *)config->rsdp;

    memcpy(rsdp, &Rsdp, sizeof(struct acpi_20_rsdp));
    rsdp->rsdt_address = ctxt->mem_ops.v2p(ctxt, rsdt);
    rsdp->xsdt_address = ctxt->mem_ops.v2p(ctxt, xsdt);
    set_checksum(rsdp,
                 offsetof(struct acpi_10_rsdp, checksum),
                 sizeof(struct acpi_10_rsdp));
    set_checksum(rsdp,
                 offsetof(struct acpi_20_rsdp, extended_checksum),
                 sizeof(struct acpi_20_rsdp));

    if ( !new_vm_gid(ctxt, config, acpi_info) )
        goto oom;

    return 0;

oom:
    printf("unable to build ACPI tables: out of memory\n");
    return -1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
