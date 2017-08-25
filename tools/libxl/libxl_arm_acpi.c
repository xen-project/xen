/*
 * ARM DomU ACPI generation
 *
 * Copyright (C) 2016      Linaro Ltd.
 *
 * Author: Shannon Zhao <shannon.zhao@linaro.org>
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

#include "libxl_arm.h"

#include <stdint.h>

/* Below typedefs are useful for the headers under acpi/ */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

#include <acpi/acconfig.h>
#include <acpi/actbl.h>

#ifndef BITS_PER_LONG
#ifdef _LP64
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif
#endif
#define ACPI_MACHINE_WIDTH BITS_PER_LONG
#define COMPILER_DEPENDENT_INT64 int64_t
#define COMPILER_DEPENDENT_UINT64 uint64_t

#include <acpi/actypes.h>

_hidden
extern const unsigned char dsdt_anycpu_arm[];
_hidden
extern const int dsdt_anycpu_arm_len;

#define ACPI_OEM_ID "Xen"
#define ACPI_OEM_TABLE_ID "ARM"
#define ACPI_ASL_COMPILER_ID "XL"

enum {
    RSDP,
    XSDT,
    GTDT,
    MADT,
    FADT,
    DSDT,
    MAX_TABLE_NUMS,
};

struct acpitable {
    uint64_t addr;
    size_t size;
};

static int libxl__estimate_madt_size(libxl__gc *gc,
                                     const libxl_domain_build_info *info,
                                     size_t *size)
{
    int rc = 0;

    switch (info->arch_arm.gic_version) {
    case LIBXL_GIC_VERSION_V2:
        *size = sizeof(struct acpi_table_madt) +
                ACPI_MADT_GICC_SIZE_v5 * info->max_vcpus +
                sizeof(struct acpi_madt_generic_distributor);
        break;
    case LIBXL_GIC_VERSION_V3:
        *size = sizeof(struct acpi_table_madt) +
                ACPI_MADT_GICC_SIZE_v5 * info->max_vcpus +
                sizeof(struct acpi_madt_generic_distributor) +
                sizeof(struct acpi_madt_generic_redistributor);
        break;
    default:
        LOG(ERROR, "Unknown GIC version");
        *size = 0;
        rc = ERROR_FAIL;
        break;
    }

    return rc;
}

int libxl__get_acpi_size(libxl__gc *gc,
                         const libxl_domain_build_info *info,
                         uint64_t *out)
{
    uint64_t size;
    int rc = 0;


    rc = libxl__estimate_madt_size(gc, info, &size);
    if (rc < 0)
        goto out;

    *out = ROUNDUP(size, 3) +
           ROUNDUP(sizeof(struct acpi_table_rsdp), 3) +
           ROUNDUP(sizeof(struct acpi_table_xsdt), 3) +
           ROUNDUP(sizeof(struct acpi_table_gtdt), 3) +
           ROUNDUP(sizeof(struct acpi_table_fadt), 3) +
           ROUNDUP(sizeof(dsdt_anycpu_arm_len), 3);

out:
    return rc;
}

static int libxl__allocate_acpi_tables(libxl__gc *gc,
                                       libxl_domain_build_info *info,
                                       struct xc_dom_image *dom,
                                       struct acpitable acpitables[])
{
    int rc;
    size_t size;

    acpitables[RSDP].addr = GUEST_ACPI_BASE;
    acpitables[RSDP].size = sizeof(struct acpi_table_rsdp);
    dom->acpi_modules[0].length += ROUNDUP(acpitables[RSDP].size, 3);

    acpitables[XSDT].addr = GUEST_ACPI_BASE + dom->acpi_modules[0].length;
    /*
     * Currently only 3 tables(GTDT, FADT, MADT) are pointed by XSDT. Alloc
     * entries for them.
     */
    acpitables[XSDT].size = sizeof(struct acpi_table_xsdt) +
                            sizeof(uint64_t) * 2;
    dom->acpi_modules[0].length += ROUNDUP(acpitables[XSDT].size, 3);

    acpitables[GTDT].addr = GUEST_ACPI_BASE + dom->acpi_modules[0].length;
    acpitables[GTDT].size = sizeof(struct acpi_table_gtdt);
    dom->acpi_modules[0].length += ROUNDUP(acpitables[GTDT].size, 3);

    acpitables[MADT].addr = GUEST_ACPI_BASE + dom->acpi_modules[0].length;

    rc = libxl__estimate_madt_size(gc, info, &size);
    if (rc < 0)
        goto out;

    acpitables[MADT].size = size;
    dom->acpi_modules[0].length += ROUNDUP(acpitables[MADT].size, 3);

    acpitables[FADT].addr = GUEST_ACPI_BASE + dom->acpi_modules[0].length;
    acpitables[FADT].size = sizeof(struct acpi_table_fadt);
    dom->acpi_modules[0].length += ROUNDUP(acpitables[FADT].size, 3);

    acpitables[DSDT].addr = GUEST_ACPI_BASE + dom->acpi_modules[0].length;
    acpitables[DSDT].size = dsdt_anycpu_arm_len;
    dom->acpi_modules[0].length += ROUNDUP(acpitables[DSDT].size, 3);

    assert(dom->acpi_modules[0].length <= GUEST_ACPI_SIZE);
    dom->acpi_modules[0].data = libxl__zalloc(gc, dom->acpi_modules[0].length);

    rc = 0;
out:
    return rc;
}

static void calculate_checksum(void *table, uint32_t checksum_offset,
                               uint32_t length)
{
    uint8_t *p, sum = 0;

    p = table;
    p[checksum_offset] = 0;

    while (length--)
        sum = sum + *p++;

    p = table;
    p[checksum_offset] = -sum;
}

static void make_acpi_rsdp(libxl__gc *gc, struct xc_dom_image *dom,
                           struct acpitable acpitables[])
{
    uint64_t offset = acpitables[RSDP].addr - GUEST_ACPI_BASE;
    struct acpi_table_rsdp *rsdp = (void *)dom->acpi_modules[0].data + offset;

    memcpy(rsdp->signature, "RSD PTR ", sizeof(rsdp->signature));
    memcpy(rsdp->oem_id, ACPI_OEM_ID, sizeof(rsdp->oem_id));
    rsdp->length = acpitables[RSDP].size;
    rsdp->revision = 0x02;
    rsdp->xsdt_physical_address = acpitables[XSDT].addr;
    calculate_checksum(rsdp,
                       offsetof(struct acpi_table_rsdp, extended_checksum),
                       acpitables[RSDP].size);
}

static void make_acpi_header(struct acpi_table_header *h, const char *sig,
                             size_t len, uint8_t rev)
{
    memcpy(h->signature, sig, 4);
    h->length = len;
    h->revision = rev;
    memcpy(h->oem_id, ACPI_OEM_ID, sizeof(h->oem_id));
    memcpy(h->oem_table_id, ACPI_OEM_TABLE_ID, sizeof(h->oem_table_id));
    h->oem_revision = 0;
    memcpy(h->asl_compiler_id, ACPI_ASL_COMPILER_ID,
           sizeof(h->asl_compiler_id));
    h->asl_compiler_revision = 0;
    h->checksum = 0;
}

static void make_acpi_xsdt(libxl__gc *gc, struct xc_dom_image *dom,
                           struct acpitable acpitables[])
{
    uint64_t offset = acpitables[XSDT].addr - GUEST_ACPI_BASE;
    struct acpi_table_xsdt *xsdt = (void *)dom->acpi_modules[0].data + offset;

    xsdt->table_offset_entry[0] = acpitables[MADT].addr;
    xsdt->table_offset_entry[1] = acpitables[GTDT].addr;
    xsdt->table_offset_entry[2] = acpitables[FADT].addr;
    make_acpi_header(&xsdt->header, "XSDT", acpitables[XSDT].size, 1);
    calculate_checksum(xsdt, offsetof(struct acpi_table_header, checksum),
                       acpitables[XSDT].size);
}

static void make_acpi_gtdt(libxl__gc *gc, struct xc_dom_image *dom,
                           struct acpitable acpitables[])
{
    uint64_t offset = acpitables[GTDT].addr - GUEST_ACPI_BASE;
    struct acpi_table_gtdt *gtdt = (void *)dom->acpi_modules[0].data + offset;

    gtdt->non_secure_el1_interrupt = GUEST_TIMER_PHYS_NS_PPI;
    gtdt->non_secure_el1_flags =
                             (ACPI_LEVEL_SENSITIVE << ACPI_GTDT_INTERRUPT_MODE)
                             |(ACPI_ACTIVE_LOW << ACPI_GTDT_INTERRUPT_POLARITY);
    gtdt->virtual_timer_interrupt = GUEST_TIMER_VIRT_PPI;
    gtdt->virtual_timer_flags =
                             (ACPI_LEVEL_SENSITIVE << ACPI_GTDT_INTERRUPT_MODE)
                             |(ACPI_ACTIVE_LOW << ACPI_GTDT_INTERRUPT_POLARITY);

    gtdt->counter_block_addresss = ~((uint64_t)0);
    gtdt->counter_read_block_address = ~((uint64_t)0);

    make_acpi_header(&gtdt->header, "GTDT", acpitables[GTDT].size, 2);
    calculate_checksum(gtdt, offsetof(struct acpi_table_header, checksum),
                       acpitables[GTDT].size);
}

static void make_acpi_madt_gicc(void *table, int nr_cpus, uint64_t gicc_base)
{
    int i;
    struct acpi_madt_generic_interrupt *gicc = table;

    for (i = 0; i < nr_cpus; i++) {
        gicc->header.type = ACPI_MADT_TYPE_GENERIC_INTERRUPT;
        gicc->header.length = ACPI_MADT_GICC_SIZE_v5;
        gicc->base_address = gicc_base;
        gicc->cpu_interface_number = i;
        gicc->arm_mpidr = libxl__compute_mpdir(i);
        gicc->uid = i;
        gicc->flags = ACPI_MADT_ENABLED;
        gicc = table + ACPI_MADT_GICC_SIZE_v5;
    }
}

static void make_acpi_madt_gicd(void *table, uint64_t gicd_base,
                                uint8_t gic_version)
{
    struct acpi_madt_generic_distributor *gicd = table;

    gicd->header.type = ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR;
    gicd->header.length = sizeof(*gicd);
    gicd->base_address = gicd_base;
    /* This version field has no meaning before ACPI 5.1 errata. */
    gicd->version = gic_version;
}

static void make_acpi_madt_gicr(void *table, uint64_t gicr_base,
                                uint64_t gicr_size)
{
    struct acpi_madt_generic_redistributor *gicr = table;

    gicr->header.type = ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR;
    gicr->header.length = sizeof(*gicr);
    gicr->base_address = gicr_base;
    gicr->length = gicr_size;
}

static int make_acpi_madt(libxl__gc *gc, struct xc_dom_image *dom,
                          libxl_domain_build_info *info,
                          struct acpitable acpitables[])
{
    uint64_t offset = acpitables[MADT].addr - GUEST_ACPI_BASE;
    void *table = dom->acpi_modules[0].data + offset;
    struct acpi_table_madt *madt = table;
    int rc = 0;

    switch (info->arch_arm.gic_version) {
    case LIBXL_GIC_VERSION_V2:
        table += sizeof(struct acpi_table_madt);
        make_acpi_madt_gicc(table, info->max_vcpus, GUEST_GICC_BASE);

        table += ACPI_MADT_GICC_SIZE_v5 * info->max_vcpus;
        make_acpi_madt_gicd(table, GUEST_GICD_BASE, ACPI_MADT_GIC_VERSION_V2);
        break;
    case LIBXL_GIC_VERSION_V3:
        table += sizeof(struct acpi_table_madt);
        make_acpi_madt_gicc(table, info->max_vcpus, 0);

        table += ACPI_MADT_GICC_SIZE_v5 * info->max_vcpus;
        make_acpi_madt_gicd(table, GUEST_GICV3_GICD_BASE,
                            ACPI_MADT_GIC_VERSION_V3);

        table += sizeof(struct acpi_madt_generic_distributor);
        make_acpi_madt_gicr(table, GUEST_GICV3_GICR0_BASE,
                            GUEST_GICV3_GICR0_SIZE);
        break;
    default:
        LOG(ERROR, "Unknown GIC version");
        rc = ERROR_FAIL;
        goto out;
    }

    make_acpi_header(&madt->header, "APIC", acpitables[MADT].size, 3);
    calculate_checksum(madt, offsetof(struct acpi_table_header, checksum),
                       acpitables[MADT].size);

out:
    return rc;
}

static void make_acpi_fadt(libxl__gc *gc, struct xc_dom_image *dom,
                           struct acpitable acpitables[])
{
    uint64_t offset = acpitables[FADT].addr - GUEST_ACPI_BASE;
    struct acpi_table_fadt *fadt = (void *)dom->acpi_modules[0].data + offset;

    /* Hardware Reduced = 1 and use PSCI 0.2+ and with HVC */
    fadt->flags = ACPI_FADT_HW_REDUCED;
    fadt->arm_boot_flags = ACPI_FADT_PSCI_COMPLIANT | ACPI_FADT_PSCI_USE_HVC;

    /* ACPI v5.1 (fadt->revision.fadt->minor_revision) */
    fadt->minor_revision = 0x1;
    fadt->dsdt = acpitables[DSDT].addr;

    make_acpi_header(&fadt->header, "FACP", acpitables[FADT].size, 5);
    calculate_checksum(fadt, offsetof(struct acpi_table_header, checksum),
                       acpitables[FADT].size);
}

static void make_acpi_dsdt(libxl__gc *gc, struct xc_dom_image *dom,
                           struct acpitable acpitables[])
{
    uint64_t offset = acpitables[DSDT].addr - GUEST_ACPI_BASE;
    void *dsdt = dom->acpi_modules[0].data + offset;

    memcpy(dsdt, dsdt_anycpu_arm, dsdt_anycpu_arm_len);
}

int libxl__prepare_acpi(libxl__gc *gc, libxl_domain_build_info *info,
                        struct xc_dom_image *dom)
{
    const libxl_version_info *vers;
    int rc = 0;
    struct acpitable acpitables[MAX_TABLE_NUMS];

    vers = libxl_get_version_info(CTX);
    if (vers == NULL) {
        rc = ERROR_FAIL;
        goto out;
    }

    LOG(DEBUG, "constructing ACPI tables for Xen version %d.%d guest",
        vers->xen_version_major, vers->xen_version_minor);

    dom->acpi_modules[0].data = NULL;
    dom->acpi_modules[0].length = 0;
    dom->acpi_modules[0].guest_addr_out = GUEST_ACPI_BASE;

    rc = libxl__allocate_acpi_tables(gc, info, dom, acpitables);
    if (rc)
        goto out;

    make_acpi_rsdp(gc, dom, acpitables);
    make_acpi_xsdt(gc, dom, acpitables);
    make_acpi_gtdt(gc, dom, acpitables);
    rc = make_acpi_madt(gc, dom, info, acpitables);
    if (rc)
        goto out;

    make_acpi_fadt(gc, dom, acpitables);
    make_acpi_dsdt(gc, dom, acpitables);

out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
