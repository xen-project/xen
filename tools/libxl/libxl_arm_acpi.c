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

#include <acpi/acconfig.h>
#include <acpi/actbl.h>

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
        rc = ERROR_FAIL;
        break;
    }

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
