/*
 * acpi_madt.c: Update ACPI MADT table for multiple processor guest.
 *
 * Yu Ke, ke.yu@intel.com
 * Copyright (c) 2005, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "acpi/acpi2_0.h"
#include "util.h"
#include "acpi_utils.h"
#include <xen/hvm/hvm_info_table.h>

#define NULL ((void*)0)

static struct hvm_info_table *table = NULL;

static int validate_hvm_info(struct hvm_info_table *t)
{
    char signature[] = "HVM INFO";
    uint8_t *ptr = (uint8_t *)t;
    uint8_t sum = 0;
    int i;

    /* strncmp(t->signature, "HVM INFO", 8) */
    for (i = 0; i < 8; i++) {
        if (signature[i] != t->signature[i]) {
            puts("Bad hvm info signature\n");
            return 0;
        }
    }

    for (i = 0; i < t->length; i++)
        sum += ptr[i];

    return (sum == 0);
}

/* xc_vmx_builder wrote hvm info at 0x9F800. Return it. */
struct hvm_info_table *
get_hvm_info_table(void)
{
    struct hvm_info_table *t;

    if (table != NULL)
        return table;

    t = (struct hvm_info_table *)HVM_INFO_PADDR;

    if (!validate_hvm_info(t)) {
        puts("Bad hvm info table\n");
        return NULL;
    }

    table = t;

    return table;
}

int
get_vcpu_nr(void)
{
    struct hvm_info_table *t = get_hvm_info_table();
    return (t ? t->nr_vcpus : 1); /* default 1 vcpu */
}

int
get_acpi_enabled(void)
{
    struct hvm_info_table *t = get_hvm_info_table();
    return (t ? t->acpi_enabled : 0); /* default no acpi */
}


static void *
acpi_madt_get_madt(unsigned char *acpi_start)
{
    struct acpi_20_rsdt *rsdt;
    struct acpi_20_madt *madt;

    rsdt = acpi_rsdt_get(acpi_start);
    if (rsdt == NULL)
        return NULL;

    madt = (struct acpi_20_madt *)(acpi_start + rsdt->entry[1] -
                                   ACPI_PHYSICAL_ADDRESS);
    if (madt->header.header.signature != ACPI_2_0_MADT_SIGNATURE) {
        puts("Bad MADT signature \n");
        return NULL;
    }

    return madt;
}

static int
acpi_madt_set_local_apics(
    int nr_vcpu,
    struct acpi_20_madt *madt)
{
    int i;

    if ((nr_vcpu > MAX_VIRT_CPUS) || (nr_vcpu < 0) || !madt)
        return -1;

    for (i = 0; i < nr_vcpu; i++) {
        madt->lapic[i].type    = ACPI_PROCESSOR_LOCAL_APIC;
        madt->lapic[i].length  = sizeof(struct acpi_20_madt_lapic);
        madt->lapic[i].acpi_processor_id = i;
        madt->lapic[i].apic_id = i;
        madt->lapic[i].flags   = 1;
    }

    madt->header.header.length =
        sizeof(struct acpi_20_madt) -
        (MAX_VIRT_CPUS - nr_vcpu) * sizeof(struct acpi_20_madt_lapic);

    return 0;
}

#define FIELD_OFFSET(TYPE,Field) ((unsigned int)(&(((TYPE *) 0)->Field)))

int acpi_madt_update(unsigned char *acpi_start)
{
    int rc;
    struct acpi_20_madt *madt;

    madt = acpi_madt_get_madt(acpi_start);
    if (!madt)
        return -1;

    rc = acpi_madt_set_local_apics(get_vcpu_nr(), madt);
    if (rc != 0)
        return rc;

    set_checksum(
        madt, FIELD_OFFSET(struct acpi_header, checksum),
        madt->header.header.length);

    return 0;
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
