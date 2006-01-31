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

#include "../acpi/acpi2_0.h"
#include "../acpi/acpi_madt.h"

#include <xen/hvm/hvm_info_table.h>

#define NULL ((void*)0)

extern int puts(const char *s);

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
static struct hvm_info_table *
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
	ACPI_2_0_RSDP *rsdp=NULL;
	ACPI_2_0_RSDT *rsdt=NULL;
	ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE *madt;

	rsdp = (ACPI_2_0_RSDP *)(acpi_start + sizeof(ACPI_2_0_FACS));
	if (rsdp->Signature != ACPI_2_0_RSDP_SIGNATURE) {
		puts("Bad RSDP signature\n");
		return NULL;
	}

	rsdt= (ACPI_2_0_RSDT *)
		(acpi_start + rsdp->RsdtAddress - ACPI_PHYSICAL_ADDRESS);
	if (rsdt->Header.Signature != ACPI_2_0_RSDT_SIGNATURE) {
		puts("Bad RSDT signature\n");
		return NULL;
	}

	madt = (ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE *)
		( acpi_start+ rsdt->Entry[1] - ACPI_PHYSICAL_ADDRESS);
	if (madt->Header.Header.Signature !=
	    ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE) {
		puts("Bad MADT signature \n");
		return NULL;
	}

	return madt;
}

static void
set_checksum(void *start, int checksum_offset, int len)
{
	unsigned char sum = 0;
	unsigned char *ptr;

	ptr = start;
	ptr[checksum_offset] = 0;
	while (len--)
		sum += *ptr++;

	ptr = start;
	ptr[checksum_offset] = -sum;
}

static int
acpi_madt_set_local_apics(
	int nr_vcpu,
	ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE *madt)
{
	int i;

	if ((nr_vcpu > MAX_VIRT_CPUS) || (nr_vcpu < 0) || !madt)
		return -1;

	for (i = 0; i < nr_vcpu; i++) {
		madt->LocalApic[i].Type            = ACPI_PROCESSOR_LOCAL_APIC;
		madt->LocalApic[i].Length          = sizeof (ACPI_LOCAL_APIC_STRUCTURE);
		madt->LocalApic[i].AcpiProcessorId = i;
		madt->LocalApic[i].ApicId          = i;
		madt->LocalApic[i].Flags           = 1;
	}

	madt->Header.Header.Length =
		sizeof(ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE) -
		(MAX_VIRT_CPUS - nr_vcpu)* sizeof(ACPI_LOCAL_APIC_STRUCTURE);

	return 0;
}

#define FIELD_OFFSET(TYPE,Field) ((unsigned int)(&(((TYPE *) 0)->Field)))

int acpi_madt_update(unsigned char *acpi_start)
{
	int rc;
	ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE *madt;

	madt = acpi_madt_get_madt(acpi_start);
	if (!madt)
		return -1;

	rc = acpi_madt_set_local_apics(get_vcpu_nr(), madt);
	if (rc != 0)
		return rc;

	set_checksum(
		madt, FIELD_OFFSET(ACPI_TABLE_HEADER, Checksum),
		madt->Header.Header.Length);

	return 0;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
