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

#define NULL ((void*)0)

extern int puts(const char *s);

#define VCPU_NR_PAGE        0x0009F000
#define VCPU_NR_OFFSET      0x00000800
#define VCPU_MAGIC          0x76637075  /* "vcpu" */

/* xc_vmx_builder wrote vcpu block at 0x9F800. Return it. */
static int
get_vcpu_nr(void)
{
	unsigned int *vcpus;

	vcpus = (unsigned int *)(VCPU_NR_PAGE + VCPU_NR_OFFSET);
	if (vcpus[0] != VCPU_MAGIC) {
		puts("Bad vcpus magic, set vcpu number to 1 by default.\n");
		return 1;
	}

	return vcpus[1];
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
