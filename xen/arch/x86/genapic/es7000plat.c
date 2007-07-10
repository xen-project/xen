/*
 * Written by: Garry Forsgren, Unisys Corporation
 *             Natalie Protasevich, Unisys Corporation
 * Modified by: Raj Subrahmanian <raj.subrahmanian@unisys.com> Unisys Corp.
 * This file contains the code to configure and interface
 * with Unisys ES7000 series hardware system manager.
 *
 * Copyright (c) 2003 Unisys Corporation.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * Contact information: Unisys Corporation, Township Line & Union Meeting
 * Roads-A, Unisys Way, Blue Bell, Pennsylvania, 19424, or:
 *
 * http://www.unisys.com
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/string.h>
#include <xen/spinlock.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/acpi.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/apicdef.h>

#define	MIP_REG			1
#define	MIP_PSAI_REG		4

struct acpi_table_sdt {
	unsigned long pa;
	unsigned long count;
	struct {
		unsigned long pa;
		enum acpi_table_id id;
		unsigned long size;
	}	entry[50];
};

struct oem_table {
	struct acpi_table_header Header;
	u32 OEMTableAddr;
	u32 OEMTableSize;
};

int __init
parse_unisys_oem(char *oemptr)
{
	int                     i;
	int 			success = 0;
	unsigned char           type, size;
	char                    *tp = NULL;

	tp = oemptr;

	tp += 8;

	for (i=0; i <= 6; i++) {
		type = *tp++;
		size = *tp++;
		tp -= 2;
		switch (type) {
		case MIP_REG:
		case MIP_PSAI_REG:
			success++;
			break;
		default:
			break;
		}
		tp += size;
	}

	return (success >= 2);
}

int __init
find_unisys_acpi_oem_table(unsigned long *oem_addr)
{
	struct acpi_table_rsdp		*rsdp = NULL;
	unsigned long			rsdp_phys = 0;
	struct acpi_table_header 	*header = NULL;
	int				i;
	struct acpi_table_sdt		sdt = { 0 }; /* initialise sdt.count */

	rsdp_phys = acpi_find_rsdp();
	rsdp = __va(rsdp_phys);
	if (rsdp->rsdt_address) {
		struct acpi_table_rsdt	*mapped_rsdt = NULL;
		sdt.pa = rsdp->rsdt_address;

		header = (struct acpi_table_header *)
			__acpi_map_table(sdt.pa, sizeof(struct acpi_table_header));
		if (!header)
			return -ENODEV;

		sdt.count = (header->length - sizeof(struct acpi_table_header)) >> 3;
		mapped_rsdt = (struct acpi_table_rsdt *)
			__acpi_map_table(sdt.pa, header->length);
		if (!mapped_rsdt)
			return -ENODEV;

		header = &mapped_rsdt->header;

		for (i = 0; i < sdt.count; i++)
			sdt.entry[i].pa = (unsigned long) mapped_rsdt->entry[i];
	};
	for (i = 0; i < sdt.count; i++) {

		header = (struct acpi_table_header *)
			__acpi_map_table(sdt.entry[i].pa,
				sizeof(struct acpi_table_header));
		if (!header)
			continue;
		if (!strncmp((char *) &header->signature, "OEM1", 4)) {
			if (!strncmp((char *) &header->oem_id, "UNISYS", 6)) {
				void *addr;
				struct oem_table *t;
				acpi_table_print(header, sdt.entry[i].pa);
				t = (struct oem_table *) __acpi_map_table(sdt.entry[i].pa, header->length);
				addr = (void *) __acpi_map_table(t->OEMTableAddr, t->OEMTableSize);
				*oem_addr = (unsigned long) addr;
				return 0;
			}
		}
	}
	return -1;
}
