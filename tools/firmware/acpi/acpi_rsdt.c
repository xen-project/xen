/*
 * Copyright (c) 2004, Intel Corporation.
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
 *
 */
#include "acpi2_0.h"

ACPI_2_0_RSDT Rsdt={	
		{
				ACPI_2_0_RSDT_SIGNATURE,
				sizeof (ACPI_TABLE_HEADER), // udpated later
				ACPI_2_0_RSDT_REVISION,
				0x0, 				  //Checksum, updated later
				ACPI_OEM_ID, 
				ACPI_OEM_TABLE_ID,
				ACPI_OEM_REVISION,
				ACPI_CREATOR_ID,
				ACPI_CREATOR_REVISION,
		},
		{0x0, 0x0}
};

ACPI_2_0_XSDT Xsdt={
		{
				ACPI_2_0_XSDT_SIGNATURE,
				sizeof (ACPI_TABLE_HEADER),  //update later
				ACPI_2_0_XSDT_REVISION,
				0x0, 				  //Checksum, update later
				ACPI_OEM_ID, 
				ACPI_OEM_TABLE_ID,
				ACPI_OEM_REVISION,
				ACPI_CREATOR_ID,
				ACPI_CREATOR_REVISION,
		},
		{0x0, 0x0},
};


ACPI_2_0_RSDP Rsdp={
		ACPI_2_0_RSDP_SIGNATURE,
		0x00, // Checksum, updated in later
		ACPI_OEM_ID,  // OEM ID,
		ACPI_OEM_REVISION, 
		0x0, // RSDT address, updated later
		sizeof (ACPI_2_0_RSDP),
		0x0, // XSDT address, updated later
		0x0, // Extended Checksum, update later
		{
				0x0, // Reserved
				0x0, // Reserved
				0x0, // Reserved
		}
};



