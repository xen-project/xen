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
#include "acpi_madt.h"

//
// Multiple APIC Description Table
//

ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE Madt = {
		{
				{
						ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE,
						sizeof (ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE),
						ACPI_2_0_MADT_REVISION,
						0x00,  // Checksum
						ACPI_OEM_ID, 
						ACPI_OEM_TABLE_ID,  
						ACPI_OEM_REVISION, 
						ACPI_CREATOR_ID,  
						ACPI_CREATOR_REVISION, 
				},
				ACPI_LOCAL_APIC_ADDRESS,
				ACPI_MULTIPLE_APIC_FLAGS,
		},
	
		//
		// IO APIC
		// 
		{
				{
						ACPI_IO_APIC,                         
						sizeof (ACPI_IO_APIC_STRUCTURE),  
						0x00,                                     
						0x00,                   
						ACPI_IO_APIC_ADDRESS_1,
						0x0000
				}
		},

		//
		// LOCAL APIC Entries for up to 32 processors.
		//
		{
				{
						ACPI_PROCESSOR_LOCAL_APIC,
						sizeof (ACPI_LOCAL_APIC_STRUCTURE),
						0x00,
						0x00,
						0x00000001,
				}

		}
};
