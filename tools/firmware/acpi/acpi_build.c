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
#include "acpi_madt.h"

extern ACPI_2_0_RSDP Rsdp;
extern ACPI_2_0_RSDT Rsdt;
extern ACPI_2_0_XSDT Xsdt;
extern ACPI_2_0_FADT Fadt;
extern ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE Madt;
extern ACPI_2_0_FACS Facs;
extern unsigned char *AmlCode;
extern int DsdtLen;


typedef struct _ACPI_TABLE_ALL{
		ACPI_2_0_RSDP *Rsdp;
		ACPI_2_0_RSDT *Rsdt;
		ACPI_2_0_XSDT *Xsdt;
		ACPI_2_0_FADT *Fadt;
		ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE *Madt;
		ACPI_2_0_FACS *Facs;
		unsigned char* Dsdt;
		uint32_t RsdpOffset;
		uint32_t RsdtOffset;
		uint32_t XsdtOffset;
		uint32_t FadtOffset;
		uint32_t MadtOffset;
		uint32_t FacsOffset;
		uint32_t DsdtOffset;
}ACPI_TABLE_ALL;

static 
void
MemCopy(void* src, void* dst, int len){

	uint8_t* src0=src;
   	uint8_t* dst0=dst;	

	while(len--){
		*(dst0++)=*(src0++);
	}
}

static
void
SetCheckSum(
  void*  Table, 
  uint32_t ChecksumOffset,
  uint32_t Length
)
/*
 * Routine Description:
 *      Calculate Checksum and store the result in the checksum 
 * 	filed of the table	
 *
 * INPUT:
 * 	Table:          Start pointer of table
 * 	ChecksumOffset: Offset of checksum field in the table
 * 	Length:         Length of Table
 */
{
	uint8_t Sum = 0;  
	uint8_t *Ptr;

	Ptr=Table;
	Ptr[ChecksumOffset]=0;
	while (Length--) {    
		Sum = (uint8_t)(Sum + (*Ptr++));
	}
	
	Ptr = Table;
	Ptr[ChecksumOffset] = (uint8_t) (0xff - Sum + 1);
}

//
//  FIELD_OFFSET - returns the byte offset to a field within a structure
//
#define FIELD_OFFSET(TYPE,Field) ((uint32_t)(&(((TYPE *) 0)->Field)))

static
void
UpdateTable(
	ACPI_TABLE_ALL *table
)
/*
 * Update the ACPI table:
 * 		fill in the actuall physical address of RSDT, XSDT, FADT, MADT, FACS
 * 		Caculate the checksum
 */
{    
	// RSDP Update	
	table->Rsdp->RsdtAddress = (uint32_t)(ACPI_PHYSICAL_ADDRESS+
					table->RsdtOffset);
	table->Rsdp->XsdtAddress = (uint64_t)(ACPI_PHYSICAL_ADDRESS+
					table->XsdtOffset);
	SetCheckSum(table->Rsdp,
					FIELD_OFFSET(ACPI_1_0_RSDP, Checksum),
					sizeof(ACPI_1_0_RSDP)
			   );
	SetCheckSum(table->Rsdp,
					FIELD_OFFSET(ACPI_2_0_RSDP,
							ExtendedChecksum),
					sizeof(ACPI_2_0_RSDP)
			   );

	
	//RSDT Update
	table->Rsdt->Entry[0] = (uint32_t)(ACPI_PHYSICAL_ADDRESS + 
					table->FadtOffset);	
	table->Rsdt->Entry[1] = (uint32_t)(ACPI_PHYSICAL_ADDRESS + 
					table->MadtOffset);
	table->Rsdt->Header.Length = sizeof (ACPI_TABLE_HEADER) +
		   			2*sizeof(uint32_t);
	SetCheckSum(table->Rsdt,
					FIELD_OFFSET(ACPI_TABLE_HEADER, Checksum),
					table->Rsdt->Header.Length
			   );	
	
	//XSDT	Update
	table->Xsdt->Entry[0] = (uint64_t)(ACPI_PHYSICAL_ADDRESS +
					table->FadtOffset);
	table->Xsdt->Entry[1] = (uint64_t)(ACPI_PHYSICAL_ADDRESS + 
					table->MadtOffset);	
	table->Xsdt->Header.Length = sizeof (ACPI_TABLE_HEADER) + 
					2*sizeof(uint64_t);
	SetCheckSum(table->Xsdt,
					FIELD_OFFSET(ACPI_TABLE_HEADER, Checksum),
					table->Xsdt->Header.Length
			   );

	// FADT Update
	table->Fadt->Dsdt = (uint32_t)(ACPI_PHYSICAL_ADDRESS + 
					table->DsdtOffset);	
	table->Fadt->XDsdt = (uint64_t)(ACPI_PHYSICAL_ADDRESS + 
				   table->DsdtOffset);
	table->Fadt->FirmwareCtrl = (uint32_t)(ACPI_PHYSICAL_ADDRESS +
					table->FacsOffset);
	table->Fadt->XFirmwareCtrl = (uint64_t)(ACPI_PHYSICAL_ADDRESS + 
					table->FacsOffset);	
	SetCheckSum(table->Fadt,
					FIELD_OFFSET(ACPI_TABLE_HEADER, Checksum),
					sizeof(ACPI_2_0_FADT)
			   );
	
	// MADT update
	SetCheckSum(table->Madt,
					FIELD_OFFSET(ACPI_TABLE_HEADER, Checksum),
					sizeof(ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE)
			   );
}

void
AcpiBuildTable(uint8_t* buf)
/*
 * Copy all the ACPI table to buffer
 * Buffer Layout:
 * 		FACS
 * 		RSDP
 * 		RSDT
 * 		XSDT
 * 		FADT
 * 		MADT
 * 		DSDT 		
 *
 */		
{
	ACPI_TABLE_ALL table;
	int offset=0;

	// FACS: should be 64-bit alignment 	
	// so it is put at the start of buffer
	// as the buffer is 64 bit alignment
	table.FacsOffset = offset;
	table.Facs = (ACPI_2_0_FACS*)(&buf[offset]);
	MemCopy(&Facs, table.Facs, sizeof(ACPI_2_0_FACS));
	offset += sizeof(ACPI_2_0_FACS);

	// RSDP
	table.RsdpOffset = offset;
	table.Rsdp = (ACPI_2_0_RSDP*)(&buf[offset]);
	MemCopy(&Rsdp, table.Rsdp, sizeof(ACPI_2_0_RSDP));
	offset+=sizeof(ACPI_2_0_RSDP);

	// RSDT
	table.RsdtOffset = offset;
	table.Rsdt = (ACPI_2_0_RSDT*)(&buf[offset]);
	MemCopy(&Rsdt, table.Rsdt, sizeof(ACPI_2_0_RSDT));
	offset+=sizeof(ACPI_2_0_RSDT);
	
	// XSDT
	table.XsdtOffset = offset;
	table.Xsdt = (ACPI_2_0_XSDT*)(&buf[offset]);
	MemCopy(&Xsdt, table.Xsdt, sizeof(ACPI_2_0_XSDT));
	offset+=sizeof(ACPI_2_0_XSDT);
	
	// FADT
	table.FadtOffset = offset;
	table.Fadt = (ACPI_2_0_FADT*)(&buf[offset]);
	MemCopy(&Fadt, table.Fadt, sizeof(ACPI_2_0_FADT));
	offset+=sizeof(ACPI_2_0_FADT);
	
	// MADT
	table.MadtOffset = offset;
	table.Madt = (ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE*)(&buf[offset]);
	MemCopy(&Madt, table.Madt, sizeof(ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE));
	offset+=sizeof(ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE);

	// DSDT
	table.DsdtOffset = offset;
	table.Dsdt = (unsigned char*)(&buf[offset]);
	MemCopy(&AmlCode, table.Dsdt, DsdtLen);
	offset+=DsdtLen; 
	
	UpdateTable(&table);
}
