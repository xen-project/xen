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

extern struct acpi_20_rsdp Rsdp;
extern struct acpi_20_rsdt Rsdt;
extern struct acpi_20_xsdt Xsdt;
extern struct acpi_20_fadt Fadt;
extern struct acpi_20_madt Madt;
extern struct acpi_20_facs Facs;
extern unsigned char *AmlCode;
extern int DsdtLen;


typedef struct _ACPI_TABLE_ALL{
    struct acpi_20_rsdp *Rsdp;
    struct acpi_20_rsdt *Rsdt;
    struct acpi_20_xsdt *Xsdt;
    struct acpi_20_fadt *Fadt;
    struct acpi_20_madt *Madt;
    struct acpi_20_facs *Facs;
    unsigned char *Dsdt;
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
    table->Rsdp->rsdt_address = (uint32_t)(ACPI_PHYSICAL_ADDRESS+
                                           table->RsdtOffset);
    table->Rsdp->xsdt_address = (uint64_t)(ACPI_PHYSICAL_ADDRESS+
                                           table->XsdtOffset);
    SetCheckSum(table->Rsdp,
                FIELD_OFFSET(struct acpi_10_rsdp, checksum),
                sizeof(struct acpi_10_rsdp)
        );
    SetCheckSum(table->Rsdp,
                FIELD_OFFSET(struct acpi_20_rsdp,
                             extended_checksum),
                sizeof(struct acpi_20_rsdp)
        );

	
    //RSDT Update
    table->Rsdt->entry[0] = (uint32_t)(ACPI_PHYSICAL_ADDRESS + 
                                       table->FadtOffset);	
    table->Rsdt->entry[1] = (uint32_t)(ACPI_PHYSICAL_ADDRESS + 
                                       table->MadtOffset);
    table->Rsdt->header.length = sizeof (struct acpi_header) +
        2*sizeof(uint32_t);
    SetCheckSum(table->Rsdt,
                FIELD_OFFSET(struct acpi_header, checksum),
                table->Rsdt->header.length
        );	

    //XSDT	Update
    table->Xsdt->entry[0] = (uint64_t)(ACPI_PHYSICAL_ADDRESS +
                                       table->FadtOffset);
    table->Xsdt->entry[1] = (uint64_t)(ACPI_PHYSICAL_ADDRESS + 
                                       table->MadtOffset);	
    table->Xsdt->header.length = sizeof (struct acpi_header) + 
        2*sizeof(uint64_t);
    SetCheckSum(table->Xsdt,
                FIELD_OFFSET(struct acpi_header, checksum),
                table->Xsdt->header.length
        );

    // FADT Update
    table->Fadt->dsdt = (uint32_t)(ACPI_PHYSICAL_ADDRESS + 
                                   table->DsdtOffset);	
    table->Fadt->x_dsdt = (uint64_t)(ACPI_PHYSICAL_ADDRESS + 
                                     table->DsdtOffset);
    table->Fadt->firmware_ctrl = (uint32_t)(ACPI_PHYSICAL_ADDRESS +
                                            table->FacsOffset);
    table->Fadt->x_firmware_ctrl = (uint64_t)(ACPI_PHYSICAL_ADDRESS + 
                                              table->FacsOffset);	
    SetCheckSum(table->Fadt,
                FIELD_OFFSET(struct acpi_header, checksum),
                sizeof(struct acpi_20_fadt)
        );
	
    // MADT update
    SetCheckSum(table->Madt,
                FIELD_OFFSET(struct acpi_header, checksum),
                sizeof(struct acpi_20_madt)
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
    table.Facs = (struct acpi_20_facs *)(&buf[offset]);
    MemCopy(&Facs, table.Facs, sizeof(struct acpi_20_facs));
    offset += sizeof(struct acpi_20_facs);

    // RSDP
    table.RsdpOffset = offset;
    table.Rsdp = (struct acpi_20_rsdp *)(&buf[offset]);
    MemCopy(&Rsdp, table.Rsdp, sizeof(struct acpi_20_rsdp));
    offset += sizeof(struct acpi_20_rsdp);

    // RSDT
    table.RsdtOffset = offset;
    table.Rsdt = (struct acpi_20_rsdt *)(&buf[offset]);
    MemCopy(&Rsdt, table.Rsdt, sizeof(struct acpi_20_rsdt));
    offset += sizeof(struct acpi_20_rsdt);
	
    // XSDT
    table.XsdtOffset = offset;
    table.Xsdt = (struct acpi_20_xsdt *)(&buf[offset]);
    MemCopy(&Xsdt, table.Xsdt, sizeof(struct acpi_20_xsdt));
    offset += sizeof(struct acpi_20_xsdt);
	
    // FADT
    table.FadtOffset = offset;
    table.Fadt = (struct acpi_20_fadt *)(&buf[offset]);
    MemCopy(&Fadt, table.Fadt, sizeof(struct acpi_20_fadt));
    offset += sizeof(struct acpi_20_fadt);
	
    // MADT
    table.MadtOffset = offset;
    table.Madt = (struct acpi_20_madt*)(&buf[offset]);
    MemCopy(&Madt, table.Madt, sizeof(struct acpi_20_madt));
    offset += sizeof(struct acpi_20_madt);

    // DSDT
    table.DsdtOffset = offset;
    table.Dsdt = (unsigned char *)(&buf[offset]);
    MemCopy(&AmlCode, table.Dsdt, DsdtLen);
    offset += DsdtLen; 
	
    UpdateTable(&table);
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
