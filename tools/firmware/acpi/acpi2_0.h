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
#ifndef _ACPI_2_0_H_
#define _ACPI_2_0_H_

#include "xc.h"  // for u8, u16, u32, u64 definition

#pragma pack (1)

//
// common ACPI header.  
//

typedef struct {
		u32			Signature;
		u32     	Length;
		u8			Revision;
		u8			Checksum;
		u8			OemId[6];
		u64			OemTableId;
		u32			OemRevision;
		u32			CreatorId;
		u32			CreatorRevision;
} ACPI_TABLE_HEADER;


#define ACPI_OEM_ID 			{'I','N','T','E','L',' '}
#define ACPI_OEM_TABLE_ID 		0x544244 		// "TBD"
#define ACPI_OEM_REVISION 		0x00000002
#define ACPI_CREATOR_ID 		0x00 			// TBD 
#define ACPI_CREATOR_REVISION 	0x00000002 		

//
// ACPI 2.0 Generic Address Space definition
//
typedef struct {
		u8                            AddressSpaceId;
		u8                            RegisterBitWidth;
		u8                            RegisterBitOffset;
		u8                            Reserved;
		u64                           Address;
} ACPI_GENERIC_ADDRESS_STRUCTURE;

//
// Generic Address Space Address IDs
//
#define ACPI_SYSTEM_MEMORY 0
#define ACPI_SYSTEM_IO 1
#define ACPI_PCI_CONFIGURATION_SPACE 2
#define ACPI_EMBEDDED_CONTROLLER 3
#define ACPI_SMBUS 4
#define ACPI_FUNCTIONAL_FIXED_HARDWARE 0x7F

//
// Root System Description Pointer Structure in ACPI 1.0
//
typedef struct {
		u64                           Signature;
		u8                            Checksum;
		u8                            OemId[6];
		u8                            Reserved;
		u32                           RsdtAddress;
} ACPI_1_0_RSDP;


//
// Root System Description Pointer Structure
//
typedef struct {
		u64                           Signature;
		u8                            Checksum;
		u8                            OemId[6];
		u8                            Revision;
		u32                           RsdtAddress;
		u32                           Length;
		u64                           XsdtAddress;
		u8                            ExtendedChecksum;
		u8                            Reserved[3];
} ACPI_2_0_RSDP;


//
// The maximum number of entrys in RSDT or XSDT
//
#define ACPI_MAX_NUM_TABLES 2

//
// Root System Description Table (RSDT)
//

typedef struct {
		ACPI_TABLE_HEADER Header;
		u32 Entry[ACPI_MAX_NUM_TABLES];
}ACPI_2_0_RSDT;

//
// RSDT Revision (as defined in ACPI 2.0 spec.)
//

#define ACPI_2_0_RSDT_REVISION 0x01

//
// Extended System Description Table (XSDT)
//

typedef struct _ACPI_2_0_XSDT{
		ACPI_TABLE_HEADER Header;
		u64 Entry[ACPI_MAX_NUM_TABLES];
}ACPI_2_0_XSDT;
#define ACPI_2_0_XSDT_REVISION 0x01

//
// Fixed ACPI Description Table Structure (FADT)
// 

typedef struct  {
		ACPI_TABLE_HEADER               Header;
		u32                                    FirmwareCtrl;
		u32                                    Dsdt;
		u8                                     Reserved0;
		u8                                     PreferredPmProfile;
		u16                                    SciInt;
		u32                                    SmiCmd;
		u8                                     AcpiEnable;
		u8                                     AcpiDisable;
		u8                                     S4BiosReq;
		u8                                     PstateCnt;
		u32                                    Pm1aEvtBlk;
		u32                                    Pm1bEvtBlk;
		u32                                    Pm1aCntBlk;
		u32                                    Pm1bCntBlk;
		u32                                    Pm2CntBlk;
		u32                                    PmTmrBlk;
		u32                                    Gpe0Blk;
		u32                                    Gpe1Blk;
		u8                                     Pm1EvtLen;
		u8                                     Pm1CntLen;
		u8                                     Pm2CntLen;
		u8                                     PmTmrLen;
		u8                                     Gpe0BlkLen;
		u8                                     Gpe1BlkLen;
		u8                                     Gpe1Base;
		u8                                     CstCnt;
		u16                                    PLvl2Lat;
		u16                                    PLvl3Lat;
		u16                                    FlushSize;
		u16                                    FlushStride;
		u8                                     DutyOffset;
		u8                                     DutyWidth;
		u8                                     DayAlrm;
		u8                                     MonAlrm;
		u8                                     Century;
		u16                                    IaPcBootArch;
		u8                                     Reserved1;
		u32                                    Flags;
		ACPI_GENERIC_ADDRESS_STRUCTURE    ResetReg;
		u8                                     ResetValue;
		u8                                     Reserved2[3];
		u64                                    XFirmwareCtrl;
		u64                                    XDsdt;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XPm1aEvtBlk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XPm1bEvtBlk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XPm1aCntBlk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XPm1bCntBlk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XPm2CntBlk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XPmTmrBlk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XGpe0Blk;
		ACPI_GENERIC_ADDRESS_STRUCTURE    XGpe1Blk;
} ACPI_2_0_FADT;
#define ACPI_2_0_FADT_REVISION 0x03

//
// FADT Boot Architecture Flags
//
#define ACPI_LEGACY_DEVICES (1 << 0)
#define ACPI_8042           (1 << 1)

//
// FADT Fixed Feature Flags
//
#define ACPI_WBINVD         (1 << 0)
#define ACPI_WBINVD_FLUSH   (1 << 1)
#define ACPI_PROC_C1        (1 << 2)
#define ACPI_P_LVL2_UP      (1 << 3)
#define ACPI_PWR_BUTTON     (1 << 4)
#define ACPI_SLP_BUTTON     (1 << 5)
#define ACPI_FIX_RTC        (1 << 6)
#define ACPI_RTC_S4         (1 << 7)
#define ACPI_TMR_VAL_EXT    (1 << 8)
#define ACPI_DCK_CAP        (1 << 9)
#define ACPI_RESET_REG_SUP  (1 << 10)
#define ACPI_SEALED_CASE    (1 << 11)
#define ACPI_HEADLESS       (1 << 12)
#define ACPI_CPU_SW_SLP     (1 << 13)

//
// Firmware ACPI Control Structure (FACS)
//
typedef struct {
		u32                               Signature;
		u32                               Length;
		u32                               HardwareSignature;
		u32                               FirmwareWakingVector;
		u32                               GlobalLock;
		u32                               Flags;
		u64                               XFirmwareWakingVector;
		u8                                Version;
		u8                                Reserved[31];
} ACPI_2_0_FACS;

#define ACPI_2_0_FACS_VERSION 0x01

//
// Multiple APIC Description Table header definition (MADT)
//
typedef struct {
		ACPI_TABLE_HEADER                       Header;
		u32                                     LocalApicAddress;
		u32                                     Flags;
} ACPI_2_0_MADT;

#define ACPI_2_0_MADT_REVISION 0x01

//
// Multiple APIC Flags
//
#define ACPI_PCAT_COMPAT (1 << 0)

//
// Multiple APIC Description Table APIC structure types
//
#define ACPI_PROCESSOR_LOCAL_APIC           0x00
#define ACPI_IO_APIC                        0x01
#define ACPI_INTERRUPT_SOURCE_OVERRIDE      0x02
#define ACPI_NON_MASKABLE_INTERRUPT_SOURCE  0x03
#define ACPI_LOCAL_APIC_NMI                 0x04
#define ACPI_LOCAL_APIC_ADDRESS_OVERRIDE    0x05
#define ACPI_IO_SAPIC                       0x06
#define ACPI_PROCESSOR_LOCAL_SAPIC          0x07
#define ACPI_PLATFORM_INTERRUPT_SOURCES     0x08

//
// APIC Structure Definitions
//

//
// Processor Local APIC Structure Definition
//

typedef struct {
		u8                                             Type;
		u8                                             Length;
		u8                                             AcpiProcessorId;
		u8                                             ApicId;
		u32                                            Flags;
} ACPI_LOCAL_APIC_STRUCTURE;

//
// Local APIC Flags.  All other bits are reserved and must be 0.
//

#define ACPI_LOCAL_APIC_ENABLED (1 << 0)

//
// IO APIC Structure
//

typedef struct {
		u8                                             Type;
		u8                                             Length;
		u8                                             IoApicId;
		u8                                             Reserved;
		u32                                            IoApicAddress;
		u32                                            GlobalSystemInterruptBase;
} ACPI_IO_APIC_STRUCTURE;

// Tabel Signature
#define ACPI_2_0_RSDP_SIGNATURE 0x2052545020445352LL  // "RSD PTR "

#define ACPI_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE 0x54445344  //"DSDT"

#define ACPI_2_0_FACS_SIGNATURE 0x53434146 // "FACS"

#define ACPI_2_0_FADT_SIGNATURE 0x50434146 // "FADT"

#define ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE 0x43495041  // "APIC"

#define ACPI_2_0_RSDT_SIGNATURE 0x54445352  // "RSDT"

#define ACPI_2_0_XSDT_SIGNATURE 0x54445358  // "XSDT"

#pragma pack ()

// The physical that acpi table reside in the guest BIOS
//#define ACPI_PHYSICAL_ADDRESS 0xE2000
#define ACPI_PHYSICAL_ADDRESS 0xEA000
#define ACPI_TABLE_SIZE (2*1024)  //Currently 2K is enough

void
AcpiBuildTable(u8* buf);

#endif
