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

typedef unsigned char  uint8_t;
typedef   signed char  int8_t;
typedef unsigned short uint16_t;
typedef   signed short int16_t;
typedef unsigned int   uint32_t;
typedef   signed int   int32_t;
#ifdef __i386__
typedef unsigned long long uint64_t;
typedef   signed long long int64_t;
#else
typedef unsigned long uint64_t;
typedef   signed long int64_t;
#endif

#include <xen/xen.h>

#pragma pack (1)

//
// common ACPI header.  
//

typedef struct {
		uint32_t			Signature;
		uint32_t     	Length;
		uint8_t			Revision;
		uint8_t			Checksum;
		uint8_t			OemId[6];
		uint64_t			OemTableId;
		uint32_t			OemRevision;
		uint32_t			CreatorId;
		uint32_t			CreatorRevision;
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
		uint8_t                            AddressSpaceId;
		uint8_t                            RegisterBitWidth;
		uint8_t                            RegisterBitOffset;
		uint8_t                            Reserved;
		uint64_t                           Address;
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
		uint64_t                           Signature;
		uint8_t                            Checksum;
		uint8_t                            OemId[6];
		uint8_t                            Reserved;
		uint32_t                           RsdtAddress;
} ACPI_1_0_RSDP;


//
// Root System Description Pointer Structure
//
typedef struct {
		uint64_t                           Signature;
		uint8_t                            Checksum;
		uint8_t                            OemId[6];
		uint8_t                            Revision;
		uint32_t                           RsdtAddress;
		uint32_t                           Length;
		uint64_t                           XsdtAddress;
		uint8_t                            ExtendedChecksum;
		uint8_t                            Reserved[3];
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
		uint32_t Entry[ACPI_MAX_NUM_TABLES];
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
		uint64_t Entry[ACPI_MAX_NUM_TABLES];
}ACPI_2_0_XSDT;
#define ACPI_2_0_XSDT_REVISION 0x01

//
// Fixed ACPI Description Table Structure (FADT)
// 

typedef struct  {
		ACPI_TABLE_HEADER               Header;
		uint32_t                                    FirmwareCtrl;
		uint32_t                                    Dsdt;
		uint8_t                                     Reserved0;
		uint8_t                                     PreferredPmProfile;
		uint16_t                                    SciInt;
		uint32_t                                    SmiCmd;
		uint8_t                                     AcpiEnable;
		uint8_t                                     AcpiDisable;
		uint8_t                                     S4BiosReq;
		uint8_t                                     PstateCnt;
		uint32_t                                    Pm1aEvtBlk;
		uint32_t                                    Pm1bEvtBlk;
		uint32_t                                    Pm1aCntBlk;
		uint32_t                                    Pm1bCntBlk;
		uint32_t                                    Pm2CntBlk;
		uint32_t                                    PmTmrBlk;
		uint32_t                                    Gpe0Blk;
		uint32_t                                    Gpe1Blk;
		uint8_t                                     Pm1EvtLen;
		uint8_t                                     Pm1CntLen;
		uint8_t                                     Pm2CntLen;
		uint8_t                                     PmTmrLen;
		uint8_t                                     Gpe0BlkLen;
		uint8_t                                     Gpe1BlkLen;
		uint8_t                                     Gpe1Base;
		uint8_t                                     CstCnt;
		uint16_t                                    PLvl2Lat;
		uint16_t                                    PLvl3Lat;
		uint16_t                                    FlushSize;
		uint16_t                                    FlushStride;
		uint8_t                                     DutyOffset;
		uint8_t                                     DutyWidth;
		uint8_t                                     DayAlrm;
		uint8_t                                     MonAlrm;
		uint8_t                                     Century;
		uint16_t                                    IaPcBootArch;
		uint8_t                                     Reserved1;
		uint32_t                                    Flags;
		ACPI_GENERIC_ADDRESS_STRUCTURE    ResetReg;
		uint8_t                                     ResetValue;
		uint8_t                                     Reserved2[3];
		uint64_t                                    XFirmwareCtrl;
		uint64_t                                    XDsdt;
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
		uint32_t                               Signature;
		uint32_t                               Length;
		uint32_t                               HardwareSignature;
		uint32_t                               FirmwareWakingVector;
		uint32_t                               GlobalLock;
		uint32_t                               Flags;
		uint64_t                               XFirmwareWakingVector;
		uint8_t                                Version;
		uint8_t                                Reserved[31];
} ACPI_2_0_FACS;

#define ACPI_2_0_FACS_VERSION 0x01

//
// Multiple APIC Description Table header definition (MADT)
//
typedef struct {
		ACPI_TABLE_HEADER                       Header;
		uint32_t                                     LocalApicAddress;
		uint32_t                                     Flags;
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
		uint8_t                                             Type;
		uint8_t                                             Length;
		uint8_t                                             AcpiProcessorId;
		uint8_t                                             ApicId;
		uint32_t                                            Flags;
} ACPI_LOCAL_APIC_STRUCTURE;

//
// Local APIC Flags.  All other bits are reserved and must be 0.
//

#define ACPI_LOCAL_APIC_ENABLED (1 << 0)

//
// IO APIC Structure
//

typedef struct {
		uint8_t                                             Type;
		uint8_t                                             Length;
		uint8_t                                             IoApicId;
		uint8_t                                             Reserved;
		uint32_t                                            IoApicAddress;
		uint32_t                                            GlobalSystemInterruptBase;
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
#define ACPI_TABLE_SIZE (4*1024)  //Currently 4K is enough

void
AcpiBuildTable(uint8_t* buf);

#endif
