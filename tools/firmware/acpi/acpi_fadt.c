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
#include "acpi_fadt.h"

//
// Fixed ACPI Description Table
//

ACPI_2_0_FADT Fadt = {
		{
				ACPI_2_0_FADT_SIGNATURE,
				sizeof (ACPI_2_0_FADT),
				ACPI_2_0_FADT_REVISION,
				0x00,// Checksum will be updated later
				ACPI_OEM_ID,  // OEM ID
				ACPI_OEM_TABLE_ID,  // OEM Table ID
				ACPI_OEM_REVISION, // OEM Revision
				ACPI_CREATOR_ID,  // Creator ID
				ACPI_CREATOR_REVISION,  // Creator Revision 
		},
		//
		// These addresses will be updated later
		//
		0x00000000,   // Physical Address (0~4G) of the FACS
		0x00000000,   // Physical Address (0~4G) of the DSDT

		0x00,  
		ACPI_PREFERRED_PM_PROFILE,  // Enterprise 
		ACPI_SCI_INT,               // IRQ 9
		ACPI_SMI_CMD,               
		ACPI_ACPI_ENABLE,
		ACPI_ACPI_DISABLE,
		ACPI_S4_BIOS_REQ,  // zero. not supported
		ACPI_PSTATE_CNT,   // not supported

		ACPI_PM1A_EVT_BLK_ADDRESS,  // required
		ACPI_PM1B_EVT_BLK_ADDRESS,  // not supported 
		ACPI_PM1A_CNT_BLK_ADDRESS,  // required
		ACPI_PM1B_CNT_BLK_ADDRESS,  // not supported 
		ACPI_PM2_CNT_BLK_ADDRESS,   // not supported 
		ACPI_PM_TMR_BLK_ADDRESS,    // required
		ACPI_GPE0_BLK_ADDRESS,      // not supported
		ACPI_GPE1_BLK_ADDRESS,      // not supported 
		ACPI_PM1_EVT_LEN,           
		ACPI_PM1_CNT_LEN,
		ACPI_PM2_CNT_LEN,
		ACPI_PM_TMR_LEN,
		ACPI_GPE0_BLK_LEN,
		ACPI_GPE1_BLK_LEN,
		ACPI_GPE1_BASE,

		ACPI_CST_CNT,
		ACPI_P_LVL2_LAT,             // >100, not support C2 state
		ACPI_P_LVL3_LAT,             // >1000, not support C3 state
		ACPI_FLUSH_SIZE,             // not support
		ACPI_FLUSH_STRIDE,           // not support
		ACPI_DUTY_OFFSET,            // not support 
		ACPI_DUTY_WIDTH,             // not support
		ACPI_DAY_ALRM,               // not support
		ACPI_MON_ALRM,               // not support
		ACPI_CENTURY,                // not support
		ACPI_IAPC_BOOT_ARCH,         
		0x00,          
		ACPI_FIXED_FEATURE_FLAGS,

		//
		// Reset Register Block
		//
		{		ACPI_RESET_REG_ADDRESS_SPACE_ID,
				ACPI_RESET_REG_BIT_WIDTH,
				ACPI_RESET_REG_BIT_OFFSET,
				0x00,
				ACPI_RESET_REG_ADDRESS,
		},

		ACPI_RESET_VALUE,
		{
				0x00,
				0x00,
				0x00,
		},
		//
		// These addresses will be updated later
		//
		0x0000000000000000,   // X_FIRMWARE_CTRL: 64bit physical address of the FACS.
		0x0000000000000000,   // X_DSDT: 64bit physical address of the DSDT.

		//
		// PM1a Event Register Block
		//
		{
				ACPI_PM1A_EVT_BLK_ADDRESS_SPACE_ID,
				ACPI_PM1A_EVT_BLK_BIT_WIDTH,
				ACPI_PM1A_EVT_BLK_BIT_OFFSET,
				0x00,
				ACPI_PM1A_EVT_BLK_ADDRESS,
		},

		//
		// PM1b Event Register Block
		//
		{
				ACPI_PM1B_EVT_BLK_ADDRESS_SPACE_ID,  // not support
				ACPI_PM1B_EVT_BLK_BIT_WIDTH,
				ACPI_PM1B_EVT_BLK_BIT_OFFSET,
				0x00,
				ACPI_PM1B_EVT_BLK_ADDRESS,
		},

		//
		// PM1a Control Register Block
		//
		{
				ACPI_PM1A_CNT_BLK_ADDRESS_SPACE_ID,
				ACPI_PM1A_CNT_BLK_BIT_WIDTH,
				ACPI_PM1A_CNT_BLK_BIT_OFFSET,
				0x00,
				ACPI_PM1A_CNT_BLK_ADDRESS,
		},

		//
		// PM1b Control Register Block
		//
		{
				ACPI_PM1B_CNT_BLK_ADDRESS_SPACE_ID,
				ACPI_PM1B_CNT_BLK_BIT_WIDTH,
				ACPI_PM1B_CNT_BLK_BIT_OFFSET,
				0x00,
				ACPI_PM1B_CNT_BLK_ADDRESS,
		},

		//
		// PM2 Control Register Block
		//
		{
				ACPI_PM2_CNT_BLK_ADDRESS_SPACE_ID,
				ACPI_PM2_CNT_BLK_BIT_WIDTH,
				ACPI_PM2_CNT_BLK_BIT_OFFSET,
				0x00,
				ACPI_PM2_CNT_BLK_ADDRESS,
		},

		//
		// PM Timer Control Register Block
		//
		{
				ACPI_PM_TMR_BLK_ADDRESS_SPACE_ID,
				ACPI_PM_TMR_BLK_BIT_WIDTH,
				ACPI_PM_TMR_BLK_BIT_OFFSET,
				0x00,
				ACPI_PM_TMR_BLK_ADDRESS,
		},

		//
		// General Purpose Event 0 Register Block
		//
		{
				ACPI_GPE0_BLK_ADDRESS_SPACE_ID,
				ACPI_GPE0_BLK_BIT_WIDTH,
				ACPI_GPE0_BLK_BIT_OFFSET,
				0x00,
				ACPI_GPE0_BLK_ADDRESS,
		},

		//
		// General Purpose Event 1 Register Block
		//
		{
				ACPI_GPE1_BLK_ADDRESS_SPACE_ID,
				ACPI_GPE1_BLK_BIT_WIDTH,
				ACPI_GPE1_BLK_BIT_OFFSET,
				0x00,
				ACPI_GPE1_BLK_ADDRESS
		}
		
};
