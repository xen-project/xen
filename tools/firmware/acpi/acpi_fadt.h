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
#ifndef _FADT_H_
#define _FADT_H_

//
// FADT Definitions, see ACPI 2.0 specification for details.
//

#define ACPI_OEM_FADT_REVISION  0x00000000 // TBD

#define ACPI_PREFERRED_PM_PROFILE 0x04
#define ACPI_SCI_INT              0x0009
#define ACPI_SMI_CMD              0x000000B2
#define ACPI_ACPI_ENABLE    0x00
#define ACPI_ACPI_DISABLE   0x00
#define ACPI_S4_BIOS_REQ    0x00
#define ACPI_PSTATE_CNT     0x00
#define ACPI_GPE1_BASE      0x20
#define ACPI_CST_CNT        0x00
#define ACPI_P_LVL2_LAT     0x0065
#define ACPI_P_LVL3_LAT     0X03E9
#define ACPI_FLUSH_SIZE     0x00
#define ACPI_FLUSH_STRIDE   0x00
#define ACPI_DUTY_OFFSET    0x01
#define ACPI_DUTY_WIDTH     0x00
#define ACPI_DAY_ALRM       0x00
#define ACPI_MON_ALRM       0x00
#define ACPI_CENTURY        0x00

//
// IA-PC Boot Architecture Flags, see ACPI 2.0 table specification and Acpi2_0.h
//
#define ACPI_IAPC_BOOT_ARCH (ACPI_LEGACY_DEVICES | ACPI_8042)

//
// Fixed Feature Flags
// 
#define ACPI_FIXED_FEATURE_FLAGS (ACPI_SLP_BUTTON| ACPI_WBINVD  )

//
// PM1A Event Register Block Generic Address Information
//
#define ACPI_PM1A_EVT_BLK_ADDRESS_SPACE_ID  ACPI_SYSTEM_IO
#define ACPI_PM1A_EVT_BLK_BIT_WIDTH         0x00
#define ACPI_PM1A_EVT_BLK_BIT_OFFSET        0x00
#define ACPI_PM1A_EVT_BLK_ADDRESS           0x0000000000008000

//
// PM1B Event Register Block Generic Address Information
//
#define ACPI_PM1B_EVT_BLK_ADDRESS_SPACE_ID  ACPI_SYSTEM_IO
#define ACPI_PM1B_EVT_BLK_BIT_WIDTH         0x00
#define ACPI_PM1B_EVT_BLK_BIT_OFFSET        0x00
#define ACPI_PM1B_EVT_BLK_ADDRESS           0x0000000000000000

//
// PM1A Control Register Block Generic Address Information
//
#define ACPI_PM1A_CNT_BLK_ADDRESS_SPACE_ID  ACPI_SYSTEM_IO
#define ACPI_PM1A_CNT_BLK_BIT_WIDTH         0x08
#define ACPI_PM1A_CNT_BLK_BIT_OFFSET        0x00
#define ACPI_PM1A_CNT_BLK_ADDRESS           (ACPI_PM1A_EVT_BLK_ADDRESS + 0x04)

//
// PM1B Control Register Block Generic Address Information
//
#define ACPI_PM1B_CNT_BLK_ADDRESS_SPACE_ID  ACPI_SYSTEM_IO
#define ACPI_PM1B_CNT_BLK_BIT_WIDTH         0x00
#define ACPI_PM1B_CNT_BLK_BIT_OFFSET        0x00
#define ACPI_PM1B_CNT_BLK_ADDRESS           0x0000000000000000

//
// PM2 Control Register Block Generic Address Information
//
#define ACPI_PM2_CNT_BLK_ADDRESS_SPACE_ID   ACPI_SYSTEM_IO
#define ACPI_PM2_CNT_BLK_BIT_WIDTH          0x00
#define ACPI_PM2_CNT_BLK_BIT_OFFSET         0x00
#define ACPI_PM2_CNT_BLK_ADDRESS            0x0000000000000000

//
// Power Management Timer Control Register Block Generic Address 
// Information
//
#define ACPI_PM_TMR_BLK_ADDRESS_SPACE_ID    ACPI_SYSTEM_IO
#define ACPI_PM_TMR_BLK_BIT_WIDTH           0x20
#define ACPI_PM_TMR_BLK_BIT_OFFSET          0x00
#define ACPI_PM_TMR_BLK_ADDRESS             (ACPI_PM1A_EVT_BLK_ADDRESS + 0x08)

//
// General Purpose Event 0 Register Block Generic Address
// Information
//

#define ACPI_GPE0_BLK_ADDRESS_SPACE_ID      ACPI_SYSTEM_IO
#define ACPI_GPE0_BLK_BIT_WIDTH             0x00
#define ACPI_GPE0_BLK_BIT_OFFSET            0x00
#define ACPI_GPE0_BLK_ADDRESS               0x00

//
// General Purpose Event 1 Register Block Generic Address
// Information
//

#define ACPI_GPE1_BLK_ADDRESS_SPACE_ID      ACPI_SYSTEM_IO
#define ACPI_GPE1_BLK_BIT_WIDTH             0x00
#define ACPI_GPE1_BLK_BIT_OFFSET            0x00
#define ACPI_GPE1_BLK_ADDRESS               0x00


//
// Reset Register Generic Address Information
//
#define ACPI_RESET_REG_ADDRESS_SPACE_ID     ACPI_SYSTEM_IO
#define ACPI_RESET_REG_BIT_WIDTH            0x08
#define ACPI_RESET_REG_BIT_OFFSET           0x00
#define ACPI_RESET_REG_ADDRESS              0x0000000000000CF9
#define ACPI_RESET_VALUE                    0x06
 
//
// Number of bytes decoded by PM1 event blocks (a and b)
//
#define ACPI_PM1_EVT_LEN ((ACPI_PM1A_EVT_BLK_BIT_WIDTH + ACPI_PM1B_EVT_BLK_BIT_WIDTH) / 8)

//
// Number of bytes decoded by PM1 control blocks (a and b)
//
#define ACPI_PM1_CNT_LEN ((ACPI_PM1A_CNT_BLK_BIT_WIDTH + ACPI_PM1B_CNT_BLK_BIT_WIDTH) / 8)

//
// Number of bytes decoded by PM2 control block
//
#define ACPI_PM2_CNT_LEN (ACPI_PM2_CNT_BLK_BIT_WIDTH / 8)

//
// Number of bytes decoded by PM timer block
//
#define ACPI_PM_TMR_LEN (ACPI_PM_TMR_BLK_BIT_WIDTH / 8)

//
// Number of bytes decoded by GPE0 block
//
#define ACPI_GPE0_BLK_LEN (ACPI_GPE0_BLK_BIT_WIDTH / 8)

//
// Number of bytes decoded by GPE1 block
//
#define ACPI_GPE1_BLK_LEN   0

#endif
