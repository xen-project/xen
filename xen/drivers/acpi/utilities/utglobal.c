/******************************************************************************
 *
 * Module Name: utglobal - Global variables for the ACPI subsystem
 *
 *****************************************************************************/

/*
 * Copyright (C) 2000 - 2008, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#define DEFINE_ACPI_GLOBALS

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <asm/processor.h>
#include <acpi/acpi.h>

ACPI_EXPORT_SYMBOL(acpi_gbl_FADT)
#define _COMPONENT          ACPI_UTILITIES
    ACPI_MODULE_NAME("utglobal")

/*******************************************************************************
 *
 * FUNCTION:    acpi_format_exception
 *
 * PARAMETERS:  Status       - The acpi_status code to be formatted
 *
 * RETURN:      A string containing the exception text. A valid pointer is
 *              always returned.
 *
 * DESCRIPTION: This function translates an ACPI exception into an ASCII string
 *              It is here instead of utxface.c so it is always present.
 *
 ******************************************************************************/

const char *__init acpi_format_exception(acpi_status status)
{
	const char *exception = NULL;

	ACPI_FUNCTION_ENTRY();

	exception = acpi_ut_validate_exception(status);
	if (!exception) {

		/* Exception code was not recognized */

		ACPI_ERROR((AE_INFO,
			    "Unknown exception code: %#X", status));

		exception = "UNKNOWN_STATUS_CODE";
		dump_execution_state();
	}

	return (ACPI_CAST_PTR(const char, exception));
}

/******************************************************************************
 *
 * Event and Hardware globals
 *
 ******************************************************************************/

struct acpi_bit_register_info acpi_gbl_bit_register_info[ACPI_NUM_BITREG] = {
	/* Name                                     Parent Register             Register Bit Position                   Register Bit Mask       */

	/* ACPI_BITREG_TIMER_STATUS         */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_TIMER_STATUS,
						ACPI_BITMASK_TIMER_STATUS},
	/* ACPI_BITREG_BUS_MASTER_STATUS    */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_BUS_MASTER_STATUS,
						ACPI_BITMASK_BUS_MASTER_STATUS},
	/* ACPI_BITREG_GLOBAL_LOCK_STATUS   */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_GLOBAL_LOCK_STATUS,
						ACPI_BITMASK_GLOBAL_LOCK_STATUS},
	/* ACPI_BITREG_POWER_BUTTON_STATUS  */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_POWER_BUTTON_STATUS,
						ACPI_BITMASK_POWER_BUTTON_STATUS},
	/* ACPI_BITREG_SLEEP_BUTTON_STATUS  */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_SLEEP_BUTTON_STATUS,
						ACPI_BITMASK_SLEEP_BUTTON_STATUS},
	/* ACPI_BITREG_RT_CLOCK_STATUS      */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_RT_CLOCK_STATUS,
						ACPI_BITMASK_RT_CLOCK_STATUS},
	/* ACPI_BITREG_WAKE_STATUS          */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_WAKE_STATUS,
						ACPI_BITMASK_WAKE_STATUS},
	/* ACPI_BITREG_PCIEXP_WAKE_STATUS   */ {ACPI_REGISTER_PM1_STATUS,
						ACPI_BITPOSITION_PCIEXP_WAKE_STATUS,
						ACPI_BITMASK_PCIEXP_WAKE_STATUS},

	/* ACPI_BITREG_TIMER_ENABLE         */ {ACPI_REGISTER_PM1_ENABLE,
						ACPI_BITPOSITION_TIMER_ENABLE,
						ACPI_BITMASK_TIMER_ENABLE},
	/* ACPI_BITREG_GLOBAL_LOCK_ENABLE   */ {ACPI_REGISTER_PM1_ENABLE,
						ACPI_BITPOSITION_GLOBAL_LOCK_ENABLE,
						ACPI_BITMASK_GLOBAL_LOCK_ENABLE},
	/* ACPI_BITREG_POWER_BUTTON_ENABLE  */ {ACPI_REGISTER_PM1_ENABLE,
						ACPI_BITPOSITION_POWER_BUTTON_ENABLE,
						ACPI_BITMASK_POWER_BUTTON_ENABLE},
	/* ACPI_BITREG_SLEEP_BUTTON_ENABLE  */ {ACPI_REGISTER_PM1_ENABLE,
						ACPI_BITPOSITION_SLEEP_BUTTON_ENABLE,
						ACPI_BITMASK_SLEEP_BUTTON_ENABLE},
	/* ACPI_BITREG_RT_CLOCK_ENABLE      */ {ACPI_REGISTER_PM1_ENABLE,
						ACPI_BITPOSITION_RT_CLOCK_ENABLE,
						ACPI_BITMASK_RT_CLOCK_ENABLE},
	/* ACPI_BITREG_WAKE_ENABLE          */ {ACPI_REGISTER_PM1_ENABLE, 0, 0},
	/* ACPI_BITREG_PCIEXP_WAKE_DISABLE  */ {ACPI_REGISTER_PM1_ENABLE,
						ACPI_BITPOSITION_PCIEXP_WAKE_DISABLE,
						ACPI_BITMASK_PCIEXP_WAKE_DISABLE},

	/* ACPI_BITREG_SCI_ENABLE           */ {ACPI_REGISTER_PM1_CONTROL,
						ACPI_BITPOSITION_SCI_ENABLE,
						ACPI_BITMASK_SCI_ENABLE},
	/* ACPI_BITREG_BUS_MASTER_RLD       */ {ACPI_REGISTER_PM1_CONTROL,
						ACPI_BITPOSITION_BUS_MASTER_RLD,
						ACPI_BITMASK_BUS_MASTER_RLD},
	/* ACPI_BITREG_GLOBAL_LOCK_RELEASE  */ {ACPI_REGISTER_PM1_CONTROL,
						ACPI_BITPOSITION_GLOBAL_LOCK_RELEASE,
						ACPI_BITMASK_GLOBAL_LOCK_RELEASE},
	/* ACPI_BITREG_SLEEP_TYPE_A         */ {ACPI_REGISTER_PM1_CONTROL,
						ACPI_BITPOSITION_SLEEP_TYPE_X,
						ACPI_BITMASK_SLEEP_TYPE_X},
	/* ACPI_BITREG_SLEEP_TYPE_B         */ {ACPI_REGISTER_PM1_CONTROL,
						ACPI_BITPOSITION_SLEEP_TYPE_X,
						ACPI_BITMASK_SLEEP_TYPE_X},
	/* ACPI_BITREG_SLEEP_ENABLE         */ {ACPI_REGISTER_PM1_CONTROL,
						ACPI_BITPOSITION_SLEEP_ENABLE,
						ACPI_BITMASK_SLEEP_ENABLE},

	/* ACPI_BITREG_ARB_DIS              */ {ACPI_REGISTER_PM2_CONTROL,
						ACPI_BITPOSITION_ARB_DISABLE,
						ACPI_BITMASK_ARB_DISABLE}
};

#ifdef ACPI_DEBUG_OUTPUT

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_get_region_name
 *
 * PARAMETERS:  None.
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Translate a Space ID into a name string (Debug only)
 *
 ******************************************************************************/

/* Region type decoding */

static const char *const acpi_gbl_region_types[ACPI_NUM_PREDEFINED_REGIONS] = {
	"SystemMemory",
	"SystemIO",
	"PCI_Config",
	"EmbeddedControl",
	"SMBus",
	"CMOS",
	"PCIBARTarget",
	"DataTable"
};

const char *acpi_ut_get_region_name(u8 space_id)
{

	if (space_id >= ACPI_USER_REGION_BEGIN) {
		return ("UserDefinedRegion");
	} else if (space_id >= ACPI_NUM_PREDEFINED_REGIONS) {
		return ("InvalidSpaceId");
	}

	return (ACPI_CAST_PTR(char, acpi_gbl_region_types[space_id]));
}

#endif
