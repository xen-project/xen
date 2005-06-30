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
#include "acpi_facs.h"

//
// Firmware ACPI Control Structure
//

ACPI_2_0_FACS Facs = {
		ACPI_2_0_FACS_SIGNATURE,
		sizeof (ACPI_2_0_FACS),

		//
		// Hardware Signature
		//
		0x00000000,

		ACPI_FIRMWARE_WAKING_VECTOR,
		ACPI_GLOBAL_LOCK,
		ACPI_FIRMWARE_CONTROL_STRUCTURE_FLAGS,
		ACPI_X_FIRMWARE_WAKING_VECTOR,
		ACPI_2_0_FACS_VERSION,
		{
				0x00,  // Reserved Fields
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
		}
};
