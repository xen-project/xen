
/*******************************************************************************
 *
 * Module Name: hwregs - Read/write access functions for the various ACPI
 *                       control and status registers.
 *
 ******************************************************************************/

/*
 * Copyright (C) 2000 - 2006, R. Byron Moore
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

#include <asm/io.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <acpi/acpi.h>

#define _COMPONENT          ACPI_HARDWARE
ACPI_MODULE_NAME("hwregs")

/******************************************************************************
 *
 * FUNCTION:    acpi_hw_register_read
 *
 * PARAMETERS:  register_id         - ACPI Register ID
 *              return_value        - Where the register value is returned
 *
 * RETURN:      Status and the value read.
 *
 * DESCRIPTION: Read from the specified ACPI register
 *
 ******************************************************************************/
acpi_status
acpi_hw_register_read(u32 register_id, u32 * return_value)
{
	u32 value1 = 0;
	u32 value2 = 0;
	acpi_status status;

	ACPI_FUNCTION_TRACE(hw_register_read);

	switch (register_id) {
	case ACPI_REGISTER_PM1_STATUS:	/* 16-bit access */

		status =
		    acpi_hw_low_level_read(16, &value1,
					   &acpi_sinfo.pm1a_evt_blk);
		if (ACPI_FAILURE(status)) {
			goto exit;
		}

		/* PM1B is optional */

		status =
		    acpi_hw_low_level_read(16, &value2,
					   &acpi_sinfo.pm1b_evt_blk);
		value1 |= value2;
		break;


	case ACPI_REGISTER_PM1_CONTROL:	/* 16-bit access */

		status =
		    acpi_hw_low_level_read(16, &value1,
					   &acpi_sinfo.pm1a_cnt_blk);
		if (ACPI_FAILURE(status)) {
			goto exit;
		}

		status =
		    acpi_hw_low_level_read(16, &value2,
					   &acpi_sinfo.pm1b_cnt_blk);
		value1 |= value2;
		break;


	default:
		status = AE_BAD_PARAMETER;
		break;
	}

      exit:

	if (ACPI_SUCCESS(status)) {
		*return_value = value1;
	}

	return_ACPI_STATUS(status);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_hw_register_write
 *
 * PARAMETERS:  register_id         - ACPI Register ID 
 *              Value               - The value to write
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Write to the specified ACPI register
 *
 * NOTE: In accordance with the ACPI specification, this function automatically
 * preserves the value of the following bits, meaning that these bits cannot be
 * changed via this interface:
 *
 * PM1_CONTROL[0] = SCI_EN
 * PM1_CONTROL[9]
 * PM1_STATUS[11]
 *
 * ACPI References:
 * 1) Hardware Ignored Bits: When software writes to a register with ignored
 *      bit fields, it preserves the ignored bit fields
 * 2) SCI_EN: OSPM always preserves this bit position
 *
 ******************************************************************************/

acpi_status acpi_hw_register_write(u32 register_id, u32 value)
{
	acpi_status status;
	u32 read_value;

	ACPI_FUNCTION_TRACE(hw_register_write);

	switch (register_id) {   //By now we just need handle PM1 status/PM1 control
	case ACPI_REGISTER_PM1_STATUS:	/* 16-bit access */

		/* Perform a read first to preserve certain bits (per ACPI spec) */

		status = acpi_hw_register_read(ACPI_REGISTER_PM1_STATUS,
					       &read_value);
		if (ACPI_FAILURE(status)) {
			goto exit;
		}

		/* Insert the bits to be preserved */

		ACPI_INSERT_BITS(value, ACPI_PM1_STATUS_PRESERVED_BITS,
				 read_value);

		/* Now we can write the data */

		status =
		    acpi_hw_low_level_write(16, value,
					    &acpi_sinfo.pm1a_evt_blk);
		if (ACPI_FAILURE(status)) {
			goto exit;
		}

		/* PM1B is optional */

		status =
		    acpi_hw_low_level_write(16, value,
					    &acpi_sinfo.pm1b_evt_blk);
		break;


	case ACPI_REGISTER_PM1_CONTROL:	/* 16-bit access */

		/*
		 * Perform a read first to preserve certain bits (per ACPI spec)
		 *
		 * Note: This includes SCI_EN, we never want to change this bit
		 */
		status = acpi_hw_register_read(ACPI_REGISTER_PM1_CONTROL,
					       &read_value);
		if (ACPI_FAILURE(status)) {
			goto exit;
		}

		/* Insert the bits to be preserved */

		ACPI_INSERT_BITS(value, ACPI_PM1_CONTROL_PRESERVED_BITS,
				 read_value);

		/* Now we can write the data */

		status =
		    acpi_hw_low_level_write(16, value,
					    &acpi_sinfo.pm1a_cnt_blk);
		if (ACPI_FAILURE(status)) {
			goto exit;
		}

		status =
		    acpi_hw_low_level_write(16, value,
					    &acpi_sinfo.pm1b_cnt_blk);
		break;

	case ACPI_REGISTER_PM1A_CONTROL:	/* 16-bit access */

		status =
		    acpi_hw_low_level_write(16, value,
					    &acpi_sinfo.pm1a_cnt_blk);
		break;

	case ACPI_REGISTER_PM1B_CONTROL:	/* 16-bit access */

		status =
		    acpi_hw_low_level_write(16, value,
					    &acpi_sinfo.pm1b_cnt_blk);
		break;


	default:
		status = AE_BAD_PARAMETER;
		break;
	}

      exit:

	return_ACPI_STATUS(status);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_hw_low_level_read
 *
 * PARAMETERS:  Width               - 8, 16, or 32
 *              Value               - Where the value is returned
 *              Reg                 - GAS register structure
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Read from either memory or IO space.
 *
 ******************************************************************************/

acpi_status
acpi_hw_low_level_read(u32 width, u32 * value, struct acpi_generic_address *reg)
{
	u64 address;
	acpi_status status;

	ACPI_FUNCTION_NAME(hw_low_level_read);

	/*
	 * Must have a valid pointer to a GAS structure, and
	 * a non-zero address within. However, don't return an error
	 * because the PM1A/B code must not fail if B isn't present.
	 */
	if (!reg) {
		return (AE_OK);
	}

	/* Get a local copy of the address. Handles possible alignment issues */

	ACPI_MOVE_64_TO_64(&address, &reg->address);
	if (!address) {
		return (AE_OK);
	}
	*value = 0;

	/*
	 * Two address spaces supported: Memory or IO.
	 * PCI_Config is not supported here because the GAS struct is insufficient
	 */
	switch (reg->space_id) {
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:

		status = acpi_os_read_memory((acpi_physical_address) address,
					     value, width);
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:

		status = acpi_os_read_port((acpi_io_address) address,
					   value, width);
		break;

	default:

		return (AE_BAD_PARAMETER);
	}

	ACPI_DEBUG_PRINT((ACPI_DB_IO,
			  "Read:  %8.8X width %2d from %8.8X%8.8X (%s)\n",
			  *value, width,
			  ACPI_FORMAT_UINT64(address),
			  acpi_ut_get_region_name(reg->address_space_id)));

	return (status);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_hw_low_level_write
 *
 * PARAMETERS:  Width               - 8, 16, or 32
 *              Value               - To be written
 *              Reg                 - GAS register structure
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Write to either memory or IO space.
 *
 ******************************************************************************/

acpi_status
acpi_hw_low_level_write(u32 width, u32 value, struct acpi_generic_address * reg)
{
	u64 address;
	acpi_status status;

	ACPI_FUNCTION_NAME(hw_low_level_write);

	/*
	 * Must have a valid pointer to a GAS structure, and
	 * a non-zero address within. However, don't return an error
	 * because the PM1A/B code must not fail if B isn't present.
	 */
	if (!reg) {
		return (AE_OK);
	}

	/* Get a local copy of the address. Handles possible alignment issues */

	ACPI_MOVE_64_TO_64(&address, &reg->address);
	if (!address) {
		return (AE_OK);
	}

	/*
	 * Two address spaces supported: Memory or IO.
	 * PCI_Config is not supported here because the GAS struct is insufficient
	 */
	switch (reg->space_id) {
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:

		status = acpi_os_write_memory((acpi_physical_address) address,
					      value, width);
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:

		status = acpi_os_write_port((acpi_io_address) address,
					    value, width);
		break;

	default:
		return (AE_BAD_PARAMETER);
	}

	ACPI_DEBUG_PRINT((ACPI_DB_IO,
			  "Wrote: %8.8X width %2d   to %8.8X%8.8X (%s)\n",
			  value, width,
			  ACPI_FORMAT_UINT64(address),
			  acpi_ut_get_region_name(reg->address_space_id)));

	return (status);
}
