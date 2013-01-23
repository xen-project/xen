/******************************************************************************
 *
 * Module Name: tbxface - Public interfaces to the ACPI subsystem
 *                         ACPI table oriented interfaces
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

#include <xen/config.h>
#include <xen/init.h>
#include <acpi/acpi.h>
#include <acpi/actables.h>

#define _COMPONENT          ACPI_TABLES
ACPI_MODULE_NAME("tbxface")

/*******************************************************************************
 *
 * FUNCTION:    acpi_allocate_root_table
 *
 * PARAMETERS:  initial_table_count - Size of initial_table_array, in number of
 *                                    struct acpi_table_desc structures
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Allocate a root table array. Used by i_aSL compiler and
 *              acpi_initialize_tables.
 *
 ******************************************************************************/

acpi_status __init acpi_allocate_root_table(u32 initial_table_count)
{

	acpi_gbl_root_table_list.size = initial_table_count -
					ACPI_ROOT_TABLE_SIZE_INCREMENT;
	acpi_gbl_root_table_list.flags = ACPI_ROOT_ALLOW_RESIZE;

	return (acpi_tb_resize_root_table_list());
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_initialize_tables
 *
 * PARAMETERS:  initial_table_array - Pointer to an array of pre-allocated
 *                                    struct acpi_table_desc structures. If NULL, the
 *                                    array is dynamically allocated.
 *              initial_table_count - Size of initial_table_array, in number of
 *                                    struct acpi_table_desc structures
 *              allow_realloc       - Flag to tell Table Manager if resize of
 *                                    pre-allocated array is allowed. Ignored
 *                                    if initial_table_array is NULL.
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Initialize the table manager, get the RSDP and RSDT/XSDT.
 *
 * NOTE:        Allows static allocation of the initial table array in order
 *              to avoid the use of dynamic memory in confined environments
 *              such as the kernel boot sequence where it may not be available.
 *
 *              If the host OS memory managers are initialized, use NULL for
 *              initial_table_array, and the table will be dynamically allocated.
 *
 ******************************************************************************/

acpi_status __init
acpi_initialize_tables(struct acpi_table_desc * initial_table_array,
		       u32 initial_table_count, u8 allow_resize)
{
	acpi_physical_address rsdp_address;
	acpi_status status;

	ACPI_FUNCTION_TRACE(acpi_initialize_tables);

	/*
	 * Set up the Root Table Array
	 * Allocate the table array if requested
	 */
	if (!initial_table_array) {
		status = acpi_allocate_root_table(initial_table_count);
		if (ACPI_FAILURE(status)) {
			return_ACPI_STATUS(status);
		}
	} else {
		/* Root Table Array has been statically allocated by the host */

		ACPI_MEMSET(initial_table_array, 0,
			    initial_table_count *
			    sizeof(struct acpi_table_desc));

		acpi_gbl_root_table_list.tables = initial_table_array;
		acpi_gbl_root_table_list.size = initial_table_count;
		acpi_gbl_root_table_list.flags = ACPI_ROOT_ORIGIN_UNKNOWN;
		if (allow_resize) {
			acpi_gbl_root_table_list.flags |=
			    ACPI_ROOT_ALLOW_RESIZE;
		}
	}

	/* Get the address of the RSDP */

	rsdp_address = acpi_os_get_root_pointer();
	if (!rsdp_address) {
		return_ACPI_STATUS(AE_NOT_FOUND);
	}

	/*
	 * Get the root table (RSDT or XSDT) and extract all entries to the local
	 * Root Table Array. This array contains the information of the RSDT/XSDT
	 * in a common, more useable format.
	 */
	status =
	    acpi_tb_parse_root_table(rsdp_address, ACPI_TABLE_ORIGIN_MAPPED);
	return_ACPI_STATUS(status);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_get_table
 *
 * PARAMETERS:  Signature           - ACPI signature of needed table
 *              Instance            - Which instance (for SSDTs)
 *              out_table           - Where the pointer to the table is returned
 *
 * RETURN:      Status and pointer to table
 *
 * DESCRIPTION: Finds and verifies an ACPI table.
 *
 *****************************************************************************/
acpi_status __init
acpi_get_table(char *signature,
	       acpi_native_uint instance, struct acpi_table_header **out_table)
{
	acpi_native_uint i;
	acpi_native_uint j;
	acpi_status status;

	/* Parameter validation */

	if (!signature || !out_table) {
		return (AE_BAD_PARAMETER);
	}

	/*
	 * Walk the root table list
	 */
	for (i = 0, j = 0; i < acpi_gbl_root_table_list.count; i++) {
		if (!ACPI_COMPARE_NAME
		    (&(acpi_gbl_root_table_list.tables[i].signature),
		     signature)) {
			continue;
		}

		if (++j < instance) {
			continue;
		}

		status =
		    acpi_tb_verify_table(&acpi_gbl_root_table_list.tables[i]);
		if (ACPI_SUCCESS(status)) {
			*out_table = acpi_gbl_root_table_list.tables[i].pointer;
		}

		acpi_gbl_root_table_list.tables[i].pointer = NULL;

		return (status);
	}

	return (AE_NOT_FOUND);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_get_table_phys
 *
 * PARAMETERS:  signature      - ACPI signature of needed table
 *              instance       - Which instance (for SSDTs)
 *              addr           - Where the table's physical address is returned
 *              len            - Where the length of table is returned
 *
 * RETURN:      Status, pointer and length of table
 *
 * DESCRIPTION: Finds physical address and length of ACPI table
 *
 *****************************************************************************/
acpi_status __init
acpi_get_table_phys(acpi_string signature, acpi_native_uint instance,
		     acpi_physical_address *addr, acpi_native_uint *len)
{
	acpi_native_uint i, j;
	acpi_status status;

	if (!signature || !addr || !len)
		return AE_BAD_PARAMETER;

	for (i = j = 0; i < acpi_gbl_root_table_list.count; i++) {
		if (!ACPI_COMPARE_NAME(
				&acpi_gbl_root_table_list.tables[i].signature,
				signature))
			continue;

		if (++j < instance)
			continue;

		status =
		    acpi_tb_verify_table(&acpi_gbl_root_table_list.tables[i]);
		if (ACPI_SUCCESS(status)) {
			*addr = acpi_gbl_root_table_list.tables[i].address;
			*len = acpi_gbl_root_table_list.tables[i].length;
		}

		acpi_gbl_root_table_list.tables[i].pointer = NULL;

		return status;
	}

	return AE_NOT_FOUND;
}
