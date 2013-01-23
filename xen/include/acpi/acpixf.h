
/******************************************************************************
 *
 * Name: acpixf.h - External interfaces to the ACPI subsystem
 *
 *****************************************************************************/

/*
 * Copyright (C) 2000 - 2007, R. Byron Moore
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

#ifndef __ACXFACE_H__
#define __ACXFACE_H__

#include "actypes.h"
#include "actbl.h"

/*
 * Global interfaces
 */
acpi_status
acpi_initialize_tables(struct acpi_table_desc *initial_storage,
		       u32 initial_table_count, u8 allow_resize);

const char *acpi_format_exception(acpi_status exception);

/*
 * ACPI table manipulation interfaces
 */
acpi_status acpi_reallocate_root_table(void);

acpi_status acpi_find_root_pointer(acpi_native_uint * rsdp_address);

acpi_status acpi_load_tables(void);

acpi_status acpi_load_table(struct acpi_table_header *table_ptr);

acpi_status
acpi_get_table_header(acpi_string signature,
		      acpi_native_uint instance,
		      struct acpi_table_header *out_table_header);

acpi_status
acpi_get_table(acpi_string signature,
	       acpi_native_uint instance, struct acpi_table_header **out_table);

acpi_status
acpi_get_table_phys(acpi_string signature, acpi_native_uint instance,
		     acpi_physical_address *addr, acpi_native_uint *len);
/*
 * Namespace and name interfaces
 */
acpi_status
acpi_get_handle(acpi_handle parent,
		acpi_string pathname, acpi_handle * ret_handle);

acpi_status
acpi_debug_trace(char *name, u32 debug_level, u32 debug_layer, u32 flags);

acpi_status
acpi_get_object_info(acpi_handle handle, struct acpi_buffer *return_buffer);

acpi_status acpi_get_type(acpi_handle object, acpi_object_type * out_type);

acpi_status acpi_get_parent(acpi_handle object, acpi_handle * out_handle);

/*
 * Hardware (ACPI device) interfaces
 */
acpi_status acpi_get_register(u32 register_id, u32 * return_value);

acpi_status acpi_set_register(u32 register_id, u32 value);

acpi_status
acpi_set_firmware_waking_vector(acpi_physical_address physical_address);

#ifdef ACPI_FUTURE_USAGE
acpi_status
acpi_get_firmware_waking_vector(acpi_physical_address * physical_address);
#endif

acpi_status
acpi_get_sleep_type_data(u8 sleep_state, u8 * slp_typ_a, u8 * slp_typ_b);

acpi_status acpi_enter_sleep_state_prep(u8 sleep_state);

acpi_status asmlinkage acpi_enter_sleep_state(u8 sleep_state);

acpi_status asmlinkage acpi_enter_sleep_state_s4bios(void);

acpi_status acpi_leave_sleep_state_prep(u8 sleep_state);

acpi_status acpi_leave_sleep_state(u8 sleep_state);

#endif				/* __ACXFACE_H__ */
