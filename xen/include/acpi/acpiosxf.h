
/******************************************************************************
 *
 * Name: acpiosxf.h - All interfaces to the OS Services Layer (OSL).  These
 *                    interfaces must be implemented by OSL to interface the
 *                    ACPI components to the host operating system.
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

#ifndef __ACPIOSXF_H__
#define __ACPIOSXF_H__

#include "platform/acenv.h"
#include "actypes.h"

/*
 * ACPI Table interfaces
 */
acpi_physical_address acpi_os_get_root_pointer(void);

/*
 * Memory mapping
 */
void __iomem *acpi_os_map_memory(acpi_physical_address where,
				 acpi_native_uint length);

void acpi_os_unmap_memory(void __iomem * logical_address, acpi_size size);

/*
 * Platform and hardware-independent I/O interfaces
 */
acpi_status acpi_os_read_port(acpi_io_address address, u32 * value, u32 width);

acpi_status acpi_os_write_port(acpi_io_address address, u32 value, u32 width);

/*
 * Platform and hardware-independent physical memory interfaces
 */
acpi_status
acpi_os_read_memory(acpi_physical_address address, u32 * value, u32 width);

acpi_status
acpi_os_write_memory(acpi_physical_address address, u32 value, u32 width);

/*
 * Debug print routines
 */
void ACPI_INTERNAL_VAR_XFACE acpi_os_printf(const char *format, ...);

void acpi_os_vprintf(const char *format, va_list args);

#endif				/* __ACPIOSXF_H__ */
