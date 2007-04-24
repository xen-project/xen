/*
 *  32bitbios - jumptable for those function reachable from 16bit area
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#include "rombios_compat.h"
#include "32bitprotos.h"

/*
   the jumptable that will be copied into the rombios in the 0xf000 segment
   for every function that is to be called from the lower BIOS, make an entry
   here.
 */
#define TABLE_ENTRY(idx, func) [idx] = (uint32_t)func
uint32_t jumptable[IDX_LAST+1] __attribute__((section (".biosjumptable"))) =
{
	TABLE_ENTRY(IDX_TCPA_ACPI_INIT, tcpa_acpi_init),
	TABLE_ENTRY(IDX_TCPA_EXTEND_ACPI_LOG, tcpa_extend_acpi_log),

	TABLE_ENTRY(IDX_TCGINTERRUPTHANDLER, TCGInterruptHandler),

	TABLE_ENTRY(IDX_TCPA_CALLING_INT19H, tcpa_calling_int19h),
	TABLE_ENTRY(IDX_TCPA_RETURNED_INT19H, tcpa_returned_int19h),
	TABLE_ENTRY(IDX_TCPA_ADD_EVENT_SEPARATORS, tcpa_add_event_separators),
	TABLE_ENTRY(IDX_TCPA_WAKE_EVENT, tcpa_wake_event),
	TABLE_ENTRY(IDX_TCPA_ADD_BOOTDEVICE, tcpa_add_bootdevice),
	TABLE_ENTRY(IDX_TCPA_START_OPTION_ROM_SCAN, tcpa_start_option_rom_scan),
	TABLE_ENTRY(IDX_TCPA_OPTION_ROM, tcpa_option_rom),
	TABLE_ENTRY(IDX_TCPA_IPL, tcpa_ipl),
	TABLE_ENTRY(IDX_TCPA_MEASURE_POST, tcpa_measure_post),

	TABLE_ENTRY(IDX_TCPA_INITIALIZE_TPM, tcpa_initialize_tpm),

	TABLE_ENTRY(IDX_LAST       , 0)     /* keep last */
};
