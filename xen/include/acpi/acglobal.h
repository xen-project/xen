/******************************************************************************
 *
 * Name: acglobal.h - Declarations for global variables
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

#ifndef __ACGLOBAL_H__
#define __ACGLOBAL_H__

/*
 * Ensure that the globals are actually defined and initialized only once.
 *
 * The use of these macros allows a single list of globals (here) in order
 * to simplify maintenance of the code.
 */
#ifdef DEFINE_ACPI_GLOBALS
#define ACPI_EXTERN
#define ACPI_INIT_GLOBAL(a,b) a=b
#else
#define ACPI_EXTERN extern
#define ACPI_INIT_GLOBAL(a,b) a
#endif

/*****************************************************************************
 *
 * ACPI Table globals
 *
 ****************************************************************************/

/*
 * acpi_gbl_root_table_list is the master list of ACPI tables found in the
 * RSDT/XSDT.
 *
 * acpi_gbl_FADT is a local copy of the FADT, converted to a common format.
 */
ACPI_EXTERN struct acpi_internal_rsdt acpi_gbl_root_table_list;
ACPI_EXTERN struct acpi_table_fadt acpi_gbl_FADT;

/* These addresses are calculated from FADT address values */

ACPI_EXTERN struct acpi_generic_address acpi_gbl_xpm1a_enable;
ACPI_EXTERN struct acpi_generic_address acpi_gbl_xpm1b_enable;

/*
 * ACPI 5.0 introduces the concept of a "reduced hardware platform", meaning
 * that the ACPI hardware is no longer required. A flag in the FADT indicates
 * a reduced HW machine, and that flag is duplicated here for convenience.
 */
ACPI_EXTERN u8 acpi_gbl_reduced_hardware;

/*****************************************************************************
 *
 * Miscellaneous globals
 *
 ****************************************************************************/

#ifndef DEFINE_ACPI_GLOBALS

extern char const *acpi_gbl_exception_names_env[];
extern char const *acpi_gbl_exception_names_pgm[];
extern char const *acpi_gbl_exception_names_tbl[];
extern char const *acpi_gbl_exception_names_aml[];
extern char const *acpi_gbl_exception_names_ctrl[];

#endif

/*****************************************************************************
 *
 * Hardware globals
 *
 ****************************************************************************/

extern struct acpi_bit_register_info
    acpi_gbl_bit_register_info[ACPI_NUM_BITREG];

#endif				/* __ACGLOBAL_H__ */
