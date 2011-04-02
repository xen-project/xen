/******************************************************************************
 *
 * Name: acutils.h -- prototypes for the common (subsystem-wide) procedures
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

#ifndef _ACUTILS_H
#define _ACUTILS_H

/* Types for Resource descriptor entries */

#define ACPI_INVALID_RESOURCE           0
#define ACPI_FIXED_LENGTH               1
#define ACPI_VARIABLE_LENGTH            2
#define ACPI_SMALL_VARIABLE_LENGTH      3

/*
 * utglobal - Global data structures and procedures
 */
const char *acpi_ut_get_region_name(u8 space_id);

/*
 * utclib - Local implementations of C library functions
 */
#ifndef ACPI_USE_SYSTEM_CLIBRARY

acpi_size acpi_ut_strlen(const char *string);

char *acpi_ut_strcpy(char *dst_string, const char *src_string);

char *acpi_ut_strncpy(char *dst_string,
		      const char *src_string, acpi_size count);

int acpi_ut_memcmp(const char *buffer1, const char *buffer2, acpi_size count);

int acpi_ut_strncmp(const char *string1, const char *string2, acpi_size count);

int acpi_ut_strcmp(const char *string1, const char *string2);

char *acpi_ut_strcat(char *dst_string, const char *src_string);

char *acpi_ut_strncat(char *dst_string,
		      const char *src_string, acpi_size count);

u32 acpi_ut_strtoul(const char *string, char **terminator, u32 base);

char *acpi_ut_strstr(char *string1, char *string2);

void *acpi_ut_memcpy(void *dest, const void *src, acpi_size count);

void *acpi_ut_memset(void *dest, acpi_native_uint value, acpi_size count);

int acpi_ut_to_upper(int c);

int acpi_ut_to_lower(int c);

extern const u8 _acpi_ctype[];

#define _ACPI_XA     0x00	/* extra alphabetic - not supported */
#define _ACPI_XS     0x40	/* extra space */
#define _ACPI_BB     0x00	/* BEL, BS, etc. - not supported */
#define _ACPI_CN     0x20	/* CR, FF, HT, NL, VT */
#define _ACPI_DI     0x04	/* '0'-'9' */
#define _ACPI_LO     0x02	/* 'a'-'z' */
#define _ACPI_PU     0x10	/* punctuation */
#define _ACPI_SP     0x08	/* space */
#define _ACPI_UP     0x01	/* 'A'-'Z' */
#define _ACPI_XD     0x80	/* '0'-'9', 'A'-'F', 'a'-'f' */

#define ACPI_IS_DIGIT(c)  (_acpi_ctype[(unsigned char)(c)] & (_ACPI_DI))
#define ACPI_IS_SPACE(c)  (_acpi_ctype[(unsigned char)(c)] & (_ACPI_SP))
#define ACPI_IS_XDIGIT(c) (_acpi_ctype[(unsigned char)(c)] & (_ACPI_XD))
#define ACPI_IS_UPPER(c)  (_acpi_ctype[(unsigned char)(c)] & (_ACPI_UP))
#define ACPI_IS_LOWER(c)  (_acpi_ctype[(unsigned char)(c)] & (_ACPI_LO))
#define ACPI_IS_PRINT(c)  (_acpi_ctype[(unsigned char)(c)] & (_ACPI_LO | _ACPI_UP | _ACPI_DI | _ACPI_SP | _ACPI_PU))
#define ACPI_IS_ALPHA(c)  (_acpi_ctype[(unsigned char)(c)] & (_ACPI_LO | _ACPI_UP))

#endif				/* ACPI_USE_SYSTEM_CLIBRARY */

/*
 * utdebug - Debug interfaces
 */
void acpi_ut_track_stack_ptr(void);

void
acpi_ut_trace(u32 line_number,
	      const char *function_name, const char *module_name, u32 component_id);

void
acpi_ut_trace_ptr(u32 line_number,
		  const char *function_name,
		  const char *module_name, u32 component_id, void *pointer);

void
acpi_ut_trace_u32(u32 line_number,
		  const char *function_name,
		  const char *module_name, u32 component_id, u32 integer);

void
acpi_ut_trace_str(u32 line_number,
		  const char *function_name,
		  const char *module_name, u32 component_id, char *string);

void
acpi_ut_exit(u32 line_number,
	     const char *function_name, const char *module_name, u32 component_id);

void
acpi_ut_status_exit(u32 line_number,
		    const char *function_name,
		    const char *module_name, u32 component_id, acpi_status status);

void
acpi_ut_value_exit(u32 line_number,
		   const char *function_name,
		   const char *module_name, u32 component_id, acpi_integer value);

void
acpi_ut_ptr_exit(u32 line_number,
		 const char *function_name,
		 const char *module_name, u32 component_id, u8 * ptr);

/* Error and message reporting interfaces */

void ACPI_INTERNAL_VAR_XFACE
acpi_ut_debug_print(u32 requested_debug_level,
		    u32 line_number,
		    const char *function_name,
		    const char *module_name,
		    u32 component_id, char *format, ...) ACPI_PRINTF_LIKE(6);

void ACPI_INTERNAL_VAR_XFACE
acpi_ut_debug_print_raw(u32 requested_debug_level,
			u32 line_number,
			const char *function_name,
			const char *module_name,
			u32 component_id,
			char *format, ...) ACPI_PRINTF_LIKE(6);

void ACPI_INTERNAL_VAR_XFACE
acpi_ut_error(const char *module_name,
	      u32 line_number, char *format, ...) ACPI_PRINTF_LIKE(3);

void ACPI_INTERNAL_VAR_XFACE
acpi_ut_exception(const char *module_name,
		  u32 line_number,
		  acpi_status status, char *format, ...) ACPI_PRINTF_LIKE(4);

void ACPI_INTERNAL_VAR_XFACE
acpi_ut_warning(const char *module_name,
		u32 line_number, char *format, ...) ACPI_PRINTF_LIKE(3);

void ACPI_INTERNAL_VAR_XFACE
acpi_ut_info(const char *module_name,
	     u32 line_number, char *format, ...) ACPI_PRINTF_LIKE(3);

/*
 * utmisc
 */
const char *acpi_ut_validate_exception(acpi_status status);

#endif				/* _ACUTILS_H */
