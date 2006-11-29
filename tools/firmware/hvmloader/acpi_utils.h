/*
 * Commonly used ACPI utility functions.
 *
 * Yu Ke, ke.yu@intel.com
 * Copyright (c) 2005, Intel Corporation.
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
 */
#ifndef ACPI_UTILS_H
#define ACPI_UTILS_H

#define FIELD_OFFSET(TYPE,Field) ((unsigned int)(&(((TYPE *) 0)->Field)))

#define NULL ((void*)0)

void set_checksum(void *start, int checksum_offset, int len);
void acpi_update(unsigned char *acpi_start,
                 unsigned long acpi_size,
                 unsigned char *limit,
                 unsigned char **freemem);

struct acpi_20_rsdt *acpi_rsdt_get(unsigned char *acpi_start);
struct acpi_20_xsdt *acpi_xsdt_get(unsigned char *acpi_start);

#endif
