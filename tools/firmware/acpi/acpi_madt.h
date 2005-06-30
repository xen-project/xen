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
#ifndef _MADT_H_
#define _MADT_H_

#include "acpi2_0.h"

//
// MADT Definitions, see ACPI 2.0 specification for details
//

#define ACPI_LOCAL_APIC_ADDRESS 0xFEE00000

#define ACPI_MULTIPLE_APIC_FLAGS      (ACPI_PCAT_COMPAT)

#define ACPI_IO_APIC_ADDRESS_1   0xFEC00000

//
// MADT structure
//
#pragma pack (1)
typedef struct {
  ACPI_2_0_MADT   				Header;
  ACPI_LOCAL_APIC_STRUCTURE     LocalApic[4];
  ACPI_IO_APIC_STRUCTURE        IoApic[1];
} ACPI_MULTIPLE_APIC_DESCRIPTION_TABLE;
#pragma pack ()

#endif
