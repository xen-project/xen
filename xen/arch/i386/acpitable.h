/*
 *  acpitable.c - IA32-specific ACPI boot-time initialization (Revision: 1)
 *
 *  Copyright (C) 1999 Andrew Henroid
 *  Copyright (C) 2001 Richard Schaal
 *  Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Jun Nakajima <jun.nakajima@intel.com>
 *  Copyright (C) 2001 Arjan van de Ven <arjanv@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * $Id: acpitable.h,v 1.3 2001/11/03 22:41:34 fenrus Exp $
 */

/*
 * The following codes are cut&pasted from drivers/acpi. Part of the code
 * there can be not updated or delivered yet.
 * To avoid conflicts when CONFIG_ACPI is defined, the following codes are
 * modified so that they are self-contained in this file.
 * -- jun
 */
 
#ifndef _HEADER_ACPITABLE_H_
#define _HEADER_ACPITABLE_H_

#define dprintk printk
typedef unsigned int ACPI_TBLPTR;

typedef struct {		/* ACPI common table header */
	char signature[4];	/* identifies type of table */
	u32 length;		/* length of table,
				   in bytes, * including header */
	u8 revision;		/* specification minor version # */
	u8 checksum;		/* to make sum of entire table == 0 */
	char oem_id[6];		/* OEM identification */
	char oem_table_id[8];	/* OEM table identification */
	u32 oem_revision;	/* OEM revision number */
	char asl_compiler_id[4];	/* ASL compiler vendor ID */
	u32 asl_compiler_revision;	/* ASL compiler revision number */
} acpi_table_header __attribute__ ((packed));;

enum {
	ACPI_APIC = 0,
	ACPI_BOOT,
	ACPI_DBGP,
	ACPI_DSDT,
	ACPI_ECDT,
	ACPI_ETDT,
	ACPI_FACP,
	ACPI_FACS,
	ACPI_OEMX,
	ACPI_PSDT,
	ACPI_SBST,
	ACPI_SLIT,
	ACPI_SPCR,
	ACPI_SRAT,
	ACPI_SSDT,
	ACPI_SPMI,
	ACPI_XSDT,
	ACPI_TABLE_COUNT
};

static char *acpi_table_signatures[ACPI_TABLE_COUNT] = {
	"APIC",
	"BOOT",
	"DBGP",
	"DSDT",
	"ECDT",
	"ETDT",
	"FACP",
	"FACS",
	"OEM",
	"PSDT",
	"SBST",
	"SLIT",
	"SPCR",
	"SRAT",
	"SSDT",
	"SPMI",
	"XSDT"
};

struct acpi_table_madt {
	acpi_table_header header;
	u32 lapic_address;
	struct {
		u32 pcat_compat:1;
		u32 reserved:31;
	} flags __attribute__ ((packed));
} __attribute__ ((packed));;

enum {
	ACPI_MADT_LAPIC = 0,
	ACPI_MADT_IOAPIC,
	ACPI_MADT_INT_SRC_OVR,
	ACPI_MADT_NMI_SRC,
	ACPI_MADT_LAPIC_NMI,
	ACPI_MADT_LAPIC_ADDR_OVR,
	ACPI_MADT_IOSAPIC,
	ACPI_MADT_LSAPIC,
	ACPI_MADT_PLAT_INT_SRC,
	ACPI_MADT_ENTRY_COUNT
};

#define RSDP_SIG			"RSD PTR "
#define RSDT_SIG 			"RSDT"

#define ACPI_DEBUG_PRINT(pl)

#define ACPI_MEMORY_MODE                0x01
#define ACPI_LOGICAL_ADDRESSING         0x00
#define ACPI_PHYSICAL_ADDRESSING        0x01

#define LO_RSDP_WINDOW_BASE         	0	/* Physical Address */
#define HI_RSDP_WINDOW_BASE         	0xE0000	/* Physical Address */
#define LO_RSDP_WINDOW_SIZE         	0x400
#define HI_RSDP_WINDOW_SIZE         	0x20000
#define RSDP_SCAN_STEP			16
#define RSDP_CHECKSUM_LENGTH		20

typedef int (*acpi_table_handler) (acpi_table_header * header, unsigned long);

struct acpi_table_rsdp {
	char signature[8];
	u8 checksum;
	char oem_id[6];
	u8 revision;
	u32 rsdt_address;
} __attribute__ ((packed));

struct acpi_table_rsdt {
	acpi_table_header header;
	u32 entry[ACPI_TABLE_COUNT];
} __attribute__ ((packed));

typedef struct {
	u8 type;
	u8 length;
} acpi_madt_entry_header __attribute__ ((packed));

typedef struct {
	u16 polarity:2;
	u16 trigger:2;
	u16 reserved:12;
} acpi_madt_int_flags __attribute__ ((packed));

struct acpi_table_lapic {
	acpi_madt_entry_header header;
	u8 acpi_id;
	u8 id;
	struct {
		u32 enabled:1;
		u32 reserved:31;
	} flags __attribute__ ((packed));
} __attribute__ ((packed));

struct acpi_table_ioapic {
	acpi_madt_entry_header header;
	u8 id;
	u8 reserved;
	u32 address;
	u32 global_irq_base;
} __attribute__ ((packed));

struct acpi_table_int_src_ovr {
	acpi_madt_entry_header header;
	u8 bus;
	u8 bus_irq;
	u32 global_irq;
	acpi_madt_int_flags flags;
} __attribute__ ((packed));

struct acpi_table_nmi_src {
	acpi_madt_entry_header header;
	acpi_madt_int_flags flags;
	u32 global_irq;
} __attribute__ ((packed));

struct acpi_table_lapic_nmi {
	acpi_madt_entry_header header;
	u8 acpi_id;
	acpi_madt_int_flags flags;
	u8 lint;
} __attribute__ ((packed));

struct acpi_table_lapic_addr_ovr {
	acpi_madt_entry_header header;
	u8 reserved[2];
	u64 address;
} __attribute__ ((packed));

struct acpi_table_iosapic {
	acpi_madt_entry_header header;
	u8 id;
	u8 reserved;
	u32 global_irq_base;
	u64 address;
} __attribute__ ((packed));

struct acpi_table_lsapic {
	acpi_madt_entry_header header;
	u8 acpi_id;
	u8 id;
	u8 eid;
	u8 reserved[3];
	struct {
		u32 enabled:1;
		u32 reserved:31;
	} flags;
} __attribute__ ((packed));

struct acpi_table_plat_int_src {
	acpi_madt_entry_header header;
	acpi_madt_int_flags flags;
	u8 type;
	u8 id;
	u8 eid;
	u8 iosapic_vector;
	u32 global_irq;
	u32 reserved;
} __attribute__ ((packed));

/*
 * ACPI Table Descriptor.  One per ACPI table
 */
typedef struct acpi_table_desc {
	struct acpi_table_desc *prev;
	struct acpi_table_desc *next;
	struct acpi_table_desc *installed_desc;
	acpi_table_header *pointer;
	void *base_pointer;
	u8 *aml_pointer;
	u64 physical_address;
	u32 aml_length;
	u32 length;
	u32 count;
	u16 table_id;
	u8 type;
	u8 allocation;
	u8 loaded_into_namespace;

} acpi_table_desc __attribute__ ((packed));;

#endif
