/*
 * smbios.c - Generate SMBIOS tables for Xen HVM domU's.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Authors: Andrew D. Ball <aball@us.ibm.com>
 */

#include <stdint.h>
#include <xen/version.h>
#include <xen/hvm/e820.h>
#include "smbios.h"
#include "smbios_types.h"
#include "util.h"
#include "hypercall.h"

/* write SMBIOS tables starting at 'start', without writing more
   than 'max_size' bytes.

   Return the number of bytes written
*/
static size_t
write_smbios_tables(void *start, size_t max_size,
		    uint32_t vcpus, uint64_t memsize,
		    uint8_t uuid[16], char *xen_version,
		    uint32_t xen_major_version, uint32_t xen_minor_version);

static void
get_cpu_manufacturer(char *buf, int len);
static size_t
smbios_table_size(uint32_t vcpus, const char *xen_version,
		  const char *processor_manufacturer);
static void *
smbios_entry_point_init(void *start,
			uint16_t max_structure_size,
			uint16_t structure_table_length,
			uint32_t structure_table_address,
			uint16_t number_of_structures);
static void *
smbios_type_0_init(void *start, const char *xen_version,
		   uint32_t xen_major_version, uint32_t xen_minor_version);
static void *
smbios_type_1_init(void *start, const char *xen_version, 
		   uint8_t uuid[16]);
static void *
smbios_type_3_init(void *start);
static void *
smbios_type_4_init(void *start, unsigned int cpu_number,
		   char *cpu_manufacturer);
static void *
smbios_type_16_init(void *start, uint32_t memory_size_mb);
static void *
smbios_type_17_init(void *start, uint32_t memory_size_mb);
static void *
smbios_type_19_init(void *start, uint32_t memory_size_mb);
static void *
smbios_type_20_init(void *start, uint32_t memory_size_mb);
static void *
smbios_type_32_init(void *start);
void *
smbios_type_127_init(void *start);

static void
get_cpu_manufacturer(char *buf, int len)
{
	char id[12];
	uint32_t eax = 0;

	cpuid(0, &eax, (uint32_t *)&id[0], (uint32_t *)&id[8], (uint32_t *)&id[4]);

	if (memcmp(id, "GenuineIntel", 12) == 0)
		strncpy(buf, "Intel", len);
	else if (memcmp(id, "AuthenticAMD", 12) == 0)
		strncpy(buf, "AMD", len);
	else
		strncpy(buf, "unknown", len);
}


/* Calculate the size of the SMBIOS structure table.
*/
static size_t
smbios_table_size(uint32_t vcpus, const char *xen_version,
		  const char *processor_manufacturer)
{
	size_t size;

	/* first compute size without strings or terminating 0 bytes */
	size =  sizeof(struct smbios_type_0) + sizeof(struct smbios_type_1) +
		sizeof(struct smbios_type_3) + sizeof(struct smbios_type_4)*vcpus +
		sizeof(struct smbios_type_16) + sizeof(struct smbios_type_17) +
		sizeof(struct smbios_type_19) + sizeof(struct smbios_type_20) +
		sizeof(struct smbios_type_32) + sizeof(struct smbios_type_127);

	/* 5 structures with no strings, 2 null bytes each */
	size += 10;

	/* Need to include 1 null byte per structure with strings (first
	   terminating null byte comes from the string terminator of the
	   last string). */
	size += 4 + vcpus;

	/* type 0: "Xen", xen_version, and release_date */
	size += strlen("Xen") + strlen(xen_version) + 2;
	/* type 1: "Xen", xen_version, "HVM domU", UUID as string for 
                   serial number */
	size += strlen("Xen") + strlen("HVM domU") + strlen(xen_version) +
			36 + 4;
	/* type 3: "Xen" */
	size += strlen("Xen") + 1;
	/* type 4: socket designation ("CPU n"), processor_manufacturer */
	size += vcpus * (strlen("CPU n") + strlen(processor_manufacturer) + 2);
	/* Make room for two-digit CPU numbers if necessary -- doesn't handle
	   vcpus > 99 */
	if (vcpus > 9)
		size += vcpus - 9;
	/* type 17: device locator string ("DIMM 1") */
	size += strlen("DIMM 1") + 1;

	return size;
}

static size_t
write_smbios_tables(void *start, size_t max_size,
		    uint32_t vcpus, uint64_t memsize,
		    uint8_t uuid[16], char *xen_version,
		    uint32_t xen_major_version, uint32_t xen_minor_version)
{
	unsigned cpu_num;
	void *p = start;
	char cpu_manufacturer[15];
	size_t structure_table_length;

	get_cpu_manufacturer(cpu_manufacturer, 15);


	structure_table_length = smbios_table_size(vcpus, xen_version,
						   cpu_manufacturer);

	if (structure_table_length + sizeof(struct smbios_entry_point) > max_size)
		return 0;

	p = smbios_entry_point_init(p, sizeof(struct smbios_type_4), 
				    structure_table_length,
				    (uint32_t)start + 
				    sizeof(struct smbios_entry_point),
				    9 + vcpus);

	p = smbios_type_0_init(p, xen_version, xen_major_version,
			       xen_minor_version);
	p = smbios_type_1_init(p, xen_version, uuid);
	p = smbios_type_3_init(p);
	for (cpu_num = 1; cpu_num <= vcpus; ++cpu_num)
		p = smbios_type_4_init(p, cpu_num, cpu_manufacturer);
	p = smbios_type_16_init(p, memsize);
	p = smbios_type_17_init(p, memsize);
	p = smbios_type_19_init(p, memsize);
	p = smbios_type_20_init(p, memsize);
	p = smbios_type_32_init(p);
	p = smbios_type_127_init(p);

	return (size_t)((char*)p - (char*)start);
}

/* This tries to figure out how much pseudo-physical memory (in MB)
   is allocated to the current domU.

   It iterates through the e820 table, adding up the 'usable' and
   'reserved' entries and rounding up to the nearest MB.

   The e820map is not at e820 in hvmloader, so this uses the
   E820_MAP_* constants from e820.h to pick it up where libxenguest
   left it.
 */
static uint64_t
get_memsize(void)
{
	struct e820entry *map = NULL;
	uint8_t num_entries = 0;
	uint64_t memsize = 0;
	uint8_t i;

	map = (struct e820entry *) (E820_MAP_PAGE + E820_MAP_OFFSET);
	num_entries = *((uint8_t *) (E820_MAP_PAGE + E820_MAP_NR_OFFSET));

	/* walk through e820map, ignoring any entries that aren't marked
	   as usable or reserved. */

	for (i = 0; i < num_entries; i++) {
		if (map->type == E820_RAM || map->type == E820_RESERVED)
			memsize += map->size;
		map++;
	}

	/* Round up to the nearest MB.  The user specifies domU
	   pseudo-physical memory in megabytes, so not doing this
	   could easily lead to reporting one less MB than the user
	   specified. */
	if (memsize & ((1<<20)-1))
		memsize = (memsize >> 20) + 1;
	else
		memsize = (memsize >> 20);

	return memsize;
}

void
hvm_write_smbios_tables(void)
{
	uint8_t uuid[16]; /* ** This will break if xen_domain_handle_t is
			     not uint8_t[16]. ** */
	uint16_t xen_major_version, xen_minor_version;
	uint32_t xen_version;
	char xen_extra_version[XEN_EXTRAVERSION_LEN];
	/* guess conservatively on buffer length for Xen version string */
	char xen_version_str[80];
	/* temporary variables used to build up Xen version string */
	char *p = NULL; /* points to next point of insertion */
	unsigned len = 0; /* length of string already composed */
	char *tmp = NULL; /* holds result of itoa() */
	unsigned tmp_len; /* length of next string to add */

	hypercall_xen_version(XENVER_guest_handle, uuid);

	/* xen_version major and minor */
	xen_version = hypercall_xen_version(XENVER_version, NULL);
	xen_major_version = (uint16_t) (xen_version >> 16);
	xen_minor_version = (uint16_t) xen_version;

	hypercall_xen_version(XENVER_extraversion, xen_extra_version);

	/* build up human-readable Xen version string */
	p = xen_version_str;
	len = 0;

	itoa(tmp, xen_major_version);
	tmp_len = strlen(tmp);
	len += tmp_len;
	if (len >= sizeof(xen_version_str))
		goto error_out;
	strcpy(p, tmp);
	p += tmp_len;

	len++;
	if (len >= sizeof(xen_version_str))
		goto error_out;
	*p = '.';
	p++;

	itoa(tmp, xen_minor_version);
	tmp_len = strlen(tmp);
	len += tmp_len;
	if (len >= sizeof(xen_version_str))
		goto error_out;
	strcpy(p, tmp);
	p += tmp_len;

	tmp_len = strlen(xen_extra_version);
	len += tmp_len;
	if (len >= sizeof(xen_version_str))
		goto error_out;
	strcpy(p, xen_extra_version);
	p += tmp_len;

	xen_version_str[sizeof(xen_version_str)-1] = '\0';

	write_smbios_tables((void *) SMBIOS_PHYSICAL_ADDRESS,
			    SMBIOS_SIZE_LIMIT, get_vcpu_nr(), get_memsize(),
			    uuid, xen_version_str,
			    xen_major_version, xen_minor_version);
	return;

 error_out:
	puts("Could not write SMBIOS tables, error in hvmloader.c:"
	     "hvm_write_smbios_tables()\n");
}


static void *
smbios_entry_point_init(void *start,
			uint16_t max_structure_size,
			uint16_t structure_table_length,
			uint32_t structure_table_address,
			uint16_t number_of_structures)
{
	uint8_t sum;
	int i;
	struct smbios_entry_point *ep = (struct smbios_entry_point *)start;

	strncpy(ep->anchor_string, "_SM_", 4);
	ep->length = 0x1f;
	ep->smbios_major_version = 2;
	ep->smbios_minor_version = 4;
	ep->max_structure_size = max_structure_size;
	ep->entry_point_revision = 0;
	memset(ep->formatted_area, 0, 5);
	strncpy(ep->intermediate_anchor_string, "_DMI_", 5);
    
	ep->structure_table_length = structure_table_length;
	ep->structure_table_address = structure_table_address;
	ep->number_of_structures = number_of_structures;
	ep->smbios_bcd_revision = 0x24;

	ep->checksum = 0;
	ep->intermediate_checksum = 0;
    
	sum = 0;
	for (i = 0; i < 0x10; ++i)
		sum += ((int8_t *)start)[i];
	ep->checksum = -sum;

	sum = 0;
	for (i = 0x10; i < ep->length; ++i)
		sum += ((int8_t *)start)[i];
	ep->intermediate_checksum = -sum;

	return (char *)start + sizeof(struct smbios_entry_point);
}

/* Type 0 -- BIOS Information */
static void *
smbios_type_0_init(void *start, const char *xen_version,
		   uint32_t xen_major_version, uint32_t xen_minor_version)
{
	struct smbios_type_0 *p = (struct smbios_type_0 *)start;
    
	p->header.type = 0;
	p->header.length = sizeof(struct smbios_type_0);
	p->header.handle = 0;
    
	p->vendor_str = 1;
	p->version_str = 2;
	p->starting_address_segment = 0xe800;
	p->release_date_str = 0;
	p->rom_size = 0;
    
	memset(p->characteristics, 0, 8);
	p->characteristics[7] = 0x08; /* BIOS characteristics not supported */
	p->characteristics_extension_bytes[0] = 0;
	p->characteristics_extension_bytes[1] = 0;
    
	p->major_release = (uint8_t) xen_major_version;
	p->minor_release = (uint8_t) xen_minor_version;
	p->embedded_controller_major = 0xff;
	p->embedded_controller_minor = 0xff;

	start += sizeof(struct smbios_type_0);
	strcpy((char *)start, "Xen");
	start += strlen("Xen") + 1;
	strcpy((char *)start, xen_version);
	start += strlen(xen_version) + 1;

	*((uint8_t *)start) = 0;
	return start + 1;
}

/* Type 1 -- System Information */
static void *
smbios_type_1_init(void *start, const char *xen_version, 
		   uint8_t uuid[16])
{
	char uuid_str[37];
	struct smbios_type_1 *p = (struct smbios_type_1 *)start;
	p->header.type = 1;
	p->header.length = sizeof(struct smbios_type_1);
	p->header.handle = 0x100;

	p->manufacturer_str = 1;
	p->product_name_str = 2;
	p->version_str = 3;
	p->serial_number_str = 4;
    
	memcpy(p->uuid, uuid, 16);

	p->wake_up_type = 0x06; /* power switch */
	p->sku_str = 0;
	p->family_str = 0;

	start += sizeof(struct smbios_type_1);
    
	strcpy((char *)start, "Xen");
	start += strlen("Xen") + 1;
	strcpy((char *)start, "HVM domU");
	start += strlen("HVM domU") + 1;
	strcpy((char *)start, xen_version);
	start += strlen(xen_version) + 1;
	uuid_to_string(uuid_str, uuid);	
	strcpy((char *)start, uuid_str);
	start += strlen(uuid_str) + 1;
	*((uint8_t *)start) = 0;
    
	return start+1; 
}

/* Type 3 -- System Enclosure */
static void *
smbios_type_3_init(void *start)
{
	struct smbios_type_3 *p = (struct smbios_type_3 *)start;
    
	p->header.type = 3;
	p->header.length = sizeof(struct smbios_type_3);
	p->header.handle = 0x300;

	p->manufacturer_str = 1;
	p->type = 0x01; /* other */
	p->version_str = 0;
	p->serial_number_str = 0;
	p->asset_tag_str = 0;
	p->boot_up_state = 0x03; /* safe */
	p->power_supply_state = 0x03; /* safe */
	p->thermal_state = 0x03; /* safe */
	p->security_status = 0x02; /* unknown */

	start += sizeof(struct smbios_type_3);
    
	strcpy((char *)start, "Xen");
	start += strlen("Xen") + 1;
	*((uint8_t *)start) = 0;
	return start+1;
}

/* Type 4 -- Processor Information */
static void *
smbios_type_4_init(void *start, unsigned int cpu_number, char *cpu_manufacturer)
{
	char buf[80]; 
	struct smbios_type_4 *p = (struct smbios_type_4 *)start;
	uint32_t eax, ebx, ecx, edx;

	p->header.type = 4;
	p->header.length = sizeof(struct smbios_type_4);
	p->header.handle = 0x400 + cpu_number;

	p->socket_designation_str = 1;
	p->processor_type = 0x03; /* CPU */
	p->processor_family = 0x01; /* other */
	p->manufacturer_str = 2;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	p->cpuid[0] = eax;
	p->cpuid[1] = edx;

	p->version_str = 0;
	p->voltage = 0;
	p->external_clock = 0;

	p->max_speed = 0; /* unknown */
	p->current_speed = 0; /* unknown */

	p->status = 0x41; /* socket populated, CPU enabled */
	p->upgrade = 0x01; /* other */

	start += sizeof(struct smbios_type_4);

	strncpy(buf, "CPU ", sizeof(buf));
	if ((sizeof(buf) - strlen("CPU ")) >= 3)
		itoa(buf + strlen("CPU "), cpu_number);

	strcpy((char *)start, buf);
	start += strlen(buf) + 1;

	strcpy((char *)start, cpu_manufacturer);
	start += strlen(buf) + 1;

	*((uint8_t *)start) = 0;
	return start+1;
}

/* Type 16 -- Physical Memory Array */
static void *
smbios_type_16_init(void *start, uint32_t memsize)
{
	struct smbios_type_16 *p = (struct smbios_type_16*)start;

	p->header.type = 16;
	p->header.handle = 0x1000;
	p->header.length = sizeof(struct smbios_type_16);
    
	p->location = 0x01; /* other */
	p->use = 0x03; /* system memory */
	p->error_correction = 0x01; /* other */
	p->maximum_capacity = memsize * 1024;
	p->memory_error_information_handle = 0xfffe; /* none provided */
	p->number_of_memory_devices = 1;

	start += sizeof(struct smbios_type_16);
	*((uint16_t *)start) = 0;
	return start + 2;
}

/* Type 17 -- Memory Device */
static void *
smbios_type_17_init(void *start, uint32_t memory_size_mb)
{
	struct smbios_type_17 *p = (struct smbios_type_17 *)start;
    
	p->header.type = 17;
	p->header.length = sizeof(struct smbios_type_17);
	p->header.handle = 0x1100;

	p->physical_memory_array_handle = 0x1000;
	p->total_width = 64;
	p->data_width = 64;
	/* truncate memory_size_mb to 16 bits and clear most significant
	   bit [indicates size in MB] */
	p->size = (uint16_t) memory_size_mb & 0x7fff;
	p->form_factor = 0x09; /* DIMM */
	p->device_set = 0;
	p->device_locator_str = 1;
	p->bank_locator_str = 0;
	p->memory_type = 0x07; /* RAM */
	p->type_detail = 0;

	start += sizeof(struct smbios_type_17);
	strcpy((char *)start, "DIMM 1");
	start += strlen("DIMM 1") + 1;
	*((uint8_t *)start) = 0;

	return start+1;
}

/* Type 19 -- Memory Array Mapped Address */
static void *
smbios_type_19_init(void *start, uint32_t memory_size_mb)
{
	struct smbios_type_19 *p = (struct smbios_type_19 *)start;
    
	p->header.type = 19;
	p->header.length = sizeof(struct smbios_type_19);
	p->header.handle = 0x1300;

	p->starting_address = 0;
	p->ending_address = (memory_size_mb-1) * 1024;
	p->memory_array_handle = 0x1000;
	p->partition_width = 1;

	start += sizeof(struct smbios_type_19);
	*((uint16_t *)start) = 0;
	return start + 2;
}

/* Type 20 -- Memory Device Mapped Address */
static void *
smbios_type_20_init(void *start, uint32_t memory_size_mb)
{
	struct smbios_type_20 *p = (struct smbios_type_20 *)start;

	p->header.type = 20;
	p->header.length = sizeof(struct smbios_type_20);
	p->header.handle = 0x1400;

	p->starting_address = 0;
	p->ending_address = (memory_size_mb-1)*1024;
	p->memory_device_handle = 0x1100;
	p->memory_array_mapped_address_handle = 0x1300;
	p->partition_row_position = 1;
	p->interleave_position = 0;
	p->interleaved_data_depth = 0;

	start += sizeof(struct smbios_type_20);

	*((uint16_t *)start) = 0;
	return start+2;
}

/* Type 32 -- System Boot Information */
static void *
smbios_type_32_init(void *start)
{
	struct smbios_type_32 *p = (struct smbios_type_32 *)start;

	p->header.type = 32;
	p->header.length = sizeof(struct smbios_type_32);
	p->header.handle = 0x2000;
	memset(p->reserved, 0, 6);
	p->boot_status = 0; /* no errors detected */
    
	start += sizeof(struct smbios_type_32);
	*((uint16_t *)start) = 0;
	return start+2;
}

/* Type 127 -- End of Table */
void *
smbios_type_127_init(void *start)
{
	struct smbios_type_127 *p = (struct smbios_type_127 *)start;

	p->header.type = 127;
	p->header.length = sizeof(struct smbios_type_127);
	p->header.handle = 0x7f00;

	start += sizeof(struct smbios_type_127);
	*((uint16_t *)start) = 0;
	return start + 2;
}
