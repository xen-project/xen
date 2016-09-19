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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Authors: Andrew D. Ball <aball@us.ibm.com>
 */

#include <stdint.h>
#include <xen/xen.h>
#include <xen/version.h>
#include "smbios_types.h"
#include "util.h"
#include "hypercall.h"
#include <xen/hvm/hvm_xs_strings.h>

/* SBMIOS handle base values */
#define SMBIOS_HANDLE_TYPE0   0x0000
#define SMBIOS_HANDLE_TYPE1   0x0100
#define SMBIOS_HANDLE_TYPE2   0x0200
#define SMBIOS_HANDLE_TYPE3   0x0300
#define SMBIOS_HANDLE_TYPE4   0x0400
#define SMBIOS_HANDLE_TYPE11  0x0B00
#define SMBIOS_HANDLE_TYPE16  0x1000
#define SMBIOS_HANDLE_TYPE17  0x1100
#define SMBIOS_HANDLE_TYPE19  0x1300
#define SMBIOS_HANDLE_TYPE20  0x1400
#define SMBIOS_HANDLE_TYPE22  0x1600
#define SMBIOS_HANDLE_TYPE32  0x2000
#define SMBIOS_HANDLE_TYPE39  0x2700
#define SMBIOS_HANDLE_TYPE127 0x7f00

static void
smbios_pt_init(void);
static void*
get_smbios_pt_struct(uint8_t type, uint32_t *length_out);
static void
get_cpu_manufacturer(char *buf, int len);
static int
write_smbios_tables(void *ep, void *start,
                    uint32_t vcpus, uint64_t memsize,
                    uint8_t uuid[16], char *xen_version,
                    uint32_t xen_major_version, uint32_t xen_minor_version,
                    unsigned *nr_structs, unsigned *max_struct_size);
static uint64_t
get_memsize(void);
static void
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
smbios_type_2_init(void *start);
static void *
smbios_type_3_init(void *start);
static void *
smbios_type_4_init(void *start, unsigned int cpu_number,
                   char *cpu_manufacturer);
static void *
smbios_type_11_init(void *start);
static void *
smbios_type_16_init(void *start, uint32_t memory_size_mb, int nr_mem_devs);
static void *
smbios_type_17_init(void *start, uint32_t memory_size_mb, int instance);
static void *
smbios_type_19_init(void *start, uint32_t memory_size_mb, int instance);
static void *
smbios_type_20_init(void *start, uint32_t memory_size_mb, int instance);
static void *
smbios_type_22_init(void *start);
static void *
smbios_type_32_init(void *start);
static void *
smbios_type_39_init(void *start);
static void *
smbios_type_vendor_oem_init(void *start);
static void *
smbios_type_127_init(void *start);

static uint32_t *smbios_pt_addr = NULL;
static uint32_t smbios_pt_length = 0;

static void
smbios_pt_init(void)
{
    const char *s;

    s = xenstore_read(HVM_XS_SMBIOS_PT_ADDRESS, NULL);
    if ( s == NULL )
        goto reset;

    smbios_pt_addr = (uint32_t*)(uint32_t)strtoll(s, NULL, 0);
    if ( smbios_pt_addr == NULL )
        goto reset;

    s = xenstore_read(HVM_XS_SMBIOS_PT_LENGTH, NULL);
    if ( s == NULL )
        goto reset;

    smbios_pt_length = (uint32_t)strtoll(s, NULL, 0);
    if ( smbios_pt_length == 0 )
        goto reset;

    return;

reset:
    smbios_pt_addr = NULL;
    smbios_pt_length = 0;
}

static void*
get_smbios_pt_struct(uint8_t type, uint32_t *length_out)
{
    uint32_t *sep = smbios_pt_addr;
    uint32_t total = 0;
    uint8_t *ptr;

    if ( sep == NULL )
        return NULL;

    while ( total < smbios_pt_length )
    {
        ptr = (uint8_t*)(sep + 1);
        if ( ptr[0] == type )
        {
            *length_out = *sep;
            return ptr;
        }

        total += (*sep + sizeof(uint32_t));
        sep = (uint32_t*)(ptr + *sep);
    }

    return NULL;
}

static void
get_cpu_manufacturer(char *buf, int len)
{
    char id[12];
    uint32_t eax = 0;

    cpuid(0, &eax, (uint32_t *)&id[0], (uint32_t *)&id[8],
          (uint32_t *)&id[4]);

    if ( memcmp(id, "GenuineIntel", 12) == 0 )
        strncpy(buf, "Intel", len);
    else if ( memcmp(id, "AuthenticAMD", 12) == 0 )
        strncpy(buf, "AMD", len);
    else
        strncpy(buf, "unknown", len);
}

static int
write_smbios_tables(void *ep, void *start,
                    uint32_t vcpus, uint64_t memsize,
                    uint8_t uuid[16], char *xen_version,
                    uint32_t xen_major_version, uint32_t xen_minor_version,
                    unsigned *nr_structs, unsigned *max_struct_size)
{
    unsigned cpu_num;
    char *p, *q;
    char cpu_manufacturer[15];
    int i, nr_mem_devs;

    smbios_pt_init();

    get_cpu_manufacturer(cpu_manufacturer, 15);

    p = (char *)start;

#define do_struct(fn) do {                      \
    q = (fn);                                   \
    if ( q != p )                               \
        (*nr_structs)++;                        \
    if ( (q - p) > *max_struct_size )           \
        *max_struct_size = q - p;               \
    p = q;                                      \
} while (0)

    do_struct(smbios_type_0_init(p, xen_version, xen_major_version,
                                 xen_minor_version));
    do_struct(smbios_type_1_init(p, xen_version, uuid));
    do_struct(smbios_type_2_init(p));
    do_struct(smbios_type_3_init(p));
    for ( cpu_num = 1; cpu_num <= vcpus; cpu_num++ )
        do_struct(smbios_type_4_init(p, cpu_num, cpu_manufacturer));
    do_struct(smbios_type_11_init(p));

    /* Each 'memory device' covers up to 16GB of address space. */
    nr_mem_devs = (memsize + 0x3fff) >> 14;
    do_struct(smbios_type_16_init(p, memsize, nr_mem_devs));
    for ( i = 0; i < nr_mem_devs; i++ )
    {
        uint32_t dev_memsize = 0x4000; /* all but last covers 16GB */
        if ( (i == (nr_mem_devs - 1)) && ((memsize & 0x3fff) != 0) )
            dev_memsize = memsize & 0x3fff; /* last dev is <16GB */
        do_struct(smbios_type_17_init(p, dev_memsize, i));
        do_struct(smbios_type_19_init(p, dev_memsize, i));
        do_struct(smbios_type_20_init(p, dev_memsize, i));
    }

    do_struct(smbios_type_22_init(p));
    do_struct(smbios_type_32_init(p));
    do_struct(smbios_type_39_init(p));
    do_struct(smbios_type_vendor_oem_init(p));
    do_struct(smbios_type_127_init(p));

#undef do_struct

    return ((char *)p - (char *)start);
}

/* Calculate how much pseudo-physical memory (in MB) is allocated to us. */
static uint64_t
get_memsize(void)
{
    uint64_t sz;

    sz = (uint64_t)hvm_info->low_mem_pgend << PAGE_SHIFT;
    if ( hvm_info->high_mem_pgend )
        sz += (((uint64_t)hvm_info->high_mem_pgend << PAGE_SHIFT)
               - (1ull << 32));

    /*
     * Round up to the nearest MB.  The user specifies domU pseudo-physical 
     * memory in megabytes, so not doing this could easily lead to reporting 
     * one less MB than the user specified.
     */
    return (sz + (1ul << 20) - 1) >> 20;
}

void
hvm_write_smbios_tables(
    unsigned long ep, unsigned long smbios_start, unsigned long smbios_end)
{
    xen_domain_handle_t uuid;
    uint16_t xen_major_version, xen_minor_version;
    uint32_t xen_version;
    char xen_extra_version[XEN_EXTRAVERSION_LEN];
    /* guess conservatively on buffer length for Xen version string */
    char xen_version_str[80];
    /* temporary variables used to build up Xen version string */
    char *p = NULL; /* points to next point of insertion */
    unsigned len = 0; /* length of string already composed */
    char tmp[16]; /* holds result of itoa() */
    unsigned tmp_len; /* length of next string to add */
    unsigned nr_structs = 0, max_struct_size = 0;

    hypercall_xen_version(XENVER_guest_handle, uuid);
    BUILD_BUG_ON(sizeof(xen_domain_handle_t) != 16);

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
    if ( len >= sizeof(xen_version_str) )
        goto error_out;
    strcpy(p, tmp);
    p += tmp_len;

    len++;
    if ( len >= sizeof(xen_version_str) )
        goto error_out;
    *p = '.';
    p++;

    itoa(tmp, xen_minor_version);
    tmp_len = strlen(tmp);
    len += tmp_len;
    if ( len >= sizeof(xen_version_str) )
        goto error_out;
    strcpy(p, tmp);
    p += tmp_len;

    tmp_len = strlen(xen_extra_version);
    len += tmp_len;
    if ( len >= sizeof(xen_version_str) )
        goto error_out;
    strcpy(p, xen_extra_version);
    p += tmp_len;

    xen_version_str[sizeof(xen_version_str)-1] = '\0';

    /* scratch_start is a safe large memory area for scratch. */
    len = write_smbios_tables((void *)ep, (void *)scratch_start,
                              hvm_info->nr_vcpus, get_memsize(),
                              uuid, xen_version_str,
                              xen_major_version, xen_minor_version,
                              &nr_structs, &max_struct_size);
    if ( smbios_start && smbios_start + len > smbios_end )
        goto error_out;

    if ( !smbios_start )
        smbios_start = (unsigned long)mem_alloc(len, 0);

    memcpy((void *)smbios_start, (void *)scratch_start, len);

    smbios_entry_point_init(
        (void *)ep, max_struct_size, len, smbios_start, nr_structs);

    return;

 error_out:
    printf("Could not write SMBIOS tables, error in hvmloader.c:"
           "hvm_write_smbios_tables()\n");
}


static void
smbios_entry_point_init(void *start,
                        uint16_t max_structure_size,
                        uint16_t structure_table_length,
                        uint32_t structure_table_address,
                        uint16_t number_of_structures)
{
    uint8_t sum;
    int i;
    struct smbios_entry_point *ep = start;

    memset(ep, 0, sizeof(*ep));

    memcpy(ep->anchor_string, "_SM_", 4);
    ep->length = 0x1f;
    ep->smbios_major_version = 2;
    ep->smbios_minor_version = 4;
    ep->max_structure_size = max_structure_size;
    ep->entry_point_revision = 0;
    memcpy(ep->intermediate_anchor_string, "_DMI_", 5);

    ep->structure_table_length = structure_table_length;
    ep->structure_table_address = structure_table_address;
    ep->number_of_structures = number_of_structures;
    ep->smbios_bcd_revision = 0x24;

    sum = 0;
    for ( i = 0; i < 0x10; i++ )
        sum += ((int8_t *)start)[i];
    ep->checksum = -sum;

    sum = 0;
    for ( i = 0x10; i < ep->length; i++ )
        sum += ((int8_t *)start)[i];
    ep->intermediate_checksum = -sum;
}

/* Type 0 -- BIOS Information */
static void *
smbios_type_0_init(void *start, const char *xen_version,
                   uint32_t xen_major_version, uint32_t xen_minor_version)
{
    struct smbios_type_0 *p = (struct smbios_type_0 *)start;
    static const char *smbios_release_date = __SMBIOS_DATE__;
    const char *s;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(0, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE0;
        return (start + length);
    }

    memset(p, 0, sizeof(*p));

    p->header.type = 0;
    p->header.length = sizeof(struct smbios_type_0);
    p->header.handle = SMBIOS_HANDLE_TYPE0;

    p->vendor_str = 1;
    p->version_str = 2;
    p->starting_address_segment = 0xe800;
    p->release_date_str = 3;
    p->rom_size = 0;

    /* BIOS Characteristics. */
    p->characteristics[0] = 0x80; /* PCI is supported */
    p->characteristics[2] = 0x08; /* EDD is supported */

    /* Extended Characteristics: Enable Targeted Content Distribution. */
    p->characteristics_extension_bytes[1] = 0x04;

    p->major_release = (uint8_t) xen_major_version;
    p->minor_release = (uint8_t) xen_minor_version;
    p->embedded_controller_major = 0xff;
    p->embedded_controller_minor = 0xff;

    start += sizeof(struct smbios_type_0);
    s = xenstore_read(HVM_XS_BIOS_VENDOR, "Xen");
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    s = xenstore_read(HVM_XS_BIOS_VERSION, xen_version);
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    strcpy((char *)start, smbios_release_date);
    start += strlen(smbios_release_date) + 1;

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
    const char *s;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(1, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE1;
        return (start + length);
    }

    memset(p, 0, sizeof(*p));

    p->header.type = 1;
    p->header.length = sizeof(struct smbios_type_1);
    p->header.handle = SMBIOS_HANDLE_TYPE1;

    p->manufacturer_str = 1;
    p->product_name_str = 2;
    p->version_str = 3;
    p->serial_number_str = 4;
    
    memcpy(p->uuid, uuid, 16);

    p->wake_up_type = 0x06; /* power switch */
    p->sku_str = 0;
    p->family_str = 0;

    start += sizeof(struct smbios_type_1);
    
    s = xenstore_read(HVM_XS_SYSTEM_MANUFACTURER, "Xen");
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    s = xenstore_read(HVM_XS_SYSTEM_PRODUCT_NAME, "HVM domU");
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    s = xenstore_read(HVM_XS_SYSTEM_VERSION, xen_version);
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    uuid_to_string(uuid_str, uuid); 
    s = xenstore_read(HVM_XS_SYSTEM_SERIAL_NUMBER, uuid_str);
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    *((uint8_t *)start) = 0;
    
    return start+1; 
}

/* Type 2 -- System Board */
static void *
smbios_type_2_init(void *start)
{
    struct smbios_type_2 *p = (struct smbios_type_2 *)start;
    uint8_t *ptr;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(2, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE2;

        /* Set current chassis handle if present */
        if ( p->header.length > 13 )
        {
            ptr = ((uint8_t*)start) + 11;            
            if ( *((uint16_t*)ptr) != 0 )
                *((uint16_t*)ptr) = SMBIOS_HANDLE_TYPE3;
        }

        return (start + length);
    }

    /* Only present when passed in */
    return start;
}

/* Type 3 -- System Enclosure */
static void *
smbios_type_3_init(void *start)
{
    struct smbios_type_3 *p = (struct smbios_type_3 *)start;
    const char *s;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(3, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE3;
        return (start + length);
    }
    
    memset(p, 0, sizeof(*p));

    p->header.type = 3;
    p->header.length = sizeof(struct smbios_type_3);
    p->header.handle = SMBIOS_HANDLE_TYPE3;

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
    
    s = xenstore_read(HVM_XS_ENCLOSURE_MANUFACTURER, "Xen");
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    /* No internal defaults for this if the value is not set */
    s = xenstore_read(HVM_XS_ENCLOSURE_SERIAL_NUMBER, NULL);
    if ( (s != NULL)&&(*s != '\0') )
    {
        strcpy((char *)start, s);
        start += strlen(s) + 1;
        p->serial_number_str = 2;
    }

    *((uint8_t *)start) = 0;
    return start+1;
}

/* Type 4 -- Processor Information */
static void *
smbios_type_4_init(
    void *start, unsigned int cpu_number, char *cpu_manufacturer)
{
    char buf[80]; 
    struct smbios_type_4 *p = (struct smbios_type_4 *)start;
    uint32_t eax, ebx, ecx, edx;

    memset(p, 0, sizeof(*p));

    p->header.type = 4;
    p->header.length = sizeof(struct smbios_type_4);
    p->header.handle = SMBIOS_HANDLE_TYPE4 + cpu_number;

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

    p->max_speed = p->current_speed = get_cpu_mhz();

    p->status = 0x41; /* socket populated, CPU enabled */
    p->upgrade = 0x01; /* other */

    start += sizeof(struct smbios_type_4);

    strncpy(buf, "CPU ", sizeof(buf));
    if ( (sizeof(buf) - strlen("CPU ")) >= 3 )
        itoa(buf + strlen("CPU "), cpu_number);

    strcpy((char *)start, buf);
    start += strlen(buf) + 1;

    strcpy((char *)start, cpu_manufacturer);
    start += strlen(cpu_manufacturer) + 1;

    *((uint8_t *)start) = 0;
    return start+1;
}

/* Type 11 -- OEM Strings */
static void *
smbios_type_11_init(void *start) 
{
    struct smbios_type_11 *p = (struct smbios_type_11 *)start;
    char path[20];
    const char *s;
    int i;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(11, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE11;
        return (start + length);
    }

    p->header.type = 11;
    p->header.length = sizeof(struct smbios_type_11);
    p->header.handle = SMBIOS_HANDLE_TYPE11;

    p->count = 0;

    start += sizeof(struct smbios_type_11);

    /* Pull out as many oem-* strings we find in xenstore */
    for ( i = 1; i < 100; i++ )
    {
        snprintf(path, sizeof(path), HVM_XS_OEM_STRINGS, i);
        if ( ((s = xenstore_read(path, NULL)) == NULL) || (*s == '\0') )
            break;
        strcpy((char *)start, s);
        start += strlen(s) + 1;
        p->count++;
    }
    
    /* Make sure there's at least one type-11 string */
    if ( p->count == 0 )
    {
        strcpy((char *)start, "Xen");
        start += strlen("Xen") + 1;
        p->count++;
    }
    *((uint8_t *)start) = 0;

    return start+1;
}

/* Type 16 -- Physical Memory Array */
static void *
smbios_type_16_init(void *start, uint32_t memsize, int nr_mem_devs)
{
    struct smbios_type_16 *p = (struct smbios_type_16*)start;

    memset(p, 0, sizeof(*p));

    p->header.type = 16;
    p->header.handle = SMBIOS_HANDLE_TYPE16;
    p->header.length = sizeof(struct smbios_type_16);
    
    p->location = 0x01; /* other */
    p->use = 0x03; /* system memory */
    p->error_correction = 0x06; /* Multi-bit ECC to make Microsoft happy */
    p->maximum_capacity = memsize * 1024;
    p->memory_error_information_handle = 0xfffe; /* none provided */
    p->number_of_memory_devices = nr_mem_devs;

    start += sizeof(struct smbios_type_16);
    *((uint16_t *)start) = 0;
    return start + 2;
}

/* Type 17 -- Memory Device */
static void *
smbios_type_17_init(void *start, uint32_t memory_size_mb, int instance)
{
    char buf[16];
    struct smbios_type_17 *p = (struct smbios_type_17 *)start;
    
    memset(p, 0, sizeof(*p));

    p->header.type = 17;
    p->header.length = sizeof(struct smbios_type_17);
    p->header.handle = SMBIOS_HANDLE_TYPE17 + instance;

    p->physical_memory_array_handle = 0x1000;
    p->total_width = 64;
    p->data_width = 64;
    ASSERT((memory_size_mb & ~0x7fff) == 0);
    p->size = memory_size_mb;
    p->form_factor = 0x09; /* DIMM */
    p->device_set = 0;
    p->device_locator_str = 1;
    p->bank_locator_str = 0;
    p->memory_type = 0x07; /* RAM */
    p->type_detail = 0;

    start += sizeof(struct smbios_type_17);
    strcpy(start, "DIMM ");
    start += strlen("DIMM ");
    itoa(buf, instance);
    strcpy(start, buf);
    start += strlen(buf) + 1;
    *((uint8_t *)start) = 0;

    return start+1;
}

/* Type 19 -- Memory Array Mapped Address */
static void *
smbios_type_19_init(void *start, uint32_t memory_size_mb, int instance)
{
    struct smbios_type_19 *p = (struct smbios_type_19 *)start;
    
    memset(p, 0, sizeof(*p));

    p->header.type = 19;
    p->header.length = sizeof(struct smbios_type_19);
    p->header.handle = SMBIOS_HANDLE_TYPE19 + instance;

    p->starting_address = instance << 24;
    p->ending_address = p->starting_address + (memory_size_mb << 10) - 1;
    p->memory_array_handle = 0x1000;
    p->partition_width = 1;

    start += sizeof(struct smbios_type_19);
    *((uint16_t *)start) = 0;
    return start + 2;
}

/* Type 20 -- Memory Device Mapped Address */
static void *
smbios_type_20_init(void *start, uint32_t memory_size_mb, int instance)
{
    struct smbios_type_20 *p = (struct smbios_type_20 *)start;

    memset(p, 0, sizeof(*p));

    p->header.type = 20;
    p->header.length = sizeof(struct smbios_type_20);
    p->header.handle = SMBIOS_HANDLE_TYPE20 + instance;

    p->starting_address = instance << 24;
    p->ending_address = p->starting_address + (memory_size_mb << 10) - 1;
    p->memory_device_handle = 0x1100 + instance;
    p->memory_array_mapped_address_handle = 0x1300 + instance;
    p->partition_row_position = 1;
    p->interleave_position = 0;
    p->interleaved_data_depth = 0;

    start += sizeof(struct smbios_type_20);

    *((uint16_t *)start) = 0;
    return start+2;
}

/* Type 22 -- Portable Battery */
static void *
smbios_type_22_init(void *start)
{
    struct smbios_type_22 *p = (struct smbios_type_22 *)start;
    static const char *smbios_release_date = __SMBIOS_DATE__;
    const char *s;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(22, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE22;
        return (start + length);
    }

    s = xenstore_read(HVM_XS_SMBIOS_DEFAULT_BATTERY, "0");
    if ( strncmp(s, "1", 1) != 0 )
        return start;

    memset(p, 0, sizeof(*p));

    p->header.type = 22;
    p->header.length = sizeof(struct smbios_type_22);
    p->header.handle = SMBIOS_HANDLE_TYPE22;

    p->location_str = 1;
    p->manufacturer_str = 2;
    p->manufacturer_date_str = 3;
    p->serial_number_str = 0;
    p->device_name_str = 4;
    p->device_chemistry = 0x2; /* unknown */
    p->device_capacity = 0; /* unknown */
    p->device_voltage = 0; /* unknown */
    p->sbds_version_number = 0;
    p->max_error = 0xff; /* unknown */
    p->sbds_serial_number = 0;
    p->sbds_manufacturer_date = 0;
    p->sbds_device_chemistry = 0;
    p->design_capacity_multiplier = 0;
    p->oem_specific = 0;

    start += sizeof(struct smbios_type_22);

    strcpy((char *)start, "Primary");
    start += strlen("Primary") + 1;

    s = xenstore_read(HVM_XS_BATTERY_MANUFACTURER, "Xen");
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    strcpy((char *)start, smbios_release_date);
    start += strlen(smbios_release_date) + 1;

    s = xenstore_read(HVM_XS_BATTERY_DEVICE_NAME, "XEN-VBAT");
    strcpy((char *)start, s);
    start += strlen(s) + 1;

    *((uint8_t *)start) = 0;

    return start+1; 
}

/* Type 32 -- System Boot Information */
static void *
smbios_type_32_init(void *start)
{
    struct smbios_type_32 *p = (struct smbios_type_32 *)start;

    memset(p, 0, sizeof(*p));

    p->header.type = 32;
    p->header.length = sizeof(struct smbios_type_32);
    p->header.handle = SMBIOS_HANDLE_TYPE32;
    memset(p->reserved, 0, 6);
    p->boot_status = 0; /* no errors detected */
    
    start += sizeof(struct smbios_type_32);
    *((uint16_t *)start) = 0;
    return start+2;
}

/* Type 39 -- Power Supply */
static void *
smbios_type_39_init(void *start)
{
    struct smbios_type_39 *p = (struct smbios_type_39 *)start;
    void *pts;
    uint32_t length;

    pts = get_smbios_pt_struct(39, &length);
    if ( (pts != NULL)&&(length > 0) )
    {
        memcpy(start, pts, length);
        p->header.handle = SMBIOS_HANDLE_TYPE39;
        return (start + length);
    }

    /* Only present when passed in */
    return start;
}

static void *
smbios_type_vendor_oem_init(void *start)
{
    uint32_t *sep = smbios_pt_addr;
    uint32_t total = 0;
    uint8_t *ptr;

    if ( sep == NULL )
        return start;

    while ( total < smbios_pt_length )
    {
        ptr = (uint8_t*)(sep + 1);
        if ( ptr[0] >= 128 )
        {
            /* Vendor/OEM table, copy it in. Note the handle values cannot
             * be changed since it is unknown what is in each of these tables
             * but they could contain handle references to other tables. This
             * means a slight risk of collision with the tables above but that
             * would have to be dealt with on a case by case basis.
             */
            memcpy(start, ptr, *sep);
            start += *sep;
        }

        total += (*sep + sizeof(uint32_t));
        sep = (uint32_t*)(ptr + *sep);
    }

    return start;
}

/* Type 127 -- End of Table */
static void *
smbios_type_127_init(void *start)
{
    struct smbios_type_127 *p = (struct smbios_type_127 *)start;

    memset(p, 0, sizeof(*p));

    p->header.type = 127;
    p->header.length = sizeof(struct smbios_type_127);
    p->header.handle = SMBIOS_HANDLE_TYPE127;

    start += sizeof(struct smbios_type_127);
    *((uint16_t *)start) = 0;
    return start + 2;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
