/*
 * Commonly used ACPI utility functions.
 * Probing for devices and writing SSDT entries into XSDT and RSDT tables.
 *
 * Yu Ke, ke.yu@intel.com
 * Copyright (c) 2005, Intel Corporation.
 * Copyright (c) 2006, IBM Corporation.
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

#include "acpi/acpi2_0.h"
#include "acpi_utils.h"
#include "util.h"

static int acpi_rsdt_add_entry_pointer(unsigned char *acpi_start,
                                       unsigned char *entry);
static unsigned char *acpi_xsdt_add_entry(unsigned char *acpi_start,
                                          unsigned char **freemem,
                                          unsigned char *limit,
                                          unsigned char *table,
                                          unsigned int table_size);

void set_checksum(void *start, int checksum_offset, int len)
{
	unsigned char sum = 0;
	unsigned char *ptr;

	ptr = start;
	ptr[checksum_offset] = 0;
	while (len--)
		sum += *ptr++;

	ptr = start;
	ptr[checksum_offset] = -sum;
}


#include "acpi_ssdt_tpm.h"
static int acpi_tpm_tis_probe(unsigned char *acpi_start,
                              unsigned char **freemem,
                              unsigned char *limit)
{
	int success = 1; /* not successful means 'out of memory' */
	unsigned char *addr;
	/* check TPM_DID, TPM_VID, TPM_RID in ioemu/hw/tpm_tis.c */
	uint16_t tis_did_vid_rid[] = {0x0001, 0x0001, 0x0001};

	/* probe for TIS interface ... */
	if (memcmp((char *)(0xFED40000 + 0xF00),
	           tis_did_vid_rid,
	           sizeof(tis_did_vid_rid)) == 0) {
		puts("TIS is available\n");
		addr = acpi_xsdt_add_entry(acpi_start, freemem, limit,
		                           AmlCode_TPM, sizeof(AmlCode_TPM));
		if (addr == NULL)
			success = 0;
		else {
			/* legacy systems need an RSDT entry */
			acpi_rsdt_add_entry_pointer(acpi_start,
			                            addr);
		}
	}
	return success;
}


/*
 * Call functions that probe for devices and have them register their
 * SSDT entries with the XSDT and RSDT tables.
 */
void acpi_update(unsigned char *acpi_start,
                 unsigned long acpi_size,
                 unsigned char *limit,
                 unsigned char **freemem)
{
    acpi_tpm_tis_probe(acpi_start, freemem, limit);
}


struct acpi_20_rsdt *acpi_rsdt_get(unsigned char *acpi_start)
{
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_rsdt *rsdt;

    rsdp = (struct acpi_20_rsdp *)(acpi_start + sizeof(struct acpi_20_facs));
    if (rsdp->signature != ACPI_2_0_RSDP_SIGNATURE) {
        puts("Bad RSDP signature\n");
        return NULL;
    }

    rsdt = (struct acpi_20_rsdt *)
        (acpi_start + rsdp->rsdt_address - ACPI_PHYSICAL_ADDRESS);
    if (rsdt->header.signature != ACPI_2_0_RSDT_SIGNATURE) {
        puts("Bad RSDT signature\n");
        return NULL;
    }
    return rsdt;
}

/*
 * Add an entry to the RSDT table given the pointer to the entry.
 */
static int acpi_rsdt_add_entry_pointer(unsigned char *acpi_start,
                                       unsigned char *entry)
{
    struct acpi_20_rsdt *rsdt = acpi_rsdt_get(acpi_start);
    int found = 0;
    int i = 0;

    /* get empty slot in the RSDT table */
    while (i < ACPI_MAX_NUM_TABLES) {
        if (rsdt->entry[i] == 0) {
            found = 1;
            break;
        }
        i++;
    }

    if (found) {
        rsdt->entry[i] = (uint64_t)(long)entry;
        rsdt->header.length =
            sizeof(struct acpi_header) +
            (i + 1) * sizeof(uint64_t);
        set_checksum(rsdt,
                     FIELD_OFFSET(struct acpi_header, checksum),
                     rsdt->header.length);
    }

    return found;
}

/* Get the XSDT table */
struct acpi_20_xsdt *acpi_xsdt_get(unsigned char *acpi_start)
{
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_xsdt *xsdt;

    rsdp = (struct acpi_20_rsdp *)(acpi_start + sizeof(struct acpi_20_facs));
    if (rsdp->signature != ACPI_2_0_RSDP_SIGNATURE) {
        puts("Bad RSDP signature\n");
        return NULL;
    }

    xsdt = (struct acpi_20_xsdt *)
        (acpi_start + rsdp->xsdt_address - ACPI_PHYSICAL_ADDRESS);
    if (xsdt->header.signature != ACPI_2_0_XSDT_SIGNATURE) {
        puts("Bad XSDT signature\n");
        return NULL;
    }
    return xsdt;
}

/*
   add an entry to the xdst table entry pointers
   copy the given ssdt data to the current available memory at
   freemem, if it does not exceed the limit
 */
static unsigned char *acpi_xsdt_add_entry(unsigned char *acpi_start,
                                          unsigned char **freemem,
                                          unsigned char *limit,
                                          unsigned char *table,
                                          unsigned int table_size)
{
    struct acpi_20_xsdt *xsdt = acpi_xsdt_get(acpi_start);
    int found = 0, i = 0;
    unsigned char *addr = NULL;

    /* get empty slot in the Xsdt table */
    while (i < ACPI_MAX_NUM_TABLES) {
        if (xsdt->entry[i] == 0) {
            found = 1;
            break;
        }
        i++;
    }

    if (found) {
        /* memory below hard limit ? */
        if (*freemem + table_size <= limit) {
            puts("Copying SSDT entry!\n");
            addr = *freemem;
            memcpy(addr, table, table_size);
            xsdt->entry[i] = (uint64_t)(long)addr;
            *freemem += table_size;
            /* update the XSDT table */
            xsdt->header.length =
                sizeof(struct acpi_header) +
                (i + 1) * sizeof(uint64_t);
            set_checksum(xsdt,
                         FIELD_OFFSET(struct acpi_header, checksum),
                         xsdt->header.length);
        }
    }
    return addr;
}
