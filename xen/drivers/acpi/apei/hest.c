/*
 * APEI Hardware Error Souce Table support
 *
 * HEST describes error sources in detail; communicates operational
 * parameters (i.e. severity levels, masking bits, and threshold
 * values) to Linux as necessary. It also allows the BIOS to report
 * non-standard error sources to Linux (for example, chipset-specific
 * error registers).
 *
 * For more information about HEST, please refer to ACPI Specification
 * version 4.0, section 17.3.2.
 *
 * Copyright 2009 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <acpi/acpi.h>
#include <acpi/apei.h>

#include "apei-internal.h"

#define HEST_PFX "HEST: "

static bool_t hest_disable;
boolean_param("hest_disable", hest_disable);

/* HEST table parsing */

static struct acpi_table_hest *__read_mostly hest_tab;

static const int hest_esrc_len_tab[ACPI_HEST_TYPE_RESERVED] = {
	[ACPI_HEST_TYPE_IA32_CHECK] = -1,	/* need further calculation */
	[ACPI_HEST_TYPE_IA32_CORRECTED_CHECK] = -1,
	[ACPI_HEST_TYPE_IA32_NMI] = sizeof(struct acpi_hest_ia_nmi),
	[ACPI_HEST_TYPE_AER_ROOT_PORT] = sizeof(struct acpi_hest_aer_root),
	[ACPI_HEST_TYPE_AER_ENDPOINT] = sizeof(struct acpi_hest_aer),
	[ACPI_HEST_TYPE_AER_BRIDGE] = sizeof(struct acpi_hest_aer_bridge),
	[ACPI_HEST_TYPE_GENERIC_ERROR] = sizeof(struct acpi_hest_generic),
};

static int hest_esrc_len(const struct acpi_hest_header *hest_hdr)
{
	u16 hest_type = hest_hdr->type;
	int len;

	if (hest_type >= ACPI_HEST_TYPE_RESERVED)
		return 0;

	len = hest_esrc_len_tab[hest_type];

	if (hest_type == ACPI_HEST_TYPE_IA32_CORRECTED_CHECK) {
		const struct acpi_hest_ia_corrected *cmc =
			container_of(hest_hdr,
				     const struct acpi_hest_ia_corrected,
				     header);

		len = sizeof(*cmc) + cmc->num_hardware_banks *
		      sizeof(struct acpi_hest_ia_error_bank);
	} else if (hest_type == ACPI_HEST_TYPE_IA32_CHECK) {
		const struct acpi_hest_ia_machine_check *mc =
			container_of(hest_hdr,
				     const struct acpi_hest_ia_machine_check,
				     header);

		len = sizeof(*mc) + mc->num_hardware_banks *
		      sizeof(struct acpi_hest_ia_error_bank);
	}
	BUG_ON(len == -1);

	return len;
};

int apei_hest_parse(apei_hest_func_t func, void *data)
{
	struct acpi_hest_header *hest_hdr;
	int i, rc, len;

	if (hest_disable || !hest_tab)
		return -EINVAL;

	hest_hdr = (struct acpi_hest_header *)(hest_tab + 1);
	for (i = 0; i < hest_tab->error_source_count; i++) {
		len = hest_esrc_len(hest_hdr);
		if (!len) {
			printk(XENLOG_WARNING HEST_PFX
			       "Unknown or unused hardware error source "
			       "type: %d for hardware error source: %d\n",
			       hest_hdr->type, hest_hdr->source_id);
			return -EINVAL;
		}
		if ((void *)hest_hdr + len >
		    (void *)hest_tab + hest_tab->header.length) {
			printk(XENLOG_WARNING HEST_PFX
			       "Table contents overflow for hardware error source: %d\n",
			       hest_hdr->source_id);
			return -EINVAL;
		}

		rc = func(hest_hdr, data);
		if (rc)
			return rc;

		hest_hdr = (void *)hest_hdr + len;
	}

	return 0;
}

/*
 * Check if firmware advertises firmware first mode. We need FF bit to be set
 * along with a set of MC banks which work in FF mode.
 */
static int __init hest_parse_cmc(const struct acpi_hest_header *hest_hdr,
				 void *data)
{
#ifdef CONFIG_X86_MCE
	unsigned int i;
	const struct acpi_hest_ia_corrected *cmc;
	const struct acpi_hest_ia_error_bank *mc_bank;

	if (hest_hdr->type != ACPI_HEST_TYPE_IA32_CORRECTED_CHECK)
		return 0;

	cmc = container_of(hest_hdr, const struct acpi_hest_ia_corrected, header);
	if (!cmc->enabled)
		return 0;

	/*
	 * We expect HEST to provide a list of MC banks that report errors
	 * in firmware first mode. Otherwise, return non-zero value to
	 * indicate that we are done parsing HEST.
	 */
	if (!(cmc->flags & ACPI_HEST_FIRMWARE_FIRST) || !cmc->num_hardware_banks)
		return 1;

	printk(XENLOG_INFO HEST_PFX "Enabling Firmware First mode for corrected errors.\n");

	mc_bank = (const struct acpi_hest_ia_error_bank *)(cmc + 1);
	for (i = 0; i < cmc->num_hardware_banks; i++, mc_bank++)
		mce_disable_bank(mc_bank->bank_number);
#else
# define acpi_disable_cmcff 1
#endif

	return 1;
}

void __init acpi_hest_init(void)
{
	acpi_status status;
	acpi_physical_address hest_addr;
	acpi_native_uint hest_len;

	if (acpi_disabled)
		return;

	if (hest_disable) {
		printk(XENLOG_INFO HEST_PFX "Table parsing disabled.\n");
		return;
	}

	status = acpi_get_table_phys(ACPI_SIG_HEST, 0, &hest_addr, &hest_len);
	if (status == AE_NOT_FOUND)
		goto err;
	if (ACPI_FAILURE(status)) {
		printk(XENLOG_ERR HEST_PFX "Failed to get table, %s\n",
		       acpi_format_exception(status));
		goto err;
	}
	map_pages_to_xen((unsigned long)__va(hest_addr), PFN_DOWN(hest_addr),
			 PFN_UP(hest_addr + hest_len) - PFN_DOWN(hest_addr),
			 PAGE_HYPERVISOR);
	hest_tab = __va(hest_addr);

	if (!acpi_disable_cmcff)
		apei_hest_parse(hest_parse_cmc, NULL);

	printk(XENLOG_INFO HEST_PFX "Table parsing has been initialized\n");
	return;
err:
	hest_disable = 1;
}
