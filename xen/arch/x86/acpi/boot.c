/*
 *  boot.c - Architecture-Specific Low-Level ACPI Boot Support
 *
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Jun Nakajima <jun.nakajima@intel.com>
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
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/acpi.h>
#include <xen/irq.h>
#include <xen/dmi.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#ifdef CONFIG_HPET_TIMER
#include <asm/hpet.h> /* for hpet_address */
#endif
#include <mach_apic.h>
#include <mach_mpparse.h>

#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length != sizeof(*entry))

#define PREFIX			"ACPI: "

bool_t __initdata acpi_noirq;	/* skip ACPI IRQ initialization */
bool_t __initdata acpi_ht = 1;	/* enable HT */

bool_t __initdata acpi_lapic;
bool_t __initdata acpi_ioapic;

bool_t acpi_skip_timer_override __initdata;

#ifdef CONFIG_X86_LOCAL_APIC
static u64 acpi_lapic_addr __initdata = APIC_DEFAULT_PHYS_BASE;
#endif

/* --------------------------------------------------------------------------
                              Boot-time Configuration
   -------------------------------------------------------------------------- */

#ifdef CONFIG_X86_LOCAL_APIC
static int __init acpi_parse_madt(struct acpi_table_header *table)
{
	struct acpi_table_madt *madt;

	madt = (struct acpi_table_madt *)table;

	if (madt->address) {
		acpi_lapic_addr = (u64) madt->address;

		printk(KERN_DEBUG PREFIX "Local APIC address 0x%08x\n",
		       madt->address);
	}

	acpi_madt_oem_check(madt->header.oem_id, madt->header.oem_table_id);

	return 0;
}

static int __init
acpi_parse_x2apic(struct acpi_subtable_header *header, const unsigned long end)
{
	struct acpi_madt_local_x2apic *processor =
		container_of(header, struct acpi_madt_local_x2apic, header);
	bool_t enabled = 0;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* Record local apic id only when enabled and fitting. */
	if (processor->local_apic_id >= MAX_APICS ||
	    processor->uid >= MAX_MADT_ENTRIES) {
		printk("%sAPIC ID %#x and/or ACPI ID %#x beyond limit"
		       " - processor ignored\n",
		       processor->lapic_flags & ACPI_MADT_ENABLED ?
				KERN_WARNING "WARNING: " : KERN_INFO,
		       processor->local_apic_id, processor->uid);
		/*
		 * Must not return an error here, to prevent
		 * acpi_table_parse_entries() from terminating early.
		 */
		return 0 /* -ENOSPC */;
	}
	if (processor->lapic_flags & ACPI_MADT_ENABLED) {
		x86_acpiid_to_apicid[processor->uid] =
			processor->local_apic_id;
		enabled = 1;
	}

	/*
	 * We need to register disabled CPU as well to permit
	 * counting disabled CPUs. This allows us to size
	 * cpus_possible_map more accurately, to permit
	 * to not preallocating memory for all NR_CPUS
	 * when we use CPU hotplug.
	 */
	mp_register_lapic(processor->local_apic_id, enabled, 0);

	return 0;
}

static int __init
acpi_parse_lapic(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_local_apic *processor =
		container_of(header, struct acpi_madt_local_apic, header);
	bool_t enabled = 0;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* Record local apic id only when enabled */
	if (processor->lapic_flags & ACPI_MADT_ENABLED) {
		x86_acpiid_to_apicid[processor->processor_id] = processor->id;
		enabled = 1;
	}

	/*
	 * We need to register disabled CPU as well to permit
	 * counting disabled CPUs. This allows us to size
	 * cpus_possible_map more accurately, to permit
	 * to not preallocating memory for all NR_CPUS
	 * when we use CPU hotplug.
	 */
	mp_register_lapic(processor->id, enabled, 0);

	return 0;
}

static int __init
acpi_parse_lapic_addr_ovr(struct acpi_subtable_header * header,
			  const unsigned long end)
{
	struct acpi_madt_local_apic_override *lapic_addr_ovr =
		container_of(header, struct acpi_madt_local_apic_override,
			     header);

	if (BAD_MADT_ENTRY(lapic_addr_ovr, end))
		return -EINVAL;

	acpi_lapic_addr = lapic_addr_ovr->address;

	return 0;
}

static int __init
acpi_parse_x2apic_nmi(struct acpi_subtable_header *header,
		      const unsigned long end)
{
	struct acpi_madt_local_x2apic_nmi *x2apic_nmi =
		container_of(header, struct acpi_madt_local_x2apic_nmi,
			     header);

	if (BAD_MADT_ENTRY(x2apic_nmi, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (x2apic_nmi->lint != 1)
		printk(KERN_WARNING PREFIX "NMI not connected to LINT 1!\n");

	return 0;
}

static int __init
acpi_parse_lapic_nmi(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_local_apic_nmi *lapic_nmi =
		container_of(header, struct acpi_madt_local_apic_nmi, header);

	if (BAD_MADT_ENTRY(lapic_nmi, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (lapic_nmi->lint != 1)
		printk(KERN_WARNING PREFIX "NMI not connected to LINT 1!\n");

	return 0;
}

#endif				/*CONFIG_X86_LOCAL_APIC */

#if defined(CONFIG_X86_IO_APIC) /*&& defined(CONFIG_ACPI_INTERPRETER)*/

static int __init
acpi_parse_ioapic(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_io_apic *ioapic =
		container_of(header, struct acpi_madt_io_apic, header);

	if (BAD_MADT_ENTRY(ioapic, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	mp_register_ioapic(ioapic->id,
			   ioapic->address, ioapic->global_irq_base);

	return 0;
}

static int __init
acpi_parse_int_src_ovr(struct acpi_subtable_header * header,
		       const unsigned long end)
{
	struct acpi_madt_interrupt_override *intsrc =
		container_of(header, struct acpi_madt_interrupt_override,
			     header);

	if (BAD_MADT_ENTRY(intsrc, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (acpi_skip_timer_override &&
	    intsrc->source_irq == 0 && intsrc->global_irq == 2) {
			printk(PREFIX "BIOS IRQ0 pin2 override ignored.\n");
			return 0;
	}

	mp_override_legacy_irq(intsrc->source_irq,
			       ACPI_MADT_GET_POLARITY(intsrc->inti_flags),
			       ACPI_MADT_GET_TRIGGER(intsrc->inti_flags),
			       intsrc->global_irq);

	return 0;
}

static int __init
acpi_parse_nmi_src(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_nmi_source *nmi_src =
		container_of(header, struct acpi_madt_nmi_source, header);

	if (BAD_MADT_ENTRY(nmi_src, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* TBD: Support nimsrc entries? */

	return 0;
}

#endif /* CONFIG_X86_IO_APIC */

#ifdef CONFIG_HPET_TIMER

static int __init acpi_parse_hpet(struct acpi_table_header *table)
{
	struct acpi_table_hpet *hpet_tbl = (struct acpi_table_hpet *)table;

	if (hpet_tbl->address.space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY) {
		printk(KERN_WARNING PREFIX "HPET timers must be located in "
		       "memory.\n");
		return -1;
	}

	hpet_address = hpet_tbl->address.address;
	printk(KERN_INFO PREFIX "HPET id: %#x base: %#lx\n",
	       hpet_tbl->id, hpet_address);

	return 0;
}
#else
#define	acpi_parse_hpet	NULL
#endif

#ifdef CONFIG_ACPI_SLEEP
#define acpi_fadt_copy_address(dst, src, len) do {			\
	if (fadt->header.revision >= FADT2_REVISION_ID)			\
		acpi_sinfo.dst##_blk = fadt->x##src##_block;		\
	if (!acpi_sinfo.dst##_blk.address) {				\
		acpi_sinfo.dst##_blk.address      = fadt->src##_block;	\
		acpi_sinfo.dst##_blk.space_id     = ACPI_ADR_SPACE_SYSTEM_IO; \
		acpi_sinfo.dst##_blk.bit_width    = fadt->len##_length << 3; \
		acpi_sinfo.dst##_blk.bit_offset   = 0;			\
		acpi_sinfo.dst##_blk.access_width = 0;			\
	} \
} while (0)

/* Get pm1x_cnt and pm1x_evt information for ACPI sleep */
static void __init
acpi_fadt_parse_sleep_info(struct acpi_table_fadt *fadt)
{
	struct acpi_table_facs *facs = NULL;
	uint64_t facs_pa;

	acpi_fadt_copy_address(pm1a_cnt, pm1a_control, pm1_control);
	acpi_fadt_copy_address(pm1b_cnt, pm1b_control, pm1_control);
	acpi_fadt_copy_address(pm1a_evt, pm1a_event, pm1_event);
	acpi_fadt_copy_address(pm1b_evt, pm1b_event, pm1_event);

	printk(KERN_INFO PREFIX
	       "ACPI SLEEP INFO: pm1x_cnt[%"PRIx64",%"PRIx64"], "
	       "pm1x_evt[%"PRIx64",%"PRIx64"]\n",
	       acpi_sinfo.pm1a_cnt_blk.address,
	       acpi_sinfo.pm1b_cnt_blk.address,
	       acpi_sinfo.pm1a_evt_blk.address,
	       acpi_sinfo.pm1b_evt_blk.address);

	/* Now FACS... */
	facs_pa = ((fadt->header.revision >= FADT2_REVISION_ID)
		   ? fadt->Xfacs : (uint64_t)fadt->facs);
	if (fadt->facs && ((uint64_t)fadt->facs != facs_pa)) {
		printk(KERN_WARNING PREFIX
		       "32/64X FACS address mismatch in FADT - "
		       "%08x/%016"PRIx64", using 32\n",
		       fadt->facs, facs_pa);
		facs_pa = (uint64_t)fadt->facs;
	}

	facs = (struct acpi_table_facs *)
		__acpi_map_table(facs_pa, sizeof(struct acpi_table_facs));
	if (!facs)
		goto bad;

	if (strncmp(facs->signature, "FACS", 4)) {
		printk(KERN_ERR PREFIX "Invalid FACS signature %.4s\n",
			facs->signature);
		goto bad;
	}

	if (facs->length < 24) {
		printk(KERN_ERR PREFIX "Invalid FACS table length: 0x%x",
			facs->length);
		goto bad;
	}

	if (facs->length < 64)
		printk(KERN_WARNING PREFIX
			"FACS is shorter than ACPI spec allow: 0x%x",
			facs->length);

	acpi_sinfo.wakeup_vector = facs_pa + 
		offsetof(struct acpi_table_facs, firmware_waking_vector);
	acpi_sinfo.vector_width = 32;

	printk(KERN_INFO PREFIX
	       "                 wakeup_vec[%"PRIx64"], vec_size[%x]\n",
	       acpi_sinfo.wakeup_vector, acpi_sinfo.vector_width);
	return;
bad:
	memset(&acpi_sinfo, 0, sizeof(acpi_sinfo));
}
#endif

static int __init acpi_parse_fadt(struct acpi_table_header *table)
{
	struct acpi_table_fadt *fadt = (struct acpi_table_fadt *)table;

#ifdef	CONFIG_ACPI_INTERPRETER
	/* initialize sci_int early for INT_SRC_OVR MADT parsing */
	acpi_fadt.sci_int = fadt->sci_int;

	/* initialize rev and apic_phys_dest_mode for x86_64 genapic */
	acpi_fadt.revision = fadt->revision;
	acpi_fadt.force_apic_physical_destination_mode =
	    fadt->force_apic_physical_destination_mode;
#endif

#ifdef CONFIG_X86_PM_TIMER
	/* detect the location of the ACPI PM Timer */
	if (fadt->header.revision >= FADT2_REVISION_ID) {
		/* FADT rev. 2 */
		if (fadt->xpm_timer_block.space_id ==
		    ACPI_ADR_SPACE_SYSTEM_IO)
			pmtmr_ioport = fadt->xpm_timer_block.address;
		/*
		 * "X" fields are optional extensions to the original V1.0
		 * fields, so we must selectively expand V1.0 fields if the
		 * corresponding X field is zero.
	 	 */
		if (!pmtmr_ioport)
			pmtmr_ioport = fadt->pm_timer_block;
	} else {
		/* FADT rev. 1 */
		pmtmr_ioport = fadt->pm_timer_block;
	}
	if (pmtmr_ioport)
		printk(KERN_INFO PREFIX "PM-Timer IO Port: %#x\n",
		       pmtmr_ioport);
#endif

	acpi_smi_cmd       = fadt->smi_command;
	acpi_enable_value  = fadt->acpi_enable;
	acpi_disable_value = fadt->acpi_disable;

#ifdef CONFIG_ACPI_SLEEP
	acpi_fadt_parse_sleep_info(fadt);
#endif

	return 0;
}

#ifdef	CONFIG_X86_LOCAL_APIC
/*
 * Parse LAPIC entries in MADT
 * returns 0 on success, < 0 on error
 */
static int __init acpi_parse_madt_lapic_entries(void)
{
	int count, x2count;

	if (!cpu_has_apic)
		return -ENODEV;

	/* 
	 * Note that the LAPIC address is obtained from the MADT (32-bit value)
	 * and (optionally) overriden by a LAPIC_ADDR_OVR entry (64-bit value).
	 */

	count =
	    acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE,
				  acpi_parse_lapic_addr_ovr, 0);
	if (count < 0) {
		printk(KERN_ERR PREFIX
		       "Error parsing LAPIC address override entry\n");
		return count;
	}

	mp_register_lapic_address(acpi_lapic_addr);

	BUILD_BUG_ON(MAX_APICS != MAX_LOCAL_APIC);
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_APIC, 
                                      acpi_parse_lapic, MAX_APICS);
	x2count = acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_X2APIC, 
                                        acpi_parse_x2apic, MAX_APICS);
	if (!count && !x2count) {
		printk(KERN_ERR PREFIX "No LAPIC entries present\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return -ENODEV;
	} else if (count < 0 || x2count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

	count =
	    acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_APIC_NMI, 
                                  acpi_parse_lapic_nmi, 0);
	x2count =
	    acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_X2APIC_NMI,
				  acpi_parse_x2apic_nmi, 0);
	if (count < 0 || x2count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC NMI entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}
	return 0;
}
#endif /* CONFIG_X86_LOCAL_APIC */

#ifdef CONFIG_X86_IO_APIC
/*
 * Parse IOAPIC related entries in MADT
 * returns 0 on success, < 0 on error
 */
static int __init acpi_parse_madt_ioapic_entries(void)
{
	int count;

	/*
	 * ACPI interpreter is required to complete interrupt setup,
	 * so if it is off, don't enumerate the io-apics with ACPI.
	 * If MPS is present, it will handle them,
	 * otherwise the system will stay in PIC mode
	 */
	if (acpi_disabled || acpi_noirq) {
		return -ENODEV;
	}

	if (!cpu_has_apic)
		return -ENODEV;

	/*
	 * if "noapic" boot option, don't look for IO-APICs
	 */
	if (skip_ioapic_setup) {
		printk(KERN_INFO PREFIX "Skipping IOAPIC probe "
		       "due to 'noapic' option.\n");
		return -ENODEV;
	}

	count =
	    acpi_table_parse_madt(ACPI_MADT_TYPE_IO_APIC, acpi_parse_ioapic,
				  MAX_IO_APICS);
	if (!count) {
		printk(KERN_ERR PREFIX "No IOAPIC entries present\n");
		return -ENODEV;
	} else if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing IOAPIC entry\n");
		return count;
	}

	count =
	    acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_OVERRIDE,
                                  acpi_parse_int_src_ovr, MAX_IRQ_SOURCES);
	if (count < 0) {
		printk(KERN_ERR PREFIX
		       "Error parsing interrupt source overrides entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

	/* Fill in identity legacy mapings where no override */
	mp_config_acpi_legacy_irqs();

	count =
	    acpi_table_parse_madt(ACPI_MADT_TYPE_NMI_SOURCE, 
                                  acpi_parse_nmi_src, MAX_IRQ_SOURCES);
	if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing NMI SRC entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

	return 0;
}
#else
static inline int acpi_parse_madt_ioapic_entries(void)
{
	return -1;
}
#endif /* !CONFIG_X86_IO_APIC */


static void __init acpi_process_madt(void)
{
#ifdef CONFIG_X86_LOCAL_APIC
	int error;

	if (!acpi_table_parse(ACPI_SIG_MADT, acpi_parse_madt)) {

		/*
		 * Parse MADT LAPIC entries
		 */
		error = acpi_parse_madt_lapic_entries();
		if (!error) {
			acpi_lapic = 1;
			generic_bigsmp_probe();
 
			/*
			 * Parse MADT IO-APIC entries
			 */
			error = acpi_parse_madt_ioapic_entries();
			if (!error) {
				acpi_ioapic = 1;

				smp_found_config = 1;
				clustered_apic_check();
			}
		}
		if (error == -EINVAL) {
			/*
			 * Dell Precision Workstation 410, 610 come here.
			 */
			printk(KERN_ERR PREFIX
			       "Invalid BIOS MADT, disabling ACPI\n");
			disable_acpi();
		}
	}
#endif
	return;
}

#ifdef __i386__

static int __init disable_acpi_irq(struct dmi_system_id *d)
{
	if (!acpi_force) {
		printk(KERN_NOTICE "%s detected: force use of acpi=noirq\n",
		       d->ident);
		acpi_noirq_set();
	}
	return 0;
}

static int __init dmi_disable_acpi(struct dmi_system_id *d)
{
	if (!acpi_force) {
		printk(KERN_NOTICE "%s detected: acpi off\n", d->ident);
		disable_acpi();
	} else {
		printk(KERN_NOTICE
		       "Warning: DMI blacklist says broken, but acpi forced\n");
	}
	return 0;
}

/*
 * Limit ACPI to CPU enumeration for HT
 */
static int __init force_acpi_ht(struct dmi_system_id *d)
{
	if (!acpi_force) {
		printk(KERN_NOTICE "%s detected: force use of acpi=ht\n",
		       d->ident);
		disable_acpi();
		acpi_ht = 1;
	} else {
		printk(KERN_NOTICE
		       "Warning: acpi=force overrules DMI blacklist: acpi=ht\n");
	}
	return 0;
}

/*
 * If your system is blacklisted here, but you find that acpi=force
 * works for you, please contact acpi-devel@sourceforge.net
 */
static struct dmi_system_id __initdata acpi_dmi_table[] = {
	/*
	 * Boxes that need ACPI disabled
	 */
	{
	 .callback = dmi_disable_acpi,
	 .ident = "IBM Thinkpad",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "IBM"),
		     DMI_MATCH(DMI_BOARD_NAME, "2629H1G"),
		     },
	 },

	/*
	 * Boxes that need acpi=ht
	 */
	{
	 .callback = force_acpi_ht,
	 .ident = "FSC Primergy T850",
	 .matches = {
		     DMI_MATCH(DMI_SYS_VENDOR, "FUJITSU SIEMENS"),
		     DMI_MATCH(DMI_PRODUCT_NAME, "PRIMERGY T850"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "DELL GX240",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "Dell Computer Corporation"),
		     DMI_MATCH(DMI_BOARD_NAME, "OptiPlex GX240"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "HP VISUALIZE NT Workstation",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "Hewlett-Packard"),
		     DMI_MATCH(DMI_PRODUCT_NAME, "HP VISUALIZE NT Workstation"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "Compaq Workstation W8000",
	 .matches = {
		     DMI_MATCH(DMI_SYS_VENDOR, "Compaq"),
		     DMI_MATCH(DMI_PRODUCT_NAME, "Workstation W8000"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "ASUS P4B266",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
		     DMI_MATCH(DMI_BOARD_NAME, "P4B266"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "ASUS P2B-DS",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
		     DMI_MATCH(DMI_BOARD_NAME, "P2B-DS"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "ASUS CUR-DLS",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
		     DMI_MATCH(DMI_BOARD_NAME, "CUR-DLS"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "ABIT i440BX-W83977",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "ABIT <http://www.abit.com>"),
		     DMI_MATCH(DMI_BOARD_NAME, "i440BX-W83977 (BP6)"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "IBM Bladecenter",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "IBM"),
		     DMI_MATCH(DMI_BOARD_NAME, "IBM eServer BladeCenter HS20"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "IBM eServer xSeries 360",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "IBM"),
		     DMI_MATCH(DMI_BOARD_NAME, "eServer xSeries 360"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "IBM eserver xSeries 330",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "IBM"),
		     DMI_MATCH(DMI_BOARD_NAME, "eserver xSeries 330"),
		     },
	 },
	{
	 .callback = force_acpi_ht,
	 .ident = "IBM eserver xSeries 440",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "IBM"),
		     DMI_MATCH(DMI_PRODUCT_NAME, "eserver xSeries 440"),
		     },
	 },

	/*
	 * Boxes that need ACPI PCI IRQ routing disabled
	 */
	{
	 .callback = disable_acpi_irq,
	 .ident = "ASUS A7V",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC"),
		     DMI_MATCH(DMI_BOARD_NAME, "<A7V>"),
		     /* newer BIOS, Revision 1011, does work */
		     DMI_MATCH(DMI_BIOS_VERSION,
			       "ASUS A7V ACPI BIOS Revision 1007"),
		     },
	 },
	{}
};

#endif				/* __i386__ */

/*
 * acpi_boot_table_init() and acpi_boot_init()
 *  called from setup_arch(), always.
 *	1. checksums all tables
 *	2. enumerates lapics
 *	3. enumerates io-apics
 *
 * acpi_table_init() is separate to allow reading SRAT without
 * other side effects.
 *
 * side effects of acpi_boot_init:
 *	acpi_lapic = 1 if LAPIC found
 *	acpi_ioapic = 1 if IOAPIC found
 *	if (acpi_lapic && acpi_ioapic) smp_found_config = 1;
 *	...
 *
 * return value: (currently ignored)
 *	0: success
 *	!0: failure
 */

int __init acpi_boot_table_init(void)
{
	int error;

#ifdef __i386__
	dmi_check_system(acpi_dmi_table);
#endif

	/*
	 * If acpi_disabled, bail out
	 * One exception: acpi=ht continues far enough to enumerate LAPICs
	 */
	if (acpi_disabled && !acpi_ht)
		return 1;

	/* 
	 * Initialize the ACPI boot-time table parser.
	 */
	error = acpi_table_init();
	if (error) {
		disable_acpi();
		return error;
	}

	return 0;
}

int __init acpi_boot_init(void)
{
	/*
	 * If acpi_disabled, bail out
	 * One exception: acpi=ht continues far enough to enumerate LAPICs
	 */
	if (acpi_disabled && !acpi_ht)
		return 1;

	/*
	 * set sci_int and PM timer address
	 */
	acpi_table_parse(ACPI_SIG_FADT, acpi_parse_fadt);

	/*
	 * Process the Multiple APIC Description Table (MADT), if present
	 */
	acpi_process_madt();

	acpi_table_parse(ACPI_SIG_HPET, acpi_parse_hpet);

	acpi_dmar_init();

	erst_init();

	return 0;
}
