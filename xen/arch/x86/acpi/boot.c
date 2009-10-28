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

int sbf_port;
#define CONFIG_ACPI_PCI

#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length != sizeof(*entry))

#define PREFIX			"ACPI: "

#ifdef CONFIG_ACPI_PCI
int acpi_noirq __initdata;	/* skip ACPI IRQ initialization */
int acpi_pci_disabled __initdata; /* skip ACPI PCI scan and IRQ initialization */
#else
int acpi_noirq __initdata = 1;
int acpi_pci_disabled __initdata = 1;
#endif
int acpi_ht __initdata = 1;	/* enable HT */

int acpi_lapic;
int acpi_ioapic;
int acpi_strict;
EXPORT_SYMBOL(acpi_strict);

u8 acpi_sci_flags __initdata;
int acpi_sci_override_gsi __initdata;
int acpi_skip_timer_override __initdata;

#ifdef CONFIG_X86_LOCAL_APIC
static u64 acpi_lapic_addr __initdata = APIC_DEFAULT_PHYS_BASE;
#endif

u32 acpi_smi_cmd;
u8 acpi_enable_value, acpi_disable_value;

#ifndef __HAVE_ARCH_CMPXCHG
#warning ACPI uses CMPXCHG, i486 and later hardware
#endif

#define MAX_MADT_ENTRIES	256
u8 x86_acpiid_to_apicid[MAX_MADT_ENTRIES] =
    {[0 ... MAX_MADT_ENTRIES - 1] = 0xff };
EXPORT_SYMBOL(x86_acpiid_to_apicid);

/* --------------------------------------------------------------------------
                              Boot-time Configuration
   -------------------------------------------------------------------------- */

/*
 * The default interrupt routing model is PIC (8259).  This gets
 * overriden if IOAPICs are enumerated (below).
 */
enum acpi_irq_model_id		acpi_irq_model = ACPI_IRQ_MODEL_PIC;

/*
 * Temporarily use the virtual area starting from FIX_IO_APIC_BASE_END,
 * to map the target physical address. The problem is that set_fixmap()
 * provides a single page, and it is possible that the page is not
 * sufficient.
 * By using this area, we can map up to MAX_IO_APICS pages temporarily,
 * i.e. until the next __va_range() call.
 *
 * Important Safety Note:  The fixed I/O APIC page numbers are *subtracted*
 * from the fixed base.  That's why we start at FIX_IO_APIC_BASE_END and
 * count idx down while incrementing the phys address.
 */
char *__acpi_map_table(unsigned long phys, unsigned long size)
{
	unsigned long base, offset, mapped_size;
	int idx;

	/* XEN: RAM holes above 1MB are not permanently mapped. */
	if ((phys + size) <= (1 * 1024 * 1024))
		return __va(phys);

	offset = phys & (PAGE_SIZE - 1);
	mapped_size = PAGE_SIZE - offset;
	set_fixmap(FIX_ACPI_END, phys);
	base = fix_to_virt(FIX_ACPI_END);

	/*
	 * Most cases can be covered by the below.
	 */
	idx = FIX_ACPI_END;
	while (mapped_size < size) {
		if (--idx < FIX_ACPI_BEGIN)
			return NULL;	/* cannot handle this */
		phys += PAGE_SIZE;
		set_fixmap(idx, phys);
		mapped_size += PAGE_SIZE;
	}

	return ((char *) base + offset);
}

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
acpi_parse_lapic(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_table_lapic *processor = NULL;

	processor = (struct acpi_table_lapic *)header;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* Record local apic id only when enabled */
	if (processor->flags.enabled)
		x86_acpiid_to_apicid[processor->acpi_id] = processor->id;

	/*
	 * We need to register disabled CPU as well to permit
	 * counting disabled CPUs. This allows us to size
	 * cpus_possible_map more accurately, to permit
	 * to not preallocating memory for all NR_CPUS
	 * when we use CPU hotplug.
	 */
	mp_register_lapic(processor->id,	/* APIC ID */
			  processor->flags.enabled);	/* Enabled? */

	return 0;
}

static int __init
acpi_parse_lapic_addr_ovr(struct acpi_subtable_header * header,
			  const unsigned long end)
{
	struct acpi_table_lapic_addr_ovr *lapic_addr_ovr = NULL;

	lapic_addr_ovr = (struct acpi_table_lapic_addr_ovr *)header;

	if (BAD_MADT_ENTRY(lapic_addr_ovr, end))
		return -EINVAL;

	acpi_lapic_addr = lapic_addr_ovr->address;

	return 0;
}

static int __init
acpi_parse_lapic_nmi(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_table_lapic_nmi *lapic_nmi = NULL;

	lapic_nmi = (struct acpi_table_lapic_nmi *)header;

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
	struct acpi_table_ioapic *ioapic = NULL;

	ioapic = (struct acpi_table_ioapic *)header;

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
	struct acpi_table_int_src_ovr *intsrc = NULL;

	intsrc = (struct acpi_table_int_src_ovr *)header;

	if (BAD_MADT_ENTRY(intsrc, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (acpi_skip_timer_override &&
		intsrc->bus_irq == 0 && intsrc->global_irq == 2) {
			printk(PREFIX "BIOS IRQ0 pin2 override ignored.\n");
			return 0;
	}

	mp_override_legacy_irq(intsrc->bus_irq,
			       intsrc->flags.polarity,
			       intsrc->flags.trigger, intsrc->global_irq);

	return 0;
}

static int __init
acpi_parse_nmi_src(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_table_nmi_src *nmi_src = NULL;

	nmi_src = (struct acpi_table_nmi_src *)header;

	if (BAD_MADT_ENTRY(nmi_src, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* TBD: Support nimsrc entries? */

	return 0;
}

#endif /* CONFIG_X86_IO_APIC */

static int __init acpi_parse_sbf(struct acpi_table_header *table)
{
	struct acpi_table_boot *sb;

	sb = (struct acpi_table_boot *)table;
	if (!sb) {
		printk(KERN_WARNING PREFIX "Unable to map SBF\n");
		return -ENODEV;
	}

	sbf_port = sb->cmos_index;	/* Save CMOS port */

	return 0;
}

#ifdef CONFIG_HPET_TIMER

static int __init acpi_parse_hpet(struct acpi_table_header *table)
{
	struct acpi_table_hpet *hpet_tbl = (struct acpi_table_hpet *)table;

	if (hpet_tbl->address.space_id != ACPI_SPACE_MEM) {
		printk(KERN_WARNING PREFIX "HPET timers must be located in "
		       "memory.\n");
		return -1;
	}

#if 0/*def	CONFIG_X86_64*/
	vxtime.hpet_address = hpet_tbl->address.address;

	printk(KERN_INFO PREFIX "HPET id: %#x base: %#lx\n",
	       hpet_tbl->id, vxtime.hpet_address);
#else	/* X86 */
	{
		hpet_address = hpet_tbl->address.address;
		printk(KERN_INFO PREFIX "HPET id: %#x base: %#lx\n",
		       hpet_tbl->id, hpet_address);
	}
#endif	/* X86 */

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
	if (fadt->header.revision >= FADT2_REVISION_ID)
		facs_pa = fadt->Xfacs;
	else
		facs_pa = (uint64_t)fadt->facs;

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
	int count;

	if (!cpu_has_apic)
		return -ENODEV;

	/* 
	 * Note that the LAPIC address is obtained from the MADT (32-bit value)
	 * and (optionally) overriden by a LAPIC_ADDR_OVR entry (64-bit value).
	 */

	count =
	    acpi_table_parse_madt(ACPI_MADT_LAPIC_ADDR_OVR,
				  acpi_parse_lapic_addr_ovr, 0);
	if (count < 0) {
		printk(KERN_ERR PREFIX
		       "Error parsing LAPIC address override entry\n");
		return count;
	}

	mp_register_lapic_address(acpi_lapic_addr);

	count = acpi_table_parse_madt(ACPI_MADT_LAPIC, acpi_parse_lapic,
				      MAX_APICS);
	if (!count) {
		printk(KERN_ERR PREFIX "No LAPIC entries present\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return -ENODEV;
	} else if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

	count =
	    acpi_table_parse_madt(ACPI_MADT_LAPIC_NMI, acpi_parse_lapic_nmi, 0);
	if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC NMI entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}
	return 0;
}
#endif /* CONFIG_X86_LOCAL_APIC */

#if defined(CONFIG_X86_IO_APIC) /*&& defined(CONFIG_ACPI_INTERPRETER)*/
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
	    acpi_table_parse_madt(ACPI_MADT_IOAPIC, acpi_parse_ioapic,
				  MAX_IO_APICS);
	if (!count) {
		printk(KERN_ERR PREFIX "No IOAPIC entries present\n");
		return -ENODEV;
	} else if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing IOAPIC entry\n");
		return count;
	}

	count =
	    acpi_table_parse_madt(ACPI_MADT_INT_SRC_OVR, acpi_parse_int_src_ovr,
				  MAX_IRQ_SOURCES);
	if (count < 0) {
		printk(KERN_ERR PREFIX
		       "Error parsing interrupt source overrides entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

#ifdef CONFIG_ACPI_INTERPRETER
	/*
	 * If BIOS did not supply an INT_SRC_OVR for the SCI
	 * pretend we got one so we can set the SCI flags.
	 */
	if (!acpi_sci_override_gsi)
		acpi_sci_ioapic_setup(acpi_fadt.sci_int, 0, 0);
#endif

	/* Fill in identity legacy mapings where no override */
	mp_config_acpi_legacy_irqs();

	count =
	    acpi_table_parse_madt(ACPI_MADT_NMI_SRC, acpi_parse_nmi_src,
				  MAX_IRQ_SOURCES);
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
#endif /* !(CONFIG_X86_IO_APIC && CONFIG_ACPI_INTERPRETER) */


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
				acpi_irq_model = ACPI_IRQ_MODEL_IOAPIC;
				acpi_irq_balance_set(NULL);
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

extern int acpi_force;

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

static int __init disable_acpi_pci(struct dmi_system_id *d)
{
	if (!acpi_force) {
		printk(KERN_NOTICE "%s detected: force use of pci=noacpi\n",
		       d->ident);
		/*acpi_disable_pci();*/
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

	/*
	 * Boxes that need ACPI PCI IRQ routing and PCI scan disabled
	 */
	{			/* _BBN 0 bug */
	 .callback = disable_acpi_pci,
	 .ident = "ASUS PR-DLS",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
		     DMI_MATCH(DMI_BOARD_NAME, "PR-DLS"),
		     DMI_MATCH(DMI_BIOS_VERSION,
			       "ASUS PR-DLS ACPI BIOS Revision 1010"),
		     DMI_MATCH(DMI_BIOS_DATE, "03/21/2003")
		     },
	 },
	{
	 .callback = disable_acpi_pci,
	 .ident = "Acer TravelMate 36x Laptop",
	 .matches = {
		     DMI_MATCH(DMI_SYS_VENDOR, "Acer"),
		     DMI_MATCH(DMI_PRODUCT_NAME, "TravelMate 360"),
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
 *	if acpi_blacklisted() acpi_disabled = 1;
 *	acpi_irq_model=...
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

	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);

	/*
	 * blacklist may disable ACPI entirely
	 */
	error = acpi_blacklisted();
	if (error) {
		if (acpi_force) {
			printk(KERN_WARNING PREFIX "acpi=force override\n");
		} else {
			printk(KERN_WARNING PREFIX "Disabling ACPI support\n");
			disable_acpi();
			return error;
		}
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

	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);

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

	acpi_mmcfg_init();

	return 0;
}

unsigned int acpi_get_processor_id(unsigned int cpu)
{
	unsigned int acpiid, apicid;

	if ((apicid = x86_cpu_to_apicid[cpu]) == 0xff)
		return 0xff;

	for (acpiid = 0; acpiid < ARRAY_SIZE(x86_acpiid_to_apicid); acpiid++)
		if (x86_acpiid_to_apicid[acpiid] == apicid)
			return acpiid;

	return 0xff;
}
