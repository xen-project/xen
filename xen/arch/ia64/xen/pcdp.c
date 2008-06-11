/*
 * Parse the EFI PCDP table to locate the console device.
 *
 * (c) Copyright 2002, 2003, 2004 Hewlett-Packard Development Company, L.P.
 *	Khalid Aziz <khalid.aziz@hp.com>
 *	Alex Williamson <alex.williamson@hp.com>
 *	Bjorn Helgaas <bjorn.helgaas@hp.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/efi.h>
#include <linux/serial.h>
#ifdef XEN
#include <linux/efi.h>
#include <linux/errno.h>
#include <asm/io.h>
#include <asm/iosapic.h>
#include <asm/system.h>
#include <acpi/acpi.h>
#endif
#include "pcdp.h"

#ifdef XEN
extern struct ns16550_defaults ns16550_com1;
extern unsigned int ns16550_com1_gsi;
extern unsigned int ns16550_com1_polarity;
extern unsigned int ns16550_com1_trigger;

/*
 * This is kind of ugly, but older rev HCDP tables don't provide interrupt
 * polarity and trigger information.  Linux/ia64 discovers these properties
 * later via ACPI names, but we don't have that luxury in Xen/ia64.  Since
 * all future platforms should have newer PCDP tables, this should be a
 * fixed list of boxes in the field, so we can hardcode based on the model.
 */
static void __init
pcdp_hp_irq_fixup(struct pcdp *pcdp, struct pcdp_uart *uart)
{
	efi_system_table_t *systab;
	efi_config_table_t *tables;
	struct acpi_table_rsdp *rsdp = NULL;
	struct acpi_table_xsdt *xsdt;
	struct acpi_table_header *hdr;
	int i;

	if (pcdp->rev >= 3 || strcmp((char *)pcdp->oemid, "HP"))
		return;

	/*
	 * Manually walk firmware provided tables to get to the XSDT.
	 * The OEM table ID on the XSDT is the platform model string.
	 * We only care about ACPI 2.0 tables as that's all HP provides.
	 */
	systab = __va(ia64_boot_param->efi_systab);

	if (!systab || systab->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE)
		return;

	tables = __va(systab->tables);

	for (i = 0 ; i < (int)systab->nr_tables && !rsdp ; i++) {
		if (efi_guidcmp(tables[i].guid, ACPI_20_TABLE_GUID) == 0)
			rsdp =
			     (struct acpi_table_rsdp *)__va(tables[i].table);
	}

	if (!rsdp ||
	    strncmp(rsdp->signature, ACPI_SIG_RSDP, sizeof(ACPI_SIG_RSDP) - 1))
		return;

	xsdt = (struct acpi_table_xsdt *)__va(rsdp->xsdt_physical_address);
	hdr = &xsdt->header;

	if (strncmp(hdr->signature, ACPI_SIG_XSDT, sizeof(ACPI_SIG_XSDT) - 1))
		return;

	/* Sanity check; are we still looking at HP firmware tables? */
	if (strcmp(hdr->oem_id, "HP"))
		return;

	if (!strcmp(hdr->oem_table_id, "zx2000") ||
	    !strcmp(hdr->oem_table_id, "zx6000") ||
	    !strcmp(hdr->oem_table_id, "rx2600") ||
	    !strcmp(hdr->oem_table_id, "cx2600")) {

		ns16550_com1.irq = ns16550_com1_gsi = uart->gsi;
		ns16550_com1_polarity = IOSAPIC_POL_HIGH;
		ns16550_com1_trigger = IOSAPIC_EDGE;

	} else if (!strcmp(hdr->oem_table_id, "rx2620") ||
	           !strcmp(hdr->oem_table_id, "cx2620") ||
	           !strcmp(hdr->oem_table_id, "rx1600") ||
	           !strcmp(hdr->oem_table_id, "rx1620")) {

		ns16550_com1.irq = ns16550_com1_gsi = uart->gsi;
		ns16550_com1_polarity = IOSAPIC_POL_LOW;
		ns16550_com1_trigger = IOSAPIC_LEVEL;
	}
}

static void __init
setup_pcdp_irq(struct pcdp *pcdp, struct pcdp_uart *uart)
{
	/* PCDP provides full interrupt info */
	if (pcdp->rev >= 3) {
		if (uart->flags & PCDP_UART_IRQ) {
			ns16550_com1.irq = ns16550_com1_gsi = uart->gsi,
			ns16550_com1_polarity =
			               uart->flags & PCDP_UART_ACTIVE_LOW ?
		                       IOSAPIC_POL_LOW : IOSAPIC_POL_HIGH;
			ns16550_com1_trigger =
			               uart->flags & PCDP_UART_EDGE_SENSITIVE ?
		                       IOSAPIC_EDGE : IOSAPIC_LEVEL;
		}
		return;
	}

	/* HCDP support */
	if (uart->pci_func & PCDP_UART_IRQ) {
		/*
		 * HCDP tables don't provide interrupt polarity/trigger
		 * info.  If the UART is a PCI device, we know to program
		 * it as low/level.  Otherwise rely on platform hacks or
		 * default to polling (irq = 0).
		 */
		if (uart->pci_func & PCDP_UART_PCI) {
			ns16550_com1.irq = ns16550_com1_gsi = uart->gsi;
			ns16550_com1_polarity = IOSAPIC_POL_LOW;
			ns16550_com1_trigger = IOSAPIC_LEVEL;
		} else if (!strcmp((char *)pcdp->oemid, "HP"))
			pcdp_hp_irq_fixup(pcdp, uart);
	}
}

static int __init
setup_serial_console(struct pcdp_uart *uart)
{

	ns16550_com1.baud = uart->baud ? uart->baud : BAUD_AUTO;
	ns16550_com1.io_base = uart->addr.address;
	if (uart->bits)
		ns16550_com1.data_bits = uart->bits;

#ifndef XEN
	setup_pcdp_irq(efi.hcdp, uart);

	/* Hide the HCDP table from dom0, xencons will be the console */
	efi.hcdp = NULL;
#else
	setup_pcdp_irq(__va(efi.hcdp), uart);

	/* Hide the HCDP table from dom0, xencons will be the console */
	efi.hcdp = EFI_INVALID_TABLE_ADDR;
#endif

	return 0;
}

static int __init
setup_vga_console(struct pcdp_vga *vga)
{
#ifdef CONFIG_VGA
	/*
	 * There was no console= in the original cmdline, and the PCDP
	 * is telling us VGA is the primary console.  We can call
	 * cmdline_parse() manually to make things appear automagic.
	 *
	 * NB - cmdline_parse() expects the first part of the cmdline
	 * to be the image name.  So "pcdp" below is just filler.
	 */
	char *console_cmdline = "pcdp console=vga";

	cmdline_parse(console_cmdline);

	/*
	 * Leave efi.hcdp intact since dom0 will take ownership.
	 * vga=keep is handled in start_kernel().
	 */

	return 0;
#else
	return -ENODEV;
#endif
}

#else /* XEN */

static int __init
setup_serial_console(struct pcdp_uart *uart)
{
#ifdef CONFIG_SERIAL_8250_CONSOLE
	int mmio;
	static char options[64];

	mmio = (uart->addr.address_space_id == ACPI_ADR_SPACE_SYSTEM_MEMORY);
	snprintf(options, sizeof(options), "console=uart,%s,0x%lx,%lun%d",
		mmio ? "mmio" : "io", uart->addr.address, uart->baud,
		uart->bits ? uart->bits : 8);

	return early_serial_console_init(options);
#else
	return -ENODEV;
#endif
}

static int __init
setup_vga_console(struct pcdp_vga *vga)
{
#if defined(CONFIG_VT) && defined(CONFIG_VGA_CONSOLE)
	if (efi_mem_type(0xA0000) == EFI_CONVENTIONAL_MEMORY) {
		printk(KERN_ERR "PCDP: VGA selected, but frame buffer is not MMIO!\n");
		return -ENODEV;
	}

	conswitchp = &vga_con;
	printk(KERN_INFO "PCDP: VGA console\n");
	return 0;
#else
	return -ENODEV;
#endif
}
#endif /* XEN */

int __init
efi_setup_pcdp_console(char *cmdline)
{
	struct pcdp *pcdp;
	struct pcdp_uart *uart;
	struct pcdp_device *dev, *end;
	int i, serial = 0;

#ifndef XEN
	pcdp = efi.hcdp;
	if (!pcdp)
		return -ENODEV;
#else
	if (efi.hcdp == EFI_INVALID_TABLE_ADDR)
		return -ENODEV;
	pcdp = __va(efi.hcdp);
#endif

	printk(KERN_INFO "PCDP: v%d at 0x%lx\n", pcdp->rev, __pa(pcdp));

	if (strstr(cmdline, "console=hcdp")) {
		if (pcdp->rev < 3)
			serial = 1;
	} else if (strstr(cmdline, "console=")) {
		printk(KERN_INFO "Explicit \"console=\"; ignoring PCDP\n");
		return -ENODEV;
	}

	if (pcdp->rev < 3 && efi_uart_console_only())
		serial = 1;

	for (i = 0, uart = pcdp->uart; i < pcdp->num_uarts; i++, uart++) {
		if (uart->flags & PCDP_UART_PRIMARY_CONSOLE || serial) {
			if (uart->type == PCDP_CONSOLE_UART) {
				return setup_serial_console(uart);
				
			}
		}
	}

	end = (struct pcdp_device *) ((u8 *) pcdp + pcdp->length);
	for (dev = (struct pcdp_device *) (pcdp->uart + pcdp->num_uarts);
	     dev < end;
	     dev = (struct pcdp_device *) ((u8 *) dev + dev->length)) {
		if (dev->flags & PCDP_PRIMARY_CONSOLE) {
			if (dev->type == PCDP_CONSOLE_VGA) {
				return setup_vga_console((struct pcdp_vga *) dev);
			}
		}
	}

	return -ENODEV;
}
