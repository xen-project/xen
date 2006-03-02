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
#include <linux/errno.h>
#endif
#include "pcdp.h"

static int __init
setup_serial_console(struct pcdp_uart *uart)
{
#ifdef XEN
	extern struct ns16550_defaults ns16550_com1;
	ns16550_com1.baud = uart->baud;
	ns16550_com1.io_base = uart->addr.address;
	if (uart->bits)
		ns16550_com1.data_bits = uart->bits;
	return 0;
#else
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
#endif
}

#ifndef XEN
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
#endif

int __init
efi_setup_pcdp_console(char *cmdline)
{
	struct pcdp *pcdp;
	struct pcdp_uart *uart;
#ifndef XEN
	struct pcdp_device *dev, *end;
#endif
	int i, serial = 0;

	pcdp = efi.hcdp;
	if (!pcdp)
		return -ENODEV;

#ifndef XEN
	printk(KERN_INFO "PCDP: v%d at 0x%lx\n", pcdp->rev, __pa(pcdp));
#endif

	if (strstr(cmdline, "console=hcdp")) {
		if (pcdp->rev < 3)
			serial = 1;
	} else if (strstr(cmdline, "console=")) {
#ifndef XEN
		printk(KERN_INFO "Explicit \"console=\"; ignoring PCDP\n");
#endif
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

#ifndef XEN
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
#endif

	return -ENODEV;
}
