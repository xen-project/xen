/*
 * C-Brick Serial Port (and console) driver for SGI Altix machines.
 *
 * Copyright (c) 2005 Silicon Graphics, Inc.  All Rights Reserved.
 */

#include <xen/lib.h>
#include <asm/acpi.h>
#include <asm/sn/sn_sal.h>
#include <xen/serial.h>

void sn_putc(struct serial_port *, char);

static struct uart_driver sn_sal_console = {
	.putc = sn_putc,
};

/**
 * early_sn_setup - early setup routine for SN platforms
 *
 * pulled from arch/ia64/sn/kernel/setup.c
 */
static void __init early_sn_setup(void)
{
	efi_system_table_t *efi_systab;
	efi_config_table_t *config_tables;
	struct ia64_sal_systab *sal_systab;
	struct ia64_sal_desc_entry_point *ep;
	char *p;
	int i, j;

	/*
	 * Parse enough of the SAL tables to locate the SAL entry point. Since, console
	 * IO on SN2 is done via SAL calls, early_printk won't work without this.
	 *
	 * This code duplicates some of the ACPI table parsing that is in efi.c & sal.c.
	 * Any changes to those file may have to be made hereas well.
	 */
	efi_systab = (efi_system_table_t *) __va(ia64_boot_param->efi_systab);
	config_tables = __va(efi_systab->tables);
	for (i = 0; i < efi_systab->nr_tables; i++) {
		if (efi_guidcmp(config_tables[i].guid, SAL_SYSTEM_TABLE_GUID) ==
		    0) {
			sal_systab = __va(config_tables[i].table);
			p = (char *)(sal_systab + 1);
			for (j = 0; j < sal_systab->entry_count; j++) {
				if (*p == SAL_DESC_ENTRY_POINT) {
					ep = (struct ia64_sal_desc_entry_point
					      *)p;
					ia64_sal_handler_init(__va
							      (ep->sal_proc),
							      __va(ep->gp));
					return;
				}
				p += SAL_DESC_SIZE(*p);
			}
		}
	}
	/* Uh-oh, SAL not available?? */
	printk(KERN_ERR "failed to find SAL entry point\n");
}

/**
 * sn_serial_console_early_setup - Sets up early console output support
 *
 * pulled from drivers/serial/sn_console.c
 */
int __init sn_serial_console_early_setup(void)
{
	if (strcmp("sn2",acpi_get_sysname()))
		return -1;

	early_sn_setup();	/* Find SAL entry points */
	serial_register_uart(0, &sn_sal_console, NULL);

	return 0;
}

/*
 * sn_putc - Send a character to the console, polled or interrupt mode
 */
void sn_putc(struct serial_port *port, char c)
{
	return ia64_sn_console_putc(c);
}
