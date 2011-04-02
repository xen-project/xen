/*
 * C-Brick Serial Port (and console) driver for SGI Altix machines.
 *
 * Copyright (c) 2005 Silicon Graphics, Inc.  All Rights Reserved.
 */

#include <xen/lib.h>
#include <asm/acpi.h>
#include <asm/sn/sn_sal.h>
#include <xen/serial.h>
#include <xen/sched.h>

struct sn_console_data {
	struct timer timer;
	unsigned int timeout_ms;
	int booted;
};

static struct sn_console_data console_data = {
	.timeout_ms = 8 * 16 * 1000 / 9600,
};


/*
 * sn_putc - Send a character to the console, polled or interrupt mode
 */
static void sn_putc(struct serial_port *port, char c)
{
	struct sn_console_data *sndata = port->uart;

	if (sndata->booted)
		ia64_sn_console_putb(&c, 1);
	else
		ia64_sn_console_putc(c);
}

/*
 * sn_getc - Get a character from the console, polled or interrupt mode
 */
static int sn_getc(struct serial_port *port, char *pc)
{
	int ch;

	ia64_sn_console_getc(&ch);
	*pc = ch & 0xff;
	return 1;
}

static void __init sn_endboot(struct serial_port *port)
{
	struct sn_console_data *sndata = port->uart;

	sndata->booted = 1;
}


static void sn_poll(void *data)
{
	int ch, status;
	struct serial_port *port = data;
	struct sn_console_data *sndata = port->uart;
	struct cpu_user_regs *regs = guest_cpu_user_regs();

	status = ia64_sn_console_check(&ch);
	if (!status && ch) {
		serial_rx_interrupt(port, regs);
	}
	set_timer(&sndata->timer, NOW() + MILLISECS(sndata->timeout_ms));
}


static void __init sn_init_postirq(struct serial_port *port)
{
	struct sn_console_data *sndata = port->uart;

        init_timer(&sndata->timer, sn_poll, port, 0);
        set_timer(&sndata->timer, NOW() + MILLISECS(console_data.timeout_ms));
}

static void sn_resume(struct serial_port *port)
{
	struct sn_console_data *sndata = port->uart;

	set_timer(&sndata->timer, NOW() + MILLISECS(console_data.timeout_ms));
}

static struct uart_driver sn_sal_console = {
	.init_postirq = sn_init_postirq,
	.resume = sn_resume,
	.putc = sn_putc,
	.getc = sn_getc,
	.endboot = sn_endboot,
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
		if (!efi_guidcmp(config_tables[i].guid, SAL_SYSTEM_TABLE_GUID)) {
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
	if (strcmp("sn2", acpi_get_sysname()))
		return -1;

	early_sn_setup();	/* Find SAL entry points */
	serial_register_uart(0, &sn_sal_console, &console_data);

	return 0;
}
