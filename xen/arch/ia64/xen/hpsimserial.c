/*
 * HP Ski simulator serial I/O
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include "hpsim_ssc.h"

static void hp_ski_putc(struct serial_port *port, char c)
{
	ia64_ssc(c,0,0,0,SSC_PUTCHAR);
}

static struct uart_driver hp_ski = { .putc = hp_ski_putc };

void hpsim_serial_init(void)
{
	serial_register_uart(0, &hp_ski, 0);
}
