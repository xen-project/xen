/*
 *	Machine specific setup for generic
 */

#include <linux/config.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <asm/acpi.h>
#include <asm/arch_hooks.h>

#ifdef CONFIG_HOTPLUG_CPU
#define DEFAULT_SEND_IPI	(1)
#else
#define DEFAULT_SEND_IPI	(0)
#endif

int no_broadcast=DEFAULT_SEND_IPI;

static __init int no_ipi_broadcast(char *str)
{
	get_option(&str, &no_broadcast);
	printk ("Using %s mode\n", no_broadcast ? "No IPI Broadcast" :
											"IPI Broadcast");
	return 1;
}

__setup("no_ipi_broadcast", no_ipi_broadcast);

static int __init print_ipi_mode(void)
{
	printk ("Using IPI %s mode\n", no_broadcast ? "No-Shortcut" :
											"Shortcut");
	return 0;
}

late_initcall(print_ipi_mode);
