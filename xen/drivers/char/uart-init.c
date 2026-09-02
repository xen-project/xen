/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Derived from:
 * xen/drivers/char/arm-uart.c
 *
 * Generic uart retrieved via the device tree or ACPI
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2013 Linaro Limited.
 */

#include <asm/device.h>

#include <xen/console.h>
#include <xen/device_tree.h>
#include <xen/param.h>
#include <xen/serial.h>
#include <xen/errno.h>
#include <xen/acpi.h>

/*
 * Configure UART port with a string:
 * path:options
 *
 * @path: full path used in the device tree for the UART. If the path
 * doesn't start with '/', we assuming that it's an alias.
 * @options: UART speficic options (see in each UART driver)
 */
static char __initdata opt_dtuart[256] = "";
string_param("dtuart", opt_dtuart);

static int __init dt_uart_init(void)
{
    struct dt_device_node *dev;
    int ret;
    const char *devpath = opt_dtuart;
    const char *options;
    char *split;
    /* Set on the command line, as opposed to inherited from /chosen */
    bool explicit_request = strcmp(opt_dtuart, "") != 0;

    if ( !explicit_request )
    {
        const struct dt_device_node *chosen = dt_find_node_by_path("/chosen");

        if ( chosen )
        {
            const char *stdout;

            ret = dt_property_read_string(chosen, "stdout-path", &stdout);
            if ( ret >= 0 )
            {
                printk("Taking dtuart configuration from /chosen/stdout-path\n");
                if ( strlcpy(opt_dtuart, stdout, sizeof(opt_dtuart))
                     >= sizeof(opt_dtuart) )
                    printk("WARNING: /chosen/stdout-path too long, truncated\n");
            }
            else if ( ret != -EINVAL /* Not present */ )
                printk("Failed to read /chosen/stdout-path (%d)\n", ret);
        }
    }

    if ( !strcmp(opt_dtuart, "") )
    {
        printk("No dtuart path configured\n");

        /*
         * console=dtuart is the compiled-in default, so an absent dtuart= is
         * not a failed user request.
         */
        return 0;
    }

    split = strchr(opt_dtuart, ':');
    if ( split )
    {
        split[0] = '\0';
        options = split + 1;
    }
    else
        options = "";

    printk("Looking for dtuart at \"%s\", options \"%s\"\n", devpath, options);
    if ( *devpath == '/' )
        dev = dt_find_node_by_path(devpath);
    else
        dev = dt_find_node_by_alias(devpath);

    if ( !dev )
    {
        printk("Unable to find device \"%s\"\n", devpath);
        return explicit_request ? -ENODEV : 0;
    }

    ret = device_init(dev, DEVICE_SERIAL, options);
    if ( ret )
        printk("Unable to initialize dtuart: %d\n", ret);

    return explicit_request ? ret : 0;
}

#ifdef CONFIG_ACPI
static int __init acpi_uart_init(void)
{
    struct acpi_table_spcr *spcr;
    acpi_status status;
    int ret;

    /* SPCR is firmware provided, so nothing here is a failed user request */
    status = acpi_get_table(ACPI_SIG_SPCR, 0,
                            (struct acpi_table_header **)&spcr);

    if ( ACPI_FAILURE(status) )
    {
        printk("Unable to get spcr table\n");
        return 0;
    }

    ret = acpi_device_init(DEVICE_SERIAL, NULL, spcr->interface_type);
    if ( ret )
        printk("Unable to initialize acpi uart: %d\n", ret);

    return 0;
}
#else
static int __init acpi_uart_init(void) { return 0; }
#endif

int __init uart_init(void)
{
    if ( !console_has("dtuart") )
        return 0; /* Not for us */

    return acpi_disabled ? dt_uart_init() : acpi_uart_init();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
