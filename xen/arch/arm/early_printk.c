/*
 * printk() for use before the final page tables are setup.
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/stdarg.h>
#include <xen/string.h>
#include <asm/early_printk.h>

void early_putch(char c);
void early_flush(void);

/* Early printk buffer */
static char __initdata buf[512];

static void __init early_puts(const char *s)
{
    while (*s != '\0') {
        if (*s == '\n')
            early_putch('\r');
        early_putch(*s);
        s++;
    }
}

static void __init early_vprintk(const char *fmt, va_list args)
{
    vsnprintf(buf, sizeof(buf), fmt, args);
    early_puts(buf);

    /*
     * Wait the UART has finished to transfer all characters before
     * to continue. This will avoid lost characters if Xen abort.
     */
    early_flush();
}

void __init early_printk(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    early_vprintk(fmt, args);
    va_end(args);
}

void __attribute__((noreturn)) __init
early_panic(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    early_vprintk(fmt, args);
    va_end(args);

    early_printk("\n\nEarly Panic: Stopping\n");

    while(1);
}
