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

#ifdef EARLY_UART_ADDRESS

static void __init early_putch(char c)
{
    volatile uint32_t *r;

    r = (uint32_t *)((EARLY_UART_ADDRESS & 0x001fffff)
                     + XEN_VIRT_START + (1 << 21));

    /* XXX: assuming a PL011 UART. */
    while(*(r + 0x6) & 0x8)
        ;
    *r = c;
}

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
    char buf[80];

    vsnprintf(buf, sizeof(buf), fmt, args);
    early_puts(buf);
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

    while(1);
}

#endif /* #ifdef EARLY_UART_ADDRESS */
