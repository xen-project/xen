/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/init.h>
#include <asm/boot.h>

static void __initdata (*putchar_func)(char);

void __init early_printk_init(void (*putchar)(char))
{
    putchar_func = putchar;
}

void __init early_puts(const char *s, size_t nr)
{
    if ( !putchar_func )
        return;

    while ( nr-- > 0 )
        putchar_func(*s++);
}

void __init early_printk(const char *s)
{
    if ( !putchar_func )
        return;

    while ( *s )
        putchar_func(*s++);
}
