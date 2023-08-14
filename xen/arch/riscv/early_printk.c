/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RISC-V early printk using SBI
 *
 * Copyright (C) 2021 Bobby Eshleman <bobbyeshleman@gmail.com>
 */
#include <asm/early_printk.h>
#include <asm/sbi.h>

/*
 * When the MMU is off during early boot, any C function called has to
 * use PC-relative rather than absolute address because the physical address
 * may not match the virtual address.
 *
 * To guarantee PC-relative address cmodel=medany should be used
 */
#ifndef __riscv_cmodel_medany
#error "early_*() can be called from head.S with MMU-off"
#endif

/*
 * TODO:
 *   sbi_console_putchar is already planned for deprecation
 *   so it should be reworked to use UART directly.
*/
void early_puts(const char *s, size_t nr)
{
    while ( nr-- > 0 )
    {
        sbi_console_putchar(*s);
        s++;
    }
}

void early_printk(const char *str)
{
    while ( *str )
    {
        early_puts(str, 1);
        str++;
    }
}

/*
 * The following #if 1 ... #endif should be removed after printk
 * and related stuff are ready.
 */
#if 1

#include <xen/stdarg.h>
#include <xen/string.h>

/**
 * strlen - Find the length of a string
 * @s: The string to be sized
 */
size_t (strlen)(const char * s)
{
    const char *sc;

    for (sc = s; *sc != '\0'; ++sc)
        /* nothing */;
    return sc - s;
}

/**
 * memcpy - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @count: The size of the area.
 *
 * You should not use this function to access IO space, use memcpy_toio()
 * or memcpy_fromio() instead.
 */
void *(memcpy)(void *dest, const void *src, size_t count)
{
    char *tmp = (char *) dest, *s = (char *) src;

    while (count--)
        *tmp++ = *s++;

    return dest;
}

int vsnprintf(char* str, size_t size, const char* format, va_list args)
{
    size_t i = 0; /* Current position in the output string */
    size_t written = 0; /* Total number of characters written */
    char* dest = str;

    while ( format[i] != '\0' && written < size - 1 )
    {
        if ( format[i] == '%' )
        {
            i++;

            if ( format[i] == '\0' )
                break;

            if ( format[i] == '%' )
            {
                if ( written < size - 1 )
                {
                    dest[written] = '%';
                    written++;
                }
                i++;
                continue;
            }

            /*
             * Handle format specifiers.
             * For simplicity, only %s and %d are implemented here.
             */

            if ( format[i] == 's' )
            {
                char* arg = va_arg(args, char*);
                size_t arglen = strlen(arg);

                size_t remaining = size - written - 1;

                if ( arglen > remaining )
                    arglen = remaining;

                memcpy(dest + written, arg, arglen);

                written += arglen;
                i++;
            }
            else if ( format[i] == 'd' )
            {
                int arg = va_arg(args, int);

                /* Convert the integer to string representation */
                char numstr[32]; /* Assumes a maximum of 32 digits */
                int numlen = 0;
                int num = arg;
                size_t remaining;

                if ( arg < 0 )
                {
                    if ( written < size - 1 )
                    {
                        dest[written] = '-';
                        written++;
                    }

                    num = -arg;
                }

                do
                {
                    numstr[numlen] = '0' + num % 10;
                    num = num / 10;
                    numlen++;
                } while ( num > 0 );

                /* Reverse the string */
                for (int j = 0; j < numlen / 2; j++)
                {
                    char tmp = numstr[j];
                    numstr[j] = numstr[numlen - 1 - j];
                    numstr[numlen - 1 - j] = tmp;
                }

                remaining = size - written - 1;

                if ( numlen > remaining )
                    numlen = remaining;

                memcpy(dest + written, numstr, numlen);

                written += numlen;
                i++;
            }
        }
        else
        {
            if ( written < size - 1 )
            {
                dest[written] = format[i];
                written++;
            }
            i++;
        }
    }

    if ( size > 0 )
        dest[written] = '\0';

    return written;
}

void printk(const char *format, ...)
{
    static char buf[1024];

    va_list args;
    va_start(args, format);

    (void)vsnprintf(buf, sizeof(buf), format, args);

    early_printk(buf);

    va_end(args);
}

#endif

