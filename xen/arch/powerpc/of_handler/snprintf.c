/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/types.h>
#include <stdarg.h>

#define UPPER   0x00001
#define SIGNED  0x00010
#define ZERO    0x00100
#define PTR 0x01000

#define NUMBUFSZ 24     /* fits a 64bit value formatted in octal */

/* do we need to handle 128 bits? */
static ulong
digits(char *buf, uint64_t val, ulong radix, ulong width, ulong flgs)
{
    const char hex[] = "0123456789abcdefx";
    const char Hex[] = "0123456789ABCDEFX";
    const char *dig;
    char *b = buf;
    char num[NUMBUFSZ];
    ulong i;

    if (radix == 0 || radix > 16) {
        radix = 16;
    }
    
    if (flgs & UPPER) {
        dig = Hex;
    } else {
        dig = hex;
    }
    
    /* sign */
    if (flgs & SIGNED && radix == 10) {
        /* there are corner cases here, for sure */
        if ((int64_t)val < 0) {
            *b++ = '-';
            val *= -1;
        }
    }

    /* ptr */
    if (flgs & PTR && radix == 16) {
        *b++ = '0';
        *b++ = dig[16];
    }

    /* put it in t backwards */
    i = 0;
    if (val == 0) {
        num[i++] = '0';
    } else {
        while (val > 0) {
            num[i++] = dig[val % radix];
            val /= radix;
        }
    }

    /* pad */
    if (flgs & ZERO && width > i) {
        while (width-- > i) {
            *b++ = '0';
        }
    }

    /* number */
    while (i-- > 0) {
        *b++ = num[i];
    }

    return (b - buf);
}

/*
 * yeah, I dislike goto's too, but ...
 */
int
vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    int c;
    int nullify;
    ulong used = 0;
    ulong sz;
    unsigned ells;
    ulong flgs;
    const char *str;
    uint64_t val = 0;
    ulong radix;
    ulong width;
    char num[NUMBUFSZ];

    /* there must always be a trailing null */
    if (size == 0) {
        /* but don't write anything is size is zero */
        nullify = 0;
    } else {
        --size;
        nullify = 1;
    }

    while ((c = *fmt++) != '\0') {
        if (c != '%') {
            if (used++ < size) {
                *buf++ = c;
            }
            continue;
        }
        /* deal with format */
        ells = 0;
        flgs = 0;

        /* check for a given width */
        width = 0;
        
        c = *fmt;
        if (c >= '0' && c <= '9') {
            flgs |= ZERO;
            ++fmt;
            while (c >= '0' && c <= '9') {
                width = (width * 10) + (c - '0');
                c = *fmt++;
            }
            --fmt;
        }
        
loop:
        c = *fmt++;
        switch (c) {
        case 'l':
            ++ells;
            goto loop;
            /*NOTREACHED*/
            break;

        case 'h':   /* support linux kernel 'h'  for short */
            ells = 0;
            goto loop;
            /*NOTREACHED*/
            break;

        case 'L':   /* support linux kernel 'L'  for long long */
            ells = 2;
            goto loop;
            /*NOTREACHED*/
            break;

        case 'Z':   /* support linux kernel 'Z'  for [s]size_t */
            /* I think it is safe to assume that 'long'
             * just gets it right but, the compiler should
             * do the right thing here anyway */
            if (sizeof (size_t) > sizeof (unsigned)) {
                ells = 1;
            }
            goto loop;
            /*NOTREACHED*/
            break;
        case 's':
            str = va_arg(ap, char *);
            if (str == NULL) {
                str = "(nil)";
            }

            /* copy over only what fits */
            sz = 0;
            while (*str != '\0') {
                c = *str++;
                if (used++ < size) {
                    *buf++ = c;
                }
            }
            break;
        case 'c':
            c = (char)va_arg(ap, int);
            /*FALLTHRU*/
        case '%':
            if (used++ < size) {
                *buf++ = c;
            }
            break;

        case 'n':
            /* totally untested */
            switch (ells) {
            case 0: {
                unsigned *pval = va_arg(ap, unsigned *);
                *pval = used;
            }
                break;
            case 1: {
                unsigned long *pval;
                pval = va_arg(ap, unsigned long *);
                *pval = used;
            }
                break;
            default: {
                unsigned long long *pval;
                pval = va_arg(ap, unsigned long long *);
                *pval = used;
            }
                break;
            }
            
            break;
        case 'p':
            flgs |= (PTR | ZERO);
            radix = 16;
            val = (unsigned long) va_arg(ap, void *);
            /* pad to max type by default */
            if (sizeof (long) == sizeof (long long)) {
                width = 16;
            } else {
                width = 8;
            }
            goto print_value;

        case 'd': case 'i':
            flgs |= SIGNED;
            radix = 10;
            switch (ells) {
            case 0:
                val = va_arg(ap, int);
                break;
            case 1:
                val = va_arg(ap, long);
                break;
            default:
                val = va_arg(ap, long long);
                break;
            }
            goto print_value;

        case 'u':
            radix = 10;
            goto print_ulongue;
            break;

        case 'o':
            radix = 8;
            goto print_ulongue;
            break;

        case 'X':
            flgs |= UPPER;
            /*FALLTHRU*/
        case 'x':
            radix = 16;
print_ulongue:
            switch (ells) {
            case 0:
                val = va_arg(ap, unsigned);
                break;
            case 1:
                val = va_arg(ap, unsigned long);
                break;
            default:
                val = va_arg(ap, unsigned long long);
                break;
            }

print_value:
            /* get the number */
            sz = digits(num, val, radix, width, flgs);

            str = num;
            while (sz-- > 0) {
                c = *str++;
                if (used++ < size) {
                    *buf++ = c;
                }
            }
            break;
            
            
        default:
            break;
        }
    }
    if (nullify) {
        /* stuff a nul char but don't include it in return */
        *buf++ = '\0';
    }
    return used;
}

int
snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    signed int ret;

    va_start(ap, fmt);
    ret = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return ret;
}

int
vsprintf(char *buf, const char *fmt, va_list ap)
{
    return vsnprintf(buf, ~0UL, fmt, ap);
}

int
sprintf(char *buf, const char *fmt, ...)
{
    va_list ap;
    signed int ret;

    va_start(ap, fmt);
    ret = vsprintf(buf, fmt, ap);
    va_end(ap);
    return ret;
}
