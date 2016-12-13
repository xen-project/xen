/*
 * util.c: Helper library functions for HVMLoader.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdarg.h>
#include <stdint.h>
#include "rombios_compat.h"
#include "util.h"

static void putchar(char c);
#define isdigit(c) ((c) >= '0' && (c) <= '9')

void outb(uint16_t addr, uint8_t val)
{
    __asm__ __volatile__ ( "outb %%al, %%dx" :: "d"(addr), "a"(val) );
}

void outw(uint16_t addr, uint16_t val)
{
    __asm__ __volatile__ ( "outw %%ax, %%dx" :: "d"(addr), "a"(val) );
}

void outl(uint16_t addr, uint32_t val)
{
    __asm__ __volatile__ ( "outl %%eax, %%dx" :: "d"(addr), "a"(val) );
}

uint8_t inb(uint16_t addr)
{
    uint8_t val;
    __asm__ __volatile__ ( "inb %%dx,%%al" : "=a" (val) : "d" (addr) );
    return val;
}

uint16_t inw(uint16_t addr)
{
    uint16_t val;
    __asm__ __volatile__ ( "inw %%dx,%%ax" : "=a" (val) : "d" (addr) );
    return val;
}

uint32_t inl(uint16_t addr)
{
    uint32_t val;
    __asm__ __volatile__ ( "inl %%dx,%%eax" : "=a" (val) : "d" (addr) );
    return val;
}

char *itoa(char *a, unsigned int i)
{
    unsigned int _i = i, x = 0;

    do {
        x++;
        _i /= 10;
    } while ( _i != 0 );

    a += x;
    *a-- = '\0';

    do {
        *a-- = (i % 10) + '0';
        i /= 10;
    } while ( i != 0 );

    return a + 1;
}

int strcmp(const char *cs, const char *ct)
{
    signed char res;

    while ( ((res = *cs - *ct++) == 0) && (*cs++ != '\0') )
        continue;

    return res;
}

int strncmp(const char *s1, const char *s2, uint32_t n)
{
    uint32_t ctr;
    for (ctr = 0; ctr < n; ctr++)
        if (s1[ctr] != s2[ctr])
            return (int)(s1[ctr] - s2[ctr]);
    return 0;
}

void *memcpy(void *dest, const void *src, unsigned n)
{
    int t0, t1, t2;

    __asm__ __volatile__ (
        "cld\n"
        "rep; movsl\n"
        "testb $2,%b4\n"
        "je 1f\n"
        "movsw\n"
        "1: testb $1,%b4\n"
        "je 2f\n"
        "movsb\n"
        "2:"
        : "=&c" (t0), "=&D" (t1), "=&S" (t2)
        : "0" (n/4), "q" (n), "1" ((long) dest), "2" ((long) src)
        : "memory" );
    return dest;
}

void *memmove(void *dest, const void *src, unsigned n)
{
    if ( (long)dest > (long)src )
    {
        n--;
        while ( n > 0 )
        {
            ((char *)dest)[n] = ((char *)src)[n];
            n--;
        }
    }
    else
    {
        memcpy(dest, src, n);
    }
    return dest;
}

char *
strcpy(char *dest, const char *src)
{
    char *p = dest;
    while ( *src )
        *p++ = *src++;
    *p = 0;
    return dest;
}

char *
strncpy(char *dest, const char *src, unsigned n)
{
    int i = 0;
    char *p = dest;

    /* write non-NUL characters from src into dest until we run
       out of room in dest or encounter a NUL in src */
    while ( (i < n) && *src )
    {
        *p++ = *src++;
        i++;
    }

    /* pad remaining bytes of dest with NUL bytes */
    while ( i < n )
    {
        *p++ = 0;
        i++;
    }

    return dest;
}

unsigned
strlen(const char *s)
{
    int i = 0;
    while ( *s++ )
        i++;
    return i;
}

void *
memset(void *s, int c, unsigned n)
{
    uint8_t b = (uint8_t) c;
    uint8_t *p = (uint8_t *)s;
    int i;
    for ( i = 0; i < n; i++ )
        *p++ = b;
    return s;
}

int
memcmp(const void *s1, const void *s2, unsigned n)
{
    unsigned i;
    uint8_t *p1 = (uint8_t *) s1;
    uint8_t *p2 = (uint8_t *) s2;

    for ( i = 0; i < n; i++ )
    {
        if ( p1[i] < p2[i] )
            return -1;
        else if ( p1[i] > p2[i] )
            return 1;
    }

    return 0;
}

void
cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    __asm__ __volatile__ (
        "cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "0" (idx) );
}

/* Write a two-character hex representation of 'byte' to digits[].
   Pre-condition: sizeof(digits) >= 2 */
void
byte_to_hex(char *digits, uint8_t byte)
{
    uint8_t nybbel = byte >> 4;

    if ( nybbel > 9 )
        digits[0] = 'a' + nybbel-10;
    else
        digits[0] = '0' + nybbel;

    nybbel = byte & 0x0f;
    if ( nybbel > 9 )
        digits[1] = 'a' + nybbel-10;
    else
        digits[1] = '0' + nybbel;
}

/* Convert an array of 16 unsigned bytes to a DCE/OSF formatted UUID
   string.

   Pre-condition: sizeof(dest) >= 37 */
void
uuid_to_string(char *dest, uint8_t *uuid)
{
    int i = 0;
    char *p = dest;

    for ( i = 0; i < 4; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 4; i < 6; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 6; i < 8; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 8; i < 10; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 10; i < 16; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p = '\0';
}

static char *printnum(char *p, unsigned long num, int base)
{
    unsigned long n;

    if ( (n = num/base) > 0 )
        p = printnum(p, n, base);
    *p++ = "0123456789abcdef"[(int)(num % base)];
    *p = '\0';
    return p;
}

static void _doprint(void (*put)(char), const char *fmt, va_list ap)
{
    register char *str, c;
    int lflag, zflag, nflag;
    char buffer[17];
    unsigned value;
    int i, slen, pad;

    for ( ; *fmt != '\0'; fmt++ )
    {
        if ( *fmt != '%' )
        {
            put(*fmt);
            continue;
        }

        pad = zflag = nflag = lflag = 0;
        c = *++fmt;
        if ( (c == '-') || isdigit(c) )
        {
            if ( c == '-' )
            {
                nflag = 1;
                c = *++fmt;
            }
            zflag = c == '0';
            for ( pad = 0; isdigit(c); c = *++fmt )
                pad = (pad * 10) + c - '0';
        }
        if ( c == 'l' ) /* long extension */
        {
            lflag = 1;
            c = *++fmt;
        }
        if ( (c == 'd') || (c == 'u') || (c == 'o') || (c == 'x') )
        {
            if ( lflag )
                value = va_arg(ap, unsigned);
            else
                value = (unsigned) va_arg(ap, unsigned int);
            str = buffer;
            printnum(str, value,
                     c == 'o' ? 8 : (c == 'x' ? 16 : 10));
            goto printn;
        }
        else if ( (c == 'O') || (c == 'D') || (c == 'X') )
        {
            value = va_arg(ap, unsigned);
            str = buffer;
            printnum(str, value,
                     c == 'O' ? 8 : (c == 'X' ? 16 : 10));
        printn:
            slen = strlen(str);
            for ( i = pad - slen; i > 0; i-- )
                put(zflag ? '0' : ' ');
            while ( *str )
                put(*str++);
        }
        else if ( c == 's' )
        {
            str = va_arg(ap, char *);
            slen = strlen(str);
            if ( nflag == 0 )
                for ( i = pad - slen; i > 0; i-- )
                    put(' ');
            while ( *str )
                put(*str++);
            if ( nflag )
                for ( i = pad - slen; i > 0; i-- )
                    put(' ');
        }
        else if ( c == 'c' )
        {
            put(va_arg(ap, int));
        }
        else
        {
            put(*fmt);
        }
    }
}

static void putchar(char c)
{
    outb(0xe9, c);
}

int printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _doprint(putchar, fmt, ap);
    va_end(ap);

    return 0;
}

void mssleep(uint32_t waittime)
{
    uint32_t i;
    uint8_t  x, y = inb(0x61) & 0x10;

    /* Poll the DRAM refresh timer: I/O port 61h, bit 4 toggles every 15us. */
    waittime *= 67; /* Convert milliseconds to multiples of 15us. */
    for ( i = 0; i < waittime; i++ )
    {
        while ( (x = inb(0x61) & 0x10) == y )
            continue;
        y = x;
    }
}

/*
 * Search for the RSDP ACPI table in the memory starting at addr and
 * ending at addr + len - 1.
 */
static struct acpi_20_rsdp *__find_rsdp(const void *start, unsigned int len)
{
    char *rsdp = (char *)start;
    char *end = rsdp + len;
    /* scan memory in steps of 16 bytes */
    while (rsdp < end) {
        /* check for expected string */
        if (!strncmp(rsdp, "RSD PTR ", 8))
            return (struct acpi_20_rsdp *)rsdp;
        rsdp += 0x10;
    }
    return 0;
}

struct acpi_20_rsdp *find_rsdp(void)
{
    struct acpi_20_rsdp *rsdp;
    uint16_t ebda_seg;

    ebda_seg = *(uint16_t *)ADDR_FROM_SEG_OFF(0x40, 0xe);
    rsdp = __find_rsdp((void *)(ebda_seg << 16), 1024);
    if (!rsdp)
        rsdp = __find_rsdp((void *)0xE0000, 0x20000);

    return rsdp;
}

uint32_t get_s3_waking_vector(void)
{
    struct acpi_20_rsdp *rsdp = find_rsdp();
    struct acpi_20_xsdt *xsdt;
    struct acpi_fadt *fadt;
    struct acpi_20_facs *facs;
    uint32_t vector;

    if (!rsdp)
        return 0;

    xsdt = (struct acpi_20_xsdt *)(long)rsdp->xsdt_address;
    if (!xsdt)
        return 0;

    fadt = (struct acpi_fadt *)(long)xsdt->entry[0];
    if (!fadt || (fadt->header.signature != ACPI_FADT_SIGNATURE))
        return 0;

    facs = (struct acpi_20_facs *)(long)fadt->x_firmware_ctrl;
    if (!facs)
        return 0;

    vector = facs->x_firmware_waking_vector;
    if (!vector)
        vector = facs->firmware_waking_vector;

    return vector;
}
