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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "util.h"
#include "config.h"
#include <stdint.h>
#include <xenctrl.h>
#include <xen/hvm/hvm_info_table.h>

void outb(uint16_t addr, uint8_t val)
{
    __asm__ __volatile__ ( "outb %%al, %%dx" : : "d" (addr), "a" (val) );
}

void outw(uint16_t addr, uint16_t val)
{
    __asm__ __volatile__ ( "outw %%ax, %%dx" : : "d" (addr), "a" (val) );
}

void outl(uint16_t addr, uint32_t val)
{
    __asm__ __volatile__ ( "outl %%eax, %%dx" : : "d" (addr), "a" (val) );
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

uint8_t cmos_inb(uint8_t idx)
{
    outb(0x70, idx);
    return inb(0x71);
}

void cmos_outb(uint8_t idx, uint8_t val)
{
    outb(0x70, idx);
    outb(0x71, val);
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
    if ( (unsigned long)dest > (unsigned long)src )
        while ( n-- != 0 )
            ((char *)dest)[n] = ((char *)src)[n];
    else
        memcpy(dest, src, n);
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

static void e820_collapse(void)
{
    int i = 0;
    struct e820entry *ent = (struct e820entry *)E820_MAP;

    while ( i < (*E820_MAP_NR-1) )
    {
        if ( (ent[i].type == ent[i+1].type) &&
             ((ent[i].addr + ent[i].size) == ent[i+1].addr) )
        {
            ent[i].size += ent[i+1].size;
            memcpy(&ent[i+1], &ent[i+2], (*E820_MAP_NR-i-2) * sizeof(*ent));
            (*E820_MAP_NR)--;
        }
        else
        {
            i++;
        }
    }
}

uint32_t e820_malloc(uint32_t size)
{
    uint32_t addr;
    int i;
    struct e820entry *ent = (struct e820entry *)E820_MAP;

    /* Align allocation request to a reasonable boundary (1kB). */
    size = (size + 1023) & ~1023;

    for ( i = *E820_MAP_NR - 1; i >= 0; i-- )
    {
        addr = ent[i].addr;
        if ( (ent[i].type != E820_RAM) || /* not ram? */
             (ent[i].size < size) ||      /* too small? */
             (addr != ent[i].addr) ||     /* starts above 4gb? */
             ((addr + size) < addr) )     /* ends above 4gb? */
            continue;

        if ( ent[i].size != size )
        {
            memmove(&ent[i+1], &ent[i], (*E820_MAP_NR-i) * sizeof(*ent));
            (*E820_MAP_NR)++;
            ent[i].size -= size;
            addr += ent[i].size;
            i++;
        }

        ent[i].addr = addr;
        ent[i].size = size;
        ent[i].type = E820_RESERVED;

        e820_collapse();

        return addr;
    }

    return 0;
}

uint32_t ioapic_read(uint32_t reg)
{
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x00) = reg;
    return *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x10);
}

void ioapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x00) = reg;
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x10) = val;
}

uint32_t lapic_read(uint32_t reg)
{
    return *(volatile uint32_t *)(LAPIC_BASE_ADDRESS + reg);
}

void lapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(LAPIC_BASE_ADDRESS + reg) = val;
}

#define PCI_CONF1_ADDRESS(bus, devfn, reg) \
    (0x80000000 | (bus << 16) | (devfn << 8) | (reg & ~3))

uint32_t pci_read(uint32_t devfn, uint32_t reg, uint32_t len)
{
    outl(0xcf8, PCI_CONF1_ADDRESS(0, devfn, reg));

    switch ( len )
    {
    case 1: return inb(0xcfc + (reg & 3));
    case 2: return inw(0xcfc + (reg & 2));
    }

    return inl(0xcfc);
}

void pci_write(uint32_t devfn, uint32_t reg, uint32_t len, uint32_t val)
{
    outl(0xcf8, PCI_CONF1_ADDRESS(0, devfn, reg));

    switch ( len )
    {
    case 1: outb(0xcfc + (reg & 3), val); break;
    case 2: outw(0xcfc + (reg & 2), val); break;
    case 4: outl(0xcfc,             val); break;
    }
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

static void _doprint(void (*put)(char), char const *fmt, va_list ap)
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

int vprintf(const char *fmt, va_list ap)
{
    _doprint(putchar, fmt, ap);
    return 0;
}

void __assert_failed(char *assertion, char *file, int line)
{
    printf("HVMLoader assertion '%s' failed at %s:%d\n",
           assertion, file, line);
    for ( ; ; )
        __asm__ __volatile__ ( "ud2" );
}

void __bug(char *file, int line)
{
    printf("HVMLoader bug at %s:%d\n", file, line);
    for ( ; ; )
        __asm__ __volatile__ ( "ud2" );
}

static int validate_hvm_info(struct hvm_info_table *t)
{
    char signature[] = "HVM INFO";
    uint8_t *ptr = (uint8_t *)t;
    uint8_t sum = 0;
    int i;

    /* strncmp(t->signature, "HVM INFO", 8) */
    for ( i = 0; i < 8; i++ )
    {
        if ( signature[i] != t->signature[i] )
        {
            printf("Bad hvm info signature\n");
            return 0;
        }
    }

    for ( i = 0; i < t->length; i++ )
        sum += ptr[i];

    return (sum == 0);
}

static struct hvm_info_table *get_hvm_info_table(void)
{
    static struct hvm_info_table *table;
    struct hvm_info_table *t;

    if ( table != NULL )
        return table;

    t = (struct hvm_info_table *)HVM_INFO_PADDR;

    if ( !validate_hvm_info(t) )
    {
        printf("Bad hvm info table\n");
        return NULL;
    }

    table = t;

    return table;
}

int get_vcpu_nr(void)
{
    struct hvm_info_table *t = get_hvm_info_table();
    return (t ? t->nr_vcpus : 1);
}

int get_acpi_enabled(void)
{
    struct hvm_info_table *t = get_hvm_info_table();
    return (t ? t->acpi_enabled : 1);
}

int get_apic_mode(void)
{
    struct hvm_info_table *t = get_hvm_info_table();
    return (t ? t->apic_mode : 1);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
