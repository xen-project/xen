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

#include "acpi/acpi2_0.h"  /* for ACPI_PHYSICAL_ADDRESS */
#include "util.h"
#include <stdint.h>

void outw(uint16_t addr, uint16_t val)
{
	__asm__ __volatile__ ("outw %%ax, %%dx" :: "d"(addr), "a"(val));
}

void outb(uint16_t addr, uint8_t val)
{
	__asm__ __volatile__ ("outb %%al, %%dx" :: "d"(addr), "a"(val));
}

uint8_t inb(uint16_t addr)
{
	uint8_t val;
	__asm__ __volatile__ ("inb %w1,%0" : "=a" (val) : "Nd" (addr));
	return val;
}

char *itoa(char *a, unsigned int i)
{
	unsigned int _i = i, x = 0;

	do {
		x++;
		_i /= 10;
	} while (_i != 0);

	a += x;
	*a-- = '\0';

	do {
		*a-- = (i % 10) + '0';
		i /= 10;
	} while (i != 0);

	return a + 1;
}

int strcmp(const char *cs, const char *ct)
{
	signed char res;

	while (((res = *cs - *ct++) == 0) && (*cs++ != '\0'))
		continue;

	return res;
}

void *memcpy(void *dest, const void *src, unsigned n)
{
	int t0, t1, t2;

	__asm__ __volatile__(
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
		: "memory"
	);
	return dest;
}

void puts(const char *s)
{
	while (*s)
		outb(0xE9, *s++);
}

char *
strcpy(char *dest, const char *src)
{
	char *p = dest;
	while (*src)
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
	while (i < n && *src) {
		*p++ = *src++;
		++i;
	}

	/* pad remaining bytes of dest with NUL bytes */
	while (i < n) {
		*p++ = 0;
		++i;
	}

	return dest;
}

unsigned
strlen(const char *s)
{
	int i = 0;
	while (*s++)
		++i;
	return i;
}

void *
memset(void *s, int c, unsigned n)
{
	uint8_t b = (uint8_t) c;
	uint8_t *p = (uint8_t *)s;
	int i;
	for (i = 0; i < n; ++i)
		*p++ = b;
	return s;
}

int
memcmp(const void *s1, const void *s2, unsigned n)
{
	unsigned i;
	uint8_t *p1 = (uint8_t *) s1;
	uint8_t *p2 = (uint8_t *) s2;

	for (i = 0; i < n; ++i) {
		if (p1[i] < p2[i])
			return -1;
		else if (p1[i] > p2[i])
			return 1;
	}

	return 0;
}

void
cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	__asm__ __volatile__(
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

	if (nybbel > 9)
		digits[0] = 'a' + nybbel-10;
	else
		digits[0] = '0' + nybbel;

	nybbel = byte & 0x0f;
	if (nybbel > 9)
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

	for (i = 0; i < 4; ++i) {
		byte_to_hex(p, uuid[i]);
		p += 2;
	}
	*p++ = '-';
	for (i = 4; i < 6; ++i) {
		byte_to_hex(p, uuid[i]);
		p += 2;
	}
	*p++ = '-';
	for (i = 6; i < 8; ++i) {
		byte_to_hex(p, uuid[i]);
		p += 2;
	}
	*p++ = '-';
	for (i = 8; i < 10; ++i) {
		byte_to_hex(p, uuid[i]);
		p += 2;
	}
	*p++ = '-';
	for (i = 10; i < 16; ++i) {
		byte_to_hex(p, uuid[i]);
		p += 2;
	}
}
