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

#include "../acpi/acpi2_0.h"  /* for ACPI_PHYSICAL_ADDRESS */
#include "util.h"

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
