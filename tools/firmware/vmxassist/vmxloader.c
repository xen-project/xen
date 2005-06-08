/*
 * vmxloader.c: ROM/VMXAssist image loader.
 *
 * A quicky so that we can boot rom images as if they were a Linux kernel.
 * This code will copy the rom images (ROMBIOS/VGABIOS/VM86) into their
 * respective spaces and transfer control to VM86 to execute the BIOSes.
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
#include "machine.h"
#include "roms.h"

/*
 * C runtime start off
 */
asm("					\n\
	.text				\n\
	.globl	_start			\n\
_start:					\n\
	cli				\n\
	movl	$stack_top, %esp	\n\
	movl	%esp, %ebp		\n\
	call    main			\n\
	jmp	halt			\n\
					\n\
	.globl	halt			\n\
halt:					\n\
	sti				\n\
	jmp	.			\n\
					\n\
	.bss				\n\
	.align	8			\n\
	.globl	stack, stack_top	\n\
stack:					\n\
	.skip	0x4000			\n\
stack_top:				\n\
");

void *
memcpy(void *dest, const void *src, unsigned n)
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

int
puts(const char *s)
{
	while (*s)
		outb(0xE9, *s++);
	return 0;
}

int
cirrus_check(void)
{
	outw(0x3C4, 0x9206);
	return inb(0x3C5) == 0x12;
}

int
main()
{
	puts("VMXAssist Loader\n");
	puts("Loading ROMBIOS ...\n");
	memcpy((void *)0xF0000, rombios, sizeof(rombios));
	if (cirrus_check()) {
		puts("Loading Cirrus VGABIOS ...\n");
		memcpy((void *)0xC0000,
			vgabios_cirrusvga, sizeof(vgabios_cirrusvga));
	} else {
		puts("Loading Standard VGABIOS ...\n");
		memcpy((void *)0xC0000,
			vgabios_stdvga, sizeof(vgabios_stdvga));
	}
	puts("Loading VMXAssist ...\n");
	memcpy((void *)TEXTADDR, vmxassist, sizeof(vmxassist));
	puts("Go ...\n");
	((void (*)())TEXTADDR)();
}

