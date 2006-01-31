/*
 * hvmloader.c: HVM ROMBIOS/VGABIOS/ACPI/VMXAssist image loader.
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
#include "roms.h"
#include "../acpi/acpi2_0.h"  /* for ACPI_PHYSICAL_ADDRESS */

/* memory map */
#define VGABIOS_PHYSICAL_ADDRESS	0x000C0000
#define	VMXASSIST_PHYSICAL_ADDRESS	0x000D0000
#define	ROMBIOS_PHYSICAL_ADDRESS	0x000F0000

/* invoke SVM's paged realmode support */
#define SVM_VMMCALL_RESET_TO_REALMODE	0x00000001

/*
 * C runtime start off
 */
asm(
"	.text				\n"
"	.globl	_start			\n"
"_start:				\n"
"	cld				\n"
"	cli				\n"
"	lgdt	gdt_desr		\n"
"	movl	$stack_top, %esp	\n"
"	movl	%esp, %ebp		\n"
"	call	main			\n"
"	jmp	halt			\n"
"					\n"
"gdt_desr:				\n"
"	.word	gdt_end - gdt - 1	\n"
"	.long	gdt			\n"
"					\n"
"	.align	8			\n"
"gdt:					\n"
"	.quad	0x0000000000000000	\n"
"	.quad	0x00CF92000000FFFF	\n"
"	.quad	0x00CF9A000000FFFF	\n"
"gdt_end:				\n"
"					\n"
"halt:					\n"
"	sti				\n"
"	jmp	.			\n"
"					\n"
"	.bss				\n"
"	.align	8			\n"
"stack:					\n"
"	.skip	0x4000			\n"
"stack_top:				\n"
);

extern int get_acpi_enabled(void);
extern int acpi_madt_update(unsigned char* acpi_start);

static inline void
outw(unsigned short addr, unsigned short val)
{
        __asm__ __volatile__ ("outw %%ax, %%dx" :: "d"(addr), "a"(val));
}

static inline void
outb(unsigned short addr, unsigned char val)
{
        __asm__ __volatile__ ("outb %%al, %%dx" :: "d"(addr), "a"(val));
}

static inline unsigned char
inb(unsigned short addr)
{
        unsigned char val;

        __asm__ __volatile__ ("inb %w1,%0" : "=a" (val) : "Nd" (addr));
        return val;
}

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
vmmcall(int edi, int esi, int edx, int ecx, int ebx)
{
        int eax;

        __asm__ __volatile__(
		".byte 0x0F,0x01,0xD9"
                : "=a" (eax)
		: "a"(0x58454E00), /* XEN\0 key */
		  "b"(ebx), "c"(ecx), "d"(edx), "D"(edi), "S"(esi)
	);
        return eax;
}

int
check_amd(void)
{
	char id[12];

        __asm__ __volatile__(
		"cpuid" 
		: "=b" (*(int *)(&id[0])),
		  "=c" (*(int *)(&id[8])),
		  "=d" (*(int *)(&id[4]))
		: "a" (0)
	);
	return __builtin_memcmp(id, "AuthenticAMD", 12) == 0;
}

int
main(void)
{
	puts("HVM Loader\n");

	puts("Loading ROMBIOS ...\n");
	memcpy((void *)ROMBIOS_PHYSICAL_ADDRESS, rombios, sizeof(rombios));
	if (cirrus_check()) {
		puts("Loading Cirrus VGABIOS ...\n");
		memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
			vgabios_cirrusvga, sizeof(vgabios_cirrusvga));
	} else {
		puts("Loading Standard VGABIOS ...\n");
		memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
			vgabios_stdvga, sizeof(vgabios_stdvga));
	}

	if (get_acpi_enabled() != 0) {
		puts("Loading ACPI ...\n");
		acpi_madt_update((unsigned char *) acpi);
		if (ACPI_PHYSICAL_ADDRESS+sizeof(acpi) <= 0xF0000) {
			/*
			 * Make sure acpi table does not overlap rombios
			 * currently acpi less than 8K will be OK.
			 */
			 memcpy((void *)ACPI_PHYSICAL_ADDRESS, acpi,
			 					sizeof(acpi));
		}
	}

	if (check_amd()) {
		/* AMD implies this is SVM */
                puts("SVM go ...\n");
                vmmcall(SVM_VMMCALL_RESET_TO_REALMODE, 0, 0, 0, 0);
	} else {
		puts("Loading VMXAssist ...\n");
		memcpy((void *)VMXASSIST_PHYSICAL_ADDRESS,
				vmxassist, sizeof(vmxassist));

		puts("VMX go ...\n");
		__asm__ __volatile__(
			"jmp *%%eax"
			: : "a" (VMXASSIST_PHYSICAL_ADDRESS), "d" (0)
		);
	}

	puts("Failed to invoke ROMBIOS\n");
	return 0;
}

