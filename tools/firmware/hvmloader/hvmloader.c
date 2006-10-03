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
#include "hypercall.h"
#include "util.h"
#include "smbios.h"
#include <xen/version.h>
#include <xen/hvm/params.h>

/* memory map */
#define HYPERCALL_PHYSICAL_ADDRESS	0x00080000
#define VGABIOS_PHYSICAL_ADDRESS	0x000C0000
#define	VMXASSIST_PHYSICAL_ADDRESS	0x000D0000
#define	ROMBIOS_PHYSICAL_ADDRESS	0x000F0000

/* invoke SVM's paged realmode support */
#define SVM_VMMCALL_RESET_TO_REALMODE	0x80000001

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
extern void create_mp_tables(void);
struct hvm_info_table *get_hvm_info_table(void);

static int
cirrus_check(void)
{
	outw(0x3C4, 0x9206);
	return inb(0x3C5) == 0x12;
}

static int
vmmcall(int function, int edi, int esi, int edx, int ecx, int ebx)
{
        int eax;

        __asm__ __volatile__(
		".byte 0x0F,0x01,0xD9"
                : "=a" (eax)
		: "a"(function),
		  "b"(ebx), "c"(ecx), "d"(edx), "D"(edi), "S"(esi)
	);
        return eax;
}

static int
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

static void
wrmsr(uint32_t idx, uint64_t v)
{
	__asm__ __volatile__(
		"wrmsr"
		: : "c" (idx), "a" ((uint32_t)v), "d" ((uint32_t)(v>>32)) );
}

static void
init_hypercalls(void)
{
	uint32_t eax, ebx, ecx, edx;
	unsigned long i;
	char signature[13], number[13];
	xen_extraversion_t extraversion;

	cpuid(0x40000000, &eax, &ebx, &ecx, &edx);

	*(uint32_t *)(signature + 0) = ebx;
	*(uint32_t *)(signature + 4) = ecx;
	*(uint32_t *)(signature + 8) = edx;
	signature[12] = '\0';

	if (strcmp("XenVMMXenVMM", signature) || (eax < 0x40000002)) {
		puts("FATAL: Xen hypervisor not detected\n");
		__asm__ __volatile__( "ud2" );
	}

	cpuid(0x40000001, &eax, &ebx, &ecx, &edx);

	puts("Detected Xen v");
	puts(itoa(number, eax >> 16));
	puts(".");
	puts(itoa(number, eax & 0xffff));

	cpuid(0x40000002, &eax, &ebx, &ecx, &edx);

	for (i = 0; i < eax; i++)
		wrmsr(ebx, HYPERCALL_PHYSICAL_ADDRESS + (i << 12) + i);

	hypercall_xen_version(XENVER_extraversion, extraversion);
	puts(extraversion);
	puts("\n");
}

int
main(void)
{
	struct xen_hvm_param hvm_param;

	puts("HVM Loader\n");

	init_hypercalls();

	puts("Writing SMBIOS tables ...\n");
	hvm_write_smbios_tables();

	puts("Loading ROMBIOS ...\n");
	memcpy((void *)ROMBIOS_PHYSICAL_ADDRESS, rombios, sizeof(rombios));

	hvm_param.domid = DOMID_SELF;
	hvm_param.index = HVM_PARAM_APIC_ENABLED;
	if (!hypercall_hvm_op(HVMOP_get_param, &hvm_param) && hvm_param.value)
		create_mp_tables();
	
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
                vmmcall(SVM_VMMCALL_RESET_TO_REALMODE, 0, 0, 0, 0, 0);
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

