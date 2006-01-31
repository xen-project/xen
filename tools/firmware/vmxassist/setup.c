/*
 * setup.c: Setup the world for vmxassist.
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
#include "vm86.h"
#include "util.h"
#include "machine.h"

#if (VMXASSIST_BASE != TEXTADDR)
#error VMXAssist base mismatch
#endif

#define	NR_PGD		(PGSIZE / sizeof(unsigned))

#define	min(a, b)	((a) > (b) ? (b) : (a))

/* Which CPU are we booting, and what is the initial CS segment? */
int booting_cpu, booting_vector;

unsigned long long gdt[] __attribute__ ((aligned(32))) = {
	0x0000000000000000ULL,		/* 0x00: reserved */
	0x0000890000000000ULL,		/* 0x08: 32-bit TSS */
	0x00CF9A000000FFFFULL,		/* 0x10: CS 32-bit */
	0x00CF92000000FFFFULL,		/* 0x18: DS 32-bit */
};

struct dtr gdtr = { sizeof(gdt)-1, (unsigned long) &gdt };

struct tss tss __attribute__ ((aligned(4)));

unsigned long long idt[NR_TRAPS] __attribute__ ((aligned(32)));

struct dtr idtr = { sizeof(idt)-1, (unsigned long) &idt };

#ifdef TEST
unsigned pgd[NR_PGD] __attribute__ ((aligned(PGSIZE))) = { 0 };

struct e820entry e820map[] = {
	{ 0x0000000000000000ULL, 0x000000000009F800ULL, E820_RAM },
	{ 0x000000000009F800ULL, 0x0000000000000800ULL, E820_RESERVED },
	{ 0x00000000000A0000ULL, 0x0000000000020000ULL, E820_IO },
	{ 0x00000000000C0000ULL, 0x0000000000040000ULL, E820_RESERVED },
	{ 0x0000000000100000ULL, 0x0000000000000000ULL, E820_RAM },
	{ 0x0000000000000000ULL, 0x0000000000001000ULL, E820_SHARED },
	{ 0x0000000000000000ULL, 0x0000000000003000ULL, E820_NVS },
	{ 0x0000000000003000ULL, 0x000000000000A000ULL, E820_ACPI },
	{ 0x00000000FEC00000ULL, 0x0000000001400000ULL, E820_IO },
};
#endif /* TEST */

struct vmx_assist_context oldctx;
struct vmx_assist_context newctx;

unsigned long memory_size;
int initialize_real_mode;

extern char stack[], stack_top[];
extern unsigned trap_handlers[];

void
banner(void)
{
	printf("VMXAssist (%s)\n", __DATE__);

	/* Bochs its way to convey memory size */
	memory_size = ((get_cmos(0x35) << 8) | get_cmos(0x34)) << 6;
	if (memory_size > 0x3bc000)
		memory_size = 0x3bc000;
	memory_size = (memory_size << 10) + 0xF00000;
	if (memory_size <= 0xF00000)
		memory_size =
		    (((get_cmos(0x31) << 8) | get_cmos(0x30)) + 0x400) << 10;
	memory_size += 0x400 << 10; /* + 1MB */

#ifdef TEST
	/* Create an SMAP for our debug environment */
	e820map[4].size = memory_size - e820map[4].addr - PGSIZE;
	e820map[5].addr = memory_size - PGSIZE;
	e820map[6].addr = memory_size;
	e820map[7].addr += memory_size;

	*LINUX_E820_MAP_NR = sizeof(e820map)/sizeof(e820map[0]);
	memcpy(LINUX_E820_MAP, e820map, sizeof(e820map));
#endif

	printf("Memory size %ld MB\n", memory_size >> 20);
	printf("E820 map:\n");
	print_e820_map(LINUX_E820_MAP, *LINUX_E820_MAP_NR);
	printf("\n");
}

#ifdef TEST
void
setup_paging(void)
{
	unsigned long i;

	if (((unsigned)pgd & ~PGMASK) != 0)
		panic("PGD not page aligned");
	set_cr4(get_cr4() | CR4_PSE);
	for (i = 0; i < NR_PGD; i++)
		pgd[i] = (i * LPGSIZE)| PTE_PS | PTE_US | PTE_RW | PTE_P;
	set_cr3((unsigned) pgd);
	set_cr0(get_cr0() | (CR0_PE|CR0_PG));
}
#endif /* TEST */

void
setup_gdt(void)
{
	/* setup task state segment */
	memset(&tss, 0, sizeof(tss));
	tss.ss0 = DATA_SELECTOR;
	tss.esp0 = (unsigned) stack_top - 4*4;
	tss.iomap_base = offsetof(struct tss, iomap);

	/* initialize gdt's tss selector */
	unsigned long long addr = (unsigned long long) &tss;
        gdt[TSS_SELECTOR / sizeof(gdt[0])] |=
		((addr & 0xFF000000) << (56-24)) |
		((addr & 0x00FF0000) << (32-16)) |
		((addr & 0x0000FFFF) << (16)) |
		(sizeof(tss) - 1);

	/* switch to our own gdt and set current tss */
	__asm__ __volatile__ ("lgdt %0" : : "m" (gdtr));
	__asm__ __volatile__ ("movl %%eax,%%ds;"
			      "movl %%eax,%%es;"
			      "movl %%eax,%%fs;"
			      "movl %%eax,%%gs;"
			      "movl %%eax,%%ss" : : "a" (DATA_SELECTOR));

	__asm__ __volatile__ ("ljmp %0,$1f; 1:" : : "i" (CODE_SELECTOR));

	__asm__ __volatile__ ("ltr %%ax" : : "a" (TSS_SELECTOR));
}

void
set_intr_gate(int i, unsigned handler)
{
	unsigned long long addr = handler;

	idt[i] = ((addr & 0xFFFF0000ULL) << 32) | (0x8E00ULL << 32) |
		(addr & 0xFFFFULL) | (CODE_SELECTOR << 16);
}

void
setup_idt(void)
{
	int i;

	for (i = 0; i < NR_TRAPS; i++)
		set_intr_gate(i, trap_handlers[i]);
	__asm__ __volatile__ ("lidt %0" : : "m" (idtr));
}

void
setup_pic(void)
{
	/* mask all interrupts */
	outb(PIC_MASTER + PIC_IMR, 0xFF);
	outb(PIC_SLAVE + PIC_IMR, 0xFF);

	/* setup master PIC */
	outb(PIC_MASTER + PIC_CMD, 0x11); /* edge triggered, cascade, ICW4 */
	outb(PIC_MASTER + PIC_IMR, NR_EXCEPTION_HANDLER);
	outb(PIC_MASTER + PIC_IMR, 1 << 2); /* slave on channel 2 */
	outb(PIC_MASTER + PIC_IMR, 0x01);

	/* setup slave PIC */
	outb(PIC_SLAVE + PIC_CMD, 0x11); /* edge triggered, cascade, ICW4 */
	outb(PIC_SLAVE + PIC_IMR, NR_EXCEPTION_HANDLER + 8);
	outb(PIC_SLAVE + PIC_IMR, 0x02); /* slave identity is 2 */
	outb(PIC_SLAVE + PIC_IMR, 0x01);

	/* enable all interrupts */
	outb(PIC_MASTER + PIC_IMR, 0);
	outb(PIC_SLAVE + PIC_IMR, 0);
}

void
setiomap(int port)
{
	tss.iomap[port >> 3] |= 1 << (port & 7);
}

void
enter_real_mode(struct regs *regs)
{
	/* mask off TSS busy bit */
        gdt[TSS_SELECTOR / sizeof(gdt[0])] &= ~0x0000020000000000ULL;

	/* start 8086 emulation of BIOS */
	if (initialize_real_mode) {
		initialize_real_mode = 0;
		regs->eflags |= EFLAGS_VM | 0x02;
		regs->ves = regs->vds = regs->vfs = regs->vgs = 0xF000;
		if (booting_cpu == 0) {
			regs->cs = 0xF000; /* ROM BIOS POST entry point */
#ifdef TEST
			regs->eip = 0xFFE0;
#else
			regs->eip = 0xFFF0;
#endif
		} else {
			regs->cs = booting_vector << 8; /* AP entry point */
			regs->eip = 0;
		}
		regs->uesp = 0;
		regs->uss = 0;

		/* intercept accesses to the PIC */
		setiomap(PIC_MASTER+PIC_CMD);
		setiomap(PIC_MASTER+PIC_IMR);
		setiomap(PIC_SLAVE+PIC_CMD);
		setiomap(PIC_SLAVE+PIC_IMR);

		printf("Starting emulated 16-bit real-mode: ip=%04x:%04x\n",
			regs->cs, regs->eip);

		mode = VM86_REAL; /* becomes previous mode */
		set_mode(regs, VM86_REAL);

		/* this should get us into 16-bit mode */
		return;
	} else {
		/* go from protected to real mode */
		regs->eflags |= EFLAGS_VM;

		set_mode(regs, VM86_PROTECTED_TO_REAL);

		emulate(regs);
	}
}

/*
 * Setup the environment for VMX assist.
 * This environment consists of flat segments (code and data),
 * its own gdt, idt, and tr.
 */
void
setup_ctx(void)
{
	struct vmx_assist_context *c = &newctx;

	memset(c, 0, sizeof(*c));
	c->eip = (unsigned long) switch_to_real_mode;
	c->esp = (unsigned) stack_top - 4*4;
	c->eflags = 0x2; /* no interrupts, please */

	/*
	 * Obviously, vmx assist is not running with CR0_PE disabled.
	 * The reason why the vmx assist cr0 has CR0.PE disabled is
	 * that a transtion to CR0.PE causes a world switch. It seems
	 * more natural to enable CR0.PE to cause a world switch to
	 * protected mode rather than disabling it.
	 */
#ifdef TEST
	c->cr0 = (get_cr0() | CR0_NE | CR0_PG) & ~CR0_PE;
	c->cr3 = (unsigned long) pgd;
#else
	c->cr0 = (get_cr0() | CR0_NE) & ~CR0_PE;
	c->cr3 = 0;
#endif
	c->cr4 = get_cr4();

	c->idtr_limit = sizeof(idt)-1;
	c->idtr_base = (unsigned long) &idt;

	c->gdtr_limit = sizeof(gdt)-1;
	c->gdtr_base = (unsigned long) &gdt;

	c->cs_sel = CODE_SELECTOR;
	c->cs_limit = 0xFFFFFFFF;
	c->cs_base = 0;
	c->cs_arbytes.fields.seg_type = 0xb;
	c->cs_arbytes.fields.s = 1;
	c->cs_arbytes.fields.dpl = 0;
	c->cs_arbytes.fields.p = 1;
	c->cs_arbytes.fields.avl = 0;
	c->cs_arbytes.fields.default_ops_size = 1;
	c->cs_arbytes.fields.g = 1;

	c->ds_sel = DATA_SELECTOR;
	c->ds_limit = 0xFFFFFFFF;
	c->ds_base = 0;
	c->ds_arbytes = c->cs_arbytes;
	c->ds_arbytes.fields.seg_type = 0x3;

	c->es_sel = DATA_SELECTOR;
	c->es_limit = 0xFFFFFFFF;
	c->es_base = 0;
	c->es_arbytes = c->ds_arbytes;

	c->ss_sel = DATA_SELECTOR;
	c->ss_limit = 0xFFFFFFFF;
	c->ss_base = 0;
	c->ss_arbytes = c->ds_arbytes;

	c->fs_sel = DATA_SELECTOR;
	c->fs_limit = 0xFFFFFFFF;
	c->fs_base = 0;
	c->fs_arbytes = c->ds_arbytes;

	c->gs_sel = DATA_SELECTOR;
	c->gs_limit = 0xFFFFFFFF;
	c->gs_base = 0;
	c->gs_arbytes = c->ds_arbytes;

	c->tr_sel = TSS_SELECTOR;
	c->tr_limit = sizeof(tss) - 1;
	c->tr_base = (unsigned long) &tss;
	c->tr_arbytes.fields.seg_type = 0xb; /* 0x9 | 0x2 (busy) */
	c->tr_arbytes.fields.s = 0;
	c->tr_arbytes.fields.dpl = 0;
	c->tr_arbytes.fields.p = 1;
	c->tr_arbytes.fields.avl = 0;
	c->tr_arbytes.fields.default_ops_size = 0;
	c->tr_arbytes.fields.g = 0;

	c->ldtr_sel = 0;
	c->ldtr_limit = 0;
	c->ldtr_base = 0;
	c->ldtr_arbytes = c->ds_arbytes;
	c->ldtr_arbytes.fields.seg_type = 0x2;
	c->ldtr_arbytes.fields.s = 0;
	c->ldtr_arbytes.fields.dpl = 0;
	c->ldtr_arbytes.fields.p = 1;
	c->ldtr_arbytes.fields.avl = 0;
	c->ldtr_arbytes.fields.default_ops_size = 0;
	c->ldtr_arbytes.fields.g = 0;
}

/*
 * Start BIOS by causing a world switch to vmxassist, which causes
 * VM8086 to be enabled and control is transfered to F000:FFF0.
 */
void
start_bios(void)
{
	unsigned long cr0;

	if (booting_cpu == 0)
		printf("Start BIOS ...\n");
	else
		printf("Start AP %d from %08x ...\n",
		       booting_cpu, booting_vector << 12);

	initialize_real_mode = 1;
	cr0 = get_cr0();
#ifndef TEST
	set_cr0(cr0 | CR0_PE);
#endif
	set_cr0(cr0 & ~CR0_PE);
	panic("vmxassist returned"); /* "cannot happen" */
}

int
main(void)
{
	if (booting_cpu == 0)
		banner();

#ifdef TEST
	setup_paging();
#endif

	setup_gdt();
	setup_idt();

#ifndef	TEST
	set_cr4(get_cr4() | CR4_VME);
#endif

	setup_ctx();

	if (booting_cpu == 0)
		setup_pic();

	start_bios();

	return 0;
}
