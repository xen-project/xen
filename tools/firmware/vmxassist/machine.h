/*
 * machine.h: Intel CPU specific definitions
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
#ifndef __MACHINE_H__
#define __MACHINE_H__

/* the size of our stack (4KB) */
#define STACK_SIZE	8192

#define TSS_SELECTOR	0x08
#define CODE_SELECTOR	0x10
#define DATA_SELECTOR	0x18

#define CR0_PE		(1 << 0)
#define CR0_EM		(1 << 2)
#define	CR0_TS		(1 << 3)
#define CR0_NE		(1 << 5)
#define CR0_PG		(1 << 31)

#define CR4_VME		(1 << 0)
#define CR4_PVI		(1 << 1)
#define CR4_PSE		(1 << 4)

#define EFLAGS_ZF	(1 << 6)
#define EFLAGS_TF	(1 << 8)
#define EFLAGS_IF	(1 << 9)
#define EFLAGS_DF	(1 << 10)
#define EFLAGS_IOPL	(3 << 12)
#define EFLAGS_VM	((1 << 17) | EFLAGS_IOPL)
#define EFLAGS_VIF	(1 << 19)
#define EFLAGS_VIP	(1 << 20)

#define	LOG_PGSIZE	12	/* log2(page size) */
#define	LOG_PDSIZE	22	/* log2(page directory size) */

/* Derived constants */
#define	PGSIZE		(1 << LOG_PGSIZE)	/* page size */
#define	PGMASK		(~(PGSIZE - 1))		/* page mask */
#define	LPGSIZE		(1 << LOG_PDSIZE)	/* large page size */
#define	LPGMASK		(~(LPGSIZE - 1))	/* large page mask */

#ifdef TEST
#define	PTE_P		(1 << 0)	/* Present */
#define	PTE_RW		(1 << 1)	/* Read/Write */
#define	PTE_US		(1 << 2)	/* User/Supervisor */
#define	PTE_PS		(1 << 7)	/* Page Size */
#endif

/* Programmable Interrupt Contoller (PIC) defines */
#define	PIC_MASTER	0x20
#define	PIC_SLAVE	0xA0

#define	PIC_CMD		0	/* command */
#define	PIC_ISR		0	/* interrupt status */
#define	PIC_IMR		1	/* interrupt mask */


#ifndef __ASSEMBLY__

struct dtr {
	unsigned short	size;
	unsigned long	base __attribute__ ((packed));
};

struct tss {
	unsigned short	prev_link;
	unsigned short	_1;
	unsigned long	esp0;
	unsigned short	ss0;
	unsigned short	_2;
	unsigned long	esp1;
	unsigned short	ss1;
	unsigned short	_3;
	unsigned long	esp2;
	unsigned short	ss2;
	unsigned short	_4;
	unsigned long	cr3;
	unsigned long	eip;
	unsigned long	eflags;
	unsigned long	eax;
	unsigned long	ecx;
	unsigned long	edx;
	unsigned long	ebx;
	unsigned long	esi;
	unsigned long	edi;
	unsigned long	esp;
	unsigned long	ebp;
	unsigned long	es;
	unsigned long	cs;
	unsigned long	ss;
	unsigned long	ds;
	unsigned long	fs;
	unsigned long	gs;
	unsigned short	ldt_segment;
	unsigned short	_5;
	unsigned short	_6;
	unsigned short	iomap_base;
#ifdef	ENABLE_VME
	unsigned long	int_redir[8];
#endif
	unsigned char	iomap[8192];
};

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

static inline unsigned
get_cmos(int reg)
{
	outb(0x70, reg);
	return inb(0x71);
}

static inline unsigned
get_cr0(void)
{
        unsigned rv;
        __asm__ __volatile__("movl %%cr0, %0" : "=r"(rv));
        return rv;
}

static inline void
set_cr0(unsigned value)
{
	__asm__ __volatile__(
		"movl	%0, %%cr0\n"
		"jmp	1f\n"
		"1: 	nop\n"
		: /* no outputs */
		: "r"(value)
	);
}

static inline unsigned
get_cr2(void)
{
	unsigned rv;

	__asm__ __volatile__("movl %%cr2, %0" : "=r"(rv));
	return rv;
}

static inline unsigned
get_cr4(void)
{
        unsigned rv;
        __asm__ __volatile__("movl %%cr4, %0" : "=r"(rv));
        return rv;
}

static inline void
set_cr3(unsigned addr)
{
        __asm__ __volatile__("movl %0, %%cr3" : /* no outputs */ : "r"(addr));
}

static inline void
set_cr4(unsigned value)
{
	__asm__ __volatile__("movl %0, %%cr4" : /* no outputs */ : "r"(value));
}

#ifdef TEST
static inline void
breakpoint(void)
{
	outw(0x8A00, 0x8AE0);
}
#endif /* TEST */

#endif /* __ASSEMBLY__ */

#endif /* __MACHINE_H__ */

