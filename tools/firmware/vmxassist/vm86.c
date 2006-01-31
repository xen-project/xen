/*
 * vm86.c: A vm86 emulator. The main purpose of this emulator is to do as
 * little work as possible. 
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

#define	HIGHMEM		(1 << 20)		/* 1MB */
#define	MASK16(v)	((v) & 0xFFFF)

#define	DATA32		0x0001
#define	ADDR32		0x0002
#define	SEG_CS		0x0004
#define	SEG_DS		0x0008
#define	SEG_ES		0x0010
#define	SEG_SS		0x0020
#define	SEG_FS		0x0040
#define	SEG_GS		0x0080

unsigned prev_eip = 0;
enum vm86_mode mode;

#ifdef DEBUG
int traceset = 0;

char *states[] = {
	"<VM86_REAL>",
	"<VM86_REAL_TO_PROTECTED>",
	"<VM86_PROTECTED_TO_REAL>",
	"<VM86_PROTECTED>"
};
#endif /* DEBUG */


unsigned
address(struct regs *regs, unsigned seg, unsigned off)
{
	unsigned long long entry;
	unsigned addr;

	/* real mode: segment is part of the address */
	if (mode == VM86_REAL || mode == VM86_REAL_TO_PROTECTED)
		return ((seg & 0xFFFF) << 4) + off;

	/* protected mode: use seg as index into gdt */
	if (seg > oldctx.gdtr_limit) {
		printf("address: Invalid segment descriptor (0x%x)\n", seg);
		return 0;
	}

	entry = ((unsigned long long *) oldctx.gdtr_base)[seg >> 3];
	addr = (((entry >> (56-24)) & 0xFF000000) |
		((entry >> (32-16)) & 0x00FF0000) |
		((entry >> (   16)) & 0x0000FFFF)) + off;
	return addr;
}

#ifdef DEBUG
void
trace(struct regs *regs, int adjust, char *fmt, ...)
{
	unsigned off = regs->eip - adjust;
        va_list ap;

	if ((traceset & (1 << mode)) &&
	   (mode == VM86_REAL_TO_PROTECTED || mode == VM86_REAL)) {
		/* 16-bit, seg:off addressing */
		unsigned addr = address(regs, regs->cs, off);
		printf("0x%08x: 0x%x:0x%04x ", addr, regs->cs, off);
		printf("(%d) ", mode);
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
	}
	if ((traceset & (1 << mode)) &&
	   (mode == VM86_PROTECTED_TO_REAL || mode == VM86_PROTECTED)) {
		/* 16-bit, gdt addressing */
		unsigned addr = address(regs, regs->cs, off);
		printf("0x%08x: 0x%x:0x%08x ", addr, regs->cs, off);
		printf("(%d) ", mode);
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
	}
}
#endif /* DEBUG */

static inline unsigned
read32(unsigned addr)
{
	return *(unsigned long *) addr;
}

static inline unsigned
read16(unsigned addr)
{
	return *(unsigned short *) addr;
}

static inline unsigned
read8(unsigned addr)
{
	return *(unsigned char *) addr;
}

static inline void
write32(unsigned addr, unsigned value)
{
	*(unsigned long *) addr = value;
}

static inline void
write16(unsigned addr, unsigned value)
{
	*(unsigned short *) addr = value;
}

static inline void
write8(unsigned addr, unsigned value)
{
	*(unsigned char *) addr = value;
}

static inline void
push32(struct regs *regs, unsigned value)
{
	regs->uesp -= 4;
	write32(address(regs, regs->uss, MASK16(regs->uesp)), value);
}

static inline void
push16(struct regs *regs, unsigned value)
{
	regs->uesp -= 2;
	write16(address(regs, regs->uss, MASK16(regs->uesp)), value);
}

static inline unsigned
pop32(struct regs *regs)
{
	unsigned value = read32(address(regs, regs->uss, MASK16(regs->uesp)));
	regs->uesp += 4;
	return value;
}

static inline unsigned
pop16(struct regs *regs)
{
	unsigned value = read16(address(regs, regs->uss, MASK16(regs->uesp)));
	regs->uesp += 2;
	return value;
}

static inline unsigned
fetch32(struct regs *regs)
{
	unsigned addr = address(regs, regs->cs, MASK16(regs->eip));

	regs->eip += 4;
	return read32(addr);
}

static inline unsigned
fetch16(struct regs *regs)
{
	unsigned addr = address(regs, regs->cs, MASK16(regs->eip));

	regs->eip += 2;
	return read16(addr);
}

static inline unsigned
fetch8(struct regs *regs)
{
	unsigned addr = address(regs, regs->cs, MASK16(regs->eip));

	regs->eip++;
	return read8(addr);
}

unsigned
getreg(struct regs *regs, int r)
{
	switch (r & 7) {
	case 0: return regs->eax;
	case 1: return regs->ecx;
	case 2: return regs->edx;
	case 3: return regs->ebx;
	case 4: return regs->esp;
	case 5: return regs->ebp;
	case 6: return regs->esi;
	case 7: return regs->edi;
	}
	return ~0;
}

void
setreg(struct regs *regs, int r, unsigned v)
{
	switch (r & 7) {
	case 0: regs->eax = v; break;
	case 1: regs->ecx = v; break;
	case 2: regs->edx = v; break;
	case 3: regs->ebx = v; break;
	case 4: regs->esp = v; break;
	case 5: regs->ebp = v; break;
	case 6: regs->esi = v; break;
	case 7: regs->edi = v; break;
	}
}

/*
 * Operand (modrm) decode
 */
unsigned
operand(unsigned prefix, struct regs *regs, unsigned modrm)
{
	int mod, disp = 0, seg;

	seg = regs->vds;
	if (prefix & SEG_ES)
		seg = regs->ves;
	if (prefix & SEG_DS)
		seg = regs->vds;
	if (prefix & SEG_CS)
		seg = regs->cs;
	if (prefix & SEG_SS)
		seg = regs->uss;
	if (prefix & SEG_FS)
		seg = regs->fs;
	if (prefix & SEG_GS)
		seg = regs->gs;

	if (prefix & ADDR32) { /* 32-bit addressing */
		switch ((mod = (modrm >> 6) & 3)) {
		case 0:
			switch (modrm & 7) {
			case 0: return address(regs, seg, regs->eax);
			case 1: return address(regs, seg, regs->ecx);
			case 2: return address(regs, seg, regs->edx);
			case 3: return address(regs, seg, regs->ebx);
			case 4: panic("No SIB decode (yet)");
			case 5: return address(regs, seg, fetch32(regs));
			case 6: return address(regs, seg, regs->esi);
			case 7: return address(regs, seg, regs->edi);
			}
			break;
		case 1:
		case 2:
			if ((modrm & 7) != 4) {
				if (mod == 1)
					disp = (char) fetch8(regs);
				else
					disp = (int) fetch32(regs);
			}
			switch (modrm & 7) {
			case 0: return address(regs, seg, regs->eax + disp);
			case 1: return address(regs, seg, regs->ecx + disp);
			case 2: return address(regs, seg, regs->edx + disp);
			case 3: return address(regs, seg, regs->ebx + disp);
			case 4: panic("No SIB decode (yet)");
			case 5: return address(regs, seg, regs->ebp + disp);
			case 6: return address(regs, seg, regs->esi + disp);
			case 7: return address(regs, seg, regs->edi + disp);
			}
			break;
		case 3:
			return getreg(regs, modrm);
		}
	} else { /* 16-bit addressing */
		switch ((mod = (modrm >> 6) & 3)) {
		case 0:
			switch (modrm & 7) {
			case 0: return address(regs, seg, MASK16(regs->ebx) +
					MASK16(regs->esi));
			case 1: return address(regs, seg, MASK16(regs->ebx) +
					MASK16(regs->edi));
			case 2: return address(regs, seg, MASK16(regs->ebp) +
					MASK16(regs->esi));
			case 3: return address(regs, seg, MASK16(regs->ebp) +
					MASK16(regs->edi));
			case 4: return address(regs, seg, MASK16(regs->esi));
			case 5: return address(regs, seg, MASK16(regs->edi));
			case 6: return address(regs, seg, fetch16(regs));
			case 7: return address(regs, seg, MASK16(regs->ebx));
			}
			break;
		case 1:
		case 2:
			if (mod == 1)
				disp = (char) fetch8(regs);
			else
				disp = (int) fetch16(regs);
			switch (modrm & 7) {
			case 0: return address(regs, seg, MASK16(regs->ebx) +
					MASK16(regs->esi) + disp);
			case 1: return address(regs, seg, MASK16(regs->ebx) +
					MASK16(regs->edi) + disp);
			case 2: return address(regs, seg, MASK16(regs->ebp) +
					MASK16(regs->esi) + disp);
			case 3: return address(regs, seg, MASK16(regs->ebp) +
					MASK16(regs->edi) + disp);
			case 4: return address(regs, seg,
					MASK16(regs->esi) + disp);
			case 5: return address(regs, seg,
					MASK16(regs->edi) + disp);
			case 6: return address(regs, seg,
					MASK16(regs->ebp) + disp);
			case 7: return address(regs, seg,
					MASK16(regs->ebx) + disp);
			}
			break;
		case 3:
			return MASK16(getreg(regs, modrm));
		}
	}

	return 0; 
}

/*
 * Load new IDT
 */
int
lidt(struct regs *regs, unsigned prefix, unsigned modrm)
{
	unsigned eip = regs->eip - 3;
	unsigned addr = operand(prefix, regs, modrm);

	oldctx.idtr_limit = ((struct dtr *) addr)->size;
	if ((prefix & DATA32) == 0)
		oldctx.idtr_base = ((struct dtr *) addr)->base & 0xFFFFFF;
	else
		oldctx.idtr_base = ((struct dtr *) addr)->base;
	TRACE((regs, regs->eip - eip, "lidt 0x%x <%d, 0x%x>",
		addr, oldctx.idtr_limit, oldctx.idtr_base));

	return 1;
}

/*
 * Load new GDT
 */
int
lgdt(struct regs *regs, unsigned prefix, unsigned modrm)
{
	unsigned eip = regs->eip - 3;
	unsigned addr = operand(prefix, regs, modrm);

	oldctx.gdtr_limit = ((struct dtr *) addr)->size;
	if ((prefix & DATA32) == 0)
		oldctx.gdtr_base = ((struct dtr *) addr)->base & 0xFFFFFF;
	else
		oldctx.gdtr_base = ((struct dtr *) addr)->base;
	TRACE((regs, regs->eip - eip, "lgdt 0x%x <%d, 0x%x>",
		addr, oldctx.gdtr_limit, oldctx.gdtr_base));

	return 1;
}

/*
 * Modify CR0 either through an lmsw instruction.
 */
int
lmsw(struct regs *regs, unsigned prefix, unsigned modrm)
{
	unsigned eip = regs->eip - 3;
	unsigned ax = operand(prefix, regs, modrm) & 0xF;
	unsigned cr0 = (oldctx.cr0 & 0xFFFFFFF0) | ax;

	TRACE((regs, regs->eip - eip, "lmsw 0x%x", ax));
#ifndef TEST
	oldctx.cr0 = cr0 | CR0_PE | CR0_NE;
#else
	oldctx.cr0 = cr0 | CR0_PE | CR0_NE | CR0_PG;
#endif
	if (cr0 & CR0_PE)
		set_mode(regs, VM86_REAL_TO_PROTECTED);

	return 1;
}

/*
 * Move to and from a control register.
 */
int
movcr(struct regs *regs, unsigned prefix, unsigned opc)
{
	unsigned eip = regs->eip - 2;
	unsigned modrm = fetch8(regs);
	unsigned cr = (modrm >> 3) & 7;

	if ((modrm & 0xC0) != 0xC0) /* only registers */
		return 0;

	switch (opc) {
	case 0x20: /* mov Rd, Cd */
		TRACE((regs, regs->eip - eip, "movl %%cr%d, %%eax", cr));
		switch (cr) {
		case 0:
#ifndef TEST
			setreg(regs, modrm,
				oldctx.cr0 & ~(CR0_PE | CR0_NE));
#else
			setreg(regs, modrm,
				oldctx.cr0 & ~(CR0_PE | CR0_NE | CR0_PG));
#endif
			break;
		case 2:
			setreg(regs, modrm, get_cr2());
			break;
		case 3:
			setreg(regs, modrm, oldctx.cr3);
			break;
		case 4:
			setreg(regs, modrm, oldctx.cr4);
			break;
		}
		break;
	case 0x22: /* mov Cd, Rd */
		TRACE((regs, regs->eip - eip, "movl %%eax, %%cr%d", cr));
		switch (cr) {
		case 0:
			oldctx.cr0 = getreg(regs, modrm) | (CR0_PE | CR0_NE);
#ifdef TEST
			oldctx.cr0 |= CR0_PG;
#endif
			if (getreg(regs, modrm) & CR0_PE)
				set_mode(regs, VM86_REAL_TO_PROTECTED);

			break;
		case 3:
			oldctx.cr3 = getreg(regs, modrm);
			break;
		case 4:
			oldctx.cr4 = getreg(regs, modrm);
			break;
		}
		break;
	}

	return 1;
}

/*
 * Emulate a segment load in protected mode
 */
int
load_seg(unsigned long sel, uint32_t *base, uint32_t *limit, union vmcs_arbytes *arbytes)
{
	unsigned long long entry;

	/* protected mode: use seg as index into gdt */
	if (sel > oldctx.gdtr_limit)
		return 0;

    if (sel == 0) {
        arbytes->fields.null_bit = 1;
        return 1;
    }

	entry =  ((unsigned long long *) oldctx.gdtr_base)[sel >> 3];

    /* Check the P bit fisrt*/
    if (!((entry >> (15+32)) & 0x1) && sel != 0) {
        return 0;
    }

	*base =  (((entry >> (56-24)) & 0xFF000000) |
		  ((entry >> (32-16)) & 0x00FF0000) |
		  ((entry >> (   16)) & 0x0000FFFF));
	*limit = (((entry >> (48-16)) & 0x000F0000) |
		  ((entry           ) & 0x0000FFFF));

	arbytes->bytes = 0;
	arbytes->fields.seg_type = (entry >> (8+32)) & 0xF; /* TYPE */
	arbytes->fields.s =  (entry >> (12+32)) & 0x1; /* S */
	if (arbytes->fields.s)
		arbytes->fields.seg_type |= 1; /* accessed */
	arbytes->fields.dpl = (entry >> (13+32)) & 0x3; /* DPL */
	arbytes->fields.p = (entry >> (15+32)) & 0x1; /* P */
	arbytes->fields.avl = (entry >> (20+32)) & 0x1; /* AVL */
	arbytes->fields.default_ops_size = (entry >> (22+32)) & 0x1; /* D */

	if (entry & (1ULL << (23+32))) { /* G */
		arbytes->fields.g = 1;
		*limit = (*limit << 12) | 0xFFF;
	}

	return 1;
}

/*
 * Transition to protected mode
 */
void
protected_mode(struct regs *regs)
{
	regs->eflags &= ~(EFLAGS_TF|EFLAGS_VM);

	oldctx.eip = regs->eip;
	oldctx.esp = regs->uesp;
	oldctx.eflags = regs->eflags;

	/* reload all segment registers */
	if (!load_seg(regs->cs, &oldctx.cs_base,
				&oldctx.cs_limit, &oldctx.cs_arbytes))
		panic("Invalid %%cs=0x%x for protected mode\n", regs->cs);
	oldctx.cs_sel = regs->cs;

	if (load_seg(regs->ves, &oldctx.es_base,
				&oldctx.es_limit, &oldctx.es_arbytes))
		oldctx.es_sel = regs->ves;
    else {
        load_seg(0, &oldctx.es_base,&oldctx.es_limit, &oldctx.es_arbytes);
        oldctx.es_sel = 0;
    }

	if (load_seg(regs->uss, &oldctx.ss_base,
				&oldctx.ss_limit, &oldctx.ss_arbytes))
		oldctx.ss_sel = regs->uss;
    else {
        load_seg(0, &oldctx.ss_base, &oldctx.ss_limit, &oldctx.ss_arbytes);
        oldctx.ss_sel = 0;
    }

	if (load_seg(regs->vds, &oldctx.ds_base,
				&oldctx.ds_limit, &oldctx.ds_arbytes))
		oldctx.ds_sel = regs->vds;
    else {
        load_seg(0, &oldctx.ds_base, &oldctx.ds_limit, &oldctx.ds_arbytes);
        oldctx.ds_sel = 0;
    }

	if (load_seg(regs->vfs, &oldctx.fs_base,
				&oldctx.fs_limit, &oldctx.fs_arbytes))
		oldctx.fs_sel = regs->vfs;
    else {
        load_seg(0, &oldctx.fs_base, &oldctx.fs_limit, &oldctx.fs_arbytes);
        oldctx.fs_sel = 0;
    }

	if (load_seg(regs->vgs, &oldctx.gs_base,
				&oldctx.gs_limit, &oldctx.gs_arbytes))
		oldctx.gs_sel = regs->vgs;
    else {
        load_seg(0, &oldctx.gs_base, &oldctx.gs_limit, &oldctx.gs_arbytes);
        oldctx.gs_sel = 0;
    }

	/* initialize jump environment to warp back to protected mode */
	regs->cs = CODE_SELECTOR;
	regs->ds = DATA_SELECTOR;
	regs->es = DATA_SELECTOR;
	regs->fs = DATA_SELECTOR;
	regs->gs = DATA_SELECTOR;
	regs->eip = (unsigned) &switch_to_protected_mode;

	/* this should get us into 32-bit mode */
}

/*
 * Start real-mode emulation
 */
void
real_mode(struct regs *regs)
{
	regs->eflags |= EFLAGS_VM | 0x02;
	regs->ds = DATA_SELECTOR;
	regs->es = DATA_SELECTOR;
	regs->fs = DATA_SELECTOR;
	regs->gs = DATA_SELECTOR;

	/*
	 * When we transition from protected to real-mode and we
	 * have not reloaded the segment descriptors yet, they are
	 * interpreted as if they were in protect mode.
	 * We emulate this behavior by assuming that these memory
	 * reference are below 1MB and set %ss, %ds, %es accordingly.
	 */
	if (regs->uss != 0) {
		if (regs->uss >= HIGHMEM)
			panic("%%ss 0x%lx higher than 1MB", regs->uss);
		regs->uss = address(regs, regs->uss, 0) >> 4;
	}
	if (regs->vds != 0) {
		if (regs->vds >= HIGHMEM)
			panic("%%ds 0x%lx higher than 1MB", regs->vds);
		regs->vds = address(regs, regs->vds, 0) >> 4;
	}
	if (regs->ves != 0) {
		if (regs->ves >= HIGHMEM)
			panic("%%es 0x%lx higher than 1MB", regs->ves);
		regs->ves = address(regs, regs->ves, 0) >> 4;
	}

	/* this should get us into 16-bit mode */
}

/*
 * This is the smarts of the emulator and handles the mode transitions. The
 * emulator handles 4 different modes. 1) VM86_REAL: emulated real-mode, Just
 * handle those instructions that are not supported under VM8086.
 * 2) VM86_REAL_TO_PROTECTED: going from real-mode to protected mode. In this
 * we single step through the instructions until we reload the new %cs (some
 * OSes do a lot of computations before reloading %cs). 2) VM86_PROTECTED_TO_REAL
 * when we are going from protected to real mode. In this case we emulate the
 * instructions by hand. Finally, 4) VM86_PROTECTED when we transitioned to
 * protected mode and we should abandon the emulator. No instructions are
 * emulated when in VM86_PROTECTED mode.
 */
void
set_mode(struct regs *regs, enum vm86_mode newmode)
{
	switch (newmode) {
	case VM86_REAL:
		if (mode == VM86_PROTECTED_TO_REAL) {
			real_mode(regs);
			break;
		} else if (mode == VM86_REAL) {
			break;
		} else
			panic("unexpected real mode transition");
		break;

	case VM86_REAL_TO_PROTECTED:
		if (mode == VM86_REAL) {
			regs->eflags |= EFLAGS_TF;
			break;
		} else if (mode == VM86_REAL_TO_PROTECTED) {
			break;
		} else
			panic("unexpected real-to-protected mode transition");
		break;

	case VM86_PROTECTED_TO_REAL:
		if (mode == VM86_PROTECTED)
			break;
		else
			panic("unexpected protected-to-real mode transition");

	case VM86_PROTECTED:
		if (mode == VM86_REAL_TO_PROTECTED) {
			protected_mode(regs);
			break;
		} else
			panic("unexpected protected mode transition");
		break;
	}

	mode = newmode;
	TRACE((regs, 0, states[mode]));
}

void
jmpl(struct regs *regs, int prefix)
{
	unsigned n = regs->eip;
	unsigned cs, eip;

	if (mode == VM86_REAL_TO_PROTECTED) { /* jump to protected mode */
		eip = (prefix & DATA32) ? fetch32(regs) : fetch16(regs);
		cs = fetch16(regs);

		TRACE((regs, (regs->eip - n) + 1, "jmpl 0x%x:0x%x", cs, eip));

                regs->cs = cs;
                regs->eip = eip;
		set_mode(regs, VM86_PROTECTED);
	} else if (mode == VM86_PROTECTED_TO_REAL) { /* jump to real mode */
		eip = (prefix & DATA32) ? fetch32(regs) : fetch16(regs);
		cs = fetch16(regs);

		TRACE((regs, (regs->eip - n) + 1, "jmpl 0x%x:0x%x", cs, eip));

                regs->cs = cs;
                regs->eip = eip;
		set_mode(regs, VM86_REAL);
	} else
		panic("jmpl");
}

void
retl(struct regs *regs, int prefix)
{
	unsigned cs, eip;

	if (prefix & DATA32) {
		eip = pop32(regs);
		cs = MASK16(pop32(regs));
	} else {
		eip = pop16(regs);
		cs = pop16(regs);
	}

	TRACE((regs, 1, "retl (to 0x%x:0x%x)", cs, eip));

	if (mode == VM86_REAL_TO_PROTECTED) { /* jump to protected mode */
                regs->cs = cs;
                regs->eip = eip;
		set_mode(regs, VM86_PROTECTED);
	} else if (mode == VM86_PROTECTED_TO_REAL) { /* jump to real mode */
                regs->cs = cs;
                regs->eip = eip;
		set_mode(regs, VM86_REAL);
	} else
		panic("retl");
}

void
interrupt(struct regs *regs, int n)
{
	TRACE((regs, 0, "external interrupt %d", n));
	push16(regs, regs->eflags);
	push16(regs, regs->cs);
	push16(regs, regs->eip);
	regs->eflags &= ~EFLAGS_IF;
	regs->eip = read16(address(regs, 0, n * 4));
	regs->cs = read16(address(regs, 0, n * 4 + 2));
}

/*
 * Most port I/O operations are passed unmodified. We do have to be
 * careful and make sure the emulated program isn't remapping the
 * interrupt vectors. The following simple state machine catches
 * these attempts and rewrites them.
 */
int
outbyte(struct regs *regs, unsigned prefix, unsigned opc)
{
	static char icw2[2] = { 0 };
	int al, port;

	switch (opc) {
	case 0xE6: /* outb port, al */
		port = fetch8(regs);
		break;
	case 0xEE: /* outb (%dx), al */
		port = MASK16(regs->edx);
		break;
	default:
		return 0;
	}

	al = regs->eax & 0xFF;

	switch (port) {
	case PIC_MASTER + PIC_CMD:
		if (al & (1 << 4)) /* A0=0,D4=1 -> ICW1 */
			icw2[0] = 1;
		break;
	case PIC_MASTER + PIC_IMR:
		if (icw2[0]) {
			icw2[0] = 0;
			printf("Remapping master: ICW2 0x%x -> 0x%x\n",
				al, NR_EXCEPTION_HANDLER);
			al = NR_EXCEPTION_HANDLER;
		}
		break;

	case PIC_SLAVE  + PIC_CMD:
		if (al & (1 << 4)) /* A0=0,D4=1 -> ICW1 */
			icw2[1] = 1;
		break;
	case PIC_SLAVE  + PIC_IMR:
		if (icw2[1]) {
			icw2[1] = 0;
			printf("Remapping slave: ICW2 0x%x -> 0x%x\n",
				al, NR_EXCEPTION_HANDLER+8);
			al = NR_EXCEPTION_HANDLER+8;
		}
		break;
	}

	outb(port, al);
	return 1;
}

int
inbyte(struct regs *regs, unsigned prefix, unsigned opc)
{
	int port;

	switch (opc) {
	case 0xE4: /* inb al, port */
		port = fetch8(regs);
		break;
	case 0xEC: /* inb al, (%dx) */
		port = MASK16(regs->edx);
		break;
	default:
		return 0;
	}

	regs->eax = (regs->eax & ~0xFF) | inb(port);
	return 1;
}

enum { OPC_INVALID, OPC_EMULATED };

/*
 * Emulate a single instruction, including all its prefixes. We only implement
 * a small subset of the opcodes, and not all opcodes are implemented for each
 * of the four modes we can operate in.
 */
int
opcode(struct regs *regs)
{
	unsigned eip = regs->eip;
	unsigned opc, modrm, disp;
	unsigned prefix = 0;

	for (;;) {
		switch ((opc = fetch8(regs))) {
		case 0x0F: /* two byte opcode */
			if (mode == VM86_PROTECTED)
				goto invalid;
			switch ((opc = fetch8(regs))) {
			case 0x01:
				switch (((modrm = fetch8(regs)) >> 3) & 7) {
				case 0: /* sgdt */
				case 1: /* sidt */
					goto invalid;
				case 2: /* lgdt */
					if (!lgdt(regs, prefix, modrm))
						goto invalid;
					return OPC_EMULATED;
				case 3: /* lidt */
					if (!lidt(regs, prefix, modrm))
						goto invalid;
					return OPC_EMULATED;
				case 4: /* smsw */
					goto invalid;
				case 5:
					goto invalid;
				case 6: /* lmsw */
					if (!lmsw(regs, prefix, modrm))
						goto invalid;
					return OPC_EMULATED;
				case 7: /* invlpg */
					goto invalid;
				}
				break;
			case 0x09: /* wbinvd */
				return OPC_EMULATED;
			case 0x20: /* mov Rd, Cd (1h) */
			case 0x22:
				if (!movcr(regs, prefix, opc))
					goto invalid;
				return OPC_EMULATED;
			default:
				goto invalid;
			}
			goto invalid;

		case 0x26:
			TRACE((regs, regs->eip - eip, "%%es:"));
			prefix |= SEG_ES;
			continue;

		case 0x2E:
			TRACE((regs, regs->eip - eip, "%%cs:"));
			prefix |= SEG_CS;
			continue;

		case 0x36:
			TRACE((regs, regs->eip - eip, "%%ss:"));
			prefix |= SEG_SS;
			continue;

		case 0x3E:
			TRACE((regs, regs->eip - eip, "%%ds:"));
			prefix |= SEG_DS;
			continue;

		case 0x64:
			TRACE((regs, regs->eip - eip, "%%fs:"));
			prefix |= SEG_FS;
			continue;

		case 0x65:
			TRACE((regs, regs->eip - eip, "%%gs:"));
			prefix |= SEG_GS;
			continue;

		case 0x66:
			TRACE((regs, regs->eip - eip, "data32"));
			prefix |= DATA32;
			continue;

		case 0x67: 
			TRACE((regs, regs->eip - eip, "addr32"));
			prefix |= ADDR32;
			continue;

		case 0x90: /* nop */
			TRACE((regs, regs->eip - eip, "nop"));
			return OPC_EMULATED;

		case 0x9C: /* pushf */
			TRACE((regs, regs->eip - eip, "pushf"));
			if (prefix & DATA32)
				push32(regs, regs->eflags & ~EFLAGS_VM);
			else
				push16(regs, regs->eflags & ~EFLAGS_VM);
			return OPC_EMULATED;

		case 0x9D:	/* popf */
			TRACE((regs, regs->eip - eip, "popf"));
			if (prefix & DATA32)
				regs->eflags = pop32(regs);
			else
				regs->eflags = (regs->eflags & 0xFFFF0000L) |
								pop16(regs);
			regs->eflags |= EFLAGS_VM;
			return OPC_EMULATED;

		case 0xCB:	/* retl */
			if ((mode == VM86_REAL_TO_PROTECTED) ||
			    (mode == VM86_PROTECTED_TO_REAL)) {
				retl(regs, prefix);
				return OPC_EMULATED;
			}
			goto invalid;

		case 0xCD:	/* int $n */
			TRACE((regs, regs->eip - eip, "int"));
			interrupt(regs, fetch8(regs));
			return OPC_EMULATED;

		case 0xCF:	/* iret */
			if (prefix & DATA32) {
				TRACE((regs, regs->eip - eip, "data32 iretd"));
				regs->eip = pop32(regs);
				regs->cs = pop32(regs);
				regs->eflags = pop32(regs);
			} else {
				TRACE((regs, regs->eip - eip, "iret"));
				regs->eip = pop16(regs);
				regs->cs = pop16(regs);
				regs->eflags = (regs->eflags & 0xFFFF0000L) |
								pop16(regs);
			}
			return OPC_EMULATED;

		case 0xE4:	/* inb al, port */
			if (!inbyte(regs, prefix, opc))
				goto invalid;
			return OPC_EMULATED;

		case 0xE6:	/* outb port, al */
			if (!outbyte(regs, prefix, opc))
				goto invalid;
			return OPC_EMULATED;

		case 0xEA: 	/* jmpl */
			if ((mode == VM86_REAL_TO_PROTECTED) ||
			    (mode == VM86_PROTECTED_TO_REAL)) {
				jmpl(regs, prefix);
				return OPC_EMULATED;
			}
			goto invalid;

		case 0xEB:	/* short jump */
			if ((mode == VM86_REAL_TO_PROTECTED) ||
			    (mode == VM86_PROTECTED_TO_REAL)) {
				disp = (char) fetch8(regs);
				TRACE((regs, 2, "jmp 0x%x", regs->eip + disp));
				regs->eip += disp;
				return OPC_EMULATED;
			}
			goto invalid;

		case 0xEC:	/* inb al, (%dx) */
			if (!inbyte(regs, prefix, opc))
				goto invalid;
			return OPC_EMULATED;

		case 0xEE:	/* outb (%dx), al */
			if (!outbyte(regs, prefix, opc))
				goto invalid;
			return OPC_EMULATED;

		case 0xF0:	/* lock */
			TRACE((regs, regs->eip - eip, "lock"));
			continue;

		case 0xFA:	/* cli */
			TRACE((regs, regs->eip - eip, "cli"));
			regs->eflags &= ~EFLAGS_IF;
			return OPC_EMULATED;

		case 0xFB:	/* sti */
			TRACE((regs, regs->eip - eip, "sti"));
			regs->eflags |= EFLAGS_IF;
			return OPC_EMULATED;

		default:
			goto invalid;
		}
	}

invalid:
	regs->eip = eip;
	return OPC_INVALID;
}

void
emulate(struct regs *regs)
{
	unsigned flteip;
	int nemul = 0;

	/* emulate as many instructions as possible */
	while (opcode(regs) != OPC_INVALID)
		nemul++;

	/* detect the case where we are not making progress */
	if (nemul == 0 && prev_eip == regs->eip) {
		flteip = address(regs, MASK16(regs->cs), regs->eip);
		panic("Unknown opcode at %04x:%04x=0x%x",
			MASK16(regs->cs), regs->eip, flteip);
	} else
		prev_eip = regs->eip;
}

void
trap(int trapno, int errno, struct regs *regs)
{
	/* emulate device interrupts */
	if (trapno >= NR_EXCEPTION_HANDLER) {
		int irq = trapno - NR_EXCEPTION_HANDLER;
		if (irq < 8) 
			interrupt(regs, irq + 8);
		else
			interrupt(regs, 0x70 + (irq - 8));
		return;
	}

	switch (trapno) {
	case 1: /* Debug */
		if (regs->eflags & EFLAGS_VM) {
			/* emulate any 8086 instructions  */
			if (mode != VM86_REAL_TO_PROTECTED)
				panic("not in real-to-protected mode");
			emulate(regs);
			return;
		}
		goto invalid;

	case 13: /* GPF */
		if (regs->eflags & EFLAGS_VM) {
			/* emulate any 8086 instructions  */
			if (mode == VM86_PROTECTED)
				panic("unexpected protected mode");
			emulate(regs);
			return;
		}
		goto invalid;

	default:
	invalid:
		printf("Trap (0x%x) while in %s mode\n",
		    trapno, regs->eflags & EFLAGS_VM ? "real" : "protected");
		if (trapno == 14)
			printf("Page fault address 0x%x\n", get_cr2());
		dump_regs(regs);
		halt();
	}
}

