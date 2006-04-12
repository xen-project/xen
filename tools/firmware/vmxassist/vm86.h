/*
 * vm86.h: vm86 emulator definitions.
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
#ifndef __VM86_H__
#define __VM86_H__

#ifndef __ASSEMBLY__
#include <stdint.h>
#endif

#include <xen/hvm/vmx_assist.h>

#define	NR_EXCEPTION_HANDLER	32
#define	NR_INTERRUPT_HANDLERS	16
#define	NR_TRAPS		(NR_EXCEPTION_HANDLER+NR_INTERRUPT_HANDLERS)

#ifndef __ASSEMBLY__

struct regs {
        unsigned	edi, esi, ebp, esp, ebx, edx, ecx, eax;
        unsigned	ds, es, fs, gs;
        unsigned	trapno, errno;
        unsigned	eip, cs, eflags, uesp, uss;
        unsigned	ves, vds, vfs, vgs;
};

enum vm86_mode {
	VM86_REAL = 0,
	VM86_REAL_TO_PROTECTED,
	VM86_PROTECTED_TO_REAL,
	VM86_PROTECTED
};

#ifdef DEBUG
#define TRACE(a)        trace a
#else
#define TRACE(a)
#endif

extern enum vm86_mode prevmode, mode;
extern struct vmx_assist_context oldctx;
extern struct vmx_assist_context newctx;

extern void emulate(struct regs *);
extern void dump_regs(struct regs *);
extern void trace(struct regs *, int, char *, ...);

extern void set_mode(struct regs *, enum vm86_mode);
extern void switch_to_real_mode(void);
extern void switch_to_protected_mode(void);

#endif /* __ASSEMBLY__ */

#endif /* __VM86_H__ */
