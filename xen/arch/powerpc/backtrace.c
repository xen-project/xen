/*
 * Routines providing a simple monitor for use on the PowerMac.
 *
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <xen/symbols.h>
#include <asm/debugger.h>

static char namebuf[KSYM_NAME_LEN+1];

/* Shamelessly lifted from Linux Xmon try to keep pristene */
#ifdef __powerpc64__
#define LRSAVE_OFFSET		0x10
#define REG_FRAME_MARKER	0x7265677368657265ul	/* "regshere" */
#define MARKER_OFFSET		0x60
#define REGS_OFFSET		0x70
#define REG "%016lX"
#else
#define LRSAVE_OFFSET		4
#define REG_FRAME_MARKER	0x72656773
#define MARKER_OFFSET		8
#define REGS_OFFSET		16
#define REG "%08lX"
#endif

#define TRAP(regs) ((regs)->entry_vector & ~0xF)
static int xmon_depth_to_print = 64;

/* Very cheap human name for vector lookup. */
static
const char *getvecname(unsigned long vec)
{
	char *ret;

	switch (vec) {
	case 0x100:	ret = "(System Reset)"; break;
	case 0x200:	ret = "(Machine Check)"; break;
	case 0x300:	ret = "(Data Access)"; break;
	case 0x380:	ret = "(Data SLB Access)"; break;
	case 0x400:	ret = "(Instruction Access)"; break;
	case 0x480:	ret = "(Instruction SLB Access)"; break;
	case 0x500:	ret = "(Hardware Interrupt)"; break;
	case 0x600:	ret = "(Alignment)"; break;
	case 0x700:	ret = "(Program Check)"; break;
	case 0x800:	ret = "(FPU Unavailable)"; break;
	case 0x900:	ret = "(Decrementer)"; break;
	case 0xc00:	ret = "(System Call)"; break;
	case 0xd00:	ret = "(Single Step)"; break;
	case 0xf00:	ret = "(Performance Monitor)"; break;
	case 0xf20:	ret = "(Altivec Unavailable)"; break;
	case 0x1300:	ret = "(Instruction Breakpoint)"; break;
	default: ret = "";
	}
	return ret;
}

static int mread(unsigned long adrs, void *buf, int size)
{
    memcpy(buf, (void *)adrs, size);
    return size;
}

static void get_function_bounds(unsigned long pc, unsigned long *startp,
				unsigned long *endp)
{
    unsigned long size, offset;
	const char *name;

    *startp = *endp = 0;
	if (pc == 0)
		return;

    name = symbols_lookup(pc, &size, &offset, namebuf);
    if (name != NULL) {
			*startp = pc - offset;
			*endp = pc - offset + size;
    }
}
    
/* Print an address in numeric and symbolic form (if possible) */
static void xmon_print_symbol(unsigned long address, const char *mid,
                              const char *after)
{
	const char *name = NULL;
	unsigned long offset, size;

	printk(REG, address);

    name = symbols_lookup(address, &size, &offset, namebuf);
	if (name) {
		printk("%s%s+%#lx/%#lx", mid, name, offset, size);
	}
	printk("%s", after);
}

static void backtrace(
    unsigned long sp, unsigned long lr, unsigned long pc)
{
	unsigned long ip;
	unsigned long newsp;
	unsigned long marker;
	int count = 0;
	struct cpu_user_regs regs;

	do {
		if (sp > xenheap_phys_end) {
			if (sp != 0)
				printk("SP (%lx) is not in xen space\n", sp);
			break;
		}

		if (!mread(sp + LRSAVE_OFFSET, &ip, sizeof(unsigned long))
		    || !mread(sp, &newsp, sizeof(unsigned long))) {
			printk("Couldn't read stack frame at %lx\n", sp);
			break;
		}

		/*
		 * For the first stack frame, try to work out if
		 * LR and/or the saved LR value in the bottommost
		 * stack frame are valid.
		 */
		if ((pc | lr) != 0) {
			unsigned long fnstart, fnend;
			unsigned long nextip;
			int printip = 1;

			get_function_bounds(pc, &fnstart, &fnend);
			nextip = 0;
			if (newsp > sp)
				mread(newsp + LRSAVE_OFFSET, &nextip,
				      sizeof(unsigned long));
			if (lr == ip) {
				if (lr >= xenheap_phys_end
				    || (fnstart <= lr && lr < fnend))
					printip = 0;
			} else if (lr == nextip) {
				printip = 0;
			} else if (lr < xenheap_phys_end
                       && !(fnstart <= lr && lr < fnend)) {
				printk("[link register   ] ");
				xmon_print_symbol(lr, " ", "\n");
			}
			if (printip) {
				printk("["REG"] ", sp);
				xmon_print_symbol(ip, " ", " (unreliable)\n");
			}
			pc = lr = 0;

		} else {
			printk("["REG"] ", sp);
			xmon_print_symbol(ip, " ", "\n");
		}

		/* Look for "regshere" marker to see if this is
		   an exception frame. */
		if (mread(sp + MARKER_OFFSET, &marker, sizeof(unsigned long))
		    && marker == REG_FRAME_MARKER) {
			if (mread(sp + REGS_OFFSET, &regs, sizeof(regs))
			    != sizeof(regs)) {
				printk("Couldn't read registers at %lx\n",
				       sp + REGS_OFFSET);
				break;
			}
            printk("--- Exception: %x %s at ", regs.entry_vector,
			       getvecname(TRAP(&regs)));
			pc = regs.pc;
			lr = regs.lr;
			xmon_print_symbol(pc, " ", "\n");
		}

		if (newsp == 0)
			break;
        
		sp = newsp;
	} while (count++ < xmon_depth_to_print);
}

void show_backtrace(ulong sp, ulong lr, ulong pc)
{
    console_start_sync();
    backtrace(sp, lr, pc);
    console_end_sync();
}

void show_backtrace_regs(struct cpu_user_regs *regs)
{
    console_start_sync();
    
    show_registers(regs);
    printk("hid4 0x%016lx\n", regs->hid4);
    printk("---[ backtrace ]---\n");
    show_backtrace(regs->gprs[1], regs->lr, regs->pc);

    console_end_sync();
}

void dump_execution_state(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    show_registers(regs);
    if (regs->msr & MSR_HV) {
        printk("In Xen:\n");
        show_backtrace(regs->gprs[1], regs->pc, regs->lr);
    }
}
