/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/i386/i386/db_interface.c,v 1.77 2003/11/08 03:01:26 alc Exp $");

/*
 * Interface to new debugger.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/reboot.h>
#include <sys/cons.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>

#include <machine/cpu.h>
#ifdef SMP
#include <machine/smptests.h>	/** CPUSTOP_ON_DDBBREAK */
#endif

#include <vm/vm.h>
#include <vm/pmap.h>

#include <ddb/ddb.h>

#include <machine/setjmp.h>
#include <machine/xenfunc.h>


static jmp_buf *db_nofault = 0;
extern jmp_buf	db_jmpbuf;

extern void	gdb_handle_exception(db_regs_t *, int, int);

int	db_active;
db_regs_t ddb_regs;

static __inline u_short
rss(void)
{
	u_short ss;
#ifdef __GNUC__
	__asm __volatile("mov %%ss,%0" : "=r" (ss));
#else
	ss = 0; /* XXXX Fix for other compilers. */
#endif
	return ss;
}

/*
 *  kdb_trap - field a TRACE or BPT trap
 */
int
kdb_trap(int type, int code, struct i386_saved_state *regs)
{
	volatile int ddb_mode = !(boothowto & RB_GDB);

	disable_intr();

	if (ddb_mode) {
	    	/* we can't do much as a guest domain except print a 
		 * backtrace and die gracefuly.  The reason is that we
		 * can't get character input to make this work.
		 */
	    	db_active = 1;
		db_print_backtrace(); 
		db_printf("************ Domain shutting down ************\n");
		HYPERVISOR_shutdown();
	} else {
	    	Debugger("kdb_trap");
	}
	return (1);
}

/*
 * Read bytes from kernel address space for debugger.
 */
void
db_read_bytes(vm_offset_t addr, size_t size, char *data)
{
	char	*src;

	db_nofault = &db_jmpbuf;

	src = (char *)addr;
	while (size-- > 0)
	    *data++ = *src++;

	db_nofault = 0;
}

/*
 * Write bytes to kernel address space for debugger.
 */
void
db_write_bytes(vm_offset_t addr, size_t size, char *data)
{
	char	*dst;

	pt_entry_t	*ptep0 = NULL;
	pt_entry_t	oldmap0 = 0;
	vm_offset_t	addr1;
	pt_entry_t	*ptep1 = NULL;
	pt_entry_t	oldmap1 = 0;

	db_nofault = &db_jmpbuf;

	if (addr > trunc_page((vm_offset_t)btext) - size &&
	    addr < round_page((vm_offset_t)etext)) {

	    ptep0 = pmap_pte(kernel_pmap, addr);
	    oldmap0 = *ptep0;
	    *ptep0 |= PG_RW;

	    /* Map another page if the data crosses a page boundary. */
	    if ((*ptep0 & PG_PS) == 0) {
	    	addr1 = trunc_page(addr + size - 1);
	    	if (trunc_page(addr) != addr1) {
		    ptep1 = pmap_pte(kernel_pmap, addr1);
		    oldmap1 = *ptep1;
		    *ptep1 |= PG_RW;
	    	}
	    } else {
		addr1 = trunc_4mpage(addr + size - 1);
		if (trunc_4mpage(addr) != addr1) {
		    ptep1 = pmap_pte(kernel_pmap, addr1);
		    oldmap1 = *ptep1;
		    *ptep1 |= PG_RW;
		}
	    }

	    invltlb();
	}

	dst = (char *)addr;

	while (size-- > 0)
	    *dst++ = *data++;

	db_nofault = 0;

	if (ptep0) {
	    *ptep0 = oldmap0;

	    if (ptep1)
		*ptep1 = oldmap1;

	    invltlb();
	}
}

/*
 * XXX
 * Move this to machdep.c and allow it to be called if any debugger is
 * installed.
 */
void
Debugger(const char *msg)
{
	static volatile u_int in_Debugger;

	/*
	 * XXX
	 * Do nothing if the console is in graphics mode.  This is
	 * OK if the call is for the debugger hotkey but not if the call
	 * is a weak form of panicing.
	 */
	if (cons_unavail && !(boothowto & RB_GDB))
	    return;

	if (atomic_cmpset_acq_int(&in_Debugger, 0, 1)) {
	    db_printf("Debugger(\"%s\")\n", msg);
	    breakpoint();
	    atomic_store_rel_int(&in_Debugger, 0);
	}
}

void
db_show_mdpcpu(struct pcpu *pc)
{

	db_printf("APIC ID      = %d\n", pc->pc_apic_id);
	db_printf("currentldt   = 0x%x\n", pc->pc_currentldt);
}
