
/*
 * pervasive debugger
 * www.cl.cam.ac.uk/netos/pdb
 *
 * alex ho
 * 2004
 * university of cambridge computer laboratory
 *
 * linux & i386 dependent code. bleech.
 */

#include <asm/pdb.h>

/* offset to the first instruction in the linux system call code
   where we can safely set a breakpoint */
unsigned int pdb_linux_syscall_enter_bkpt_offset = 20;

/* offset to eflags saved on the stack after an int 80 */
unsigned int pdb_linux_syscall_eflags_offset     = 48;

/* offset to the instruction pointer saved on the stack after an int 80 */
unsigned int pdb_linux_syscall_eip_offset        = 40;

unsigned char
pdb_linux_set_bkpt (unsigned long addr)
{
    unsigned char old_instruction = *(unsigned char *)addr;
    *(unsigned char *)addr = 0xcc;
    return old_instruction;
}

void
pdb_linux_clr_bkpt (unsigned long addr, unsigned char value)
{
    *(unsigned char *)addr = value;
}

void
pdb_linux_syscall_enter_bkpt (struct xen_regs *regs, long error_code,
			      trap_info_t *ti)
{
    /* set at breakpoint at the beginning of the 
       system call in the target domain */
 
    pdb_system_call_enter_instr = pdb_linux_set_bkpt(ti->address +
				    pdb_linux_syscall_enter_bkpt_offset);
    pdb_system_call = 1;
}

void
pdb_linux_syscall_exit_bkpt (struct xen_regs *regs, struct pdb_context *pdb_ctx)
{
    /*
      we've hit an int 0x80 in a user's program, jumped into xen
      (traps.c::do_general_protection()) which re-wrote the next
      instruction in the os kernel to 0xcc, and then hit that 
      exception.

      we need to re-write the return instruction in the user's
      program so that we know when we have finished the system call
      and are back in the user's program.

      at this point our stack should look something like this:

      esp      = 0x80a59f0
      esp + 4  = 0x0
      esp + 8  = 0x80485a0
      esp + 12 = 0x2d
      esp + 16 = 0x80485f4
      esp + 20 = 0xbffffa48
      esp + 24 = 0xd
      esp + 28 = 0xc00a0833
      esp + 32 = 0x833
      esp + 36 = 0xd
      esp + 40 = 0x804dcdd     saved eip
      esp + 44 = 0x82b         saved cs
      esp + 48 = 0x213392      saved eflags
      esp + 52 = 0xbffffa2c    saved esp
      esp + 56 = 0x833         saved ss
      esp + 60 = 0x1000000
    */

    /* restore the entry instruction for the system call */
    pdb_linux_clr_bkpt(regs->eip - 1, pdb_system_call_enter_instr);

    /* save the address of eflags that was saved on the stack */
    pdb_system_call_eflags_addr = (regs->esp +
				   pdb_linux_syscall_eflags_offset);
 
    /* muck with the return instruction so that we trap back into the
       debugger when re-entering user space */
    pdb_system_call_next_addr = *(unsigned long *)(regs->esp + 
						 pdb_linux_syscall_eip_offset);
    pdb_linux_get_values (&pdb_system_call_leave_instr, 1, 
			  pdb_system_call_next_addr,
			  pdb_ctx->process, pdb_ctx->ptbr);
    pdb_linux_set_values ("cc", 1, pdb_system_call_next_addr,
			  pdb_ctx->process, pdb_ctx->ptbr);
}
