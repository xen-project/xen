/******************************************************************************
 * asm/debugger.h
 * 
 * Generic hooks into arch-dependent Xen.
 * 
 * Each debugger should define two functions here:
 * 
 * 1. debugger_trap_entry(): 
 *  Called at start of any synchronous fault or trap, before any other work
 *  is done. The idea is that if your debugger deliberately caused the trap
 *  (e.g. to implement breakpoints or data watchpoints) then you can take
 *  appropriate action and return a non-zero value to cause early exit from
 *  the trap function.
 * 
 * 2. debugger_trap_fatal():
 *  Called when Xen is about to give up and crash. Typically you will use this
 *  hook to drop into a debug session. It can also be used to hook off
 *  deliberately caused traps (which you then handle and return non-zero)
 *  but really these should be hooked off 'debugger_trap_entry'.
 */

#ifndef __X86_DEBUGGER_H__
#define __X86_DEBUGGER_H__

#include <asm/processor.h>

/* The main trap handlers use these helper macros which include early bail. */
#define DEBUGGER_trap_entry(_v, _r) \
    if ( debugger_trap_entry(_v, _r) ) return EXCRET_fault_fixed;
#define DEBUGGER_trap_fatal(_v, _r) \
    if ( debugger_trap_fatal(_v, _r) ) return EXCRET_fault_fixed;

#ifdef XEN_DEBUGGER

#include <asm/pdb.h>

static inline int debugger_trap_entry(
    unsigned int vector, struct xen_regs *regs)
{
    int ret = 0;

    switch ( vector )
    {
    case TRAP_debug:
        if ( pdb_initialized )
        {
            pdb_handle_debug_trap(regs, regs->error_code);
            ret = 1; /* early exit */
        }
        break;

    case TRAP_int3:
        if ( pdb_initialized && (pdb_handle_exception(vector, regs) == 0) )
            ret = 1; /* early exit */
        break;

    case TRAP_gp_fault:        
        if ( (VM86_MODE(regs) || !RING_0(regs)) &&
             ((regs->error_code & 3) == 2) &&
             pdb_initialized && (pdb_ctx.system_call != 0) )
        {
            unsigned long cr3 = read_cr3();
            if ( cr3 == pdb_ctx.ptbr )
                pdb_linux_syscall_enter_bkpt(
                    regs, regs->error_code, 
                    current->thread.traps + (regs->error_code>>3));
        }
        break;
    }

    return ret;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct xen_regs *regs)
{
    int ret = 0;

    switch ( vector )
    {
    case TRAP_page_fault:
        if ( pdb_page_fault_possible )
        {
            pdb_page_fault = 1;
            /* make eax & edx valid to complete the instruction */
            regs->eax = (long)&pdb_page_fault_scratch;
            regs->edx = (long)&pdb_page_fault_scratch;
            ret = 1; /* exit - do not crash! */
        }
        break;
    }

    return ret;
}

#elif 0

extern int kdb_trap(int, int, struct xen_regs *);

static inline int debugger_trap_entry(
    unsigned int vector, struct xen_regs *regs)
{
    return 0;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct xen_regs *regs)
{
    return kdb_trap(vector, 0, regs);
}

#else

#define debugger_trap_entry(_v, _r) (0)
#define debugger_trap_fatal(_v, _r) (0)

#endif

#endif /* __X86_DEBUGGER_H__ */
