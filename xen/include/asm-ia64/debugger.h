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

#ifndef __ASM_DEBUGGER_H__
#define __ASM_DEBUGGER_H__

/* The main trap handlers use these helper macros which include early bail. */
static inline int debugger_trap_entry(
    unsigned int vector, struct xen_regs *regs)
{
    return 0;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct xen_regs *regs)
{
    return 0;
}

#define debugger_trap_immediate() do {} while(0)

#endif /* __ASM_DEBUGGER_H__ */
