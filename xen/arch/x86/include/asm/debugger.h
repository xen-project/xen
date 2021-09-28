/******************************************************************************
 * asm/debugger.h
 * 
 * Generic hooks into arch-dependent Xen.
 * 
 * Each debugger should define two functions here:
 * 
 * debugger_trap_fatal():
 *  Called when Xen is about to give up and crash. Typically you will use this
 *  hook to drop into a debug session. It can also be used to hook off
 *  deliberately caused traps (which you then handle and return non-zero).
 *
 * debugger_trap_immediate():
 *  Called if we want to drop into a debugger now.  This is essentially the
 *  same as debugger_trap_fatal, except that we use the current register state
 *  rather than the state which was in effect when we took the trap.
 *  For example: if we're dying because of an unhandled exception, we call
 *  debugger_trap_fatal; if we're dying because of a panic() we call
 *  debugger_trap_immediate().
 */

#ifndef __X86_DEBUGGER_H__
#define __X86_DEBUGGER_H__

#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/processor.h>

void domain_pause_for_debugger(void);

#ifdef CONFIG_CRASH_DEBUG

#include <xen/gdbstub.h>

static inline bool debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    int rc = __trap_to_gdb(regs, vector);
    return ((rc == 0) || (vector == TRAP_int3));
}

/* Int3 is a trivial way to gather cpu_user_regs context. */
#define debugger_trap_immediate() __asm__ __volatile__ ( "int3" );

#else

static inline bool debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return false;
}

#define debugger_trap_immediate() ((void)0)

#endif

#ifdef CONFIG_GDBSX
unsigned int dbg_rw_mem(unsigned long gva, XEN_GUEST_HANDLE_PARAM(void) buf,
                        unsigned int len, struct domain *d, bool toaddr,
                        uint64_t pgd3);
#endif

#endif /* __X86_DEBUGGER_H__ */
