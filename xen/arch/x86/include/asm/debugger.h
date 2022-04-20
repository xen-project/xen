/* SPDX-License-Identifier: GPL-2.0 */
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

#ifdef CONFIG_CRASH_DEBUG

#include <xen/gdbstub.h>
#include <xen/stdbool.h>

#include <asm/x86-defns.h>

/* Returns true if GDB handled the trap, or it is surviveable. */
static inline bool debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    int rc = __trap_to_gdb(regs, vector);

    if ( rc == 0 )
        return true;

    return vector == X86_EXC_BP;
}

/* Int3 is a trivial way to gather cpu_user_regs context. */
#define debugger_trap_immediate() __asm__ __volatile__ ( "int3" )

#else

static inline bool debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return false;
}

#define debugger_trap_immediate() ((void)0)

#endif

#endif /* __X86_DEBUGGER_H__ */
