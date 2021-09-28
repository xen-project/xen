/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 * Arch specific debuggers should implement:
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

#ifndef __XEN_DEBUGGER_H__
#define __XEN_DEBUGGER_H__

#ifdef CONFIG_CRASH_DEBUG

#include <asm/debugger.h>

#else

#include <xen/stdbool.h>

struct cpu_user_regs;

static inline bool debugger_trap_fatal(
    unsigned int vector, const struct cpu_user_regs *regs)
{
    return false;
}

static inline void debugger_trap_immediate(void)
{
}

#endif /* CONFIG_CRASH_DEBUG */

#endif /* __XEN_DEBUGGER_H__ */
