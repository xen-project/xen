/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 * xen/arch/x86/include/asm/debugger.h
 *
 * x86-specific debugger hooks.
 */
#ifndef __X86_DEBUGGER_H__
#define __X86_DEBUGGER_H__

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

#endif /* __X86_DEBUGGER_H__ */
