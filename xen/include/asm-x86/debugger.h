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
 *  deliberately caused traps (which you then handle and return non-zero).
 *
 * 3. debugger_trap_immediate():
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

static inline bool debugger_trap_entry(
    unsigned int vector, struct cpu_user_regs *regs)
{
    /*
     * This function is called before any checks are made.  Amongst other
     * things, be aware that during early boot, current is not a safe pointer
     * to follow.
     */
    struct vcpu *v = current;

    if ( vector != TRAP_int3 && vector != TRAP_debug )
        return false;

    if ( guest_mode(regs) && guest_kernel_mode(v, regs) &&
         v->domain->debugger_attached  )
    {
        if ( vector != TRAP_debug ) /* domain pause is good enough */
            current->arch.gdbsx_vcpu_event = vector;
        domain_pause_for_debugger();
        return true;
    }

    return false;
}

unsigned int dbg_rw_mem(void * __user addr, void * __user buf,
                        unsigned int len, domid_t domid, bool_t toaddr,
                        uint64_t pgd3);

#endif /* __X86_DEBUGGER_H__ */
