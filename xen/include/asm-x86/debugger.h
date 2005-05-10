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
 *
 * 3. debugger_trap_immediate():
 *  Called if we want to drop into a debugger now.  This is essentially the
 *  same as debugger_trap_fatal, except that we use the current register state
 *  rather than the state which was in effect when we took the trap.
 *  Essentially, if we're dying because of an unhandled exception, we call
 *  debugger_trap_fatal; if we're dying because of a panic() we call
 *  debugger_trap_immediate().
 */

#ifndef __X86_DEBUGGER_H__
#define __X86_DEBUGGER_H__

#include <asm/processor.h>

/* The main trap handlers use these helper macros which include early bail. */
#define DEBUGGER_trap_entry(_v, _r) \
    if ( debugger_trap_entry(_v, _r) ) return EXCRET_fault_fixed;
#define DEBUGGER_trap_fatal(_v, _r) \
    if ( debugger_trap_fatal(_v, _r) ) return EXCRET_fault_fixed;

#if defined(CRASH_DEBUG)

extern int __trap_to_cdb(struct cpu_user_regs *r);
#define debugger_trap_entry(_v, _r) (0)

static inline int debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    (void)__trap_to_cdb(regs);
    return (vector == TRAP_int3); /* int3 is harmless */
}

/* Int3 is a trivial way to gather cpu_user_regs context. */
#define debugger_trap_immediate() __asm__ __volatile__ ( "int3" );

#elif defined(DOMU_DEBUG)

#include <xen/softirq.h>

static inline int debugger_trap_entry(
    unsigned int vector, struct cpu_user_regs *regs)
{
    struct exec_domain *ed = current;

    if ( !KERNEL_MODE(ed, regs) || (ed->domain->id == 0) )
        return 0;
    
    switch ( vector )
    {
    case TRAP_int3:
    case TRAP_debug:
        set_bit(EDF_CTRLPAUSE, &ed->flags);
        raise_softirq(SCHEDULE_SOFTIRQ);
        return 1;
    }

    return 0;
}

#define debugger_trap_fatal(_v, _r) (0)
#define debugger_trap_immediate()


#elif 0

extern int kdb_trap(int, int, struct cpu_user_regs *);

static inline int debugger_trap_entry(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return 0;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return kdb_trap(vector, 0, regs);
}

/* Int3 is a trivial way to gather cpu_user_regs context. */
#define debugger_trap_immediate() __asm__ __volatile__ ( "int3" );

#else

#define debugger_trap_entry(_v, _r) (0)
#define debugger_trap_fatal(_v, _r) (0)
#define debugger_trap_immediate()

#endif

#endif /* __X86_DEBUGGER_H__ */
