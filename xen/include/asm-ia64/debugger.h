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

#include <xen/softirq.h>

// this number is an arbitary number which is not used for any other purpose
// __builtin_trap(), FORCE_CRASH() 0x0
// ski  0x80001, 0x80002
// kdb  0x80100, 0x80101
// kprobe 0x80200, jprobe 0x80300
// kgdb 0x6665
// gdb 0x99998 (#define IA64_BREAKPOINT 0x00003333300LL)

// cdb should handle 0 and CDB_BREAK_NUM.
#define CDB_BREAK_NUM	0x80800


#ifndef __ASSEMBLY__

#include <xen/gdbstub.h>

// NOTE: on xen struct pt_regs = struct cpu_user_regs
//       see include/asm-ia64/linux-xen/asm/ptrace.h
#ifdef CRASH_DEBUG
// crash_debug=y

/* The main trap handlers use these helper macros which include early bail. */
static inline int debugger_trap_entry(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return 0;
}

extern int __trap_to_cdb(struct cpu_user_regs *r);
static inline int debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
	(void)__trap_to_gdb(regs, vector);
    return 0;
}

#define ____debugger_trap_immediate(b) __asm__ __volatile__ ("break.m "#b"\n")
#define __debugger_trap_immediate(b) ____debugger_trap_immediate(b)
#define debugger_trap_immediate() __debugger_trap_immediate(CDB_BREAK_NUM)

//XXX temporal work around
#ifndef CONFIG_SMP
#define smp_send_stop()	/* nothing */
#endif

#elif defined DOMU_DEBUG
// domu_debug=y
#warning "domu_debug is not implemented yet."
/* The main trap handlers use these helper macros which include early bail. */
static inline int debugger_trap_entry(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return 0;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return 0;
}

#define debugger_trap_immediate()		((void)0)
#else
/* The main trap handlers use these helper macros which include early bail. */
static inline int debugger_trap_entry(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return 0;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct cpu_user_regs *regs)
{
    return 0;
}

#define debugger_trap_immediate()		((void)0)
#endif
#endif // __ASSEMBLLY__

#endif /* __ASM_DEBUGGER_H__ */
