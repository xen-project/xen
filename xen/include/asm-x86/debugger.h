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

/* Avoid magic vector numbers by using these semi-sensical names. */
#define TRAP_divide_error     0
#define TRAP_debug            1
#define TRAP_nmi              2
#define TRAP_int3             3
#define TRAP_overflow         4
#define TRAP_bounds           5
#define TRAP_invalid_op       6
#define TRAP_no_device        7
#define TRAP_double_fault     8
#define TRAP_copro_seg        9
#define TRAP_invalid_tss     10
#define TRAP_no_segment      11
#define TRAP_stack_error     12
#define TRAP_gp_fault        13
#define TRAP_page_fault      14
#define TRAP_spurious_int    15
#define TRAP_copro_error     16
#define TRAP_alignment_check 17
#define TRAP_machine_check   18
#define TRAP_simd_error      19

/* The main trap handlers use these helper macros which include early bail. */
#define DEBUGGER_trap_entry(_v, _r, _e) \
    if ( debugger_trap_entry(_v, _r, _e) ) return;
#define DEBUGGER_trap_fatal(_v, _r, _e) \
    if ( debugger_trap_fatal(_v, _r, _e) ) return;

#ifdef XEN_DEBUGGER

#include <asm/pdb.h>

static inline int debugger_trap_entry(
    unsigned int vector, struct xen_regs *regs, unsigned int error_code)
{
    int ret = 0;

    switch ( vector )
    {
    case TRAP_debug:
        if ( pdb_initialized )
        {
            pdb_handle_debug_trap(regs, (long)error_code);
            ret = 1; /* early exit */
        }
        break;

    case TRAP_int3:
        if ( pdb_initialized && (pdb_handle_exception(vector, regs) == 0) )
            ret = 1; /* early exit */
        break;

    case TRAP_gp_fault:        
        if ( ((regs->cs & 3) != 0) && ((error_code & 3) == 2) &&
             pdb_initialized && (pdb_ctx.system_call != 0) )
        {
            unsigned long cr3 = read_cr3();
            if ( cr3 == pdb_ctx.ptbr )
                pdb_linux_syscall_enter_bkpt(
                    regs, error_code, current->thread.traps + (error_code>>3));
        }
        break;
    }

    return ret;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct xen_regs *regs, unsigned int error_code)
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
    unsigned int vector, struct xen_regs *regs, unsigned int error_code)
{
    return 0;
}

static inline int debugger_trap_fatal(
    unsigned int vector, struct xen_regs *regs, unsigned int error_code)
{
    return kdb_trap(vector, 0, regs);
}

#else

#define debugger_trap_entry(_v, _r, _e) (0)
#define debugger_trap_fatal(_v, _r, _e) (0)

#endif

#endif /* __X86_DEBUGGER_H__ */
