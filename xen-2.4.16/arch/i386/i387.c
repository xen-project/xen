/*
 *  linux/arch/i386/kernel/i387.c
 *
 *  Copyright (C) 1994 Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/processor.h>
#include <asm/i387.h>

void init_fpu(void)
{
    __asm__("fninit");
    if ( cpu_has_xmm ) load_mxcsr(0x1f80);
    current->flags |= PF_DONEFPUINIT;
}

static inline void __save_init_fpu( struct task_struct *tsk )
{
    if ( cpu_has_fxsr ) {
        asm volatile( "fxsave %0 ; fnclex"
                      : "=m" (tsk->thread.i387.fxsave) );
    } else {
        asm volatile( "fnsave %0 ; fwait"
                      : "=m" (tsk->thread.i387.fsave) );
    }
    tsk->flags &= ~PF_USEDFPU;
}

void save_init_fpu( struct task_struct *tsk )
{
    /*
     * The guest OS may have set the 'virtual STTS' flag.
     * This causes us to set the real flag, so we'll need
     * to temporarily clear it while saving f-p state.
     */
    if ( tsk->flags & PF_GUEST_STTS ) clts();
    __save_init_fpu(tsk);
    stts();
}

void restore_fpu( struct task_struct *tsk )
{
    if ( cpu_has_fxsr ) {
        asm volatile( "fxrstor %0"
                      : : "m" (tsk->thread.i387.fxsave) );
    } else {
        asm volatile( "frstor %0"
                      : : "m" (tsk->thread.i387.fsave) );
    }
}
