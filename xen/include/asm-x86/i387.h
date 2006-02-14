/*
 * include/asm-i386/i387.h
 *
 * Copyright (C) 1994 Linus Torvalds
 *
 * Pentium III FXSR, SSE support
 * General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#ifndef __ASM_I386_I387_H
#define __ASM_I386_I387_H

#include <xen/sched.h>
#include <asm/processor.h>

extern void init_fpu(void);
extern void save_init_fpu(struct vcpu *tsk);
extern void restore_fpu(struct vcpu *tsk);

#define unlazy_fpu(_tsk) do { \
    if ( test_bit(_VCPUF_fpu_dirtied, &(_tsk)->vcpu_flags) ) \
        save_init_fpu(_tsk); \
} while ( 0 )

#define load_mxcsr( val ) do { \
    unsigned long __mxcsr = ((unsigned long)(val) & 0xffbf); \
    __asm__ __volatile__ ( "ldmxcsr %0" : : "m" (__mxcsr) ); \
} while ( 0 )

/* Make domain the FPU owner */
static inline void setup_fpu(struct vcpu *v)
{
    if ( !test_and_set_bit(_VCPUF_fpu_dirtied, &v->vcpu_flags) )
    {
        clts();
        if ( test_bit(_VCPUF_fpu_initialised, &v->vcpu_flags) )
            restore_fpu(v);
        else
            init_fpu();
    }
}

#endif /* __ASM_I386_I387_H */
