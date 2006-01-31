/*
 *  linux/arch/i386/kernel/i387.c
 *
 *  Copyright (C) 1994 Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>

void init_fpu(void)
{
    __asm__ __volatile__ ( "fninit" );
    if ( cpu_has_xmm )
        load_mxcsr(0x1f80);
    set_bit(_VCPUF_fpu_initialised, &current->vcpu_flags);
}

void save_init_fpu(struct vcpu *tsk)
{
    /*
     * The guest OS may have set the 'virtual STTS' flag.
     * This causes us to set the real flag, so we'll need
     * to temporarily clear it while saving f-p state.
     */
    if ( HVM_DOMAIN(tsk) || (tsk->arch.guest_context.ctrlreg[0] & X86_CR0_TS) )
        clts();

    if ( cpu_has_fxsr )
        __asm__ __volatile__ (
            "fxsave %0 ; fnclex"
            : "=m" (tsk->arch.guest_context.fpu_ctxt) );
    else
        __asm__ __volatile__ (
            "fnsave %0 ; fwait"
            : "=m" (tsk->arch.guest_context.fpu_ctxt) );

    clear_bit(_VCPUF_fpu_dirtied, &tsk->vcpu_flags);
    stts();
}

void restore_fpu(struct vcpu *tsk)
{
    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools, by silently clearing the block.
     */
    if ( cpu_has_fxsr )
        __asm__ __volatile__ (
            "1: fxrstor %0            \n"
            ".section .fixup,\"ax\"   \n"
            "2: push %%"__OP"ax       \n"
            "   push %%"__OP"cx       \n"
            "   push %%"__OP"di       \n"
            "   lea  %0,%%"__OP"di    \n"
            "   mov  %1,%%ecx         \n"
            "   xor  %%eax,%%eax      \n"
            "   rep ; stosl           \n"
            "   pop  %%"__OP"di       \n"
            "   pop  %%"__OP"cx       \n"
            "   pop  %%"__OP"ax       \n"
            "   jmp  1b               \n"
            ".previous                \n"
            ".section __ex_table,\"a\"\n"
            "   "__FIXUP_ALIGN"       \n"
            "   "__FIXUP_WORD" 1b,2b  \n"
            ".previous                \n"
            : 
            : "m" (tsk->arch.guest_context.fpu_ctxt),
              "i" (sizeof(tsk->arch.guest_context.fpu_ctxt)/4) );
    else
        __asm__ __volatile__ (
            "frstor %0"
            : : "m" (tsk->arch.guest_context.fpu_ctxt) );
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
