/*
 *  linux/arch/i386/kernel/i387.c
 *
 *  Copyright (C) 1994 Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>
#include <asm/asm_defns.h>

void init_fpu(void)
{
    __asm__ __volatile__ ( "fninit" );
    if ( cpu_has_xmm )
        load_mxcsr(0x1f80);
    current->fpu_initialised = 1;
}

void save_init_fpu(struct vcpu *v)
{
    unsigned long cr0 = read_cr0();
    char *fpu_ctxt = v->arch.guest_context.fpu_ctxt.x;

    /* This can happen, if a paravirtualised guest OS has set its CR0.TS. */
    if ( cr0 & X86_CR0_TS )
        clts();

    if ( cpu_has_fxsr )
    {
#ifdef __i386__
        __asm__ __volatile__ (
            "fxsave %0"
            : "=m" (*fpu_ctxt) );
#else /* __x86_64__ */
        /*
         * The only way to force fxsaveq on a wide range of gas versions. On 
         * older versions the rex64 prefix works only if we force an
         * addressing mode that doesn't require extended registers.
         */
        __asm__ __volatile__ (
            REX64_PREFIX "fxsave (%1)"
            : "=m" (*fpu_ctxt) : "cdaSDb" (fpu_ctxt) );
#endif

        /* Clear exception flags if FSW.ES is set. */
        if ( unlikely(fpu_ctxt[2] & 0x80) )
            __asm__ __volatile__ ("fnclex");

        /*
         * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
         * is pending. Clear the x87 state here by setting it to fixed
         * values. The hypervisor data segment can be sometimes 0 and
         * sometimes new user value. Both should be ok. Use the FPU saved
         * data block as a safe address because it should be in L1.
         */
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        {
            __asm__ __volatile__ (
                "emms\n\t"  /* clear stack tags */
                "fildl %0"  /* load to clear state */
                : : "m" (*fpu_ctxt) );
        }
    }
    else
    {
        __asm__ __volatile__ (
            "fnsave %0 ; fwait"
            : "=m" (*fpu_ctxt) );
    }

    v->fpu_dirtied = 0;
    write_cr0(cr0|X86_CR0_TS);
}

void restore_fpu(struct vcpu *v)
{
    char *fpu_ctxt = v->arch.guest_context.fpu_ctxt.x;

    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools, by silently clearing the block.
     */
    if ( cpu_has_fxsr )
    {
        __asm__ __volatile__ (
#ifdef __i386__
            "1: fxrstor %0            \n"
#else /* __x86_64__ */
            /* See above for why the operands/constraints are this way. */
            "1: " REX64_PREFIX "fxrstor (%2)\n"
#endif
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
            : "m" (*fpu_ctxt),
              "i" (sizeof(v->arch.guest_context.fpu_ctxt)/4)
#ifdef __x86_64__
             ,"cdaSDb" (fpu_ctxt)
#endif
            );
    }
    else
    {
        __asm__ __volatile__ (
            "frstor %0"
            : : "m" (v->arch.guest_context.fpu_ctxt) );
    }
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
