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
#include <asm/xstate.h>
#include <asm/asm_defns.h>

static void load_mxcsr(unsigned long val)
{
    val &= 0xffbf;
    asm volatile ( "ldmxcsr %0" : : "m" (val) );
}

static void init_fpu(void);
static void restore_fpu(struct vcpu *v);

void setup_fpu(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    /* Avoid recursion. */
    clts();

    if ( v->fpu_dirtied )
        return;

    if ( xsave_enabled(v) )
    {
        /*
         * XCR0 normally represents what guest OS set. In case of Xen itself, 
         * we set all supported feature mask before doing save/restore.
         */
        set_xcr0(v->arch.xcr0_accum);
        xrstor(v);
        set_xcr0(v->arch.xcr0);
    }
    else if ( v->fpu_initialised )
    {
        restore_fpu(v);
    }
    else
    {
        init_fpu();
    }

    v->fpu_initialised = 1;
    v->fpu_dirtied = 1;
}

static void init_fpu(void)
{
    asm volatile ( "fninit" );
    if ( cpu_has_xmm )
        load_mxcsr(0x1f80);
}

void save_init_fpu(struct vcpu *v)
{
    unsigned long cr0;
    char *fpu_ctxt;

    if ( !v->fpu_dirtied )
        return;

    ASSERT(!is_idle_vcpu(v));

    cr0 = read_cr0();
    fpu_ctxt = v->arch.fpu_ctxt;

    /* This can happen, if a paravirtualised guest OS has set its CR0.TS. */
    if ( cr0 & X86_CR0_TS )
        clts();

    if ( xsave_enabled(v) )
    {
        /* XCR0 normally represents what guest OS set. In case of Xen itself,
         * we set all accumulated feature mask before doing save/restore.
         */
        set_xcr0(v->arch.xcr0_accum);
        xsave(v);
        set_xcr0(v->arch.xcr0);
    }
    else if ( cpu_has_fxsr )
    {
#ifdef __i386__
        asm volatile (
            "fxsave %0"
            : "=m" (*fpu_ctxt) );
#else /* __x86_64__ */
        /*
         * The only way to force fxsaveq on a wide range of gas versions. On 
         * older versions the rex64 prefix works only if we force an
         * addressing mode that doesn't require extended registers.
         */
        asm volatile (
            REX64_PREFIX "fxsave (%1)"
            : "=m" (*fpu_ctxt) : "cdaSDb" (fpu_ctxt) );
#endif

        /* Clear exception flags if FSW.ES is set. */
        if ( unlikely(fpu_ctxt[2] & 0x80) )
            asm volatile ("fnclex");

        /*
         * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
         * is pending. Clear the x87 state here by setting it to fixed
         * values. The hypervisor data segment can be sometimes 0 and
         * sometimes new user value. Both should be ok. Use the FPU saved
         * data block as a safe address because it should be in L1.
         */
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        {
            asm volatile (
                "emms\n\t"  /* clear stack tags */
                "fildl %0"  /* load to clear state */
                : : "m" (*fpu_ctxt) );
        }
    }
    else
    {
        /* FWAIT is required to make FNSAVE synchronous. */
        asm volatile ( "fnsave %0 ; fwait" : "=m" (*fpu_ctxt) );
    }

    v->fpu_dirtied = 0;
    write_cr0(cr0|X86_CR0_TS);
}

static void restore_fpu(struct vcpu *v)
{
    const char *fpu_ctxt = v->arch.fpu_ctxt;

    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools, by silently clearing the block.
     */
    if ( cpu_has_fxsr )
    {
        asm volatile (
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
            _ASM_EXTABLE(1b, 2b)
            : 
            : "m" (*fpu_ctxt),
              "i" (sizeof(v->arch.xsave_area->fpu_sse)/4)
#ifdef __x86_64__
             ,"cdaSDb" (fpu_ctxt)
#endif
            );
    }
    else
    {
        asm volatile ( "frstor %0" : : "m" (*fpu_ctxt) );
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
