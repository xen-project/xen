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

static void fpu_init(void)
{
    unsigned long val;
    
    asm volatile ( "fninit" );
    if ( cpu_has_xmm )
    {
        /* load default value into MXCSR control/status register */
        val = MXCSR_DEFAULT;
        asm volatile ( "ldmxcsr %0" : : "m" (val) );
    }
}

/*******************************/
/*     FPU Restore Functions   */
/*******************************/
/* Restore x87 extended state */
static inline void fpu_xrstor(struct vcpu *v, uint64_t mask)
{
    bool_t ok;

    ASSERT(v->arch.xsave_area);
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself, 
     * we set the accumulated feature mask before doing save/restore.
     */
    ok = set_xcr0(v->arch.xcr0_accum | XSTATE_FP_SSE);
    ASSERT(ok);
    xrstor(v, mask);
    ok = set_xcr0(v->arch.xcr0 ?: XSTATE_FP_SSE);
    ASSERT(ok);
}

/* Restor x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxrstor(struct vcpu *v)
{
    const char *fpu_ctxt = v->arch.fpu_ctxt;

    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools or through VCPUOP_initialise, by silently clearing the block.
     */
    switch ( __builtin_expect(fpu_ctxt[FPU_WORD_SIZE_OFFSET], sizeof(long)) )
    {
    default:
#ifdef __x86_64__
        asm volatile (
            /* See below for why the operands/constraints are this way. */
            "1: " REX64_PREFIX "fxrstor (%2)\n"
            ".section .fixup,\"ax\"   \n"
            "2: push %%"__OP"ax       \n"
            "   push %%"__OP"cx       \n"
            "   push %%"__OP"di       \n"
            "   mov  %2,%%"__OP"di    \n"
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
              "i" (sizeof(v->arch.xsave_area->fpu_sse) / 4),
              "cdaSDb" (fpu_ctxt) );
        break;
    case 4: case 2:
#endif
        asm volatile (
            "1: fxrstor %0         \n"
            ".section .fixup,\"ax\"\n"
            "2: push %%"__OP"ax    \n"
            "   push %%"__OP"cx    \n"
            "   push %%"__OP"di    \n"
            "   lea  %0,%%"__OP"di \n"
            "   mov  %1,%%ecx      \n"
            "   xor  %%eax,%%eax   \n"
            "   rep ; stosl        \n"
            "   pop  %%"__OP"di    \n"
            "   pop  %%"__OP"cx    \n"
            "   pop  %%"__OP"ax    \n"
            "   jmp  1b            \n"
            ".previous             \n"
            _ASM_EXTABLE(1b, 2b)
            :
            : "m" (*fpu_ctxt),
              "i" (sizeof(v->arch.xsave_area->fpu_sse) / 4) );
        break;
    }
}

/* Restore x87 extended state */
static inline void fpu_frstor(struct vcpu *v)
{
    const char *fpu_ctxt = v->arch.fpu_ctxt;

    asm volatile ( "frstor %0" : : "m" (*fpu_ctxt) );
}

/*******************************/
/*      FPU Save Functions     */
/*******************************/

static inline uint64_t vcpu_xsave_mask(const struct vcpu *v)
{
    if ( v->fpu_dirtied )
        return v->arch.nonlazy_xstate_used ? XSTATE_ALL : XSTATE_LAZY;

    return v->arch.nonlazy_xstate_used ? XSTATE_NONLAZY : 0;
}

/* Save x87 extended state */
static inline void fpu_xsave(struct vcpu *v)
{
    bool_t ok;
    uint64_t mask = vcpu_xsave_mask(v);

    ASSERT(mask);
    ASSERT(v->arch.xsave_area);
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set the accumulated feature mask before doing save/restore.
     */
    ok = set_xcr0(v->arch.xcr0_accum | XSTATE_FP_SSE);
    ASSERT(ok);
    xsave(v, mask);
    ok = set_xcr0(v->arch.xcr0 ?: XSTATE_FP_SSE);
    ASSERT(ok);
}

/* Save x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxsave(struct vcpu *v)
{
    typeof(v->arch.xsave_area->fpu_sse) *fpu_ctxt = v->arch.fpu_ctxt;
    int word_size = cpu_has_fpu_sel ? sizeof(long) : 0;

#ifdef __x86_64__
    if ( !is_pv_32bit_vcpu(v) )
    {
        /*
         * The only way to force fxsaveq on a wide range of gas versions.
         * On older versions the rex64 prefix works only if we force an
         * addressing mode that doesn't require extended registers.
         */
        asm volatile ( REX64_PREFIX "fxsave (%1)"
                       : "=m" (*fpu_ctxt) : "cdaSDb" (fpu_ctxt) );

        /*
         * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
         * is pending.
         */
        if ( !(fpu_ctxt->fsw & 0x0080) &&
             boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
            word_size = -1;

        if ( word_size > 0 &&
             !((fpu_ctxt->fip.addr | fpu_ctxt->fdp.addr) >> 32) )
        {
            struct ix87_env fpu_env;

            asm volatile ( "fnstenv %0" : "=m" (fpu_env) );
            fpu_ctxt->fip.sel = fpu_env.fcs;
            fpu_ctxt->fdp.sel = fpu_env.fds;
            word_size = 4;
        }
    }
    else
#endif
    {
        asm volatile ( "fxsave %0" : "=m" (*fpu_ctxt) );
        word_size = 4;
    }

    if ( word_size >= 0 )
        fpu_ctxt->x[FPU_WORD_SIZE_OFFSET] = word_size;
    
    /* Clear exception flags if FSW.ES is set. */
    if ( unlikely(fpu_ctxt->fsw & 0x0080) )
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

/* Save x87 FPU state */
static inline void fpu_fsave(struct vcpu *v)
{
    char *fpu_ctxt = v->arch.fpu_ctxt;

    /* FWAIT is required to make FNSAVE synchronous. */
    asm volatile ( "fnsave %0 ; fwait" : "=m" (*fpu_ctxt) );
}

/*******************************/
/*       VCPU FPU Functions    */
/*******************************/
/* Restore FPU state whenever VCPU is schduled in. */
void vcpu_restore_fpu_eager(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));
    
    /* save the nonlazy extended state which is not tracked by CR0.TS bit */
    if ( v->arch.nonlazy_xstate_used )
    {
        /* Avoid recursion */
        clts();        
        fpu_xrstor(v, XSTATE_NONLAZY);
        stts();
    }
}

/* 
 * Restore FPU state when #NM is triggered.
 */
void vcpu_restore_fpu_lazy(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    /* Avoid recursion. */
    clts();

    if ( v->fpu_dirtied )
        return;

    if ( cpu_has_xsave )
        fpu_xrstor(v, XSTATE_LAZY);
    else if ( v->fpu_initialised )
    {
        if ( cpu_has_fxsr )
            fpu_fxrstor(v);
        else
            fpu_frstor(v);
    }
    else
        fpu_init();

    v->fpu_initialised = 1;
    v->fpu_dirtied = 1;
}

/* 
 * On each context switch, save the necessary FPU info of VCPU being switch 
 * out. It dispatches saving operation based on CPU's capability.
 */
void vcpu_save_fpu(struct vcpu *v)
{
    if ( !v->fpu_dirtied && !v->arch.nonlazy_xstate_used )
        return;

    ASSERT(!is_idle_vcpu(v));

    /* This can happen, if a paravirtualised guest OS has set its CR0.TS. */
    clts();

    if ( cpu_has_xsave )
        fpu_xsave(v);
    else if ( cpu_has_fxsr )
        fpu_fxsave(v);
    else
        fpu_fsave(v);

    v->fpu_dirtied = 0;
    stts();
}

/* Initialize FPU's context save area */
int vcpu_init_fpu(struct vcpu *v)
{
    int rc = 0;
    
    /* Idle domain doesn't have FPU state allocated */
    if ( is_idle_vcpu(v) )
        goto done;

    if ( (rc = xstate_alloc_save_area(v)) != 0 )
        return rc;

    if ( v->arch.xsave_area )
        v->arch.fpu_ctxt = &v->arch.xsave_area->fpu_sse;
    else
    {
        v->arch.fpu_ctxt = _xzalloc(sizeof(v->arch.xsave_area->fpu_sse), 16);
        if ( !v->arch.fpu_ctxt )
        {
            rc = -ENOMEM;
            goto done;
        }
    }

done:
    return rc;
}

/* Free FPU's context save area */
void vcpu_destroy_fpu(struct vcpu *v)
{
    if ( v->arch.xsave_area )
        xstate_free_save_area(v);
    else
        xfree(v->arch.fpu_ctxt);
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
