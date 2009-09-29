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
    asm volatile ( "fninit" );
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

    if ( cpu_has_xsave && is_hvm_vcpu(v) )
    {
        xsave(v);
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
        asm volatile ( "frstor %0" : : "m" (v->arch.guest_context.fpu_ctxt) );
    }
}

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
u32 xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u32 xfeature_low, xfeature_high;

void xsave_init(void)
{
    u32 eax, ebx, ecx, edx;
    int cpu = smp_processor_id();
    u32 min_size;

    cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);

    printk("%s: cpu%d: cntxt_max_size: 0x%x and states: %08x:%08x\n",
        __func__, cpu, ecx, edx, eax);

    if ( ((eax & XSTATE_FP_SSE) != XSTATE_FP_SSE) ||
         ((eax & XSTATE_YMM) && !(eax & XSTATE_SSE)) )
    {
        BUG();
    }

    /* FP/SSE, XSAVE.HEADER, YMM */
    min_size =  512 + 64 + ((eax & XSTATE_YMM) ? XSTATE_YMM_SIZE : 0);
    BUG_ON(ecx < min_size);

    /*
     * We will only enable the features we know for hvm guest. Here we use
     * set/clear CR4_OSXSAVE and re-run cpuid to get xsave_cntxt_size.
     */
    set_in_cr4(X86_CR4_OSXSAVE);
    set_xcr0(eax & XCNTXT_MASK);
    cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
    clear_in_cr4(X86_CR4_OSXSAVE);

    if ( cpu == 0 )
    {
        /*
         * xsave_cntxt_size is the max size required by enabled features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = ebx;
        xfeature_low = eax & XCNTXT_MASK;
        xfeature_high = 0;
        printk("%s: using cntxt_size: 0x%x and states: %08x:%08x\n",
            __func__, xsave_cntxt_size, xfeature_high, xfeature_low);
    }
    else
    {
        BUG_ON(xsave_cntxt_size != ebx);
        BUG_ON(xfeature_low != (eax & XCNTXT_MASK));
    }
}

void xsave_init_save_area(void *save_area)
{
    memset(save_area, 0, xsave_cntxt_size);

    ((u16 *)save_area)[0] = 0x37f;   /* FCW   */
    ((u16 *)save_area)[2] = 0xffff;  /* FTW   */
    ((u32 *)save_area)[6] = 0x1f80;  /* MXCSR */

    ((struct xsave_struct *)save_area)->xsave_hdr.xstate_bv = XSTATE_FP_SSE;
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
