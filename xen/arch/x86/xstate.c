/*
 *  arch/x86/xstate.c
 *
 *  x86 extended state operations
 *
 */

#include <xen/percpu.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

static bool_t __read_mostly cpu_has_xsaveopt;
static bool_t __read_mostly cpu_has_xsavec;
bool_t __read_mostly cpu_has_xgetbv1;
bool_t __read_mostly cpu_has_xsaves;

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
static u32 __read_mostly xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 __read_mostly xfeature_mask;

/* Cached xcr0 for fast read */
static DEFINE_PER_CPU(uint64_t, xcr0);

/* Because XCR0 is cached for each CPU, xsetbv() is not exposed. Users should 
 * use set_xcr0() instead.
 */
static inline bool_t xsetbv(u32 index, u64 xfeatures)
{
    u32 hi = xfeatures >> 32;
    u32 lo = (u32)xfeatures;

    asm volatile ( "1: .byte 0x0f,0x01,0xd1\n"
                   "3:                     \n"
                   ".section .fixup,\"ax\" \n"
                   "2: xor %0,%0           \n"
                   "   jmp 3b              \n"
                   ".previous              \n"
                   _ASM_EXTABLE(1b, 2b)
                   : "+a" (lo)
                   : "c" (index), "d" (hi));
    return lo != 0;
}

bool_t set_xcr0(u64 xfeatures)
{
    if ( !xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeatures) )
        return 0;
    this_cpu(xcr0) = xfeatures;
    return 1;
}

uint64_t get_xcr0(void)
{
    return this_cpu(xcr0);
}

void xsave(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.xsave_area;
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;
    unsigned int fip_width = v->domain->arch.x87_fip_width;

    if ( fip_width == 8 || !(mask & XSTATE_FP) )
    {
        if ( cpu_has_xsaveopt )
            asm volatile ( ".byte 0x48,0x0f,0xae,0x37"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
        else
            asm volatile ( ".byte 0x48,0x0f,0xae,0x27"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
    }
    else if ( fip_width == 4 )
    {
        if ( cpu_has_xsaveopt )
            asm volatile ( ".byte 0x0f,0xae,0x37"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
        else
            asm volatile ( ".byte 0x0f,0xae,0x27"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
    }
    else
    {
        /*
         * FIP/FDP may not be written in some cases (e.g., if XSAVEOPT/XSAVES
         * is used, or on AMD CPUs if an exception isn't pending).
         *
         * To tell if the hardware writes these fields, poison the FIP field.
         * The poison is
         * a) non-canonical
         * b) non-zero for the reserved part of a 32-bit FCS:FIP
         * c) random with a vanishingly small probability to match a value the
         *    hardware may write (1e-19) even if it did not canonicalize the
         *    64-bit FIP or zero-extend the 16-bit FCS.
         */
        uint64_t orig_fip = ptr->fpu_sse.fip.addr;
        const uint64_t bad_fip = 0x6a3f5c4b13a533f6;

        ptr->fpu_sse.fip.addr = bad_fip;

        if ( cpu_has_xsaveopt )
            asm volatile ( ".byte 0x48,0x0f,0xae,0x37"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
        else
            asm volatile ( ".byte 0x48,0x0f,0xae,0x27"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );

        /* FIP/FDP not updated? Restore the old FIP value. */
        if ( ptr->fpu_sse.fip.addr == bad_fip )
        {
            ptr->fpu_sse.fip.addr = orig_fip;
            return;
        }

        /*
         * If the FIP/FDP[63:32] are both zero, it is safe to use the
         * 32-bit restore to also restore the selectors.
         */
        if ( !((ptr->fpu_sse.fip.addr | ptr->fpu_sse.fdp.addr) >> 32) )
        {
            struct ix87_env fpu_env;

            asm volatile ( "fnstenv %0" : "=m" (fpu_env) );
            ptr->fpu_sse.fip.sel = fpu_env.fcs;
            ptr->fpu_sse.fdp.sel = fpu_env.fds;
            fip_width = 4;
        }
        else
            fip_width = 8;
    }
    if ( mask & XSTATE_FP )
        ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] = fip_width;
}

void xrstor(struct vcpu *v, uint64_t mask)
{
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;
    struct xsave_struct *ptr = v->arch.xsave_area;

    /*
     * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
     * is pending. Clear the x87 state here by setting it to fixed
     * values. The hypervisor data segment can be sometimes 0 and
     * sometimes new user value. Both should be ok. Use the FPU saved
     * data block as a safe address because it should be in L1.
     */
    if ( (mask & ptr->xsave_hdr.xstate_bv & XSTATE_FP) &&
         !(ptr->fpu_sse.fsw & ~ptr->fpu_sse.fcw & 0x003f) &&
         boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        asm volatile ( "fnclex\n\t"        /* clear exceptions */
                       "ffree %%st(7)\n\t" /* clear stack tag */
                       "fildl %0"          /* load to clear state */
                       : : "m" (ptr->fpu_sse) );

    /*
     * XRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools or through VCPUOP_initialise, by silently clearing the block.
     */
    switch ( __builtin_expect(ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET], 8) )
    {
    default:
        asm volatile ( "1: .byte 0x48,0x0f,0xae,0x2f\n"
                       ".section .fixup,\"ax\"      \n"
                       "2: mov %5,%%ecx             \n"
                       "   xor %1,%1                \n"
                       "   rep stosb                \n"
                       "   lea %2,%0                \n"
                       "   mov %3,%1                \n"
                       "   jmp 1b                   \n"
                       ".previous                   \n"
                       _ASM_EXTABLE(1b, 2b)
                       : "+&D" (ptr), "+&a" (lmask)
                       : "m" (*ptr), "g" (lmask), "d" (hmask),
                         "m" (xsave_cntxt_size)
                       : "ecx" );
        break;
    case 4: case 2:
        asm volatile ( "1: .byte 0x0f,0xae,0x2f\n"
                       ".section .fixup,\"ax\" \n"
                       "2: mov %5,%%ecx        \n"
                       "   xor %1,%1           \n"
                       "   rep stosb           \n"
                       "   lea %2,%0           \n"
                       "   mov %3,%1           \n"
                       "   jmp 1b              \n"
                       ".previous              \n"
                       _ASM_EXTABLE(1b, 2b)
                       : "+&D" (ptr), "+&a" (lmask)
                       : "m" (*ptr), "g" (lmask), "d" (hmask),
                         "m" (xsave_cntxt_size)
                       : "ecx" );
        break;
    }
}

bool_t xsave_enabled(const struct vcpu *v)
{
    if ( !cpu_has_xsave )
        return 0;

    ASSERT(xsave_cntxt_size >= XSTATE_AREA_MIN_SIZE);
    ASSERT(v->arch.xsave_area);

    return !!v->arch.xcr0_accum;
}

int xstate_alloc_save_area(struct vcpu *v)
{
    struct xsave_struct *save_area;

    if ( !cpu_has_xsave || is_idle_vcpu(v) )
        return 0;

    BUG_ON(xsave_cntxt_size < XSTATE_AREA_MIN_SIZE);

    /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
    save_area = _xzalloc(xsave_cntxt_size, 64);
    if ( save_area == NULL )
        return -ENOMEM;

    /*
     * Set the memory image to default values, but don't force the context
     * to be loaded from memory (i.e. keep save_area->xsave_hdr.xstate_bv
     * clear).
     */
    save_area->fpu_sse.fcw = FCW_DEFAULT;
    save_area->fpu_sse.mxcsr = MXCSR_DEFAULT;

    v->arch.xsave_area = save_area;
    v->arch.xcr0 = 0;
    v->arch.xcr0_accum = 0;

    return 0;
}

void xstate_free_save_area(struct vcpu *v)
{
    xfree(v->arch.xsave_area);
    v->arch.xsave_area = NULL;
}

static unsigned int _xstate_ctxt_size(u64 xcr0)
{
    u64 act_xcr0 = get_xcr0();
    u32 eax, ebx = 0, ecx, edx;
    bool_t ok = set_xcr0(xcr0);

    ASSERT(ok);
    cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
    ASSERT(ebx <= ecx);
    ok = set_xcr0(act_xcr0);
    ASSERT(ok);

    return ebx;
}

/* Fastpath for common xstate size requests, avoiding reloads of xcr0. */
unsigned int xstate_ctxt_size(u64 xcr0)
{
    if ( xcr0 == xfeature_mask )
        return xsave_cntxt_size;

    if ( xcr0 == 0 )
        return 0;

    return _xstate_ctxt_size(xcr0);
}

/* Collect the information of processor's extended state */
void xstate_init(bool_t bsp)
{
    u32 eax, ebx, ecx, edx;
    u64 feature_mask;

    if ( boot_cpu_data.cpuid_level < XSTATE_CPUID )
    {
        BUG_ON(!bsp);
        setup_clear_cpu_cap(X86_FEATURE_XSAVE);
        return;
    }

    cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);

    BUG_ON((eax & XSTATE_FP_SSE) != XSTATE_FP_SSE);
    BUG_ON((eax & XSTATE_YMM) && !(eax & XSTATE_SSE));
    feature_mask = (((u64)edx << 32) | eax) & XCNTXT_MASK;

    /*
     * Set CR4_OSXSAVE and run "cpuid" to get xsave_cntxt_size.
     */
    set_in_cr4(X86_CR4_OSXSAVE);
    if ( !set_xcr0(feature_mask) )
        BUG();

    if ( bsp )
    {
        xfeature_mask = feature_mask;
        /*
         * xsave_cntxt_size is the max size required by enabled features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = _xstate_ctxt_size(feature_mask);
        printk("%s: using cntxt_size: %#x and states: %#"PRIx64"\n",
            __func__, xsave_cntxt_size, xfeature_mask);
    }
    else
    {
        BUG_ON(xfeature_mask != feature_mask);
        BUG_ON(xsave_cntxt_size != _xstate_ctxt_size(feature_mask));
    }

    /* Check extended XSAVE features. */
    cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
    if ( bsp )
    {
        cpu_has_xsaveopt = !!(eax & XSTATE_FEATURE_XSAVEOPT);
        cpu_has_xsavec = !!(eax & XSTATE_FEATURE_XSAVEC);
        /* XXX cpu_has_xgetbv1 = !!(eax & XSTATE_FEATURE_XGETBV1); */
        /* XXX cpu_has_xsaves = !!(eax & XSTATE_FEATURE_XSAVES); */
    }
    else
    {
        BUG_ON(!cpu_has_xsaveopt != !(eax & XSTATE_FEATURE_XSAVEOPT));
        BUG_ON(!cpu_has_xsavec != !(eax & XSTATE_FEATURE_XSAVEC));
        /* XXX BUG_ON(!cpu_has_xgetbv1 != !(eax & XSTATE_FEATURE_XGETBV1)); */
        /* XXX BUG_ON(!cpu_has_xsaves != !(eax & XSTATE_FEATURE_XSAVES)); */
    }
}

static bool_t valid_xcr0(u64 xcr0)
{
    /* FP must be unconditionally set. */
    if ( !(xcr0 & XSTATE_FP) )
        return 0;

    /* YMM depends on SSE. */
    if ( (xcr0 & XSTATE_YMM) && !(xcr0 & XSTATE_SSE) )
        return 0;

    if ( xcr0 & (XSTATE_OPMASK | XSTATE_ZMM | XSTATE_HI_ZMM) )
    {
        /* OPMASK, ZMM, and HI_ZMM require YMM. */
        if ( !(xcr0 & XSTATE_YMM) )
            return 0;

        /* OPMASK, ZMM, and HI_ZMM must be the same. */
        if ( ~xcr0 & (XSTATE_OPMASK | XSTATE_ZMM | XSTATE_HI_ZMM) )
            return 0;
    }

    /* BNDREGS and BNDCSR must be the same. */
    return !(xcr0 & XSTATE_BNDREGS) == !(xcr0 & XSTATE_BNDCSR);
}

int validate_xstate(u64 xcr0, u64 xcr0_accum, u64 xstate_bv)
{
    if ( (xstate_bv & ~xcr0_accum) ||
         (xcr0 & ~xcr0_accum) ||
         !valid_xcr0(xcr0) ||
         !valid_xcr0(xcr0_accum) )
        return -EINVAL;

    if ( xcr0_accum & ~xfeature_mask )
        return -EOPNOTSUPP;

    return 0;
}

int handle_xsetbv(u32 index, u64 new_bv)
{
    struct vcpu *curr = current;
    u64 mask;

    if ( index != XCR_XFEATURE_ENABLED_MASK )
        return -EOPNOTSUPP;

    if ( (new_bv & ~xfeature_mask) || !valid_xcr0(new_bv) )
        return -EINVAL;

    if ( !set_xcr0(new_bv) )
        return -EFAULT;

    mask = new_bv & ~curr->arch.xcr0_accum;
    curr->arch.xcr0 = new_bv;
    curr->arch.xcr0_accum |= new_bv;

    /* LWP sets nonlazy_xstate_used independently. */
    if ( new_bv & (XSTATE_NONLAZY & ~XSTATE_LWP) )
        curr->arch.nonlazy_xstate_used = 1;

    mask &= curr->fpu_dirtied ? ~XSTATE_FP_SSE : XSTATE_NONLAZY;
    if ( mask )
    {
        unsigned long cr0 = read_cr0();

        clts();
        if ( curr->fpu_dirtied )
            asm ( "stmxcsr %0" : "=m" (curr->arch.xsave_area->fpu_sse.mxcsr) );
        xrstor(curr, mask);
        if ( cr0 & X86_CR0_TS )
            write_cr0(cr0);
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
