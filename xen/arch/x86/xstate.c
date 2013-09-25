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

bool_t __read_mostly cpu_has_xsaveopt;

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
static u32 __read_mostly xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 xfeature_mask;

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
    int word_size = mask & XSTATE_FP ? (cpu_has_fpu_sel ? sizeof(long) : 0)
                                     : -1;

#ifdef CONFIG_X86_64
    if ( word_size <= 0 || !is_pv_32bit_vcpu(v) )
    {
        typeof(ptr->fpu_sse.fip.sel) fcs = ptr->fpu_sse.fip.sel;
        typeof(ptr->fpu_sse.fdp.sel) fds = ptr->fpu_sse.fdp.sel;

        if ( cpu_has_xsaveopt )
        {
            /*
             * xsaveopt may not write the FPU portion even when the respective
             * mask bit is set. For the check further down to work we hence
             * need to put the save image back into the state that it was in
             * right after the previous xsaveopt.
             */
            if ( word_size > 0 &&
                 (ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] == 4 ||
                  ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] == 2) )
            {
                ptr->fpu_sse.fip.sel = 0;
                ptr->fpu_sse.fdp.sel = 0;
            }
            asm volatile ( ".byte 0x48,0x0f,0xae,0x37"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
        }
        else
            asm volatile ( ".byte 0x48,0x0f,0xae,0x27"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );

        if ( !(mask & ptr->xsave_hdr.xstate_bv & XSTATE_FP) ||
             /*
              * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
              * is pending.
              */
             (!(ptr->fpu_sse.fsw & 0x0080) &&
              boot_cpu_data.x86_vendor == X86_VENDOR_AMD) )
        {
            if ( cpu_has_xsaveopt && word_size > 0 )
            {
                ptr->fpu_sse.fip.sel = fcs;
                ptr->fpu_sse.fdp.sel = fds;
            }
            return;
        }

        if ( word_size > 0 &&
             !((ptr->fpu_sse.fip.addr | ptr->fpu_sse.fdp.addr) >> 32) )
        {
            struct ix87_env fpu_env;

            asm volatile ( "fnstenv %0" : "=m" (fpu_env) );
            ptr->fpu_sse.fip.sel = fpu_env.fcs;
            ptr->fpu_sse.fdp.sel = fpu_env.fds;
            word_size = 4;
        }
    }
    else
#endif
    {
        if ( cpu_has_xsaveopt )
            asm volatile ( ".byte 0x0f,0xae,0x37"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
        else
            asm volatile ( ".byte 0x0f,0xae,0x27"
                           : "=m" (*ptr)
                           : "a" (lmask), "d" (hmask), "D" (ptr) );
        word_size = 4;
    }
    if ( word_size >= 0 )
        ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] = word_size;
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
         !(ptr->fpu_sse.fsw & 0x0080) &&
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
    switch ( __builtin_expect(ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET],
                              sizeof(long)) )
    {
    default:
#ifdef CONFIG_X86_64
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
#endif
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

    save_area->fpu_sse.fcw = FCW_DEFAULT;
    save_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    save_area->xsave_hdr.xstate_bv = XSTATE_FP_SSE;

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

/* Collect the information of processor's extended state */
void xstate_init(bool_t bsp)
{
    u32 eax, ebx, ecx, edx, min_size;
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

    /* FP/SSE, XSAVE.HEADER, YMM */
    min_size =  XSTATE_AREA_MIN_SIZE;
    if ( eax & XSTATE_YMM )
        min_size += XSTATE_YMM_SIZE;
    BUG_ON(ecx < min_size);

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
        xsave_cntxt_size = xstate_ctxt_size(feature_mask);
        printk("%s: using cntxt_size: 0x%x and states: 0x%"PRIx64"\n",
            __func__, xsave_cntxt_size, xfeature_mask);
    }
    else
    {
        BUG_ON(xfeature_mask != feature_mask);
        BUG_ON(xsave_cntxt_size != xstate_ctxt_size(feature_mask));
    }

    /* Check XSAVEOPT feature. */
    cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
    if ( bsp )
        cpu_has_xsaveopt = !!(eax & XSTATE_FEATURE_XSAVEOPT);
    else
        BUG_ON(!cpu_has_xsaveopt != !(eax & XSTATE_FEATURE_XSAVEOPT));
}

unsigned int xstate_ctxt_size(u64 xcr0)
{
    u32 ebx = 0;

    if ( xcr0 )
    {
        u64 act_xcr0 = get_xcr0();
        u32 eax, ecx, edx;
        bool_t ok = set_xcr0(xcr0);

        ASSERT(ok);
        cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
        ASSERT(ebx <= ecx);
        ok = set_xcr0(act_xcr0);
        ASSERT(ok);
    }

    return ebx;
}

int validate_xstate(u64 xcr0, u64 xcr0_accum, u64 xstate_bv, u64 xfeat_mask)
{
    if ( (xcr0_accum & ~xfeat_mask) ||
         (xstate_bv & ~xcr0_accum) ||
         (xcr0 & ~xcr0_accum) ||
         !(xcr0 & XSTATE_FP) ||
         ((xcr0 & XSTATE_YMM) && !(xcr0 & XSTATE_SSE)) ||
         ((xcr0_accum & XSTATE_YMM) && !(xcr0_accum & XSTATE_SSE)) )
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

    if ( (new_bv & ~xfeature_mask) || !(new_bv & XSTATE_FP) )
        return -EINVAL;

    if ( (new_bv & XSTATE_YMM) && !(new_bv & XSTATE_SSE) )
        return -EINVAL;

    if ( !set_xcr0(new_bv) )
        return -EFAULT;

    mask = new_bv & ~curr->arch.xcr0_accum;
    curr->arch.xcr0 = new_bv;
    curr->arch.xcr0_accum |= new_bv;

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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
