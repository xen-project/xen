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

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
static u32 __read_mostly xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 __read_mostly xfeature_mask;

static unsigned int *__read_mostly xstate_offsets;
unsigned int *__read_mostly xstate_sizes;
static unsigned int __read_mostly xstate_features;
static unsigned int __read_mostly xstate_comp_offsets[sizeof(xfeature_mask)*8];

static uint32_t __read_mostly mxcsr_mask = 0x0000ffbf;

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

/* Cached xss for fast read */
static DEFINE_PER_CPU(uint64_t, xss);

void set_msr_xss(u64 xss)
{
    u64 *this_xss = &this_cpu(xss);

    if ( *this_xss != xss )
    {
        wrmsrl(MSR_IA32_XSS, xss);
        *this_xss = xss;
    }
}

uint64_t get_msr_xss(void)
{
    return this_cpu(xss);
}

static bool_t xsave_area_compressed(const struct xsave_struct *xsave_area)
{
     return xsave_area && (xsave_area->xsave_hdr.xcomp_bv
                           & XSTATE_COMPACTION_ENABLED);
}

static int setup_xstate_features(bool_t bsp)
{
    unsigned int leaf, tmp, eax, ebx;

    if ( bsp )
    {
        xstate_features = fls(xfeature_mask);
        xstate_offsets = xzalloc_array(unsigned int, xstate_features);
        if ( !xstate_offsets )
            return -ENOMEM;

        xstate_sizes = xzalloc_array(unsigned int, xstate_features);
        if ( !xstate_sizes )
            return -ENOMEM;
    }

    for ( leaf = 2; leaf < xstate_features; leaf++ )
    {
        if ( bsp )
            cpuid_count(XSTATE_CPUID, leaf, &xstate_sizes[leaf],
                        &xstate_offsets[leaf], &tmp, &tmp);
        else
        {
            cpuid_count(XSTATE_CPUID, leaf, &eax,
                        &ebx, &tmp, &tmp);
            BUG_ON(eax != xstate_sizes[leaf]);
            BUG_ON(ebx != xstate_offsets[leaf]);
        }
    }

    return 0;
}

static void __init setup_xstate_comp(void)
{
    unsigned int i;

    /*
     * The FP xstates and SSE xstates are legacy states. They are always
     * in the fixed offsets in the xsave area in either compacted form
     * or standard form.
     */
    xstate_comp_offsets[0] = 0;
    xstate_comp_offsets[1] = XSAVE_SSE_OFFSET;

    xstate_comp_offsets[2] = FXSAVE_SIZE + XSAVE_HDR_SIZE;

    for ( i = 3; i < xstate_features; i++ )
    {
        xstate_comp_offsets[i] = xstate_comp_offsets[i - 1] +
                                 (((1ul << i) & xfeature_mask)
                                  ? xstate_sizes[i - 1] : 0);
        ASSERT(xstate_comp_offsets[i] + xstate_sizes[i] <= xsave_cntxt_size);
    }
}

static void *get_xsave_addr(struct xsave_struct *xsave,
        unsigned int xfeature_idx)
{
    if ( !((1ul << xfeature_idx) & xsave->xsave_hdr.xstate_bv) )
        return NULL;

    return (void *)xsave + (xsave_area_compressed(xsave)
            ? xstate_comp_offsets
            : xstate_offsets)[xfeature_idx];
}

void expand_xsave_states(struct vcpu *v, void *dest, unsigned int size)
{
    struct xsave_struct *xsave = v->arch.xsave_area;
    u64 xstate_bv = xsave->xsave_hdr.xstate_bv;
    u64 valid;

    if ( !cpu_has_xsaves && !cpu_has_xsavec )
    {
        memcpy(dest, xsave, size);
        return;
    }

    ASSERT(xsave_area_compressed(xsave));
    /*
     * Copy legacy XSAVE area and XSAVE hdr area.
     */
    memcpy(dest, xsave, XSTATE_AREA_MIN_SIZE);

    ((struct xsave_struct *)dest)->xsave_hdr.xcomp_bv =  0;

    /*
     * Copy each region from the possibly compacted offset to the
     * non-compacted offset.
     */
    valid = xstate_bv & ~XSTATE_FP_SSE;
    while ( valid )
    {
        u64 feature = valid & -valid;
        unsigned int index = fls(feature) - 1;
        const void *src = get_xsave_addr(xsave, index);

        if ( src )
        {
            ASSERT((xstate_offsets[index] + xstate_sizes[index]) <= size);
            memcpy(dest + xstate_offsets[index], src, xstate_sizes[index]);
        }

        valid &= ~feature;
    }
}

void compress_xsave_states(struct vcpu *v, const void *src, unsigned int size)
{
    struct xsave_struct *xsave = v->arch.xsave_area;
    u64 xstate_bv = ((const struct xsave_struct *)src)->xsave_hdr.xstate_bv;
    u64 valid;

    if ( !cpu_has_xsaves && !cpu_has_xsavec )
    {
        memcpy(xsave, src, size);
        return;
    }

    ASSERT(!xsave_area_compressed(src));
    /*
     * Copy legacy XSAVE area, to avoid complications with CPUID
     * leaves 0 and 1 in the loop below.
     */
    memcpy(xsave, src, FXSAVE_SIZE);

    /* Set XSTATE_BV and XCOMP_BV.  */
    xsave->xsave_hdr.xstate_bv = xstate_bv;
    xsave->xsave_hdr.xcomp_bv = v->arch.xcr0_accum | XSTATE_COMPACTION_ENABLED;

    /*
     * Copy each region from the non-compacted offset to the
     * possibly compacted offset.
     */
    valid = xstate_bv & ~XSTATE_FP_SSE;
    while ( valid )
    {
        u64 feature = valid & -valid;
        unsigned int index = fls(feature) - 1;
        void *dest = get_xsave_addr(xsave, index);

        if ( dest )
        {
            ASSERT((xstate_offsets[index] + xstate_sizes[index]) <= size);
            memcpy(dest, src + xstate_offsets[index], xstate_sizes[index]);
        }

        valid &= ~feature;
    }
}

void xsave(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.xsave_area;
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;
    unsigned int fip_width = v->domain->arch.x87_fip_width;
#define XSAVE(pfx) \
        alternative_io_3(".byte " pfx "0x0f,0xae,0x27\n", /* xsave */ \
                         ".byte " pfx "0x0f,0xae,0x37\n", /* xsaveopt */ \
                         X86_FEATURE_XSAVEOPT, \
                         ".byte " pfx "0x0f,0xc7,0x27\n", /* xsavec */ \
                         X86_FEATURE_XSAVEC, \
                         ".byte " pfx "0x0f,0xc7,0x2f\n", /* xsaves */ \
                         X86_FEATURE_XSAVES, \
                         "=m" (*ptr), \
                         "a" (lmask), "d" (hmask), "D" (ptr))

    if ( fip_width == 8 || !(mask & XSTATE_FP) )
    {
        XSAVE("0x48,");
    }
    else if ( fip_width == 4 )
    {
        XSAVE("");
    }
    else
    {
        typeof(ptr->fpu_sse.fip.sel) fcs = ptr->fpu_sse.fip.sel;
        typeof(ptr->fpu_sse.fdp.sel) fds = ptr->fpu_sse.fdp.sel;

        if ( cpu_has_xsaveopt || cpu_has_xsaves )
        {
            /*
             * XSAVEOPT/XSAVES may not write the FPU portion even when the
             * respective mask bit is set. For the check further down to work
             * we hence need to put the save image back into the state that
             * it was in right after the previous XSAVEOPT.
             */
            if ( ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] == 4 ||
                 ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] == 2 )
            {
                ptr->fpu_sse.fip.sel = 0;
                ptr->fpu_sse.fdp.sel = 0;
            }
        }

        XSAVE("0x48,");

        if ( !(ptr->xsave_hdr.xstate_bv & XSTATE_FP) ||
             /*
              * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
              * is pending.
              */
             (!(ptr->fpu_sse.fsw & 0x0080) &&
              boot_cpu_data.x86_vendor == X86_VENDOR_AMD) )
        {
            if ( cpu_has_xsaveopt || cpu_has_xsaves )
            {
                ptr->fpu_sse.fip.sel = fcs;
                ptr->fpu_sse.fdp.sel = fds;
            }
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
#undef XSAVE
    if ( mask & XSTATE_FP )
        ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] = fip_width;
}

void xrstor(struct vcpu *v, uint64_t mask)
{
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;
    struct xsave_struct *ptr = v->arch.xsave_area;
    unsigned int faults, prev_faults;

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
     * tools or through VCPUOP_initialise, by silently adjusting state.
     */
    for ( prev_faults = faults = 0; ; prev_faults = faults )
    {
        switch ( __builtin_expect(ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET], 8) )
        {
            BUILD_BUG_ON(sizeof(faults) != 4); /* Clang doesn't support %z in asm. */
#define XRSTOR(pfx) \
        alternative_io("1: .byte " pfx "0x0f,0xae,0x2f\n" \
                       "3:\n" \
                       "   .section .fixup,\"ax\"\n" \
                       "2: incl %[faults]\n" \
                       "   jmp 3b\n" \
                       "   .previous\n" \
                       _ASM_EXTABLE(1b, 2b), \
                       ".byte " pfx "0x0f,0xc7,0x1f\n", \
                       X86_FEATURE_XSAVES, \
                       ASM_OUTPUT2([mem] "+m" (*ptr), [faults] "+g" (faults)), \
                       [lmask] "a" (lmask), [hmask] "d" (hmask), \
                       [ptr] "D" (ptr))

        default:
            XRSTOR("0x48,");
            break;
        case 4: case 2:
            XRSTOR("");
            break;
#undef XRSTOR
        }
        if ( likely(faults == prev_faults) )
            break;
#ifndef NDEBUG
        gprintk(XENLOG_WARNING, "fault#%u: mxcsr=%08x\n",
                faults, ptr->fpu_sse.mxcsr);
        gprintk(XENLOG_WARNING, "xs=%016lx xc=%016lx\n",
                ptr->xsave_hdr.xstate_bv, ptr->xsave_hdr.xcomp_bv);
        gprintk(XENLOG_WARNING, "r0=%016lx r1=%016lx\n",
                ptr->xsave_hdr.reserved[0], ptr->xsave_hdr.reserved[1]);
        gprintk(XENLOG_WARNING, "r2=%016lx r3=%016lx\n",
                ptr->xsave_hdr.reserved[2], ptr->xsave_hdr.reserved[3]);
        gprintk(XENLOG_WARNING, "r4=%016lx r5=%016lx\n",
                ptr->xsave_hdr.reserved[4], ptr->xsave_hdr.reserved[5]);
#endif
        switch ( faults )
        {
        case 1: /* Stage 1: Reset state to be loaded. */
            ptr->xsave_hdr.xstate_bv &= ~mask;
            /*
             * Also try to eliminate fault reasons, even if this shouldn't be
             * needed here (other code should ensure the sanity of the data).
             */
            if ( ((mask & XSTATE_SSE) ||
                  ((mask & XSTATE_YMM) &&
                   !(ptr->xsave_hdr.xcomp_bv & XSTATE_COMPACTION_ENABLED))) )
                ptr->fpu_sse.mxcsr &= mxcsr_mask;
            if ( cpu_has_xsaves || cpu_has_xsavec )
            {
                ptr->xsave_hdr.xcomp_bv &= this_cpu(xcr0) | this_cpu(xss);
                ptr->xsave_hdr.xstate_bv &= ptr->xsave_hdr.xcomp_bv;
                ptr->xsave_hdr.xcomp_bv |= XSTATE_COMPACTION_ENABLED;
            }
            else
            {
                ptr->xsave_hdr.xstate_bv &= this_cpu(xcr0);
                ptr->xsave_hdr.xcomp_bv = 0;
            }
            memset(ptr->xsave_hdr.reserved, 0, sizeof(ptr->xsave_hdr.reserved));
            continue;

        case 2: /* Stage 2: Reset all state. */
            ptr->fpu_sse.mxcsr = MXCSR_DEFAULT;
            ptr->xsave_hdr.xstate_bv = 0;
            ptr->xsave_hdr.xcomp_bv = cpu_has_xsaves
                                      ? XSTATE_COMPACTION_ENABLED : 0;
            continue;
        }

        domain_crash(current->domain);
        return;
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
    BUILD_BUG_ON(__alignof(*save_area) < 64);
    save_area = _xzalloc(xsave_cntxt_size, __alignof(*save_area));
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
void xstate_init(struct cpuinfo_x86 *c)
{
    bool_t bsp = c == &boot_cpu_data;
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
        static typeof(current->arch.xsave_area->fpu_sse) __initdata ctxt;

        xfeature_mask = feature_mask;
        /*
         * xsave_cntxt_size is the max size required by enabled features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = _xstate_ctxt_size(feature_mask);
        printk("%s: using cntxt_size: %#x and states: %#"PRIx64"\n",
            __func__, xsave_cntxt_size, xfeature_mask);

        asm ( "fxsave %0" : "=m" (ctxt) );
        if ( ctxt.mxcsr_mask )
            mxcsr_mask = ctxt.mxcsr_mask;
    }
    else
    {
        BUG_ON(xfeature_mask != feature_mask);
        BUG_ON(xsave_cntxt_size != _xstate_ctxt_size(feature_mask));
    }

    /* Check extended XSAVE features. */
    cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);

    /* Mask out features not currently understood by Xen. */
    eax &= (cpufeat_mask(X86_FEATURE_XSAVEOPT) |
            cpufeat_mask(X86_FEATURE_XSAVEC) |
            cpufeat_mask(X86_FEATURE_XGETBV1) |
            cpufeat_mask(X86_FEATURE_XSAVES));

    c->x86_capability[cpufeat_word(X86_FEATURE_XSAVEOPT)] = eax;

    BUG_ON(eax != boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_XSAVEOPT)]);

    if ( setup_xstate_features(bsp) && bsp )
        BUG();
    if ( bsp && (cpu_has_xsaves || cpu_has_xsavec) )
        setup_xstate_comp();
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

int validate_xstate(u64 xcr0, u64 xcr0_accum, const struct xsave_hdr *hdr)
{
    unsigned int i;

    if ( (hdr->xstate_bv & ~xcr0_accum) ||
         (xcr0 & ~xcr0_accum) ||
         !valid_xcr0(xcr0) ||
         !valid_xcr0(xcr0_accum) )
        return -EINVAL;

    if ( (xcr0_accum & ~xfeature_mask) ||
         hdr->xcomp_bv )
        return -EOPNOTSUPP;

    for ( i = 0; i < ARRAY_SIZE(hdr->reserved); ++i )
        if ( hdr->reserved[i] )
            return -EIO;

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

    /* XCR0.PKRU is disabled on PV mode. */
    if ( is_pv_vcpu(curr) && (new_bv & XSTATE_PKRU) )
        return -EOPNOTSUPP;

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
