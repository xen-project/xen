/*
 *  arch/x86/xstate.c
 *
 *  x86 extended state operations
 *
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

bool_t __read_mostly cpu_has_xsaveopt;

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
u32 xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 xfeature_mask;

/* Cached xcr0 for fast read */
DEFINE_PER_CPU(uint64_t, xcr0);

/* Because XCR0 is cached for each CPU, xsetbv() is not exposed. Users should 
 * use set_xcr0() instead.
 */
static inline void xsetbv(u32 index, u64 xfeatures)
{
    u32 hi = xfeatures >> 32;
    u32 lo = (u32)xfeatures;

    asm volatile (".byte 0x0f,0x01,0xd1" :: "c" (index),
            "a" (lo), "d" (hi));
}

void set_xcr0(u64 xfeatures)
{
    this_cpu(xcr0) = xfeatures;
    xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeatures);
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

    if ( cpu_has_xsaveopt )
        asm volatile (
            ".byte " REX_PREFIX "0x0f,0xae,0x37"
            :
            : "a" (lmask), "d" (hmask), "D"(ptr)
            : "memory" );
    else
        asm volatile (
            ".byte " REX_PREFIX "0x0f,0xae,0x27"
            :
            : "a" (lmask), "d" (hmask), "D"(ptr)
            : "memory" );
}

void xrstor(struct vcpu *v, uint64_t mask)
{
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;

    struct xsave_struct *ptr = v->arch.xsave_area;

    asm volatile (
        ".byte " REX_PREFIX "0x0f,0xae,0x2f"
        :
        : "m" (*ptr), "a" (lmask), "d" (hmask), "D"(ptr) );
}

bool_t xsave_enabled(const struct vcpu *v)
{
    if ( cpu_has_xsave )
    {
        ASSERT(xsave_cntxt_size >= XSTATE_AREA_MIN_SIZE);
        ASSERT(v->arch.xsave_area);
    }

    return cpu_has_xsave;	
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
    v->arch.xcr0 = XSTATE_FP_SSE;
    v->arch.xcr0_accum = XSTATE_FP_SSE;

    return 0;
}

void xstate_free_save_area(struct vcpu *v)
{
    xfree(v->arch.xsave_area);
    v->arch.xsave_area = NULL;
}

/* Collect the information of processor's extended state */
void xstate_init(void)
{
    u32 eax, ebx, ecx, edx;
    int cpu = smp_processor_id();
    u32 min_size;

    if ( boot_cpu_data.cpuid_level < XSTATE_CPUID )
        return;

    cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);

    BUG_ON((eax & XSTATE_FP_SSE) != XSTATE_FP_SSE);
    BUG_ON((eax & XSTATE_YMM) && !(eax & XSTATE_SSE));

    /* FP/SSE, XSAVE.HEADER, YMM */
    min_size =  XSTATE_AREA_MIN_SIZE;
    if ( eax & XSTATE_YMM )
        min_size += XSTATE_YMM_SIZE;
    BUG_ON(ecx < min_size);

    /*
     * Set CR4_OSXSAVE and run "cpuid" to get xsave_cntxt_size.
     */
    set_in_cr4(X86_CR4_OSXSAVE);
    set_xcr0((((u64)edx << 32) | eax) & XCNTXT_MASK);
    cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);

    if ( cpu == 0 )
    {
        /*
         * xsave_cntxt_size is the max size required by enabled features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = ebx;
        xfeature_mask = eax + ((u64)edx << 32);
        xfeature_mask &= XCNTXT_MASK;
        printk("%s: using cntxt_size: 0x%x and states: 0x%"PRIx64"\n",
            __func__, xsave_cntxt_size, xfeature_mask);

        /* Check XSAVEOPT feature. */
        cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
        cpu_has_xsaveopt = !!(eax & XSTATE_FEATURE_XSAVEOPT);
    }
    else
    {
        BUG_ON(xsave_cntxt_size != ebx);
        BUG_ON(xfeature_mask != (xfeature_mask & XCNTXT_MASK));
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
