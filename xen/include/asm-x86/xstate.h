/*
 * include/asm-i386/xstate.h
 *
 * x86 extended state (xsave/xrstor) related definitions
 * 
 */

#ifndef __ASM_XSTATE_H
#define __ASM_XSTATE_H

#include <xen/types.h>
#include <xen/percpu.h>

#define XSTATE_CPUID              0x0000000d
#define XSTATE_FEATURE_XSAVEOPT   (1 << 0)    /* sub-leaf 1, eax[bit 0] */

#define XCR_XFEATURE_ENABLED_MASK 0x00000000  /* index of XCR0 */

#define XSTATE_YMM_SIZE           256
#define XSTATE_YMM_OFFSET         XSAVE_AREA_MIN_SIZE
#define XSTATE_AREA_MIN_SIZE      (512 + 64)  /* FP/SSE + XSAVE.HEADER */

#define XSTATE_FP      (1ULL << 0)
#define XSTATE_SSE     (1ULL << 1)
#define XSTATE_YMM     (1ULL << 2)
#define XSTATE_LWP     (1ULL << 62) /* AMD lightweight profiling */
#define XSTATE_FP_SSE  (XSTATE_FP | XSTATE_SSE)
#define XCNTXT_MASK    (XSTATE_FP | XSTATE_SSE | XSTATE_YMM | XSTATE_LWP)

#define XSTATE_ALL     (~0)
#define XSTATE_NONLAZY (XSTATE_LWP)
#define XSTATE_LAZY    (XSTATE_ALL & ~XSTATE_NONLAZY)

#ifdef CONFIG_X86_64
#define REX_PREFIX     "0x48, "
#else
#define REX_PREFIX
#endif

/* extended state variables */
DECLARE_PER_CPU(uint64_t, xcr0);

extern unsigned int xsave_cntxt_size;
extern u64 xfeature_mask;

/* extended state save area */
struct xsave_struct
{
    struct { char x[512]; } fpu_sse;         /* FPU/MMX, SSE */

    struct {
        u64 xstate_bv;
        u64 reserved[7];
    } xsave_hdr;                             /* The 64-byte header */

    struct { char x[XSTATE_YMM_SIZE]; } ymm; /* YMM */
    char   data[];                           /* Future new states */
} __attribute__ ((packed, aligned (64)));

/* extended state operations */
void set_xcr0(u64 xfeatures);
uint64_t get_xcr0(void);
void xsave(struct vcpu *v, uint64_t mask);
void xrstor(struct vcpu *v, uint64_t mask);
bool_t xsave_enabled(const struct vcpu *v);

/* extended state init and cleanup functions */
void xstate_free_save_area(struct vcpu *v);
int xstate_alloc_save_area(struct vcpu *v);
void xstate_init(void);

#endif /* __ASM_XSTATE_H */
