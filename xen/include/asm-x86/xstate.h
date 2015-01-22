/*
 * include/asm-i386/xstate.h
 *
 * x86 extended state (xsave/xrstor) related definitions
 * 
 */

#ifndef __ASM_XSTATE_H
#define __ASM_XSTATE_H

#include <xen/types.h>

#define FCW_DEFAULT               0x037f
#define FCW_RESET                 0x0040
#define MXCSR_DEFAULT             0x1f80

#define XSTATE_CPUID              0x0000000d
#define XSTATE_FEATURE_XSAVEOPT   (1 << 0)    /* sub-leaf 1, eax[bit 0] */
#define XSTATE_FEATURE_XSAVEC     (1 << 1)    /* sub-leaf 1, eax[bit 1] */
#define XSTATE_FEATURE_XGETBV1    (1 << 2)    /* sub-leaf 1, eax[bit 2] */
#define XSTATE_FEATURE_XSAVES     (1 << 3)    /* sub-leaf 1, eax[bit 3] */

#define XCR_XFEATURE_ENABLED_MASK 0x00000000  /* index of XCR0 */

#define XSTATE_YMM_SIZE           256
#define XSTATE_AREA_MIN_SIZE      (512 + 64)  /* FP/SSE + XSAVE.HEADER */

#define XSTATE_FP      (1ULL << 0)
#define XSTATE_SSE     (1ULL << 1)
#define XSTATE_YMM     (1ULL << 2)
#define XSTATE_BNDREGS (1ULL << 3)
#define XSTATE_BNDCSR  (1ULL << 4)
#define XSTATE_OPMASK  (1ULL << 5)
#define XSTATE_ZMM     (1ULL << 6)
#define XSTATE_HI_ZMM  (1ULL << 7)
#define XSTATE_LWP     (1ULL << 62) /* AMD lightweight profiling */
#define XSTATE_FP_SSE  (XSTATE_FP | XSTATE_SSE)
#define XCNTXT_MASK    (XSTATE_FP | XSTATE_SSE | XSTATE_YMM | XSTATE_OPMASK | \
                        XSTATE_ZMM | XSTATE_HI_ZMM | XSTATE_NONLAZY)

#define XSTATE_ALL     (~(1ULL << 63))
#define XSTATE_NONLAZY (XSTATE_LWP | XSTATE_BNDREGS | XSTATE_BNDCSR)
#define XSTATE_LAZY    (XSTATE_ALL & ~XSTATE_NONLAZY)

extern u64 xfeature_mask;
extern bool_t cpu_has_xsaves, cpu_has_xgetbv1;

/* extended state save area */
struct __packed __attribute__((aligned (64))) xsave_struct
{
    union {                                  /* FPU/MMX, SSE */
        char x[512];
        struct {
            uint16_t fcw;
            uint16_t fsw;
            uint8_t ftw;
            uint8_t rsvd1;
            uint16_t fop;
            union {
                uint64_t addr;
                struct {
                    uint32_t offs;
                    uint16_t sel;
                    uint16_t rsvd;
                };
            } fip, fdp;
            uint32_t mxcsr;
            uint32_t mxcsr_mask;
            /* data registers follow here */
        };
    } fpu_sse;

    struct {
        u64 xstate_bv;
        u64 reserved[7];
    } xsave_hdr;                             /* The 64-byte header */

    struct { char x[XSTATE_YMM_SIZE]; } ymm; /* YMM */
    char   data[];                           /* Future new states */
};

/* extended state operations */
bool_t __must_check set_xcr0(u64 xfeatures);
uint64_t get_xcr0(void);
void xsave(struct vcpu *v, uint64_t mask);
void xrstor(struct vcpu *v, uint64_t mask);
bool_t xsave_enabled(const struct vcpu *v);
int __must_check validate_xstate(u64 xcr0, u64 xcr0_accum, u64 xstate_bv);
int __must_check handle_xsetbv(u32 index, u64 new_bv);

/* extended state init and cleanup functions */
void xstate_free_save_area(struct vcpu *v);
int xstate_alloc_save_area(struct vcpu *v);
void xstate_init(bool_t bsp);
unsigned int xstate_ctxt_size(u64 xcr0);

#endif /* __ASM_XSTATE_H */
