/*
 * include/asm-i386/xstate.h
 *
 * x86 extended state (xsave/xrstor) related definitions
 * 
 */

#ifndef __ASM_XSTATE_H
#define __ASM_XSTATE_H

#include <xen/sched.h>
#include <asm/cpufeature.h>

#define FCW_DEFAULT               0x037f
#define FCW_RESET                 0x0040
#define MXCSR_DEFAULT             0x1f80

extern uint32_t mxcsr_mask;

#define XSTATE_CPUID              0x0000000d

#define XCR_XFEATURE_ENABLED_MASK 0x00000000  /* index of XCR0 */

#define XSAVE_HDR_SIZE            64
#define XSAVE_SSE_OFFSET          160
#define XSTATE_YMM_SIZE           256
#define FXSAVE_SIZE               512
#define XSAVE_HDR_OFFSET          FXSAVE_SIZE
#define XSTATE_AREA_MIN_SIZE      (FXSAVE_SIZE + XSAVE_HDR_SIZE)

#define _XSTATE_FP                0
#define XSTATE_FP                 (1ULL << _XSTATE_FP)
#define _XSTATE_SSE               1
#define XSTATE_SSE                (1ULL << _XSTATE_SSE)
#define _XSTATE_YMM               2
#define XSTATE_YMM                (1ULL << _XSTATE_YMM)
#define _XSTATE_BNDREGS           3
#define XSTATE_BNDREGS            (1ULL << _XSTATE_BNDREGS)
#define _XSTATE_BNDCSR            4
#define XSTATE_BNDCSR             (1ULL << _XSTATE_BNDCSR)
#define _XSTATE_OPMASK            5
#define XSTATE_OPMASK             (1ULL << _XSTATE_OPMASK)
#define _XSTATE_ZMM               6
#define XSTATE_ZMM                (1ULL << _XSTATE_ZMM)
#define _XSTATE_HI_ZMM            7
#define XSTATE_HI_ZMM             (1ULL << _XSTATE_HI_ZMM)
#define _XSTATE_PKRU              9
#define XSTATE_PKRU               (1ULL << _XSTATE_PKRU)
#define _XSTATE_LWP               62
#define XSTATE_LWP                (1ULL << _XSTATE_LWP)

#define XSTATE_FP_SSE  (XSTATE_FP | XSTATE_SSE)
#define XCNTXT_MASK    (XSTATE_FP | XSTATE_SSE | XSTATE_YMM | XSTATE_OPMASK | \
                        XSTATE_ZMM | XSTATE_HI_ZMM | XSTATE_NONLAZY)

#define XSTATE_ALL     (~(1ULL << 63))
#define XSTATE_NONLAZY (XSTATE_LWP | XSTATE_BNDREGS | XSTATE_BNDCSR | \
                        XSTATE_PKRU)
#define XSTATE_LAZY    (XSTATE_ALL & ~XSTATE_NONLAZY)
#define XSTATE_XSAVES_ONLY         0
#define XSTATE_COMPACTION_ENABLED  (1ULL << 63)

#define XSTATE_ALIGN64 (1U << 1)

extern u64 xfeature_mask;
extern u64 xstate_align;
extern unsigned int *xstate_offsets;
extern unsigned int *xstate_sizes;

/* extended state save area */
struct __attribute__((aligned (64))) xsave_struct
{
    union __attribute__((aligned(16))) {     /* FPU/MMX, SSE */
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

    struct xsave_hdr {
        u64 xstate_bv;
        u64 xcomp_bv;
        u64 reserved[6];
    } xsave_hdr;                             /* The 64-byte header */

    char data[];                             /* Variable layout states */
};

struct xstate_bndcsr {
    uint64_t bndcfgu;
    uint64_t bndstatus;
};

/* extended state operations */
bool __must_check set_xcr0(u64 xfeatures);
uint64_t get_xcr0(void);
void set_msr_xss(u64 xss);
uint64_t get_msr_xss(void);
uint64_t read_bndcfgu(void);
void xsave(struct vcpu *v, uint64_t mask);
void xrstor(struct vcpu *v, uint64_t mask);
void xstate_set_init(uint64_t mask);
bool xsave_enabled(const struct vcpu *v);
int __must_check validate_xstate(u64 xcr0, u64 xcr0_accum,
                                 const struct xsave_hdr *);
int __must_check handle_xsetbv(u32 index, u64 new_bv);
void expand_xsave_states(struct vcpu *v, void *dest, unsigned int size);
void compress_xsave_states(struct vcpu *v, const void *src, unsigned int size);

/* extended state init and cleanup functions */
void xstate_free_save_area(struct vcpu *v);
int xstate_alloc_save_area(struct vcpu *v);
void xstate_init(struct cpuinfo_x86 *c);
unsigned int xstate_ctxt_size(u64 xcr0);

static inline bool xstate_all(const struct vcpu *v)
{
    /*
     * XSTATE_FP_SSE may be excluded, because the offsets of XSTATE_FP_SSE
     * (in the legacy region of xsave area) are fixed, so saving
     * XSTATE_FP_SSE will not cause overwriting problem with XSAVES/XSAVEC.
     */
    return (v->arch.xsave_area->xsave_hdr.xcomp_bv &
            XSTATE_COMPACTION_ENABLED) &&
           (v->arch.xcr0_accum & XSTATE_LAZY & ~XSTATE_FP_SSE);
}

static inline bool __nonnull(1)
xsave_area_compressed(const struct xsave_struct *xsave_area)
{
    return xsave_area->xsave_hdr.xcomp_bv & XSTATE_COMPACTION_ENABLED;
}

#endif /* __ASM_XSTATE_H */
