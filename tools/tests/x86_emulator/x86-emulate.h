#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
/*
 * Use of sse registers must be disabled prior to the definition of
 * always_inline functions that would use them (memcpy, memset, etc),
 * so do this as early as possible, aiming to be before any always_inline
 * functions that are used are declared.
 * Unfortunately, this cannot be done prior to inclusion of <stdlib.h>
 * due to functions such as 'atof' that have SSE register return declared,
 * so do so here, immediately after that.
 */
#if __GNUC__ >= 6
# pragma GCC target("no-sse")
#endif
 /*
 * Attempt detection of unwanted prior inclusion of some headers known to use
 * always_inline with SSE registers in some library / compiler / optimization
 * combinations.
 */
#ifdef _STRING_H
# error "Must not include <string.h> before x86-emulate.h"
#endif
#include <string.h>

/* EOF is a standard macro defined in <stdio.h> so use it for detection */
#ifdef EOF
# error "Must not include <stdio.h> before x86-emulate.h"
#endif
#ifdef WRAP
# include <stdio.h>
#endif

#include <xen/xen.h>

#include <xen/asm/msr-index.h>
#include <xen/asm/x86-defns.h>
#include <xen/asm/x86-vendors.h>

#include <xen-tools/libs.h>

#define BUG() abort()
#define ASSERT assert
#define ASSERT_UNREACHABLE() assert(!__LINE__)

#define MASK_EXTR(v, m) (((v) & (m)) / ((m) & -(m)))
#define MASK_INSR(v, m) (((v) * ((m) & -(m))) & (m))

#define __init
#define __maybe_unused __attribute__((__unused__))

#define likely(x)   __builtin_expect(!!(x), true)
#define unlikely(x) __builtin_expect(!!(x), false)

#define container_of(ptr, type, member) ({             \
    typeof(((type *)0)->member) *mptr__ = (ptr);       \
    (type *)((char *)mptr__ - offsetof(type, member)); \
})

#define is_canonical_address(x) (((int64_t)(x) >> 47) == ((int64_t)(x) >> 63))

extern uint32_t mxcsr_mask;
extern struct cpuid_policy cp;

#define MMAP_SZ 16384
bool emul_test_init(void);

/* Must save and restore FPU state between any call into libc. */
void emul_save_fpu_state(void);
void emul_restore_fpu_state(void);

/*
 * In order to reasonably use the above, wrap library calls we use and which we
 * think might access any of the FPU state into wrappers saving/restoring state
 * around the actual function.
 */
#ifndef WRAP
# if 0 /* This only works for explicit calls, not for compiler generated ones. */
#  define WRAP(x) typeof(x) x asm("emul_" #x)
# else
# define WRAP(x) asm(".equ " #x ", emul_" #x)
# endif
#endif

WRAP(fwrite);
WRAP(memcmp);
WRAP(memcpy);
WRAP(memset);
WRAP(printf);
WRAP(putchar);
WRAP(puts);

#undef WRAP

#include "x86_emulate/x86_emulate.h"

void evex_disp8_test(void *instr, struct x86_emulate_ctxt *ctxt,
                     const struct x86_emulate_ops *ops);

static inline uint64_t xgetbv(uint32_t xcr)
{
    uint32_t lo, hi;

    asm ( ".byte 0x0f, 0x01, 0xd0" : "=a" (lo), "=d" (hi) : "c" (xcr) );

    return ((uint64_t)hi << 32) | lo;
}

/* Intentionally checking OSXSAVE here. */
#define cpu_has_xsave     (cp.basic.raw[1].c & (1u << 27))

static inline bool xcr0_mask(uint64_t mask)
{
    return cpu_has_xsave && ((xgetbv(0) & mask) == mask);
}

#define cache_line_size() (cp.basic.clflush_size * 8)
#define cpu_has_mmx        cp.basic.mmx
#define cpu_has_fxsr       cp.basic.fxsr
#define cpu_has_sse        cp.basic.sse
#define cpu_has_sse2       cp.basic.sse2
#define cpu_has_sse3       cp.basic.sse3
#define cpu_has_fma       (cp.basic.fma && xcr0_mask(6))
#define cpu_has_sse4_1     cp.basic.sse4_1
#define cpu_has_sse4_2     cp.basic.sse4_2
#define cpu_has_popcnt     cp.basic.popcnt
#define cpu_has_avx       (cp.basic.avx  && xcr0_mask(6))
#define cpu_has_f16c      (cp.basic.f16c && xcr0_mask(6))

#define cpu_has_avx2      (cp.feat.avx2 && xcr0_mask(6))
#define cpu_has_bmi1       cp.feat.bmi1
#define cpu_has_bmi2       cp.feat.bmi2
#define cpu_has_avx512f   (cp.feat.avx512f  && xcr0_mask(0xe6))
#define cpu_has_avx512dq  (cp.feat.avx512dq && xcr0_mask(0xe6))
#define cpu_has_avx512bw  (cp.feat.avx512bw && xcr0_mask(0xe6))
#define cpu_has_avx512vl  (cp.feat.avx512vl && xcr0_mask(0xe6))

#define cpu_has_xgetbv1   (cpu_has_xsave && cp.xstate.xgetbv1)

#define cpu_has_3dnow_ext  cp.extd._3dnowext
#define cpu_has_sse4a      cp.extd.sse4a
#define cpu_has_xop       (cp.extd.xop  && xcr0_mask(6))
#define cpu_has_fma4      (cp.extd.fma4 && xcr0_mask(6))
#define cpu_has_tbm        cp.extd.tbm

int emul_test_cpuid(
    uint32_t leaf,
    uint32_t subleaf,
    struct cpuid_leaf *res,
    struct x86_emulate_ctxt *ctxt);

int emul_test_read_cr(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt);

int emul_test_read_xcr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt);

int emul_test_get_fpu(
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt);

void emul_test_put_fpu(
    struct x86_emulate_ctxt *ctxt,
    enum x86_emulate_fpu_type backout,
    const struct x86_emul_fpu_aux *aux);
