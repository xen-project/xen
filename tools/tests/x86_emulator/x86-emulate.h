#ifndef X86_EMULATE_H
#define X86_EMULATE_H

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
#include <stdio.h>

#include <xen/xen.h>

#include <xen/asm/msr-index.h>
#include <xen/asm/x86-defns.h>
#include <xen/asm/x86-vendors.h>

#include <xen-tools/common-macros.h>

#define ASSERT assert
#define ASSERT_UNREACHABLE() assert(!__LINE__)

#define DEFINE_PER_CPU(type, var) type per_cpu_##var
#define this_cpu(var) per_cpu_##var

#define __init
#define __maybe_unused __attribute__((__unused__))

#define likely(x)   __builtin_expect(!!(x), true)
#define unlikely(x) __builtin_expect(!!(x), false)

#define cf_check /* No Control Flow Integriy checking */

/*
 * Pseudo keyword 'fallthrough' to make explicit the fallthrough intention at
 * the end of a case statement block.
 */
#if !defined(__clang__) && (__GNUC__ >= 7)
# define fallthrough        __attribute__((__fallthrough__))
#else
# define fallthrough        do {} while (0)  /* fallthrough */
#endif

#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define ASM_FLAG_OUT(yes, no) yes
#else
# define ASM_FLAG_OUT(yes, no) no
#endif

#define hweight32 __builtin_popcount
#define hweight64 __builtin_popcountll

#define is_canonical_address(x) (((int64_t)(x) >> 47) == ((int64_t)(x) >> 63))

extern uint32_t mxcsr_mask;
extern struct cpu_policy cpu_policy;

#define MMAP_SZ 16384
bool emul_test_init(void);

/* Must save and restore FPU state between any call into libc. */
void emul_save_fpu_state(void);
void emul_restore_fpu_state(void);

struct x86_fxsr *get_fpu_save_area(void);

/*
 * In order to reasonably use the above, wrap library calls we use and which we
 * think might access any of the FPU state into wrappers saving/restoring state
 * around the actual function.
 */
#ifndef WRAP
# define WRAP(x) typeof(x) __wrap_ ## x
#endif

WRAP(fwrite);
WRAP(memcmp);
WRAP(memcpy);
WRAP(memset);
WRAP(printf);
WRAP(putchar);
WRAP(puts);
WRAP(snprintf);
WRAP(strstr);
WRAP(vprintf);
WRAP(vsnprintf);

#undef WRAP

#include "x86_emulate/x86_emulate.h"

void evex_disp8_test(void *instr, struct x86_emulate_ctxt *ctxt,
                     const struct x86_emulate_ops *ops);
void predicates_test(void *instr, struct x86_emulate_ctxt *ctxt,
                     int (*fetch)(unsigned long offset,
                                  void *p_data,
                                  unsigned int bytes,
                                  struct x86_emulate_ctxt *ctxt));

static inline uint64_t xgetbv(uint32_t xcr)
{
    uint32_t lo, hi;

    asm ( ".byte 0x0f, 0x01, 0xd0" : "=a" (lo), "=d" (hi) : "c" (xcr) );

    return ((uint64_t)hi << 32) | lo;
}

/* Intentionally checking OSXSAVE here. */
#define cpu_has_xsave     (cpu_policy.basic.raw[1].c & (1u << 27))

static inline bool xcr0_mask(uint64_t mask)
{
    return cpu_has_xsave && ((xgetbv(0) & mask) == mask);
}

unsigned int rdpkru(void);
void wrpkru(unsigned int val);

#define cache_line_size()           (cpu_policy.basic.clflush_size * 8)
#define cpu_has_fpu                  cpu_policy.basic.fpu
#define cpu_has_mmx                  cpu_policy.basic.mmx
#define cpu_has_fxsr                 cpu_policy.basic.fxsr
#define cpu_has_sse                  cpu_policy.basic.sse
#define cpu_has_sse2                 cpu_policy.basic.sse2
#define cpu_has_sse3                 cpu_policy.basic.sse3
#define cpu_has_pclmulqdq            cpu_policy.basic.pclmulqdq
#define cpu_has_ssse3                cpu_policy.basic.ssse3
#define cpu_has_fma                 (cpu_policy.basic.fma && xcr0_mask(6))
#define cpu_has_sse4_1               cpu_policy.basic.sse4_1
#define cpu_has_sse4_2               cpu_policy.basic.sse4_2
#define cpu_has_popcnt               cpu_policy.basic.popcnt
#define cpu_has_aesni                cpu_policy.basic.aesni
#define cpu_has_avx                 (cpu_policy.basic.avx  && xcr0_mask(6))
#define cpu_has_f16c                (cpu_policy.basic.f16c && xcr0_mask(6))

#define cpu_has_avx2                (cpu_policy.feat.avx2 && xcr0_mask(6))
#define cpu_has_bmi1                 cpu_policy.feat.bmi1
#define cpu_has_bmi2                 cpu_policy.feat.bmi2
#define cpu_has_avx512f             (cpu_policy.feat.avx512f && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512dq            (cpu_policy.feat.avx512dq && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512_ifma         (cpu_policy.feat.avx512_ifma && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512cd            (cpu_policy.feat.avx512cd && \
                                     xcr0_mask(0xe6))
#define cpu_has_sha                  cpu_policy.feat.sha
#define cpu_has_avx512bw            (cpu_policy.feat.avx512bw && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512vl            (cpu_policy.feat.avx512vl && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512_vbmi         (cpu_policy.feat.avx512_vbmi && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512_vbmi2        (cpu_policy.feat.avx512_vbmi2 && \
                                     xcr0_mask(0xe6))
#define cpu_has_gfni                 cpu_policy.feat.gfni
#define cpu_has_vaes                (cpu_policy.feat.vaes && xcr0_mask(6))
#define cpu_has_vpclmulqdq          (cpu_policy.feat.vpclmulqdq && xcr0_mask(6))
#define cpu_has_avx512_vnni         (cpu_policy.feat.avx512_vnni && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512_bitalg       (cpu_policy.feat.avx512_bitalg && \
                                     xcr0_mask(0xe6))
#define cpu_has_avx512_vpopcntdq    (cpu_policy.feat.avx512_vpopcntdq && \
                                     xcr0_mask(0xe6))
#define cpu_has_movdiri              cpu_policy.feat.movdiri
#define cpu_has_movdir64b            cpu_policy.feat.movdir64b
#define cpu_has_avx512_vp2intersect (cpu_policy.feat.avx512_vp2intersect && \
                                     xcr0_mask(0xe6))
#define cpu_has_serialize            cpu_policy.feat.serialize
#define cpu_has_avx512_fp16         (cpu_policy.feat.avx512_fp16 && \
                                     xcr0_mask(0xe6))
#define cpu_has_sha512              (cpu_policy.feat.sha512 && xcr0_mask(6))
#define cpu_has_sm3                 (cpu_policy.feat.sm3 && xcr0_mask(6))
#define cpu_has_sm4                 (cpu_policy.feat.sm4 && xcr0_mask(6))
#define cpu_has_avx_vnni            (cpu_policy.feat.avx_vnni && xcr0_mask(6))
#define cpu_has_avx512_bf16         (cpu_policy.feat.avx512_bf16 && \
                                     xcr0_mask(0xe6))
#define cpu_has_cmpccxadd            cpu_policy.feat.cmpccxadd
#define cpu_has_avx_ifma            (cpu_policy.feat.avx_ifma && xcr0_mask(6))
#define cpu_has_avx_vnni_int8       (cpu_policy.feat.avx_vnni_int8 && \
                                     xcr0_mask(6))
#define cpu_has_avx_ne_convert      (cpu_policy.feat.avx_ne_convert && \
                                     xcr0_mask(6))
#define cpu_has_avx_vnni_int16      (cpu_policy.feat.avx_vnni_int16 && \
                                     xcr0_mask(6))

#define cpu_has_xgetbv1             (cpu_has_xsave && cpu_policy.xstate.xgetbv1)

#define cpu_has_3dnow_ext            cpu_policy.extd._3dnowext
#define cpu_has_sse4a                cpu_policy.extd.sse4a
#define cpu_has_xop                 (cpu_policy.extd.xop  && xcr0_mask(6))
#define cpu_has_fma4                (cpu_policy.extd.fma4 && xcr0_mask(6))
#define cpu_has_tbm                  cpu_policy.extd.tbm

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

#endif /* X86_EMULATE_H */
