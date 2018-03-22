#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if __GNUC__ >= 6
#pragma GCC target("no-sse")
#endif

#include <xen/xen.h>

#include <asm/msr-index.h>
#include <asm/x86-defns.h>
#include <asm/x86-vendors.h>

#define BUG() abort()
#define ASSERT assert
#define ASSERT_UNREACHABLE() assert(!__LINE__)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(cond) ({ _Static_assert(!(cond), "!(" #cond ")"); })
#define BUILD_BUG_ON_ZERO(cond) \
    sizeof(struct { _Static_assert(!(cond), "!(" #cond ")"); })
#else
#define BUILD_BUG_ON_ZERO(cond) sizeof(struct { int:-!!(cond); })
#define BUILD_BUG_ON(cond) ((void)BUILD_BUG_ON_ZERO(cond))
#endif

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

static inline uint64_t xgetbv(uint32_t xcr)
{
    uint32_t lo, hi;

    asm ( ".byte 0x0f, 0x01, 0xd0" : "=a" (lo), "=d" (hi) : "c" (xcr) );

    return ((uint64_t)hi << 32) | lo;
}

#define cache_line_size() ({		     \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    res.d & (1U << 19) ? (res.b >> 5) & 0x7f8 : 0; \
})

#define cpu_has_mmx ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.d & (1U << 23)) != 0; \
})

#define cpu_has_fxsr ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.d & (1U << 24)) != 0; \
})

#define cpu_has_sse ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.d & (1U << 25)) != 0; \
})

#define cpu_has_sse2 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.d & (1U << 26)) != 0; \
})

#define cpu_has_sse3 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.c & (1U << 0)) != 0; \
})

#define cpu_has_fma ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        res.c = 0; \
    (res.c & (1U << 12)) != 0; \
})

#define cpu_has_sse4_1 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.c & (1U << 19)) != 0; \
})

#define cpu_has_sse4_2 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.c & (1U << 20)) != 0; \
})

#define cpu_has_popcnt ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    (res.c & (1U << 23)) != 0; \
})

#define cpu_has_xsave ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    /* Intentionally checking OSXSAVE here. */ \
    (res.c & (1U << 27)) != 0; \
})

#define cpu_has_avx ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        res.c = 0; \
    (res.c & (1U << 28)) != 0; \
})

#define cpu_has_f16c ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        res.c = 0; \
    (res.c & (1U << 29)) != 0; \
})

#define cpu_has_avx2 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        res.b = 0; \
    else { \
        emul_test_cpuid(7, 0, &res, NULL); \
    } \
    (res.b & (1U << 5)) != 0; \
})

#define cpu_has_xgetbv1 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) ) \
        res.a = 0; \
    else \
        emul_test_cpuid(0xd, 1, &res, NULL); \
    (res.a & (1U << 2)) != 0; \
})

#define cpu_has_bmi1 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(7, 0, &res, NULL); \
    (res.b & (1U << 3)) != 0; \
})

#define cpu_has_bmi2 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(7, 0, &res, NULL); \
    (res.b & (1U << 8)) != 0; \
})

#define cpu_has_3dnow_ext ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(0x80000001, 0, &res, NULL); \
    (res.d & (1U << 30)) != 0; \
})

#define cpu_has_sse4a ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(0x80000001, 0, &res, NULL); \
    (res.c & (1U << 6)) != 0; \
})

#define cpu_has_xop ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        res.c = 0; \
    else \
        emul_test_cpuid(0x80000001, 0, &res, NULL); \
    (res.c & (1U << 11)) != 0; \
})

#define cpu_has_fma4 ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(1, 0, &res, NULL); \
    if ( !(res.c & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        res.c = 0; \
    else \
        emul_test_cpuid(0x80000001, 0, &res, NULL); \
    (res.c & (1U << 16)) != 0; \
})

#define cpu_has_tbm ({ \
    struct cpuid_leaf res; \
    emul_test_cpuid(0x80000001, 0, &res, NULL); \
    (res.c & (1U << 21)) != 0; \
})

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
