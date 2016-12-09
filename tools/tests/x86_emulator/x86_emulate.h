#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <xen/xen.h>

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

#define is_canonical_address(x) (((int64_t)(x) >> 47) == ((int64_t)(x) >> 63))

#define MMAP_SZ 16384
bool emul_test_make_stack_executable(void);

#include "x86_emulate/x86_emulate.h"

static inline uint64_t xgetbv(uint32_t xcr)
{
    uint32_t lo, hi;

    asm ( ".byte 0x0f, 0x01, 0xd0" : "=a" (lo), "=d" (hi) : "c" (xcr) );

    return ((uint64_t)hi << 32) | lo;
}

#define cache_line_size() ({		     \
    unsigned int eax = 1, ebx, ecx = 0, edx; \
    emul_test_cpuid(&eax, &ebx, &ecx, &edx, NULL); \
    edx & (1U << 19) ? (ebx >> 5) & 0x7f8 : 0; \
})

#define cpu_has_mmx ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emul_test_cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 23)) != 0; \
})

#define cpu_has_sse ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emul_test_cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 25)) != 0; \
})

#define cpu_has_sse2 ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emul_test_cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 26)) != 0; \
})

#define cpu_has_xsave ({ \
    unsigned int eax = 1, ecx = 0; \
    emul_test_cpuid(&eax, &eax, &ecx, &eax, NULL); \
    /* Intentionally checking OSXSAVE here. */ \
    (ecx & (1U << 27)) != 0; \
})

#define cpu_has_avx ({ \
    unsigned int eax = 1, ecx = 0; \
    emul_test_cpuid(&eax, &eax, &ecx, &eax, NULL); \
    if ( !(ecx & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        ecx = 0; \
    (ecx & (1U << 28)) != 0; \
})

#define cpu_has_avx2 ({ \
    unsigned int eax = 1, ebx, ecx = 0; \
    emul_test_cpuid(&eax, &ebx, &ecx, &eax, NULL); \
    if ( !(ecx & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        ebx = 0; \
    else { \
        eax = 7, ecx = 0; \
        emul_test_cpuid(&eax, &ebx, &ecx, &eax, NULL); \
    } \
    (ebx & (1U << 5)) != 0; \
})

int emul_test_cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt);

int emul_test_read_cr(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt);

int emul_test_get_fpu(
    void (*exception_callback)(void *, struct cpu_user_regs *),
    void *exception_callback_arg,
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt);
