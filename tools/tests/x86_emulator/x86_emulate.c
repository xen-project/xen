#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <xen/xen.h>

#include "x86_emulate/x86_emulate.h"

typedef bool bool_t;

#define is_canonical_address(x) (((int64_t)(x) >> 47) == ((int64_t)(x) >> 63))

#define EFER_SCE       (1 << 0)
#define EFER_LMA       (1 << 10)

#define BUG() abort()
#define ASSERT assert
#define ASSERT_UNREACHABLE() assert(!__LINE__)

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

#define cpu_has_amd_erratum(nr) 0

/* For generic assembly code: use macros to define operation/operand sizes. */
#ifdef __i386__
# define __OS          "l"  /* Operation Suffix */
# define __OP          "e"  /* Operand Prefix */
#else
# define __OS          "q"  /* Operation Suffix */
# define __OP          "r"  /* Operand Prefix */
#endif

#define get_stub(stb) ((void *)((stb).addr = (uintptr_t)(stb).buf))
#define put_stub(stb)

#define __init
#define __maybe_unused __attribute__((__unused__))

#define likely(x)     __builtin_expect(!!(x), true)
#define unlikely(x)   __builtin_expect(!!(x), false)

#include "x86_emulate/x86_emulate.c"
