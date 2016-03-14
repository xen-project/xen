#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <xen/xen.h>

typedef bool bool_t;

#define is_canonical_address(x) (((int64_t)(x) >> 47) == ((int64_t)(x) >> 63))

#define BUG() abort()
#define ASSERT assert

#define cpu_has_amd_erratum(nr) 0
#define mark_regs_dirty(r) ((void)(r))

#define __packed __attribute__((packed))

/* For generic assembly code: use macros to define operation/operand sizes. */
#ifdef __i386__
# define __OS          "l"  /* Operation Suffix */
# define __OP          "e"  /* Operand Prefix */
#else
# define __OS          "q"  /* Operation Suffix */
# define __OP          "r"  /* Operand Prefix */
#endif

#include "x86_emulate/x86_emulate.h"

#define get_stub(stb) ((void *)((stb).addr = (uintptr_t)(stb).buf))
#define put_stub(stb)

#include "x86_emulate/x86_emulate.c"
