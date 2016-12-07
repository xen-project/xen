#include "x86_emulate.h"

#define EFER_SCE       (1 << 0)
#define EFER_LMA       (1 << 10)

#define cpu_has_amd_erratum(nr) 0
#define mark_regs_dirty(r) ((void)(r))

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

#include "x86_emulate/x86_emulate.c"
