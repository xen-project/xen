#include "x86_emulate.h"

#include <sys/mman.h>

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

bool emul_test_make_stack_executable(void)
{
    unsigned long sp;

    /*
     * Mark the entire stack executable so that the stub executions
     * don't fault
     */
#ifdef __x86_64__
    asm ("movq %%rsp, %0" : "=g" (sp));
#else
    asm ("movl %%esp, %0" : "=g" (sp));
#endif

    return mprotect((void *)(sp & -0x1000L) - (MMAP_SZ - 0x1000),
                    MMAP_SZ, PROT_READ|PROT_WRITE|PROT_EXEC) == 0;
}

#include "x86_emulate/x86_emulate.c"
