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

int emul_test_cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned int leaf = *eax;

    asm ("cpuid" : "+a" (*eax), "+c" (*ecx), "=d" (*edx), "=b" (*ebx));

    /*
     * The emulator doesn't itself use MOVBE, so we can always run the
     * respective tests.
     */
    if ( leaf == 1 )
        *ecx |= 1U << 22;

    return X86EMUL_OKAY;
}

int emul_test_read_cr(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    /* Fake just enough state for the emulator's _get_fpu() to be happy. */
    switch ( reg )
    {
    case 0:
        *val = 0x00000001; /* PE */
        return X86EMUL_OKAY;

    case 4:
        /* OSFXSR, OSXMMEXCPT, and maybe OSXSAVE */
        *val = 0x00000600 | (cpu_has_xsave ? 0x00040000 : 0);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

int emul_test_get_fpu(
    void (*exception_callback)(void *, struct cpu_user_regs *),
    void *exception_callback_arg,
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( type )
    {
    case X86EMUL_FPU_fpu:
        break;
    case X86EMUL_FPU_mmx:
        if ( cpu_has_mmx )
            break;
    case X86EMUL_FPU_xmm:
        if ( cpu_has_sse )
            break;
    case X86EMUL_FPU_ymm:
        if ( cpu_has_avx )
            break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }
    return X86EMUL_OKAY;
}

#include "x86_emulate/x86_emulate.c"
