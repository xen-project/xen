#include <asm/asm_defns.h>

FUNC(memcpy)
        mov     %rdx, %rcx
        mov     %rdi, %rax
        /*
         * We need to be careful here: memcpy() is involved in alternatives
         * patching, so the code doing the actual copying (i.e. past setting
         * up registers) may not be subject to patching (unless further
         * precautions were taken).
         */
        ALTERNATIVE "and $7, %edx; shr $3, %rcx", \
                    STR(rep movsb; RET), X86_FEATURE_ERMS
        rep movsq
        or      %edx, %ecx
        jz      1f
        rep movsb
1:
        RET
END(memcpy)
