#include <asm/asm_defns.h>

.macro memset
        and     $7, %edx
        shr     $3, %rcx
        movzbl  %sil, %esi
        mov     $0x0101010101010101, %rax
        imul    %rsi, %rax
        mov     %rdi, %r8
        rep stosq
        or      %edx, %ecx
        jz      0f
        rep stosb
0:
        mov     %r8, %rax
        RET
.endm

.macro memset_erms
        mov     %esi, %eax
        mov     %rdi, %r8
        rep stosb
        mov     %r8, %rax
        RET
.endm

FUNC(memset)
        mov     %rdx, %rcx
        ALTERNATIVE memset, memset_erms, X86_FEATURE_ERMS
END(memset)
