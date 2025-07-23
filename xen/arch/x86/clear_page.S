        .file __FILE__

#include <xen/linkage.h>

#include <asm/asm_defns.h>
#include <asm/page.h>

        .macro clear_page_sse2
        mov     $PAGE_SIZE/32, %ecx
        xor     %eax,%eax

0:      movnti  %rax,   (%rdi)
        movnti  %rax,  8(%rdi)
        movnti  %rax, 16(%rdi)
        movnti  %rax, 24(%rdi)
        add     $32, %rdi
        sub     $1, %ecx
        jnz     0b

        sfence
        RET
        .endm

        .macro clear_page_clzero
        mov     %rdi, %rax
        mov     $PAGE_SIZE/64, %ecx
        .globl clear_page_clzero_post_count
clear_page_clzero_post_count:

0:      clzero
        sub     $-64, %rax
        .globl clear_page_clzero_post_neg_size
clear_page_clzero_post_neg_size:
        sub     $1, %ecx
        jnz     0b

        sfence
        RET
        .endm

FUNC(clear_page_cold)
        ALTERNATIVE clear_page_sse2, clear_page_clzero, X86_FEATURE_CLZERO
END(clear_page_cold)

        .macro clear_page_stosb
        mov     $PAGE_SIZE, %ecx
        xor     %eax,%eax
        rep stosb
        .endm

        .macro clear_page_stosq
        mov     $PAGE_SIZE/8, %ecx
        xor     %eax, %eax
        rep stosq
        .endm

FUNC(clear_page_hot)
        ALTERNATIVE clear_page_stosq, clear_page_stosb, X86_FEATURE_ERMS
        RET
END(clear_page_hot)
