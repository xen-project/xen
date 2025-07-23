        .file __FILE__

#include <asm/asm_defns.h>
#include <xen/page-size.h>
#include <xen/scrub.h>

FUNC(scrub_page_cold)
        mov     $PAGE_SIZE/32, %ecx
        mov     $SCRUB_PATTERN, %rax

0:      movnti  %rax,   (%rdi)
        movnti  %rax,  8(%rdi)
        movnti  %rax, 16(%rdi)
        movnti  %rax, 24(%rdi)
        add     $32, %rdi
        sub     $1, %ecx
        jnz     0b

        sfence
        RET
END(scrub_page_cold)

        .macro scrub_page_stosb
        mov     $PAGE_SIZE, %ecx
        mov     $SCRUB_BYTE_PATTERN, %eax
        rep stosb
        .endm

        .macro scrub_page_stosq
        mov     $PAGE_SIZE/8, %ecx
        mov     $SCRUB_PATTERN, %rax
        rep stosq
        .endm

FUNC(scrub_page_hot)
        ALTERNATIVE scrub_page_stosq, scrub_page_stosb, X86_FEATURE_ERMS
        RET
END(scrub_page_hot)
