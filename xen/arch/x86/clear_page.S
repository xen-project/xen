        .file __FILE__

#include <asm/page.h>

ENTRY(clear_page_sse2)
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
        ret
