        .file __FILE__

#include <xen/linkage.h>
#include <asm/page.h>

FUNC(clear_page_sse2)
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
END(clear_page_sse2)
