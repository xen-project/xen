        .file __FILE__

#include <asm/page.h>

#define ptr_reg %rdi

ENTRY(clear_page_sse2)
        mov     $PAGE_SIZE/16, %ecx
        xor     %eax,%eax

0:      dec     %ecx
        movnti  %eax, (ptr_reg)
        movnti  %eax, 4(ptr_reg)
        movnti  %eax, 8(ptr_reg)
        movnti  %eax, 12(ptr_reg)
        lea     16(ptr_reg), ptr_reg
        jnz     0b

        sfence
        ret
