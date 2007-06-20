#include <xen/config.h>
#include <asm/page.h>

#ifdef __i386__
#define ptr_reg %edx
#else
#define ptr_reg %rdi
#endif

ENTRY(clear_page_sse2)
#ifdef __i386__
        mov     4(%esp), ptr_reg
#endif
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
