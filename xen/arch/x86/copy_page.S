#include <xen/config.h>
#include <asm/page.h>

#define src_reg %rsi
#define dst_reg %rdi
#define WORD_SIZE 8
#define tmp1_reg %r8
#define tmp2_reg %r9
#define tmp3_reg %r10
#define tmp4_reg %r11

ENTRY(copy_page_sse2)
        mov     $PAGE_SIZE/(4*WORD_SIZE)-3, %ecx

        prefetchnta 2*4*WORD_SIZE(src_reg)
        mov     (src_reg), tmp1_reg
        mov     WORD_SIZE(src_reg), tmp2_reg
        mov     2*WORD_SIZE(src_reg), tmp3_reg
        mov     3*WORD_SIZE(src_reg), tmp4_reg

0:      prefetchnta 3*4*WORD_SIZE(src_reg)
1:      add     $4*WORD_SIZE, src_reg
        movnti  tmp1_reg, (dst_reg)
        mov     (src_reg), tmp1_reg
        dec     %ecx
        movnti  tmp2_reg, WORD_SIZE(dst_reg)
        mov     WORD_SIZE(src_reg), tmp2_reg
        movnti  tmp3_reg, 2*WORD_SIZE(dst_reg)
        mov     2*WORD_SIZE(src_reg), tmp3_reg
        movnti  tmp4_reg, 3*WORD_SIZE(dst_reg)
        lea     4*WORD_SIZE(dst_reg), dst_reg
        mov     3*WORD_SIZE(src_reg), tmp4_reg
        jg      0b
        jpe     1b

        movnti  tmp1_reg, (dst_reg)
        movnti  tmp2_reg, WORD_SIZE(dst_reg)
        movnti  tmp3_reg, 2*WORD_SIZE(dst_reg)
        movnti  tmp4_reg, 3*WORD_SIZE(dst_reg)

        sfence
        ret
