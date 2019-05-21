#ifdef __i386__
# define R(x) e##x
# define DATA(x) x
#else
# if SIZE == 8
#  define R(x) r##x
# else
#  define R(x) e##x
# endif
# define DATA(x) x(%rip)
#endif

#if SIZE == 1
# define _(x) x##b
# define _v(x, t) _v_(x##q, t)
#elif SIZE == 2
# define _(x) x##w
# define _v(x, t) _v_(x##d, t)
# define WIDEN(x) x##bw
#elif SIZE == 4
# define _(x) x##d
# define _v(x, t) _v_(x##w, t)
# define WIDEN(x) x##wd
#elif SIZE == 8
# define _(x) x##q
# define _v(x, t) _v_(x##b, t)
# define WIDEN(x) x##dq
#endif

#define _v_(x, t) v##x##t

    .macro check res1:req, res2:req, line:req
    _(kmov)       %\res1, DATA(out)
#if SIZE < 8 || !defined(__i386__)
    _(kmov)       %\res2, %R(dx)
    cmp           DATA(out), %R(dx)
#else
    sub           $8, %esp
    kmovq         %\res2, (%esp)
    pop           %ecx
    pop           %edx
    cmp           DATA(out), %ecx
    jne           0f
    cmp           DATA(out+4), %edx
0:
#endif
    je            1f
    mov           $\line, %eax
    ret
1:
    .endm

    .text
    .globl _start
_start:
    _(kmov)       DATA(in1), %k1
#if SIZE < 8 || !defined(__i386__)
    mov           DATA(in2), %R(ax)
    _(kmov)       %R(ax), %k2
#else
    _(kmov)       DATA(in2), %k2
#endif

    _(kor)        %k1, %k2, %k3
    _(kand)       %k1, %k2, %k4
    _(kandn)      %k3, %k4, %k5
    _(kxor)       %k1, %k2, %k6
    check         k5, k6, __LINE__

    _(knot)       %k6, %k3
    _(kxnor)      %k1, %k2, %k4
    check         k3, k4, __LINE__

    _(kshiftl)    $1, %k1, %k3
    _(kshiftl)    $2, %k3, %k4
    _(kshiftl)    $3, %k1, %k5
    check         k4, k5, __LINE__

    _(kshiftr)    $1, %k1, %k3
    _(kshiftr)    $2, %k3, %k4
    _(kshiftr)    $3, %k1, %k5
    check         k4, k5, __LINE__

    _(kortest)    %k6, %k6
    jnbe          1f
    mov           $__LINE__, %eax
    ret
1:

    _(kxor)       %k0, %k0, %k3
    _(kortest)    %k3, %k3
    jz            1f
    mov           $__LINE__, %eax
    ret
1:

    _(kxnor)      %k0, %k0, %k3
    _(kortest)    %k3, %k3
    jc            1f
    mov           $__LINE__, %eax
    ret
1:

#if SIZE > 1

    _(kshiftr)    $SIZE*4, %k3, %k4
    WIDEN(kunpck) %k4, %k4, %k5
    check         k3, k5, __LINE__

#endif

#if SIZE != 2 || defined(__AVX512DQ__)

    _(kadd)       %k1, %k1, %k3
    _(kshiftl)    $1, %k1, %k4
    check         k3, k4, __LINE__

    _(ktest)      %k2, %k1
    jnbe          1f
    mov           $__LINE__, %eax
    ret
1:

    _(kxor)       %k0, %k0, %k3
    _(ktest)      %k0, %k3
    jz            1f
    mov           $__LINE__, %eax
    ret
1:

    _(kxnor)      %k0, %k0, %k4
    _(ktest)      %k0, %k4
    jc            1f
    mov           $__LINE__, %eax
    ret
1:

#endif

#if SIZE > 2 ? defined(__AVX512BW__) : defined(__AVX512DQ__)

    _(kmov)       DATA(in1), %k0
    _v(pmovm2,)   %k0, %zmm7
    _v(pmov,2m)   %zmm7, %k3
    check         k0, k3, __LINE__

#endif

    xor           %eax, %eax
    ret

    .section .rodata, "a", @progbits
    .balign 8
in1: .byte 0b10110011, 0b10001111, 0b00001111, 0b10000011, 0b11110000, 0b00111111, 0b10000000, 0b11111111
in2: .byte 0b11111111, 0b00000001, 0b11111100, 0b00001111, 0b11000001, 0b11110000, 0b11110001, 0b11001101

    .data
    .balign 8
out: .quad 0
