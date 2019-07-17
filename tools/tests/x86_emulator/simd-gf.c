#define UINT_SIZE 1

#include "simd.h"
ENTRY(gf_test);

#if VEC_SIZE == 16
# define GF(op, s, a...) __builtin_ia32_vgf2p8 ## op ## _v16qi ## s(a)
#elif VEC_SIZE == 32
# define GF(op, s, a...) __builtin_ia32_vgf2p8 ## op ## _v32qi ## s(a)
#elif VEC_SIZE == 64
# define GF(op, s, a...) __builtin_ia32_vgf2p8 ## op ## _v64qi ## s(a)
#endif

#ifdef __AVX512BW__
# define ALL_TRUE (~0ULL >> (64 - ELEM_COUNT))
# define eq(x, y) (B(pcmpeqb, _mask, (vqi_t)(x), (vqi_t)(y), -1) == ALL_TRUE)
# define mul(x, y) GF(mulb, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0)
# define transform(m, dir, x, c) ({ \
    vec_t t_; \
    asm ( "vgf2p8affine" #dir "qb %[imm], %[matrix]%{1to%c[n]%}, %[src], %[dst]" \
          : [dst] "=v" (t_) \
          : [matrix] "m" (m), [src] "v" (x), [imm] "i" (c), [n] "i" (VEC_SIZE / 8) ); \
    t_; \
})
#else
# if defined(__AVX2__)
#  define bcstq(x) ({ \
    vdi_t t_; \
    asm ( "vpbroadcastq %1, %0" : "=x" (t_) : "m" (x) ); \
    t_; \
})
#  define to_bool(cmp) B(ptestc, , cmp, (vdi_t){} == 0)
# else
#  define bcstq(x) ((vdi_t){x, x})
#  define to_bool(cmp) (__builtin_ia32_pmovmskb128(cmp) == 0xffff)
# endif
# define eq(x, y) to_bool((x) == (y))
# define mul(x, y) GF(mulb, , (vqi_t)(x), (vqi_t)(y))
# define transform(m, dir, x, c) ({ \
    vdi_t m_ = bcstq(m); \
    touch(m_); \
    ((vec_t)GF(affine ## dir ## qb, , (vqi_t)(x), (vqi_t)m_, c)); \
})
#endif

const unsigned __attribute__((mode(DI))) ident = 0x0102040810204080ULL;

int gf_test(void)
{
    unsigned int i;
    vec_t src, one;

    for ( i = 0; i < ELEM_COUNT; ++i )
    {
        src[i] = i;
        one[i] = 1;
    }

    /* Special case for first iteration. */
    one[0] = 0;

    do {
        vec_t inv = transform(ident, inv, src, 0);

        touch(src);
        touch(inv);
        if ( !eq(mul(src, inv), one) ) return __LINE__;

        touch(src);
        touch(inv);
        if ( !eq(mul(inv, src), one) ) return __LINE__;

        one[0] = 1;

        src += ELEM_COUNT;
        i += ELEM_COUNT;
    } while ( i < 256 );

    return 0;
}
