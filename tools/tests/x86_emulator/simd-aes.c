#define UINT_SIZE 1

#include "simd.h"
ENTRY(aes_test);

#if VEC_SIZE == 16
# define AES(op, a...) __builtin_ia32_vaes ## op ## _v16qi(a)
# define imc(x) ((vec_t)__builtin_ia32_aesimc128((vdi_t)(x)))
#elif VEC_SIZE == 32
# define AES(op, a...) __builtin_ia32_vaes ## op ## _v32qi(a)
# define imc(x) ({ \
    vec_t r_; \
    unsigned char __attribute__((vector_size(16))) t_; \
    asm ( "vaesimc (%3), %x0\n\t" \
          "vaesimc 16(%3), %1\n\t" \
          "vinserti128 $1, %1, %0, %0" \
          : "=&v" (r_), "=&v" (t_) \
          : "m" (x), "r" (&(x)) ); \
    r_; \
})
#elif VEC_SIZE == 64
# define AES(op, a...) __builtin_ia32_vaes ## op ## _v64qi(a)
# define imc(x) ({ \
    vec_t r_; \
    unsigned char __attribute__((vector_size(16))) t_; \
    asm ( "vaesimc (%3), %x0\n\t" \
          "vaesimc 1*16(%3), %1\n\t" \
          "vinserti32x4 $1, %1, %0, %0\n\t" \
          "vaesimc 2*16(%3), %1\n\t" \
          "vinserti32x4 $2, %1, %0, %0\n\t" \
          "vaesimc 3*16(%3), %1\n\t" \
          "vinserti32x4 $3, %1, %0, %0" \
          : "=&v" (r_), "=&v" (t_) \
          : "m" (x), "r" (&(x)) ); \
    r_; \
})
#endif

#ifdef __AVX512BW__
# define ALL_TRUE (~0ULL >> (64 - ELEM_COUNT))
# define eq(x, y) (B(pcmpeqb, _mask, (vqi_t)(x), (vqi_t)(y), -1) == ALL_TRUE)
# define aes(op, x, y) ((vec_t)AES(op, (vqi_t)(x), (vqi_t)(y)))
#else
# if defined(__AVX2__) && VEC_SIZE == 32
#  define to_bool(cmp) B(ptestc, , cmp, (vdi_t){} == 0)
#  define aes(op, x, y) ((vec_t)AES(op, (vqi_t)(x), (vqi_t)(y)))
# else
#  define to_bool(cmp) (__builtin_ia32_pmovmskb128(cmp) == 0xffff)
#  define aes(op, x, y) ((vec_t)__builtin_ia32_aes ## op ## 128((vdi_t)(x), (vdi_t)(y)))
# endif
# define eq(x, y) to_bool((x) == (y))
#endif

int aes_test(void)
{
    unsigned int i;
    vec_t src, zero = {};

    for ( i = 0; i < ELEM_COUNT; ++i )
        src[i] = i;

    do {
        vec_t x, y;

        touch(src);
        x = imc(src);
        touch(src);

        touch(zero);
        y = aes(enclast, src, zero);
        touch(zero);
        y = aes(dec, y, zero);

        if ( !eq(x, y) ) return __LINE__;

        touch(zero);
        x = aes(declast, src, zero);
        touch(zero);
        y = aes(enc, x, zero);
        touch(y);
        x = imc(y);

        if ( !eq(x, src) ) return __LINE__;

#if VEC_SIZE == 16
        touch(src);
        x = (vec_t)__builtin_ia32_aeskeygenassist128((vdi_t)src, 0);
        touch(src);
        y = (vec_t)__builtin_ia32_pshufb128((vqi_t)x,
                                            (vqi_t){  7,  4,  5,  6,
                                                      1,  2,  3,  0,
                                                     15, 12, 13, 14,
                                                      9, 10, 11,  8 });
        if ( !eq(x, y) ) return __LINE__;
#endif

        src += ELEM_COUNT;
        i += ELEM_COUNT;
    } while ( i <= 256 );

    return 0;
}
