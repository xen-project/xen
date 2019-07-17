#define UINT_SIZE 8

#include "simd.h"
ENTRY(clmul_test);

#ifdef __AVX512F__ /* AVX512BW may get enabled only below */
# define ALL_TRUE (~0ULL >> (64 - ELEM_COUNT))
# define eq(x, y) (B(pcmpeqq, _mask, (vdi_t)(x), (vdi_t)(y), -1) == ALL_TRUE)
# define lane_shr_unit(x) \
    ((vec_t)B(palignr, _mask, (vdi_t)(x), (vdi_t)(x), 64, (vdi_t){}, \
              0x00ff00ff00ff00ffULL & (~0ULL >> (64 - VEC_SIZE))))
#else
# if defined(__AVX2__) && VEC_SIZE == 32
#  define to_bool(cmp) B(ptestc, , cmp, (vdi_t){} == 0)
# else
#  define to_bool(cmp) (__builtin_ia32_pmovmskb128(cmp) == 0xffff)
# endif
# define eq(x, y) to_bool((x) == (y))
# define lane_shr_unit(x) ((vec_t)B(palignr, , (vdi_t){}, (vdi_t)(x), 64))
#endif

#define CLMUL(op, x, y, c) (vec_t)(__builtin_ia32_ ## op((vdi_t)(x), (vdi_t)(y), c))

#if VEC_SIZE == 16
# define clmul(x, y, c) CLMUL(pclmulqdq128, x, y, c)
# define vpshrd __builtin_ia32_vpshrd_v2di
#elif VEC_SIZE == 32
# define clmul(x, y, c) CLMUL(vpclmulqdq_v4di, x, y, c)
# define vpshrd __builtin_ia32_vpshrd_v4di
#elif VEC_SIZE == 64
# define clmul(x, y, c) CLMUL(vpclmulqdq_v8di, x, y, c)
# define vpshrd __builtin_ia32_vpshrd_v8di
#endif

#define clmul_ll(x, y) clmul(x, y, 0x00)
#define clmul_hl(x, y) clmul(x, y, 0x01)
#define clmul_lh(x, y) clmul(x, y, 0x10)
#define clmul_hh(x, y) clmul(x, y, 0x11)

#if defined(__AVX512VBMI2__)
# pragma GCC target ( "avx512bw" )
# define lane_shr_i(x, n) ({ \
    vec_t h_ = lane_shr_unit(x); \
    touch(h_); \
    (n) < 64 ? (vec_t)vpshrd((vdi_t)(x), (vdi_t)(h_), n) : h_ >> ((n) - 64); \
})
# define lane_shr_v(x, n) ({ \
    vec_t t_ = (x), h_ = lane_shr_unit(x); \
    typeof(t_[0]) n_ = (n); \
    if ( (n) < 64 ) \
        /* gcc does not support embedded broadcast */ \
        asm ( "vpshrdvq %2%{1to%c3%}, %1, %0" \
              : "+v" (t_) : "v" (h_), "m" (n_), "i" (ELEM_COUNT) ); \
    else \
        t_ = h_ >> ((n) - 64); \
    t_; \
})
#else
# define lane_shr_i lane_shr_v
# define lane_shr_v(x, n) ({ \
    vec_t t_ = (n) > 0 ? lane_shr_unit(x) : (x); \
    (n) < 64 ? ((x) >> (n)) | (t_ << (-(n) & 0x3f)) \
             : t_ >> ((n) - 64); \
})
#endif

int clmul_test(void)
{
    unsigned int i;
    vec_t src;
    vqi_t raw = {};

    for ( i = 1; i < VEC_SIZE; ++i )
        raw[i] = i;
    src = (vec_t)raw;

    for ( i = 0; i < 256; i += VEC_SIZE )
    {
        vec_t x = {}, y, z, lo, hi;
        unsigned int j;

        touch(x);
        y = clmul_ll(src, x);
        touch(x);

        if ( !eq(y, x) ) return __LINE__;

        for ( j = 0; j < ELEM_COUNT; j += 2 )
            x[j] = 1;

        touch(src);
        y = clmul_ll(x, src);
        touch(src);
        z = clmul_lh(x, src);
        touch(src);

        for ( j = 0; j < ELEM_COUNT; j += 2 )
            y[j + 1] = z[j];

        if ( !eq(y, src) ) return __LINE__;

        /*
         * Besides the obvious property of the low and high half products
         * being the same either direction, the "square" of a number has the
         * property of simply being the original bit pattern with a zero bit
         * inserted between any two bits. This is what the code below checks.
         */

        x = src;
        touch(src);
        y = clmul_lh(x, src);
        touch(src);
        z = clmul_hl(x, src);

        if ( !eq(y, z) ) return __LINE__;

        touch(src);
        y = lo = clmul_ll(x, src);
        touch(src);
        z = hi = clmul_hh(x, src);
        touch(src);

        for ( j = 0; j < 64; ++j )
        {
            vec_t l = lane_shr_v(lo, 2 * j);
            vec_t h = lane_shr_v(hi, 2 * j);
            unsigned int n;

            if ( !eq(l, y) ) return __LINE__;
            if ( !eq(h, z) ) return __LINE__;

            x = src >> j;

            for ( n = 0; n < ELEM_COUNT; n += 2 )
            {
                if ( (x[n + 0] & 1) != (l[n] & 3) ) return __LINE__;
                if ( (x[n + 1] & 1) != (h[n] & 3) ) return __LINE__;
            }

            touch(y);
            y = lane_shr_i(y, 2);
            touch(z);
            z = lane_shr_i(z, 2);
        }

        src += 0x0101010101010101ULL * VEC_SIZE;
    }

    return 0;
}
