#if !defined(__XOP__) && !defined(__AVX512F__)
#include "simd.h"
ENTRY(fma_test);
#endif

#if VEC_SIZE < 16 && !defined(to_bool)
# define to_bool(cmp) (!~(cmp)[0])
#elif VEC_SIZE == 16 && !defined(__AVX512VL__)
# if FLOAT_SIZE == 4
#  define to_bool(cmp) __builtin_ia32_vtestcps(cmp, (vec_t){} == 0)
# elif FLOAT_SIZE == 8
#  define to_bool(cmp) __builtin_ia32_vtestcpd(cmp, (vec_t){} == 0)
# endif
#elif VEC_SIZE == 32 && !defined(__AVX512VL__)
# if FLOAT_SIZE == 4
#  define to_bool(cmp) __builtin_ia32_vtestcps256(cmp, (vec_t){} == 0)
# elif FLOAT_SIZE == 8
#  define to_bool(cmp) __builtin_ia32_vtestcpd256(cmp, (vec_t){} == 0)
# endif
#endif

#ifndef eq
# define eq(x, y) to_bool((x) == (y))
#endif

#if defined(__AVX512F__) && VEC_SIZE > FLOAT_SIZE
# if FLOAT_SIZE == 4
#  define fmaddsub(x, y, z) BR(vfmaddsubps, _mask, x, y, z, ~0)
# elif FLOAT_SIZE == 8
#  define fmaddsub(x, y, z) BR(vfmaddsubpd, _mask, x, y, z, ~0)
# endif
#elif VEC_SIZE == 16
# if FLOAT_SIZE == 4
#  define addsub(x, y) __builtin_ia32_addsubps(x, y)
#  if defined(__FMA4__) || defined(__FMA__)
#   define fmaddsub(x, y, z) __builtin_ia32_vfmaddsubps(x, y, z)
#  endif
# elif FLOAT_SIZE == 8
#  define addsub(x, y) __builtin_ia32_addsubpd(x, y)
#  if defined(__FMA4__) || defined(__FMA__)
#   define fmaddsub(x, y, z) __builtin_ia32_vfmaddsubpd(x, y, z)
#  endif
# endif
#elif VEC_SIZE == 32
# if FLOAT_SIZE == 4
#  define addsub(x, y) __builtin_ia32_addsubps256(x, y)
#  if defined(__FMA4__) || defined(__FMA__)
#   define fmaddsub(x, y, z) __builtin_ia32_vfmaddsubps256(x, y, z)
#  endif
# elif FLOAT_SIZE == 8
#  define addsub(x, y) __builtin_ia32_addsubpd256(x, y)
#  if defined(__FMA4__) || defined(__FMA__)
#   define fmaddsub(x, y, z) __builtin_ia32_vfmaddsubpd256(x, y, z)
#  endif
# endif
#endif

#if defined(fmaddsub) && !defined(addsub)
# define addsub(x, y) fmaddsub(x, broadcast(1), y)
#endif

int fma_test(void)
{
    unsigned int i;
    vec_t x, y, z, src, inv, one;

    for ( i = 0; i < ELEM_COUNT; ++i )
    {
        src[i] = i + 1;
        inv[i] = ELEM_COUNT - i;
        one[i] = 1;
    }

    x = (src + one) * inv;
    y = (src - one) * inv;
    touch(src);
    z = inv * src + inv;
    if ( !eq(x, z) ) return __LINE__;

    touch(src);
    z = -inv * src - inv;
    if ( !eq(-x, z) ) return __LINE__;

    touch(src);
    z = inv * src - inv;
    if ( !eq(y, z) ) return __LINE__;

    touch(src);
    z = -inv * src + inv;
    if ( !eq(-y, z) ) return __LINE__;
    touch(src);

    x = src + inv;
    y = src - inv;
    touch(inv);
    z = src * one + inv;
    if ( !eq(x, z) ) return __LINE__;

    touch(inv);
    z = -src * one - inv;
    if ( !eq(-x, z) ) return __LINE__;

    touch(inv);
    z = src * one - inv;
    if ( !eq(y, z) ) return __LINE__;

    touch(inv);
    z = -src * one + inv;
    if ( !eq(-y, z) ) return __LINE__;
    touch(inv);

#if defined(addsub) && defined(fmaddsub)
    x = addsub(src * inv, one);
    y = addsub(src * inv, -one);
    touch(one);
    z = fmaddsub(src, inv, one);
    if ( !eq(x, z) ) return __LINE__;

    touch(one);
    z = fmaddsub(src, inv, -one);
    if ( !eq(y, z) ) return __LINE__;
    touch(one);

    x = addsub(src * inv, one);
    touch(inv);
    z = fmaddsub(src, inv, one);
    if ( !eq(x, z) ) return __LINE__;

    touch(inv);
    z = fmaddsub(src, inv, -one);
    if ( !eq(y, z) ) return __LINE__;
    touch(inv);
#endif

    return 0;
}
