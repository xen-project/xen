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
# elif FLOAT_SIZE == 2
#  define fmaddsub(x, y, z) BR(vfmaddsubph, _mask, x, y, z, ~0)
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
# ifdef __AVX512F__
#  define addsub(x, y) ({ \
    vec_t t_; \
    typeof(t_[0]) one_ = 1; \
    asm ( "vfmaddsub231p" ELEM_SFX " %2%{1to%c4%}, %1, %0" \
          : "=v" (t_) \
          : "v" (x), "m" (one_), "0" (y), "i" (ELEM_COUNT) ); \
    t_; \
})
# else
#  define addsub(x, y) fmaddsub(x, broadcast(1), y)
# endif
#endif

#ifdef __AVX512FP16__
# define I (1.if16)
# if VEC_SIZE > FLOAT_SIZE
#  define CELEM_COUNT (ELEM_COUNT / 2)
static const unsigned int conj_mask = 0x80000000;
#  define conj(z) ({ \
    vec_t r_; \
    asm ( "vpxord %2%{1to%c3%}, %1, %0" \
          : "=v" (r_) \
          : "v" (z), "m" (conj_mask), "i" (CELEM_COUNT) ); \
    r_; \
})
#  define _cmul_vv(a, b, c)  BR2(vf##c##mulcph, , a, b)
#  define _cmul_vs(a, b, c) ({ \
    vec_t r_; \
    _Complex _Float16 b_ = (b); \
    asm ( "vf"#c"mulcph %2%{1to%c3%}, %1, %0" \
          : "=v" (r_) \
          : "v" (a), "m" (b_), "i" (CELEM_COUNT) ); \
    r_; \
})
#  define cmadd_vv(a, b, c) BR2(vfmaddcph, , a, b, c)
#  define cmadd_vs(a, b, c) ({ \
    _Complex _Float16 b_ = (b); \
    vec_t r_; \
    asm ( "vfmaddcph %2%{1to%c3%}, %1, %0" \
          : "=v" (r_) \
          : "v" (a), "m" (b_), "i" (CELEM_COUNT), "0" (c) ); \
    r_; \
})
# else
#  define CELEM_COUNT 1
typedef _Float16 __attribute__((vector_size(4))) cvec_t;
#  define conj(z) ({ \
    cvec_t r_; \
    asm ( "xor $0x80000000, %0" : "=rm" (r_) : "0" (z) ); \
    r_; \
})
#  define _cmul_vv(a, b, c) ({ \
    cvec_t r_; \
    /* "=&x" to force destination to be different from both sources */ \
    asm ( "vf"#c"mulcsh %2, %1, %0" : "=&x" (r_) : "x" (a), "m" (b) ); \
    r_; \
})
#  define _cmul_vs(a, b, c) ({ \
    _Complex _Float16 b_ = (b); \
    cvec_t r_; \
    /* "=&x" to force destination to be different from both sources */ \
    asm ( "vf"#c"mulcsh %2, %1, %0" : "=&x" (r_) : "x" (a), "m" (b_) ); \
    r_; \
})
#  define cmadd_vv(a, b, c) ({ \
    cvec_t r_ = (c); \
    asm ( "vfmaddcsh %2, %1, %0" : "+x" (r_) : "x" (a), "m" (b) ); \
    r_; \
})
#  define cmadd_vs(a, b, c) ({ \
    _Complex _Float16 b_ = (b); \
    cvec_t r_ = (c); \
    asm ( "vfmaddcsh %2, %1, %0" : "+x" (r_) : "x" (a), "m" (b_) ); \
    r_; \
})
# endif
# define cmul_vv(a, b) _cmul_vv(a, b, )
# define cmulc_vv(a, b) _cmul_vv(a, b, c)
# define cmul_vs(a, b) _cmul_vs(a, b, )
# define cmulc_vs(a, b) _cmul_vs(a, b, c)
#endif

int fma_test(void)
{
    unsigned int i;
    vec_t x, y, z, src, inv, one;
#ifdef __AVX512F__
    typeof(one[0]) one_ = 1;
#endif

    for ( i = 0; i < ELEM_COUNT; ++i )
    {
        src[i] = i + 1;
        inv[i] = ELEM_COUNT - i;
        one[i] = 1;
    }

#ifdef __AVX512F__
# define one one_
#endif

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
    touch(one);
    z = src * one + inv;
    if ( !eq(x, z) ) return __LINE__;

    touch(inv);
    touch(one);
    z = -src * one - inv;
    if ( !eq(-x, z) ) return __LINE__;

    touch(inv);
    touch(one);
    z = src * one - inv;
    if ( !eq(y, z) ) return __LINE__;

    touch(inv);
    touch(one);
    z = -src * one + inv;
    if ( !eq(-y, z) ) return __LINE__;
    touch(inv);

#undef one

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

#ifdef CELEM_COUNT

# if VEC_SIZE > FLOAT_SIZE
#  define cvec_t vec_t
#  define ceq eq
# else
  {
    /* Cannot re-use the function-scope variables (for being too small). */
    cvec_t x, y, z, src = { 1, 2 }, inv = { 2, 1 }, one = { 1, 1 };
#  define ceq(x, y) ({ \
    unsigned int r_; \
    asm ( "vcmpph $0, %1, %2, %0"  : "=k" (r_) : "x" (x), "x" (y) ); \
    (r_ & 3) == 3; \
})
# endif

    /* (a * i)² == -a² */
    x = cmul_vs(src, I);
    y = cmul_vv(x, x);
    x = -src;
    touch(src);
    z = cmul_vv(x, src);
    if ( !ceq(y, z) ) return __LINE__;

    /* conj(a * b) == conj(a) * conj(b) */
    touch(src);
    x = conj(src);
    touch(inv);
    y = cmulc_vv(x, inv);
    touch(src);
    touch(inv);
    z = conj(cmul_vv(src, inv));
    if ( !ceq(y, z) ) return __LINE__;

    /* a * conj(a) == |a|² */
    touch(src);
    y = src;
    touch(src);
    x = cmulc_vv(y, src);
    y *= y;
    for ( i = 0; i < ELEM_COUNT; i += 2 )
    {
        if ( x[i] != y[i] + y[i + 1] ) return __LINE__;
        if ( x[i + 1] ) return __LINE__;
    }

    /* a * b == b * a + 0 */
    touch(src);
    touch(inv);
    x = cmul_vv(src, inv);
    touch(src);
    touch(inv);
    y = cmadd_vv(inv, src, (cvec_t){});
    if ( !ceq(x, y) ) return __LINE__;

    /* a * 1 + b == b * 1 + a */
    touch(src);
    touch(inv);
    x = cmadd_vs(src, 1, inv);
    for ( i = 0; i < ELEM_COUNT; i += 2 )
    {
        z[i] = 1;
        z[i + 1] = 0;
    }
    touch(z);
    y = cmadd_vv(inv, z, src);
    if ( !ceq(x, y) ) return __LINE__;

    /* (a + b) * c == a * c + b * c */
    touch(one);
    touch(inv);
    x = cmul_vv(src + one, inv);
    touch(inv);
    y = cmul_vv(one, inv);
    touch(inv);
    z = cmadd_vv(src, inv, y);
    if ( !ceq(x, z) ) return __LINE__;

    /* a * i + conj(a) == (Re(a) - Im(a)) * (1 + i) */
    x = cmadd_vs(src, I, conj(src));
    for ( i = 0; i < ELEM_COUNT; i += 2 )
    {
        typeof(x[0]) val = src[i] - src[i + 1];

        if ( x[i] != val ) return __LINE__;
        if ( x[i + 1] != val ) return __LINE__;
    }

# if VEC_SIZE == FLOAT_SIZE
  }
# endif

#endif /* CELEM_COUNT */

    return 0;
}
