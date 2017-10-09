#include <stdbool.h>

asm (
    "\t.text\n"
    "\t.globl _start\n"
    "_start:\n"
#if defined(__i386__) && VEC_SIZE == 16
    "\tpush %ebp\n"
    "\tmov %esp,%ebp\n"
    "\tand $~0xf,%esp\n"
    "\tcall simd_test\n"
    "\tleave\n"
    "\tret"
#else
    "\tjmp simd_test"
#endif
    );

typedef
#if defined(INT_SIZE)
# define ELEM_SIZE INT_SIZE
signed int
# if INT_SIZE == 1
#  define MODE QI
# elif INT_SIZE == 2
#  define MODE HI
# elif INT_SIZE == 4
#  define MODE SI
# elif INT_SIZE == 8
#  define MODE DI
# endif
#elif defined(UINT_SIZE)
# define ELEM_SIZE UINT_SIZE
unsigned int
# if UINT_SIZE == 1
#  define MODE QI
# elif UINT_SIZE == 2
#  define MODE HI
# elif UINT_SIZE == 4
#  define MODE SI
# elif UINT_SIZE == 8
#  define MODE DI
# endif
#elif defined(FLOAT_SIZE)
float
# define ELEM_SIZE FLOAT_SIZE
# if FLOAT_SIZE == 4
#  define MODE SF
# elif FLOAT_SIZE == 8
#  define MODE DF
# endif
#endif
#ifndef VEC_SIZE
# define VEC_SIZE ELEM_SIZE
#endif
__attribute__((mode(MODE), vector_size(VEC_SIZE))) vec_t;

#define ELEM_COUNT (VEC_SIZE / ELEM_SIZE)

typedef unsigned int __attribute__((mode(QI), vector_size(VEC_SIZE))) byte_vec_t;

/* Various builtins want plain char / int / long long vector types ... */
typedef char __attribute__((vector_size(VEC_SIZE))) vqi_t;
typedef short __attribute__((vector_size(VEC_SIZE))) vhi_t;
typedef int __attribute__((vector_size(VEC_SIZE))) vsi_t;
#if VEC_SIZE >= 8
typedef long long __attribute__((vector_size(VEC_SIZE))) vdi_t;
#endif

#if VEC_SIZE == 8 && defined(__SSE__)
# define to_bool(cmp) (__builtin_ia32_pmovmskb(cmp) == 0xff)
#elif VEC_SIZE == 16
# if defined(__AVX__) && defined(FLOAT_SIZE)
#  if ELEM_SIZE == 4
#   define to_bool(cmp) __builtin_ia32_vtestcps(cmp, (vec_t){} == 0)
#  elif ELEM_SIZE == 8
#   define to_bool(cmp) __builtin_ia32_vtestcpd(cmp, (vec_t){} == 0)
#  endif
# elif defined(__SSE4_1__)
#  define to_bool(cmp) __builtin_ia32_ptestc128(cmp, (vdi_t){} == 0)
# elif defined(__SSE__) && ELEM_SIZE == 4
#  define to_bool(cmp) (__builtin_ia32_movmskps(cmp) == 0xf)
# elif defined(__SSE2__)
#  if ELEM_SIZE == 8
#   define to_bool(cmp) (__builtin_ia32_movmskpd(cmp) == 3)
#  else
#   define to_bool(cmp) (__builtin_ia32_pmovmskb128(cmp) == 0xffff)
#  endif
# endif
#elif VEC_SIZE == 32
# if defined(__AVX__) && ELEM_SIZE == 4
#  define to_bool(cmp) (__builtin_ia32_movmskps256(cmp) == 0xff)
# elif defined(__AVX__) && ELEM_SIZE == 8
#  define to_bool(cmp) (__builtin_ia32_movmskpd256(cmp) == 0xf)
# endif
#endif

#ifndef to_bool
static inline bool _to_bool(byte_vec_t bv)
{
    unsigned int i;

    for ( i = 0; i < VEC_SIZE; ++i )
        if ( bv[i] != 0xff )
            return false;

    return true;
}
# define to_bool(cmp) _to_bool((byte_vec_t)(cmp))
#endif

#if VEC_SIZE == FLOAT_SIZE
# define to_int(x) ((vec_t){ (int)(x)[0] })
#elif VEC_SIZE == 16 && defined(__SSE2__)
# if FLOAT_SIZE == 4
#  define to_int(x) __builtin_ia32_cvtdq2ps(__builtin_ia32_cvtps2dq(x))
# elif FLOAT_SIZE == 8
#  define to_int(x) __builtin_ia32_cvtdq2pd(__builtin_ia32_cvtpd2dq(x))
# endif
#elif VEC_SIZE == 32 && defined(__AVX__)
# if FLOAT_SIZE == 4
#  define to_int(x) __builtin_ia32_cvtdq2ps256(__builtin_ia32_cvtps2dq256(x))
# elif FLOAT_SIZE == 8
#  define to_int(x) __builtin_ia32_cvtdq2pd256(__builtin_ia32_cvtpd2dq256(x))
# endif
#endif

#if VEC_SIZE == FLOAT_SIZE
# define scalar_1op(x, op) ({ \
    typeof((x)[0]) __attribute__((vector_size(16))) r_; \
    asm ( op : [out] "=&x" (r_) : [in] "m" (x) ); \
    (vec_t){ r_[0] }; \
})
#endif

#if FLOAT_SIZE == 4 && defined(__SSE__)
# if VEC_SIZE == 32 && defined(__AVX__)
#  define broadcast(x) ({ float t_ = (x); __builtin_ia32_vbroadcastss256(&t_); })
#  define max(x, y) __builtin_ia32_maxps256(x, y)
#  define min(x, y) __builtin_ia32_minps256(x, y)
#  define recip(x) __builtin_ia32_rcpps256(x)
#  define rsqrt(x) __builtin_ia32_rsqrtps256(x)
#  define sqrt(x) __builtin_ia32_sqrtps256(x)
#  define swap(x) ({ \
    vec_t t_ = __builtin_ia32_vpermilps256(x, 0b00011011); \
    __builtin_ia32_vperm2f128_ps256(t_, t_, 0b00000001); \
})
#  define swap2(x) ({ \
    vec_t t_ = __builtin_ia32_vpermilvarps256(x, __builtin_ia32_cvtps2dq256(inv) - 1); \
    __builtin_ia32_vperm2f128_ps256(t_, t_, 0b00000001); \
})
# elif VEC_SIZE == 16
#  ifdef __AVX__
#   define broadcast(x) ({ float t_ = (x); __builtin_ia32_vbroadcastss(&t_); })
#  endif
#  define interleave_hi(x, y) __builtin_ia32_unpckhps(x, y)
#  define interleave_lo(x, y) __builtin_ia32_unpcklps(x, y)
#  define max(x, y) __builtin_ia32_maxps(x, y)
#  define min(x, y) __builtin_ia32_minps(x, y)
#  define recip(x) __builtin_ia32_rcpps(x)
#  define rsqrt(x) __builtin_ia32_rsqrtps(x)
#  define sqrt(x) __builtin_ia32_sqrtps(x)
#  define swap(x) __builtin_ia32_shufps(x, x, 0b00011011)
#  ifdef __AVX__
#   define swap2(x) __builtin_ia32_vpermilvarps(x, __builtin_ia32_cvtps2dq(inv) - 1)
#  endif
# elif VEC_SIZE == 4
#  define recip(x) scalar_1op(x, "rcpss %[in], %[out]")
#  define rsqrt(x) scalar_1op(x, "rsqrtss %[in], %[out]")
#  define sqrt(x) scalar_1op(x, "sqrtss %[in], %[out]")
# endif
#elif FLOAT_SIZE == 8 && defined(__SSE2__)
# if VEC_SIZE == 32 && defined(__AVX__)
#  define broadcast(x) ({ double t_ = (x); __builtin_ia32_vbroadcastsd256(&t_); })
#  define max(x, y) __builtin_ia32_maxpd256(x, y)
#  define min(x, y) __builtin_ia32_minpd256(x, y)
#  define recip(x) ({ \
    float __attribute__((vector_size(16))) t_ = __builtin_ia32_cvtpd2ps256(x); \
    t_ = __builtin_ia32_vextractf128_ps256( \
             __builtin_ia32_rcpps256( \
                 __builtin_ia32_vbroadcastf128_ps256(&t_)), 0); \
    __builtin_ia32_cvtps2pd256(t_); \
})
#  define rsqrt(x) ({ \
    float __attribute__((vector_size(16))) t1_ = __builtin_ia32_cvtpd2ps256(x); \
    float __attribute__((vector_size(32))) t2_ = __builtin_ia32_vinsertf128_ps256((typeof(t2_)){}, t1_, 0); \
    t2_ = __builtin_ia32_vinsertf128_ps256(t2_, t1_, 1); \
    t1_ = __builtin_ia32_vextractf128_ps256(__builtin_ia32_rsqrtps256(t2_), 0); \
    __builtin_ia32_cvtps2pd256(t1_); \
})
#  define sqrt(x) __builtin_ia32_sqrtpd256(x)
#  define swap(x) ({ \
    vec_t t_ = __builtin_ia32_vpermilpd256(x, 0b00000101); \
    __builtin_ia32_vperm2f128_pd256(t_, t_, 0b00000001); \
})
# elif VEC_SIZE == 16
#  define interleave_hi(x, y) __builtin_ia32_unpckhpd(x, y)
#  define interleave_lo(x, y) __builtin_ia32_unpcklpd(x, y)
#  define max(x, y) __builtin_ia32_maxpd(x, y)
#  define min(x, y) __builtin_ia32_minpd(x, y)
#  define recip(x) __builtin_ia32_cvtps2pd(__builtin_ia32_rcpps(__builtin_ia32_cvtpd2ps(x)))
#  define rsqrt(x) __builtin_ia32_cvtps2pd(__builtin_ia32_rsqrtps(__builtin_ia32_cvtpd2ps(x)))
#  define sqrt(x) __builtin_ia32_sqrtpd(x)
#  define swap(x) __builtin_ia32_shufpd(x, x, 0b01)
#  ifdef __AVX__
#   define swap2(x) __builtin_ia32_vpermilvarpd(x, __builtin_ia32_pmovsxdq128( \
                                                       __builtin_ia32_cvtpd2dq(inv) - 1) << 1)
#  endif
# elif VEC_SIZE == 8
#  define recip(x) scalar_1op(x, "cvtsd2ss %[in], %[out]; rcpss %[out], %[out]; cvtss2sd %[out], %[out]")
#  define rsqrt(x) scalar_1op(x, "cvtsd2ss %[in], %[out]; rsqrtss %[out], %[out]; cvtss2sd %[out], %[out]")
#  define sqrt(x) scalar_1op(x, "sqrtsd %[in], %[out]")
# endif
#endif
#if VEC_SIZE == 16 && defined(__SSE2__)
# if INT_SIZE == 1 || UINT_SIZE == 1
#  define interleave_hi(x, y) ((vec_t)__builtin_ia32_punpckhbw128((vqi_t)(x), (vqi_t)(y)))
#  define interleave_lo(x, y) ((vec_t)__builtin_ia32_punpcklbw128((vqi_t)(x), (vqi_t)(y)))
# elif INT_SIZE == 2 || UINT_SIZE == 2
#  define interleave_hi(x, y) ((vec_t)__builtin_ia32_punpckhwd128((vhi_t)(x), (vhi_t)(y)))
#  define interleave_lo(x, y) ((vec_t)__builtin_ia32_punpcklwd128((vhi_t)(x), (vhi_t)(y)))
#  define swap(x) ((vec_t)__builtin_ia32_pshufd( \
                   (vsi_t)__builtin_ia32_pshufhw( \
                          __builtin_ia32_pshuflw((vhi_t)(x), 0b00011011), 0b00011011), 0b01001110))
# elif INT_SIZE == 4 || UINT_SIZE == 4
#  define interleave_hi(x, y) ((vec_t)__builtin_ia32_punpckhdq128((vsi_t)(x), (vsi_t)(y)))
#  define interleave_lo(x, y) ((vec_t)__builtin_ia32_punpckldq128((vsi_t)(x), (vsi_t)(y)))
#  define swap(x) ((vec_t)__builtin_ia32_pshufd((vsi_t)(x), 0b00011011))
# elif INT_SIZE == 8 || UINT_SIZE == 8
#  define interleave_hi(x, y) ((vec_t)__builtin_ia32_punpckhqdq128((vdi_t)(x), (vdi_t)(y)))
#  define interleave_lo(x, y) ((vec_t)__builtin_ia32_punpcklqdq128((vdi_t)(x), (vdi_t)(y)))
#  define swap(x) ((vec_t)__builtin_ia32_pshufd((vsi_t)(x), 0b01001110))
# endif
# if UINT_SIZE == 1
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxub128((vqi_t)(x), (vqi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminub128((vqi_t)(x), (vqi_t)(y)))
# elif INT_SIZE == 2
#  define max(x, y) __builtin_ia32_pmaxsw128(x, y)
#  define min(x, y) __builtin_ia32_pminsw128(x, y)
#  define mul_hi(x, y) __builtin_ia32_pmulhw128(x, y)
# elif UINT_SIZE == 2
#  define mul_hi(x, y) ((vec_t)__builtin_ia32_pmulhuw128((vhi_t)(x), (vhi_t)(y)))
# elif UINT_SIZE == 4
#  define mul_full(x, y) ((vec_t)__builtin_ia32_pmuludq128((vsi_t)(x), (vsi_t)(y)))
# endif
# define select(d, x, y, m) ({ \
    void *d_ = (d); \
    vqi_t m_ = (vqi_t)(m); \
    __builtin_ia32_maskmovdqu((vqi_t)(x),  m_, d_); \
    __builtin_ia32_maskmovdqu((vqi_t)(y), ~m_, d_); \
})
#endif
#if VEC_SIZE == 16 && defined(__SSE3__)
# if FLOAT_SIZE == 4
#  define addsub(x, y) __builtin_ia32_addsubps(x, y)
#  define dup_hi(x) __builtin_ia32_movshdup(x)
#  define dup_lo(x) __builtin_ia32_movsldup(x)
#  define hadd(x, y) __builtin_ia32_haddps(x, y)
#  define hsub(x, y) __builtin_ia32_hsubps(x, y)
# elif FLOAT_SIZE == 8
#  define addsub(x, y) __builtin_ia32_addsubpd(x, y)
#  define dup_lo(x) ({ \
    double __attribute__((vector_size(16))) r_; \
    asm ( "movddup %1,%0" : "=x" (r_) : "m" ((x)[0]) ); \
    r_; \
})
#  define hadd(x, y) __builtin_ia32_haddpd(x, y)
#  define hsub(x, y) __builtin_ia32_hsubpd(x, y)
# endif
#elif VEC_SIZE == 32 && defined(__AVX__)
# if FLOAT_SIZE == 4
#  define addsub(x, y) __builtin_ia32_addsubps256(x, y)
#  define dup_hi(x) __builtin_ia32_movshdup256(x)
#  define dup_lo(x) __builtin_ia32_movsldup256(x)
#  define hadd(x, y) ({ \
        vec_t t_ = __builtin_ia32_haddps256(x, y); \
        (vec_t){t_[0], t_[1], t_[4], t_[5], t_[2], t_[3], t_[6], t_[7]}; \
})
#  define hsub(x, y) ({ \
        vec_t t_ = __builtin_ia32_hsubps256(x, y); \
        (vec_t){t_[0], t_[1], t_[4], t_[5], t_[2], t_[3], t_[6], t_[7]}; \
})
# elif FLOAT_SIZE == 8
#  define addsub(x, y) __builtin_ia32_addsubpd256(x, y)
#  define dup_lo(x) __builtin_ia32_movddup256(x)
#  define hadd(x, y) ({ \
        vec_t t_ = __builtin_ia32_haddpd256(x, y); \
        (vec_t){t_[0], t_[2], t_[1], t_[3]}; \
})
#  define hsub(x, y) ({ \
        vec_t t_ = __builtin_ia32_hsubpd256(x, y); \
        (vec_t){t_[0], t_[2], t_[1], t_[3]}; \
})
# endif
#endif
#if VEC_SIZE == 16 && defined(__SSSE3__)
# if INT_SIZE == 1
#  define abs(x) ((vec_t)__builtin_ia32_pabsb128((vqi_t)(x)))
# elif INT_SIZE == 2
#  define abs(x) __builtin_ia32_pabsw128(x)
# elif INT_SIZE == 4
#  define abs(x) __builtin_ia32_pabsd128(x)
# endif
# if INT_SIZE == 1 || UINT_SIZE == 1
#  define copysignz(x, y) ((vec_t)__builtin_ia32_psignb128((vqi_t)(x), (vqi_t)(y)))
#  define swap(x) ((vec_t)__builtin_ia32_pshufb128((vqi_t)(x), (vqi_t)(inv - 1)))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr128((vdi_t)(x), (vdi_t)(x), (n) * 8))
# elif INT_SIZE == 2 || UINT_SIZE == 2
#  define copysignz(x, y) ((vec_t)__builtin_ia32_psignw128((vhi_t)(x), (vhi_t)(y)))
#  define hadd(x, y) ((vec_t)__builtin_ia32_phaddw128((vhi_t)(x), (vhi_t)(y)))
#  define hsub(x, y) ((vec_t)__builtin_ia32_phsubw128((vhi_t)(x), (vhi_t)(y)))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr128((vdi_t)(x), (vdi_t)(x), (n) * 16))
# elif INT_SIZE == 4 || UINT_SIZE == 4
#  define copysignz(x, y) ((vec_t)__builtin_ia32_psignd128((vsi_t)(x), (vsi_t)(y)))
#  define hadd(x, y) ((vec_t)__builtin_ia32_phaddd128((vsi_t)(x), (vsi_t)(y)))
#  define hsub(x, y) ((vec_t)__builtin_ia32_phsubd128((vsi_t)(x), (vsi_t)(y)))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr128((vdi_t)(x), (vdi_t)(x), (n) * 32))
# elif INT_SIZE == 8 || UINT_SIZE == 8
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr128((vdi_t)(x), (vdi_t)(x), (n) * 64))
# endif
#endif
#if VEC_SIZE == 16 && defined(__SSE4_1__)
# if INT_SIZE == 1
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxsb128((vqi_t)(x), (vqi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminsb128((vqi_t)(x), (vqi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovsxbw128((vqi_t)(x)))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovsxbd128((vqi_t)(x)))
#  define widen3(x) ((vec_t)__builtin_ia32_pmovsxbq128((vqi_t)(x)))
# elif INT_SIZE == 2
#  define widen1(x) ((vec_t)__builtin_ia32_pmovsxwd128(x))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovsxwq128(x))
# elif INT_SIZE == 4
#  define max(x, y) __builtin_ia32_pmaxsd128(x, y)
#  define min(x, y) __builtin_ia32_pminsd128(x, y)
#  define mul_full(x, y) ((vec_t)__builtin_ia32_pmuldq128(x, y))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovsxdq128(x))
# elif UINT_SIZE == 1
#  define widen1(x) ((vec_t)__builtin_ia32_pmovzxbw128((vqi_t)(x)))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovzxbd128((vqi_t)(x)))
#  define widen3(x) ((vec_t)__builtin_ia32_pmovzxbq128((vqi_t)(x)))
# elif UINT_SIZE == 2
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxuw128((vhi_t)(x), (vhi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminuw128((vhi_t)(x), (vhi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovzxwd128((vhi_t)(x)))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovzxwq128((vhi_t)(x)))
# elif UINT_SIZE == 4
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxud128((vsi_t)(x), (vsi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminud128((vsi_t)(x), (vsi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovzxdq128((vsi_t)(x)))
# endif
# undef select
# if defined(INT_SIZE) || defined(UINT_SIZE)
#  define select(d, x, y, m) \
    (*(d) = (vec_t)__builtin_ia32_pblendvb128((vqi_t)(y), (vqi_t)(x), (vqi_t)(m)))
# elif FLOAT_SIZE == 4
#  define dot_product(x, y) __builtin_ia32_dpps(x, y, 0b11110001)
#  define select(d, x, y, m) (*(d) = __builtin_ia32_blendvps(y, x, m))
#  define trunc(x) __builtin_ia32_roundps(x, 0b1011)
# elif FLOAT_SIZE == 8
#  define dot_product(x, y) __builtin_ia32_dppd(x, y, 0b00110001)
#  define select(d, x, y, m) (*(d) = __builtin_ia32_blendvpd(y, x, m))
#  define trunc(x) __builtin_ia32_roundpd(x, 0b1011)
# endif
# if INT_SIZE == 2 || UINT_SIZE == 2
#  define mix(x, y) ((vec_t)__builtin_ia32_pblendw128((vhi_t)(x), (vhi_t)(y), 0b10101010))
# elif INT_SIZE == 4 || UINT_SIZE == 4
#  define mix(x, y) ((vec_t)__builtin_ia32_pblendw128((vhi_t)(x), (vhi_t)(y), 0b11001100))
# elif INT_SIZE == 8 || UINT_SIZE == 8
#  define mix(x, y) ((vec_t)__builtin_ia32_pblendw128((vhi_t)(x), (vhi_t)(y), 0b11110000))
# elif FLOAT_SIZE == 4
#  define mix(x, y) __builtin_ia32_blendps(x, y, 0b1010)
# elif FLOAT_SIZE == 8
#  define mix(x, y) __builtin_ia32_blendpd(x, y, 0b10)
# endif
#endif
#if VEC_SIZE == 32 && defined(__AVX__)
# if FLOAT_SIZE == 4
#  define dot_product(x, y) ({ \
    vec_t t_ = __builtin_ia32_dpps256(x, y, 0b11110001); \
    (vec_t){t_[0] + t_[4]}; \
})
#  define mix(x, y) __builtin_ia32_blendps256(x, y, 0b10101010)
#  define select(d, x, y, m) (*(d) = __builtin_ia32_blendvps256(y, x, m))
#  define select2(d, x, y, m) ({ \
    vsi_t m_ = (vsi_t)(m); \
    *(d) = __builtin_ia32_maskloadps256(&(x),  m_); \
    __builtin_ia32_maskstoreps256(d, ~m_, y); \
})
#  define trunc(x) __builtin_ia32_roundps256(x, 0b1011)
# elif FLOAT_SIZE == 8
#  define mix(x, y) __builtin_ia32_blendpd256(x, y, 0b1010)
#  define select(d, x, y, m) (*(d) = __builtin_ia32_blendvpd256(y, x, m))
#  define select2(d, x, y, m) ({ \
    vdi_t m_ = (vdi_t)(m); \
    *(d) = __builtin_ia32_maskloadpd256(&(x),  m_); \
    __builtin_ia32_maskstorepd256(d, ~m_, y); \
})
#  define trunc(x) __builtin_ia32_roundpd256(x, 0b1011)
# endif
#endif
#if VEC_SIZE == FLOAT_SIZE
# define max(x, y) ((vec_t){({ typeof(x[0]) x_ = (x)[0], y_ = (y)[0]; x_ > y_ ? x_ : y_; })})
# define min(x, y) ((vec_t){({ typeof(x[0]) x_ = (x)[0], y_ = (y)[0]; x_ < y_ ? x_ : y_; })})
# ifdef __SSE4_1__
#  if FLOAT_SIZE == 4
#   define trunc(x) ({ \
    float __attribute__((vector_size(16))) r_; \
    asm ( "roundss $0b1011,%1,%0" : "=x" (r_) : "m" (x) ); \
    (vec_t){ r_[0] }; \
})
#  elif FLOAT_SIZE == 8
#   define trunc(x) ({ \
    double __attribute__((vector_size(16))) r_; \
    asm ( "roundsd $0b1011,%1,%0" : "=x" (r_) : "m" (x) ); \
    (vec_t){ r_[0] }; \
})
#  endif
# endif
#endif

/*
 * Suppress value propagation by the compiler, preventing unwanted
 * optimization. This at once makes the compiler use memory operands
 * more often, which for our purposes is the more interesting case.
 */
#define touch(var) asm volatile ( "" : "+m" (var) )

int simd_test(void)
{
    unsigned int i, j;
    vec_t x, y, z, src, inv, alt, sh;

    for ( i = 0, j = ELEM_SIZE << 3; i < ELEM_COUNT; ++i )
    {
        src[i] = i + 1;
        inv[i] = ELEM_COUNT - i;
#ifdef UINT_SIZE
        alt[i] = -!(i & 1);
#else
        alt[i] = i & 1 ? -1 : 1;
#endif
        if ( !(i & (i + 1)) )
            --j;
        sh[i] = j;
    }

    touch(src);
    x = src;
    touch(x);
    if ( !to_bool(x == src) ) return __LINE__;

    touch(src);
    y = x + src;
    touch(src);
    touch(y);
    if ( !to_bool(y == 2 * src) ) return __LINE__;

    touch(src);
    z = y -= src;
    touch(z);
    if ( !to_bool(x == z) ) return __LINE__;

#if defined(UINT_SIZE)

    touch(inv);
    x |= inv;
    touch(inv);
    y &= inv;
    touch(inv);
    z ^= inv;
    touch(inv);
    touch(x);
    if ( !to_bool((x & ~y) == z) ) return __LINE__;

#elif ELEM_SIZE > 1 || VEC_SIZE <= 8

    touch(src);
    x *= src;
    y = inv * inv;
    touch(src);
    z = src + inv;
    touch(inv);
    z *= (src - inv);
    if ( !to_bool(x - y == z) ) return __LINE__;

#endif

#if defined(FLOAT_SIZE)

    x = src * alt;
    touch(alt);
    y = src / alt;
    if ( !to_bool(x == y) ) return __LINE__;
    touch(alt);
    touch(src);
    if ( !to_bool(x * -alt == -src) ) return __LINE__;

# if defined(recip) && defined(to_int)

    touch(src);
    x = recip(src);
    touch(src);
    touch(x);
    if ( !to_bool(to_int(recip(x)) == src) ) return __LINE__;

#  ifdef rsqrt
    x = src * src;
    touch(x);
    y = rsqrt(x);
    touch(y);
    if ( !to_bool(to_int(recip(y)) == src) ) return __LINE__;
    touch(src);
    if ( !to_bool(to_int(y) == to_int(recip(src))) ) return __LINE__;
#  endif

# endif

# ifdef sqrt
    x = src * src;
    touch(x);
    if ( !to_bool(sqrt(x) == src) ) return __LINE__;
# endif

# ifdef trunc
    x = 1 / src;
    y = (vec_t){ 1 };
    touch(x);
    z = trunc(x);
    if ( !to_bool(y == z) ) return __LINE__;
# endif

#else

# if ELEM_SIZE > 1

    touch(inv);
    x = src * inv;
    touch(inv);
    y[ELEM_COUNT - 1] = y[0] = j = ELEM_COUNT;
    for ( i = 1; i < ELEM_COUNT / 2; ++i )
        y[ELEM_COUNT - i - 1] = y[i] = y[i - 1] + (j -= 2);
    if ( !to_bool(x == y) ) return __LINE__;

#  ifdef mul_hi
    touch(alt);
    x = mul_hi(src, alt);
    touch(alt);
#   ifdef INT_SIZE
    if ( !to_bool(x == (alt < 0)) ) return __LINE__;
#   else
    if ( !to_bool(x == (src & alt) + alt) ) return __LINE__;
#   endif
#  endif

#  ifdef mul_full
    x = src ^ alt;
    touch(inv);
    y = mul_full(x, inv);
    touch(inv);
    for ( i = 0; i < ELEM_COUNT; i += 2 )
    {
        unsigned long long res = x[i] * 1ULL * inv[i];

        z[i] = res;
        z[i + 1] = res >> (ELEM_SIZE << 3);
    }
    if ( !to_bool(y == z) ) return __LINE__;
#  endif

    z = src;
#  ifdef INT_SIZE
    z *= alt;
#  endif
    touch(z);
    x = z << 3;
    touch(z);
    y = z << 2;
    touch(z);
    if ( !to_bool(x == y + y) ) return __LINE__;

    touch(x);
    z = x >> 2;
    touch(x);
    if ( !to_bool(y == z + z) ) return __LINE__;

    z = src;
#  ifdef INT_SIZE
    z *= alt;
#  endif
    /*
     * Note that despite the touch()-es here there doesn't appear to be a way
     * to make the compiler use a memory operand for the shift instruction (at
     * least without resorting to built-ins).
     */
    j = 3;
    touch(j);
    x = z << j;
    touch(j);
    j = 2;
    touch(j);
    y = z << j;
    touch(j);
    if ( !to_bool(x == y + y) ) return __LINE__;

    z = x >> j;
    touch(j);
    if ( !to_bool(y == z + z) ) return __LINE__;

# endif

# if ELEM_SIZE == 2 || defined(__SSE4_1__)
    /*
     * Even when there are no instructions with varying shift counts per
     * field, the code turns out to be a nice exercise for pextr/pinsr.
     */
    z = src;
#  ifdef INT_SIZE
    z *= alt;
#  endif
    /*
     * Zap elements for which the shift count is negative (and the hence the
     * decrement below would yield a negative count.
     */
    z &= (sh > 0);
    touch(sh);
    x = z << sh;
    touch(sh);
    --sh;
    touch(sh);
    y = z << sh;
    touch(sh);
    if ( !to_bool(x == y + y) ) return __LINE__;

# endif

#endif

#if defined(max) && defined(min)
# ifdef UINT_SIZE
    touch(inv);
    x = min(src, inv);
    touch(inv);
    y = max(src, inv);
    touch(inv);
    if ( !to_bool(x + y == src + inv) ) return __LINE__;
# else
    x = src * alt;
    y = inv * alt;
    touch(y);
    z = max(x, y);
    touch(y);
    y = min(x, y);
    touch(y);
    if ( !to_bool((y + z) * alt == src + inv) ) return __LINE__;
# endif
#endif

#ifdef abs
    x = src * alt;
    touch(x);
    if ( !to_bool(abs(x) == src) ) return __LINE__;
#endif

#ifdef copysignz
    touch(alt);
    if ( !to_bool(copysignz((vec_t){} + 1, alt) == alt) ) return __LINE__;
#endif

#ifdef swap
    touch(src);
    if ( !to_bool(swap(src) == inv) ) return __LINE__;
#endif

#ifdef swap2
    touch(src);
    if ( !to_bool(swap2(src) == inv) ) return __LINE__;
#endif

#if defined(broadcast)
    if ( !to_bool(broadcast(ELEM_COUNT + 1) == src + inv) ) return __LINE__;
#endif

#if defined(interleave_lo) && defined(interleave_hi)
    touch(src);
    x = interleave_lo(inv, src);
    touch(src);
    y = interleave_hi(inv, src);
    touch(src);
# ifdef UINT_SIZE
    z = ((x - y) ^ ~alt) - ~alt;
# else
    z = (x - y) * alt;
# endif
    if ( !to_bool(z == ELEM_COUNT / 2) ) return __LINE__;
#endif

#if defined(INT_SIZE) && defined(widen1) && defined(interleave_lo)

    x = src * alt;
    y = interleave_lo(x, alt < 0);
    touch(x);
    z = widen1(x);
    touch(x);
    if ( !to_bool(z == y) ) return __LINE__;

# ifdef widen2
    y = interleave_lo(alt < 0, alt < 0);
    y = interleave_lo(z, y);
    touch(x);
    z = widen2(x);
    touch(x);
    if ( !to_bool(z == y) ) return __LINE__;

#  ifdef widen3
    y = interleave_lo(alt < 0, alt < 0);
    y = interleave_lo(y, y);
    y = interleave_lo(z, y);
    touch(x);
    z = widen3(x);
    touch(x);
    if ( !to_bool(z == y) ) return __LINE__;
#  endif
# endif

#endif

#if defined(UINT_SIZE) && defined(interleave_lo)

    y = interleave_lo(src, (vec_t){});
    z = interleave_lo(y, (vec_t){});

# ifdef widen1
    touch(src);
    x = widen1(src);
    touch(src);
    if ( !to_bool(x == y) ) return __LINE__;
# endif

# ifdef widen2
    touch(src);
    x = widen2(src);
    touch(src);
    if ( !to_bool(x == z) ) return __LINE__;
# endif

# ifdef widen3
    touch(src);
    x = widen3(src);
    touch(src);
    if ( !to_bool(x == interleave_lo(z, (vec_t){})) ) return __LINE__;
# endif

#endif

#ifdef dup_lo
    touch(src);
    x = dup_lo(src);
    touch(src);
    if ( !to_bool(x - src == (alt - 1) / 2) ) return __LINE__;
#endif

#ifdef dup_hi
    touch(src);
    x = dup_hi(src);
    touch(src);
    if ( !to_bool(x - src == (alt + 1) / 2) ) return __LINE__;
#endif

    for ( i = 0; i < ELEM_COUNT; ++i )
        y[i] = (i & 1 ? inv : src)[i];

#ifdef select
# ifdef UINT_SIZE
    select(&z, src, inv, alt);
# else
    select(&z, src, inv, alt > 0);
# endif
    if ( !to_bool(z == y) ) return __LINE__;
#endif

#ifdef select2
# ifdef UINT_SIZE
    select2(&z, src, inv, alt);
# else
    select2(&z, src, inv, alt > 0);
# endif
    if ( !to_bool(z == y) ) return __LINE__;
#endif

#ifdef mix
    touch(src);
    touch(inv);
    x = mix(src, inv);
    if ( !to_bool(x == y) ) return __LINE__;

# ifdef addsub
    touch(src);
    touch(inv);
    x = addsub(src, inv);
    touch(src);
    touch(inv);
    y = mix(src - inv, src + inv);
    if ( !to_bool(x == y) ) return __LINE__;
# endif
#endif

#ifdef rotr
    x = rotr(src, 1);
    y = (src & (ELEM_COUNT - 1)) + 1;
    if ( !to_bool(x == y) ) return __LINE__;
#endif

#ifdef dot_product
    touch(src);
    touch(inv);
    x = dot_product(src, inv);
    if ( !to_bool(x == (vec_t){ (ELEM_COUNT * (ELEM_COUNT + 1) *
                                 (ELEM_COUNT + 2)) / 6 }) ) return __LINE__;
#endif

#ifdef hadd
    x = src;
    for ( i = ELEM_COUNT; i >>= 1; )
    {
        touch(x);
        x = hadd((vec_t){}, x);
    }
    if ( x[ELEM_COUNT - 1] != (ELEM_COUNT * (ELEM_COUNT + 1)) / 2 ) return __LINE__;

# ifdef hsub
    touch(src);
    touch(inv);
    x = hsub(src, inv);
    for ( i = ELEM_COUNT; i >>= 1; )
        x = hadd(x, (vec_t){});
    if ( !to_bool(x == 0) ) return __LINE__;
# endif
#endif


    return 0;
}
