#include "simd.h"

ENTRY(simd_test);

#if defined(__AVX512F__)
# define ALL_TRUE (~0ULL >> (64 - ELEM_COUNT))
# if VEC_SIZE == 4
#  define eq(x, y) ({ \
    float x_ = (x)[0]; \
    float __attribute__((vector_size(16))) y_ = { (y)[0] }; \
    unsigned short r_; \
    asm ( "vcmpss $0, %1, %2, %0"  : "=k" (r_) : "m" (x_), "v" (y_) ); \
    r_ == 1; \
})
# elif VEC_SIZE == 8
#  define eq(x, y) ({ \
    double x_ = (x)[0]; \
    double __attribute__((vector_size(16))) y_ = { (y)[0] }; \
    unsigned short r_; \
    asm ( "vcmpsd $0, %1, %2, %0"  : "=k" (r_) : "m" (x_), "v" (y_) ); \
    r_ == 1; \
})
# elif FLOAT_SIZE == 4
/*
 * gcc's (up to at least 8.2) __builtin_ia32_cmpps256_mask() has an anomaly in
 * that its return type is QI rather than UQI, and hence the value would get
 * sign-extended before comapring to ALL_TRUE. The same oddity does not matter
 * for __builtin_ia32_cmppd256_mask(), as there only 4 bits are significant.
 * Hence the extra " & ALL_TRUE".
 */
#  define eq(x, y) ((BR(cmpps, _mask, x, y, 0, -1) & ALL_TRUE) == ALL_TRUE)
# elif FLOAT_SIZE == 8
#  define eq(x, y) (BR(cmppd, _mask, x, y, 0, -1) == ALL_TRUE)
# elif (INT_SIZE == 1 || UINT_SIZE == 1) && defined(__AVX512BW__)
#  define eq(x, y) (B(pcmpeqb, _mask, (vqi_t)(x), (vqi_t)(y), -1) == ALL_TRUE)
# elif (INT_SIZE == 2 || UINT_SIZE == 2) && defined(__AVX512BW__)
#  define eq(x, y) (B(pcmpeqw, _mask, (vhi_t)(x), (vhi_t)(y), -1) == ALL_TRUE)
# elif INT_SIZE == 4 || UINT_SIZE == 4
#  define eq(x, y) (B(pcmpeqd, _mask, (vsi_t)(x), (vsi_t)(y), -1) == ALL_TRUE)
# elif INT_SIZE == 8 || UINT_SIZE == 8
#  define eq(x, y) (B(pcmpeqq, _mask, (vdi_t)(x), (vdi_t)(y), -1) == ALL_TRUE)
# endif
#elif VEC_SIZE == 8 && defined(__SSE__)
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
# if defined(__AVX2__)
#  define to_bool(cmp) __builtin_ia32_ptestc256(cmp, (vdi_t){} == 0)
# elif defined(__AVX__) && ELEM_SIZE == 4
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

#ifndef eq
# define eq(x, y) to_bool((x) == (y))
#endif

#if VEC_SIZE == FLOAT_SIZE
# define to_int(x) ({ int i_ = (x)[0]; touch(i_); ((vec_t){ i_ }); })
# ifdef __x86_64__
#  define to_wint(x) ({ long l_ = (x)[0]; touch(l_); ((vec_t){ l_ }); })
# endif
# ifdef __AVX512F__
/*
 * Sadly even gcc 9.x, at the time of writing, does not carry out at least
 * uint -> FP conversions using VCVTUSI2S{S,D}, so we need to use builtins
 * or inline assembly here. The full-vector parameter types of the builtins
 * aren't very helpful for our purposes, so use inline assembly.
 */
#  if FLOAT_SIZE == 4
#   define to_u_int(type, x) ({ \
    unsigned type u_; \
    float __attribute__((vector_size(16))) t_; \
    asm ( "vcvtss2usi %1, %0" : "=r" (u_) : "m" ((x)[0]) ); \
    asm ( "vcvtusi2ss%z1 %1, %0, %0" : "=v" (t_) : "m" (u_) ); \
    (vec_t){ t_[0] }; \
})
#  elif FLOAT_SIZE == 8
#   define to_u_int(type, x) ({ \
    unsigned type u_; \
    double __attribute__((vector_size(16))) t_; \
    asm ( "vcvtsd2usi %1, %0" : "=r" (u_) : "m" ((x)[0]) ); \
    asm ( "vcvtusi2sd%z1 %1, %0, %0" : "=v" (t_) : "m" (u_) ); \
    (vec_t){ t_[0] }; \
})
#  endif
#  define to_uint(x) to_u_int(int, x)
#  ifdef __x86_64__
#   define to_uwint(x) to_u_int(long, x)
#  endif
# endif
#elif VEC_SIZE == 8 && FLOAT_SIZE == 4 && defined(__3dNOW__)
# define to_int(x) __builtin_ia32_pi2fd(__builtin_ia32_pf2id(x))
#elif defined(FLOAT_SIZE) && VEC_SIZE > FLOAT_SIZE && defined(__AVX512F__) && \
      (VEC_SIZE == 64 || defined(__AVX512VL__))
# if FLOAT_SIZE == 4
#  define to_int(x) BR(cvtdq2ps, _mask, BR(cvtps2dq, _mask, x, (vsi_t)undef(), ~0), undef(), ~0)
#  define to_uint(x) BR(cvtudq2ps, _mask, BR(cvtps2udq, _mask, x, (vsi_t)undef(), ~0), undef(), ~0)
#  ifdef __AVX512DQ__
#   define to_w_int(x, s) ({ \
    vsf_half_t t_ = low_half(x); \
    vdi_t lo_, hi_; \
    touch(t_); \
    lo_ = BR(cvtps2 ## s ## qq, _mask, t_, (vdi_t)undef(), ~0); \
    t_ = high_half(x); \
    touch(t_); \
    hi_ = BR(cvtps2 ## s ## qq, _mask, t_, (vdi_t)undef(), ~0); \
    touch(lo_); touch(hi_); \
    insert_half(insert_half(undef(), \
                            BR(cvt ## s ## qq2ps, _mask, lo_, (vsf_half_t){}, ~0), 0), \
                BR(cvt ## s ## qq2ps, _mask, hi_, (vsf_half_t){}, ~0), 1); \
})
#   define to_wint(x) to_w_int(x, )
#   define to_uwint(x) to_w_int(x, u)
#  endif
# elif FLOAT_SIZE == 8
#  define to_int(x) B(cvtdq2pd, _mask, BR(cvtpd2dq, _mask, x, (vsi_half_t){}, ~0), undef(), ~0)
#  define to_uint(x) B(cvtudq2pd, _mask, BR(cvtpd2udq, _mask, x, (vsi_half_t){}, ~0), undef(), ~0)
#  ifdef __AVX512DQ__
#   define to_wint(x) BR(cvtqq2pd, _mask, BR(cvtpd2qq, _mask, x, (vdi_t)undef(), ~0), undef(), ~0)
#   define to_uwint(x) BR(cvtuqq2pd, _mask, BR(cvtpd2uqq, _mask, x, (vdi_t)undef(), ~0), undef(), ~0)
#  endif
# endif
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
# define scalar_2op(x, y, op) ({ \
    typeof((x)[0]) __attribute__((vector_size(16))) r_ = { x[0] }; \
    asm ( op : [out] "=&x" (r_) : [in1] "[out]" (r_), [in2] "m" (y) ); \
    (vec_t){ r_[0] }; \
})
#endif

#if VEC_SIZE == 16 && FLOAT_SIZE == 4 && defined(__SSE__)
# define low_half(x) (x)
# define high_half(x) B_(movhlps, , undef(), x)
/*
 * GCC 7 (and perhaps earlier) report a bogus type mismatch for the conditional
 * expression below. All works well with this no-op wrapper.
 */
static inline vec_t movlhps(vec_t x, vec_t y) {
    return __builtin_ia32_movlhps(x, y);
}
# define insert_pair(x, y, p) \
    ((p) ? movlhps(x, y) \
         : ({ vec_t t_ = (x); t_[0] = (y)[0]; t_[1] = (y)[1]; t_; }))
#endif

#if VEC_SIZE == 8 && FLOAT_SIZE == 4 && defined(__3dNOW_A__)
# define max __builtin_ia32_pfmax
# define min __builtin_ia32_pfmin
# define recip(x) ({ \
    vec_t t_ = __builtin_ia32_pfrcp(x); \
    touch(x); \
    t_[1] = __builtin_ia32_pfrcp(__builtin_ia32_pswapdsf(x))[0]; \
    touch(x); \
    __builtin_ia32_pfrcpit2(__builtin_ia32_pfrcpit1(t_, x), t_); \
})
# define rsqrt(x) ({ \
    vec_t t_ = __builtin_ia32_pfrsqrt(x); \
    touch(x); \
    t_[1] = __builtin_ia32_pfrsqrt(__builtin_ia32_pswapdsf(x))[0]; \
    touch(x); \
    __builtin_ia32_pfrcpit2(__builtin_ia32_pfrsqit1(__builtin_ia32_pfmul(t_, t_), x), t_); \
})
#elif defined(FLOAT_SIZE) && VEC_SIZE == FLOAT_SIZE && defined(__AVX512F__)
# if FLOAT_SIZE == 4
#  define getexp(x) scalar_1op(x, "vgetexpss %[in], %[out], %[out]")
#  define getmant(x) scalar_1op(x, "vgetmantss $0, %[in], %[out], %[out]")
#  ifdef __AVX512ER__
#   define recip(x) scalar_1op(x, "vrcp28ss %[in], %[out], %[out]")
#   define rsqrt(x) scalar_1op(x, "vrsqrt28ss %[in], %[out], %[out]")
#  else
#   define recip(x) scalar_1op(x, "vrcp14ss %[in], %[out], %[out]")
#   define rsqrt(x) scalar_1op(x, "vrsqrt14ss %[in], %[out], %[out]")
#  endif
#  define scale(x, y) scalar_2op(x, y, "vscalefss %[in2], %[in1], %[out]")
#  define sqrt(x) scalar_1op(x, "vsqrtss %[in], %[out], %[out]")
#  define trunc(x) scalar_1op(x, "vrndscaless $0b1011, %[in], %[out], %[out]")
# elif FLOAT_SIZE == 8
#  define getexp(x) scalar_1op(x, "vgetexpsd %[in], %[out], %[out]")
#  define getmant(x) scalar_1op(x, "vgetmantsd $0, %[in], %[out], %[out]")
#  ifdef __AVX512ER__
#   define recip(x) scalar_1op(x, "vrcp28sd %[in], %[out], %[out]")
#   define rsqrt(x) scalar_1op(x, "vrsqrt28sd %[in], %[out], %[out]")
#  else
#   define recip(x) scalar_1op(x, "vrcp14sd %[in], %[out], %[out]")
#   define rsqrt(x) scalar_1op(x, "vrsqrt14sd %[in], %[out], %[out]")
#  endif
#  define scale(x, y) scalar_2op(x, y, "vscalefsd %[in2], %[in1], %[out]")
#  define sqrt(x) scalar_1op(x, "vsqrtsd %[in], %[out], %[out]")
#  define trunc(x) scalar_1op(x, "vrndscalesd $0b1011, %[in], %[out], %[out]")
# endif
#elif defined(FLOAT_SIZE) && defined(__AVX512F__) && \
      (VEC_SIZE == 64 || defined(__AVX512VL__))
# if ELEM_COUNT == 8 /* vextractf{32,64}x4 */ || \
     (ELEM_COUNT == 16 && ELEM_SIZE == 4 && defined(__AVX512DQ__)) /* vextractf32x8 */ || \
     (ELEM_COUNT == 4 && ELEM_SIZE == 8 && defined(__AVX512DQ__)) /* vextractf64x2 */
#  define _half(x, lh) ({ \
    half_t t_; \
    asm ( "vextractf%c[w]x%c[n] %[sel], %[s], %[d]" \
          : [d] "=m" (t_) \
          : [s] "v" (x), [sel] "i" (lh), \
            [w] "i" (ELEM_SIZE * 8), [n] "i" (ELEM_COUNT / 2) ); \
    t_; \
})
#  define low_half(x)  _half(x, 0)
#  define high_half(x) _half(x, 1)
# endif
# if (ELEM_COUNT == 16 && ELEM_SIZE == 4) /* vextractf32x4 */ || \
     (ELEM_COUNT == 8 && ELEM_SIZE == 8 && defined(__AVX512DQ__)) /* vextractf64x2 */
#  define low_quarter(x) ({ \
    quarter_t t_; \
    asm ( "vextractf%c[w]x%c[n] $0, %[s], %[d]" \
          : [d] "=m" (t_) \
          : [s] "v" (x), [w] "i" (ELEM_SIZE * 8), [n] "i" (ELEM_COUNT / 4) ); \
    t_; \
})
# endif
# if FLOAT_SIZE == 4
#  define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vbroadcastss %1, %0" \
          : "=v" (t_) : "m" (*(float[1]){ x }) ); \
    t_; \
})
#  if VEC_SIZE >= 32 && defined(__AVX512DQ__)
#   define broadcast_pair(x) ({ \
    vec_t t_; \
    asm ( "vbroadcastf32x2 %1, %0" : "=v" (t_) : "m" (x) ); \
    t_; \
})
#  endif
#  if VEC_SIZE == 64 && defined(__AVX512DQ__)
#   define broadcast_octet(x) B(broadcastf32x8_, _mask, x, undef(), ~0)
#   define insert_octet(x, y, p) B(insertf32x8_, _mask, x, y, p, undef(), ~0)
#  endif
#  ifdef __AVX512DQ__
#   define frac(x) B(reduceps, _mask, x, 0b00001011, undef(), ~0)
#  endif
#  define getexp(x) BR(getexpps, _mask, x, undef(), ~0)
#  define getmant(x) BR(getmantps, _mask, x, 0, undef(), ~0)
#  ifdef __AVX512DQ__
#   define max(x, y) BR(rangeps, _mask, x, y, 0b0101, undef(), ~0)
#   define min(x, y) BR(rangeps, _mask, x, y, 0b0100, undef(), ~0)
#  else
#   define max(x, y) BR_(maxps, _mask, x, y, undef(), ~0)
#   define min(x, y) BR_(minps, _mask, x, y, undef(), ~0)
#  endif
#  define mix(x, y) B(blendmps_, _mask, x, y, (0b1010101010101010 & ALL_TRUE))
#  define scale(x, y) BR(scalefps, _mask, x, y, undef(), ~0)
#  if VEC_SIZE == 64 && defined(__AVX512ER__)
#   define recip(x) BR(rcp28ps, _mask, x, undef(), ~0)
#   define rsqrt(x) BR(rsqrt28ps, _mask, x, undef(), ~0)
#  else
#   define recip(x) B(rcp14ps, _mask, x, undef(), ~0)
#   define rsqrt(x) B(rsqrt14ps, _mask, x, undef(), ~0)
#  endif
#  define shrink1(x) BR_(cvtpd2ps, _mask, (vdf_t)(x), (vsf_half_t){}, ~0)
#  define sqrt(x) BR(sqrtps, _mask, x, undef(), ~0)
#  define trunc(x) BR(rndscaleps_, _mask, x, 0b1011, undef(), ~0)
#  define widen1(x) ((vec_t)BR(cvtps2pd, _mask, x, (vdf_t)undef(), ~0))
#  if VEC_SIZE == 16
#   define interleave_hi(x, y) B(unpckhps, _mask, x, y, undef(), ~0)
#   define interleave_lo(x, y) B(unpcklps, _mask, x, y, undef(), ~0)
#   define swap(x) B(shufps, _mask, x, x, 0b00011011, undef(), ~0)
#   define swap2(x) B_(vpermilps, _mask, x, 0b00011011, undef(), ~0)
#  else
#   define broadcast_quartet(x) B(broadcastf32x4_, _mask, x, undef(), ~0)
#   define insert_pair(x, y, p) \
    B(insertf32x4_, _mask, x, \
      /* Cast needed below to work around gcc 7.x quirk. */ \
      (p) & 1 ? (typeof(y))__builtin_ia32_shufps(y, y, 0b01000100) : (y), \
      (p) >> 1, x, 3 << ((p) * 2))
#   define insert_quartet(x, y, p) B(insertf32x4_, _mask, x, y, p, undef(), ~0)
#   define interleave_hi(x, y) B(vpermi2varps, _mask, x, interleave_hi, y, ~0)
#   define interleave_lo(x, y) B(vpermt2varps, _mask, interleave_lo, x, y, ~0)
#   define swap(x) ({ \
    vec_t t_ = B(shuf_f32x4_, _mask, x, x, VEC_SIZE == 32 ? 0b01 : 0b00011011, undef(), ~0); \
    B(shufps, _mask, t_, t_, 0b00011011, undef(), ~0); \
})
#   define swap2(x) B(vpermilps, _mask, \
                       B(shuf_f32x4_, _mask, x, x, \
                         VEC_SIZE == 32 ? 0b01 : 0b00011011, undef(), ~0), \
                       0b00011011, undef(), ~0)
#  endif
# elif FLOAT_SIZE == 8
#  if VEC_SIZE >= 32
#   define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vbroadcastsd %1, %0" : "=v" (t_) \
          : "m" (*(double[1]){ x }) ); \
    t_; \
})
#  else
#   define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vpbroadcastq %1, %0" \
          : "=v" (t_) : "m" (*(double[1]){ x }) ); \
    t_; \
})
#  endif
#  if VEC_SIZE >= 32 && defined(__AVX512DQ__)
#   define broadcast_pair(x) B(broadcastf64x2_, _mask, x, undef(), ~0)
#   define insert_pair(x, y, p) B(insertf64x2_, _mask, x, y, p, undef(), ~0)
#  endif
#  if VEC_SIZE == 64
#   define broadcast_quartet(x) B(broadcastf64x4_, , x, undef(), ~0)
#   define insert_quartet(x, y, p) B(insertf64x4_, _mask, x, y, p, undef(), ~0)
#  endif
#  ifdef __AVX512DQ__
#   define frac(x) B(reducepd, _mask, x, 0b00001011, undef(), ~0)
#  endif
#  define getexp(x) BR(getexppd, _mask, x, undef(), ~0)
#  define getmant(x) BR(getmantpd, _mask, x, 0, undef(), ~0)
#  ifdef __AVX512DQ__
#   define max(x, y) BR(rangepd, _mask, x, y, 0b0101, undef(), ~0)
#   define min(x, y) BR(rangepd, _mask, x, y, 0b0100, undef(), ~0)
#  else
#   define max(x, y) BR_(maxpd, _mask, x, y, undef(), ~0)
#   define min(x, y) BR_(minpd, _mask, x, y, undef(), ~0)
#  endif
#  define mix(x, y) B(blendmpd_, _mask, x, y, 0b10101010)
#  define scale(x, y) BR(scalefpd, _mask, x, y, undef(), ~0)
#  if VEC_SIZE == 64 && defined(__AVX512ER__)
#   define recip(x) BR(rcp28pd, _mask, x, undef(), ~0)
#   define rsqrt(x) BR(rsqrt28pd, _mask, x, undef(), ~0)
#  else
#   define recip(x) B(rcp14pd, _mask, x, undef(), ~0)
#   define rsqrt(x) B(rsqrt14pd, _mask, x, undef(), ~0)
#  endif
#  define sqrt(x) BR(sqrtpd, _mask, x, undef(), ~0)
#  define trunc(x) BR(rndscalepd_, _mask, x, 0b1011, undef(), ~0)
#  if VEC_SIZE == 16
#   define interleave_hi(x, y) B(unpckhpd, _mask, x, y, undef(), ~0)
#   define interleave_lo(x, y) B(unpcklpd, _mask, x, y, undef(), ~0)
#   define swap(x) B(shufpd, _mask, x, x, 0b01, undef(), ~0)
#   define swap2(x) B_(vpermilpd, _mask, x, 0b01, undef(), ~0)
#  else
#   define interleave_hi(x, y) B(vpermi2varpd, _mask, x, interleave_hi, y, ~0)
#   define interleave_lo(x, y) B(vpermt2varpd, _mask, interleave_lo, x, y, ~0)
#   define swap(x) ({ \
    vec_t t_ = B(shuf_f64x2_, _mask, x, x, VEC_SIZE == 32 ? 0b01 : 0b00011011, undef(), ~0); \
    B(shufpd, _mask, t_, t_, 0b01010101, undef(), ~0); \
})
#   define swap2(x) B(vpermilpd, _mask, \
                       B(shuf_f64x2_, _mask, x, x, \
                         VEC_SIZE == 32 ? 0b01 : 0b00011011, undef(), ~0), \
                       0b01010101, undef(), ~0)
#  endif
# endif
#elif FLOAT_SIZE == 4 && defined(__SSE__)
# if VEC_SIZE == 32 && defined(__AVX__)
#  if defined(__AVX2__)
#   define broadcast(x) \
    __builtin_ia32_vbroadcastss_ps256((float __attribute__((vector_size(16)))){ x })
#  else
#   define broadcast(x) ({ float t_ = (x); __builtin_ia32_vbroadcastss256(&t_); })
#  endif
#  define max(x, y) __builtin_ia32_maxps256(x, y)
#  define min(x, y) __builtin_ia32_minps256(x, y)
#  define recip(x) __builtin_ia32_rcpps256(x)
#  define rsqrt(x) __builtin_ia32_rsqrtps256(x)
#  define sqrt(x) __builtin_ia32_sqrtps256(x)
#  define swap(x) ({ \
    vec_t t_ = __builtin_ia32_vpermilps256(x, 0b00011011); \
    __builtin_ia32_vperm2f128_ps256(t_, t_, 0b00000001); \
})
#  ifdef __AVX2__
#   define swap2(x) __builtin_ia32_permvarsf256(x, __builtin_ia32_cvtps2dq256(inv) - 1)
#  else
#   define swap2(x) ({ \
        vec_t t_ = __builtin_ia32_vpermilvarps256(x, __builtin_ia32_cvtps2dq256(inv) - 1); \
        __builtin_ia32_vperm2f128_ps256(t_, t_, 0b00000001); \
})
#  endif
# elif VEC_SIZE == 16
#  if defined(__AVX2__)
#   define broadcast(x) __builtin_ia32_vbroadcastss_ps((vec_t){ x })
#  elif defined(__AVX__)
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
#  if defined(__AVX2__)
#   define broadcast(x) \
    __builtin_ia32_vbroadcastsd_pd256((double __attribute__((vector_size(16)))){ x })
#  else
#   define broadcast(x) ({ double t_ = (x); __builtin_ia32_vbroadcastsd256(&t_); })
#  endif
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
#  ifdef __AVX2__
#   define swap2(x) __builtin_ia32_permdf256(x, 0b00011011)
#  endif
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
#if (INT_SIZE == 4 || UINT_SIZE == 4 || INT_SIZE == 8 || UINT_SIZE == 8) && \
     defined(__AVX512F__) && (VEC_SIZE == 64 || defined(__AVX512VL__))
# if ELEM_COUNT == 8 /* vextracti{32,64}x4 */ || \
     (ELEM_COUNT == 16 && ELEM_SIZE == 4 && defined(__AVX512DQ__)) /* vextracti32x8 */ || \
     (ELEM_COUNT == 4 && ELEM_SIZE == 8 && defined(__AVX512DQ__)) /* vextracti64x2 */
#  define low_half(x) ({ \
    half_t t_; \
    asm ( "vextracti%c[w]x%c[n] $0, %[s], %[d]" \
          : [d] "=m" (t_) \
          : [s] "v" (x), [w] "i" (ELEM_SIZE * 8), [n] "i" (ELEM_COUNT / 2) ); \
    t_; \
})
# endif
# if (ELEM_COUNT == 16 && ELEM_SIZE == 4) /* vextracti32x4 */ || \
       (ELEM_COUNT == 8 && ELEM_SIZE == 8 && defined(__AVX512DQ__)) /* vextracti64x2 */
#  define low_quarter(x) ({ \
    quarter_t t_; \
    asm ( "vextracti%c[w]x%c[n] $0, %[s], %[d]" \
          : [d] "=m" (t_) \
          : [s] "v" (x), [w] "i" (ELEM_SIZE * 8), [n] "i" (ELEM_COUNT / 4) ); \
    t_; \
})
# endif
# if INT_SIZE == 4 || UINT_SIZE == 4
#  define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vpbroadcastd %1, %0" \
          : "=v" (t_) : "m" (*(int[1]){ x }) ); \
    t_; \
})
#  define broadcast2(x) ({ \
    vec_t t_; \
    asm ( "vpbroadcastd %k1, %0" : "=v" (t_) : "r" (x) ); \
    t_; \
})
#  ifdef __AVX512DQ__
#   define broadcast_pair(x) ({ \
    vec_t t_; \
    asm ( "vbroadcasti32x2 %1, %0" : "=v" (t_) : "m" (x) ); \
    t_; \
})
#  endif
#  if VEC_SIZE == 64 && defined(__AVX512DQ__)
#   define broadcast_octet(x) ((vec_t)B(broadcasti32x8_, _mask, (vsi_octet_t)(x), (vsi_t)undef(), ~0))
#   define insert_octet(x, y, p) ((vec_t)B(inserti32x8_, _mask, (vsi_t)(x), (vsi_octet_t)(y), p, (vsi_t)undef(), ~0))
#  endif
#  if VEC_SIZE == 16
#   define interleave_hi(x, y) ((vec_t)B(punpckhdq, _mask, (vsi_t)(x), (vsi_t)(y), (vsi_t)undef(), ~0))
#   define interleave_lo(x, y) ((vec_t)B(punpckldq, _mask, (vsi_t)(x), (vsi_t)(y), (vsi_t)undef(), ~0))
#   define swap(x) ((vec_t)B(pshufd, _mask, (vsi_t)(x), 0b00011011, (vsi_t)undef(), ~0))
#  else
#   define broadcast_quartet(x) ((vec_t)B(broadcasti32x4_, _mask, (vsi_quartet_t)(x), (vsi_t)undef(), ~0))
#   define insert_pair(x, y, p) \
    (vec_t)(B(inserti32x4_, _mask, (vsi_t)(x), \
              /* First cast needed below to work around gcc 7.x quirk. */ \
              (p) & 1 ? (vsi_pair_t)__builtin_ia32_pshufd((vsi_pair_t)(y), 0b01000100) \
                      : (vsi_pair_t)(y), \
              (p) >> 1, (vsi_t)(x), 3 << ((p) * 2)))
#   define insert_quartet(x, y, p) ((vec_t)B(inserti32x4_, _mask, (vsi_t)(x), (vsi_quartet_t)(y), p, (vsi_t)undef(), ~0))
#   define interleave_hi(x, y) ((vec_t)B(vpermi2vard, _mask, (vsi_t)(x), interleave_hi, (vsi_t)(y), ~0))
#   define interleave_lo(x, y) ((vec_t)B(vpermt2vard, _mask, interleave_lo, (vsi_t)(x), (vsi_t)(y), ~0))
#   define swap(x) ((vec_t)B(pshufd, _mask, \
                             B(shuf_i32x4_, _mask, (vsi_t)(x), (vsi_t)(x), \
                               VEC_SIZE == 32 ? 0b01 : 0b00011011, (vsi_t)undef(), ~0), \
                             0b00011011, (vsi_t)undef(), ~0))
#   define swap2(x) ((vec_t)B_(permvarsi, _mask, (vsi_t)(x), (vsi_t)(inv - 1), (vsi_t)undef(), ~0))
#  endif
#  define mix(x, y) ((vec_t)B(blendmd_, _mask, (vsi_t)(x), (vsi_t)(y), \
                              (0b1010101010101010 & ((1 << ELEM_COUNT) - 1))))
#  define rotr(x, n) ((vec_t)B(alignd, _mask, (vsi_t)(x), (vsi_t)(x), n, (vsi_t)undef(), ~0))
#  define shrink1(x) ((half_t)B(pmovqd, _mask, (vdi_t)(x), (vsi_half_t){}, ~0))
# elif INT_SIZE == 8 || UINT_SIZE == 8
#  define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vpbroadcastq %1, %0" \
          : "=v" (t_) : "m" (*(long long[1]){ x }) ); \
    t_; \
})
#  ifdef __x86_64__
#   define broadcast2(x) ({ \
    vec_t t_; \
    asm ( "vpbroadcastq %1, %0" : "=v" (t_) : "r" ((x) + 0ULL) ); \
    t_; \
})
#  endif
#  if VEC_SIZE >= 32 && defined(__AVX512DQ__)
#   define broadcast_pair(x) ((vec_t)B(broadcasti64x2_, _mask, (vdi_pair_t)(x), (vdi_t)undef(), ~0))
#   define insert_pair(x, y, p) ((vec_t)B(inserti64x2_, _mask, (vdi_t)(x), (vdi_pair_t)(y), p, (vdi_t)undef(), ~0))
#  endif
#  if VEC_SIZE == 64
#   define broadcast_quartet(x) ((vec_t)B(broadcasti64x4_, , (vdi_quartet_t)(x), (vdi_t)undef(), ~0))
#   define insert_quartet(x, y, p) ((vec_t)B(inserti64x4_, _mask, (vdi_t)(x), (vdi_quartet_t)(y), p, (vdi_t)undef(), ~0))
#  endif
#  if VEC_SIZE == 16
#   define interleave_hi(x, y) ((vec_t)B(punpckhqdq, _mask, (vdi_t)(x), (vdi_t)(y), (vdi_t)undef(), ~0))
#   define interleave_lo(x, y) ((vec_t)B(punpcklqdq, _mask, (vdi_t)(x), (vdi_t)(y), (vdi_t)undef(), ~0))
#   define swap(x) ((vec_t)B(pshufd, _mask, (vsi_t)(x), 0b01001110, (vsi_t)undef(), ~0))
#  else
#   define interleave_hi(x, y) ((vec_t)B(vpermi2varq, _mask, (vdi_t)(x), interleave_hi, (vdi_t)(y), ~0))
#   define interleave_lo(x, y) ((vec_t)B(vpermt2varq, _mask, interleave_lo, (vdi_t)(x), (vdi_t)(y), ~0))
#   define swap(x) ((vec_t)B(pshufd, _mask, \
                             (vsi_t)B(shuf_i64x2_, _mask, (vdi_t)(x), (vdi_t)(x), \
                                      VEC_SIZE == 32 ? 0b01 : 0b00011011, (vdi_t)undef(), ~0), \
                             0b01001110, (vsi_t)undef(), ~0))
#   define swap2(x) ((vec_t)B(permvardi, _mask, (vdi_t)(x), (vdi_t)(inv - 1), (vdi_t)undef(), ~0))
#  endif
#  define mix(x, y) ((vec_t)B(blendmq_, _mask, (vdi_t)(x), (vdi_t)(y), 0b10101010))
#  define rotr(x, n) ((vec_t)B(alignq, _mask, (vdi_t)(x), (vdi_t)(x), n, (vdi_t)undef(), ~0))
#  if VEC_SIZE == 32
#   define swap3(x) ((vec_t)B_(permdi, _mask, (vdi_t)(x), 0b00011011, (vdi_t)undef(), ~0))
#  elif VEC_SIZE == 64
#   define swap3(x) ({ \
    vdi_t t_ = B_(permdi, _mask, (vdi_t)(x), 0b00011011, (vdi_t)undef(), ~0); \
    B(shuf_i64x2_, _mask, t_, t_, 0b01001110, (vdi_t)undef(), ~0); \
})
#  endif
# endif
# if INT_SIZE == 4
#  define abs(x) B(pabsd, _mask, x, undef(), ~0)
#  define max(x, y) B(pmaxsd, _mask, x, y, undef(), ~0)
#  define min(x, y) B(pminsd, _mask, x, y, undef(), ~0)
#  define mul_full(x, y) ((vec_t)B(pmuldq, _mask, x, y, (vdi_t)undef(), ~0))
#  define widen1(x) ((vec_t)B(pmovsxdq, _mask, x, (vdi_t)undef(), ~0))
# elif UINT_SIZE == 4
#  define max(x, y) ((vec_t)B(pmaxud, _mask, (vsi_t)(x), (vsi_t)(y), (vsi_t)undef(), ~0))
#  define min(x, y) ((vec_t)B(pminud, _mask, (vsi_t)(x), (vsi_t)(y), (vsi_t)undef(), ~0))
#  define mul_full(x, y) ((vec_t)B(pmuludq, _mask, (vsi_t)(x), (vsi_t)(y), (vdi_t)undef(), ~0))
#  define widen1(x) ((vec_t)B(pmovzxdq, _mask, (vsi_half_t)(x), (vdi_t)undef(), ~0))
# elif INT_SIZE == 8
#  define abs(x) ((vec_t)B(pabsq, _mask, (vdi_t)(x), (vdi_t)undef(), ~0))
#  define max(x, y) ((vec_t)B(pmaxsq, _mask, (vdi_t)(x), (vdi_t)(y), (vdi_t)undef(), ~0))
#  define min(x, y) ((vec_t)B(pminsq, _mask, (vdi_t)(x), (vdi_t)(y), (vdi_t)undef(), ~0))
# elif UINT_SIZE == 8
#  define max(x, y) ((vec_t)B(pmaxuq, _mask, (vdi_t)(x), (vdi_t)(y), (vdi_t)undef(), ~0))
#  define min(x, y) ((vec_t)B(pminuq, _mask, (vdi_t)(x), (vdi_t)(y), (vdi_t)undef(), ~0))
# endif
#elif (INT_SIZE == 1 || UINT_SIZE == 1 || INT_SIZE == 2 || UINT_SIZE == 2) && \
      defined(__AVX512BW__) && (VEC_SIZE == 64 || defined(__AVX512VL__))
# if INT_SIZE == 1 || UINT_SIZE == 1
#  define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vpbroadcastb %1, %0" \
          : "=v" (t_) : "m" (*(char[1]){ x }) ); \
    t_; \
})
#  define broadcast2(x) ({ \
    vec_t t_; \
    asm ( "vpbroadcastb %k1, %0" : "=v" (t_) : "r" (x) ); \
    t_; \
})
#  if VEC_SIZE == 16
#   define interleave_hi(x, y) ((vec_t)B(punpckhbw, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0))
#   define interleave_lo(x, y) ((vec_t)B(punpcklbw, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0))
#   define rotr(x, n) ((vec_t)B(palignr, _mask, (vdi_t)(x), (vdi_t)(x), (n) * 8, (vdi_t)undef(), ~0))
#   define swap(x) ((vec_t)B(pshufb, _mask, (vqi_t)(x), (vqi_t)(inv - 1), (vqi_t)undef(), ~0))
#  elif defined(__AVX512VBMI__)
#   define interleave_hi(x, y) ((vec_t)B(vpermi2varqi, _mask, (vqi_t)(x), interleave_hi, (vqi_t)(y), ~0))
#   define interleave_lo(x, y) ((vec_t)B(vpermt2varqi, _mask, interleave_lo, (vqi_t)(x), (vqi_t)(y), ~0))
#  endif
#  define mix(x, y) ((vec_t)B(blendmb_, _mask, (vqi_t)(x), (vqi_t)(y), \
                              (0b1010101010101010101010101010101010101010101010101010101010101010LL & ALL_TRUE)))
#  define shrink1(x) ((half_t)B(pmovwb, _mask, (vhi_t)(x), (vqi_half_t){}, ~0))
#  define shrink2(x) ((quarter_t)B(pmovdb, _mask, (vsi_t)(x), (vqi_quarter_t){}, ~0))
#  define shrink3(x) ((eighth_t)B(pmovqb, _mask, (vdi_t)(x), (vqi_eighth_t){}, ~0))
#  ifdef __AVX512VBMI__
#   define swap2(x) ((vec_t)B(permvarqi, _mask, (vqi_t)(x), (vqi_t)(inv - 1), (vqi_t)undef(), ~0))
#  endif
# elif INT_SIZE == 2 || UINT_SIZE == 2
#  define broadcast(x) ({ \
    vec_t t_; \
    asm ( "%{evex%} vpbroadcastw %1, %0" \
          : "=v" (t_) : "m" (*(short[1]){ x }) ); \
    t_; \
})
#  define broadcast2(x) ({ \
    vec_t t_; \
    asm ( "vpbroadcastw %k1, %0" : "=v" (t_) : "r" (x) ); \
    t_; \
})
#  if VEC_SIZE == 16
#   define interleave_hi(x, y) ((vec_t)B(punpckhwd, _mask, (vhi_t)(x), (vhi_t)(y), (vhi_t)undef(), ~0))
#   define interleave_lo(x, y) ((vec_t)B(punpcklwd, _mask, (vhi_t)(x), (vhi_t)(y), (vhi_t)undef(), ~0))
#   define rotr(x, n) ((vec_t)B(palignr, _mask, (vdi_t)(x), (vdi_t)(x), (n) * 16, (vdi_t)undef(), ~0))
#   define swap(x) ((vec_t)B(pshufd, _mask, \
                             (vsi_t)B(pshufhw, _mask, \
                                      B(pshuflw, _mask, (vhi_t)(x), 0b00011011, (vhi_t)undef(), ~0), \
                                      0b00011011, (vhi_t)undef(), ~0), \
                             0b01001110, (vsi_t)undef(), ~0))
#  else
#   define interleave_hi(x, y) ((vec_t)B(vpermi2varhi, _mask, (vhi_t)(x), interleave_hi, (vhi_t)(y), ~0))
#   define interleave_lo(x, y) ((vec_t)B(vpermt2varhi, _mask, interleave_lo, (vhi_t)(x), (vhi_t)(y), ~0))
#  endif
#  define mix(x, y) ((vec_t)B(blendmw_, _mask, (vhi_t)(x), (vhi_t)(y), \
                              (0b10101010101010101010101010101010 & ALL_TRUE)))
#  define shrink1(x) ((half_t)B(pmovdw, _mask, (vsi_t)(x), (vhi_half_t){}, ~0))
#  define shrink2(x) ((quarter_t)B(pmovqw, _mask, (vdi_t)(x), (vhi_quarter_t){}, ~0))
#  define swap2(x) ((vec_t)B(permvarhi, _mask, (vhi_t)(x), (vhi_t)(inv - 1), (vhi_t)undef(), ~0))
# endif
# if INT_SIZE == 1
#  define abs(x) ((vec_t)B(pabsb, _mask, (vqi_t)(x), (vqi_t)undef(), ~0))
#  define max(x, y) ((vec_t)B(pmaxsb, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0))
#  define min(x, y) ((vec_t)B(pminsb, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0))
#  define widen1(x) ((vec_t)B(pmovsxbw, _mask, (vqi_half_t)(x), (vhi_t)undef(), ~0))
#  define widen2(x) ((vec_t)B(pmovsxbd, _mask, (vqi_quarter_t)(x), (vsi_t)undef(), ~0))
#  define widen3(x) ((vec_t)B(pmovsxbq, _mask, (vqi_eighth_t)(x), (vdi_t)undef(), ~0))
# elif UINT_SIZE == 1
#  define max(x, y) ((vec_t)B(pmaxub, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0))
#  define min(x, y) ((vec_t)B(pminub, _mask, (vqi_t)(x), (vqi_t)(y), (vqi_t)undef(), ~0))
#  define widen1(x) ((vec_t)B(pmovzxbw, _mask, (vqi_half_t)(x), (vhi_t)undef(), ~0))
#  define widen2(x) ((vec_t)B(pmovzxbd, _mask, (vqi_quarter_t)(x), (vsi_t)undef(), ~0))
#  define widen3(x) ((vec_t)B(pmovzxbq, _mask, (vqi_eighth_t)(x), (vdi_t)undef(), ~0))
# elif INT_SIZE == 2
#  define abs(x) B(pabsw, _mask, x, undef(), ~0)
#  define max(x, y) B(pmaxsw, _mask, x, y, undef(), ~0)
#  define min(x, y) B(pminsw, _mask, x, y, undef(), ~0)
#  define mul_hi(x, y) B(pmulhw, _mask, x, y, undef(), ~0)
#  define widen1(x) ((vec_t)B(pmovsxwd, _mask, x, (vsi_t)undef(), ~0))
#  define widen2(x) ((vec_t)B(pmovsxwq, _mask, x, (vdi_t)undef(), ~0))
# elif UINT_SIZE == 2
#  define max(x, y) ((vec_t)B(pmaxuw, _mask, (vhi_t)(x), (vhi_t)(y), (vhi_t)undef(), ~0))
#  define min(x, y) ((vec_t)B(pminuw, _mask, (vhi_t)(x), (vhi_t)(y), (vhi_t)undef(), ~0))
#  define mul_hi(x, y) ((vec_t)B(pmulhuw, _mask, (vhi_t)(x), (vhi_t)(y), (vhi_t)undef(), ~0))
#  define widen1(x) ((vec_t)B(pmovzxwd, _mask, (vhi_half_t)(x), (vsi_t)undef(), ~0))
#  define widen2(x) ((vec_t)B(pmovzxwq, _mask, (vhi_quarter_t)(x), (vdi_t)undef(), ~0))
# endif
#elif VEC_SIZE == 16 && defined(__SSE2__)
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
#elif VEC_SIZE == 32 && defined(__AVX2__)
# define swap_lanes(x, y, func, type) ({ \
    long long __attribute__((vector_size(16))) t_ = __builtin_ia32_extract128i256((vdi_t)(y), 0); \
    type t1_ = (type)__builtin_ia32_insert128i256((vdi_t)(x), t_, 1), t2_; \
    t_ = __builtin_ia32_extract128i256((vdi_t)(x), 1); \
    t2_ = (type)__builtin_ia32_insert128i256((vdi_t)(y), t_, 0); \
    func(t1_, t2_); \
})
# if INT_SIZE == 1 || UINT_SIZE == 1
#  define broadcast(x) ({ char s_ = (x); vec_t d_; asm ( "vpbroadcastb %1,%0" : "=x" (d_) : "m" (s_)); d_; })
#  define copysignz(x, y) ((vec_t)__builtin_ia32_psignb256((vqi_t)(x), (vqi_t)(y)))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr256(__builtin_ia32_permti256((vdi_t)(x), (vdi_t)(x), 0b00000001), \
                                                       (vdi_t)(x), (n) * 8))
# elif INT_SIZE == 2 || UINT_SIZE == 2
#  define broadcast(x) ({ short s_ = (x); vec_t d_; asm ( "vpbroadcastw %1,%0" : "=x" (d_) : "m" (s_)); d_; })
#  define copysignz(x, y) ((vec_t)__builtin_ia32_psignw256((vhi_t)(x), (vhi_t)(y)))
#  define hadd(x, y) ((vec_t)swap_lanes(x, y, __builtin_ia32_phaddw256, vhi_t))
#  define hsub(x, y) ((vec_t)swap_lanes(x, y, __builtin_ia32_phsubw256, vhi_t))
#  define mix(x, y) ((vec_t)__builtin_ia32_pblendw256((vhi_t)(x), (vhi_t)(y), 0b10101010))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr256(__builtin_ia32_permti256((vdi_t)(x), (vdi_t)(x), 0b00000001), \
                                                       (vdi_t)(x), (n) * 16))
# elif INT_SIZE == 4 || UINT_SIZE == 4
#  define broadcast(x) ({ int s_ = (x); vec_t d_; asm ( "vpbroadcastd %1,%0" : "=x" (d_) : "m" (s_)); d_; })
#  define copysignz(x, y) ((vec_t)__builtin_ia32_psignd256((vsi_t)(x), (vsi_t)(y)))
#  define hadd(x, y) ((vec_t)swap_lanes(x, y, __builtin_ia32_phaddd256, vsi_t))
#  define hsub(x, y) ((vec_t)swap_lanes(x, y, __builtin_ia32_phsubd256, vsi_t))
#  define mix(x, y) ((vec_t)__builtin_ia32_pblendd256((vsi_t)(x), (vsi_t)(y), 0b10101010))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr256(__builtin_ia32_permti256((vdi_t)(x), (vdi_t)(x), 0b00000001), \
                                                       (vdi_t)(x), (n) * 32))
#  define select(d, x, y, m) ({ \
    vsi_t m_ = (vsi_t)(m); \
    *(d) = (vec_t)__builtin_ia32_maskloadd256((vsi_t *)&(x),  m_); \
    __builtin_ia32_maskstored256((vsi_t *)(d), ~m_, (vsi_t)(y)); \
})
#  define swap(x) ((vec_t)__builtin_ia32_permvarsi256((vsi_t)(x), (vsi_t)inv - 1))
# elif INT_SIZE == 8 || UINT_SIZE == 8
#  define mix(x, y) ((vec_t)__builtin_ia32_pblendd256((vsi_t)(x), (vsi_t)(y), 0b11001100))
#  define rotr(x, n) ((vec_t)__builtin_ia32_palignr256(__builtin_ia32_permti256((vdi_t)(x), (vdi_t)(x), 0b00000001), \
                                                       (vdi_t)(x), (n) * 64))
#  define select(d, x, y, m) ({ \
    vdi_t m_ = (vdi_t)(m); \
    *(d) = (vec_t)__builtin_ia32_maskloadq256((vdi_t *)&(x),  m_); \
    __builtin_ia32_maskstoreq256((vdi_t *)(d), ~m_, (vdi_t)(y)); \
})
#  define swap(x) ((vec_t)__builtin_ia32_permdi256((vdi_t)(x), 0b00011011))
#  define swap2(x) ({ \
    vdi_t t_ = __builtin_ia32_permdi256((vdi_t)(x), 0b10110001); \
    (vec_t)__builtin_ia32_permti256(t_, t_, 0b00000001); \
})
# endif
# if INT_SIZE == 1
#  define abs(x) ((vec_t)__builtin_ia32_pabsb256((vqi_t)(x)))
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxsb256((vqi_t)(x), (vqi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminsb256((vqi_t)(x), (vqi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovsxbw256((vqi_t)(x)))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovsxbd256((vqi_t)(x)))
#  define widen3(x) ((vec_t)__builtin_ia32_pmovsxbq256((vqi_t)(x)))
# elif UINT_SIZE == 1
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxub256((vqi_t)(x), (vqi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminub256((vqi_t)(x), (vqi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovzxbw256((vqi_t)(x)))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovzxbd256((vqi_t)(x)))
#  define widen3(x) ((vec_t)__builtin_ia32_pmovzxbq256((vqi_t)(x)))
# elif INT_SIZE == 2
#  define abs(x) __builtin_ia32_pabsw256(x)
#  define max(x, y) __builtin_ia32_pmaxsw256(x, y)
#  define min(x, y) __builtin_ia32_pminsw256(x, y)
#  define mul_hi(x, y) __builtin_ia32_pmulhw256(x, y)
#  define widen1(x) ((vec_t)__builtin_ia32_pmovsxwd256(x))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovsxwq256(x))
# elif UINT_SIZE == 2
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxuw256((vhi_t)(x), (vhi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminuw256((vhi_t)(x), (vhi_t)(y)))
#  define mul_hi(x, y) ((vec_t)__builtin_ia32_pmulhuw256((vhi_t)(x), (vhi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovzxwd256((vhi_t)(x)))
#  define widen2(x) ((vec_t)__builtin_ia32_pmovzxwq256((vhi_t)(x)))
# elif INT_SIZE == 4
#  define abs(x) __builtin_ia32_pabsd256(x)
#  define max(x, y) __builtin_ia32_pmaxsd256(x, y)
#  define min(x, y) __builtin_ia32_pminsd256(x, y)
#  define widen1(x) ((vec_t)__builtin_ia32_pmovsxdq256(x))
# elif UINT_SIZE == 4
#  define max(x, y) ((vec_t)__builtin_ia32_pmaxud256((vsi_t)(x), (vsi_t)(y)))
#  define min(x, y) ((vec_t)__builtin_ia32_pminud256((vsi_t)(x), (vsi_t)(y)))
#  define mul_full(x, y) ((vec_t)__builtin_ia32_pmuludq256((vsi_t)(x), (vsi_t)(y)))
#  define widen1(x) ((vec_t)__builtin_ia32_pmovzxdq256((vsi_t)(x)))
# elif INT_SIZE == 8
#  define broadcast(x) ({ \
    long long s_ = (x); \
    long long __attribute__((vector_size(16))) t_; \
    vec_t d_; \
    asm ( "vpbroadcastq %1,%0" : "=x" (t_) : "m" (s_)); \
    asm ( "vbroadcasti128 %1,%0" : "=x" (d_) : "m" (t_)); \
    d_; \
})
# elif UINT_SIZE == 8
#  define broadcast(x) ({ long long s_ = (x); vec_t d_; asm ( "vpbroadcastq %1,%0" : "=x" (d_) : "m" (s_)); d_; })
# endif
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
#  ifdef __AVX2__
#   define hadd(x, y) __builtin_ia32_permvarsf256(__builtin_ia32_haddps256(x, y), \
                                                  (vsi_t){0, 1, 4, 5, 2, 3, 6, 7})
#   define hsub(x, y) __builtin_ia32_permvarsf256(__builtin_ia32_hsubps256(x, y), \
                                                  (vsi_t){0, 1, 4, 5, 2, 3, 6, 7})
#  else
#   define hadd(x, y) ({ \
        vec_t t_ = __builtin_ia32_haddps256(x, y); \
        (vec_t){t_[0], t_[1], t_[4], t_[5], t_[2], t_[3], t_[6], t_[7]}; \
})
#   define hsub(x, y) ({ \
        vec_t t_ = __builtin_ia32_hsubps256(x, y); \
        (vec_t){t_[0], t_[1], t_[4], t_[5], t_[2], t_[3], t_[6], t_[7]}; \
})
#  endif
# elif FLOAT_SIZE == 8
#  define addsub(x, y) __builtin_ia32_addsubpd256(x, y)
#  define dup_lo(x) __builtin_ia32_movddup256(x)
#  ifdef __AVX2__
#   define hadd(x, y) __builtin_ia32_permdf256(__builtin_ia32_haddpd256(x, y), 0b11011000)
#   define hsub(x, y) __builtin_ia32_permdf256(__builtin_ia32_hsubpd256(x, y), 0b11011000)
#  else
#   define hadd(x, y) ({ \
        vec_t t_ = __builtin_ia32_haddpd256(x, y); \
        (vec_t){t_[0], t_[2], t_[1], t_[3]}; \
})
#   define hsub(x, y) ({ \
        vec_t t_ = __builtin_ia32_hsubpd256(x, y); \
        (vec_t){t_[0], t_[2], t_[1], t_[3]}; \
})
#  endif
# endif
#endif
#if VEC_SIZE == 16 && defined(__SSSE3__) && !defined(__AVX512VL__)
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
#if VEC_SIZE == 16 && defined(__SSE4_1__) && !defined(__AVX512VL__)
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
#if VEC_SIZE == 32 && defined(__AVX__) && !defined(__AVX512VL__)
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
# if defined(__SSE4_1__) && !defined(__AVX512F__)
#  if FLOAT_SIZE == 4
#   define trunc(x) scalar_1op(x, "roundss $0b1011, %[in], %[out]")
#  elif FLOAT_SIZE == 8
#   define trunc(x) scalar_1op(x, "roundsd $0b1011, %[in], %[out]")
#  endif
# endif
#endif
#ifdef __XOP__
# undef select
# if VEC_SIZE == 16
#  if INT_SIZE == 2 || INT_SIZE == 4
#   include "simd-fma.c"
#  endif
#  define select(d, x, y, m) \
    (*(d) = (vec_t)__builtin_ia32_vpcmov((vdi_t)(x), (vdi_t)(y), (vdi_t)(m)))
#  if INT_SIZE == 1 || UINT_SIZE == 1
#   define swap2(x) ((vec_t)__builtin_ia32_vpperm((vqi_t)(x), (vqi_t)(x), (vqi_t)inv - 1))
#  elif INT_SIZE == 2 || UINT_SIZE == 2
#   define swap2(x) \
    ((vec_t)__builtin_ia32_vpperm((vqi_t)(x), (vqi_t)(x), \
                                  (vqi_t)(__builtin_ia32_vprotwi(2 * (vhi_t)inv - 1, 8) | \
                                          (2 * inv - 2))))
#  elif FLOAT_SIZE == 4
#   define frac(x) __builtin_ia32_vfrczps(x)
#   undef swap2
#   define swap2(x) ({ \
    /* Buggy in gcc 7.1.0 and earlier. */ \
    /* __builtin_ia32_vpermil2ps((vec_t){}, x, __builtin_ia32_cvtps2dq(inv) + 3, 0) */ \
    vec_t t_; \
    asm ( "vpermil2ps $0, %3, %2, %1, %0" : \
          "=x" (t_) : \
          "x" ((vec_t){}), "m" (x), "x" (__builtin_ia32_cvtps2dq(inv) + 3) ); \
    t_; \
})
#  elif FLOAT_SIZE == 8
#   define frac(x) __builtin_ia32_vfrczpd(x)
#   undef swap2
#   define swap2(x) ({ \
    /* Buggy in gcc 7.1.0 and earlier. */ \
    /* __builtin_ia32_vpermil2pd((vec_t){}, x, */ \
    /*                            __builtin_ia32_pmovsxdq128( */ \
    /*                                __builtin_ia32_cvtpd2dq(inv) + 1) << 1, 0) */ \
    vdi_t s_ = __builtin_ia32_pmovsxdq128( \
                   __builtin_ia32_cvtpd2dq(inv) + 1) << 1; \
    vec_t t_; \
    asm ( "vpermil2pd $0, %3, %2, %1, %0" : \
          "=x" (t_) : "x" ((vec_t){}), "x" (x), "m" (s_) ); \
    t_; \
})
#  endif
#  if INT_SIZE == 1
#   define hadd(x, y) ((vec_t)__builtin_ia32_packsswb128(__builtin_ia32_vphaddbw((vqi_t)(x)), \
                                                         __builtin_ia32_vphaddbw((vqi_t)(y))))
#   define hsub(x, y) ((vec_t)__builtin_ia32_packsswb128(__builtin_ia32_vphsubbw((vqi_t)(x)), \
                                                         __builtin_ia32_vphsubbw((vqi_t)(y))))
#  elif UINT_SIZE == 1
#   define hadd(x, y) ((vec_t)__builtin_ia32_packuswb128(__builtin_ia32_vphaddubw((vqi_t)(x)), \
                                                         __builtin_ia32_vphaddubw((vqi_t)(y))))
#  elif INT_SIZE == 2
#   undef hadd
#   define hadd(x, y) __builtin_ia32_packssdw128(__builtin_ia32_vphaddwd(x), \
                                                 __builtin_ia32_vphaddwd(y))
#   undef hsub
#   define hsub(x, y) __builtin_ia32_packssdw128(__builtin_ia32_vphsubwd(x), \
                                                 __builtin_ia32_vphsubwd(y))
#  elif UINT_SIZE == 2
#   undef hadd
#   define hadd(x, y) ((vec_t)__builtin_ia32_packusdw128(__builtin_ia32_vphadduwd((vhi_t)(x)), \
                                                         __builtin_ia32_vphadduwd((vhi_t)(y))))
#   undef hsub
#  endif
# elif VEC_SIZE == 32
#  define select(d, x, y, m) \
    (*(d) = (vec_t)__builtin_ia32_vpcmov256((vdi_t)(x), (vdi_t)(y), (vdi_t)(m)))
#  if FLOAT_SIZE == 4
#   define frac(x) __builtin_ia32_vfrczps256(x)
#  elif FLOAT_SIZE == 8
#   define frac(x) __builtin_ia32_vfrczpd256(x)
#  endif
# elif VEC_SIZE == FLOAT_SIZE
#  if VEC_SIZE == 4
#   define frac(x) scalar_1op(x, "vfrczss %[in], %[out]")
#  elif VEC_SIZE == 8
#   define frac(x) scalar_1op(x, "vfrczsd %[in], %[out]")
#  endif
# endif
#endif

#if VEC_SIZE >= 16

# if !defined(low_half) && defined(HALF_SIZE)
static inline half_t low_half(vec_t x)
{
#  if HALF_SIZE < VEC_SIZE
    half_t y;
    unsigned int i;

    for ( i = 0; i < ELEM_COUNT / 2; ++i )
        y[i] = x[i];

    return y;
#  else
    return x;
#  endif
}
# endif

# if !defined(low_quarter) && defined(QUARTER_SIZE)
static inline quarter_t low_quarter(vec_t x)
{
#  if QUARTER_SIZE < VEC_SIZE
    quarter_t y;
    unsigned int i;

    for ( i = 0; i < ELEM_COUNT / 4; ++i )
        y[i] = x[i];

    return y;
#  else
    return x;
#  endif
}
# endif

# if !defined(low_eighth) && defined(EIGHTH_SIZE)
static inline eighth_t low_eighth(vec_t x)
{
#  if EIGHTH_SIZE < VEC_SIZE
    eighth_t y;
    unsigned int i;

    for ( i = 0; i < ELEM_COUNT / 8; ++i )
        y[i] = x[i];

    return y;
#  else
    return x;
#  endif
}
# endif

#endif

#ifdef broadcast_pair
# if ELEM_COUNT == 4
#  define broadcast_half broadcast_pair
# elif ELEM_COUNT == 8
#  define broadcast_quarter broadcast_pair
# elif ELEM_COUNT == 16
#  define broadcast_eighth broadcast_pair
# endif
#endif

#ifdef insert_pair
# if ELEM_COUNT == 4
#  define insert_half insert_pair
# elif ELEM_COUNT == 8
#  define insert_quarter insert_pair
# elif ELEM_COUNT == 16
#  define insert_eighth insert_pair
# endif
#endif

#ifdef broadcast_quartet
# if ELEM_COUNT == 8
#  define broadcast_half broadcast_quartet
# elif ELEM_COUNT == 16
#  define broadcast_quarter broadcast_quartet
# endif
#endif

#ifdef insert_quartet
# if ELEM_COUNT == 8
#  define insert_half insert_quartet
# elif ELEM_COUNT == 16
#  define insert_quarter insert_quartet
# endif
#endif

#if defined(broadcast_octet) && ELEM_COUNT == 16
# define broadcast_half broadcast_octet
#endif

#if defined(insert_octet) && ELEM_COUNT == 16
# define insert_half insert_octet
#endif

#if defined(__AVX512F__) && defined(FLOAT_SIZE)
# include "simd-fma.c"
#endif

int simd_test(void)
{
    unsigned int i, j;
    vec_t x, y, z, src, inv, alt, sh;
    vint_t interleave_lo, interleave_hi;

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

        interleave_lo[i] = ((i & 1) * ELEM_COUNT) | (i >> 1);
        interleave_hi[i] = interleave_lo[i] + (ELEM_COUNT / 2);
    }

    touch(src);
    x = src;
    touch(x);
    if ( !eq(x, src) ) return __LINE__;

    touch(src);
    y = x + src;
    touch(src);
    touch(y);
    if ( !eq(y, 2 * src) ) return __LINE__;

    touch(src);
    z = y -= src;
    touch(z);
    if ( !eq(x, z) ) return __LINE__;

#if defined(UINT_SIZE)

    touch(inv);
    x |= inv;
    touch(inv);
    y &= inv;
    touch(inv);
    z ^= inv;
    touch(inv);
    touch(x);
    if ( !eq(x & ~y, z) ) return __LINE__;

#elif ELEM_SIZE > 1 || VEC_SIZE <= 8

    touch(src);
    x *= src;
    y = inv * inv;
    touch(src);
    z = src + inv;
    touch(inv);
    z *= (src - inv);
    if ( !eq(x - y, z) ) return __LINE__;

#endif

#if defined(FLOAT_SIZE)

    x = src * alt;
    touch(alt);
    y = src / alt;
    if ( !eq(x, y) ) return __LINE__;
    touch(alt);
    touch(src);
    if ( !eq(x * -alt, -src) ) return __LINE__;

# ifdef to_int

    touch(src);
    x = to_int(src);
    touch(src);
    if ( !eq(x, src) ) return __LINE__;

#  ifdef recip
    touch(src);
    x = recip(src);
    touch(src);
    touch(x);
    if ( !eq(to_int(recip(x)), src) ) return __LINE__;

#   ifdef rsqrt
    x = src * src;
    touch(x);
    y = rsqrt(x);
    touch(y);
    if ( !eq(to_int(recip(y)), src) ) return __LINE__;
    touch(src);
    if ( !eq(to_int(y), to_int(recip(src))) ) return __LINE__;
#   endif
#  endif

# endif

# ifdef to_wint
    touch(src);
    x = to_wint(src);
    touch(src);
    if ( !eq(x, src) ) return __LINE__;
# endif

# ifdef to_uint
    touch(src);
    x = to_uint(src);
    touch(src);
    if ( !eq(x, src) ) return __LINE__;
# endif

# ifdef to_uwint
    touch(src);
    x = to_uwint(src);
    touch(src);
    if ( !eq(x, src) ) return __LINE__;
# endif

# ifdef sqrt
    x = src * src;
    touch(x);
    if ( !eq(sqrt(x), src) ) return __LINE__;
# endif

# ifdef trunc
    x = 1 / src;
    y = (vec_t){ 1 };
    touch(x);
    z = trunc(x);
    if ( !eq(y, z) ) return __LINE__;
# endif

# ifdef frac
    touch(src);
    x = frac(src);
    touch(src);
    if ( !eq(x, (vec_t){}) ) return __LINE__;

    x = 1 / (src + 1);
    touch(x);
    y = frac(x);
    touch(x);
    if ( !eq(x, y) ) return __LINE__;
# endif

# if defined(trunc) && defined(frac)
    x = src / 4;
    touch(x);
    y = trunc(x);
    touch(x);
    z = frac(x);
    touch(x);
    if ( !eq(x, y + z) ) return __LINE__;
# endif

#else

# if ELEM_SIZE > 1

    touch(inv);
    x = src * inv;
    touch(inv);
    y[ELEM_COUNT - 1] = y[0] = j = ELEM_COUNT;
    for ( i = 1; i < ELEM_COUNT / 2; ++i )
        y[ELEM_COUNT - i - 1] = y[i] = y[i - 1] + (j -= 2);
    if ( !eq(x, y) ) return __LINE__;

#  ifdef mul_hi
    touch(alt);
    x = mul_hi(src, alt);
    touch(alt);
#   ifdef INT_SIZE
    if ( !eq(x, alt < 0) ) return __LINE__;
#   else
    if ( !eq(x, (src & alt) + alt) ) return __LINE__;
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
    if ( !eq(y, z) ) return __LINE__;
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
    if ( !eq(x, y + y) ) return __LINE__;

    touch(x);
    z = x >> 2;
    touch(x);
    if ( !eq(y, z + z) ) return __LINE__;

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
    if ( !eq(x, y + y) ) return __LINE__;

    z = x >> j;
    touch(j);
    if ( !eq(y, z + z) ) return __LINE__;

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
     * Zap elements for which the shift count is zero (and the hence the
     * decrement below would yield a negative count.
     */
    z &= (sh > 0);
    touch(sh);
    x = z << sh;
    touch(sh);
    --sh;
    touch(sh);
    y = z << sh;
    if ( !eq(x, y + y) ) return __LINE__;

#  if (defined(__AVX2__) && ELEM_SIZE >= 4) || defined(__XOP__)
    touch(sh);
    x = y >> sh;
    if ( !eq(x, z) ) return __LINE__;
#  endif

# endif

#endif

#if defined(max) && defined(min)
# ifdef UINT_SIZE
    touch(inv);
    x = min(src, inv);
    touch(inv);
    y = max(src, inv);
    touch(inv);
    if ( !eq(x + y, src + inv) ) return __LINE__;
# else
    x = src * alt;
    y = inv * alt;
    touch(y);
    z = max(x, y);
    touch(y);
    y = min(x, y);
    touch(y);
    if ( !eq((y + z) * alt, src + inv) ) return __LINE__;
# endif
#endif

#ifdef abs
    x = src * alt;
    touch(x);
    if ( !eq(abs(x), src) ) return __LINE__;
#endif

#ifdef copysignz
    touch(alt);
    if ( !eq(copysignz((vec_t){} + 1, alt), alt) ) return __LINE__;
#endif

#ifdef swap
    touch(src);
    if ( !eq(swap(src), inv) ) return __LINE__;
#endif

#ifdef swap2
    touch(src);
    if ( !eq(swap2(src), inv) ) return __LINE__;
#endif

#ifdef swap3
    touch(src);
    if ( !eq(swap3(src), inv) ) return __LINE__;
    touch(src);
#endif

#ifdef broadcast
    if ( !eq(broadcast(ELEM_COUNT + 1), src + inv) ) return __LINE__;
#endif

#ifdef broadcast2
    if ( !eq(broadcast2(ELEM_COUNT + 1), src + inv) ) return __LINE__;
#endif

#if defined(broadcast_half) && defined(insert_half)
    {
        half_t aux = low_half(src);

        touch(aux);
        x = broadcast_half(aux);
        touch(aux);
        y = insert_half(src, aux, 1);
        if ( !eq(x, y) ) return __LINE__;
    }
#endif

#if defined(broadcast_quarter) && defined(insert_quarter)
    {
        quarter_t aux = low_quarter(src);

        touch(aux);
        x = broadcast_quarter(aux);
        touch(aux);
        y = insert_quarter(src, aux, 1);
        touch(aux);
        y = insert_quarter(y, aux, 2);
        touch(aux);
        y = insert_quarter(y, aux, 3);
        if ( !eq(x, y) ) return __LINE__;
    }
#endif

#if defined(broadcast_eighth) && defined(insert_eighth) && \
    /* At least gcc 7.3 "optimizes" away all insert_eighth() calls below. */ \
    __GNUC__ >= 8
    {
        eighth_t aux = low_eighth(src);

        touch(aux);
        x = broadcast_eighth(aux);
        touch(aux);
        y = insert_eighth(src, aux, 1);
        touch(aux);
        y = insert_eighth(y, aux, 2);
        touch(aux);
        y = insert_eighth(y, aux, 3);
        touch(aux);
        y = insert_eighth(y, aux, 4);
        touch(aux);
        y = insert_eighth(y, aux, 5);
        touch(aux);
        y = insert_eighth(y, aux, 6);
        touch(aux);
        y = insert_eighth(y, aux, 7);
        if ( !eq(x, y) ) return __LINE__;
    }
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
# ifdef broadcast
    if ( !eq(z, broadcast(ELEM_COUNT / 2)) ) return __LINE__;
# else
    if ( !eq(z, ELEM_COUNT / 2) ) return __LINE__;
# endif
#endif

#if defined(INT_SIZE) && defined(widen1) && defined(interleave_lo)

    x = src * alt;
    y = interleave_lo(x, alt < 0);
    touch(x);
    z = widen1(low_half(x));
    touch(x);
    if ( !eq(z, y) ) return __LINE__;

# ifdef widen2
    y = interleave_lo(alt < 0, alt < 0);
    y = interleave_lo(z, y);
    touch(x);
    z = widen2(low_quarter(x));
    touch(x);
    if ( !eq(z, y) ) return __LINE__;

#  ifdef widen3
    y = interleave_lo(alt < 0, alt < 0);
    y = interleave_lo(y, y);
    y = interleave_lo(z, y);
    touch(x);
    z = widen3(low_eighth(x));
    touch(x);
    if ( !eq(z, y) ) return __LINE__;
#  endif
# endif

#endif

#if defined(UINT_SIZE) && defined(interleave_lo)

    y = interleave_lo(src, (vec_t){});
    z = interleave_lo(y, (vec_t){});

# ifdef widen1
    touch(src);
    x = widen1(low_half(src));
    touch(src);
    if ( !eq(x, y) ) return __LINE__;
# endif

# ifdef widen2
    touch(src);
    x = widen2(low_quarter(src));
    touch(src);
    if ( !eq(x, z) ) return __LINE__;
# endif

# ifdef widen3
    touch(src);
    x = widen3(low_eighth(src));
    touch(src);
    if ( !eq(x, interleave_lo(z, (vec_t){})) ) return __LINE__;
# endif

#endif

#if defined(widen1) && defined(shrink1)
    {
        half_t aux1 = low_half(src), aux2;

        touch(aux1);
        x = widen1(aux1);
        touch(x);
        aux2 = shrink1(x);
        touch(aux2);
        for ( i = 0; i < ELEM_COUNT / 2; ++i )
            if ( aux2[i] != src[i] )
                return __LINE__;
    }
#endif

#if defined(widen2) && defined(shrink2)
    {
        quarter_t aux1 = low_quarter(src), aux2;

        touch(aux1);
        x = widen2(aux1);
        touch(x);
        aux2 = shrink2(x);
        touch(aux2);
        for ( i = 0; i < ELEM_COUNT / 4; ++i )
            if ( aux2[i] != src[i] )
                return __LINE__;
    }
#endif

#if defined(widen3) && defined(shrink3)
    {
        eighth_t aux1 = low_eighth(src), aux2;

        touch(aux1);
        x = widen3(aux1);
        touch(x);
        aux2 = shrink3(x);
        touch(aux2);
        for ( i = 0; i < ELEM_COUNT / 8; ++i )
            if ( aux2[i] != src[i] )
                return __LINE__;
    }
#endif

#ifdef dup_lo
    touch(src);
    x = dup_lo(src);
    touch(src);
    if ( !eq(x - src, (alt - 1) / 2) ) return __LINE__;
#endif

#ifdef dup_hi
    touch(src);
    x = dup_hi(src);
    touch(src);
    if ( !eq(x - src, (alt + 1) / 2) ) return __LINE__;
#endif

    for ( i = 0; i < ELEM_COUNT; ++i )
        y[i] = (i & 1 ? inv : src)[i];

#ifdef select
# ifdef UINT_SIZE
    select(&z, src, inv, alt);
# else
    select(&z, src, inv, alt > 0);
# endif
    if ( !eq(z, y) ) return __LINE__;
#endif

#ifdef select2
# ifdef UINT_SIZE
    select2(&z, src, inv, alt);
# else
    select2(&z, src, inv, alt > 0);
# endif
    if ( !eq(z, y) ) return __LINE__;
#endif

#ifdef mix
    touch(src);
    touch(inv);
    x = mix(src, inv);
    if ( !eq(x, y) ) return __LINE__;

# ifdef addsub
    touch(src);
    touch(inv);
    x = addsub(src, inv);
    touch(src);
    touch(inv);
    y = mix(src - inv, src + inv);
    if ( !eq(x, y) ) return __LINE__;
# endif
#endif

#ifdef rotr
    x = rotr(src, 1);
    y = (src & (ELEM_COUNT - 1)) + 1;
    if ( !eq(x, y) ) return __LINE__;
#endif

#ifdef dot_product
    touch(src);
    touch(inv);
    x = dot_product(src, inv);
    if ( !eq(x, (vec_t){ (ELEM_COUNT * (ELEM_COUNT + 1) *
                          (ELEM_COUNT + 2)) / 6 }) ) return __LINE__;
#endif

#ifdef hadd
# if (!defined(INT_SIZE) || INT_SIZE > 1 || ELEM_COUNT < 16) && \
     (!defined(UINT_SIZE) || UINT_SIZE > 1 || ELEM_COUNT <= 16)
    x = src;
    for ( i = ELEM_COUNT; i >>= 1; )
    {
        touch(x);
        x = hadd((vec_t){}, x);
    }
    if ( x[ELEM_COUNT - 1] != (ELEM_COUNT * (ELEM_COUNT + 1)) / 2 ) return __LINE__;
# endif

# ifdef hsub
    touch(src);
    touch(inv);
    x = hsub(src, inv);
    for ( i = ELEM_COUNT; i >>= 1; )
        x = hadd(x, (vec_t){});
    if ( !eq(x, (vec_t){}) ) return __LINE__;
# endif
#endif

#if defined(getexp) && defined(getmant)
    touch(src);
    x = getmant(src);
    touch(src);
    y = getexp(src);
    touch(src);
    for ( j = i = 0; i < ELEM_COUNT; ++i )
    {
        if ( y[i] != j ) return __LINE__;

        if ( !((i + 1) & (i + 2)) )
            ++j;

        if ( !(i & (i + 1)) && x[i] != 1 ) return __LINE__;
    }
# ifdef scale
    touch(y);
    z = scale(x, y);
    if ( !eq(src, z) ) return __LINE__;
# endif
#endif

#if (defined(__XOP__) && VEC_SIZE == 16 && (INT_SIZE == 2 || INT_SIZE == 4)) || \
    (defined(__AVX512F__) && defined(FLOAT_SIZE))
    return -fma_test();
#endif

    return 0;
}
