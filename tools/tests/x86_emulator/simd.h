#include <stdbool.h>

#if defined(__i386__) && VEC_SIZE == 16
# define ENTRY(name) \
asm ( "\t.text\n" \
      "\t.globl _start\n" \
      "_start:\n" \
      "\tpush %ebp\n" \
      "\tmov %esp,%ebp\n" \
      "\tand $~0xf,%esp\n" \
      "\tcall " #name "\n" \
      "\tleave\n" \
      "\tret" )
#else
# define ENTRY(name) \
asm ( "\t.text\n" \
      "\t.globl _start\n" \
      "_start:\n" \
      "\tjmp " #name )
#endif

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
typedef double __attribute__((vector_size(VEC_SIZE))) vdf_t;
#endif

#if ELEM_SIZE == 1
typedef vqi_t vint_t;
#elif ELEM_SIZE == 2
typedef vhi_t vint_t;
#elif ELEM_SIZE == 4
typedef vsi_t vint_t;
#elif ELEM_SIZE == 8
typedef vdi_t vint_t;
#endif

#if VEC_SIZE >= 16

# if ELEM_COUNT >= 2
#  if VEC_SIZE > 32
#   define HALF_SIZE (VEC_SIZE / 2)
#  else
#   define HALF_SIZE 16
#  endif
typedef typeof((vec_t){}[0]) __attribute__((vector_size(HALF_SIZE))) half_t;
typedef char __attribute__((vector_size(HALF_SIZE))) vqi_half_t;
typedef short __attribute__((vector_size(HALF_SIZE))) vhi_half_t;
typedef int __attribute__((vector_size(HALF_SIZE))) vsi_half_t;
typedef long long __attribute__((vector_size(HALF_SIZE))) vdi_half_t;
typedef float __attribute__((vector_size(HALF_SIZE))) vsf_half_t;
# endif

# if ELEM_COUNT >= 4
#  if VEC_SIZE > 64
#   define QUARTER_SIZE (VEC_SIZE / 4)
#  else
#   define QUARTER_SIZE 16
#  endif
typedef typeof((vec_t){}[0]) __attribute__((vector_size(QUARTER_SIZE))) quarter_t;
typedef char __attribute__((vector_size(QUARTER_SIZE))) vqi_quarter_t;
typedef short __attribute__((vector_size(QUARTER_SIZE))) vhi_quarter_t;
typedef int __attribute__((vector_size(QUARTER_SIZE))) vsi_quarter_t;
typedef long long __attribute__((vector_size(QUARTER_SIZE))) vdi_quarter_t;
# endif

# if ELEM_COUNT >= 8
#  if VEC_SIZE > 128
#   define EIGHTH_SIZE (VEC_SIZE / 8)
#  else
#   define EIGHTH_SIZE 16
#  endif
typedef typeof((vec_t){}[0]) __attribute__((vector_size(EIGHTH_SIZE))) eighth_t;
typedef char __attribute__((vector_size(EIGHTH_SIZE))) vqi_eighth_t;
typedef short __attribute__((vector_size(EIGHTH_SIZE))) vhi_eighth_t;
typedef int __attribute__((vector_size(EIGHTH_SIZE))) vsi_eighth_t;
typedef long long __attribute__((vector_size(EIGHTH_SIZE))) vdi_eighth_t;
# endif

# define DECL_PAIR(w) \
typedef w ## _t pair_t; \
typedef vsi_ ## w ## _t vsi_pair_t; \
typedef vdi_ ## w ## _t vdi_pair_t
# define DECL_QUARTET(w) \
typedef w ## _t quartet_t; \
typedef vsi_ ## w ## _t vsi_quartet_t; \
typedef vdi_ ## w ## _t vdi_quartet_t
# define DECL_OCTET(w) \
typedef w ## _t octet_t; \
typedef vsi_ ## w ## _t vsi_octet_t; \
typedef vdi_ ## w ## _t vdi_octet_t

# if ELEM_COUNT == 4
DECL_PAIR(half);
# elif ELEM_COUNT == 8
DECL_PAIR(quarter);
DECL_QUARTET(half);
# elif ELEM_COUNT == 16
DECL_PAIR(eighth);
DECL_QUARTET(quarter);
DECL_OCTET(half);
# endif

# undef DECL_OCTET
# undef DECL_QUARTET
# undef DECL_PAIR

#endif

#if VEC_SIZE == 16
# define B(n, s, a...)   __builtin_ia32_ ## n ## 128 ## s(a)
# define B_(n, s, a...)  __builtin_ia32_ ## n ##        s(a)
#elif VEC_SIZE == 32
# define B(n, s, a...)   __builtin_ia32_ ## n ## 256 ## s(a)
#elif VEC_SIZE == 64
# define B(n, s, a...)   __builtin_ia32_ ## n ## 512 ## s(a)
# define BR(n, s, a...)  __builtin_ia32_ ## n ## 512 ## s(a, 4)
#endif
#ifndef B_
# define B_ B
#endif
#ifndef BR
# define BR B
# define BR_ B_
#endif
#ifndef BR_
# define BR_ BR
#endif

#ifdef __AVX512F__

/* Sadly there are a few exceptions to the general naming rules. */
# define __builtin_ia32_broadcastf32x4_512_mask __builtin_ia32_broadcastf32x4_512
# define __builtin_ia32_broadcasti32x4_512_mask __builtin_ia32_broadcasti32x4_512
# define __builtin_ia32_exp2pd512_mask __builtin_ia32_exp2pd_mask
# define __builtin_ia32_exp2ps512_mask __builtin_ia32_exp2ps_mask
# define __builtin_ia32_insertf32x4_512_mask __builtin_ia32_insertf32x4_mask
# define __builtin_ia32_insertf32x8_512_mask __builtin_ia32_insertf32x8_mask
# define __builtin_ia32_insertf64x4_512_mask __builtin_ia32_insertf64x4_mask
# define __builtin_ia32_inserti32x4_512_mask __builtin_ia32_inserti32x4_mask
# define __builtin_ia32_inserti32x8_512_mask __builtin_ia32_inserti32x8_mask
# define __builtin_ia32_inserti64x4_512_mask __builtin_ia32_inserti64x4_mask
# define __builtin_ia32_rcp28pd512_mask __builtin_ia32_rcp28pd_mask
# define __builtin_ia32_rcp28ps512_mask __builtin_ia32_rcp28ps_mask
# define __builtin_ia32_rndscalepd_512_mask __builtin_ia32_rndscalepd_mask
# define __builtin_ia32_rndscaleps_512_mask __builtin_ia32_rndscaleps_mask
# define __builtin_ia32_rsqrt28pd512_mask __builtin_ia32_rsqrt28pd_mask
# define __builtin_ia32_rsqrt28ps512_mask __builtin_ia32_rsqrt28ps_mask
# define __builtin_ia32_shuf_f32x4_512_mask __builtin_ia32_shuf_f32x4_mask
# define __builtin_ia32_shuf_f64x2_512_mask __builtin_ia32_shuf_f64x2_mask
# define __builtin_ia32_shuf_i32x4_512_mask __builtin_ia32_shuf_i32x4_mask
# define __builtin_ia32_shuf_i64x2_512_mask __builtin_ia32_shuf_i64x2_mask

# if VEC_SIZE > ELEM_SIZE && (defined(VEC_MAX) ? VEC_MAX : VEC_SIZE) < 64
#  pragma GCC target ( "avx512vl" )
# endif

# define REN(insn, old, new)                     \
    asm ( ".macro v" #insn #old " o:vararg \n\t" \
          "v" #insn #new " \\o             \n\t" \
          ".endm" )

/*
 * The original plan was to effect use of EVEX encodings for scalar as well as
 * 128- and 256-bit insn variants by restricting the compiler to use (on 64-bit
 * only of course) XMM16-XMM31 only. All sorts of compiler errors result when
 * doing this with gcc 8.2. Therefore resort to injecting {evex} prefixes,
 * which has the benefit of also working for 32-bit. Granted, there is a lot of
 * escaping to get right here.
 */
asm ( ".macro override insn    \n\t"
      ".macro $\\insn o:vararg \n\t"
      ".purgem \\insn          \n\t"
      "{evex} \\insn \\(\\)o   \n\t"
      ".macro \\insn o:vararg  \n\t"
      "$\\insn \\(\\(\\))o     \n\t"
      ".endm                   \n\t"
      ".endm                   \n\t"
      ".macro \\insn o:vararg  \n\t"
      "$\\insn \\(\\)o         \n\t"
      ".endm                   \n\t"
      ".endm" );

# define OVR(n) asm ( "override v" #n )
# define OVR_SFP(n) OVR(n ## sd); OVR(n ## ss)

# ifdef __AVX512VL__
#  ifdef __AVX512BW__
#   define OVR_BW(n) OVR(p ## n ## b); OVR(p ## n ## w)
#  else
#   define OVR_BW(n)
#  endif
#  define OVR_DQ(n) OVR(p ## n ## d); OVR(p ## n ## q)
#  define OVR_VFP(n) OVR(n ## pd); OVR(n ## ps)
# else
#  define OVR_BW(n)
#  define OVR_DQ(n)
#  define OVR_VFP(n)
# endif

# define OVR_FMA(n, w) OVR_ ## w(n ## 132); OVR_ ## w(n ## 213); \
                       OVR_ ## w(n ## 231)
# define OVR_FP(n) OVR_VFP(n); OVR_SFP(n)
# define OVR_INT(n) OVR_BW(n); OVR_DQ(n)

OVR_INT(broadcast);
OVR_SFP(broadcast);
OVR_SFP(comi);
OVR_VFP(cvtdq2);
OVR_INT(abs);
OVR_FP(add);
OVR_INT(add);
OVR_BW(adds);
OVR_BW(addus);
OVR_BW(avg);
OVR_FP(div);
OVR(extractps);
OVR_FMA(fmadd, FP);
OVR_FMA(fmaddsub, VFP);
OVR_FMA(fmsub, FP);
OVR_FMA(fmsubadd, VFP);
OVR_FMA(fnmadd, FP);
OVR_FMA(fnmsub, FP);
OVR(insertps);
OVR_FP(max);
OVR_INT(maxs);
OVR_INT(maxu);
OVR_FP(min);
OVR_INT(mins);
OVR_INT(minu);
OVR(movd);
OVR(movq);
OVR_SFP(mov);
OVR_VFP(mova);
OVR(movhlps);
OVR(movhpd);
OVR(movhps);
OVR(movlhps);
OVR(movlpd);
OVR(movlps);
OVR_VFP(movnt);
OVR_VFP(movu);
OVR_FP(mul);
OVR_VFP(perm);
OVR_VFP(permil);
OVR_VFP(shuf);
OVR_INT(sll);
OVR_DQ(sllv);
OVR_FP(sqrt);
OVR_INT(sra);
OVR_DQ(srav);
OVR_INT(srl);
OVR_DQ(srlv);
OVR_FP(sub);
OVR_INT(sub);
OVR_BW(subs);
OVR_BW(subus);
OVR_SFP(ucomi);
OVR_VFP(unpckh);
OVR_VFP(unpckl);

# ifdef __AVX512VL__
#  if ELEM_SIZE == 8 && defined(__AVX512DQ__)
REN(extract, f128, f64x2);
REN(extract, i128, i64x2);
REN(insert, f128, f64x2);
REN(insert, i128, i64x2);
#  else
REN(extract, f128, f32x4);
REN(extract, i128, i32x4);
REN(insert, f128, f32x4);
REN(insert, i128, i32x4);
#  endif
#  if ELEM_SIZE == 8
REN(movdqa, , 64);
REN(movdqu, , 64);
REN(pand, , q);
REN(pandn, , q);
REN(por, , q);
REN(pxor, , q);
#  else
#   if ELEM_SIZE == 1 && defined(__AVX512BW__)
REN(movdq, a, u8);
REN(movdqu, , 8);
#   elif ELEM_SIZE == 2 && defined(__AVX512BW__)
REN(movdq, a, u16);
REN(movdqu, , 16);
#   else
REN(movdqa, , 32);
REN(movdqu, , 32);
#   endif
REN(pand, , d);
REN(pandn, , d);
REN(por, , d);
REN(pxor, , d);
#  endif
OVR(aesdec);
OVR(aesdeclast);
OVR(aesenc);
OVR(aesenclast);
OVR(cvtpd2dqx);
OVR(cvtpd2dqy);
OVR(cvtpd2psx);
OVR(cvtpd2psy);
OVR(cvtph2ps);
OVR(cvtps2dq);
OVR(cvtps2pd);
OVR(cvtps2ph);
OVR(cvtsd2ss);
OVR(cvtsd2si);
OVR(cvtsd2sil);
OVR(cvtsd2siq);
OVR(cvtsi2sd);
OVR(cvtsi2sdl);
OVR(cvtsi2sdq);
OVR(cvtsi2ss);
OVR(cvtsi2ssl);
OVR(cvtsi2ssq);
OVR(cvtss2sd);
OVR(cvtss2si);
OVR(cvtss2sil);
OVR(cvtss2siq);
OVR(cvttpd2dqx);
OVR(cvttpd2dqy);
OVR(cvttps2dq);
OVR(cvttsd2si);
OVR(cvttsd2sil);
OVR(cvttsd2siq);
OVR(cvttss2si);
OVR(cvttss2sil);
OVR(cvttss2siq);
OVR(gf2p8mulb);
OVR(movddup);
OVR(movntdq);
OVR(movntdqa);
OVR(movshdup);
OVR(movsldup);
OVR(pclmulqdq);
OVR(permd);
OVR(permq);
OVR(pmovsxbd);
OVR(pmovsxbq);
OVR(pmovsxdq);
OVR(pmovsxwd);
OVR(pmovsxwq);
OVR(pmovzxbd);
OVR(pmovzxbq);
OVR(pmovzxdq);
OVR(pmovzxwd);
OVR(pmovzxwq);
OVR(pmulld);
OVR(pmuldq);
OVR(pmuludq);
OVR(pshufd);
OVR(punpckhdq);
OVR(punpckhqdq);
OVR(punpckldq);
OVR(punpcklqdq);
# endif

# ifdef __AVX512BW__
OVR(pextrb);
OVR(pextrw);
OVR(pinsrb);
OVR(pinsrw);
#  ifdef __AVX512VL__
OVR(packssdw);
OVR(packsswb);
OVR(packusdw);
OVR(packuswb);
OVR(palignr);
OVR(pmaddubsw);
OVR(pmaddwd);
OVR(pmovsxbw);
OVR(pmovzxbw);
OVR(pmulhrsw);
OVR(pmulhuw);
OVR(pmulhw);
OVR(pmullw);
OVR(psadbw);
OVR(pshufb);
OVR(pshufhw);
OVR(pshuflw);
OVR(pslldq);
OVR(psrldq);
OVR(punpckhbw);
OVR(punpckhwd);
OVR(punpcklbw);
OVR(punpcklwd);
#  endif
# endif

# ifdef __AVX512DQ__
OVR_VFP(and);
OVR_VFP(andn);
OVR_VFP(or);
OVR(pextrd);
OVR(pextrq);
OVR(pinsrd);
OVR(pinsrq);
#  ifdef __AVX512VL__
OVR(pmullq);
#  endif
OVR_VFP(xor);
# endif

# undef OVR_VFP
# undef OVR_SFP
# undef OVR_INT
# undef OVR_FP
# undef OVR_FMA
# undef OVR_DQ
# undef OVR_BW
# undef OVR

#endif /* __AVX512F__ */

/*
 * Suppress value propagation by the compiler, preventing unwanted
 * optimization. This at once makes the compiler use memory operands
 * more often, which for our purposes is the more interesting case.
 */
#define touch(var) asm volatile ( "" : "+m" (var) )

static inline vec_t undef(void)
{
    vec_t v = v;
    return v;
}
