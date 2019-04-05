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
OVR_FP(add);
OVR_INT(add);
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
OVR_VFP(movnt);
OVR_VFP(movu);
OVR_FP(mul);
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
OVR(movntdq);
OVR(movntdqa);
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
