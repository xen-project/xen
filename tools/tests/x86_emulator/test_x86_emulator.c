#include "x86-emulate.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>

asm ( ".pushsection .test, \"ax\", @progbits; .popsection" );

#include "blowfish.h"
#include "3dnow.h"
#include "sse.h"
#include "sse2.h"
#include "sse2-gf.h"
#include "ssse3-aes.h"
#include "ssse3-pclmul.h"
#include "sse4.h"
#include "sse4-sha.h"
#include "avx.h"
#include "avx-aes.h"
#include "avx-pclmul.h"
#include "avx-sha.h"
#include "fma4.h"
#include "fma.h"
#include "avx2.h"
#include "avx2-sg.h"
#include "avx2-vaes.h"
#include "avx2-vpclmulqdq.h"
#include "avx2-gf.h"
#include "xop.h"
#include "avx512f-opmask.h"
#include "avx512dq-opmask.h"
#include "avx512bw-opmask.h"
#include "avx512f.h"
#include "avx512f-sg.h"
#include "avx512f-sha.h"
#include "avx512vl-sg.h"
#include "avx512bw.h"
#include "avx512bw-vaes.h"
#include "avx512bw-vpclmulqdq.h"
#include "avx512bw-gf.h"
#include "avx512dq.h"
#include "avx512er.h"
#include "avx512vbmi.h"
#include "avx512vbmi2-vpclmulqdq.h"

#define verbose false /* Switch to true for far more logging. */

static void blowfish_set_regs(struct cpu_user_regs *regs)
{
    regs->eax = 2;
    regs->edx = 1;
}

static bool blowfish_check_regs(const struct cpu_user_regs *regs)
{
    return regs->eax == 2 && regs->edx == 1;
}

static bool simd_check__3dnow(void)
{
    return cpu_has_3dnow_ext && cpu_has_sse;
}

static bool simd_check_sse(void)
{
    return cpu_has_sse;
}

static bool simd_check_sse2(void)
{
    return cpu_has_sse2;
}

static bool simd_check_sse4(void)
{
    return cpu_has_sse4_2;
}

static bool simd_check_avx(void)
{
    return cpu_has_avx;
}

static bool simd_check_fma4(void)
{
    return cpu_has_fma4;
}

static bool simd_check_fma(void)
{
    return cpu_has_fma;
}

static bool simd_check_avx2(void)
{
    return cpu_has_avx2;
}
#define simd_check_avx2_sg simd_check_avx2

static bool simd_check_xop(void)
{
    return cpu_has_xop;
}

static bool simd_check_ssse3_aes(void)
{
    return cpu_has_aesni && cpu_has_ssse3;
}

static bool simd_check_avx_aes(void)
{
    return cpu_has_aesni && cpu_has_avx;
}

static bool simd_check_ssse3_pclmul(void)
{
    return cpu_has_pclmulqdq && cpu_has_ssse3;
}

static bool simd_check_avx_pclmul(void)
{
    return cpu_has_pclmulqdq && cpu_has_avx;
}

static bool simd_check_avx512f(void)
{
    return cpu_has_avx512f;
}
#define simd_check_avx512f_opmask simd_check_avx512f
#define simd_check_avx512f_sg simd_check_avx512f

static bool simd_check_avx512f_vl(void)
{
    return cpu_has_avx512f && cpu_has_avx512vl;
}
#define simd_check_avx512vl_sg simd_check_avx512f_vl

static bool simd_check_avx512dq(void)
{
    return cpu_has_avx512dq;
}
#define simd_check_avx512dq_opmask simd_check_avx512dq

static bool simd_check_avx512dq_vl(void)
{
    return cpu_has_avx512dq && cpu_has_avx512vl;
}

static bool simd_check_avx512er(void)
{
    return cpu_has_avx512er;
}

static bool simd_check_avx512bw(void)
{
    return cpu_has_avx512bw;
}
#define simd_check_avx512bw_opmask simd_check_avx512bw

static bool simd_check_avx512bw_vl(void)
{
    return cpu_has_avx512bw && cpu_has_avx512vl;
}

static bool simd_check_avx512vbmi(void)
{
    return cpu_has_avx512_vbmi;
}

static bool simd_check_avx512vbmi_vl(void)
{
    return cpu_has_avx512_vbmi && cpu_has_avx512vl;
}

static bool simd_check_sse4_sha(void)
{
    return cpu_has_sha && cpu_has_sse4_2;
}

static bool simd_check_avx_sha(void)
{
    return cpu_has_sha && cpu_has_avx;
}

static bool simd_check_avx512f_sha_vl(void)
{
    return cpu_has_sha && cpu_has_avx512vl;
}

static bool simd_check_avx2_vaes(void)
{
    return cpu_has_aesni && cpu_has_vaes && cpu_has_avx2;
}

static bool simd_check_avx512bw_vaes(void)
{
    return cpu_has_aesni && cpu_has_vaes && cpu_has_avx512bw;
}

static bool simd_check_avx512bw_vaes_vl(void)
{
    return cpu_has_aesni && cpu_has_vaes &&
           cpu_has_avx512bw && cpu_has_avx512vl;
}

static bool simd_check_avx2_vpclmulqdq(void)
{
    return cpu_has_vpclmulqdq && cpu_has_avx2;
}

static bool simd_check_avx512bw_vpclmulqdq(void)
{
    return cpu_has_vpclmulqdq && cpu_has_avx512bw;
}

static bool simd_check_avx512bw_vpclmulqdq_vl(void)
{
    return cpu_has_vpclmulqdq && cpu_has_avx512bw && cpu_has_avx512vl;
}

static bool simd_check_avx512vbmi2_vpclmulqdq(void)
{
    return cpu_has_avx512_vbmi2 && simd_check_avx512bw_vpclmulqdq();
}

static bool simd_check_avx512vbmi2_vpclmulqdq_vl(void)
{
    return cpu_has_avx512_vbmi2 && simd_check_avx512bw_vpclmulqdq_vl();
}

static bool simd_check_sse2_gf(void)
{
    return cpu_has_gfni && cpu_has_sse2;
}

static bool simd_check_avx2_gf(void)
{
    return cpu_has_gfni && cpu_has_avx2;
}

static bool simd_check_avx512bw_gf(void)
{
    return cpu_has_gfni && cpu_has_avx512bw;
}

static bool simd_check_avx512bw_gf_vl(void)
{
    return cpu_has_gfni && cpu_has_avx512vl;
}

static void simd_set_regs(struct cpu_user_regs *regs)
{
    if ( cpu_has_mmx )
        asm volatile ( "emms" );
}

static bool simd_check_regs(const struct cpu_user_regs *regs)
{
    if ( !regs->eax )
        return true;
    printf("[line %u] ", (unsigned int)regs->eax);
    return false;
}

static const struct {
    const void *code;
    size_t size;
    unsigned int bitness;
    const char*name;
    bool (*check_cpu)(void);
    void (*set_regs)(struct cpu_user_regs *);
    bool (*check_regs)(const struct cpu_user_regs *);
} blobs[] = {
#define BLOWFISH(bits, desc, tag)                   \
    { .code = blowfish_x86_ ## bits ## tag,         \
      .size = sizeof(blowfish_x86_ ## bits ## tag), \
      .bitness = bits, .name = #desc,               \
      .set_regs = blowfish_set_regs,                \
      .check_regs = blowfish_check_regs }
#ifdef __x86_64__
    BLOWFISH(64, blowfish, ),
#endif
    BLOWFISH(32, blowfish, ),
    BLOWFISH(32, blowfish (push), _mno_accumulate_outgoing_args),
#undef BLOWFISH
#define SIMD_(bits, desc, feat, form)                               \
    { .code = feat ## _x86_ ## bits ## _D ## _ ## form,             \
      .size = sizeof(feat ## _x86_ ## bits ## _D ## _ ## form),     \
      .bitness = bits, .name = #desc,                               \
      .check_cpu = simd_check_ ## feat,                             \
      .set_regs = simd_set_regs,                                    \
      .check_regs = simd_check_regs }
#define AVX512VL_(bits, desc, feat, form)                          \
    { .code = feat ## _x86_ ## bits ## _D ## _ ## form,            \
      .size = sizeof(feat ## _x86_ ## bits ## _D ## _ ## form),    \
      .bitness = bits, .name = "AVX512" #desc,                     \
      .check_cpu = simd_check_ ## feat ## _vl,                     \
      .set_regs = simd_set_regs,                                   \
      .check_regs = simd_check_regs }
#ifdef __x86_64__
# define SIMD(desc, feat, form) SIMD_(64, desc, feat, form), \
                                SIMD_(32, desc, feat, form)
# define AVX512VL(desc, feat, form) AVX512VL_(64, desc, feat, form), \
                                    AVX512VL_(32, desc, feat, form)
#else
# define SIMD(desc, feat, form) SIMD_(32, desc, feat, form)
# define AVX512VL(desc, feat, form) AVX512VL_(32, desc, feat, form)
#endif
    SIMD(3DNow! single,          _3dnow,     8f4),
    SIMD(SSE scalar single,      sse,         f4),
    SIMD(SSE packed single,      sse,       16f4),
    SIMD(SSE2 scalar single,     sse2,        f4),
    SIMD(SSE2 packed single,     sse2,      16f4),
    SIMD(SSE2 scalar double,     sse2,        f8),
    SIMD(SSE2 packed double,     sse2,      16f8),
    SIMD(SSE2 packed s8,         sse2,      16i1),
    SIMD(SSE2 packed u8,         sse2,      16u1),
    SIMD(SSE2 packed s16,        sse2,      16i2),
    SIMD(SSE2 packed u16,        sse2,      16u2),
    SIMD(SSE2 packed s32,        sse2,      16i4),
    SIMD(SSE2 packed u32,        sse2,      16u4),
    SIMD(SSE2 packed s64,        sse2,      16i8),
    SIMD(SSE2 packed u64,        sse2,      16u8),
    SIMD(SSE4 scalar single,     sse4,        f4),
    SIMD(SSE4 packed single,     sse4,      16f4),
    SIMD(SSE4 scalar double,     sse4,        f8),
    SIMD(SSE4 packed double,     sse4,      16f8),
    SIMD(SSE4 packed s8,         sse4,      16i1),
    SIMD(SSE4 packed u8,         sse4,      16u1),
    SIMD(SSE4 packed s16,        sse4,      16i2),
    SIMD(SSE4 packed u16,        sse4,      16u2),
    SIMD(SSE4 packed s32,        sse4,      16i4),
    SIMD(SSE4 packed u32,        sse4,      16u4),
    SIMD(SSE4 packed s64,        sse4,      16i8),
    SIMD(SSE4 packed u64,        sse4,      16u8),
    SIMD(AVX scalar single,      avx,         f4),
    SIMD(AVX 128bit single,      avx,       16f4),
    SIMD(AVX 256bit single,      avx,       32f4),
    SIMD(AVX scalar double,      avx,         f8),
    SIMD(AVX 128bit double,      avx,       16f8),
    SIMD(AVX 256bit double,      avx,       32f8),
    SIMD(FMA4 scalar single,     fma4,        f4),
    SIMD(FMA4 128bit single,     fma4,      16f4),
    SIMD(FMA4 256bit single,     fma4,      32f4),
    SIMD(FMA4 scalar double,     fma4,        f8),
    SIMD(FMA4 128bit double,     fma4,      16f8),
    SIMD(FMA4 256bit double,     fma4,      32f8),
    SIMD(FMA scalar single,      fma,         f4),
    SIMD(FMA 128bit single,      fma,       16f4),
    SIMD(FMA 256bit single,      fma,       32f4),
    SIMD(FMA scalar double,      fma,         f8),
    SIMD(FMA 128bit double,      fma,       16f8),
    SIMD(FMA 256bit double,      fma,       32f8),
    SIMD(AVX2 128bit single,     avx2,      16f4),
    SIMD(AVX2 256bit single,     avx2,      32f4),
    SIMD(AVX2 128bit double,     avx2,      16f8),
    SIMD(AVX2 256bit double,     avx2,      32f8),
    SIMD(AVX2 s8x16,             avx2,      16i1),
    SIMD(AVX2 u8x16,             avx2,      16u1),
    SIMD(AVX2 s16x8,             avx2,      16i2),
    SIMD(AVX2 u16x8,             avx2,      16u2),
    SIMD(AVX2 s32x4,             avx2,      16i4),
    SIMD(AVX2 u32x4,             avx2,      16u4),
    SIMD(AVX2 s64x2,             avx2,      16i8),
    SIMD(AVX2 u64x2,             avx2,      16u8),
    SIMD(AVX2 s8x32,             avx2,      32i1),
    SIMD(AVX2 u8x32,             avx2,      32u1),
    SIMD(AVX2 s16x16,            avx2,      32i2),
    SIMD(AVX2 u16x16,            avx2,      32u2),
    SIMD(AVX2 s32x8,             avx2,      32i4),
    SIMD(AVX2 u32x8,             avx2,      32u4),
    SIMD(AVX2 s64x4,             avx2,      32i8),
    SIMD(AVX2 u64x4,             avx2,      32u8),
    SIMD(AVX2 S/G f32[4x32],  avx2_sg,    16x4f4),
    SIMD(AVX2 S/G f64[2x32],  avx2_sg,    16x4f8),
    SIMD(AVX2 S/G f32[2x64],  avx2_sg,    16x8f4),
    SIMD(AVX2 S/G f64[2x64],  avx2_sg,    16x8f8),
    SIMD(AVX2 S/G f32[8x32],  avx2_sg,    32x4f4),
    SIMD(AVX2 S/G f64[4x32],  avx2_sg,    32x4f8),
    SIMD(AVX2 S/G f32[4x64],  avx2_sg,    32x8f4),
    SIMD(AVX2 S/G f64[4x64],  avx2_sg,    32x8f8),
    SIMD(AVX2 S/G i32[4x32],  avx2_sg,    16x4i4),
    SIMD(AVX2 S/G i64[2x32],  avx2_sg,    16x4i8),
    SIMD(AVX2 S/G i32[2x64],  avx2_sg,    16x8i4),
    SIMD(AVX2 S/G i64[2x64],  avx2_sg,    16x8i8),
    SIMD(AVX2 S/G i32[8x32],  avx2_sg,    32x4i4),
    SIMD(AVX2 S/G i64[4x32],  avx2_sg,    32x4i8),
    SIMD(AVX2 S/G i32[4x64],  avx2_sg,    32x8i4),
    SIMD(AVX2 S/G i64[4x64],  avx2_sg,    32x8i8),
#ifdef __x86_64__
    SIMD_(64, AVX2 S/G %ymm8+, avx2_sg,     high),
#endif
    SIMD(XOP 128bit single,       xop,      16f4),
    SIMD(XOP 256bit single,       xop,      32f4),
    SIMD(XOP 128bit double,       xop,      16f8),
    SIMD(XOP 256bit double,       xop,      32f8),
    SIMD(XOP s8x16,               xop,      16i1),
    SIMD(XOP u8x16,               xop,      16u1),
    SIMD(XOP s16x8,               xop,      16i2),
    SIMD(XOP u16x8,               xop,      16u2),
    SIMD(XOP s32x4,               xop,      16i4),
    SIMD(XOP u32x4,               xop,      16u4),
    SIMD(XOP s64x2,               xop,      16i8),
    SIMD(XOP u64x2,               xop,      16u8),
    SIMD(XOP i8x32,               xop,      32i1),
    SIMD(XOP i16x16,              xop,      32i2),
    SIMD(XOP i32x8,               xop,      32i4),
    SIMD(XOP i64x4,               xop,      32i8),
    SIMD(AES (legacy),      ssse3_aes,        16),
    SIMD(AES (VEX/x16),       avx_aes,        16),
    SIMD(PCLMUL (legacy), ssse3_pclmul,       16),
    SIMD(PCLMUL (VEX/x2),  avx_pclmul,        16),
    SIMD(OPMASK/w,     avx512f_opmask,         2),
    SIMD(OPMASK+DQ/b, avx512dq_opmask,         1),
    SIMD(OPMASK+DQ/w, avx512dq_opmask,         2),
    SIMD(OPMASK+BW/d, avx512bw_opmask,         4),
    SIMD(OPMASK+BW/q, avx512bw_opmask,         8),
    SIMD(AVX512F f32 scalar,  avx512f,        f4),
    SIMD(AVX512F f32x16,      avx512f,      64f4),
    SIMD(AVX512F f64 scalar,  avx512f,        f8),
    SIMD(AVX512F f64x8,       avx512f,      64f8),
    SIMD(AVX512F s32x16,      avx512f,      64i4),
    SIMD(AVX512F u32x16,      avx512f,      64u4),
    SIMD(AVX512F s64x8,       avx512f,      64i8),
    SIMD(AVX512F u64x8,       avx512f,      64u8),
    SIMD(AVX512F S/G f32[16x32], avx512f_sg, 64x4f4),
    SIMD(AVX512F S/G f64[ 8x32], avx512f_sg, 64x4f8),
    SIMD(AVX512F S/G f32[ 8x64], avx512f_sg, 64x8f4),
    SIMD(AVX512F S/G f64[ 8x64], avx512f_sg, 64x8f8),
    SIMD(AVX512F S/G i32[16x32], avx512f_sg, 64x4i4),
    SIMD(AVX512F S/G i64[ 8x32], avx512f_sg, 64x4i8),
    SIMD(AVX512F S/G i32[ 8x64], avx512f_sg, 64x8i4),
    SIMD(AVX512F S/G i64[ 8x64], avx512f_sg, 64x8i8),
#ifdef __x86_64__
    SIMD_(64, AVX512F S/G %zmm8+, avx512f_sg, higher),
    SIMD_(64, AVX512F S/G %zmm16+, avx512f_sg, highest),
#endif
    AVX512VL(VL f32x4,        avx512f,      16f4),
    AVX512VL(VL f64x2,        avx512f,      16f8),
    AVX512VL(VL f32x8,        avx512f,      32f4),
    AVX512VL(VL f64x4,        avx512f,      32f8),
    AVX512VL(VL s32x4,        avx512f,      16i4),
    AVX512VL(VL u32x4,        avx512f,      16u4),
    AVX512VL(VL s32x8,        avx512f,      32i4),
    AVX512VL(VL u32x8,        avx512f,      32u4),
    AVX512VL(VL s64x2,        avx512f,      16i8),
    AVX512VL(VL u64x2,        avx512f,      16u8),
    AVX512VL(VL s64x4,        avx512f,      32i8),
    AVX512VL(VL u64x4,        avx512f,      32u8),
    SIMD(AVX512VL S/G f32[4x32], avx512vl_sg, 16x4f4),
    SIMD(AVX512VL S/G f64[2x32], avx512vl_sg, 16x4f8),
    SIMD(AVX512VL S/G f32[2x64], avx512vl_sg, 16x8f4),
    SIMD(AVX512VL S/G f64[2x64], avx512vl_sg, 16x8f8),
    SIMD(AVX512VL S/G f32[8x32], avx512vl_sg, 32x4f4),
    SIMD(AVX512VL S/G f64[4x32], avx512vl_sg, 32x4f8),
    SIMD(AVX512VL S/G f32[4x64], avx512vl_sg, 32x8f4),
    SIMD(AVX512VL S/G f64[4x64], avx512vl_sg, 32x8f8),
    SIMD(AVX512VL S/G i32[4x32], avx512vl_sg, 16x4i4),
    SIMD(AVX512VL S/G i64[2x32], avx512vl_sg, 16x4i8),
    SIMD(AVX512VL S/G i32[2x64], avx512vl_sg, 16x8i4),
    SIMD(AVX512VL S/G i64[2x64], avx512vl_sg, 16x8i8),
    SIMD(AVX512VL S/G i32[8x32], avx512vl_sg, 32x4i4),
    SIMD(AVX512VL S/G i64[4x32], avx512vl_sg, 32x4i8),
    SIMD(AVX512VL S/G i32[4x64], avx512vl_sg, 32x8i4),
    SIMD(AVX512VL S/G i64[4x64], avx512vl_sg, 32x8i8),
    SIMD(AVX512BW s8x64,     avx512bw,      64i1),
    SIMD(AVX512BW u8x64,     avx512bw,      64u1),
    SIMD(AVX512BW s16x32,    avx512bw,      64i2),
    SIMD(AVX512BW u16x32,    avx512bw,      64u2),
    AVX512VL(BW+VL s8x16,    avx512bw,      16i1),
    AVX512VL(BW+VL u8x16,    avx512bw,      16u1),
    AVX512VL(BW+VL s8x32,    avx512bw,      32i1),
    AVX512VL(BW+VL u8x32,    avx512bw,      32u1),
    AVX512VL(BW+VL s16x8,    avx512bw,      16i2),
    AVX512VL(BW+VL u16x8,    avx512bw,      16u2),
    AVX512VL(BW+VL s16x16,   avx512bw,      32i2),
    AVX512VL(BW+VL u16x16,   avx512bw,      32u2),
    SIMD(AVX512DQ f32x16,    avx512dq,      64f4),
    SIMD(AVX512DQ f64x8,     avx512dq,      64f8),
    SIMD(AVX512DQ s32x16,    avx512dq,      64i4),
    SIMD(AVX512DQ u32x16,    avx512dq,      64u4),
    SIMD(AVX512DQ s64x8,     avx512dq,      64i8),
    SIMD(AVX512DQ u64x8,     avx512dq,      64u8),
    AVX512VL(DQ+VL f32x4,    avx512dq,      16f4),
    AVX512VL(DQ+VL f64x2,    avx512dq,      16f8),
    AVX512VL(DQ+VL f32x8,    avx512dq,      32f4),
    AVX512VL(DQ+VL f64x4,    avx512dq,      32f8),
    AVX512VL(DQ+VL s32x4,    avx512dq,      16i4),
    AVX512VL(DQ+VL u32x4,    avx512dq,      16u4),
    AVX512VL(DQ+VL s32x8,    avx512dq,      32i4),
    AVX512VL(DQ+VL u32x8,    avx512dq,      32u4),
    AVX512VL(DQ+VL s64x2,    avx512dq,      16i8),
    AVX512VL(DQ+VL u64x2,    avx512dq,      16u8),
    AVX512VL(DQ+VL s64x4,    avx512dq,      32i8),
    AVX512VL(DQ+VL u64x4,    avx512dq,      32u8),
    SIMD(AVX512ER f32 scalar,avx512er,        f4),
    SIMD(AVX512ER f32x16,    avx512er,      64f4),
    SIMD(AVX512ER f64 scalar,avx512er,        f8),
    SIMD(AVX512ER f64x8,     avx512er,      64f8),
    SIMD(AVX512_VBMI s8x64,  avx512vbmi,    64i1),
    SIMD(AVX512_VBMI u8x64,  avx512vbmi,    64u1),
    SIMD(AVX512_VBMI s16x32, avx512vbmi,    64i2),
    SIMD(AVX512_VBMI u16x32, avx512vbmi,    64u2),
    AVX512VL(_VBMI+VL s8x16, avx512vbmi,    16i1),
    AVX512VL(_VBMI+VL u8x16, avx512vbmi,    16u1),
    AVX512VL(_VBMI+VL s8x32, avx512vbmi,    32i1),
    AVX512VL(_VBMI+VL u8x32, avx512vbmi,    32u1),
    AVX512VL(_VBMI+VL s16x8, avx512vbmi,    16i2),
    AVX512VL(_VBMI+VL u16x8, avx512vbmi,    16u2),
    AVX512VL(_VBMI+VL s16x16, avx512vbmi,   32i2),
    AVX512VL(_VBMI+VL u16x16, avx512vbmi,   32u2),
    SIMD(SHA,                sse4_sha,        16),
    SIMD(AVX+SHA,             avx_sha,        16),
    AVX512VL(VL+SHA,      avx512f_sha,        16),
    SIMD(VAES (VEX/x32),    avx2_vaes,        32),
    SIMD(VAES (EVEX/x64), avx512bw_vaes,      64),
    AVX512VL(VL+VAES (x16), avx512bw_vaes,    16),
    AVX512VL(VL+VAES (x32), avx512bw_vaes,    32),
    SIMD(VPCLMUL (VEX/x4), avx2_vpclmulqdq,  32),
    SIMD(VPCLMUL (EVEX/x8), avx512bw_vpclmulqdq, 64),
    AVX512VL(VL+VPCLMUL (x4), avx512bw_vpclmulqdq, 16),
    AVX512VL(VL+VPCLMUL (x8), avx512bw_vpclmulqdq, 32),
    SIMD(AVX512_VBMI2+VPCLMUL (x8), avx512vbmi2_vpclmulqdq, 64),
    AVX512VL(_VBMI2+VL+VPCLMUL (x2), avx512vbmi2_vpclmulqdq, 16),
    AVX512VL(_VBMI2+VL+VPCLMUL (x4), avx512vbmi2_vpclmulqdq, 32),
    SIMD(GFNI (legacy),       sse2_gf,        16),
    SIMD(GFNI (VEX/x16),      avx2_gf,        16),
    SIMD(GFNI (VEX/x32),      avx2_gf,        32),
    SIMD(GFNI (EVEX/x64), avx512bw_gf,        64),
    AVX512VL(VL+GFNI (x16), avx512bw_gf,      16),
    AVX512VL(VL+GFNI (x32), avx512bw_gf,      32),
#undef AVX512VL_
#undef AVX512VL
#undef SIMD_
#undef SIMD
};

static unsigned int bytes_read;

static int read(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    switch ( seg )
    {
        uint64_t value;

    case x86_seg_gdtr:
        /* Fake system segment type matching table index. */
        if ( (offset & 7) || (bytes > 8) )
            return X86EMUL_UNHANDLEABLE;
#ifdef __x86_64__
        if ( !(offset & 8) )
        {
            memset(p_data, 0, bytes);
            return X86EMUL_OKAY;
        }
        value = (offset - 8) >> 4;
#else
        value = (offset - 8) >> 3;
#endif
        if ( value >= 0x10 )
            return X86EMUL_UNHANDLEABLE;
        value |= value << 40;
        memcpy(p_data, &value, bytes);
        return X86EMUL_OKAY;

    case x86_seg_ldtr:
        /* Fake user segment type matching table index. */
        if ( (offset & 7) || (bytes > 8) )
            return X86EMUL_UNHANDLEABLE;
        value = offset >> 3;
        if ( value >= 0x10 )
            return X86EMUL_UNHANDLEABLE;
        value |= (value | 0x10) << 40;
        memcpy(p_data, &value, bytes);
        return X86EMUL_OKAY;

    default:
        if ( !is_x86_user_segment(seg) )
            return X86EMUL_UNHANDLEABLE;
        bytes_read += bytes;
        break;
    }
    memcpy(p_data, (void *)offset, bytes);
    return X86EMUL_OKAY;
}

static int fetch(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    memcpy(p_data, (void *)offset, bytes);
    return X86EMUL_OKAY;
}

static int write(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
    memcpy((void *)offset, p_data, bytes);
    return X86EMUL_OKAY;
}

static int rmw(
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    return x86_emul_rmw((void *)offset, bytes, eflags, state, ctxt);
}

static int cmpxchg(
    enum x86_segment seg,
    unsigned long offset,
    void *old,
    void *new,
    unsigned int bytes,
    bool lock,
    struct x86_emulate_ctxt *ctxt)
{
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
    memcpy((void *)offset, new, bytes);
    return X86EMUL_OKAY;
}

static int blk(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    return x86_emul_blk((void *)offset, p_data, bytes, eflags, state, ctxt);
}

static int read_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
    memset(reg, 0, sizeof(*reg));
    reg->p = 1;
    return X86EMUL_OKAY;
}

static int read_msr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0xc0000080: /* EFER */
        *val = ctxt->addr_size > 32 ? 0x500 /* LME|LMA */ : 0;
        return X86EMUL_OKAY;

    case 0xc0000103: /* TSC_AUX */
#define TSC_AUX_VALUE 0xCACACACA
        *val = TSC_AUX_VALUE;
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

#define INVPCID_ADDR 0x12345678
#define INVPCID_PCID 0x123

static int read_cr_invpcid(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    int rc = emul_test_read_cr(reg, val, ctxt);

    if ( rc == X86EMUL_OKAY && reg == 4 )
        *val |= X86_CR4_PCIDE;

    return rc;
}

static int tlb_op_invpcid(
    enum x86emul_tlb_op op,
    unsigned long addr,
    unsigned long aux,
    struct x86_emulate_ctxt *ctxt)
{
    static unsigned int seq;

    if ( op != x86emul_invpcid || addr != INVPCID_ADDR ||
         x86emul_invpcid_pcid(aux) != (seq < 4 ? 0 : INVPCID_PCID) ||
         x86emul_invpcid_type(aux) != (seq++ & 3) )
        return X86EMUL_UNHANDLEABLE;

    return X86EMUL_OKAY;
}

static struct x86_emulate_ops emulops = {
    .read       = read,
    .insn_fetch = fetch,
    .write      = write,
    .cmpxchg    = cmpxchg,
    .blk        = blk,
    .read_segment = read_segment,
    .cpuid      = emul_test_cpuid,
    .read_cr    = emul_test_read_cr,
    .read_xcr   = emul_test_read_xcr,
    .read_msr   = read_msr,
    .get_fpu    = emul_test_get_fpu,
    .put_fpu    = emul_test_put_fpu,
};

#define EFLAGS_ALWAYS_SET (X86_EFLAGS_IF | X86_EFLAGS_MBS)
#define EFLAGS_MASK (X86_EFLAGS_ARITH_MASK | EFLAGS_ALWAYS_SET)

#define MMAP_ADDR 0x100000

/*
 * 64-bit OSes may not (be able to) properly restore the two selectors in
 * the FPU environment. Zap them so that memcmp() on two saved images will
 * work regardless of whether a context switch occurred in the middle.
 */
static void zap_fpsel(unsigned int *env, bool is_32bit)
{
    if ( is_32bit )
    {
        env[4] &= ~0xffff;
        env[6] &= ~0xffff;
    }
    else
    {
        env[2] &= ~0xffff;
        env[3] &= ~0xffff;
    }
}

static void zap_xfpsel(unsigned int *env)
{
    env[3] &= ~0xffff;
    env[5] &= ~0xffff;
}

#ifdef __x86_64__
# define STKVAL_DISP 64
static const struct {
    const char *descr;
    uint8_t opcode[8];
    /* Index 0: AMD, index 1: Intel. */
    uint8_t opc_len[2];
    int8_t stkoff[2];
    int32_t disp[2];
} vendor_tests[] = {
    {
        .descr = "retw",
        .opcode = { 0x66, 0xc3 },
        .opc_len = { 2, 2 },
        .stkoff = { 2, 8 },
        .disp = { STKVAL_DISP - MMAP_ADDR, STKVAL_DISP },
    }, {
        .descr = "retw $16",
        .opcode = { 0x66, 0xc2, 0x10, 0x00 },
        .opc_len = { 4, 4 },
        .stkoff = { 2 + 16, 8 + 16 },
        .disp = { STKVAL_DISP - MMAP_ADDR, STKVAL_DISP },
    }, {
        .descr = "jmpw .+16",
        .opcode = { 0x66, 0xeb, 0x10 },
        .opc_len = { 3, 3 },
        .disp = { 3 + 16 - MMAP_ADDR, 3 + 16 },
    }, {
        .descr = "jmpw .+128",
        .opcode = { 0x66, 0xe9, 0x80, 0x00, 0x00, 0x00 },
        .opc_len = { 4, 6 },
        .disp = { 4 + 128 - MMAP_ADDR, 6 + 128 },
    }, {
        .descr = "callw .+16",
        .opcode = { 0x66, 0xe8, 0x10, 0x00, 0x00, 0x00 },
        .opc_len = { 4, 6 },
        .stkoff = { -2, -8 },
        .disp = { 4 + 16 - MMAP_ADDR, 6 + 16 },
    }, {
        .descr = "jzw .+16",
        .opcode = { 0x66, 0x74, 0x10 },
        .opc_len = { 3, 3 },
        .disp = { 3, 3 },
    }, {
        .descr = "jzw .+128",
        .opcode = { 0x66, 0x0f, 0x84, 0x80, 0x00, 0x00, 0x00 },
        .opc_len = { 5, 7 },
        .disp = { 5, 7 },
    }, {
        .descr = "jnzw .+16",
        .opcode = { 0x66, 0x75, 0x10 },
        .opc_len = { 3, 3 },
        .disp = { 3 + 16 - MMAP_ADDR, 3 + 16 },
    }, {
        .descr = "jnzw .+128",
        .opcode = { 0x66, 0x0f, 0x85, 0x80, 0x00, 0x00, 0x00 },
        .opc_len = { 5, 7 },
        .disp = { 5 + 128 - MMAP_ADDR, 7 + 128 },
    }, {
        .descr = "loopqw .+16 (RCX>1)",
        .opcode = { 0x66, 0xe0, 0x10 },
        .opc_len = { 3, 3 },
        .disp = { 3 + 16 - MMAP_ADDR, 3 + 16 },
    }, {
        .descr = "looplw .+16 (ECX=1)",
        .opcode = { 0x66, 0x67, 0xe0, 0x10 },
        .opc_len = { 4, 4 },
        .disp = { 4, 4 },
    }, {
        .descr = "jrcxzw .+16 (RCX>0)",
        .opcode = { 0x66, 0xe3, 0x10 },
        .opc_len = { 3, 3 },
        .disp = { 3, 3 },
    }, {
        .descr = "jecxzw .+16 (ECX=0)",
        .opcode = { 0x66, 0x67, 0xe3, 0x10 },
        .opc_len = { 4, 4 },
        .disp = { 4 + 16 - MMAP_ADDR, 4 + 16 },
    }, {
        .descr = "jmpw *(%rsp)",
        .opcode = { 0x66, 0xff, 0x24, 0x24 },
        .opc_len = { 4, 4 },
        .disp = { STKVAL_DISP - MMAP_ADDR, STKVAL_DISP },
    }, {
        .descr = "callw *(%rsp)",
        .opcode = { 0x66, 0xff, 0x14, 0x24 },
        .opc_len = { 4, 4 },
        .stkoff = { -2, -8 },
        .disp = { STKVAL_DISP - MMAP_ADDR, STKVAL_DISP },
    },
};
#endif

int main(int argc, char **argv)
{
    struct x86_emulate_ctxt ctxt;
    struct cpu_user_regs regs;
    char *instr;
    unsigned int *res, i, j;
    bool stack_exec;
    int rc;
#ifdef __x86_64__
    unsigned int vendor_native;
#else
    unsigned int bcdres_native, bcdres_emul;
#endif

    /* Disable output buffering. */
    setbuf(stdout, NULL);

    ctxt.regs = &regs;
    ctxt.force_writeback = 0;
    ctxt.cpuid     = &cp;
    ctxt.lma       = sizeof(void *) == 8;
    ctxt.addr_size = 8 * sizeof(void *);
    ctxt.sp_size   = 8 * sizeof(void *);

    res = mmap((void *)MMAP_ADDR, MMAP_SZ, PROT_READ|PROT_WRITE|PROT_EXEC,
               MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if ( res == MAP_FAILED )
    {
        fprintf(stderr, "mmap to low address failed\n");
        exit(1);
    }
    instr = (char *)res + 0x100;

    stack_exec = emul_test_init();

    if ( !stack_exec )
        printf("Warning: Stack could not be made executable (%d).\n", errno);

 rmw_restart:
    printf("%-40s", "Testing addl %ecx,(%eax)...");
    instr[0] = 0x01; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x7FFFFFFF;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x92345677) || 
         (regs.eflags != 0xa94) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing addl %ecx,%eax...");
    instr[0] = 0x01; instr[1] = 0xc8;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = 0x7FFFFFFF;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (regs.ecx != 0x12345678) ||
         (regs.eax != 0x92345677) ||
         (regs.eflags != 0xa94) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing xorl (%eax),%ecx...");
    instr[0] = 0x33; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
#ifdef __x86_64__
    regs.ecx    = 0xFFFFFFFF12345678UL;
#else
    regs.ecx    = 0x12345678UL;
#endif
    regs.eax    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x92345677) || 
         (regs.ecx != 0x8000000FUL) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movl (%eax),%ecx...");
    instr[0] = 0x8b; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = ~0UL;
    regs.eax    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x92345677) || 
         (regs.ecx != 0x92345677UL) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lock cmpxchgb %cl,(%ebx)...");
    instr[0] = 0xf0; instr[1] = 0x0f; instr[2] = 0xb0; instr[3] = 0x0b;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x92345677UL;
    regs.ecx    = 0xAA;
    regs.ebx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x923456AA) || 
         (regs.eflags != 0x244) ||
         (regs.eax != 0x92345677UL) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lock cmpxchgb %cl,(%ebx)...");
    instr[0] = 0xf0; instr[1] = 0x0f; instr[2] = 0xb0; instr[3] = 0x0b;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0xAABBCC77UL;
    regs.ecx    = 0xFF;
    regs.ebx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x923456AA) || 
         ((regs.eflags & 0xad5) != 0xa91) ||
         (regs.eax != 0xAABBCCAA) ||
         (regs.ecx != 0xFF) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing xchgl %ecx,(%eax)...");
    instr[0] = 0x87; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x12345678) || 
         (regs.eflags != 0x200) ||
         (regs.ecx != 0x923456AA) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing xchg %bl,%ah...");
    instr[0] = 0x86; instr[1] = 0xdc;
    regs.eflags = X86_EFLAGS_IF;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0xaaaabbcc;
    regs.ebx    = 0xddddeeff;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0xaaaaffcc) ||
         (regs.ebx != 0xddddeebb) ||
         (regs.eflags != X86_EFLAGS_IF) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lock cmpxchgl %ecx,(%ebx)...");
    instr[0] = 0xf0; instr[1] = 0x0f; instr[2] = 0xb1; instr[3] = 0x0b;
    regs.eflags = 0x200;
    *res        = 0x923456AA;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x923456AAUL;
    regs.ecx    = 0xDDEEFF00L;
    regs.ebx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0xDDEEFF00) || 
         (regs.eflags != 0x244) ||
         (regs.eax != 0x923456AAUL) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing notb (%edi)...");
    instr[0] = 0xf6; instr[1] = 0x17;
    *res        = 0x22334455;
    regs.eflags = EFLAGS_MASK;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x223344aa) ||
         ((regs.eflags & EFLAGS_MASK) != EFLAGS_MASK) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing rcll $2,(%edi)...");
    instr[0] = 0xc1; instr[1] = 0x17; instr[2] = 0x02;
    *res        = 0x2233445F;
    regs.eflags = EFLAGS_ALWAYS_SET | X86_EFLAGS_CF;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != ((0x2233445F << 2) | 2)) ||
         ((regs.eflags & (EFLAGS_MASK & ~X86_EFLAGS_OF))
          != EFLAGS_ALWAYS_SET) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing shrdl $8,%ecx,(%edi)...");
    instr[0] = 0x0f; instr[1] = 0xac; instr[2] = 0x0f; instr[3] = 0x08;
    *res        = 0x22334455;
    regs.eflags = EFLAGS_ALWAYS_SET | X86_EFLAGS_CF;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x44332211;
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x11223344) ||
         ((regs.eflags & (EFLAGS_MASK & ~(X86_EFLAGS_OF|X86_EFLAGS_AF)))
          != (EFLAGS_ALWAYS_SET | X86_EFLAGS_PF)) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing btrl $0x1,(%edi)...");
    instr[0] = 0x0f; instr[1] = 0xba; instr[2] = 0x37; instr[3] = 0x01;
    *res        = 0x2233445F;
    regs.eflags = EFLAGS_ALWAYS_SET;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x2233445D) ||
         ((regs.eflags & (EFLAGS_ALWAYS_SET | X86_EFLAGS_ZF |
                          X86_EFLAGS_CF)) !=
          (EFLAGS_ALWAYS_SET | X86_EFLAGS_CF)) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing btrl %eax,(%edi)...");
    instr[0] = 0x0f; instr[1] = 0xb3; instr[2] = 0x07;
    *res        = 0x2233445F;
    regs.eflags = EFLAGS_ALWAYS_SET | X86_EFLAGS_ZF;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = -32;
    regs.edi    = (unsigned long)(res+1);
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x2233445E) ||
         ((regs.eflags & (EFLAGS_ALWAYS_SET | X86_EFLAGS_ZF |
                          X86_EFLAGS_CF)) !=
          (EFLAGS_ALWAYS_SET | X86_EFLAGS_ZF | X86_EFLAGS_CF)) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

#ifdef __x86_64__
    printf("%-40s", "Testing btcq %r8,(%r11)...");
    instr[0] = 0x4d; instr[1] = 0x0f; instr[2] = 0xbb; instr[3] = 0x03;
    regs.eflags = EFLAGS_ALWAYS_SET;
    regs.rip    = (unsigned long)&instr[0];
    regs.r8     = (-1L << 40) + 1;
    regs.r11    = (unsigned long)(res + (1L << 35));
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x2233445C) ||
         ((regs.eflags & (EFLAGS_ALWAYS_SET | X86_EFLAGS_ZF |
                          X86_EFLAGS_CF)) !=
          (EFLAGS_ALWAYS_SET | X86_EFLAGS_CF)) ||
         (regs.rip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");
#endif

    printf("%-40s", "Testing xadd %ax,(%ecx)...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0xc1; instr[3] = 0x01;
    regs.eflags = EFLAGS_ALWAYS_SET | X86_EFLAGS_ARITH_MASK;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    regs.eax    = 0x12345678;
    *res        = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x11116789) ||
         (regs.eax != 0x12341111) ||
         ((regs.eflags & EFLAGS_MASK) != EFLAGS_ALWAYS_SET) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    if ( !emulops.rmw )
    {
        printf("[Switching to read-modify-write mode]\n");
        emulops.rmw = rmw;
        goto rmw_restart;
    }

    printf("%-40s", "Testing rep movsw...");
    instr[0] = 0xf3; instr[1] = 0x66; instr[2] = 0xa5;
    *res        = 0x22334455;
    regs.eflags = 0x200;
    regs.ecx    = 23;
    regs.eip    = (unsigned long)&instr[0];
    regs.esi    = (unsigned long)res + 0;
    regs.edi    = (unsigned long)res + 2;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x44554455) ||
         (regs.eflags != 0x200) ||
         (regs.ecx != 22) ||
         (regs.esi != ((unsigned long)res + 2)) ||
         (regs.edi != ((unsigned long)res + 4)) ||
         (regs.eip != (unsigned long)&instr[0]) )
        goto fail;
    printf("okay\n");

    res[0] = 0x12345678;
    res[1] = 0x87654321;

    printf("%-40s", "Testing cmpxchg8b (%edi) [succeeding]...");
    instr[0] = 0x0f; instr[1] = 0xc7; instr[2] = 0x0f;
    regs.eflags = 0x200;
    regs.eax    = res[0];
    regs.edx    = res[1];
    regs.ebx    = 0x9999AAAA;
    regs.ecx    = 0xCCCCFFFF;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (res[0] != 0x9999AAAA) ||
         (res[1] != 0xCCCCFFFF) ||
         ((regs.eflags&0x240) != 0x240) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing cmpxchg8b (%edi) [failing]...");
    instr[0] = 0x0f; instr[1] = 0xc7; instr[2] = 0x0f;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (res[0] != 0x9999AAAA) ||
         (res[1] != 0xCCCCFFFF) ||
         (regs.eax != 0x9999AAAA) ||
         (regs.edx != 0xCCCCFFFF) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing cmpxchg8b (%edi) [opsize]...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0xc7; instr[3] = 0x0f;
    res[0]      = 0x12345678;
    res[1]      = 0x87654321;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (res[0] != 0x12345678) ||
         (res[1] != 0x87654321) ||
         (regs.eax != 0x12345678) ||
         (regs.edx != 0x87654321) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movsxbd (%eax),%ecx...");
    instr[0] = 0x0f; instr[1] = 0xbe; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x82;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x82) ||
         (regs.ecx != 0xFFFFFF82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movzxwd (%eax),%ecx...");
    instr[0] = 0x0f; instr[1] = 0xb7; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x1234aa82;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x1234aa82) ||
         (regs.ecx != 0xaa82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

#ifndef __x86_64__
    printf("%-40s", "Testing arpl %cx,(%eax)...");
    instr[0] = 0x63; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x22222222;
    regs.eax    = (unsigned long)res;
    *res        = 0x33331111;
    bytes_read  = 0;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x33331112) ||
         (regs.ecx != 0x22222222) ||
         !(regs.eflags & X86_EFLAGS_ZF) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
#else
    printf("%-40s", "Testing movsxd (%rax),%rcx...");
    instr[0] = 0x48; instr[1] = 0x63; instr[2] = 0x08;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x123456789abcdef;
    regs.eax    = (unsigned long)res;
    *res        = 0xfedcba98;
    bytes_read  = 0;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0xfedcba98) ||
         (regs.ecx != 0xfffffffffedcba98) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    if ( bytes_read != 4 )
    {
        printf("%u bytes read - ", bytes_read);
        goto fail;
    }
#endif
    printf("okay\n");

    printf("%-40s", "Testing dec %ax...");
#ifndef __x86_64__
    instr[0] = 0x66; instr[1] = 0x48;
#else
    instr[0] = 0x66; instr[1] = 0xff; instr[2] = 0xc8;
#endif
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x00000000;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0x0000ffff) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[2 + (ctxt.addr_size > 32)]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lea 8(%ebp),%eax...");
    instr[0] = 0x8d; instr[1] = 0x45; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x12345678;
    regs.ebp    = 0xaaaaaaaa;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0xaaaaaab2) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing imull -4(%ecx)...");
    instr[0] = 0xf7; instr[1] = 0x69; instr[2] = 0xfc;
    regs.eflags = EFLAGS_ALWAYS_SET;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x89abcdef;
    res[0]      = 0x12345678;
    regs.ecx    = (unsigned long)(res + 1);
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0x89abcdef * 0x12345678) ||
         (regs.edx != (uint64_t)((int64_t)(int32_t)0x89abcdef *
                                 0x12345678) >> 32) ||
         ((regs.eflags & (EFLAGS_ALWAYS_SET | X86_EFLAGS_CF |
                          X86_EFLAGS_OF)) !=
          (EFLAGS_ALWAYS_SET | X86_EFLAGS_CF | X86_EFLAGS_OF)) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing imul $3,-4(%edx),%ecx...");
    instr[0] = 0x6b; instr[1] = 0x4a; instr[2] = 0xfc; instr[3] = 0x03;
    regs.eflags = EFLAGS_ALWAYS_SET;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    res[0]      = 0x89abcdef;
    regs.edx    = (unsigned long)(res + 1);
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.ecx != 0x89abcdef * 3) ||
         ((regs.eflags & (EFLAGS_ALWAYS_SET | X86_EFLAGS_CF |
                          X86_EFLAGS_OF)) !=
          (EFLAGS_ALWAYS_SET | X86_EFLAGS_CF | X86_EFLAGS_OF)) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

#ifndef __x86_64__
    printf("%-40s", "Testing daa/das (all inputs)...");
    /* Bits 0-7: AL; Bit 8: EFLAGS.AF; Bit 9: EFLAGS.CF; Bit 10: DAA vs. DAS. */
    for ( i = 0; i < 0x800; i++ )
    {
        regs.eflags  = (i & 0x200) ? X86_EFLAGS_CF : 0;
        regs.eflags |= (i & 0x100) ? X86_EFLAGS_AF : 0;
        if ( i & 0x400 )
            __asm__ (
                "pushf; andl $~0x11,(%%esp); or %1,(%%esp); popf; das; "
                "pushf; popl %1"
                : "=a" (bcdres_native), "=r" (regs.eflags)
                : "0" (i & 0xff), "1" (regs.eflags) );
        else
            __asm__ (
                "pushf; andl $~0x11,(%%esp); or %1,(%%esp); popf; daa; "
                "pushf; popl %1"
                : "=a" (bcdres_native), "=r" (regs.eflags)
                : "0" (i & 0xff), "1" (regs.eflags) );
        bcdres_native |= (regs.eflags & X86_EFLAGS_PF) ? 0x1000 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_ZF) ? 0x800 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_SF) ? 0x400 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_CF) ? 0x200 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_AF) ? 0x100 : 0;

        instr[0] = (i & 0x400) ? 0x2f: 0x27; /* daa/das */
        regs.eflags  = (i & 0x200) ? X86_EFLAGS_CF : 0;
        regs.eflags |= (i & 0x100) ? X86_EFLAGS_AF : 0;
        regs.eip    = (unsigned long)&instr[0];
        regs.eax    = (unsigned char)i;
        rc = x86_emulate(&ctxt, &emulops);
        bcdres_emul  = regs.eax;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_PF) ? 0x1000 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_ZF) ? 0x800 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_SF) ? 0x400 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_CF) ? 0x200 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_AF) ? 0x100 : 0;
        if ( (rc != X86EMUL_OKAY) || (regs.eax > 255) ||
             (regs.eip != (unsigned long)&instr[1]) )
            goto fail;

        if ( bcdres_emul != bcdres_native )
        {
            printf("%s:    AL=%02x %s %s\n"
                   "Output: AL=%02x %s %s %s %s %s\n"
                   "Emul.:  AL=%02x %s %s %s %s %s\n",
                   (i & 0x400) ? "DAS" : "DAA",
                   (unsigned char)i,
                   (i & 0x200) ? "CF" : "  ",
                   (i & 0x100) ? "AF" : "  ",
                   (unsigned char)bcdres_native,
                   (bcdres_native & 0x200) ? "CF" : "  ",
                   (bcdres_native & 0x100) ? "AF" : "  ",
                   (bcdres_native & 0x1000) ? "PF" : "  ",
                   (bcdres_native & 0x800) ? "ZF" : "  ",
                   (bcdres_native & 0x400) ? "SF" : "  ",
                   (unsigned char)bcdres_emul,
                   (bcdres_emul & 0x200) ? "CF" : "  ",
                   (bcdres_emul & 0x100) ? "AF" : "  ",
                   (bcdres_emul & 0x1000) ? "PF" : "  ",
                   (bcdres_emul & 0x800) ? "ZF" : "  ",
                   (bcdres_emul & 0x400) ? "SF" : "  ");
            goto fail;
        }
    }
    printf("okay\n");
#else /* x86-64 */
    printf("%-40s", "Testing cmovz %ecx,%eax...");
    instr[0] = 0x0f; instr[1] = 0x44; instr[2] = 0xc1;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.rax    = 0x1111111122222222;
    regs.rcx    = 0x3333333344444444;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.rax != 0x0000000022222222) ||
         (regs.rcx != 0x3333333344444444) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    vendor_native = cp.x86_vendor;
    for ( cp.x86_vendor = X86_VENDOR_AMD; ; )
    {
        unsigned int v = cp.x86_vendor == X86_VENDOR_INTEL;
        const char *vendor = cp.x86_vendor == X86_VENDOR_INTEL ? "Intel" : "AMD";
        uint64_t *stk = (void *)res + MMAP_SZ - 16;

        regs.rcx = 2;
        for ( i = 0; i < ARRAY_SIZE(vendor_tests); ++i )
        {
            printf("%-*s",
                   40 - printf("Testing %s [%s]", vendor_tests[i].descr, vendor),
                   "...");
            memcpy(instr, vendor_tests[i].opcode, vendor_tests[i].opc_len[v]);
            regs.eflags = EFLAGS_ALWAYS_SET;
            regs.rip    = (unsigned long)instr;
            regs.rsp    = (unsigned long)stk;
            regs.rcx   |= 0x8765432100000000UL;
            stk[0]      = regs.rip + STKVAL_DISP;
            rc = x86_emulate(&ctxt, &emulops);
            if ( (rc != X86EMUL_OKAY) ||
                 (regs.eflags != EFLAGS_ALWAYS_SET) ||
                 (regs.rip != (unsigned long)instr +
                              (vendor_tests[i].disp[v]
                               ?: vendor_tests[i].opc_len[v])) ||
                 (regs.rsp != (unsigned long)stk + vendor_tests[i].stkoff[v]) )
                goto fail;
            /* For now only call insns push something onto the stack. */
            if ( regs.rsp < (unsigned long)stk )
            {
                unsigned long opc_end = (unsigned long)instr +
                                        vendor_tests[i].opc_len[v];

                if ( memcmp(&opc_end, (void *)regs.rsp,
                            min((unsigned long)stk - regs.rsp, 8UL)) )
                    goto fail;
            }
            printf("okay\n");
        }

        if ( cp.x86_vendor == X86_VENDOR_INTEL )
            break;
        cp.x86_vendor = X86_VENDOR_INTEL;
    }
    cp.x86_vendor = vendor_native;
#endif /* x86-64 */

    printf("%-40s", "Testing shld $1,%ecx,(%edx)...");
    res[0]      = 0x12345678;
    regs.edx    = (unsigned long)res;
    regs.ecx    = 0x9abcdef0;
    instr[0] = 0x0f; instr[1] = 0xa4; instr[2] = 0x0a; instr[3] = 0x01;
    for ( i = 0; i < 0x20; ++i )
    {
        uint32_t r = res[0];
        const uint32_t m = X86_EFLAGS_ARITH_MASK & ~X86_EFLAGS_AF;
        unsigned long f;

        asm ( "shld $1,%2,%0; pushf; pop %1"
              : "+rm" (r), "=rm" (f) : "r" ((uint32_t)regs.ecx) );
        regs.eflags = f ^ m;
        regs.eip    = (unsigned long)&instr[0];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[4]) ||
             (res[0] != r) ||
             ((regs.eflags ^ f) & m) )
            goto fail;
        regs.ecx <<= 1;
    }
    printf("okay\n");

    printf("%-40s", "Testing movbe (%ecx),%eax...");
    instr[0] = 0x0f; instr[1] = 0x38; instr[2] = 0xf0; instr[3] = 0x01;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    regs.eax    = 0x11111111;
    *res        = 0x12345678;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x12345678) ||
         (regs.eax != 0x78563412) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movbe %ax,(%ecx)...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0x38; instr[3] = 0xf1; instr[4] = 0x01;
    regs.eip = (unsigned long)&instr[0];
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x12341234) ||
         (regs.eax != 0x78563412) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[5]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing popcnt (%edx),%cx...");
    if ( cpu_has_popcnt )
    {
        instr[0] = 0x66; instr[1] = 0xf3;
        instr[2] = 0x0f; instr[3] = 0xb8; instr[4] = 0x0a;

        *res        = 0xfedcba98;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xac3;
        regs.eip    = (unsigned long)&instr[0];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || (uint16_t)regs.ecx != 8 || *res != 0xfedcba98 ||
             (regs.eflags & 0xfeb) != 0x202 ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");

        printf("%-40s", "Testing popcnt (%edx),%ecx...");
        regs.eflags = 0xac3;
        regs.eip    = (unsigned long)&instr[1];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 20 || *res != 0xfedcba98 ||
             (regs.eflags & 0xfeb) != 0x202 ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");

#ifdef __x86_64__
        printf("%-40s", "Testing popcnt (%rdx),%rcx...");
        instr[0]    = 0xf3;
        instr[1]    = 0x48;
        res[1]      = 0x12345678;
        regs.eflags = 0xac3;
        regs.eip    = (unsigned long)&instr[0];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 33 ||
             res[0] != 0xfedcba98 || res[1] != 0x12345678 ||
             (regs.eflags & 0xfeb) != 0x202 ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");
#endif
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing lar (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x02; instr[2] = 0xc1;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0;
    regs.eax    = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0x11111111) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lsl (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x03; instr[2] = 0xca;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.edx    = 0;
    regs.ecx    = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.ecx != 0x11111111) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing verr (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0x21;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    *res        = 0;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing verw (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0x2a;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0;
    regs.edx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lar/lsl/verr/verw (all types)...");
    for ( i = 0; i < 0x20; ++i )
    {
        unsigned int sel = i < 0x10 ?
#ifndef __x86_64__
                                      (i << 3) + 8
#else
                                      (i << 4) + 8
#endif
                                    : ((i - 0x10) << 3) | 4;
        bool failed;

#ifndef __x86_64__
# define LAR_VALID 0xffff1a3eU
# define LSL_VALID 0xffff0a0eU
#else
# define LAR_VALID 0xffff1a04U
# define LSL_VALID 0xffff0a04U
#endif
#define VERR_VALID 0xccff0000U
#define VERW_VALID 0x00cc0000U

        instr[0] = 0x0f; instr[1] = 0x02; instr[2] = 0xc2;
        regs.eflags = (LAR_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.edx    = sel;
        regs.eax    = 0x11111111;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( (LAR_VALID >> i) & 1 )
            failed = (regs.eflags != 0x240) ||
                     ((regs.eax & 0xf0ff00) != (i << 8));
        else
            failed = (regs.eflags != 0x200) ||
                     (regs.eax != 0x11111111);
        if ( failed )
        {
            printf("LAR %04x (type %02x) ", sel, i);
            goto fail;
        }

        instr[0] = 0x0f; instr[1] = 0x03; instr[2] = 0xd1;
        regs.eflags = (LSL_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.ecx    = sel;
        regs.edx    = 0x11111111;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( (LSL_VALID >> i) & 1 )
            failed = (regs.eflags != 0x240) ||
                     (regs.edx != (i & 0xf));
        else
            failed = (regs.eflags != 0x200) ||
                     (regs.edx != 0x11111111);
        if ( failed )
        {
            printf("LSL %04x (type %02x) ", sel, i);
            goto fail;
        }

        instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0xe2;
        regs.eflags = (VERR_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.ecx    = 0;
        regs.edx    = sel;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( regs.eflags != ((VERR_VALID >> i) & 1 ? 0x240 : 0x200) )
        {
            printf("VERR %04x (type %02x) ", sel, i);
            goto fail;
        }

        instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0xe9;
        regs.eflags = (VERW_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.ecx    = sel;
        regs.edx    = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( regs.eflags != ((VERW_VALID >> i) & 1 ? 0x240 : 0x200) )
        {
            printf("VERW %04x (type %02x) ", sel, i);
            goto fail;
        }
    }
    printf("okay\n");

    printf("%-40s", "Testing mov %%cr4,%%esi (bad ModRM)...");
    /*
     * Mod = 1, Reg = 4, R/M = 6 would normally encode a memory reference of
     * disp8(%esi), but mov to/from cr/dr are special and behave as if they
     * were encoded with Mod == 3.
     */
    instr[0] = 0x0f; instr[1] = 0x20, instr[2] = 0x66;
    instr[3] = 0; /* Supposed disp8. */
    regs.esi = 0;
    regs.eip = (unsigned long)&instr[0];
    rc = x86_emulate(&ctxt, &emulops);
    /*
     * We don't care precicely what gets read from %cr4 into %esi, just so
     * long as ModRM is treated as a register operand and 0(%esi) isn't
     * followed as a memory reference.
     */
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

#define decl_insn(which) extern const unsigned char which[], \
                         which##_end[] asm ( ".L" #which "_end" )
#define put_insn(which, insn) ".pushsection .test\n" \
                              #which ": " insn "\n"  \
                              ".L" #which "_end:\n"  \
                              ".popsection"
#define set_insn(which) (regs.eip = (unsigned long)(which))
#define valid_eip(which) (regs.eip >= (unsigned long)(which) && \
                          regs.eip < (unsigned long)which##_end)
#define check_eip(which) (regs.eip == (unsigned long)which##_end)

    printf("%-40s", "Testing andn (%edx),%ecx,%ebx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(andn);

        asm volatile ( put_insn(andn, "andn (%0), %%ecx, %%ebx")
                       :: "d" (NULL) );
        set_insn(andn);

        *res        = 0xfedcba98;
        regs.ecx    = 0xcccc3333;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x32108888 ||
             regs.ecx != 0xcccc3333 || *res != 0xfedcba98 ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(andn) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing bextr %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(bextr);
#ifdef __x86_64__
        decl_insn(bextr64);
#endif

        asm volatile ( put_insn(bextr, "bextr %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(bextr);

        regs.ecx    = (unsigned long)res;
        regs.edx    = 0x0a03;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != ((*res >> 3) & 0x3ff) ||
             regs.edx != 0x0a03 || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr) )
            goto fail;
        printf("okay\n");
#ifdef __x86_64__
        printf("%-40s", "Testing bextr %r9,(%r10),%r11...");

        asm volatile ( put_insn(bextr64, "bextr %r9, (%r10), %r11") );
        set_insn(bextr64);

        res[0]      = 0x76543210;
        res[1]      = 0xfedcba98;
        regs.r10    = (unsigned long)res;
        regs.r9     = 0x211e;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.r9 != 0x211e ||
             regs.r11 != (((unsigned long)(res[1] << 1) << 1) |
                          (res[0] >> 30)) ||
             res[0] != 0x76543210 || res[1] != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr64) )
            goto fail;
        printf("okay\n");
#endif
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsi (%edx),%ecx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(blsi);

        asm volatile ( put_insn(blsi, "blsi (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsi);

        *res        = 0xfedcba98;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xac2;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 8 || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x203 || !check_eip(blsi) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsmsk (%edx),%ecx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(blsmsk);

        asm volatile ( put_insn(blsmsk, "blsmsk (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsmsk);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 0xf || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(blsmsk) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsr (%edx),%ecx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(blsr);

        asm volatile ( put_insn(blsr, "blsr (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsr);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 0xfedcba90 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(blsr) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing bzhi %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(bzhi);

        asm volatile ( put_insn(bzhi, "bzhi %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(bzhi);

        regs.ecx    = (unsigned long)res;
        regs.edx    = 0xff13;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != (*res & 0x7ffff) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bzhi) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing mulx (%eax),%ecx,%ebx...");
    if ( cpu_has_bmi2 )
    {
        decl_insn(mulx);

        asm volatile ( put_insn(mulx, "mulx (%0), %%ecx, %%ebx")
                       :: "a" (NULL) );
        set_insn(mulx);

        regs.eax    = (unsigned long)res;
        regs.edx    = 0x12345678;
        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x121fa00a ||
             regs.ecx != 0x35068740 || *res != 0xfedcba98 ||
             regs.eflags != 0xac3 || !check_eip(mulx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pdep (%edx),%ecx,%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(pdep);

        asm volatile ( put_insn(pdep, "pdep (%0), %%ecx, %%ebx")
                       :: "d" (NULL) );
        set_insn(pdep);

        regs.ecx    = 0x8cef;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x850b298 ||
             regs.ecx != 0x8cef || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(pdep) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pext (%edx),%ecx,%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(pext);

        asm volatile ( put_insn(pext, "pext (%0), %%ecx, %%ebx")
                       :: "d" (NULL) );
        set_insn(pext);

        regs.ecx    = 0x137f8cef;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x12f95 ||
             regs.ecx != 0x137f8cef || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(pext) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing rorx $16,(%ecx),%ebx...");
    if ( cpu_has_bmi2 )
    {
        decl_insn(rorx);

        asm volatile ( put_insn(rorx, "rorx $16, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(rorx);

        regs.ecx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0xba98fedc ||
             *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(rorx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing sarx %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(sarx);

        asm volatile ( put_insn(sarx, "sarx %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(sarx);

        regs.ecx    = (unsigned long)res;
        regs.edx    = 0xff13;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.ebx != (unsigned)(((signed)*res >> (regs.edx & 0x1f))) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(sarx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing shlx %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(shlx);

        asm volatile ( put_insn(shlx, "shlx %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(shlx);

        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.ebx != (*res << (regs.edx & 0x1f)) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(shlx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing shrx %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(shrx);

        asm volatile ( put_insn(shrx, "shrx %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(shrx);

        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.ebx != (*res >> (regs.edx & 0x1f)) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(shrx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing adcx/adox ...");
    {
        static const unsigned int data[] = {
            0x01234567, 0x12345678, 0x23456789, 0x3456789a,
            0x456789ab, 0x56789abc, 0x6789abcd, 0x789abcde,
            0x89abcdef, 0x9abcdef0, 0xabcdef01, 0xbcdef012,
            0xcdef0123, 0xdef01234, 0xef012345, 0xf0123456
        };
        decl_insn(adx);
        unsigned int cf, of;

        asm volatile ( put_insn(adx, ".Lloop%=:\n\t"
                                     "adcx (%[addr]), %k[dst1]\n\t"
                                     "adox -%c[full]-%c[elem](%[addr],%[cnt],2*%c[elem]), %k[dst2]\n\t"
                                     "lea %c[elem](%[addr]),%[addr]\n\t"
                                     "loop .Lloop%=\n\t"
                                     "adcx %k[cnt], %k[dst1]\n\t"
                                     "adox %k[cnt], %k[dst2]\n\t" )
                       : [addr] "=S" (regs.esi), [cnt] "=c" (regs.ecx),
                         [dst1] "=a" (regs.eax), [dst2] "=d" (regs.edx)
                       : [full] "i" (sizeof(data)), [elem] "i" (sizeof(*data)),
                         "[addr]" (data), "[cnt]" (ARRAY_SIZE(data)),
                         "[dst1]" (0), "[dst2]" (0) );

        set_insn(adx);
        regs.eflags = 0x2d6;
        of = cf = i = 0;
        while ( (rc = x86_emulate(&ctxt, &emulops)) == X86EMUL_OKAY )
        {
            ++i;
            /*
             * Count CF/OF being set after each loop iteration during the
             * first half (to observe different counts), in order to catch
             * the wrong flag being fiddled with.
             */
            if ( i < ARRAY_SIZE(data) * 2 && !(i % 4) )
            {
                if ( regs.eflags & 0x001 )
                   ++cf;
                if ( regs.eflags & 0x800 )
                   ++of;
            }
            if ( !valid_eip(adx) )
                break;
        }
        if ( (rc != X86EMUL_OKAY) ||
             i != ARRAY_SIZE(data) * 4 + 2 || cf != 1 || of != 5 ||
             regs.eax != 0xffffffff || regs.ecx || regs.edx != 0xffffffff ||
             !check_eip(adx) || regs.eflags != 0x2d6 )
            goto fail;
        printf("okay\n");
    }

    printf("%-40s", "Testing bextr $0x0a03,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(bextr_imm);
#ifdef __x86_64__
        decl_insn(bextr64_imm);
#endif

        asm volatile ( put_insn(bextr_imm, "bextr $0x0a03, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(bextr_imm);

        *res        = 0xfedcba98;
        regs.ecx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != ((*res >> 3) & 0x3ff) ||
             *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr_imm) )
            goto fail;
        printf("okay\n");
#ifdef __x86_64__
        printf("%-40s", "Testing bextr $0x211e,(%r10),%r11...");

        asm volatile ( put_insn(bextr64_imm, "bextr $0x211e, (%r10), %r11") );
        set_insn(bextr64_imm);

        res[0]      = 0x76543210;
        res[1]      = 0xfedcba98;
        regs.r10    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.r11 != (((unsigned long)(res[1] << 1) << 1) |
                          (res[0] >> 30)) ||
             res[0] != 0x76543210 || res[1] != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr64_imm) )
            goto fail;
        printf("okay\n");
#endif
    }
    else
        printf("skipped\n");

    res[0]      = 0xfedcba98;
    res[1]      = 0x01234567;
    regs.edx    = (unsigned long)res;

    printf("%-40s", "Testing blcfill 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcfill);

        asm volatile ( put_insn(blcfill, "blcfill 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcfill);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) & res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcfill) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blci 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blci);

        asm volatile ( put_insn(blci, "blci 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blci);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != (~(res[1] + 1) | res[1]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(blci) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blcic 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcic);

        asm volatile ( put_insn(blcic, "blcic 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcic);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) & ~res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcic) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blcmsk 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcmsk);

        asm volatile ( put_insn(blcmsk, "blcmsk 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcmsk);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) ^ res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcmsk) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blcs 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcs);

        asm volatile ( put_insn(blcs, "blcs 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcs);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) | res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcs) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsfill (%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blsfill);

        asm volatile ( put_insn(blsfill, "blsfill (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsfill);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[0] != 0xfedcba98 ||
             regs.ecx != ((res[0] - 1) | res[0]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(blsfill) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsic (%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blsic);

        asm volatile ( put_insn(blsic, "blsic (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsic);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[0] != 0xfedcba98 ||
             regs.ecx != ((res[0] - 1) | ~res[0]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(blsic) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing t1mskc 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(t1mskc);

        asm volatile ( put_insn(t1mskc, "t1mskc 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(t1mskc);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) | ~res[1]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(t1mskc) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing tzmsk (%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(tzmsk);

        asm volatile ( put_insn(tzmsk, "tzmsk (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(tzmsk);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[0] != 0xfedcba98 ||
             regs.ecx != ((res[0] - 1) & ~res[0]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(tzmsk) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing rdpid %ecx...");
    instr[0] = 0xF3; instr[1] = 0x0f; instr[2] = 0xC7; instr[3] = 0xf9;
    regs.eip = (unsigned long)&instr[0];
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.ecx != TSC_AUX_VALUE) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movdiri %edx,(%ecx)...");
    if ( stack_exec && cpu_has_movdiri )
    {
        instr[0] = 0x0f; instr[1] = 0x38; instr[2] = 0xf9; instr[3] = 0x11;

        regs.eip = (unsigned long)&instr[0];
        regs.ecx = (unsigned long)memset(res, -1, 16);
        regs.edx = 0x44332211;

        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[4]) ||
             res[0] != 0x44332211 || ~res[1] )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movdir64b 144(%edx),%ecx...");
    if ( stack_exec && cpu_has_movdir64b )
    {
        instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0x38; instr[3] = 0xf8;
        instr[4] = 0x8a; instr[5] = 0x90; instr[8] = instr[7] = instr[6] = 0;

        regs.eip = (unsigned long)&instr[0];
        for ( i = 0; i < 64; ++i )
            res[i] = i - 20;
        regs.edx = (unsigned long)res;
        regs.ecx = (unsigned long)(res + 16);

        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[9]) ||
             res[15] != -5 || res[32] != 12 )
            goto fail;
        for ( i = 16; i < 32; ++i )
            if ( res[i] != i )
                goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing fnstenv 4(%ecx)...");
    if ( stack_exec && cpu_has_fpu )
    {
        const uint16_t three = 3;

        asm volatile ( "fninit\n\t"
                       "fld1\n\t"
                       "fidivs %1\n\t"
                       "fstenv %0"
                       : "=m" (res[9]) : "m" (three) : "memory" );
        zap_fpsel(&res[9], true);
        instr[0] = 0xd9; instr[1] = 0x71; instr[2] = 0x04;
        regs.eip = (unsigned long)&instr[0];
        regs.ecx = (unsigned long)res;
        res[8] = 0xaa55aa55;
        rc = x86_emulate(&ctxt, &emulops);
        zap_fpsel(&res[1], true);
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res + 1, res + 9, 28) ||
             res[8] != 0xaa55aa55 ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing fldenv 8(%edx)...");
    if ( stack_exec && cpu_has_fpu )
    {
        asm volatile ( "fnstenv %0\n\t"
                       "fninit"
                       : "=m" (res[2]) :: "memory" );
        zap_fpsel(&res[2], true);
        instr[0] = 0xd9; instr[1] = 0x62; instr[2] = 0x08;
        regs.eip = (unsigned long)&instr[0];
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm volatile ( "fnstenv %0" : "=m" (res[9]) :: "memory" );
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res + 2, res + 9, 28) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing 16-bit fnsave (%ecx)...");
    if ( stack_exec && cpu_has_fpu )
    {
        const uint16_t five = 5;

        asm volatile ( "fninit\n\t"
                       "fld1\n\t"
                       "fidivs %1\n\t"
                       "fsaves %0"
                       : "=m" (res[25]) : "m" (five) : "memory" );
        zap_fpsel(&res[25], false);
        asm volatile ( "frstors %0" :: "m" (res[25]) : "memory" );
        instr[0] = 0x66; instr[1] = 0xdd; instr[2] = 0x31;
        regs.eip = (unsigned long)&instr[0];
        regs.ecx = (unsigned long)res;
        res[23] = 0xaa55aa55;
        res[24] = 0xaa55aa55;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res, res + 25, 94) ||
             (res[23] >> 16) != 0xaa55 ||
             res[24] != 0xaa55aa55 ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing frstor (%edx)...");
    if ( stack_exec && cpu_has_fpu )
    {
        const uint16_t seven = 7;

        asm volatile ( "fninit\n\t"
                       "fld1\n\t"
                       "fidivs %1\n\t"
                       "fnsave %0\n\t"
                       : "=&m" (res[0]) : "m" (seven) : "memory" );
        zap_fpsel(&res[0], true);
        instr[0] = 0xdd; instr[1] = 0x22;
        regs.eip = (unsigned long)&instr[0];
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm volatile ( "fnsave %0" : "=m" (res[27]) :: "memory" );
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res, res + 27, 108) ||
             (regs.eip != (unsigned long)&instr[2]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing fxsave 4(%ecx)...");
    if ( stack_exec && cpu_has_fxsr )
    {
        const uint16_t nine = 9;

        memset(res + 0x80, 0xcc, 0x400);
        if ( cpu_has_sse2 )
            asm volatile ( "pcmpeqd %xmm7, %xmm7\n\t"
                           "pxor %xmm6, %xmm6\n\t"
                           "psubw %xmm7, %xmm6" );
        asm volatile ( "fninit\n\t"
                       "fld1\n\t"
                       "fidivs %1\n\t"
                       "fxsave %0"
                       : "=m" (res[0x100]) : "m" (nine) : "memory" );
        zap_xfpsel(&res[0x100]);
        instr[0] = 0x0f; instr[1] = 0xae; instr[2] = 0x41; instr[3] = 0x04;
        regs.eip = (unsigned long)&instr[0];
        regs.ecx = (unsigned long)(res + 0x7f);
        memset(res + 0x100 + 0x74, 0x33, 0x30);
        memset(res + 0x80 + 0x74, 0x33, 0x30);
        rc = x86_emulate(&ctxt, &emulops);
        zap_xfpsel(&res[0x80]);
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res + 0x80, res + 0x100, 0x200) ||
             (regs.eip != (unsigned long)&instr[4]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing fxrstor -4(%ecx)...");
    if ( stack_exec && cpu_has_fxsr )
    {
        const uint16_t eleven = 11;

        memset(res + 0x80, 0xcc, 0x400);
        asm volatile ( "fxsave %0" : "=m" (res[0x80]) :: "memory" );
        zap_xfpsel(&res[0x80]);
        if ( cpu_has_sse2 )
            asm volatile ( "pxor %xmm7, %xmm6\n\t"
                           "pxor %xmm7, %xmm3\n\t"
                           "pxor %xmm7, %xmm0\n\t"
                           "pxor %xmm7, %xmm7" );
        asm volatile ( "fninit\n\t"
                       "fld1\n\t"
                       "fidivs %0\n\t"
                       :: "m" (eleven) );
        instr[0] = 0x0f; instr[1] = 0xae; instr[2] = 0x49; instr[3] = 0xfc;
        regs.eip = (unsigned long)&instr[0];
        regs.ecx = (unsigned long)(res + 0x81);
        rc = x86_emulate(&ctxt, &emulops);
        asm volatile ( "fxsave %0" : "=m" (res[0x100]) :: "memory" );
        zap_xfpsel(&res[0x100]);
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res + 0x100, res + 0x80, 0x200) ||
             (regs.eip != (unsigned long)&instr[4]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

#ifdef __x86_64__
    printf("%-40s", "Testing fxsaveq 8(%edx)...");
    if ( stack_exec && cpu_has_fxsr )
    {
        memset(res + 0x80, 0xcc, 0x400);
        asm volatile ( "fxsaveq %0" : "=m" (res[0x100]) :: "memory" );
        instr[0] = 0x48; instr[1] = 0x0f; instr[2] = 0xae; instr[3] = 0x42; instr[4] = 0x08;
        regs.eip = (unsigned long)&instr[0];
        regs.edx = (unsigned long)(res + 0x7e);
        memset(res + 0x100 + 0x74, 0x33, 0x30);
        memset(res + 0x80 + 0x74, 0x33, 0x30);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             memcmp(res + 0x80, res + 0x100, 0x200) ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");
#endif

    printf("%-40s", "Testing movq %mm3,(%ecx)...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_to_mem);

        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movq_to_mem, "movq %%mm3, (%0)")
                       :: "c" (NULL) );

        set_insn(movq_to_mem);
        memset(res, 0x33, 64);
        memset(res + 8, 0xff, 8);
        regs.ecx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(movq_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq (%edx),%mm5...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_from_mem);

        asm volatile ( "pcmpgtb %%mm5, %%mm5\n"
                       put_insn(movq_from_mem, "movq (%0), %%mm5")
                       :: "d" (NULL) );

        set_insn(movq_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_from_mem) )
            goto fail;
        asm ( "pcmpeqb %%mm3, %%mm3\n\t"
              "pcmpeqb %%mm5, %%mm3\n\t"
              "pmovmskb %%mm3, %0" : "=r" (rc) );
        if ( rc != 0xff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %xmm0,32(%ecx)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movq_to_mem2);

        asm volatile ( "pcmpgtb %%xmm0, %%xmm0\n"
                       put_insn(movq_to_mem2, "movq %%xmm0, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(movq_to_mem2);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_to_mem2) ||
             *((uint64_t *)res + 4) ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq 32(%ecx),%xmm1...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movq_from_mem2);

        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(movq_from_mem2, "movq 32(%0), %%xmm1")
                       :: "c" (NULL) );

        set_insn(movq_from_mem2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_from_mem2) )
            goto fail;
        asm ( "pcmpgtb %%xmm0, %%xmm0\n\t"
              "pcmpeqb %%xmm1, %%xmm0\n\t"
              "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %xmm1,32(%edx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_to_mem);

        asm volatile ( "pcmpgtb %%xmm1, %%xmm1\n"
                       put_insn(vmovq_to_mem, "vmovq %%xmm1, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(vmovq_to_mem);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovq_to_mem) ||
             *((uint64_t *)res + 4) ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq 32(%edx),%xmm0...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_from_mem);

        asm volatile ( "pcmpeqb %%xmm0, %%xmm0\n"
                       put_insn(vmovq_from_mem, "vmovq 32(%0), %%xmm0")
                       :: "d" (NULL) );

        set_insn(vmovq_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovq_from_mem) )
            goto fail;
        asm ( "pcmpgtb %%xmm1, %%xmm1\n\t"
              "pcmpeqb %%xmm0, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovq %xmm1,32(%edx)...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovq_to_mem);

        asm volatile ( "pcmpgtb %%xmm1, %%xmm1\n"
                       put_insn(evex_vmovq_to_mem, "%{evex%} vmovq %%xmm1, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(evex_vmovq_to_mem);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovq_to_mem) ||
             *((uint64_t *)res + 4) ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovq 32(%edx),%xmm0...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovq_from_mem);

        asm volatile ( "pcmpeqb %%xmm0, %%xmm0\n"
                       put_insn(evex_vmovq_from_mem, "%{evex%} vmovq 32(%0), %%xmm0")
                       :: "d" (NULL) );

        set_insn(evex_vmovq_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovq_from_mem) )
            goto fail;
        asm ( "vmovq %1, %%xmm1\n\t"
              "vpcmpeqq %%zmm0, %%zmm1, %%k0\n"
              "kmovw %%k0, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movdqu %xmm2,(%ecx)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movdqu_to_mem);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movdqu_to_mem, "movdqu %%xmm2, (%0)")
                       :: "c" (NULL) );

        set_insn(movdqu_to_mem);
        memset(res, 0x55, 64);
        memset(res + 8, 0xff, 16);
        regs.ecx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(movdqu_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movdqu (%edx),%xmm4...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movdqu_from_mem);

        asm volatile ( "pcmpgtb %%xmm4, %%xmm4\n"
                       put_insn(movdqu_from_mem, "movdqu (%0), %%xmm4")
                       :: "d" (NULL) );

        set_insn(movdqu_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movdqu_from_mem) )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm4, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu %ymm2,(%ecx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovdqu_to_mem);

        asm volatile ( "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n"
                       put_insn(vmovdqu_to_mem, "vmovdqu %%ymm2, (%0)")
                       :: "c" (NULL) );

        set_insn(vmovdqu_to_mem);
        memset(res, 0x55, 128);
        memset(res + 16, 0xff, 16);
        memset(res + 20, 0x00, 16);
        regs.ecx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 16, 64) ||
             !check_eip(vmovdqu_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu (%edx),%ymm4...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovdqu_from_mem);

        asm volatile ( "vpxor %%xmm4, %%xmm4, %%xmm4\n"
                       put_insn(vmovdqu_from_mem, "vmovdqu (%0), %%ymm4")
                       :: "d" (NULL) );

        set_insn(vmovdqu_from_mem);
        memset(res + 4, 0xff, 16);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovdqu_from_mem) )
            goto fail;
        asm ( "vextractf128 $1, %%ymm4, %%xmm3\n\t"
              "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n\t"
              "vpcmpeqb %%xmm4, %%xmm2, %%xmm0\n\t"
              "vpcmpeqb %%xmm3, %%xmm2, %%xmm1\n\t"
              "vpmovmskb %%xmm0, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        rc |= i << 16;
        if ( rc != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu32 %zmm2,(%ecx){%k1}...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(vmovdqu32_to_mem);

        memset(res, 0x55, 128);

        asm volatile ( "vpcmpeqd %%ymm2, %%ymm2, %%ymm2\n\t"
                       "kmovw %1,%%k1\n"
                       put_insn(vmovdqu32_to_mem,
                                "vmovdqu32 %%zmm2, (%0)%{%%k1%}")
                       :: "c" (NULL), "rm" (res[0]) );
        set_insn(vmovdqu32_to_mem);

        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res + 16, res + 24, 32) ||
             !check_eip(vmovdqu32_to_mem) )
            goto fail;

        res[16] = ~0; res[18] = ~0; res[20] = ~0; res[22] = ~0;
        res[24] =  0; res[26] =  0; res[28] =  0; res[30] =  0;
        if ( memcmp(res, res + 16, 64) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu32 64(%edx),%zmm2{%k2}...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(vmovdqu32_from_mem);

        asm volatile ( "knotw %%k1, %%k2\n"
                       put_insn(vmovdqu32_from_mem,
                                "vmovdqu32 64(%0), %%zmm2%{%%k2%}")
                       :: "d" (NULL) );

        set_insn(vmovdqu32_from_mem);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovdqu32_from_mem) )
            goto fail;
        asm ( "vpcmpeqd %1, %%zmm2, %%k0\n\t"
              "kmovw %%k0, %0" : "=r" (rc) : "m" (res[0]) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu16 %zmm3,(%ecx){%k1}...");
    if ( stack_exec && cpu_has_avx512bw )
    {
        decl_insn(vmovdqu16_to_mem);

        memset(res, 0x55, 128);

        asm volatile ( "vpcmpeqw %%ymm3, %%ymm3, %%ymm3\n\t"
                       "kmovd %1,%%k1\n"
                       put_insn(vmovdqu16_to_mem,
                                "vmovdqu16 %%zmm3, (%0)%{%%k1%}")
                       :: "c" (NULL), "rm" (res[0]) );
        set_insn(vmovdqu16_to_mem);

        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res + 16, res + 24, 32) ||
             !check_eip(vmovdqu16_to_mem) )
            goto fail;

        for ( i = 16; i < 24; ++i )
            res[i] |= 0x0000ffff;
        for ( ; i < 32; ++i )
            res[i] &= 0xffff0000;
        if ( memcmp(res, res + 16, 64) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu16 64(%edx),%zmm3{%k2}...");
    if ( stack_exec && cpu_has_avx512bw )
    {
        decl_insn(vmovdqu16_from_mem);

        asm volatile ( "knotd %%k1, %%k2\n"
                       put_insn(vmovdqu16_from_mem,
                                "vmovdqu16 64(%0), %%zmm3%{%%k2%}")
                       :: "d" (NULL) );

        set_insn(vmovdqu16_from_mem);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovdqu16_from_mem) )
            goto fail;
        asm ( "vpcmpeqw %1, %%zmm3, %%k0\n\t"
              "kmovd %%k0, %0" : "=r" (rc) : "m" (res[0]) );
        if ( rc != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movsd %xmm5,(%ecx)...");
    memset(res, 0x77, 64);
    memset(res + 10, 0x66, 8);
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movsd_to_mem);

        asm volatile ( "movlpd %0, %%xmm5\n\t"
                       "movhpd %0, %%xmm5\n"
                       put_insn(movsd_to_mem, "movsd %%xmm5, (%1)")
                       :: "m" (res[10]), "c" (NULL) );

        set_insn(movsd_to_mem);
        regs.ecx    = (unsigned long)(res + 2);
        regs.edx    = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(movsd_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
    {
        printf("skipped\n");
        memset(res + 2, 0x66, 8);
    }

    printf("%-40s", "Testing movaps (%edx),%xmm7...");
    if ( stack_exec && cpu_has_sse )
    {
        decl_insn(movaps_from_mem);

        asm volatile ( "xorps %%xmm7, %%xmm7\n"
                       put_insn(movaps_from_mem, "movaps (%0), %%xmm7")
                       :: "d" (NULL) );

        set_insn(movaps_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movaps_from_mem) )
            goto fail;
        asm ( "cmpeqps %1, %%xmm7\n\t"
              "movmskps %%xmm7, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xf )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovsd %xmm5,(%ecx)...");
    memset(res, 0x88, 64);
    memset(res + 10, 0x77, 8);
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovsd_to_mem);

        asm volatile ( "vbroadcastsd %0, %%ymm5\n"
                       put_insn(vmovsd_to_mem, "vmovsd %%xmm5, (%1)")
                       :: "m" (res[10]), "c" (NULL) );

        set_insn(vmovsd_to_mem);
        regs.ecx    = (unsigned long)(res + 2);
        regs.edx    = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(vmovsd_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
    {
        printf("skipped\n");
        memset(res + 2, 0x77, 8);
    }

    printf("%-40s", "Testing vmovaps (%edx),%ymm7...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovaps_from_mem);

        asm volatile ( "vxorps %%ymm7, %%ymm7, %%ymm7\n"
                       put_insn(vmovaps_from_mem, "vmovaps (%0), %%ymm7")
                       :: "d" (NULL) );

        set_insn(vmovaps_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovaps_from_mem) )
            goto fail;
        asm ( "vcmpeqps %1, %%ymm7, %%ymm0\n\t"
              "vmovmskps %%ymm0, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovsd %xmm5,16(%ecx){%k3}...");
    memset(res, 0x88, 128);
    memset(res + 20, 0x77, 8);
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(vmovsd_masked_to_mem);

        asm volatile ( "vbroadcastsd %0, %%ymm5\n\t"
                       "kxorw %%k3, %%k3, %%k3\n"
                       put_insn(vmovsd_masked_to_mem,
                                "vmovsd %%xmm5, 16(%1)%{%%k3%}")
                       :: "m" (res[20]), "c" (NULL) );

        set_insn(vmovsd_masked_to_mem);
        regs.ecx = 0;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(vmovsd_masked_to_mem) )
            goto fail;

        asm volatile ( "kmovw %0, %%k3\n" :: "m" (res[20]) );

        set_insn(vmovsd_masked_to_mem);
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(vmovsd_masked_to_mem) ||
             memcmp(res, res + 16, 64) )
            goto fail;

        printf("okay\n");
    }
    else
    {
        printf("skipped\n");
        memset(res + 4, 0x77, 8);
    }

    printf("%-40s", "Testing vmovaps (%edx),%zmm7{%k3}{z}...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(vmovaps_masked_from_mem);

        asm volatile ( "vpcmpeqd %%xmm7, %%xmm7, %%xmm7\n\t"
                       "vbroadcastss %%xmm7, %%zmm7\n"
                       put_insn(vmovaps_masked_from_mem,
                                "vmovaps (%0), %%zmm7%{%%k3%}%{z%}")
                       :: "d" (NULL) );

        set_insn(vmovaps_masked_from_mem);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovaps_masked_from_mem) )
            goto fail;
        asm ( "vcmpeqps %1, %%zmm7, %%k0\n\t"
              "vxorps %%xmm0, %%xmm0, %%xmm0\n\t"
              "vcmpeqps %%zmm0, %%zmm7, %%k1\n\t"
              "kxorw %%k1, %%k0, %%k0\n\t"
              "kmovw %%k0, %0" : "=r" (rc) : "m" (res[16]) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %mm3,32(%ecx)...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_to_mem);

        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movd_to_mem, "movd %%mm3, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(movd_to_mem);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_to_mem) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd 32(%ecx),%mm4...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_from_mem);

        asm volatile ( "pcmpgtb %%mm4, %%mm4\n"
                       put_insn(movd_from_mem, "movd 32(%0), %%mm4")
                       :: "c" (NULL) );

        set_insn(movd_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_from_mem) )
            goto fail;
        asm ( "pxor %%mm2,%%mm2\n\t"
              "pcmpeqb %%mm4, %%mm2\n\t"
              "pmovmskb %%mm2, %0" : "=r" (rc) );
        if ( rc != 0xf0 )
            goto fail;
        asm ( "pcmpeqb %%mm4, %%mm3\n\t"
              "pmovmskb %%mm3, %0" : "=r" (rc) );
        if ( rc != 0x0f )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %xmm2,32(%edx)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_to_mem2);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movd_to_mem2, "movd %%xmm2, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(movd_to_mem2);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_to_mem2) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd 32(%edx),%xmm3...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_from_mem2);

        asm volatile ( "pcmpeqb %%xmm3, %%xmm3\n"
                       put_insn(movd_from_mem2, "movd 32(%0), %%xmm3")
                       :: "d" (NULL) );

        set_insn(movd_from_mem2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_from_mem2) )
            goto fail;
        asm ( "pxor %%xmm1,%%xmm1\n\t"
              "pcmpeqb %%xmm3, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm3, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0x000f )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovd %xmm1,32(%ecx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_to_mem);

        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(vmovd_to_mem, "vmovd %%xmm1, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(vmovd_to_mem);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovd_to_mem) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovd 32(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_from_mem);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(vmovd_from_mem, "vmovd 32(%0), %%xmm2")
                       :: "c" (NULL) );

        set_insn(vmovd_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovd_from_mem) )
            goto fail;
        asm ( "pxor %%xmm0,%%xmm0\n\t"
              "pcmpeqb %%xmm2, %%xmm0\n\t"
              "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm1, %%xmm1\n\t"
              "pcmpeqb %%xmm2, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0x000f )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovd %xmm3,32(%ecx)...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovd_to_mem);

        asm volatile ( "pcmpeqb %%xmm3, %%xmm3\n"
                       put_insn(evex_vmovd_to_mem,
                                "%{evex%} vmovd %%xmm3, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(evex_vmovd_to_mem);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovd_to_mem) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovd 32(%ecx),%xmm4...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovd_from_mem);

        asm volatile ( "pcmpeqb %%xmm4, %%xmm4\n"
                       put_insn(evex_vmovd_from_mem,
                                "%{evex%} vmovd 32(%0), %%xmm4")
                       :: "c" (NULL) );

        set_insn(evex_vmovd_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovd_from_mem) )
            goto fail;
        asm ( "vmovd %1, %%xmm0\n\t"
              "vpcmpeqd %%zmm4, %%zmm0, %%k0\n\t"
              "kmovw %%k0, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %mm3,%ebx...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_to_reg);

        /*
         * Intentionally not specifying "b" as an input (or even output) here
         * to not keep the compiler from using the variable, which in turn
         * allows noticing whether the emulator touches the actual register
         * instead of the regs field.
         */
        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movd_to_reg, "movd %%mm3, %%ebx")
                       :: );

        set_insn(movd_to_reg);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_to_reg) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %ebx,%mm4...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_from_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%mm4, %%mm4\n"
                       put_insn(movd_from_reg, "movd %%ebx, %%mm4")
                       :: );

        set_insn(movd_from_reg);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_from_reg) )
            goto fail;
        asm ( "pxor %%mm2,%%mm2\n\t"
              "pcmpeqb %%mm4, %%mm2\n\t"
              "pmovmskb %%mm2, %0" : "=r" (rc) );
        if ( rc != 0xf0 )
            goto fail;
        asm ( "pcmpeqb %%mm4, %%mm3\n\t"
              "pmovmskb %%mm3, %0" : "=r" (rc) );
        if ( rc != 0x0f )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %xmm2,%ebx...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_to_reg2);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movd_to_reg2, "movd %%xmm2, %%ebx")
                       :: );

        set_insn(movd_to_reg2);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_to_reg2) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %ebx,%xmm3...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_from_reg2);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%xmm3, %%xmm3\n"
                       put_insn(movd_from_reg2, "movd %%ebx, %%xmm3")
                       :: );

        set_insn(movd_from_reg2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_from_reg2) )
            goto fail;
        asm ( "pxor %%xmm1,%%xmm1\n\t"
              "pcmpeqb %%xmm3, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm3, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0x000f )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovd %xmm1,%ebx...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(vmovd_to_reg, "vmovd %%xmm1, %%ebx")
                       :: );

        set_insn(vmovd_to_reg);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(vmovd_to_reg) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovd %ebx,%xmm2...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_from_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%xmm2, %%xmm2\n"
                       put_insn(vmovd_from_reg, "vmovd %%ebx, %%xmm2")
                       :: );

        set_insn(vmovd_from_reg);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(vmovd_from_reg) )
            goto fail;
        asm ( "pxor %%xmm0,%%xmm0\n\t"
              "pcmpeqb %%xmm2, %%xmm0\n\t"
              "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm1, %%xmm1\n\t"
              "pcmpeqb %%xmm2, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0x000f )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovd %xmm2,%ebx...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovd_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(evex_vmovd_to_reg,
                                "%{evex%} vmovd %%xmm2, %%ebx")
                       :: );

        set_insn(evex_vmovd_to_reg);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(evex_vmovd_to_reg) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovd %ebx,%xmm1...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovd_from_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%xmm1, %%xmm1\n"
                       put_insn(evex_vmovd_from_reg,
                                "%{evex%} vmovd %%ebx, %%xmm1")
                       :: );

        set_insn(evex_vmovd_from_reg);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(evex_vmovd_from_reg) )
            goto fail;
        asm ( "vmovd %1, %%xmm0\n\t"
              "vpcmpeqd %%zmm1, %%zmm0, %%k0\n\t"
              "kmovw %%k0, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

#ifdef __x86_64__
    printf("%-40s", "Testing movq %mm3,32(%ecx)...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_to_mem3);

        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movq_to_mem3, "rex64 movd %%mm3, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(movq_to_mem3);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_to_mem3) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %xmm2,32(%edx)...");
    if ( stack_exec )
    {
        decl_insn(movq_to_mem4);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movq_to_mem4, "rex64 movd %%xmm2, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(movq_to_mem4);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_to_mem4) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %xmm1,32(%ecx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_to_mem2);

        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
#if 0 /* This doesn't work, as the assembler will pick opcode D6. */
                       put_insn(vmovq_to_mem2, "vmovq %%xmm1, 32(%0)")
#else
                       put_insn(vmovq_to_mem2, ".byte 0xc4, 0xe1, 0xf9, 0x7e, 0x49, 0x20")
#endif
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(vmovq_to_mem2);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovq_to_mem2) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing {evex} vmovq %xmm11,32(%ecx)...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovq_to_mem2);

        asm volatile ( "pcmpeqb %%xmm11, %%xmm11\n"
#if 0 /* This may not work, as the assembler might pick opcode D6. */
                       put_insn(evex_vmovq_to_mem2,
                                "{evex} vmovq %%xmm11, 32(%0)")
#else
                       put_insn(evex_vmovq_to_mem2,
                                ".byte 0x62, 0xf1, 0xfd, 0x08, 0x7e, 0x49, 0x04")
#endif
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(evex_vmovq_to_mem2);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovq_to_mem2) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %mm3,%rbx...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movq_to_reg, "movq %%mm3, %%rbx")
                       :: );

        set_insn(movq_to_reg);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || regs.rbx + 1 || !check_eip(movq_to_reg) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %xmm2,%rbx...");
    if ( stack_exec )
    {
        decl_insn(movq_to_reg2);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movq_to_reg2, "movq %%xmm2, %%rbx")
                       :: );

        set_insn(movq_to_reg2);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || regs.rbx + 1 || !check_eip(movq_to_reg2) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %xmm1,%rbx...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(vmovq_to_reg, "vmovq %%xmm1, %%rbx")
                       :: );

        set_insn(vmovq_to_reg);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || regs.rbx + 1 || !check_eip(vmovq_to_reg) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %xmm22,%rbx...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovq_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqq %%xmm2, %%xmm2\n\t"
                       "vmovq %%xmm2, %%xmm22\n"
                       put_insn(evex_vmovq_to_reg, "vmovq %%xmm22, %%rbx")
                       :: );

        set_insn(evex_vmovq_to_reg);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovq_to_reg) ||
             regs.rbx + 1 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");
#endif

    printf("%-40s", "Testing maskmovq %mm4,%mm4...");
    if ( stack_exec && cpu_has_sse )
    {
        decl_insn(maskmovq);

        asm volatile ( "pcmpgtb %mm4, %mm4\n"
                       put_insn(maskmovq, "maskmovq %mm4, %mm4") );

        set_insn(maskmovq);
        regs.edi = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(maskmovq) )
            goto fail;

        asm volatile ( "pcmpeqb %mm3, %mm3\n\t"
                       "punpcklbw %mm3, %mm4\n" );
        memset(res, 0x55, 24);

        set_insn(maskmovq);
        regs.edi = (unsigned long)(res + 2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(maskmovq) ||
             memcmp(res, res + 4, 8) ||
             res[2] != 0xff55ff55 || res[3] != 0xff55ff55 )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing maskmovdqu %xmm3,%xmm3...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(maskmovdqu);

        asm volatile ( "pcmpgtb %xmm3, %xmm3\n"
                       put_insn(maskmovdqu, "maskmovdqu %xmm3, %xmm3") );

        set_insn(maskmovdqu);
        regs.edi = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(maskmovdqu) )
            goto fail;

        asm volatile ( "pcmpeqb %xmm4, %xmm4\n\t"
                       "punpcklbw %xmm4, %xmm3\n" );
        memset(res, 0x55, 48);

        set_insn(maskmovdqu);
        regs.edi = (unsigned long)(res + 4);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(maskmovdqu) ||
             memcmp(res, res + 8, 16) ||
             res[4] != 0xff55ff55 || res[5] != 0xff55ff55 ||
             res[6] != 0xff55ff55 || res[7] != 0xff55ff55 )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing lddqu 4(%edx),%xmm4...");
    if ( stack_exec && cpu_has_sse3 )
    {
        decl_insn(lddqu);

        asm volatile ( "pcmpgtb %%xmm4, %%xmm4\n"
                       put_insn(lddqu, "lddqu 4(%0), %%xmm4")
                       :: "d" (NULL) );

        set_insn(lddqu);
        memset(res, 0x55, 64);
        memset(res + 1, 0xff, 16);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(lddqu) )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm4, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vlddqu (%ecx),%ymm4...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vlddqu);

        asm volatile ( "vpxor %%xmm4, %%xmm4, %%xmm4\n"
                       put_insn(vlddqu, "vlddqu (%0), %%ymm4")
                       :: "c" (NULL) );

        set_insn(vlddqu);
        memset(res + 1, 0xff, 32);
        regs.ecx = (unsigned long)(res + 1);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vlddqu) )
            goto fail;
        asm ( "vextractf128 $1, %%ymm4, %%xmm3\n\t"
              "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n\t"
              "vpcmpeqb %%xmm4, %%xmm2, %%xmm0\n\t"
              "vpcmpeqb %%xmm3, %%xmm2, %%xmm1\n\t"
              "vpmovmskb %%xmm0, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        rc |= i << 16;
        if ( ~rc )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movntdqa 16(%edx),%xmm4...");
    if ( stack_exec && cpu_has_sse4_1 )
    {
        decl_insn(movntdqa);

        asm volatile ( "pcmpgtb %%xmm4, %%xmm4\n"
                       put_insn(movntdqa, "movntdqa 16(%0), %%xmm4")
                       :: "d" (NULL) );

        set_insn(movntdqa);
        memset(res, 0x55, 64);
        memset(res + 4, 0xff, 16);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movntdqa) )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm4, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovntdqa (%ecx),%ymm4...");
    if ( stack_exec && cpu_has_avx2 )
    {
        decl_insn(vmovntdqa);

        asm volatile ( "vpxor %%ymm4, %%ymm4, %%ymm4\n"
                       put_insn(vmovntdqa, "vmovntdqa (%0), %%ymm4")
                       :: "c" (NULL) );

        set_insn(vmovntdqa);
        memset(res, 0x55, 96);
        memset(res + 8, 0xff, 32);
        regs.ecx = (unsigned long)(res + 8);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovntdqa) )
            goto fail;
        asm ( "vpcmpeqb %%ymm2, %%ymm2, %%ymm2\n\t"
              "vpcmpeqb %%ymm4, %%ymm2, %%ymm0\n\t"
              "vpmovmskb %%ymm0, %0" : "=r" (rc) );
        if ( ~rc )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovntdqa 64(%ecx),%zmm4...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vmovntdqa);

        asm volatile ( "vpxor %%xmm4, %%xmm4, %%xmm4\n"
                       put_insn(evex_vmovntdqa, "vmovntdqa 64(%0), %%zmm4")
                       :: "c" (NULL) );

        set_insn(evex_vmovntdqa);
        memset(res, 0x55, 192);
        memset(res + 16, 0xff, 64);
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vmovntdqa) )
            goto fail;
        asm ( "vpbroadcastd %1, %%zmm2\n\t"
              "vpcmpeqd %%zmm4, %%zmm2, %%k0\n\t"
              "kmovw %%k0, %0" : "=r" (rc) : "0" (~0) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpestri $0x1a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpestri);

        memcpy(res, "abcdefgh\0\1\2\3\4\5\6\7", 16);
        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpestri, "pcmpestri $0b00011010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpestri);
        regs.eax = regs.edx = 12;
        regs.ecx = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpestri) ||
             regs.ecx != 9 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_CF | X86_EFLAGS_ZF | X86_EFLAGS_SF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpestrm $0x5a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpestrm);

        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpestrm, "pcmpestrm $0b01011010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpestrm);
        regs.ecx = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpestrm) )
            goto fail;
        asm ( "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0x0e00 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_CF | X86_EFLAGS_ZF | X86_EFLAGS_SF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpistri $0x1a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpistri);

        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpistri, "pcmpistri $0b00011010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpistri);
        regs.eflags = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpistri) ||
             regs.ecx != 16 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_ZF | X86_EFLAGS_SF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpistrm $0x4a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpistrm);

        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpistrm, "pcmpistrm $0b01001010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpistrm);
        regs.ecx = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_IF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpistrm) )
            goto fail;
        asm ( "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xffff ||
            (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
            (X86_EFLAGS_CF | X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vpcmpestri $0x7a,(%esi),%xmm2...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vpcmpestri);

        asm volatile ( "movq %0, %%xmm2\n"
#ifdef __x86_64__
                       put_insn(vpcmpestri,
                                "vpcmpestriq $0b01111010, (%1), %%xmm2")
#else
                       put_insn(vpcmpestri,
                                "vpcmpestri $0b01111010, (%1), %%xmm2")
#endif
                       :: "m" (res[0]), "S" (NULL) );

        set_insn(vpcmpestri);
#ifdef __x86_64__
        regs.rax = ~0U + 1UL;
        regs.rcx = ~0UL;
#else
        regs.eax = 0x7fffffff;
#endif
        regs.esi = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_SF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpcmpestri) ||
             regs.ecx != 11 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_ZF | X86_EFLAGS_CF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing extrq $4,$56,%xmm2...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(extrq_imm);

        res[0] = 0x44332211;
        res[1] = 0x88776655;
        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(extrq_imm, "extrq $4, $56, %%xmm2")
                       :: "m" (res[0]) : "memory" );

        set_insn(extrq_imm);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm2, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(extrq_imm) ||
             res[4] != 0x54433221 || res[5] != 0x877665 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing extrq %xmm3,%xmm2...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(extrq_reg);

        res[4] = 56 + (4 << 8);
        res[5] = 0;
        asm volatile ( "movq %0, %%xmm2\n"
                       "movq %1, %%xmm3\n"
                       put_insn(extrq_reg, "extrq %%xmm3, %%xmm2")
                       :: "m" (res[0]), "m" (res[4]) : "memory" );

        set_insn(extrq_reg);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm2, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(extrq_reg) ||
             res[4] != 0x54433221 || res[5] != 0x877665 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing insertq $12,$40,%xmm2,%xmm3...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(insertq_imm);

        res[4] = 0xccbbaa99;
        res[5] = 0x00ffeedd;
        asm volatile ( "movq %1, %%xmm2\n"
                       "movq %0, %%xmm3\n"
                       put_insn(insertq_imm, "insertq $12, $40, %%xmm2, %%xmm3")
                       :: "m" (res[0]), "m" (res[4]) : "memory" );

        set_insn(insertq_imm);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm3, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(insertq_imm) ||
             res[4] != 0xbaa99211 || res[5] != 0x887ddccb )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing insertq %xmm2,%xmm3...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(insertq_reg);

        res[4] = 0xccbbaa99;
        res[5] = 0x00ffeedd;
        res[6] = 40 + (12 << 8);
        res[7] = 0;
        asm volatile ( "movdqu %1, %%xmm2\n"
                       "movq %0, %%xmm3\n"
                       put_insn(insertq_reg, "insertq %%xmm2, %%xmm3")
                       :: "m" (res[0]), "m" (res[4]) : "memory" );

        set_insn(insertq_reg);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm3, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(insertq_reg) ||
             res[4] != 0xbaa99211 || res[5] != 0x887ddccb )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    /*
     * The following "maskmov" tests are not only making sure the written data
     * is correct, but verify (by placing operands on the mapping boundaries)
     * that elements controlled by clear mask bits aren't being accessed.
     */
    printf("%-40s", "Testing vmaskmovps %xmm1,%xmm2,(%edx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmaskmovps);

        asm volatile ( "vxorps %%xmm1, %%xmm1, %%xmm1\n\t"
                       "vcmpeqss %%xmm1, %%xmm1, %%xmm2\n\t"
                       put_insn(vmaskmovps, "vmaskmovps %%xmm1, %%xmm2, (%0)")
                       :: "d" (NULL) );

        memset(res + MMAP_SZ / sizeof(*res) - 8, 0xdb, 32);
        set_insn(vmaskmovps);
        regs.edx = (unsigned long)res + MMAP_SZ - 4;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovps) ||
             res[MMAP_SZ / sizeof(*res) - 1] ||
             memcmp(res + MMAP_SZ / sizeof(*res) - 8,
                    res + MMAP_SZ / sizeof(*res) - 4, 12) )
            goto fail;

        asm volatile ( "vinsertps $0b00110111, %xmm2, %xmm2, %xmm2" );
        memset(res, 0xdb, 32);
        set_insn(vmaskmovps);
        regs.edx = (unsigned long)(res - 3);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovps) ||
             res[0] || memcmp(res + 1, res + 4, 12) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmaskmovpd %xmm1,%xmm2,(%edx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmaskmovpd);

        asm volatile ( "vxorpd %%xmm1, %%xmm1, %%xmm1\n\t"
                       "vcmpeqsd %%xmm1, %%xmm1, %%xmm2\n\t"
                       put_insn(vmaskmovpd, "vmaskmovpd %%xmm1, %%xmm2, (%0)")
                       :: "d" (NULL) );

        memset(res + MMAP_SZ / sizeof(*res) - 8, 0xdb, 32);
        set_insn(vmaskmovpd);
        regs.edx = (unsigned long)res + MMAP_SZ - 8;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovpd) ||
             res[MMAP_SZ / sizeof(*res) - 1] ||
             res[MMAP_SZ / sizeof(*res) - 2] ||
             memcmp(res + MMAP_SZ / sizeof(*res) - 8,
                    res + MMAP_SZ / sizeof(*res) - 4, 8) )
            goto fail;

        asm volatile ( "vmovddup %xmm2, %xmm2\n\t"
                       "vmovsd %xmm1, %xmm2, %xmm2" );
        memset(res, 0xdb, 32);
        set_insn(vmaskmovpd);
        regs.edx = (unsigned long)(res - 2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovpd) ||
             res[0] || res[1] || memcmp(res + 2, res + 4, 8) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vpmaskmovd %xmm1,%xmm2,(%edx)...");
    if ( stack_exec && cpu_has_avx2 )
    {
        decl_insn(vpmaskmovd);

        asm volatile ( "vpxor %%xmm1, %%xmm1, %%xmm1\n\t"
                       "vpinsrd $0b00, %1, %%xmm1, %%xmm2\n\t"
                       put_insn(vpmaskmovd, "vpmaskmovd %%xmm1, %%xmm2, (%0)")
                       :: "d" (NULL), "r" (~0) );

        memset(res + MMAP_SZ / sizeof(*res) - 8, 0xdb, 32);
        set_insn(vpmaskmovd);
        regs.edx = (unsigned long)res + MMAP_SZ - 4;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpmaskmovd) ||
             res[MMAP_SZ / sizeof(*res) - 1] ||
             memcmp(res + MMAP_SZ / sizeof(*res) - 8,
                    res + MMAP_SZ / sizeof(*res) - 4, 12) )
            goto fail;

        asm volatile ( "vpinsrd $0b11, %0, %%xmm1, %%xmm2" :: "r" (~0) );
        memset(res, 0xdb, 32);
        set_insn(vpmaskmovd);
        regs.edx = (unsigned long)(res - 3);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpmaskmovd) ||
             res[0] || memcmp(res + 1, res + 4, 12) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vpmaskmovq %xmm1,%xmm2,(%edx)...");
    if ( stack_exec && cpu_has_avx2 )
    {
        decl_insn(vpmaskmovq);

        asm volatile ( "vpxor %%xmm1, %%xmm1, %%xmm1\n\t"
                       "vpcmpeqd %%xmm0, %%xmm0, %%xmm0\n\t"
                       "vpblendd $0b0011, %%xmm0, %%xmm1, %%xmm2\n\t"
                       put_insn(vpmaskmovq, "vpmaskmovq %%xmm1, %%xmm2, (%0)")
                       :: "d" (NULL) );

        memset(res + MMAP_SZ / sizeof(*res) - 8, 0xdb, 32);
        set_insn(vpmaskmovq);
        regs.edx = (unsigned long)res + MMAP_SZ - 8;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpmaskmovq) ||
             res[MMAP_SZ / sizeof(*res) - 1] ||
             res[MMAP_SZ / sizeof(*res) - 2] ||
             memcmp(res + MMAP_SZ / sizeof(*res) - 8,
                    res + MMAP_SZ / sizeof(*res) - 4, 8) )
            goto fail;

        asm volatile ( "vpermq $0b00000001, %ymm2, %ymm2" );
        memset(res, 0xdb, 32);
        set_insn(vpmaskmovq);
        regs.edx = (unsigned long)(res - 2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpmaskmovq) ||
             res[0] || res[1] || memcmp(res + 2, res + 4, 8) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing stmxcsr (%edx)...");
    if ( cpu_has_sse )
    {
        decl_insn(stmxcsr);

        asm volatile ( put_insn(stmxcsr, "stmxcsr (%0)") :: "d" (NULL) );

        res[0] = 0x12345678;
        res[1] = 0x87654321;
        asm ( "stmxcsr %0" : "=m" (res[2]) );
        set_insn(stmxcsr);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(stmxcsr) ||
             res[0] != res[2] || res[1] != 0x87654321 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing ldmxcsr 4(%ecx)...");
    if ( cpu_has_sse )
    {
        decl_insn(ldmxcsr);

        asm volatile ( put_insn(ldmxcsr, "ldmxcsr 4(%0)") :: "c" (NULL) );

        set_insn(ldmxcsr);
        res[1] = mxcsr_mask;
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "stmxcsr %0; ldmxcsr %1" : "=m" (res[0]) : "m" (res[2]) );
        if ( rc != X86EMUL_OKAY || !check_eip(ldmxcsr) ||
             res[0] != mxcsr_mask )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vstmxcsr (%ecx)...");
    if ( cpu_has_avx )
    {
        decl_insn(vstmxcsr);

        asm volatile ( put_insn(vstmxcsr, "vstmxcsr (%0)") :: "c" (NULL) );

        res[0] = 0x12345678;
        res[1] = 0x87654321;
        set_insn(vstmxcsr);
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vstmxcsr) ||
             res[0] != res[2] || res[1] != 0x87654321 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vldmxcsr 4(%edx)...");
    if ( cpu_has_avx )
    {
        decl_insn(vldmxcsr);

        asm volatile ( put_insn(vldmxcsr, "vldmxcsr 4(%0)") :: "d" (NULL) );

        set_insn(vldmxcsr);
        res[1] = mxcsr_mask;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "stmxcsr %0; ldmxcsr %1" : "=m" (res[0]) : "m" (res[2]) );
        if ( rc != X86EMUL_OKAY || !check_eip(vldmxcsr) ||
             res[0] != mxcsr_mask )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

#ifdef __x86_64__
    printf("%-40s", "Testing vzeroupper (compat)...");
    if ( cpu_has_avx )
    {
        decl_insn(vzeroupper);

        ctxt.lma = false;
        ctxt.sp_size = ctxt.addr_size = 32;

        asm volatile ( "vxorps %xmm2, %xmm2, %xmm3\n"
                       "vcmpeqps %ymm3, %ymm3, %ymm4\n"
                       "vmovaps %ymm4, %ymm9\n"
                       put_insn(vzeroupper, "vzeroupper") );

        set_insn(vzeroupper);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vzeroupper) )
            goto fail;

        /* XMM0...XMM7 should have their high parts cleared. */
        asm ( "vextractf128 $1, %%ymm4, %%xmm0\n\t"
              "vpmovmskb %%xmm4, %0\n\t"
              "vpmovmskb %%xmm0, %1" : "=r" (rc), "=r" (i) );
        if ( rc != 0xffff || i )
            goto fail;

        /* XMM8...XMM15 should have their high parts preserved. */
        asm ( "vextractf128 $1, %%ymm9, %%xmm1\n\t"
              "vpmovmskb %%xmm9, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        if ( rc != 0xffff || i != 0xffff )
            goto fail;
        printf("okay\n");

        ctxt.lma = true;
        ctxt.sp_size = ctxt.addr_size = 64;
    }
    else
        printf("skipped\n");
#endif

    printf("%-40s", "Testing vcvtph2ps (%ecx),%ymm1...");
    if ( stack_exec && cpu_has_f16c )
    {
        decl_insn(vcvtph2ps);
        decl_insn(vcvtps2ph);

        asm volatile ( "vxorps %%xmm1, %%xmm1, %%xmm1\n"
                       put_insn(vcvtph2ps, "vcvtph2ps (%0), %%ymm1")
                       :: "c" (NULL) );

        set_insn(vcvtph2ps);
        res[1] = 0x40003c00; /* (1.0, 2.0) */
        res[2] = 0x44004200; /* (3.0, 4.0) */
        res[3] = 0x3400b800; /* (-.5, .25) */
        res[4] = 0xbc000000; /* (0.0, -1.) */
        memset(res + 5, 0xff, 16);
        regs.ecx = (unsigned long)(res + 1);
        rc = x86_emulate(&ctxt, &emulops);
        asm volatile ( "vmovups %%ymm1, %0" : "=m" (res[16]) );
        if ( rc != X86EMUL_OKAY || !check_eip(vcvtph2ps) )
            goto fail;
        printf("okay\n");

        printf("%-40s", "Testing vcvtps2ph $0,%ymm1,(%edx)...");
        asm volatile ( "vmovups %0, %%ymm1\n"
                       put_insn(vcvtps2ph, "vcvtps2ph $0, %%ymm1, (%1)")
                       :: "m" (res[16]), "d" (NULL) );

        set_insn(vcvtps2ph);
        memset(res + 7, 0, 32);
        regs.edx = (unsigned long)(res + 7);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vcvtps2ph) ||
             memcmp(res + 1, res + 7, 16) ||
             res[11] || res[12] || res[13] || res[14] )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vcvtph2ps 32(%ecx),%zmm7{%k4}...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(evex_vcvtph2ps);
        decl_insn(evex_vcvtps2ph);

        asm volatile ( "vpternlogd $0x81, %%zmm7, %%zmm7, %%zmm7\n\t"
                       "kmovw %1,%%k4\n"
                       put_insn(evex_vcvtph2ps, "vcvtph2ps 32(%0), %%zmm7%{%%k4%}")
                       :: "c" (NULL), "r" (0x3333) );

        set_insn(evex_vcvtph2ps);
        memset(res, 0xff, 128);
        res[8] = 0x40003c00; /* (1.0, 2.0) */
        res[10] = 0x44004200; /* (3.0, 4.0) */
        res[12] = 0x3400b800; /* (-.5, .25) */
        res[14] = 0xbc000000; /* (0.0, -1.) */
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm volatile ( "vmovups %%zmm7, %0" : "=m" (res[16]) );
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vcvtph2ps) )
            goto fail;
        printf("okay\n");

        printf("%-40s", "Testing vcvtps2ph $0,%zmm3,64(%edx){%k4}...");
        asm volatile ( "vmovups %0, %%zmm3\n"
                       put_insn(evex_vcvtps2ph, "vcvtps2ph $0, %%zmm3, 128(%1)%{%%k4%}")
                       :: "m" (res[16]), "d" (NULL) );

        set_insn(evex_vcvtps2ph);
        regs.edx = (unsigned long)res;
        memset(res + 32, 0xcc, 32);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(evex_vcvtps2ph) )
            goto fail;
        res[15] = res[13] = res[11] = res[9] = 0xcccccccc;
        if ( memcmp(res + 8, res + 32, 32) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vfixupimmpd $0,8(%edx){1to8},%zmm3,%zmm4...");
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(vfixupimmpd);
        static const struct {
            double d[4];
        }
        src = { { -1, 0, 1, 2 } },
        dst = { { 3, 4, 5, 6 } },
        out = { { .5, -1, 90, 2 } };

        asm volatile ( "vbroadcastf64x4 %1, %%zmm3\n\t"
                       "vbroadcastf64x4 %2, %%zmm4\n"
                       put_insn(vfixupimmpd,
                                "vfixupimmpd $0, 8(%0)%{1to8%}, %%zmm3, %%zmm4")
                       :: "d" (NULL), "m" (src), "m" (dst) );

        set_insn(vfixupimmpd);
        /*
         * Nibble (token) mapping (unused ones simply set to zero):
         * 2 (ZERO)    ->  -1 (0x9)
         * 3 (POS_ONE) ->  90 (0xc)
         * 6 (NEG)     -> 1/2 (0xb)
         * 7 (POS)     -> src (0x1)
         */
        res[2] = 0x1b00c900;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm volatile ( "vmovupd %%zmm4, %0" : "=m" (res[0]) );
        if ( rc != X86EMUL_OKAY || !check_eip(vfixupimmpd) ||
             memcmp(res + 0, &out, sizeof(out)) ||
             memcmp(res + 8, &out, sizeof(out)) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");


    printf("%-40s", "Testing vfpclasspsz $0x46,64(%edx),%k2...");
    if ( stack_exec && cpu_has_avx512dq )
    {
        decl_insn(vfpclassps);

        asm volatile ( put_insn(vfpclassps,
                                /* 0x46: check for +/- 0 and neg. */
                                "vfpclasspsz $0x46, 64(%0), %%k2")
                       :: "d" (NULL) );

        set_insn(vfpclassps);
        for ( i = 0; i < 3; ++i )
        {
            res[16 + i * 5 + 0] = 0x00000000; /* +0 */
            res[16 + i * 5 + 1] = 0x80000000; /* -0 */
            res[16 + i * 5 + 2] = 0x80000001; /* -DEN */
            res[16 + i * 5 + 3] = 0xff000000; /* -FIN */
            res[16 + i * 5 + 4] = 0x7f000000; /* +FIN */
        }
        res[31] = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vfpclassps) )
            goto fail;
        asm volatile ( "kmovw %%k2, %0" : "=g" (rc) );
        if ( rc != 0xbdef )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    /*
     * The following compress/expand tests are not only making sure the
     * accessed data is correct, but they also verify (by placing operands
     * on the mapping boundaries) that elements controlled by clear mask
     * bits don't get accessed.
     */
    if ( stack_exec && cpu_has_avx512f )
    {
        decl_insn(vpcompressd);
        decl_insn(vpcompressq);
        decl_insn(vpexpandd);
        decl_insn(vpexpandq);
        static const struct {
            unsigned int d[16];
        } dsrc = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } };
        static const struct {
            unsigned long long q[8];
        } qsrc = { { 0, 1, 2, 3, 4, 5, 6, 7 } };
        unsigned int *ptr = res + MMAP_SZ / sizeof(*res) - 32;

        printf("%-40s", "Testing vpcompressd %zmm1,24*4(%ecx){%k2}...");
        asm volatile ( "kmovw %1, %%k2\n\t"
                       "vmovdqu32 %2, %%zmm1\n"
                       put_insn(vpcompressd,
                                "vpcompressd %%zmm1, 24*4(%0)%{%%k2%}")
                       :: "c" (NULL), "r" (0x55aa), "m" (dsrc) );

        memset(ptr, 0xdb, 32 * 4);
        set_insn(vpcompressd);
        regs.ecx = (unsigned long)ptr;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpcompressd) ||
             memcmp(ptr, ptr + 8, 16 * 4) )
            goto fail;
        for ( i = 0; i < 4; ++i )
            if ( ptr[24 + i] != 2 * i + 1 )
                goto fail;
        for ( ; i < 8; ++i )
            if ( ptr[24 + i] != 2 * i )
                goto fail;
        printf("okay\n");

        printf("%-40s", "Testing vpexpandd 8*4(%edx),%zmm3{%k2}{z}...");
        asm volatile ( "vpternlogd $0x81, %%zmm3, %%zmm3, %%zmm3\n"
                       put_insn(vpexpandd,
                                "vpexpandd 8*4(%0), %%zmm3%{%%k2%}%{z%}")
                       :: "d" (NULL) );
        set_insn(vpexpandd);
        regs.edx = (unsigned long)(ptr + 16);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpexpandd) )
            goto fail;
        asm ( "vmovdqa32 %%zmm1, %%zmm2%{%%k2%}%{z%}\n\t"
              "vpcmpeqd %%zmm2, %%zmm3, %%k0\n\t"
              "kmovw %%k0, %0"
              : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");

        printf("%-40s", "Testing vpcompressq %zmm4,12*8(%edx){%k3}...");
        asm volatile ( "kmovw %1, %%k3\n\t"
                       "vmovdqu64 %2, %%zmm4\n"
                       put_insn(vpcompressq,
                                "vpcompressq %%zmm4, 12*8(%0)%{%%k3%}")
                       :: "d" (NULL), "r" (0x5a), "m" (qsrc) );

        memset(ptr, 0xdb, 16 * 8);
        set_insn(vpcompressq);
        regs.edx = (unsigned long)ptr;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpcompressq) ||
             memcmp(ptr, ptr + 8, 8 * 8) )
            goto fail;
        for ( i = 0; i < 2; ++i )
        {
            if ( ptr[(12 + i) * 2] != 2 * i + 1 ||
                 ptr[(12 + i) * 2 + 1] )
                goto fail;
        }
        for ( ; i < 4; ++i )
        {
            if ( ptr[(12 + i) * 2] != 2 * i ||
                 ptr[(12 + i) * 2 + 1] )
                goto fail;
        }
        printf("okay\n");

        printf("%-40s", "Testing vpexpandq 4*8(%ecx),%zmm5{%k3}{z}...");
        asm volatile ( "vpternlogq $0x81, %%zmm5, %%zmm5, %%zmm5\n"
                       put_insn(vpexpandq,
                                "vpexpandq 4*8(%0), %%zmm5%{%%k3%}%{z%}")
                       :: "c" (NULL) );
        set_insn(vpexpandq);
        regs.ecx = (unsigned long)(ptr + 16);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpexpandq) )
            goto fail;
        asm ( "vmovdqa64 %%zmm4, %%zmm6%{%%k3%}%{z%}\n\t"
              "vpcmpeqq %%zmm5, %%zmm6, %%k0\n\t"
              "kmovw %%k0, %0"
              : "=r" (rc) );
        if ( rc != 0xff )
            goto fail;
        printf("okay\n");
    }

#if __GNUC__ > 7 /* can't check for __AVX512VBMI2__ here */
    if ( stack_exec && cpu_has_avx512_vbmi2 )
    {
        decl_insn(vpcompressb);
        decl_insn(vpcompressw);
        decl_insn(vpexpandb);
        decl_insn(vpexpandw);
        static const struct {
            unsigned char b[64];
        } bsrc = { { 0,  1,  2,  3,  4,  5,  6,  7,
                     8,  9, 10, 11, 12, 13, 14, 15,
                    16, 17, 18, 19, 20, 21, 22, 23,
                    24, 25, 26, 27, 28, 29, 30, 31,
                    32, 33, 34, 35, 36, 37, 38, 39,
                    40, 41, 42, 43, 44, 45, 46, 47,
                    48, 49, 50, 51, 52, 53, 54, 55,
                    56, 57, 58, 59, 60, 61, 62, 63 } };
        static const struct {
            unsigned short w[32];
        } wsrc = { { 0,  1,  2,  3,  4,  5,  6,  7,
                     8,  9, 10, 11, 12, 13, 14, 15,
                    16, 17, 18, 19, 20, 21, 22, 23,
                    24, 25, 26, 27, 28, 29, 30, 31 } };
        unsigned char *ptr = (void *)res + MMAP_SZ - 128;
        unsigned long long w = 0x55555555aaaaaaaaULL;

        printf("%-40s", "Testing vpcompressb %zmm1,96*1(%ecx){%k2}...");
        asm volatile ( "kmovq %1, %%k2\n\t"
                       "vmovdqu8 %2, %%zmm1\n"
                       put_insn(vpcompressb,
                                "vpcompressb %%zmm1, 96*1(%0)%{%%k2%}")
                       :: "c" (NULL), "m" (w), "m" (bsrc) );

        memset(ptr, 0xdb, 128 * 1);
        set_insn(vpcompressb);
        regs.ecx = (unsigned long)ptr;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpcompressb) ||
             memcmp(ptr, ptr + 32, 64 * 1) )
            goto fail;
        for ( i = 0; i < 16; ++i )
            if ( ptr[96 + i] != 2 * i + 1 )
                goto fail;
        for ( ; i < 32; ++i )
            if ( ptr[96 + i] != 2 * i )
                goto fail;
        printf("okay\n");

        printf("%-40s", "Testing vpexpandb 32*1(%edx),%zmm3{%k2}{z}...");
        asm volatile ( "vpternlogd $0x81, %%zmm3, %%zmm3, %%zmm3\n"
                       put_insn(vpexpandb,
                                "vpexpandb 32*1(%0), %%zmm3%{%%k2%}%{z%}")
                       :: "d" (NULL) );
        set_insn(vpexpandb);
        regs.edx = (unsigned long)(ptr + 64);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpexpandb) )
            goto fail;
        asm ( "vmovdqu8 %%zmm1, %%zmm2%{%%k2%}%{z%}\n\t"
              "vpcmpeqb %%zmm2, %%zmm3, %%k0\n\t"
              "kmovq %%k0, %0"
              : "=m" (w) );
        if ( w != 0xffffffffffffffffULL )
            goto fail;
        printf("okay\n");

        printf("%-40s", "Testing vpcompressw %zmm4,48*2(%edx){%k3}...");
        asm volatile ( "kmovd %1, %%k3\n\t"
                       "vmovdqu16 %2, %%zmm4\n"
                       put_insn(vpcompressw,
                                "vpcompressw %%zmm4, 48*2(%0)%{%%k3%}")
                       :: "d" (NULL), "r" (0x5555aaaa), "m" (wsrc) );

        memset(ptr, 0xdb, 64 * 2);
        set_insn(vpcompressw);
        regs.edx = (unsigned long)ptr;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpcompressw) ||
             memcmp(ptr, ptr + 32, 32 * 2) )
            goto fail;
        for ( i = 0; i < 8; ++i )
        {
            if ( ptr[(48 + i) * 2] != 2 * i + 1 ||
                 ptr[(48 + i) * 2 + 1] )
                goto fail;
        }
        for ( ; i < 16; ++i )
        {
            if ( ptr[(48 + i) * 2] != 2 * i ||
                 ptr[(48 + i) * 2 + 1] )
                goto fail;
        }
        printf("okay\n");

        printf("%-40s", "Testing vpexpandw 16*2(%ecx),%zmm5{%k3}{z}...");
        asm volatile ( "vpternlogd $0x81, %%zmm5, %%zmm5, %%zmm5\n"
                       put_insn(vpexpandw,
                                "vpexpandw 16*2(%0), %%zmm5%{%%k3%}%{z%}")
                       :: "c" (NULL) );
        set_insn(vpexpandw);
        regs.ecx = (unsigned long)(ptr + 64);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpexpandw) )
            goto fail;
        asm ( "vmovdqu16 %%zmm4, %%zmm6%{%%k3%}%{z%}\n\t"
              "vpcmpeqw %%zmm5, %%zmm6, %%k0\n\t"
              "kmovq %%k0, %0"
              : "=m" (w) );
        if ( w != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
#endif

    printf("%-40s", "Testing v4fmaddps 32(%ecx),%zmm4,%zmm4{%k5}...");
    if ( stack_exec && cpu_has_avx512_4fmaps )
    {
        decl_insn(v4fmaddps);
        static const struct {
            float f[16];
        } in = {{
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        }}, out = {{
            1 + 1 * 9 + 2 * 10 + 3 * 11 + 4 * 12,
            2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16 + 16 * 9 + 17 * 10 + 18 * 11 + 19 * 12
        }};

        asm volatile ( "vmovups %1, %%zmm4\n\t"
                       "vbroadcastss %%xmm4, %%zmm7\n\t"
                       "vaddps %%zmm4, %%zmm7, %%zmm5\n\t"
                       "vaddps %%zmm5, %%zmm7, %%zmm6\n\t"
                       "vaddps %%zmm6, %%zmm7, %%zmm7\n\t"
                       "kmovw %2, %%k5\n"
                       put_insn(v4fmaddps,
                                "v4fmaddps 32(%0), %%zmm4, %%zmm4%{%%k5%}")
                       :: "c" (NULL), "m" (in), "rmk" (0x8001) );

        set_insn(v4fmaddps);
        regs.ecx = (unsigned long)&in;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(v4fmaddps) )
            goto fail;

        asm ( "vcmpeqps %1, %%zmm4, %%k0\n\t"
              "kmovw %%k0, %0" : "=g" (rc) : "m" (out) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing v4fnmaddss 16(%edx),%zmm4,%zmm4{%k3}...");
    if ( stack_exec && cpu_has_avx512_4fmaps )
    {
        decl_insn(v4fnmaddss);
        static const struct {
            float f[16];
        } in = {{
            1, 2, 3, 4, 5, 6, 7, 8
        }}, out = {{
            1 - 1 * 5 - 2 * 6 - 3 * 7 - 4 * 8, 2, 3, 4
        }};

        asm volatile ( "vmovups %1, %%xmm4\n\t"
                       "vaddss %%xmm4, %%xmm4, %%xmm5\n\t"
                       "vaddss %%xmm5, %%xmm4, %%xmm6\n\t"
                       "vaddss %%xmm6, %%xmm4, %%xmm7\n\t"
                       "kmovw %2, %%k3\n"
                       put_insn(v4fnmaddss,
                                "v4fnmaddss 16(%0), %%xmm4, %%xmm4%{%%k3%}")
                       :: "d" (NULL), "m" (in), "rmk" (1) );

        set_insn(v4fnmaddss);
        regs.edx = (unsigned long)&in;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(v4fnmaddss) )
            goto fail;

        asm ( "vcmpeqps %1, %%zmm4, %%k0\n\t"
              "kmovw %%k0, %0" : "=g" (rc) : "m" (out) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    if ( stack_exec && cpu_has_avx512_bf16 )
    {
        decl_insn(vcvtne2ps2bf16);
        decl_insn(vcvtneps2bf16);
        decl_insn(vdpbf16ps);
        static const struct {
            float f[16];
        } in1 = {{
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        }}, in2 = {{
            1, -2, 3, -4, 5, -6, 7, -8, 9, -10, 11, -12, 13, -14, 15, -16
        }}, out = {{
            1 * 1 + 2 * 2, 3 * 3 + 4 * 4,
            5 * 5 + 6 * 6, 7 * 7 + 8 * 8,
            9 * 9 + 10 * 10, 11 * 11 + 12 * 12,
            13 * 13 + 14 * 14, 15 * 15 + 16 * 16,
            1 * 1 - 2 * 2, 3 * 3 - 4 * 4,
            5 * 5 - 6 * 6, 7 * 7 - 8 * 8,
            9 * 9 - 10 * 10, 11 * 11 - 12 * 12,
            13 * 13 - 14 * 14, 15 * 15 - 16 * 16
        }};

        printf("%-40s", "Testing vcvtne2ps2bf16 64(%ecx),%zmm1,%zmm2...");
        asm volatile ( "vmovups %1, %%zmm1\n"
                       put_insn(vcvtne2ps2bf16,
                                /* vcvtne2ps2bf16 64(%0), %%zmm1, %%zmm2 */
                                ".byte 0x62, 0xf2, 0x77, 0x48, 0x72, 0x51, 0x01")
                       :: "c" (NULL), "m" (in2) );
        set_insn(vcvtne2ps2bf16);
        regs.ecx = (unsigned long)&in1 - 64;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vcvtne2ps2bf16) )
            goto fail;
        printf("pending\n");

        printf("%-40s", "Testing vcvtneps2bf16 64(%ecx),%ymm3...");
        asm volatile ( put_insn(vcvtneps2bf16,
                                /* vcvtneps2bf16 64(%0), %%ymm3 */
                                ".byte 0x62, 0xf2, 0x7e, 0x48, 0x72, 0x59, 0x01")
                       :: "c" (NULL) );
        set_insn(vcvtneps2bf16);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vcvtneps2bf16) )
            goto fail;
        asm ( "vmovdqa %%ymm2, %%ymm5\n\t"
              "vpcmpeqd %%zmm3, %%zmm5, %%k0\n\t"
              "kmovw %%k0, %0"
              : "=g" (rc) : "m" (out) );
        if ( rc != 0xffff )
            goto fail;
        printf("pending\n");

        printf("%-40s", "Testing vdpbf16ps 128(%ecx),%zmm2,%zmm4...");
        asm volatile ( "vmovdqa %%ymm3, %0\n\t"
                       "vmovdqa %%ymm3, %1\n"
                       put_insn(vdpbf16ps,
                                /* vdpbf16ps 128(%2), %%zmm2, %%zmm4 */
                                ".byte 0x62, 0xf2, 0x6e, 0x48, 0x52, 0x61, 0x02")
                       : "=&m" (res[0]), "=&m" (res[8])
                       : "c" (NULL)
                       : "memory" );
        set_insn(vdpbf16ps);
        regs.ecx = (unsigned long)res - 128;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vdpbf16ps) )
            goto fail;
        asm ( "vcmpeqps %1, %%zmm4, %%k0\n\t"
              "kmovw %%k0, %0"
              : "=g" (rc) : "m" (out) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }

    printf("%-40s", "Testing invpcid 16(%ecx),%%edx...");
    if ( stack_exec )
    {
        decl_insn(invpcid);

        asm volatile ( put_insn(invpcid, "invpcid 16(%0), %1")
                       :: "c" (NULL), "d" (0L) );

        res[4] = 0;
        res[5] = 0;
        res[6] = INVPCID_ADDR;
        res[7] = 0;
        regs.ecx = (unsigned long)res;
        emulops.tlb_op = tlb_op_invpcid;

        for ( ; ; )
        {
            for ( regs.edx = 0; regs.edx < 4; ++regs.edx )
            {
                set_insn(invpcid);
                rc = x86_emulate(&ctxt, &emulops);
                if ( rc != X86EMUL_OKAY || !check_eip(invpcid) )
                    goto fail;
            }

            if ( ctxt.addr_size < 64 || res[4] == INVPCID_PCID )
                break;

            emulops.read_cr = read_cr_invpcid;
            res[4] = INVPCID_PCID;
        }

        emulops.read_cr = emul_test_read_cr;
        emulops.tlb_op = NULL;

        printf("okay\n");
    }
    else
        printf("skipped\n");

#undef decl_insn
#undef put_insn
#undef set_insn
#undef check_eip

    j = cache_line_size();
    snprintf(instr, (char *)res + MMAP_SZ - instr,
             "Testing clzero (%u-byte line)...", j);
    printf("%-40s", instr);
    if ( j >= sizeof(*res) && j <= MMAP_SZ / 4 )
    {
        instr[0] = 0x0f; instr[1] = 0x01; instr[2] = 0xfc;
        regs.eflags = 0x200;
        regs.eip    = (unsigned long)&instr[0];
        regs.eax    = (unsigned long)res + MMAP_SZ / 2 + j - 1;
        memset((void *)res + MMAP_SZ / 4, ~0, 3 * MMAP_SZ / 4);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eax != (unsigned long)res + MMAP_SZ / 2 + j - 1) ||
             (regs.eflags != 0x200) ||
             (regs.eip != (unsigned long)&instr[3]) ||
             (res[MMAP_SZ / 2 / sizeof(*res) - 1] != ~0U) ||
             (res[(MMAP_SZ / 2 + j) / sizeof(*res)] != ~0U) )
            goto fail;
        for ( i = 0; i < j; i += sizeof(*res) )
            if ( res[(MMAP_SZ / 2 + i) / sizeof(*res)] )
                break;
        if ( i < j )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    if ( stack_exec )
        evex_disp8_test(instr, &ctxt, &emulops);

    predicates_test(instr, &ctxt, fetch);

    for ( j = 0; j < ARRAY_SIZE(blobs); j++ )
    {
        if ( blobs[j].check_cpu && !blobs[j].check_cpu() )
            continue;

        if ( !blobs[j].size )
        {
            printf("%-39s n/a (%u-bit)\n", blobs[j].name, blobs[j].bitness);
            continue;
        }

        memcpy(res, blobs[j].code, blobs[j].size);
        ctxt.lma = blobs[j].bitness == 64;
        ctxt.addr_size = ctxt.sp_size = blobs[j].bitness;

        if ( ctxt.addr_size == sizeof(void *) * CHAR_BIT )
        {
            i = printf("Testing %s native execution...", blobs[j].name);
            if ( blobs[j].set_regs )
                blobs[j].set_regs(&regs);
            asm volatile (
#if defined(__i386__)
                "call *%%ecx"
#else
                "call *%%rcx"
#endif
                : "+a" (regs.eax), "+d" (regs.edx) : "c" (res)
#ifdef __x86_64__
                : "rsi", "rdi", "r8", "r9", "r10", "r11"
#endif
            );
            if ( !blobs[j].check_regs(&regs) )
                goto fail;
            printf("%*sokay\n", i < 40 ? 40 - i : 0, "");
        }

        printf("Testing %s %u-bit code sequence",
               blobs[j].name, ctxt.addr_size);
        if ( blobs[j].set_regs )
            blobs[j].set_regs(&regs);
        regs.eip = (unsigned long)res;
        regs.esp = (unsigned long)res + MMAP_SZ - 4;
        if ( ctxt.addr_size == 64 )
        {
            *(uint32_t *)(unsigned long)regs.esp = 0;
            regs.esp -= 4;
        }
        *(uint32_t *)(unsigned long)regs.esp = 0x12345678;
        regs.eflags = 2;
        i = 0;
        while ( regs.eip >= (unsigned long)res &&
                regs.eip < (unsigned long)res + blobs[j].size )
        {
            if ( (i++ & 8191) == 0 )
                printf(".");
            rc = x86_emulate(&ctxt, &emulops);
            if ( rc != X86EMUL_OKAY )
            {
                printf("failed (%d) at %%eip == %08lx (opcode %08x)\n",
                       rc, (unsigned long)regs.eip, ctxt.opcode);
                return 1;
            }
        }
        for ( ; i < 2 * 8192; i += 8192 )
            printf(".");
        if ( (regs.eip != 0x12345678) ||
             (regs.esp != ((unsigned long)res + MMAP_SZ)) ||
             !blobs[j].check_regs(&regs) )
            goto fail;
        printf("okay\n");
    }

    return 0;

 fail:
    printf("failed!\n");
    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
