#include "x86-emulate.h"

#include <stdarg.h>
#include <stdio.h>

struct test {
    const char *mnemonic;
    unsigned int opc:8;
    unsigned int spc:2;
    unsigned int pfx:2;
    unsigned int vsz:3;
    unsigned int esz:4;
    unsigned int scale:1;
    unsigned int ext:3;
};

enum spc {
    SPC_invalid,
    SPC_0f,
    SPC_0f38,
    SPC_0f3a,
};

enum pfx {
    PFX_,
    PFX_66,
    PFX_f3,
    PFX_f2
};

enum vl {
    VL_128,
    VL_256,
    VL_512,
};

enum scale { /* scale by memory operand ... */
    SC_vl,   /* ... vector length */
    SC_el,   /* ... element length */
};

/*
 * Vector size is determined either from EVEX.L'L (VL) or vector
 * element size (EL), often controlled by EVEX.W (see enum esz).
 */
enum vsz {
    VSZ_vl,
    VSZ_vl_2, /* VL / 2 */
    VSZ_vl_4, /* VL / 4 */
    VSZ_vl_8, /* VL / 8 */
    /* "no broadcast" implied from here on. */
    VSZ_el,
    VSZ_el_2, /* EL * 2 */
    VSZ_el_4, /* EL * 4 */
    VSZ_el_8, /* EL * 8 */
};

/*
 * Vector element size is either an opcode attribute or often determined
 * by EVEX.W (in which case enumerators below name two sizes). Instructions
 * accessing GPRs often use EVEX.W to select between 32- and 64-bit GPR
 * width, but this distinction goes away outside of 64-bit mode (and EVEX.W
 * is ignored there).
 */
enum esz {
    ESZ_d,
    ESZ_q,
    ESZ_dq,
    ESZ_sd,
    ESZ_d_nb,
    ESZ_q_nb,
    /* "no broadcast" implied from here on. */
#ifdef __i386__
    ESZ_d_WIG,
#endif
    ESZ_b,
    ESZ_w,
    ESZ_bw,
};

#ifndef __i386__
# define ESZ_dq64 ESZ_dq
#else
# define ESZ_dq64 ESZ_d_WIG
#endif

#define INSNX(m, p, sp, o, e, vs, es, sc) { \
    .mnemonic = #m, .opc = 0x##o, .spc = SPC_##sp, .pfx = PFX_##p, \
    .vsz = VSZ_##vs, .esz = ESZ_##es, .scale = SC_##sc, .ext = 0##e \
}
#define INSN(m, p, sp, o, vs, es, sc) INSNX(m, p, sp, o, 0, vs, es, sc)
#define INSN_PFP(m, sp, o) \
    INSN(m##pd, 66, sp, o, vl, q, vl), \
    INSN(m##ps,   , sp, o, vl, d, vl)
#define INSN_PFP_NB(m, sp, o) \
    INSN(m##pd, 66, sp, o, vl, q_nb, vl), \
    INSN(m##ps,   , sp, o, vl, d_nb, vl)
#define INSN_SFP(m, sp, o) \
    INSN(m##sd, f2, sp, o, el, q, el), \
    INSN(m##ss, f3, sp, o, el, d, el)

#define INSN_FP(m, sp, o) \
    INSN_PFP(m, sp, o), \
    INSN_SFP(m, sp, o)

static const struct test avx512f_all[] = {
    INSN_FP(add,             0f, 58),
    INSN(align,        66, 0f3a, 03,    vl,     dq, vl),
    INSN(blendm,       66, 0f38, 65,    vl,     sd, vl),
    INSN(broadcastss,  66, 0f38, 18,    el,      d, el),
    INSN_FP(cmp,             0f, c2),
    INSN(comisd,       66,   0f, 2f,    el,      q, el),
    INSN(comiss,         ,   0f, 2f,    el,      d, el),
    INSN(compress,     66, 0f38, 8a,    vl,     sd, el),
    INSN(cvtdq2pd,     f3,   0f, e6,    vl_2,    d, vl),
    INSN(cvtdq2ps,       ,   0f, 5b,    vl,      d, vl),
    INSN(cvtpd2dq,     f2,   0f, e6,    vl,      q, vl),
    INSN(cvtpd2udq,      ,   0f, 79,    vl,      q, vl),
    INSN(cvtpd2ps,     66,   0f, 5a,    vl,      q, vl),
    INSN(cvtph2ps,     66, 0f38, 13,    vl_2, d_nb, vl),
    INSN(cvtps2dq,     66,   0f, 5b,    vl,      d, vl),
    INSN(cvtps2pd,       ,   0f, 5a,    vl_2,    d, vl),
    INSN(cvtps2ph,     66, 0f3a, 1d,    vl_2, d_nb, vl),
    INSN(cvtps2udq,      ,   0f, 79,    vl,      d, vl),
    INSN(cvtsd2si,     f2,   0f, 2d,    el,      q, el),
    INSN(cvtsd2usi,    f2,   0f, 79,    el,      q, el),
    INSN(cvtsd2ss,     f2,   0f, 5a,    el,      q, el),
    INSN(cvtsi2sd,     f2,   0f, 2a,    el,   dq64, el),
    INSN(cvtsi2ss,     f3,   0f, 2a,    el,   dq64, el),
    INSN(cvtss2sd,     f3,   0f, 5a,    el,      d, el),
    INSN(cvtss2si,     f3,   0f, 2d,    el,      d, el),
    INSN(cvtss2usi,    f3,   0f, 79,    el,      d, el),
    INSN(cvttpd2dq,    66,   0f, e6,    vl,      q, vl),
    INSN(cvttpd2udq,     ,   0f, 78,    vl,      q, vl),
    INSN(cvttps2dq,    f3,   0f, 5b,    vl,      d, vl),
    INSN(cvttps2udq,     ,   0f, 78,    vl,      d, vl),
    INSN(cvttsd2si,    f2,   0f, 2c,    el,      q, el),
    INSN(cvttsd2usi,   f2,   0f, 78,    el,      q, el),
    INSN(cvttss2si,    f3,   0f, 2c,    el,      d, el),
    INSN(cvttss2usi,   f3,   0f, 78,    el,      d, el),
    INSN(cvtudq2pd,    f3,   0f, 7a,    vl_2,    d, vl),
    INSN(cvtudq2ps,    f2,   0f, 7a,    vl,      d, vl),
    INSN(cvtusi2sd,    f2,   0f, 7b,    el,   dq64, el),
    INSN(cvtusi2ss,    f3,   0f, 7b,    el,   dq64, el),
    INSN_FP(div,             0f, 5e),
    INSN(expand,       66, 0f38, 88,    vl,     sd, el),
    INSN(fixupimm,     66, 0f3a, 54,    vl,     sd, vl),
    INSN(fixupimm,     66, 0f3a, 55,    el,     sd, el),
    INSN(fmadd132,     66, 0f38, 98,    vl,     sd, vl),
    INSN(fmadd132,     66, 0f38, 99,    el,     sd, el),
    INSN(fmadd213,     66, 0f38, a8,    vl,     sd, vl),
    INSN(fmadd213,     66, 0f38, a9,    el,     sd, el),
    INSN(fmadd231,     66, 0f38, b8,    vl,     sd, vl),
    INSN(fmadd231,     66, 0f38, b9,    el,     sd, el),
    INSN(fmaddsub132,  66, 0f38, 96,    vl,     sd, vl),
    INSN(fmaddsub213,  66, 0f38, a6,    vl,     sd, vl),
    INSN(fmaddsub231,  66, 0f38, b6,    vl,     sd, vl),
    INSN(fmsub132,     66, 0f38, 9a,    vl,     sd, vl),
    INSN(fmsub132,     66, 0f38, 9b,    el,     sd, el),
    INSN(fmsub213,     66, 0f38, aa,    vl,     sd, vl),
    INSN(fmsub213,     66, 0f38, ab,    el,     sd, el),
    INSN(fmsub231,     66, 0f38, ba,    vl,     sd, vl),
    INSN(fmsub231,     66, 0f38, bb,    el,     sd, el),
    INSN(fmsubadd132,  66, 0f38, 97,    vl,     sd, vl),
    INSN(fmsubadd213,  66, 0f38, a7,    vl,     sd, vl),
    INSN(fmsubadd231,  66, 0f38, b7,    vl,     sd, vl),
    INSN(fnmadd132,    66, 0f38, 9c,    vl,     sd, vl),
    INSN(fnmadd132,    66, 0f38, 9d,    el,     sd, el),
    INSN(fnmadd213,    66, 0f38, ac,    vl,     sd, vl),
    INSN(fnmadd213,    66, 0f38, ad,    el,     sd, el),
    INSN(fnmadd231,    66, 0f38, bc,    vl,     sd, vl),
    INSN(fnmadd231,    66, 0f38, bd,    el,     sd, el),
    INSN(fnmsub132,    66, 0f38, 9e,    vl,     sd, vl),
    INSN(fnmsub132,    66, 0f38, 9f,    el,     sd, el),
    INSN(fnmsub213,    66, 0f38, ae,    vl,     sd, vl),
    INSN(fnmsub213,    66, 0f38, af,    el,     sd, el),
    INSN(fnmsub231,    66, 0f38, be,    vl,     sd, vl),
    INSN(fnmsub231,    66, 0f38, bf,    el,     sd, el),
    INSN(gatherd,      66, 0f38, 92,    vl,     sd, el),
    INSN(gatherq,      66, 0f38, 93,    vl,     sd, el),
    INSN(getexp,       66, 0f38, 42,    vl,     sd, vl),
    INSN(getexp,       66, 0f38, 43,    el,     sd, el),
    INSN(getmant,      66, 0f3a, 26,    vl,     sd, vl),
    INSN(getmant,      66, 0f3a, 27,    el,     sd, el),
    INSN_FP(max,             0f, 5f),
    INSN_FP(min,             0f, 5d),
    INSN_SFP(mov,            0f, 10),
    INSN_SFP(mov,            0f, 11),
    INSN_PFP_NB(mova,        0f, 28),
    INSN_PFP_NB(mova,        0f, 29),
    INSN(movddup,      f2,   0f, 12,    vl,   q_nb, vl),
    INSN(movdqa32,     66,   0f, 6f,    vl,   d_nb, vl),
    INSN(movdqa32,     66,   0f, 7f,    vl,   d_nb, vl),
    INSN(movdqa64,     66,   0f, 6f,    vl,   q_nb, vl),
    INSN(movdqa64,     66,   0f, 7f,    vl,   q_nb, vl),
    INSN(movdqu32,     f3,   0f, 6f,    vl,   d_nb, vl),
    INSN(movdqu32,     f3,   0f, 7f,    vl,   d_nb, vl),
    INSN(movdqu64,     f3,   0f, 6f,    vl,   q_nb, vl),
    INSN(movdqu64,     f3,   0f, 7f,    vl,   q_nb, vl),
    INSN(movntdq,      66,   0f, e7,    vl,   d_nb, vl),
    INSN(movntdqa,     66, 0f38, 2a,    vl,   d_nb, vl),
    INSN_PFP_NB(movnt,       0f, 2b),
    INSN(movshdup,     f3,   0f, 16,    vl,   d_nb, vl),
    INSN(movsldup,     f3,   0f, 12,    vl,   d_nb, vl),
    INSN_PFP_NB(movu,        0f, 10),
    INSN_PFP_NB(movu,        0f, 11),
    INSN_FP(mul,             0f, 59),
    INSN(pabsd,        66, 0f38, 1e,    vl,      d, vl),
    INSN(pabsq,        66, 0f38, 1f,    vl,      q, vl),
    INSN(paddd,        66,   0f, fe,    vl,      d, vl),
    INSN(paddq,        66,   0f, d4,    vl,      q, vl),
    INSN(pand,         66,   0f, db,    vl,     dq, vl),
    INSN(pandn,        66,   0f, df,    vl,     dq, vl),
    INSN(pblendm,      66, 0f38, 64,    vl,     dq, vl),
//       pbroadcast,   66, 0f38, 7c,          dq64
    INSN(pbroadcastd,  66, 0f38, 58,    el,      d, el),
    INSN(pbroadcastq,  66, 0f38, 59,    el,      q, el),
    INSN(pcmp,         66, 0f3a, 1f,    vl,     dq, vl),
    INSN(pcmpeqd,      66,   0f, 76,    vl,      d, vl),
    INSN(pcmpeqq,      66, 0f38, 29,    vl,      q, vl),
    INSN(pcmpgtd,      66,   0f, 66,    vl,      d, vl),
    INSN(pcmpgtq,      66, 0f38, 37,    vl,      q, vl),
    INSN(pcmpu,        66, 0f3a, 1e,    vl,     dq, vl),
    INSN(pcompress,    66, 0f38, 8b,    vl,     dq, el),
    INSN(permi2,       66, 0f38, 76,    vl,     dq, vl),
    INSN(permi2,       66, 0f38, 77,    vl,     sd, vl),
    INSN(permilpd,     66, 0f38, 0d,    vl,      q, vl),
    INSN(permilpd,     66, 0f3a, 05,    vl,      q, vl),
    INSN(permilps,     66, 0f38, 0c,    vl,      d, vl),
    INSN(permilps,     66, 0f3a, 04,    vl,      d, vl),
    INSN(permt2,       66, 0f38, 7e,    vl,     dq, vl),
    INSN(permt2,       66, 0f38, 7f,    vl,     sd, vl),
    INSN(pexpand,      66, 0f38, 89,    vl,     dq, el),
    INSN(pgatherd,     66, 0f38, 90,    vl,     dq, el),
    INSN(pgatherq,     66, 0f38, 91,    vl,     dq, el),
    INSN(pmaxs,        66, 0f38, 3d,    vl,     dq, vl),
    INSN(pmaxu,        66, 0f38, 3f,    vl,     dq, vl),
    INSN(pmins,        66, 0f38, 39,    vl,     dq, vl),
    INSN(pminu,        66, 0f38, 3b,    vl,     dq, vl),
    INSN(pmovdb,       f3, 0f38, 31,    vl_4,    b, vl),
    INSN(pmovdw,       f3, 0f38, 33,    vl_2,    b, vl),
    INSN(pmovqb,       f3, 0f38, 32,    vl_8,    b, vl),
    INSN(pmovqd,       f3, 0f38, 35,    vl_2, d_nb, vl),
    INSN(pmovqw,       f3, 0f38, 34,    vl_4,    b, vl),
    INSN(pmovsdb,      f3, 0f38, 21,    vl_4,    b, vl),
    INSN(pmovsdw,      f3, 0f38, 23,    vl_2,    b, vl),
    INSN(pmovsqb,      f3, 0f38, 22,    vl_8,    b, vl),
    INSN(pmovsqd,      f3, 0f38, 25,    vl_2, d_nb, vl),
    INSN(pmovsqw,      f3, 0f38, 24,    vl_4,    b, vl),
    INSN(pmovsxbd,     66, 0f38, 21,    vl_4,    b, vl),
    INSN(pmovsxbq,     66, 0f38, 22,    vl_8,    b, vl),
    INSN(pmovsxwd,     66, 0f38, 23,    vl_2,    w, vl),
    INSN(pmovsxwq,     66, 0f38, 24,    vl_4,    w, vl),
    INSN(pmovsxdq,     66, 0f38, 25,    vl_2, d_nb, vl),
    INSN(pmovusdb,     f3, 0f38, 11,    vl_4,    b, vl),
    INSN(pmovusdw,     f3, 0f38, 13,    vl_2,    b, vl),
    INSN(pmovusqb,     f3, 0f38, 12,    vl_8,    b, vl),
    INSN(pmovusqd,     f3, 0f38, 15,    vl_2, d_nb, vl),
    INSN(pmovusqw,     f3, 0f38, 14,    vl_4,    b, vl),
    INSN(pmovzxbd,     66, 0f38, 31,    vl_4,    b, vl),
    INSN(pmovzxbq,     66, 0f38, 32,    vl_8,    b, vl),
    INSN(pmovzxwd,     66, 0f38, 33,    vl_2,    w, vl),
    INSN(pmovzxwq,     66, 0f38, 34,    vl_4,    w, vl),
    INSN(pmovzxdq,     66, 0f38, 35,    vl_2, d_nb, vl),
    INSN(pmuldq,       66, 0f38, 28,    vl,      q, vl),
    INSN(pmulld,       66, 0f38, 40,    vl,      d, vl),
    INSN(pmuludq,      66,   0f, f4,    vl,      q, vl),
    INSN(por,          66,   0f, eb,    vl,     dq, vl),
    INSNX(prol,        66,   0f, 72, 1, vl,     dq, vl),
    INSN(prolv,        66, 0f38, 15,    vl,     dq, vl),
    INSNX(pror,        66,   0f, 72, 0, vl,     dq, vl),
    INSN(prorv,        66, 0f38, 14,    vl,     dq, vl),
    INSN(pscatterd,    66, 0f38, a0,    vl,     dq, el),
    INSN(pscatterq,    66, 0f38, a1,    vl,     dq, el),
    INSN(pshufd,       66,   0f, 70,    vl,      d, vl),
    INSN(pslld,        66,   0f, f2,    el_4,    d, vl),
    INSNX(pslld,       66,   0f, 72, 6, vl,      d, vl),
    INSN(psllq,        66,   0f, f3,    el_2,    q, vl),
    INSNX(psllq,       66,   0f, 73, 6, vl,      q, vl),
    INSN(psllv,        66, 0f38, 47,    vl,     dq, vl),
    INSNX(psra,        66,   0f, 72, 4, vl,     dq, vl),
    INSN(psrad,        66,   0f, e2,    el_4,    d, vl),
    INSN(psraq,        66,   0f, e2,    el_2,    q, vl),
    INSN(psrav,        66, 0f38, 46,    vl,     dq, vl),
    INSN(psrld,        66,   0f, d2,    el_4,    d, vl),
    INSNX(psrld,       66,   0f, 72, 2, vl,      d, vl),
    INSN(psrlq,        66,   0f, d3,    el_2,    q, vl),
    INSNX(psrlq,       66,   0f, 73, 2, vl,      q, vl),
    INSN(psrlv,        66, 0f38, 45,    vl,     dq, vl),
    INSN(psubd,        66,   0f, fa,    vl,      d, vl),
    INSN(psubq,        66,   0f, fb,    vl,      q, vl),
    INSN(pternlog,     66, 0f3a, 25,    vl,     dq, vl),
    INSN(ptestm,       66, 0f38, 27,    vl,     dq, vl),
    INSN(ptestnm,      f3, 0f38, 27,    vl,     dq, vl),
    INSN(punpckhdq,    66,   0f, 6a,    vl,      d, vl),
    INSN(punpckhqdq,   66,   0f, 6d,    vl,      q, vl),
    INSN(punpckldq,    66,   0f, 62,    vl,      d, vl),
    INSN(punpcklqdq,   66,   0f, 6c,    vl,      q, vl),
    INSN(pxor,         66,   0f, ef,    vl,     dq, vl),
    INSN(rcp14,        66, 0f38, 4c,    vl,     sd, vl),
    INSN(rcp14,        66, 0f38, 4d,    el,     sd, el),
    INSN(rndscalepd,   66, 0f3a, 09,    vl,      q, vl),
    INSN(rndscaleps,   66, 0f3a, 08,    vl,      d, vl),
    INSN(rndscalesd,   66, 0f3a, 0b,    el,      q, el),
    INSN(rndscaless,   66, 0f3a, 0a,    el,      d, el),
    INSN(rsqrt14,      66, 0f38, 4e,    vl,     sd, vl),
    INSN(rsqrt14,      66, 0f38, 4f,    el,     sd, el),
    INSN(scalef,       66, 0f38, 2c,    vl,     sd, vl),
    INSN(scalef,       66, 0f38, 2d,    el,     sd, el),
    INSN(scatterd,     66, 0f38, a2,    vl,     sd, el),
    INSN(scatterq,     66, 0f38, a3,    vl,     sd, el),
    INSN_PFP(shuf,           0f, c6),
    INSN_FP(sqrt,            0f, 51),
    INSN_FP(sub,             0f, 5c),
    INSN(ucomisd,      66,   0f, 2e,    el,      q, el),
    INSN(ucomiss,        ,   0f, 2e,    el,      d, el),
    INSN_PFP(unpckh,         0f, 15),
    INSN_PFP(unpckl,         0f, 14),
};

static const struct test avx512f_128[] = {
    INSN(extractps, 66, 0f3a, 17, el,    d, el),
    INSN(insertps,  66, 0f3a, 21, el,    d, el),
    INSN(mov,       66,   0f, 6e, el, dq64, el),
    INSN(mov,       66,   0f, 7e, el, dq64, el),
//       movhlps,     ,   0f, 12,        d
    INSN(movhpd,    66,   0f, 16, el,    q, vl),
    INSN(movhpd,    66,   0f, 17, el,    q, vl),
    INSN(movhps,      ,   0f, 16, el_2,  d, vl),
    INSN(movhps,      ,   0f, 17, el_2,  d, vl),
//       movlhps,     ,   0f, 16,        d
    INSN(movlpd,    66,   0f, 12, el,    q, vl),
    INSN(movlpd,    66,   0f, 13, el,    q, vl),
    INSN(movlps,      ,   0f, 12, el_2,  d, vl),
    INSN(movlps,      ,   0f, 13, el_2,  d, vl),
    INSN(movq,      f3,   0f, 7e, el,    q, el),
    INSN(movq,      66,   0f, d6, el,    q, el),
};

static const struct test avx512f_no128[] = {
    INSN(broadcastf32x4, 66, 0f38, 1a, el_4,  d, vl),
    INSN(broadcasti32x4, 66, 0f38, 5a, el_4,  d, vl),
    INSN(broadcastsd,    66, 0f38, 19, el,    q, el),
    INSN(extractf32x4,   66, 0f3a, 19, el_4,  d, vl),
    INSN(extracti32x4,   66, 0f3a, 39, el_4,  d, vl),
    INSN(insertf32x4,    66, 0f3a, 18, el_4,  d, vl),
    INSN(inserti32x4,    66, 0f3a, 38, el_4,  d, vl),
    INSN(perm,           66, 0f38, 36, vl,   dq, vl),
    INSN(perm,           66, 0f38, 16, vl,   sd, vl),
    INSN(permpd,         66, 0f3a, 01, vl,    q, vl),
    INSN(permq,          66, 0f3a, 00, vl,    q, vl),
    INSN(shuff32x4,      66, 0f3a, 23, vl,    d, vl),
    INSN(shuff64x2,      66, 0f3a, 23, vl,    q, vl),
    INSN(shufi32x4,      66, 0f3a, 43, vl,    d, vl),
    INSN(shufi64x2,      66, 0f3a, 43, vl,    q, vl),
};

static const struct test avx512f_512[] = {
    INSN(broadcastf64x4, 66, 0f38, 1b, el_4, q, vl),
    INSN(broadcasti64x4, 66, 0f38, 5b, el_4, q, vl),
    INSN(extractf64x4,   66, 0f3a, 1b, el_4, q, vl),
    INSN(extracti64x4,   66, 0f3a, 3b, el_4, q, vl),
    INSN(insertf64x4,    66, 0f3a, 1a, el_4, q, vl),
    INSN(inserti64x4,    66, 0f3a, 3a, el_4, q, vl),
};

static const struct test avx512bw_all[] = {
    INSN(dbpsadbw,    66, 0f3a, 42,    vl,    b, vl),
    INSN(movdqu8,     f2,   0f, 6f,    vl,    b, vl),
    INSN(movdqu8,     f2,   0f, 7f,    vl,    b, vl),
    INSN(movdqu16,    f2,   0f, 6f,    vl,    w, vl),
    INSN(movdqu16,    f2,   0f, 7f,    vl,    w, vl),
    INSN(pabsb,       66, 0f38, 1c,    vl,    b, vl),
    INSN(pabsw,       66, 0f38, 1d,    vl,    w, vl),
    INSN(packssdw,    66,   0f, 6b,    vl, d_nb, vl),
    INSN(packsswb,    66,   0f, 63,    vl,    w, vl),
    INSN(packusdw,    66, 0f38, 2b,    vl, d_nb, vl),
    INSN(packuswb,    66,   0f, 67,    vl,    w, vl),
    INSN(paddb,       66,   0f, fc,    vl,    b, vl),
    INSN(paddsb,      66,   0f, ec,    vl,    b, vl),
    INSN(paddsw,      66,   0f, ed,    vl,    w, vl),
    INSN(paddusb,     66,   0f, dc,    vl,    b, vl),
    INSN(paddusw,     66,   0f, dd,    vl,    w, vl),
    INSN(paddw,       66,   0f, fd,    vl,    w, vl),
    INSN(palignr,     66, 0f3a, 0f,    vl,    b, vl),
    INSN(pavgb,       66,   0f, e0,    vl,    b, vl),
    INSN(pavgw,       66,   0f, e3,    vl,    w, vl),
    INSN(pblendm,     66, 0f38, 66,    vl,   bw, vl),
    INSN(pbroadcastb, 66, 0f38, 78,    el,    b, el),
//       pbroadcastb, 66, 0f38, 7a,           b
    INSN(pbroadcastw, 66, 0f38, 79,    el_2,  b, vl),
//       pbroadcastw, 66, 0f38, 7b,           b
    INSN(pcmp,        66, 0f3a, 3f,    vl,   bw, vl),
    INSN(pcmpeqb,     66,   0f, 74,    vl,    b, vl),
    INSN(pcmpeqw,     66,   0f, 75,    vl,    w, vl),
    INSN(pcmpgtb,     66,   0f, 64,    vl,    b, vl),
    INSN(pcmpgtw,     66,   0f, 65,    vl,    w, vl),
    INSN(pcmpu,       66, 0f3a, 3e,    vl,   bw, vl),
    INSN(permw,       66, 0f38, 8d,    vl,    w, vl),
    INSN(permi2w,     66, 0f38, 75,    vl,    w, vl),
    INSN(permt2w,     66, 0f38, 7d,    vl,    w, vl),
    INSN(pmaddubsw,   66, 0f38, 04,    vl,    b, vl),
    INSN(pmaddwd,     66,   0f, f5,    vl,    w, vl),
    INSN(pmaxsb,      66, 0f38, 3c,    vl,    b, vl),
    INSN(pmaxsw,      66,   0f, ee,    vl,    w, vl),
    INSN(pmaxub,      66,   0f, de,    vl,    b, vl),
    INSN(pmaxuw,      66, 0f38, 3e,    vl,    w, vl),
    INSN(pminsb,      66, 0f38, 38,    vl,    b, vl),
    INSN(pminsw,      66,   0f, ea,    vl,    w, vl),
    INSN(pminub,      66,   0f, da,    vl,    b, vl),
    INSN(pminuw,      66, 0f38, 3a,    vl,    w, vl),
//       pmovb2m,     f3, 0f38, 29,           b
//       pmovm2,      f3, 0f38, 28,          bw
    INSN(pmovswb,     f3, 0f38, 20,    vl_2,  b, vl),
    INSN(pmovsxbw,    66, 0f38, 20,    vl_2,  b, vl),
    INSN(pmovuswb,    f3, 0f38, 10,    vl_2,  b, vl),
//       pmovw2m,     f3, 0f38, 29,           w
    INSN(pmovwb,      f3, 0f38, 30,    vl_2,  b, vl),
    INSN(pmovzxbw,    66, 0f38, 30,    vl_2,  b, vl),
    INSN(pmulhrsw,    66, 0f38, 0b,    vl,    w, vl),
    INSN(pmulhuw,     66,   0f, e4,    vl,    w, vl),
    INSN(pmulhw,      66,   0f, e5,    vl,    w, vl),
    INSN(pmullw,      66,   0f, d5,    vl,    w, vl),
    INSN(psadbw,      66,   0f, f6,    vl,    b, vl),
    INSN(pshufb,      66, 0f38, 00,    vl,    b, vl),
    INSN(pshufhw,     f3,   0f, 70,    vl,    w, vl),
    INSN(pshuflw,     f2,   0f, 70,    vl,    w, vl),
    INSNX(pslldq,     66,   0f, 73, 7, vl,    b, vl),
    INSN(psllvw,      66, 0f38, 12,    vl,    w, vl),
    INSN(psllw,       66,   0f, f1,    el_8,  w, vl),
    INSNX(psllw,      66,   0f, 71, 6, vl,    w, vl),
    INSN(psravw,      66, 0f38, 11,    vl,    w, vl),
    INSN(psraw,       66,   0f, e1,    el_8,  w, vl),
    INSNX(psraw,      66,   0f, 71, 4, vl,    w, vl),
    INSNX(psrldq,     66,   0f, 73, 3, vl,    b, vl),
    INSN(psrlvw,      66, 0f38, 10,    vl,    w, vl),
    INSN(psrlw,       66,   0f, d1,    el_8,  w, vl),
    INSNX(psrlw,      66,   0f, 71, 2, vl,    w, vl),
    INSN(psubb,       66,   0f, f8,    vl,    b, vl),
    INSN(psubsb,      66,   0f, e8,    vl,    b, vl),
    INSN(psubsw,      66,   0f, e9,    vl,    w, vl),
    INSN(psubusb,     66,   0f, d8,    vl,    b, vl),
    INSN(psubusw,     66,   0f, d9,    vl,    w, vl),
    INSN(psubw,       66,   0f, f9,    vl,    w, vl),
    INSN(ptestm,      66, 0f38, 26,    vl,   bw, vl),
    INSN(ptestnm,     f3, 0f38, 26,    vl,   bw, vl),
    INSN(punpckhbw,   66,   0f, 68,    vl,    b, vl),
    INSN(punpckhwd,   66,   0f, 69,    vl,    w, vl),
    INSN(punpcklbw,   66,   0f, 60,    vl,    b, vl),
    INSN(punpcklwd,   66,   0f, 61,    vl,    w, vl),
};

static const struct test avx512bw_128[] = {
    INSN(pextrb, 66, 0f3a, 14, el, b, el),
//       pextrw, 66,   0f, c5,     w
    INSN(pextrw, 66, 0f3a, 15, el, w, el),
    INSN(pinsrb, 66, 0f3a, 20, el, b, el),
    INSN(pinsrw, 66,   0f, c4, el, w, el),
};

static const struct test avx512cd_all[] = {
//       pbroadcastmb2q, f3, 0f38, 2a,      q
//       pbroadcastmw2d, f3, 0f38, 3a,      d
    INSN(pconflict,      66, 0f38, c4, vl, dq, vl),
    INSN(plzcnt,         66, 0f38, 44, vl, dq, vl),
};

static const struct test avx512dq_all[] = {
    INSN_PFP(and,              0f, 54),
    INSN_PFP(andn,             0f, 55),
    INSN(broadcasti32x2, 66, 0f38, 59, el_2,  d, vl),
    INSN(cvtpd2qq,       66,   0f, 7b,   vl,  q, vl),
    INSN(cvtpd2uqq,      66,   0f, 79,   vl,  q, vl),
    INSN(cvtps2qq,       66,   0f, 7b, vl_2,  d, vl),
    INSN(cvtps2uqq,      66,   0f, 79, vl_2,  d, vl),
    INSN(cvtqq2pd,       f3,   0f, e6,   vl,  q, vl),
    INSN(cvtqq2ps,         ,   0f, 5b,   vl,  q, vl),
    INSN(cvttpd2qq,      66,   0f, 7a,   vl,  q, vl),
    INSN(cvttpd2uqq,     66,   0f, 78,   vl,  q, vl),
    INSN(cvttps2qq,      66,   0f, 7a, vl_2,  d, vl),
    INSN(cvttps2uqq,     66,   0f, 78, vl_2,  d, vl),
    INSN(cvtuqq2pd,      f3,   0f, 7a,   vl,  q, vl),
    INSN(cvtuqq2ps,      f2,   0f, 7a,   vl,  q, vl),
    INSN(fpclass,        66, 0f3a, 66,   vl, sd, vl),
    INSN(fpclass,        66, 0f3a, 67,   el, sd, el),
    INSN_PFP(or,               0f, 56),
//       pmovd2m,        f3, 0f38, 39,        d
//       pmovm2,         f3, 0f38, 38,       dq
//       pmovq2m,        f3, 0f38, 39,        q
    INSN(pmullq,         66, 0f38, 40,   vl,  q, vl),
    INSN(range,          66, 0f3a, 50,   vl, sd, vl),
    INSN(range,          66, 0f3a, 51,   el, sd, el),
    INSN(reduce,         66, 0f3a, 56,   vl, sd, vl),
    INSN(reduce,         66, 0f3a, 57,   el, sd, el),
    INSN_PFP(xor,              0f, 57),
};

static const struct test avx512dq_128[] = {
    INSN(pextr, 66, 0f3a, 16, el, dq64, el),
    INSN(pinsr, 66, 0f3a, 22, el, dq64, el),
};

static const struct test avx512dq_no128[] = {
    INSN(broadcastf32x2, 66, 0f38, 19, el_2, d, vl),
    INSN(broadcastf64x2, 66, 0f38, 1a, el_2, q, vl),
    INSN(broadcasti64x2, 66, 0f38, 5a, el_2, q, vl),
    INSN(extractf64x2,   66, 0f3a, 19, el_2, q, vl),
    INSN(extracti64x2,   66, 0f3a, 39, el_2, q, vl),
    INSN(insertf64x2,    66, 0f3a, 18, el_2, q, vl),
    INSN(inserti64x2,    66, 0f3a, 38, el_2, q, vl),
};

static const struct test avx512dq_512[] = {
    INSN(broadcastf32x8, 66, 0f38, 1b, el_8, d, vl),
    INSN(broadcasti32x8, 66, 0f38, 5b, el_8, d, vl),
    INSN(extractf32x8,   66, 0f3a, 1b, el_8, d, vl),
    INSN(extracti32x8,   66, 0f3a, 3b, el_8, d, vl),
    INSN(insertf32x8,    66, 0f3a, 1a, el_8, d, vl),
    INSN(inserti32x8,    66, 0f3a, 3a, el_8, d, vl),
};

static const struct test avx512er_512[] = {
    INSN(exp2,    66, 0f38, c8, vl, sd, vl),
    INSN(rcp28,   66, 0f38, ca, vl, sd, vl),
    INSN(rcp28,   66, 0f38, cb, el, sd, el),
    INSN(rsqrt28, 66, 0f38, cc, vl, sd, vl),
    INSN(rsqrt28, 66, 0f38, cd, el, sd, el),
};

static const struct test avx512pf_512[] = {
    INSNX(gatherpf0d,  66, 0f38, c6, 1, vl, sd, el),
    INSNX(gatherpf0q,  66, 0f38, c7, 1, vl, sd, el),
    INSNX(gatherpf1d,  66, 0f38, c6, 2, vl, sd, el),
    INSNX(gatherpf1q,  66, 0f38, c7, 2, vl, sd, el),
    INSNX(scatterpf0d, 66, 0f38, c6, 5, vl, sd, el),
    INSNX(scatterpf0q, 66, 0f38, c7, 5, vl, sd, el),
    INSNX(scatterpf1d, 66, 0f38, c6, 6, vl, sd, el),
    INSNX(scatterpf1q, 66, 0f38, c7, 6, vl, sd, el),
};

static const struct test avx512_4fmaps_512[] = {
    INSN(4fmaddps,  f2, 0f38, 9a, el_4, d, vl),
    INSN(4fmaddss,  f2, 0f38, 9b, el_4, d, vl),
    INSN(4fnmaddps, f2, 0f38, aa, el_4, d, vl),
    INSN(4fnmaddss, f2, 0f38, ab, el_4, d, vl),
};

static const struct test avx512_4vnniw_512[] = {
    INSN(p4dpwssd,  f2, 0f38, 52, el_4, d, vl),
    INSN(p4dpwssds, f2, 0f38, 53, el_4, d, vl),
};

static const struct test avx512_bf16_all[] = {
    INSN(vcvtne2ps2bf16, f2, 0f38, 72, vl, d, vl),
    INSN(vcvtneps2bf16,  f3, 0f38, 72, vl, d, vl),
    INSN(vdpbf16ps,      f3, 0f38, 52, vl, d, vl),
};

static const struct test avx512_bitalg_all[] = {
    INSN(popcnt,      66, 0f38, 54, vl, bw, vl),
    INSN(pshufbitqmb, 66, 0f38, 8f, vl,  b, vl),
};

static const struct test avx512_ifma_all[] = {
    INSN(pmadd52huq, 66, 0f38, b5, vl, q, vl),
    INSN(pmadd52luq, 66, 0f38, b4, vl, q, vl),
};

static const struct test avx512_vbmi_all[] = {
    INSN(permb,         66, 0f38, 8d, vl, b, vl),
    INSN(permi2b,       66, 0f38, 75, vl, b, vl),
    INSN(permt2b,       66, 0f38, 7d, vl, b, vl),
    INSN(pmultishiftqb, 66, 0f38, 83, vl, q, vl),
};

static const struct test avx512_vbmi2_all[] = {
    INSN(pcompress, 66, 0f38, 63, vl, bw, el),
    INSN(pexpand,   66, 0f38, 62, vl, bw, el),
    INSN(pshld,     66, 0f3a, 71, vl, dq, vl),
    INSN(pshldv,    66, 0f38, 71, vl, dq, vl),
    INSN(pshldvw,   66, 0f38, 70, vl,  w, vl),
    INSN(pshldw,    66, 0f3a, 70, vl,  w, vl),
    INSN(pshrd,     66, 0f3a, 73, vl, dq, vl),
    INSN(pshrdv,    66, 0f38, 73, vl, dq, vl),
    INSN(pshrdvw,   66, 0f38, 72, vl,  w, vl),
    INSN(pshrdw,    66, 0f3a, 72, vl,  w, vl),
};

static const struct test avx512_vnni_all[] = {
    INSN(pdpbusd,  66, 0f38, 50, vl, d, vl),
    INSN(pdpbusds, 66, 0f38, 51, vl, d, vl),
    INSN(pdpwssd,  66, 0f38, 52, vl, d, vl),
    INSN(pdpwssds, 66, 0f38, 53, vl, d, vl),
};

static const struct test avx512_vpopcntdq_all[] = {
    INSN(popcnt, 66, 0f38, 55, vl, dq, vl)
};

static const struct test gfni_all[] = {
    INSN(gf2p8affineinvqb, 66, 0f3a, cf, vl, q, vl),
    INSN(gf2p8affineqb,    66, 0f3a, ce, vl, q, vl),
    INSN(gf2p8mulb,        66, 0f38, cf, vl, b, vl),
};

/*
 * The uses of b in this table are simply (one of) the shortest form(s) of
 * saying "no broadcast" without introducing a 128-bit granularity enumerator.
 * Due to all of the insns being WIG, w, d_nb, and q_nb would all also fit.
 */
static const struct test vaes_all[] = {
    INSN(aesdec,     66, 0f38, de, vl, b, vl),
    INSN(aesdeclast, 66, 0f38, df, vl, b, vl),
    INSN(aesenc,     66, 0f38, dc, vl, b, vl),
    INSN(aesenclast, 66, 0f38, dd, vl, b, vl),
};

static const struct test vpclmulqdq_all[] = {
    INSN(pclmulqdq, 66, 0f3a, 44, vl, q_nb, vl)
};

static const unsigned char vl_all[] = { VL_512, VL_128, VL_256 };
static const unsigned char vl_128[] = { VL_128 };
static const unsigned char vl_no128[] = { VL_512, VL_256 };
static const unsigned char vl_512[] = { VL_512 };

/*
 * This table, indicating the presence of an immediate (byte) for an opcode
 * space 0f major opcode, is indexed by high major opcode byte nibble, with
 * each table element then bit-indexed by low major opcode byte nibble.
 */
static const uint16_t imm0f[16] = {
    [0x7] = (1 << 0x0) /* vpshuf* */ |
            (1 << 0x1) /* vps{ll,ra,rl}w */ |
            (1 << 0x2) /* vps{l,r}ld, vp{rol,ror,sra}{d,q} */ |
            (1 << 0x3) /* vps{l,r}l{,d}q */,
    [0xc] = (1 << 0x2) /* vcmp{p,s}{d,s} */ |
            (1 << 0x4) /* vpinsrw */ |
            (1 << 0x5) /* vpextrw */ |
            (1 << 0x6) /* vshufp{d,s} */,
};

static struct x86_emulate_ops emulops;

/*
 * Access tracking (by granular) is used on the first 64 bytes of address
 * space. Instructions get encode with a raw Disp8 value of 1, which then
 * gets scaled accordingly. Hence accesses below the address <scaling factor>
 * as well as at or above 2 * <scaling factor> are indications of bugs. To
 * aid diagnosis / debugging, track all accesses below 3 * <scaling factor>.
 * With AVX512 the maximum scaling factor is 64.
 */
static unsigned int accessed[3 * 64];

static bool record_access(enum x86_segment seg, unsigned long offset,
                          unsigned int bytes)
{
    while ( bytes-- )
    {
        if ( offset >= ARRAY_SIZE(accessed) )
            return false;
        ++accessed[offset++];
    }

    return true;
}

static int read(enum x86_segment seg, unsigned long offset, void *p_data,
                unsigned int bytes, struct x86_emulate_ctxt *ctxt)
{
    if ( !record_access(seg, offset, bytes + !bytes) )
        return X86EMUL_UNHANDLEABLE;
    memset(p_data, 0, bytes);
    return X86EMUL_OKAY;
}

static int write(enum x86_segment seg, unsigned long offset, void *p_data,
                 unsigned int bytes, struct x86_emulate_ctxt *ctxt)
{
    if ( !record_access(seg, offset, bytes + !bytes) )
        return X86EMUL_UNHANDLEABLE;
    return X86EMUL_OKAY;
}

static void test_one(const struct test *test, enum vl vl,
                     unsigned char *instr, struct x86_emulate_ctxt *ctxt)
{
    unsigned int vsz, esz, i, n;
    int rc;
    bool sg = strstr(test->mnemonic, "gather") ||
              strstr(test->mnemonic, "scatter");
    bool imm = test->spc == SPC_0f3a ||
               (test->spc == SPC_0f &&
                (imm0f[test->opc >> 4] & (1 << (test->opc & 0xf))));
    union evex {
        uint8_t raw[3];
        struct {
            uint8_t opcx:2;
            uint8_t mbz:2;
            uint8_t R:1;
            uint8_t b:1;
            uint8_t x:1;
            uint8_t r:1;
            uint8_t pfx:2;
            uint8_t mbs:1;
            uint8_t reg:4;
            uint8_t w:1;
            uint8_t opmsk:3;
            uint8_t RX:1;
            uint8_t bcst:1;
            uint8_t lr:2;
            uint8_t z:1;
        };
    } evex = {
        .opcx = test->spc, .pfx = test->pfx, .lr = vl,
        .R = 1, .b = 1, .x = 1, .r = 1, .mbs = 1,
        .reg = 0xf, .RX = 1, .opmsk = sg,
    };

    switch ( test->esz )
    {
    case ESZ_b:
        esz = 1;
        break;

    case ESZ_w:
        esz = 2;
        evex.w = 1;
        break;

#ifdef __i386__
    case ESZ_d_WIG:
        evex.w = 1;
        /* fall through */
#endif
    case ESZ_d: case ESZ_d_nb:
        esz = 4;
        break;

    case ESZ_q: case ESZ_q_nb:
        esz = 8;
        evex.w = 1;
        break;

    default:
        ASSERT_UNREACHABLE();
    }

    switch ( test->vsz )
    {
    case VSZ_vl:
        vsz = 16 << vl;
        break;

    case VSZ_vl_2:
        vsz = 8 << vl;
        break;

    case VSZ_vl_4:
        vsz = 4 << vl;
        break;

    case VSZ_vl_8:
        vsz = 2 << vl;
        break;

    case VSZ_el:
        vsz = esz;
        break;

    case VSZ_el_2:
        vsz = esz * 2;
        break;

    case VSZ_el_4:
        vsz = esz * 4;
        break;

    case VSZ_el_8:
        vsz = esz * 8;
        break;

    default:
        ASSERT_UNREACHABLE();
    }

    /*
     * Note: SIB addressing is used here, such that S/G insns can be handled
     * without extra conditionals.
     */
    instr[0] = 0x62;
    instr[1] = evex.raw[0];
    instr[2] = evex.raw[1];
    instr[3] = evex.raw[2];
    instr[4] = test->opc;
    instr[5] = 0x44 | (test->ext << 3); /* ModR/M */
    instr[6] = 0x22; /* SIB: base rDX, index none / xMM4 */
    instr[7] = 1; /* Disp8 */
    instr[8] = 0; /* immediate, if any */

    asm volatile ( "kxnorw %k1, %k1, %k1" );
    asm volatile ( "vxorps %xmm4, %xmm4, %xmm4" );

    ctxt->regs->eip = (unsigned long)&instr[0];
    ctxt->regs->edx = 0;
    memset(accessed, 0, sizeof(accessed));

    rc = x86_emulate(ctxt, &emulops);
    if ( rc != X86EMUL_OKAY ||
         (ctxt->regs->eip != (unsigned long)&instr[8 + imm]) )
        goto fail;

    for ( i = 0; i < (test->scale == SC_vl ? vsz : esz); ++i )
         if ( accessed[i] )
             goto fail;

    n = test->scale == SC_vl ? vsz : esz;
    if ( !sg )
        n += vsz;
    else if ( !strstr(test->mnemonic, "pf") )
        n += esz;
    else
        ++n;

    for ( ; i < n; ++i )
         if ( accessed[i] != (sg ? (vsz / esz) >> (test->opc & 1 & !evex.w)
                                 : 1) )
             goto fail;

    for ( ; i < ARRAY_SIZE(accessed); ++i )
         if ( accessed[i] )
             goto fail;

    /* Also check the broadcast case, if available. */
    if ( test->vsz >= VSZ_el || test->scale != SC_vl )
        return;

    switch ( test->esz )
    {
    case ESZ_d_nb: case ESZ_q_nb:
    case ESZ_b: case ESZ_w: case ESZ_bw:
        return;

    case ESZ_d: case ESZ_q:
        break;

    default:
        ASSERT_UNREACHABLE();
    }

    evex.bcst = 1;
    instr[3] = evex.raw[2];

    ctxt->regs->eip = (unsigned long)&instr[0];
    memset(accessed, 0, sizeof(accessed));

    rc = x86_emulate(ctxt, &emulops);
    if ( rc != X86EMUL_OKAY ||
         (ctxt->regs->eip != (unsigned long)&instr[8 + imm]) )
        goto fail;

    for ( i = 0; i < esz; ++i )
         if ( accessed[i] )
             goto fail;
    for ( ; i < esz * 2; ++i )
         if ( accessed[i] != 1 )
             goto fail;
    for ( ; i < ARRAY_SIZE(accessed); ++i )
         if ( accessed[i] )
             goto fail;

    return;

 fail:
    printf("failed (v%s%s %u-bit)\n", test->mnemonic,
           evex.bcst ? "/bcst" : "", 128 << vl);
    exit(1);
}

static void test_pair(const struct test *tmpl, enum vl vl,
                      enum esz esz1, const char *suffix1,
                      enum esz esz2, const char *suffix2,
                      unsigned char *instr, struct x86_emulate_ctxt *ctxt)
{
    struct test test = *tmpl;
    char mnemonic[24];

    test.esz = esz1;
    snprintf(mnemonic, ARRAY_SIZE(mnemonic), "%s%s", tmpl->mnemonic, suffix1);
    test.mnemonic = mnemonic;
    test_one(&test, vl, instr, ctxt);

    test.esz = esz2;
    snprintf(mnemonic, ARRAY_SIZE(mnemonic), "%s%s", tmpl->mnemonic, suffix2);
    test.mnemonic = mnemonic;
    test_one(&test, vl, instr, ctxt);
}

static void test_group(const struct test tests[], unsigned int nr_test,
                       const unsigned char vl[], unsigned int nr_vl,
                       void *instr, struct x86_emulate_ctxt *ctxt)
{
    unsigned int i, j;

    for ( i = 0; i < nr_test; ++i )
    {
        for ( j = 0; j < nr_vl; ++j )
        {
            if ( vl[0] == VL_512 && vl[j] != VL_512 && !cpu_has_avx512vl )
                continue;

            switch ( tests[i].esz )
            {
            case ESZ_q_nb:
                /* The 128-bit form of VMOVDDUP needs special casing. */
                if ( vl[j] == VL_128 && tests[i].spc == SPC_0f &&
                     tests[i].opc == 0x12 && tests[i].pfx == PFX_f2 )
                {
                    struct test test = tests[i];

                    test.vsz = VSZ_el;
                    test.scale = SC_el;
                    test_one(&test, vl[j], instr, ctxt);
                    continue;
                }
                /* fall through */
            default:
                test_one(&tests[i], vl[j], instr, ctxt);
                break;

            case ESZ_bw:
                test_pair(&tests[i], vl[j], ESZ_b, "b", ESZ_w, "w",
                          instr, ctxt);
                break;

            case ESZ_dq:
                test_pair(&tests[i], vl[j], ESZ_d,
                          strncmp(tests[i].mnemonic, "cvt", 3) ? "d" : "l",
                          ESZ_q, "q", instr, ctxt);
                break;

#ifdef __i386__
            case ESZ_d_WIG:
                test_pair(&tests[i], vl[j], ESZ_d, "/W0",
                          ESZ_d_WIG, "/W1", instr, ctxt);
                break;
#endif

            case ESZ_sd:
                test_pair(&tests[i], vl[j],
                          ESZ_d, tests[i].vsz < VSZ_el ? "ps" : "ss",
                          ESZ_q, tests[i].vsz < VSZ_el ? "pd" : "sd",
                          instr, ctxt);
                break;
            }
        }
    }
}

void evex_disp8_test(void *instr, struct x86_emulate_ctxt *ctxt,
                     const struct x86_emulate_ops *ops)
{
    emulops = *ops;
    emulops.read = read;
    emulops.write = write;

#define RUN(feat, vl) do { \
    if ( cpu_has_##feat ) \
    { \
        printf("%-40s", "Testing " #feat "/" #vl " disp8 handling..."); \
        test_group(feat ## _ ## vl, ARRAY_SIZE(feat ## _ ## vl), \
                   vl_ ## vl, ARRAY_SIZE(vl_ ## vl), instr, ctxt); \
        printf("okay\n"); \
    } \
} while ( false )

    RUN(avx512f, all);
    RUN(avx512f, 128);
    RUN(avx512f, no128);
    RUN(avx512f, 512);
    RUN(avx512bw, all);
    RUN(avx512bw, 128);
    RUN(avx512cd, all);
    RUN(avx512dq, all);
    RUN(avx512dq, 128);
    RUN(avx512dq, no128);
    RUN(avx512dq, 512);
    RUN(avx512er, 512);
#define cpu_has_avx512pf cpu_has_avx512f
    RUN(avx512pf, 512);
    RUN(avx512_4fmaps, 512);
    RUN(avx512_4vnniw, 512);
    RUN(avx512_bf16, all);
    RUN(avx512_bitalg, all);
    RUN(avx512_ifma, all);
    RUN(avx512_vbmi, all);
    RUN(avx512_vbmi2, all);
    RUN(avx512_vnni, all);
    RUN(avx512_vpopcntdq, all);

    if ( cpu_has_avx512f )
    {
        RUN(gfni, all);
        RUN(vaes, all);
        RUN(vpclmulqdq, all);
    }
}
