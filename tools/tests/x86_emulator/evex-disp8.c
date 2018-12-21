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
    INSN(broadcastss,  66, 0f38, 18,    el,      d, el),
    INSN_FP(cmp,             0f, c2),
    INSN(comisd,       66,   0f, 2f,    el,      q, el),
    INSN(comiss,         ,   0f, 2f,    el,      d, el),
    INSN_FP(div,             0f, 5e),
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
    INSN_FP(max,             0f, 5f),
    INSN_FP(min,             0f, 5d),
    INSN_SFP(mov,            0f, 10),
    INSN_SFP(mov,            0f, 11),
    INSN_PFP_NB(mova,        0f, 28),
    INSN_PFP_NB(mova,        0f, 29),
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
    INSN_PFP_NB(movu,        0f, 10),
    INSN_PFP_NB(movu,        0f, 11),
    INSN_FP(mul,             0f, 59),
    INSN(paddd,        66,   0f, fe,    vl,      d, vl),
    INSN(paddq,        66,   0f, d4,    vl,      q, vl),
    INSN(pand,         66,   0f, db,    vl,     dq, vl),
    INSN(pandn,        66,   0f, df,    vl,     dq, vl),
    INSN(pcmp,         66, 0f3a, 1f,    vl,     dq, vl),
    INSN(pcmpeqd,      66,   0f, 76,    vl,      d, vl),
    INSN(pcmpeqq,      66, 0f38, 29,    vl,      q, vl),
    INSN(pcmpgtd,      66,   0f, 66,    vl,      d, vl),
    INSN(pcmpgtq,      66, 0f38, 37,    vl,      q, vl),
    INSN(pcmpu,        66, 0f3a, 1e,    vl,     dq, vl),
    INSN(pmaxs,        66, 0f38, 3d,    vl,     dq, vl),
    INSN(pmaxu,        66, 0f38, 3f,    vl,     dq, vl),
    INSN(pmins,        66, 0f38, 39,    vl,     dq, vl),
    INSN(pminu,        66, 0f38, 3b,    vl,     dq, vl),
    INSN(pmuldq,       66, 0f38, 28,    vl,      q, vl),
    INSN(pmulld,       66, 0f38, 40,    vl,      d, vl),
    INSN(pmuludq,      66,   0f, f4,    vl,      q, vl),
    INSN(por,          66,   0f, eb,    vl,     dq, vl),
    INSNX(prol,        66,   0f, 72, 1, vl,     dq, vl),
    INSN(prolv,        66, 0f38, 15,    vl,     dq, vl),
    INSNX(pror,        66,   0f, 72, 0, vl,     dq, vl),
    INSN(prorv,        66, 0f38, 14,    vl,     dq, vl),
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
    INSN(pxor,         66,   0f, ef,    vl,     dq, vl),
    INSN_PFP(shuf,           0f, c6),
    INSN_FP(sqrt,            0f, 51),
    INSN_FP(sub,             0f, 5c),
    INSN(ucomisd,      66,   0f, 2e,    el,      q, el),
    INSN(ucomiss,        ,   0f, 2e,    el,      d, el),
    INSN_PFP(unpckh,         0f, 15),
    INSN_PFP(unpckl,         0f, 14),
};

static const struct test avx512f_128[] = {
    INSN(mov,       66,   0f, 6e, el, dq64, el),
    INSN(mov,       66,   0f, 7e, el, dq64, el),
    INSN(movq,      f3,   0f, 7e, el,    q, el),
    INSN(movq,      66,   0f, d6, el,    q, el),
};

static const struct test avx512f_no128[] = {
    INSN(broadcastf32x4, 66, 0f38, 1a, el_4,  d, vl),
    INSN(broadcastsd,    66, 0f38, 19, el,    q, el),
};

static const struct test avx512f_512[] = {
    INSN(broadcastf64x4, 66, 0f38, 1b, el_4, q, vl),
};

static const struct test avx512bw_all[] = {
    INSN(movdqu8,     f2,   0f, 6f,    vl,    b, vl),
    INSN(movdqu8,     f2,   0f, 7f,    vl,    b, vl),
    INSN(movdqu16,    f2,   0f, 6f,    vl,    w, vl),
    INSN(movdqu16,    f2,   0f, 7f,    vl,    w, vl),
    INSN(paddb,       66,   0f, fc,    vl,    b, vl),
    INSN(paddsb,      66,   0f, ec,    vl,    b, vl),
    INSN(paddsw,      66,   0f, ed,    vl,    w, vl),
    INSN(paddusb,     66,   0f, dc,    vl,    b, vl),
    INSN(paddusw,     66,   0f, dd,    vl,    w, vl),
    INSN(paddw,       66,   0f, fd,    vl,    w, vl),
    INSN(pavgb,       66,   0f, e0,    vl,    b, vl),
    INSN(pavgw,       66,   0f, e3,    vl,    w, vl),
    INSN(pcmp,        66, 0f3a, 3f,    vl,   bw, vl),
    INSN(pcmpeqb,     66,   0f, 74,    vl,    b, vl),
    INSN(pcmpeqw,     66,   0f, 75,    vl,    w, vl),
    INSN(pcmpgtb,     66,   0f, 64,    vl,    b, vl),
    INSN(pcmpgtw,     66,   0f, 65,    vl,    w, vl),
    INSN(pcmpu,       66, 0f3a, 3e,    vl,   bw, vl),
    INSN(pmaddwd,     66,   0f, f5,    vl,    w, vl),
    INSN(pmaxsb,      66, 0f38, 3c,    vl,    b, vl),
    INSN(pmaxsw,      66,   0f, ee,    vl,    w, vl),
    INSN(pmaxub,      66,   0f, de,    vl,    b, vl),
    INSN(pmaxuw,      66, 0f38, 3e,    vl,    w, vl),
    INSN(pminsb,      66, 0f38, 38,    vl,    b, vl),
    INSN(pminsw,      66,   0f, ea,    vl,    w, vl),
    INSN(pminub,      66,   0f, da,    vl,    b, vl),
    INSN(pminuw,      66, 0f38, 3a,    vl,    w, vl),
    INSN(pmulhuw,     66,   0f, e4,    vl,    w, vl),
    INSN(pmulhw,      66,   0f, e5,    vl,    w, vl),
    INSN(pmullw,      66,   0f, d5,    vl,    w, vl),
    INSN(psadbw,      66,   0f, f6,    vl,    b, vl),
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
};

static const struct test avx512dq_all[] = {
    INSN_PFP(and,              0f, 54),
    INSN_PFP(andn,             0f, 55),
    INSN_PFP(or,               0f, 56),
    INSN(pmullq,         66, 0f38, 40,   vl,  q, vl),
    INSN_PFP(xor,              0f, 57),
};

static const struct test avx512dq_no128[] = {
    INSN(broadcastf32x2, 66, 0f38, 19, el_2, d, vl),
    INSN(broadcastf64x2, 66, 0f38, 1a, el_2, q, vl),
};

static const struct test avx512dq_512[] = {
    INSN(broadcastf32x8, 66, 0f38, 1b, el_8, d, vl),
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
    if ( !record_access(seg, offset, bytes) )
        return X86EMUL_UNHANDLEABLE;
    memset(p_data, 0, bytes);
    return X86EMUL_OKAY;
}

static int write(enum x86_segment seg, unsigned long offset, void *p_data,
                 unsigned int bytes, struct x86_emulate_ctxt *ctxt)
{
    if ( !record_access(seg, offset, bytes) )
        return X86EMUL_UNHANDLEABLE;
    return X86EMUL_OKAY;
}

static void test_one(const struct test *test, enum vl vl,
                     unsigned char *instr, struct x86_emulate_ctxt *ctxt)
{
    unsigned int vsz, esz, i;
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
    instr[6] = 0x12; /* SIB: base rDX, index none / xMM4 */
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
    for ( ; i < (test->scale == SC_vl ? vsz : esz) + (sg ? esz : vsz); ++i )
         if ( accessed[i] != (sg ? vsz / esz : 1) )
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
            default:
                test_one(&tests[i], vl[j], instr, ctxt);
                break;

            case ESZ_bw:
                test_pair(&tests[i], vl[j], ESZ_b, "b", ESZ_w, "w",
                          instr, ctxt);
                break;

            case ESZ_dq:
                test_pair(&tests[i], vl[j], ESZ_d, "d", ESZ_q, "q",
                          instr, ctxt);
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
    RUN(avx512dq, all);
    RUN(avx512dq, no128);
    RUN(avx512dq, 512);
}
