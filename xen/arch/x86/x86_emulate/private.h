/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * private.h - interface between x86_emulate.c and its helpers
 *
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 */

#ifdef __XEN__

# include <xen/bug.h>
# include <xen/kernel.h>
# include <asm/endbr.h>
# include <asm/msr-index.h>
# include <asm/x86-vendors.h>
# include <asm/x86_emulate.h>

# undef BUG /* Make sure it's not used anywhere here. */
void BUG(void);

# ifndef CONFIG_HVM
#  define X86EMUL_NO_FPU
#  define X86EMUL_NO_MMX
#  define X86EMUL_NO_SIMD
# endif

#else /* !__XEN__ */
# include "x86-emulate.h"
#endif

#ifdef __i386__
# define mode_64bit() false
# define r(name) e ## name
# define PTR_POISON NULL /* 32-bit builds are for user-space, so NULL is OK. */
#else
# define mode_64bit() (ctxt->addr_size == 64)
# define r(name) r ## name
# define PTR_POISON ((void *)0x8086000000008086UL) /* non-canonical */
#endif

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0) /* 8-bit operands. */
/* Destination operand type. */
#define DstNone     (0<<1) /* No destination operand. */
#define DstImplicit (0<<1) /* Destination operand is implicit in the opcode. */
#define DstBitBase  (1<<1) /* Memory operand, bit string. */
#define DstReg      (2<<1) /* Register operand. */
#define DstEax      DstReg /* Register EAX (aka DstReg with no ModRM) */
#define DstMem      (3<<1) /* Memory operand. */
#define DstMask     (3<<1)
/* Source operand type. */
#define SrcNone     (0<<3) /* No source operand. */
#define SrcImplicit (0<<3) /* Source operand is implicit in the opcode. */
#define SrcReg      (1<<3) /* Register operand. */
#define SrcEax      SrcReg /* Register EAX (aka SrcReg with no ModRM) */
#define SrcMem      (2<<3) /* Memory operand. */
#define SrcMem16    (3<<3) /* Memory operand (16-bit). */
#define SrcImm      (4<<3) /* Immediate operand. */
#define SrcImmByte  (5<<3) /* 8-bit sign-extended immediate operand. */
#define SrcImm16    (6<<3) /* 16-bit zero-extended immediate operand. */
#define SrcMask     (7<<3)
/* Generic ModRM decode. */
#define ModRM       (1<<6)
/* vSIB addressing mode (0f38 extension opcodes only), aliasing ModRM. */
#define vSIB        (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)
/* VEX/EVEX (SIMD only): 2nd source operand unused (must be all ones) */
#define TwoOp       Mov
/* All operands are implicit in the opcode. */
#define ImplicitOps (DstImplicit|SrcImplicit)

typedef uint8_t opcode_desc_t;

enum disp8scale {
    /* Values 0 ... 4 are explicit sizes. */
    d8s_bw = 5,
    d8s_dq,
    /* EVEX.W ignored outside of 64-bit mode */
    d8s_dq64,
    /*
     * All further values must strictly be last and in the order
     * given so that arithmetic on the values works.
     */
    d8s_vl,
    d8s_vl_by_2,
    d8s_vl_by_4,
    d8s_vl_by_8,
};
typedef uint8_t disp8scale_t;

/* Type, address-of, and value of an instruction's operand. */
struct operand {
    enum { OP_REG, OP_MEM, OP_IMM, OP_NONE } type;
    unsigned int bytes;

    /* Operand value. */
    unsigned long val;

    /* Original operand value. */
    unsigned long orig_val;

    /* OP_REG: Pointer to register field. */
    unsigned long *reg;

    /* OP_MEM: Segment and offset. */
    struct {
        enum x86_segment seg;
        unsigned long    off;
    } mem;
};

#define REX_PREFIX 0x40
#define REX_B 0x01
#define REX_X 0x02
#define REX_R 0x04
#define REX_W 0x08

enum simd_opsize {
    simd_none,

    /*
     * Ordinary packed integers:
     * - 64 bits without prefix 66 (MMX)
     * - 128 bits with prefix 66 (SSEn)
     * - 128/256/512 bits depending on VEX.L/EVEX.LR (AVX+)
     */
    simd_packed_int,

    /*
     * Ordinary packed/scalar floating point:
     * - 128 bits without prefix or with prefix 66 (SSEn)
     * - 128/256/512 bits depending on VEX.L/EVEX.LR (AVX+)
     * - 32 bits with prefix F3 (scalar single)
     * - 64 bits with prefix F2 (scalar doubgle)
     */
    simd_any_fp,

    /*
     * Packed floating point:
     * - 128 bits without prefix or with prefix 66 (SSEn)
     * - 128/256/512 bits depending on VEX.L/EVEX.LR (AVX+)
     */
    simd_packed_fp,

    /*
     * Single precision packed/scalar floating point:
     * - 128 bits without prefix (SSEn)
     * - 128/256/512 bits depending on VEX.L/EVEX.LR (AVX+)
     * - 32 bits with prefix F3 (scalar)
     */
    simd_single_fp,

    /*
     * Scalar floating point:
     * - 32 bits with low opcode bit clear (scalar single)
     * - 64 bits with low opcode bit set (scalar double)
     */
    simd_scalar_opc,

    /*
     * Scalar floating point:
     * - 32/64 bits depending on VEX.W/EVEX.W
     */
    simd_scalar_vexw,

    /*
     * 128 bits of integer or floating point data, with no further
     * formatting information, or with it encoded by EVEX.W.
     */
    simd_128,

    /*
     * 256 bits of integer or floating point data, with formatting
     * encoded by EVEX.W.
     */
    simd_256,

    /* Operand size encoded in non-standard way. */
    simd_other
};
typedef uint8_t simd_opsize_t;

#define vex_none 0

enum vex_opcx {
    vex_0f = vex_none + 1,
    vex_0f38,
    vex_0f3a,
    evex_map5 = 5,
    evex_map6,
};

enum vex_pfx {
    vex_66 = vex_none + 1,
    vex_f3,
    vex_f2
};

#define VEX_PREFIX_DOUBLE_MASK 0x1
#define VEX_PREFIX_SCALAR_MASK 0x2

union vex {
    uint8_t raw[2];
    struct {             /* SDM names */
        uint8_t opcx:5;  /* mmmmm */
        uint8_t b:1;     /* B */
        uint8_t x:1;     /* X */
        uint8_t r:1;     /* R */
        uint8_t pfx:2;   /* pp */
        uint8_t l:1;     /* L */
        uint8_t reg:4;   /* vvvv */
        uint8_t w:1;     /* W */
    };
};

union evex {
    uint8_t raw[3];
    struct {             /* SDM names */
        uint8_t opcx:3;  /* mmm */
        uint8_t mbz:1;
        uint8_t R:1;     /* R' */
        uint8_t b:1;     /* B */
        uint8_t x:1;     /* X */
        uint8_t r:1;     /* R */
        uint8_t pfx:2;   /* pp */
        uint8_t mbs:1;
        uint8_t reg:4;   /* vvvv */
        uint8_t w:1;     /* W */
        uint8_t opmsk:3; /* aaa */
        uint8_t RX:1;    /* V' */
        uint8_t brs:1;   /* b */
        uint8_t lr:2;    /* L'L */
        uint8_t z:1;     /* z */
    };
};

struct x86_emulate_state {
    unsigned int op_bytes, ad_bytes;

    enum {
        ext_none = vex_none,
        ext_0f   = vex_0f,
        ext_0f38 = vex_0f38,
        ext_0f3a = vex_0f3a,
        ext_map5 = evex_map5,
        ext_map6 = evex_map6,
        /*
         * For XOP use values such that the respective instruction field
         * can be used without adjustment.
         */
        ext_8f08 = 8,
        ext_8f09,
        ext_8f0a,
    } ext;
    enum {
        rmw_NONE,
        rmw_adc,
        rmw_add,
        rmw_and,
        rmw_btc,
        rmw_btr,
        rmw_bts,
        rmw_cmpccxadd,
        rmw_dec,
        rmw_inc,
        rmw_neg,
        rmw_not,
        rmw_or,
        rmw_rcl,
        rmw_rcr,
        rmw_rol,
        rmw_ror,
        rmw_sar,
        rmw_sbb,
        rmw_shl,
        rmw_shld,
        rmw_shr,
        rmw_shrd,
        rmw_sub,
        rmw_xadd,
        rmw_xchg,
        rmw_xor,
    } rmw;
    enum {
        blk_NONE,
        blk_enqcmd,
#ifndef X86EMUL_NO_FPU
        blk_fld, /* FLDENV, FRSTOR */
        blk_fst, /* FNSTENV, FNSAVE */
#endif
#if !defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
    !defined(X86EMUL_NO_SIMD)
        blk_fxrstor,
        blk_fxsave,
#endif
        blk_movdir,
    } blk;
    uint8_t modrm, modrm_mod, modrm_reg, modrm_rm;
    uint8_t sib_index, sib_scale;
    uint8_t rex_prefix;
    bool lock_prefix;
    bool not_64bit; /* Instruction not available in 64bit. */
    bool fpu_ctrl;  /* Instruction is an FPU control one. */
    bool fp16;      /* Instruction has half-precision FP source operand. */
    opcode_desc_t desc;
    union vex vex;
    union evex evex;
    enum simd_opsize simd_size;

    /*
     * Data operand effective address (usually computed from ModRM).
     * Default is a memory operand relative to segment DS.
     */
    struct operand ea;

    /* Immediate operand values, if any. Use otherwise unused fields. */
#define imm1 ea.val
#define imm2 ea.orig_val

    unsigned long ip;

    struct stub_exn *stub_exn;

#ifndef NDEBUG
    /*
     * Track caller of x86_decode_insn() to spot missing as well as
     * premature calls to x86_emulate_free_state().
     */
    void *caller;
#endif
};

static inline void check_state(const struct x86_emulate_state *s)
{
#if defined(__XEN__) && !defined(NDEBUG)
    ASSERT(s->caller);
#endif
}

typedef union {
    uint64_t mmx;
    uint64_t __attribute__ ((aligned(16))) xmm[2];
    uint64_t __attribute__ ((aligned(32))) ymm[4];
    uint64_t __attribute__ ((aligned(64))) zmm[8];
    uint32_t data32[16];
} mmval_t;

struct x86_fxsr {
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw, :8;
    uint16_t fop;
    union {
        struct {
            uint32_t offs;
            uint16_t sel, :16;
        };
        uint64_t addr;
    } fip, fdp;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    struct {
        uint8_t data[10];
        uint16_t :16, :16, :16;
    } fpreg[8];
    uint64_t __attribute__ ((aligned(16))) xmm[16][2];
    uint64_t rsvd[6];
    uint64_t avl[6];
};

#ifndef X86EMUL_NO_FPU
struct x87_env16 {
    uint16_t fcw;
    uint16_t fsw;
    uint16_t ftw;
    union {
        struct {
            uint16_t fip_lo;
            uint16_t fop:11, :1, fip_hi:4;
            uint16_t fdp_lo;
            uint16_t :12, fdp_hi:4;
        } real;
        struct {
            uint16_t fip;
            uint16_t fcs;
            uint16_t fdp;
            uint16_t fds;
        } prot;
    } mode;
};

struct x87_env32 {
    uint32_t fcw:16, :16;
    uint32_t fsw:16, :16;
    uint32_t ftw:16, :16;
    union {
        struct {
            /* some CPUs/FPUs also store the full FIP here */
            uint32_t fip_lo:16, :16;
            uint32_t fop:11, :1, fip_hi:16, :4;
            /* some CPUs/FPUs also store the full FDP here */
            uint32_t fdp_lo:16, :16;
            uint32_t :12, fdp_hi:16, :4;
        } real;
        struct {
            uint32_t fip;
            uint32_t fcs:16, fop:11, :5;
            uint32_t fdp;
            uint32_t fds:16, :16;
        } prot;
    } mode;
};
#endif

/*
 * Externally visible return codes from x86_emulate() are non-negative.
 * Use negative values for internal state change indicators from helpers
 * to the main function.
 */
#define X86EMUL_rdtsc        (-1)
#define X86EMUL_stub_failure (-2)

/*
 * These EFLAGS bits are restored from saved value during emulation, and
 * any changes are written back to the saved value after emulation.
 */
#define EFLAGS_MASK (X86_EFLAGS_OF | X86_EFLAGS_SF | X86_EFLAGS_ZF | \
                     X86_EFLAGS_AF | X86_EFLAGS_PF | X86_EFLAGS_CF)

/*
 * These EFLAGS bits are modifiable (by POPF and IRET), possibly subject
 * to further CPL and IOPL constraints.
 */
#define EFLAGS_MODIFIABLE (X86_EFLAGS_ID | X86_EFLAGS_AC | X86_EFLAGS_RF | \
                           X86_EFLAGS_NT | X86_EFLAGS_IOPL | X86_EFLAGS_DF | \
                           X86_EFLAGS_IF | X86_EFLAGS_TF | EFLAGS_MASK)

#define truncate_word(ea, byte_width)           \
({  unsigned long __ea = (ea);                  \
    unsigned int _width = (byte_width);         \
    ((_width == sizeof(unsigned long)) ? __ea : \
     (__ea & ((1UL << (_width << 3)) - 1)));    \
})
#define truncate_ea(ea) truncate_word((ea), ad_bytes)

#define fail_if(p)                                      \
do {                                                    \
    rc = (p) ? X86EMUL_UNHANDLEABLE : X86EMUL_OKAY;     \
    if ( rc ) goto done;                                \
} while (0)

#define EXPECT(p)                                       \
do {                                                    \
    if ( unlikely(!(p)) )                               \
    {                                                   \
        ASSERT_UNREACHABLE();                           \
        goto unhandleable;                              \
    }                                                   \
} while (0)

static inline int mkec(uint8_t e, int32_t ec, ...)
{
    return (e < 32 && ((1u << e) & X86_EXC_HAVE_EC)) ? ec : X86_EVENT_NO_EC;
}

#define generate_exception_if(p, e, ec...)                                \
({  if ( (p) ) {                                                          \
        x86_emul_hw_exception(e, mkec(e, ##ec, 0), ctxt);                 \
        rc = X86EMUL_EXCEPTION;                                           \
        goto done;                                                        \
    }                                                                     \
})

#define generate_exception(e, ec...) generate_exception_if(true, e, ##ec)

static inline bool
in_realmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    unsigned long cr0;
    int rc;

    if ( ops->read_cr == NULL )
        return 0;

    rc = ops->read_cr(0, &cr0, ctxt);
    return (!rc && !(cr0 & X86_CR0_PE));
}

static inline bool
in_protmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    return !(in_realmode(ctxt, ops) || (ctxt->regs->eflags & X86_EFLAGS_VM));
}

#define mode_ring0() ({                         \
    int _cpl = x86emul_get_cpl(ctxt, ops);      \
    fail_if(_cpl < 0);                          \
    (_cpl == 0);                                \
})

static inline bool
_amd_like(const struct cpu_policy *cp)
{
    return cp->x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON);
}

static inline bool
amd_like(const struct x86_emulate_ctxt *ctxt)
{
    return _amd_like(ctxt->cpu_policy);
}

#define vcpu_has_fpu()         (ctxt->cpuid->basic.fpu)
#define vcpu_has_sep()         (ctxt->cpuid->basic.sep)
#define vcpu_has_cx8()         (ctxt->cpuid->basic.cx8)
#define vcpu_has_cmov()        (ctxt->cpuid->basic.cmov)
#define vcpu_has_clflush()     (ctxt->cpuid->basic.clflush)
#define vcpu_has_mmx()         (ctxt->cpuid->basic.mmx)
#define vcpu_has_fxsr()        (ctxt->cpuid->basic.fxsr)
#define vcpu_has_sse()         (ctxt->cpuid->basic.sse)
#define vcpu_has_sse2()        (ctxt->cpuid->basic.sse2)
#define vcpu_has_sse3()        (ctxt->cpuid->basic.sse3)
#define vcpu_has_pclmulqdq()   (ctxt->cpuid->basic.pclmulqdq)
#define vcpu_has_ssse3()       (ctxt->cpuid->basic.ssse3)
#define vcpu_has_fma()         (ctxt->cpuid->basic.fma)
#define vcpu_has_cx16()        (ctxt->cpuid->basic.cx16)
#define vcpu_has_sse4_1()      (ctxt->cpuid->basic.sse4_1)
#define vcpu_has_sse4_2()      (ctxt->cpuid->basic.sse4_2)
#define vcpu_has_movbe()       (ctxt->cpuid->basic.movbe)
#define vcpu_has_popcnt()      (ctxt->cpuid->basic.popcnt)
#define vcpu_has_aesni()       (ctxt->cpuid->basic.aesni)
#define vcpu_has_avx()         (ctxt->cpuid->basic.avx)
#define vcpu_has_f16c()        (ctxt->cpuid->basic.f16c)
#define vcpu_has_rdrand()      (ctxt->cpuid->basic.rdrand)

#define vcpu_has_mmxext()      (ctxt->cpuid->extd.mmxext || vcpu_has_sse())
#define vcpu_has_3dnow_ext()   (ctxt->cpuid->extd._3dnowext)
#define vcpu_has_3dnow()       (ctxt->cpuid->extd._3dnow)
#define vcpu_has_lahf_lm()     (ctxt->cpuid->extd.lahf_lm)
#define vcpu_has_cr8_legacy()  (ctxt->cpuid->extd.cr8_legacy)
#define vcpu_has_lzcnt()       (ctxt->cpuid->extd.abm)
#define vcpu_has_sse4a()       (ctxt->cpuid->extd.sse4a)
#define vcpu_has_misalignsse() (ctxt->cpuid->extd.misalignsse)
#define vcpu_has_xop()         (ctxt->cpuid->extd.xop)
#define vcpu_has_fma4()        (ctxt->cpuid->extd.fma4)
#define vcpu_has_tbm()         (ctxt->cpuid->extd.tbm)
#define vcpu_has_clzero()      (ctxt->cpuid->extd.clzero)
#define vcpu_has_wbnoinvd()    (ctxt->cpuid->extd.wbnoinvd)
#define vcpu_has_nscb()        (ctxt->cpuid->extd.nscb)

#define vcpu_has_bmi1()        (ctxt->cpuid->feat.bmi1)
#define vcpu_has_hle()         (ctxt->cpuid->feat.hle)
#define vcpu_has_avx2()        (ctxt->cpuid->feat.avx2)
#define vcpu_has_bmi2()        (ctxt->cpuid->feat.bmi2)
#define vcpu_has_invpcid()     (ctxt->cpuid->feat.invpcid)
#define vcpu_has_rtm()         (ctxt->cpuid->feat.rtm)
#define vcpu_has_mpx()         (ctxt->cpuid->feat.mpx)
#define vcpu_has_avx512f()     (ctxt->cpuid->feat.avx512f)
#define vcpu_has_avx512dq()    (ctxt->cpuid->feat.avx512dq)
#define vcpu_has_rdseed()      (ctxt->cpuid->feat.rdseed)
#define vcpu_has_adx()         (ctxt->cpuid->feat.adx)
#define vcpu_has_smap()        (ctxt->cpuid->feat.smap)
#define vcpu_has_avx512_ifma() (ctxt->cpuid->feat.avx512_ifma)
#define vcpu_has_clflushopt()  (ctxt->cpuid->feat.clflushopt)
#define vcpu_has_clwb()        (ctxt->cpuid->feat.clwb)
#define vcpu_has_avx512cd()    (ctxt->cpuid->feat.avx512cd)
#define vcpu_has_sha()         (ctxt->cpuid->feat.sha)
#define vcpu_has_avx512bw()    (ctxt->cpuid->feat.avx512bw)
#define vcpu_has_avx512vl()    (ctxt->cpuid->feat.avx512vl)
#define vcpu_has_avx512_vbmi() (ctxt->cpuid->feat.avx512_vbmi)
#define vcpu_has_avx512_vbmi2() (ctxt->cpuid->feat.avx512_vbmi2)
#define vcpu_has_gfni()        (ctxt->cpuid->feat.gfni)
#define vcpu_has_vaes()        (ctxt->cpuid->feat.vaes)
#define vcpu_has_vpclmulqdq()  (ctxt->cpuid->feat.vpclmulqdq)
#define vcpu_has_avx512_vnni() (ctxt->cpuid->feat.avx512_vnni)
#define vcpu_has_avx512_bitalg() (ctxt->cpuid->feat.avx512_bitalg)
#define vcpu_has_avx512_vpopcntdq() (ctxt->cpuid->feat.avx512_vpopcntdq)
#define vcpu_has_rdpid()       (ctxt->cpuid->feat.rdpid)
#define vcpu_has_movdiri()     (ctxt->cpuid->feat.movdiri)
#define vcpu_has_movdir64b()   (ctxt->cpuid->feat.movdir64b)
#define vcpu_has_enqcmd()      (ctxt->cpuid->feat.enqcmd)
#define vcpu_has_avx512_vp2intersect() (ctxt->cpuid->feat.avx512_vp2intersect)
#define vcpu_has_serialize()   (ctxt->cpuid->feat.serialize)
#define vcpu_has_tsxldtrk()    (ctxt->cpuid->feat.tsxldtrk)
#define vcpu_has_avx512_fp16() (ctxt->cpuid->feat.avx512_fp16)
#define vcpu_has_sha512()      (ctxt->cpuid->feat.sha512)
#define vcpu_has_sm3()         (ctxt->cpuid->feat.sm3)
#define vcpu_has_sm4()         (ctxt->cpuid->feat.sm4)
#define vcpu_has_avx_vnni()    (ctxt->cpuid->feat.avx_vnni)
#define vcpu_has_avx512_bf16() (ctxt->cpuid->feat.avx512_bf16)
#define vcpu_has_cmpccxadd()   (ctxt->cpuid->feat.cmpccxadd)
#define vcpu_has_wrmsrns()     (ctxt->cpuid->feat.wrmsrns)
#define vcpu_has_avx_ifma()    (ctxt->cpuid->feat.avx_ifma)
#define vcpu_has_avx_vnni_int8() (ctxt->cpuid->feat.avx_vnni_int8)
#define vcpu_has_avx_ne_convert() (ctxt->cpuid->feat.avx_ne_convert)
#define vcpu_has_avx_vnni_int16() (ctxt->cpuid->feat.avx_vnni_int16)

#define vcpu_must_have(feat) \
    generate_exception_if(!vcpu_has_##feat(), X86_EXC_UD)

#ifdef __XEN__
/*
 * Note the difference between vcpu_must_have(<feature>) and
 * host_and_vcpu_must_have(<feature>): The latter needs to be used when
 * emulation code is using the same instruction class for carrying out
 * the actual operation.
 */
# define host_and_vcpu_must_have(feat) ({ \
    generate_exception_if(!cpu_has_##feat, X86_EXC_UD); \
    vcpu_must_have(feat); \
})
#else
/*
 * For the test harness both are fine to be used interchangeably, i.e.
 * features known to always be available (e.g. SSE/SSE2) to (64-bit) Xen
 * may be checked for by just vcpu_must_have().
 */
# define host_and_vcpu_must_have(feat) vcpu_must_have(feat)
#endif

/*
 * Instruction emulation:
 * Most instructions are emulated directly via a fragment of inline assembly
 * code. This allows us to save/restore EFLAGS and thus very easily pick up
 * any modified flags.
 */

#if defined(__x86_64__)
#define _LO32 "k"          /* force 32-bit operand */
#define _STK  "%%rsp"      /* stack pointer */
#define _BYTES_PER_LONG "8"
#elif defined(__i386__)
#define _LO32 ""           /* force 32-bit operand */
#define _STK  "%%esp"      /* stack pointer */
#define _BYTES_PER_LONG "4"
#endif

/* Before executing instruction: restore necessary bits in EFLAGS. */
#define _PRE_EFLAGS(_sav, _msk, _tmp)                           \
/* EFLAGS = (_sav & _msk) | (EFLAGS & ~_msk); _sav &= ~_msk; */ \
"movl %"_LO32 _sav",%"_LO32 _tmp"; "                            \
"push %"_tmp"; "                                                \
"push %"_tmp"; "                                                \
"movl %"_msk",%"_LO32 _tmp"; "                                  \
"andl %"_LO32 _tmp",("_STK"); "                                 \
"pushf; "                                                       \
"notl %"_LO32 _tmp"; "                                          \
"andl %"_LO32 _tmp",("_STK"); "                                 \
"andl %"_LO32 _tmp",2*"_BYTES_PER_LONG"("_STK"); "              \
"pop  %"_tmp"; "                                                \
"orl  %"_LO32 _tmp",("_STK"); "                                 \
"popf; "                                                        \
"pop  %"_tmp"; "                                                \
"movl %"_LO32 _tmp",%"_LO32 _sav"; "

/* After executing instruction: write-back necessary bits in EFLAGS. */
#define _POST_EFLAGS(_sav, _msk, _tmp)          \
/* _sav |= EFLAGS & _msk; */                    \
"pushf; "                                       \
"pop  %"_tmp"; "                                \
"andl %"_msk",%"_LO32 _tmp"; "                  \
"orl  %"_LO32 _tmp",%"_LO32 _sav"; "

#ifdef __XEN__

# include <xen/domain_page.h>
# include <asm/uaccess.h>

# define get_stub(stb) ({                                    \
    void *_ptr;                                              \
    BUILD_BUG_ON(STUB_BUF_SIZE / 2 < MAX_INST_LEN + 1);      \
    ASSERT(!(stb).ptr);                                      \
    (stb).addr = this_cpu(stubs.addr) + STUB_BUF_SIZE / 2;   \
    (stb).ptr = map_domain_page(_mfn(this_cpu(stubs.mfn))) + \
        ((stb).addr & ~PAGE_MASK);                           \
    _ptr = memset((stb).ptr, 0xcc, STUB_BUF_SIZE / 2);       \
    if ( cpu_has_xen_ibt )                                   \
    {                                                        \
        place_endbr64(_ptr);                                 \
        _ptr += 4;                                           \
    }                                                        \
    _ptr;                                                    \
})

# define put_stub(stb) ({             \
    if ( (stb).ptr )                  \
    {                                 \
        unmap_domain_page((stb).ptr); \
        (stb).ptr = NULL;             \
    }                                 \
})


struct stub_exn {
    union stub_exception_token info;
    unsigned int line;
};

# define invoke_stub(pre, post, constraints...) do {                    \
    stub_exn.info = (union stub_exception_token) { .raw = ~0 };         \
    stub_exn.line = __LINE__; /* Utility outweighs livepatching cost */ \
    block_speculation(); /* SCSB */                                     \
    asm volatile ( pre "\n\tINDIRECT_CALL %[stub]\n\t" post "\n"        \
                   ".Lret%=:\n\t"                                       \
                   ".pushsection .fixup,\"ax\"\n"                       \
                   ".Lfix%=:\n\t"                                       \
                   "pop %[exn]\n\t"                                     \
                   "jmp .Lret%=\n\t"                                    \
                   ".popsection\n\t"                                    \
                   _ASM_EXTABLE(.Lret%=, .Lfix%=)                       \
                   : [exn] "+g" (stub_exn.info) ASM_CALL_CONSTRAINT,    \
                     constraints,                                       \
                     [stub] "r" (stub.func),                            \
                     "m" (*(uint8_t(*)[MAX_INST_LEN + 1])stub.ptr) );   \
    if ( unlikely(~stub_exn.info.raw) )                                 \
        goto emulation_stub_failure;                                    \
} while (0)

#else /* !__XEN__ */

# define get_stub(stb) ({                        \
    assert(!(stb).addr);                         \
    (void *)((stb).addr = (uintptr_t)(stb).buf); \
})

# define put_stub(stb) ((stb).addr = 0)

struct stub_exn {};

# define invoke_stub(pre, post, constraints...)                         \
    asm volatile ( pre "\n\tcall *%[stub]\n\t" post                     \
                   : constraints, [stub] "rm" (stub.func),              \
                     "m" (*(typeof(stub.buf) *)stub.addr) )

#endif /* __XEN__ */

int x86emul_get_cpl(struct x86_emulate_ctxt *ctxt,
                    const struct x86_emulate_ops *ops);

int x86emul_get_fpu(enum x86_emulate_fpu_type type,
                    struct x86_emulate_ctxt *ctxt,
                    const struct x86_emulate_ops *ops);

#define get_fpu(type)                                           \
do {                                                            \
    rc = x86emul_get_fpu(fpu_type = (type), ctxt, ops);         \
    if ( rc ) goto done;                                        \
} while (0)

int x86emul_decode(struct x86_emulate_state *s,
                   struct x86_emulate_ctxt *ctxt,
                   const struct x86_emulate_ops *ops);

int x86emul_fpu(struct x86_emulate_state *s,
                struct cpu_user_regs *regs,
                struct operand *dst,
                struct operand *src,
                struct x86_emulate_ctxt *ctxt,
                const struct x86_emulate_ops *ops,
                unsigned int *insn_bytes,
                enum x86_emulate_fpu_type *fpu_type,
                mmval_t *mmvalp);
int x86emul_0f01(struct x86_emulate_state *s,
                 struct cpu_user_regs *regs,
                 struct operand *dst,
                 struct x86_emulate_ctxt *ctxt,
                 const struct x86_emulate_ops *ops);
int x86emul_0fae(struct x86_emulate_state *s,
                 struct cpu_user_regs *regs,
                 struct operand *dst,
                 const struct operand *src,
                 struct x86_emulate_ctxt *ctxt,
                 const struct x86_emulate_ops *ops,
                 enum x86_emulate_fpu_type *fpu_type);
int x86emul_0fc7(struct x86_emulate_state *s,
                 struct cpu_user_regs *regs,
                 struct operand *dst,
                 struct x86_emulate_ctxt *ctxt,
                 const struct x86_emulate_ops *ops,
                 mmval_t *mmvalp);

/* Initialise output state in x86_emulate_ctxt */
static inline void init_context(struct x86_emulate_ctxt *ctxt)
{
    ctxt->retire.raw = 0;
    x86_emul_reset_event(ctxt);
}

static inline bool is_aligned(enum x86_segment seg, unsigned long offs,
                              unsigned int size, struct x86_emulate_ctxt *ctxt,
                              const struct x86_emulate_ops *ops)
{
    struct segment_register reg;

    /* Expecting powers of two only. */
    ASSERT(!(size & (size - 1)));

    if ( mode_64bit() && seg < x86_seg_fs )
        memset(&reg, 0, sizeof(reg));
    else
    {
        /* No alignment checking when we have no way to read segment data. */
        if ( !ops->read_segment )
            return true;

        if ( ops->read_segment(seg, &reg, ctxt) != X86EMUL_OKAY )
            return false;
    }

    return !((reg.base + offs) & (size - 1));
}

static inline bool umip_active(struct x86_emulate_ctxt *ctxt,
                               const struct x86_emulate_ops *ops)
{
    unsigned long cr4;

    /* Intentionally not using mode_ring0() here to avoid its fail_if(). */
    return x86emul_get_cpl(ctxt, ops) > 0 &&
           ops->read_cr && ops->read_cr(4, &cr4, ctxt) == X86EMUL_OKAY &&
           (cr4 & X86_CR4_UMIP);
}

/* Compatibility function: read guest memory, zero-extend result to a ulong. */
static inline int read_ulong(enum x86_segment seg,
                             unsigned long offset,
                             unsigned long *val,
                             unsigned int bytes,
                             struct x86_emulate_ctxt *ctxt,
                             const struct x86_emulate_ops *ops)
{
    *val = 0;
    return ops->read(seg, offset, val, bytes, ctxt);
}
