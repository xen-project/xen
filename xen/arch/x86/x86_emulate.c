/******************************************************************************
 * x86_emulate.c
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 * 
 * Copyright (c) 2005 Keir Fraser
 */

#ifdef __TEST_HARNESS__
#include <stdio.h>
#include <stdint.h>
typedef uint8_t            u8;
typedef uint16_t           u16;
typedef uint32_t           u32;
typedef uint64_t           u64;
typedef int8_t             s8;
typedef int16_t            s16;
typedef int32_t            s32;
typedef int64_t            s64;
#include <public/xen.h>
#else
#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <asm/regs.h>
#endif
#include <asm-x86/x86_emulate.h>

/*
 * Opcode effective-address decode tables.
 * Note that we only emulate instructions that have at least one memory
 * operand (excluding implicit stack references). We assume that stack
 * references and instruction fetches will never occur in special memory
 * areas that require emulation. So, for example, 'mov <imm>,<reg>' need
 * not be handled.
 */

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0) /* 8-bit operands. */
/* Destination operand type. */
#define ImplicitOps (1<<1) /* Implicit in opcode. No generic decode. */
#define DstReg      (2<<1) /* Register operand. */
#define DstMem      (3<<1) /* Memory operand. */
#define DstMask     (3<<1)
/* Source operand type. */
#define SrcNone     (0<<3) /* No source operand. */
#define SrcImplicit (0<<3) /* Source operand is implicit in the opcode. */
#define SrcReg      (1<<3) /* Register operand. */
#define SrcMem      (2<<3) /* Memory operand. */
#define SrcImm      (3<<3) /* Immediate operand. */
#define SrcImmByte  (4<<3) /* 8-bit sign-extended immediate operand. */
#define SrcMask     (7<<3)
/* Generic ModRM decode. */
#define ModRM       (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)

static u8 opcode_table[256] = {
    /* 0x00 - 0x07 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x08 - 0x0F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x10 - 0x17 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x18 - 0x1F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x20 - 0x27 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x28 - 0x2F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x30 - 0x37 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x38 - 0x3F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x40 - 0x4F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x50 - 0x5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 - 0x6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 - 0x87 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    /* 0x88 - 0x8F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, DstMem|SrcNone|ModRM|Mov,
    /* 0x90 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    ByteOp|DstReg|SrcMem|Mov, DstReg|SrcMem|Mov,
    ByteOp|DstMem|SrcReg|Mov, DstMem|SrcReg|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xA8 - 0xAF */
    0, 0, ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xB0 - 0xBF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM, 0, 0,
    0, 0, ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    /* 0xC8 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xD7 */
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM, 
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM, 
    0, 0, 0, 0,
    /* 0xD8 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xF7 */
    0, 0, 0, 0,
    0, 0, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM,
    /* 0xF8 - 0xFF */
    0, 0, 0, 0,
    0, 0, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM
};

static u8 twobyte_table[256] = {
    /* 0x00 - 0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0,
    /* 0x10 - 0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0, 0, 0, 0, 0, 0,
    /* 0x20 - 0x2F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x30 - 0x3F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x40 - 0x47 */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x48 - 0x4F */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x50 - 0x5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 - 0x6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 - 0x8F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x90 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    0, 0, 0, DstMem|SrcReg|ModRM, 0, 0, 0, 0, 
    /* 0xA8 - 0xAF */
    0, 0, 0, DstMem|SrcReg|ModRM, 0, 0, 0, 0,
    /* 0xB0 - 0xB7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM, 0, DstMem|SrcReg|ModRM,
    0, 0, 0, 0,
    /* 0xB8 - 0xBF */
    0, 0, DstMem|SrcImmByte|ModRM, DstMem|SrcReg|ModRM, 0, 0, 0, 0,
    /* 0xC0 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xFF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Type, address-of, and value of an instruction's operand. */
struct operand {
    enum { OP_REG, OP_MEM, OP_IMM } type;
    unsigned int  bytes;
    unsigned long val, orig_val, *ptr;
};

/* EFLAGS bit definitions. */
#define EFLG_OF (1<<11)
#define EFLG_DF (1<<10)
#define EFLG_SF (1<<7)
#define EFLG_ZF (1<<6)
#define EFLG_AF (1<<4)
#define EFLG_PF (1<<2)
#define EFLG_CF (1<<0)

/*
 * Instruction emulation:
 * Most instructions are emulated directly via a fragment of inline assembly
 * code. This allows us to save/restore EFLAGS and thus very easily pick up
 * any modified flags.
 */

#if defined(__x86_64__)
#define _LO32 "k"          /* force 32-bit operand */
#define _STK  "%%rsp"      /* stack pointer */
#elif defined(__i386__)
#define _LO32 ""           /* force 32-bit operand */
#define _STK  "%%esp"      /* stack pointer */
#endif

/*
 * These EFLAGS bits are restored from saved value during emulation, and
 * any changes are written back to the saved value after emulation.
 */
#define EFLAGS_MASK (EFLG_OF|EFLG_SF|EFLG_ZF|EFLG_AF|EFLG_PF|EFLG_CF)

/* Before executing instruction: restore necessary bits in EFLAGS. */
/* EFLAGS = (_sav & _msk) | (EFLAGS & ~_msk); _sav &= ~msk; */
#define _PRE_EFLAGS(_sav, _msk, _tmp)           \
"push %"_sav"; "                                \
"movl %"_msk",%"_LO32 _tmp"; "                  \
"andl %"_LO32 _tmp",("_STK"); "                 \
"notl %"_LO32 _tmp"; "                          \
"andl %"_LO32 _tmp",%"_sav"; "                  \
"pushf; "                                       \
"andl %"_LO32 _tmp",("_STK"); "                 \
"pop  %"_tmp"; "                                \
"orl  %"_LO32 _tmp",("_STK"); "                 \
"popf; "

/* After executing instruction: write-back necessary bits in EFLAGS. */
/* _sav |= EFLAGS & _msk; */
#define _POST_EFLAGS(_sav, _msk, _tmp)          \
"pushf; "                                       \
"pop  %"_tmp"; "                                \
"andl %"_msk",%"_LO32 _tmp"; "                  \
"orl  %"_LO32 _tmp",%"_sav"; "

/* Raw emulation: instruction has two explicit operands. */
#define __emulate_2op_nobyte(_op,_src,_dst,_eflags,_wx,_wy,_lx,_ly,_qx,_qy)\
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 2:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"w %"_wx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : _wy ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    case 4:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"l %"_lx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : _ly ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    case 8:                                                                \
        __emulate_2op_8byte(_op, _src, _dst, _eflags, _qx, _qy);           \
        break;                                                             \
    }                                                                      \
} while (0)
#define __emulate_2op(_op,_src,_dst,_eflags,_bx,_by,_wx,_wy,_lx,_ly,_qx,_qy)\
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 1:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"b %"_bx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : _by ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    default:                                                               \
        __emulate_2op_nobyte(_op,_src,_dst,_eflags,_wx,_wy,_lx,_ly,_qx,_qy);\
        break;                                                             \
    }                                                                      \
} while (0)
/* Source operand is byte-sized and may be restricted to just %cl. */
#define emulate_2op_SrcB(_op, _src, _dst, _eflags)                         \
    __emulate_2op(_op, _src, _dst, _eflags,                                \
                  "b", "c", "b", "c", "b", "c", "b", "c")
/* Source operand is byte, word, long or quad sized. */
#define emulate_2op_SrcV(_op, _src, _dst, _eflags)                         \
    __emulate_2op(_op, _src, _dst, _eflags,                                \
                  "b", "q", "w", "r", _LO32, "r", "", "r")
/* Source operand is word, long or quad sized. */
#define emulate_2op_SrcV_nobyte(_op, _src, _dst, _eflags)                  \
    __emulate_2op_nobyte(_op, _src, _dst, _eflags,                         \
                  "w", "r", _LO32, "r", "", "r")

/* Instruction has only one explicit operand (no source operand). */
#define emulate_1op(_op,_dst,_eflags)                                      \
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 1:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"b %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 2:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"w %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 4:                                                                \
        __asm__ __volatile__ (                                             \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"l %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 8:                                                                \
        __emulate_1op_8byte(_op, _dst, _eflags);                           \
        break;                                                             \
    }                                                                      \
} while (0)

/* Emulate an instruction with quadword operands (x86/64 only). */
#if defined(__x86_64__)
#define __emulate_2op_8byte(_op, _src, _dst, _eflags, _qx, _qy)         \
do{ __asm__ __volatile__ (                                              \
        _PRE_EFLAGS("0","4","2")                                        \
        _op"q %"_qx"3,%1; "                                             \
        _POST_EFLAGS("0","4","2")                                       \
        : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)               \
        : _qy ((_src).val), "i" (EFLAGS_MASK) );                        \
} while (0)
#define __emulate_1op_8byte(_op, _dst, _eflags)                         \
do{ __asm__ __volatile__ (                                              \
        _PRE_EFLAGS("0","3","2")                                        \
        _op"q %1; "                                                     \
        _POST_EFLAGS("0","3","2")                                       \
        : "=m" (_eflags), "=m" ((_dst).val), "=&r" (_tmp)               \
        : "i" (EFLAGS_MASK) );                                          \
} while (0)
#elif defined(__i386__)
#define __emulate_2op_8byte(_op, _src, _dst, _eflags, _qx, _qy)
#define __emulate_1op_8byte(_op, _dst, _eflags)
#endif /* __i386__ */

/* Fetch next part of the instruction being emulated. */
#define insn_fetch(_type, _size, _eip) \
({ unsigned long _x; \
   if ( ops->read_std((unsigned long)(_eip), &_x, (_size)) ) \
       goto done; \
   (_eip) += (_size); \
   (_type)_x; \
})

#define DPRINTF(_f, _a...) printf( _f , ## _a )

void *
decode_register(
    u8 modrm_reg, struct xen_regs *regs, int highbyte_regs)
{
    void *p;

    switch ( modrm_reg )
    {
    case  0: p = &regs->eax; break;
    case  1: p = &regs->ecx; break;
    case  2: p = &regs->edx; break;
    case  3: p = &regs->ebx; break;
    case  4: p = (highbyte_regs ?
                  ((unsigned char *)&regs->eax + 1) : 
                  (unsigned char *)&regs->esp); break;
    case  5: p = (highbyte_regs ?
                  ((unsigned char *)&regs->ecx + 1) : 
                  (unsigned char *)&regs->ebp); break;
    case  6: p = (highbyte_regs ?
                  ((unsigned char *)&regs->edx + 1) : 
                  (unsigned char *)&regs->esi); break;
    case  7: p = (highbyte_regs ?
                  ((unsigned char *)&regs->ebx + 1) : 
                  (unsigned char *)&regs->edi); break;
#if defined(__x86_64__)
    case  8: p = &regs->r8;  break;
    case  9: p = &regs->r9;  break;
    case 10: p = &regs->r10; break;
    case 11: p = &regs->r11; break;
    case 12: p = &regs->r12; break;
    case 13: p = &regs->r13; break;
    case 14: p = &regs->r14; break;
    case 15: p = &regs->r15; break;
#endif
    default: p = NULL; break;
    }

    return p;
}

int 
x86_emulate_memop(
    struct xen_regs *regs,
    unsigned long cr2,
    struct x86_mem_emulator *ops,
    int mode)
{
    u8 b, d, sib, twobyte = 0, rex_prefix = 0;
    u8 modrm, modrm_mod = 0, modrm_reg = 0, modrm_rm = 0;
    unsigned int op_bytes = (mode == 8) ? 4 : mode, ad_bytes = mode;
    unsigned int lock_prefix = 0, rep_prefix = 0, i;
    struct operand src, dst;

    /* Shadow copy of register state. Committed on successful emulation. */
    struct xen_regs _regs = *regs;

    /* Legacy prefixes. */
    for ( i = 0; i < 8; i++ )
    {
        switch ( b = insn_fetch(u8, 1, _regs.eip) )
        {
        case 0x66: /* operand-size override */
            op_bytes ^= 6;                    /* switch between 2/4 bytes */
            break;
        case 0x67: /* address-size override */
            ad_bytes ^= (mode == 8) ? 12 : 6; /* switch between 2/4/8 bytes */
            break;
        case 0x2e: /* CS override */
        case 0x3e: /* DS override */
        case 0x26: /* ES override */
        case 0x64: /* FS override */
        case 0x65: /* GS override */
        case 0x36: /* SS override */
            DPRINTF("Warning: ignoring a segment override.\n");
            break;
        case 0xf0: /* LOCK */
            lock_prefix = 1;
            break;
        case 0xf3: /* REP/REPE/REPZ */
            rep_prefix = 1;
            break;
        case 0xf2: /* REPNE/REPNZ */
            break;
        default:
            goto done_prefixes;
        }
    }
 done_prefixes:

    if ( ad_bytes == 2 )
    {
        DPRINTF("Cannot parse 16-bit effective addresses.\n");
        goto cannot_emulate;
    }

    /* REX prefix. */
    if ( (mode == 8) && ((b & 0xf0) == 0x40) )
    {
        rex_prefix = b;
        if ( b & 8 )
            op_bytes = 8;          /* REX.W */
        modrm_reg = (b & 4) << 1;  /* REX.R */
        /* REX.B and REX.X do not need to be decoded. */
        b = insn_fetch(u8, 1, _regs.eip);
    }

    /* Opcode byte(s). */
    d = opcode_table[b];
    if ( d == 0 )
    {
        /* Two-byte opcode? */
        if ( b == 0x0f )
        {
            twobyte = 1;
            b = insn_fetch(u8, 1, _regs.eip);
            d = twobyte_table[b];
        }

        /* Unrecognised? */
        if ( d == 0 )
            goto cannot_emulate;
    }

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        modrm = insn_fetch(u8, 1, _regs.eip);
        modrm_mod |= (modrm & 0xc0) >> 6;
        modrm_reg |= (modrm & 0x38) >> 3;
        modrm_rm  |= (modrm & 0x07);
        switch ( modrm_mod )
        {
        case 0:
            if ( (modrm_rm == 4) && 
                 (((sib = insn_fetch(u8, 1, _regs.eip)) & 7) == 5) )
                _regs.eip += 4; /* skip disp32 specified by SIB.base */
            else if ( modrm_rm == 5 )
                _regs.eip += 4; /* skip disp32 */
            break;
        case 1:
            if ( modrm_rm == 4 )
                sib = insn_fetch(u8, 1, _regs.eip);
            _regs.eip += 1; /* skip disp8 */
            break;
        case 2:
            if ( modrm_rm == 4 )
                sib = insn_fetch(u8, 1, _regs.eip);
            _regs.eip += 4; /* skip disp32 */
            break;
        case 3:
            DPRINTF("Cannot parse ModRM.mod == 3.\n");
            goto cannot_emulate;
        }
    }

    /* Decode and fetch the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case ImplicitOps:
        /* Special instructions do their own operand decoding. */
        goto special_insn;
    case DstReg:
        dst.type = OP_REG;
        if ( d & ByteOp )
        {
            dst.ptr = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            dst.val = *(u8 *)dst.ptr;
            dst.bytes = 1;
        }
        else
        {
            dst.ptr = decode_register(modrm_reg, &_regs, 0);
            switch ( (dst.bytes = op_bytes) )
            {
            case 2: dst.val = *(u16 *)dst.ptr; break;
            case 4: dst.val = *(u32 *)dst.ptr; break;
            case 8: dst.val = *(u64 *)dst.ptr; break;
            }
        }
        break;
    case DstMem:
        dst.type  = OP_MEM;
        dst.ptr   = (unsigned long *)cr2;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( !(d & Mov) && /* optimisation - avoid slow emulated read */
             ops->read_emulated((unsigned long)dst.ptr, &dst.val, dst.bytes) )
             goto done;
        break;
    }
    dst.orig_val = dst.val;

    /* Decode and fetch the source operand: register, memory or immediate. */
    switch ( d & SrcMask )
    {
    case SrcNone:
        break;
    case SrcReg:
        src.type = OP_REG;
        if ( d & ByteOp )
        {
            src.ptr = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            src.val = src.orig_val = *(u8 *)src.ptr;
            src.bytes = 1;
        }
        else
        {
            src.ptr = decode_register(modrm_reg, &_regs, 0);
            switch ( (src.bytes = op_bytes) )
            {
            case 2: src.val = src.orig_val = *(u16 *)src.ptr; break;
            case 4: src.val = src.orig_val = *(u32 *)src.ptr; break;
            case 8: src.val = src.orig_val = *(u64 *)src.ptr; break;
            }
        }
        break;
    case SrcMem:
        src.type  = OP_MEM;
        src.ptr   = (unsigned long *)cr2;
        src.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( ops->read_emulated((unsigned long)src.ptr, &src.val, src.bytes) )
            goto done;
        src.orig_val = src.val;
        break;
    case SrcImm:
        src.type  = OP_IMM;
        src.ptr   = (unsigned long *)_regs.eip;
        src.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( src.bytes == 8 ) src.bytes = 4;
        /* NB. Immediates are sign-extended as necessary. */
        switch ( src.bytes )
        {
        case 1: src.val = insn_fetch(s8,  1, _regs.eip); break;
        case 2: src.val = insn_fetch(s16, 2, _regs.eip); break;
        case 4: src.val = insn_fetch(s32, 4, _regs.eip); break;
        }
        break;
    case SrcImmByte:
        src.type  = OP_IMM;
        src.ptr   = (unsigned long *)_regs.eip;
        src.bytes = 1;
        src.val   = insn_fetch(s8,  1, _regs.eip);
        break;
    }

    if ( twobyte )
        goto twobyte_insn;

    switch ( b )
    {
    case 0x00 ... 0x05: add: /* add */
        emulate_2op_SrcV("add", src, dst, _regs.eflags);
        break;
    case 0x08 ... 0x0d: or:  /* or */
        emulate_2op_SrcV("or", src, dst, _regs.eflags);
        break;
    case 0x10 ... 0x15: adc: /* adc */
        emulate_2op_SrcV("adc", src, dst, _regs.eflags);
        break;
    case 0x18 ... 0x1d: sbb: /* sbb */
        emulate_2op_SrcV("sbb", src, dst, _regs.eflags);
        break;
    case 0x20 ... 0x25: and: /* and */
        emulate_2op_SrcV("and", src, dst, _regs.eflags);
        break;
    case 0x28 ... 0x2d: sub: /* sub */
        emulate_2op_SrcV("sub", src, dst, _regs.eflags);
        break;
    case 0x30 ... 0x35: xor: /* xor */
        emulate_2op_SrcV("xor", src, dst, _regs.eflags);
        break;
    case 0x38 ... 0x3d: cmp: /* cmp */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        break;
    case 0x80 ... 0x83: /* Grp1 */
        switch ( modrm_reg )
        {
        case 0: goto add;
        case 1: goto or;
        case 2: goto adc;
        case 3: goto sbb;
        case 4: goto and;
        case 5: goto sub;
        case 6: goto xor;
        case 7: goto cmp;
        }
        break;
    case 0x84 ... 0x85: test: /* test */
        emulate_2op_SrcV("test", src, dst, _regs.eflags);
        break;
    case 0x86 ... 0x87: /* xchg */
        src.val ^= dst.val;
        dst.val ^= src.val;
        src.val ^= dst.val;
        break;
    case 0xa0 ... 0xa1: /* mov */
        dst.ptr = (unsigned long *)&_regs.eax;
        dst.val = src.val;
        _regs.eip += ad_bytes; /* skip src displacement */
        break;
    case 0xa2 ... 0xa3: /* mov */
        dst.val = (unsigned long)_regs.eax;
        _regs.eip += ad_bytes; /* skip dst displacement */
        break;
    case 0x88 ... 0x8b: /* mov */
    case 0xc6 ... 0xc7: /* mov (sole member of Grp11) */
        dst.val = src.val;
        break;
    case 0x8f: /* pop (sole member of Grp1a) */
        /* 64-bit mode: POP defaults to 64-bit operands. */
        if ( (mode == 8) && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( ops->read_std(_regs.esp, &dst.val, dst.bytes) )
            goto done;
        _regs.esp += dst.bytes;
        break;
    case 0xc0 ... 0xc1: grp2: /* Grp2 */
        switch ( modrm_reg )
        {
        case 0: /* rol */
            emulate_2op_SrcB("rol", src, dst, _regs.eflags);
            break;
        case 1: /* ror */
            emulate_2op_SrcB("ror", src, dst, _regs.eflags);
            break;
        case 2: /* rcl */
            emulate_2op_SrcB("rcl", src, dst, _regs.eflags);
            break;
        case 3: /* rcr */
            emulate_2op_SrcB("rcr", src, dst, _regs.eflags);
            break;
        case 4: /* sal/shl */
        case 6: /* sal/shl */
            emulate_2op_SrcB("sal", src, dst, _regs.eflags);
            break;
        case 5: /* shr */
            emulate_2op_SrcB("shr", src, dst, _regs.eflags);
            break;
        case 7: /* sar */
            emulate_2op_SrcB("sar", src, dst, _regs.eflags);
            break;
        }
        break;
    case 0xd0 ... 0xd1: /* Grp2 */
        src.val = 1;
        goto grp2;
    case 0xd2 ... 0xd3: /* Grp2 */
        src.val = _regs.ecx;
        goto grp2;
    case 0xf6 ... 0xf7: /* Grp3 */
        switch ( modrm_reg )
        {
        case 0 ... 1: /* test */
            /* Special case in Grp3: test has an immediate source operand. */
            src.type = OP_IMM;
            src.ptr  = (unsigned long *)_regs.eip;
            src.bytes = (d & ByteOp) ? 1 : op_bytes;
            if ( src.bytes == 8 ) src.bytes = 4;
            switch ( src.bytes )
            {
            case 1: src.val = insn_fetch(s8,  1, _regs.eip); break;
            case 2: src.val = insn_fetch(s16, 2, _regs.eip); break;
            case 4: src.val = insn_fetch(s32, 4, _regs.eip); break;
            }
            goto test;
        case 2: /* not */
            dst.val = ~dst.val;
            break;
        case 3: /* neg */
            emulate_1op("neg", dst, _regs.eflags);
            break;
        default:
            goto cannot_emulate;
        }
        break;
    case 0xfe ... 0xff: /* Grp4/Grp5 */
        switch ( modrm_reg )
        {
        case 0: /* inc */
            emulate_1op("inc", dst, _regs.eflags);
            break;
        case 1: /* dec */
            emulate_1op("dec", dst, _regs.eflags);
            break;
        case 6: /* push */
            /* 64-bit mode: PUSH defaults to 64-bit operands. */
            if ( (mode == 8) && (dst.bytes == 4) )
            {
                dst.bytes = 8;
                if ( ops->read_std((unsigned long)dst.ptr, &dst.val, 8) )
                    goto done;
            }
            _regs.esp -= dst.bytes;
            if ( ops->write_std(_regs.esp, dst.val, dst.bytes) )
                goto done;
            dst.val = dst.orig_val; /* skanky: disable writeback */
            break;
        default:
            goto cannot_emulate;
        }
        break;
    }

 writeback:
    if ( (d & Mov) || (dst.orig_val != dst.val) )
    {
        switch ( dst.type )
        {
        case OP_REG:
            /* The 4-byte case *is* correct: in 64-bit mode we zero-extend. */
            switch ( dst.bytes )
            {
            case 1: *(u8  *)dst.ptr = (u8)dst.val; break;
            case 2: *(u16 *)dst.ptr = (u16)dst.val; break;
            case 4: *dst.ptr = (u32)dst.val; break; /* 64b mode: zero-extend */
            case 8: *dst.ptr = dst.val; break;
            }
            break;
        case OP_MEM:
            if ( lock_prefix )
            {
                unsigned long seen;
                if ( ops->cmpxchg_emulated((unsigned long)dst.ptr,
                                           dst.orig_val, dst.val,
                                           &seen, dst.bytes) )
                    goto done;
                if ( seen != dst.orig_val )
                    goto done; /* Try again... */
            }
            else
            {
                if ( ops->write_emulated((unsigned long)dst.ptr,
                                         dst.val, dst.bytes) )
                    goto done;
            }
            break;
        default:
            break;
        }
    }

    /* Commit shadow register state. */
    *regs = _regs;

 done:
    return 0;

 special_insn:
    if ( twobyte )
        goto twobyte_special_insn;
    if ( rep_prefix )
    {
        if ( _regs.ecx == 0 )
        {
            regs->eip = _regs.eip;
            goto done;
        }
        _regs.ecx--;
        _regs.eip = regs->eip;
    }
    switch ( b )
    {
    case 0xa4 ... 0xa5: /* movs */
        dst.type  = OP_MEM;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( _regs.error_code & 2 )
        {
            /* Write fault: destination is special memory. */
            dst.ptr = (unsigned long *)cr2;
            if ( ops->read_std(_regs.esi - _regs.edi + cr2, 
                               &dst.val, dst.bytes) )
                goto done;
        }
        else
        {
            /* Read fault: source is special memory. */
            dst.ptr = (unsigned long *)(_regs.edi - _regs.esi + cr2);
            if ( ops->read_emulated(cr2, &dst.val, dst.bytes) )
                goto done;
        }
        _regs.esi += (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes;
        _regs.edi += (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes;
        break;
    case 0xa6 ... 0xa7: /* cmps */
        DPRINTF("Urk! I don't handle CMPS.\n");
        goto cannot_emulate;
    case 0xaa ... 0xab: /* stos */
        dst.type  = OP_MEM;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.ptr   = (unsigned long *)cr2;
        dst.val   = _regs.eax;
        _regs.edi += (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes;
        break;
    case 0xac ... 0xad: /* lods */
        dst.type  = OP_REG;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.ptr   = (unsigned long *)&_regs.eax;
        if ( ops->read_emulated(cr2, &dst.val, dst.bytes) )
            goto done;
        _regs.esi += (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes;
        break;
    case 0xae ... 0xaf: /* scas */
        DPRINTF("Urk! I don't handle SCAS.\n");
        goto cannot_emulate;
    }
    goto writeback;

 twobyte_insn:
    switch ( b )
    {
    case 0x40 ... 0x4f: /* cmov */
        dst.val = dst.orig_val = src.val;
        d &= ~Mov; /* default to no move */
        /* First, assume we're decoding an even cmov opcode (lsb == 0). */
        switch ( (b & 15) >> 1 )
        {
        case 0: /* cmovo */
            d |= (_regs.eflags & EFLG_OF) ? Mov : 0;
            break;
        case 1: /* cmovb/cmovc/cmovnae */
            d |= (_regs.eflags & EFLG_CF) ? Mov : 0;
            break;
        case 2: /* cmovz/cmove */
            d |= (_regs.eflags & EFLG_ZF) ? Mov : 0;
            break;
        case 3: /* cmovbe/cmovna */
            d |= (_regs.eflags & (EFLG_CF|EFLG_ZF)) ? Mov : 0;
            break;
        case 4: /* cmovs */
            d |= (_regs.eflags & EFLG_SF) ? Mov : 0;
            break;
        case 5: /* cmovp/cmovpe */
            d |= (_regs.eflags & EFLG_PF) ? Mov : 0;
            break;
        case 7: /* cmovle/cmovng */
            d |= (_regs.eflags & EFLG_ZF) ? Mov : 0;
            /* fall through */
        case 6: /* cmovl/cmovnge */
            d |= (!(_regs.eflags & EFLG_SF) != !(_regs.eflags & EFLG_OF)) ?
                Mov : 0;
            break;
        }
        /* Odd cmov opcodes (lsb == 1) have inverted sense. */
        d ^= (b & 1) ? Mov : 0;
        break;
    case 0xb0 ... 0xb1: /* cmpxchg */
        /* Save real source value, then compare EAX against destination. */
        src.orig_val = src.val;
        src.val = _regs.eax;
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        /* Always write back. The question is: where to? */
        d |= Mov;
        if ( _regs.eflags & EFLG_ZF )
        {
            /* Success: write back to memory. */
            dst.val = src.orig_val;
        }
        else
        {
            /* Failure: write the value we saw to EAX. */
            dst.type = OP_REG;
            dst.ptr  = (unsigned long *)&_regs.eax;
        }
        break;
    case 0xa3: bt: /* bt */
        src.val &= (1UL << (1 << dst.bytes)) - 1; /* only subword offset */
        emulate_2op_SrcV_nobyte("bt", src, dst, _regs.eflags);
        break;
    case 0xb3: btr: /* btr */
        src.val &= (1UL << (1 << dst.bytes)) - 1; /* only subword offset */
        emulate_2op_SrcV_nobyte("btr", src, dst, _regs.eflags);
        break;
    case 0xab: bts: /* bts */
        src.val &= (1UL << (1 << dst.bytes)) - 1; /* only subword offset */
        emulate_2op_SrcV_nobyte("bts", src, dst, _regs.eflags);
        break;
    case 0xbb: btc: /* btc */
        src.val &= (1UL << (1 << dst.bytes)) - 1; /* only subword offset */
        emulate_2op_SrcV_nobyte("btc", src, dst, _regs.eflags);
        break;
    case 0xba: /* Grp8 */
        switch ( modrm_reg >> 1 )
        {
        case 0: goto bt;
        case 1: goto bts;
        case 2: goto btr;
        case 3: goto btc;
        }
        break;
    }
    goto writeback;

 twobyte_special_insn:
    /* Only prefetch instructions get here, so nothing to do. */
    dst.orig_val = dst.val; /* disable writeback */
    goto writeback;

 cannot_emulate:
    DPRINTF("Cannot emulate %02x\n", b);
    return -1;
}
