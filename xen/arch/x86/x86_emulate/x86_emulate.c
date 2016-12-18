/******************************************************************************
 * x86_emulate.c
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 * 
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

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
/* Destination is only written; never read. */
#define Mov         (1<<7)
/* All operands are implicit in the opcode. */
#define ImplicitOps (DstImplicit|SrcImplicit)

typedef uint8_t opcode_desc_t;

static const opcode_desc_t opcode_table[256] = {
    /* 0x00 - 0x07 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x08 - 0x0F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, 0,
    /* 0x10 - 0x17 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x18 - 0x1F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x20 - 0x27 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x28 - 0x2F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x30 - 0x37 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x38 - 0x3F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x40 - 0x4F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x50 - 0x5F */
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x60 - 0x67 */
    ImplicitOps, ImplicitOps, DstReg|SrcMem|ModRM, DstReg|SrcNone|ModRM|Mov,
    0, 0, 0, 0,
    /* 0x68 - 0x6F */
    DstImplicit|SrcImm|Mov, DstReg|SrcImm|ModRM|Mov,
    DstImplicit|SrcImmByte|Mov, DstReg|SrcImmByte|ModRM|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x70 - 0x77 */
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    /* 0x78 - 0x7F */
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    /* 0x80 - 0x87 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    /* 0x88 - 0x8F */
    ByteOp|DstMem|SrcReg|ModRM|Mov, DstMem|SrcReg|ModRM|Mov,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstMem|SrcReg|ModRM|Mov, DstReg|SrcNone|ModRM,
    DstReg|SrcMem16|ModRM|Mov, DstMem|SrcNone|ModRM|Mov,
    /* 0x90 - 0x97 */
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    /* 0x98 - 0x9F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps, ImplicitOps,
    /* 0xA0 - 0xA7 */
    ByteOp|DstEax|SrcMem|Mov, DstEax|SrcMem|Mov,
    ByteOp|DstMem|SrcEax|Mov, DstMem|SrcEax|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xA8 - 0xAF */
    ByteOp|DstEax|SrcImm, DstEax|SrcImm,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xB0 - 0xB7 */
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    /* 0xB8 - 0xBF */
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    DstImplicit|SrcImm16, ImplicitOps,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    ByteOp|DstMem|SrcImm|ModRM|Mov, DstMem|SrcImm|ModRM|Mov,
    /* 0xC8 - 0xCF */
    DstImplicit|SrcImm16, ImplicitOps, DstImplicit|SrcImm16, ImplicitOps,
    ImplicitOps, DstImplicit|SrcImmByte, ImplicitOps, ImplicitOps,
    /* 0xD0 - 0xD7 */
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM,
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte, ImplicitOps, ImplicitOps,
    /* 0xD8 - 0xDF */
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    /* 0xE0 - 0xE7 */
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstEax|SrcImmByte, DstEax|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    /* 0xE8 - 0xEF */
    DstImplicit|SrcImm|Mov, DstImplicit|SrcImm,
    ImplicitOps, DstImplicit|SrcImmByte,
    DstEax|SrcImplicit, DstEax|SrcImplicit, ImplicitOps, ImplicitOps,
    /* 0xF0 - 0xF7 */
    0, ImplicitOps, 0, 0,
    ImplicitOps, ImplicitOps, ByteOp|ModRM, ModRM,
    /* 0xF8 - 0xFF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM
};

static const opcode_desc_t twobyte_table[256] = {
    /* 0x00 - 0x07 */
    ModRM, ImplicitOps|ModRM, ModRM, ModRM,
    0, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x08 - 0x0F */
    ImplicitOps, ImplicitOps, 0, ImplicitOps,
    0, ImplicitOps|ModRM, ImplicitOps, ModRM|SrcImmByte,
    /* 0x10 - 0x17 */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    /* 0x18 - 0x1F */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    /* 0x20 - 0x27 */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    0, 0, 0, 0,
    /* 0x28 - 0x2F */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    /* 0x30 - 0x37 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, 0, ImplicitOps,
    /* 0x38 - 0x3F */
    DstReg|SrcMem|ModRM, 0, DstReg|SrcImmByte|ModRM, 0, 0, 0, 0, 0,
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
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM,
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM,
    /* 0x60 - 0x6F */
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM,
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ImplicitOps|ModRM,
    /* 0x70 - 0x7F */
    SrcImmByte|ModRM, SrcImmByte|ModRM, SrcImmByte|ModRM, SrcImmByte|ModRM,
    ModRM, ModRM, ModRM, ImplicitOps,
    ModRM, ModRM, 0, 0, ModRM, ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    /* 0x80 - 0x87 */
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    /* 0x88 - 0x8F */
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    DstImplicit|SrcImm, DstImplicit|SrcImm,
    /* 0x90 - 0x97 */
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    /* 0x98 - 0x9F */
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    /* 0xA0 - 0xA7 */
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps, DstBitBase|SrcReg|ModRM,
    DstMem|SrcImmByte|ModRM, DstMem|SrcReg|ModRM, ModRM, ModRM,
    /* 0xA8 - 0xAF */
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps, DstBitBase|SrcReg|ModRM,
    DstMem|SrcImmByte|ModRM, DstMem|SrcReg|ModRM,
    ImplicitOps|ModRM, DstReg|SrcMem|ModRM,
    /* 0xB0 - 0xB7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    DstReg|SrcMem|ModRM|Mov, DstBitBase|SrcReg|ModRM,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xB8 - 0xBF */
    DstReg|SrcMem|ModRM, ModRM,
    DstBitBase|SrcImmByte|ModRM, DstBitBase|SrcReg|ModRM,
    DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    SrcImmByte|ModRM, DstMem|SrcReg|ModRM|Mov,
    SrcImmByte|ModRM, SrcImmByte|ModRM, SrcImmByte|ModRM, ImplicitOps|ModRM,
    /* 0xC8 - 0xCF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xD0 - 0xDF */
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ImplicitOps|ModRM, ModRM,
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM,
    /* 0xE0 - 0xEF */
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ImplicitOps|ModRM,
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM,
    /* 0xF0 - 0xFF */
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM,
    ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM, ModRM
};

static const opcode_desc_t xop_table[] = {
    DstReg|SrcImmByte|ModRM,
    DstReg|SrcMem|ModRM,
    DstReg|SrcImm|ModRM,
};

#define REX_PREFIX 0x40
#define REX_B 0x01
#define REX_X 0x02
#define REX_R 0x04
#define REX_W 0x08

#define vex_none 0

enum vex_opcx {
    vex_0f = vex_none + 1,
    vex_0f38,
    vex_0f3a,
};

enum vex_pfx {
    vex_66 = vex_none + 1,
    vex_f3,
    vex_f2
};

#define VEX_PREFIX_DOUBLE_MASK 0x1
#define VEX_PREFIX_SCALAR_MASK 0x2

static const uint8_t sse_prefix[] = { 0x66, 0xf3, 0xf2 };

#define SET_SSE_PREFIX(dst, vex_pfx) do { \
    if ( vex_pfx ) \
        (dst) = sse_prefix[(vex_pfx) - 1]; \
} while (0)

union vex {
    uint8_t raw[2];
    struct {
        uint8_t opcx:5;
        uint8_t b:1;
        uint8_t x:1;
        uint8_t r:1;
        uint8_t pfx:2;
        uint8_t l:1;
        uint8_t reg:4;
        uint8_t w:1;
    };
};

#define copy_REX_VEX(ptr, rex, vex) do { \
    if ( (vex).opcx != vex_none ) \
        ptr[0] = 0xc4, ptr[1] = (vex).raw[0], ptr[2] = (vex).raw[1]; \
    else if ( mode_64bit() ) \
        ptr[1] = rex | REX_PREFIX; \
} while (0)

union evex {
    uint8_t raw[3];
    struct {
        uint8_t opcx:2;
        uint8_t :2;
        uint8_t R:1;
        uint8_t b:1;
        uint8_t x:1;
        uint8_t r:1;
        uint8_t pfx:2;
        uint8_t evex:1;
        uint8_t reg:4;
        uint8_t w:1;
        uint8_t opmsk:3;
        uint8_t RX:1;
        uint8_t bcst:1;
        uint8_t lr:2;
        uint8_t z:1;
    };
};

#define rep_prefix()   (vex.pfx >= vex_f3)
#define repe_prefix()  (vex.pfx == vex_f3)
#define repne_prefix() (vex.pfx == vex_f2)

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
#ifdef __x86_64__
#define PTR_POISON ((void *)0x8086000000008086UL) /* non-canonical */
#else
#define PTR_POISON NULL /* 32-bit builds are for user-space, so NULL is OK. */
#endif

typedef union {
    uint64_t mmx;
    uint64_t __attribute__ ((aligned(16))) xmm[2];
    uint64_t __attribute__ ((aligned(32))) ymm[4];
} mmval_t;

/*
 * While proper alignment gets specified above, this doesn't get honored by
 * the compiler for automatic variables. Use this helper to instantiate a
 * suitably aligned variable, producing a pointer to access it.
 */
#define DECLARE_ALIGNED(type, var)                                   \
    long __##var[sizeof(type) + __alignof(type) - __alignof(long)];  \
    type *const var##p =                                             \
        (void *)((long)(__##var + __alignof(type) - __alignof(long)) \
                 & -__alignof(type))

/* MSRs. */
#define MSR_TSC          0x00000010
#define MSR_SYSENTER_CS  0x00000174
#define MSR_SYSENTER_ESP 0x00000175
#define MSR_SYSENTER_EIP 0x00000176
#define MSR_EFER         0xc0000080
#define MSR_STAR         0xc0000081
#define MSR_LSTAR        0xc0000082
#define MSR_CSTAR        0xc0000083
#define MSR_FMASK        0xc0000084
#define MSR_TSC_AUX      0xc0000103

/* Control register flags. */
#define CR0_PE    (1<<0)
#define CR0_MP    (1<<1)
#define CR0_EM    (1<<2)
#define CR0_TS    (1<<3)

#define CR4_TSD        (1<<2)
#define CR4_OSFXSR     (1<<9)
#define CR4_OSXMMEXCPT (1<<10)
#define CR4_UMIP       (1<<11)
#define CR4_OSXSAVE    (1<<18)

/* EFLAGS bit definitions. */
#define EFLG_VIP  (1<<20)
#define EFLG_VIF  (1<<19)
#define EFLG_AC   (1<<18)
#define EFLG_VM   (1<<17)
#define EFLG_RF   (1<<16)
#define EFLG_NT   (1<<14)
#define EFLG_IOPL (3<<12)
#define EFLG_OF   (1<<11)
#define EFLG_DF   (1<<10)
#define EFLG_IF   (1<<9)
#define EFLG_TF   (1<<8)
#define EFLG_SF   (1<<7)
#define EFLG_ZF   (1<<6)
#define EFLG_AF   (1<<4)
#define EFLG_PF   (1<<2)
#define EFLG_CF   (1<<0)

/* MXCSR bit definitions. */
#define MXCSR_MM  (1U << 17)

/* Exception definitions. */
#define EXC_DE  0
#define EXC_DB  1
#define EXC_BP  3
#define EXC_OF  4
#define EXC_BR  5
#define EXC_UD  6
#define EXC_NM  7
#define EXC_TS 10
#define EXC_NP 11
#define EXC_SS 12
#define EXC_GP 13
#define EXC_PF 14
#define EXC_MF 16
#define EXC_XM 19

/* Segment selector error code bits. */
#define ECODE_EXT (1 << 0)
#define ECODE_IDT (1 << 1)
#define ECODE_TI  (1 << 2)

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

/*
 * These EFLAGS bits are restored from saved value during emulation, and
 * any changes are written back to the saved value after emulation.
 */
#define EFLAGS_MASK (EFLG_OF|EFLG_SF|EFLG_ZF|EFLG_AF|EFLG_PF|EFLG_CF)

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
"pop  %"_sav"; "

/* After executing instruction: write-back necessary bits in EFLAGS. */
#define _POST_EFLAGS(_sav, _msk, _tmp)          \
/* _sav |= EFLAGS & _msk; */                    \
"pushf; "                                       \
"pop  %"_tmp"; "                                \
"andl %"_msk",%"_LO32 _tmp"; "                  \
"orl  %"_LO32 _tmp",%"_LO32 _sav"; "

/* Raw emulation: instruction has two explicit operands. */
#define __emulate_2op_nobyte(_op,_src,_dst,_eflags, wsx,wsy,wdx,wdy,       \
                             lsx,lsy,ldx,ldy, qsx,qsy,qdx,qdy)             \
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 2:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"w %"wsx"3,%"wdx"1; "                                       \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (_eflags), "+" wdy ((_dst).val), "=&r" (_tmp)           \
            : wsy ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    case 4:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"l %"lsx"3,%"ldx"1; "                                       \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (_eflags), "+" ldy ((_dst).val), "=&r" (_tmp)           \
            : lsy ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    case 8:                                                                \
        __emulate_2op_8byte(_op, _src, _dst, _eflags, qsx, qsy, qdx, qdy); \
        break;                                                             \
    }                                                                      \
} while (0)
#define __emulate_2op(_op,_src,_dst,_eflags,_bx,_by,_wx,_wy,_lx,_ly,_qx,_qy)\
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 1:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"b %"_bx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (_eflags), "+m" ((_dst).val), "=&r" (_tmp)              \
            : _by ((_src).val), "i" (EFLAGS_MASK) );                       \
        break;                                                             \
    default:                                                               \
        __emulate_2op_nobyte(_op,_src,_dst,_eflags, _wx,_wy,"","m",        \
                             _lx,_ly,"","m", _qx,_qy,"","m");              \
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
    __emulate_2op_nobyte(_op, _src, _dst, _eflags, "w", "r", "", "m",      \
                         _LO32, "r", "", "m", "", "r", "", "m")
/* Operands are word, long or quad sized and source may be in memory. */
#define emulate_2op_SrcV_srcmem(_op, _src, _dst, _eflags)                  \
    __emulate_2op_nobyte(_op, _src, _dst, _eflags, "", "m", "w", "r",      \
                         "", "m", _LO32, "r", "", "m", "", "r")

/* Instruction has only one explicit operand (no source operand). */
#define emulate_1op(_op,_dst,_eflags)                                      \
do{ unsigned long _tmp;                                                    \
    switch ( (_dst).bytes )                                                \
    {                                                                      \
    case 1:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"b %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (_eflags), "+m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 2:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"w %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (_eflags), "+m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 4:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"l %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (_eflags), "+m" ((_dst).val), "=&r" (_tmp)              \
            : "i" (EFLAGS_MASK) );                                         \
        break;                                                             \
    case 8:                                                                \
        __emulate_1op_8byte(_op, _dst, _eflags);                           \
        break;                                                             \
    }                                                                      \
} while (0)

/* Emulate an instruction with quadword operands (x86/64 only). */
#if defined(__x86_64__)
#define __emulate_2op_8byte(_op, _src, _dst, _eflags, qsx, qsy, qdx, qdy) \
do{ asm volatile (                                                      \
        _PRE_EFLAGS("0","4","2")                                        \
        _op"q %"qsx"3,%"qdx"1; "                                        \
        _POST_EFLAGS("0","4","2")                                       \
        : "+g" (_eflags), "+" qdy ((_dst).val), "=&r" (_tmp)            \
        : qsy ((_src).val), "i" (EFLAGS_MASK) );                        \
} while (0)
#define __emulate_1op_8byte(_op, _dst, _eflags)                         \
do{ asm volatile (                                                      \
        _PRE_EFLAGS("0","3","2")                                        \
        _op"q %1; "                                                     \
        _POST_EFLAGS("0","3","2")                                       \
        : "+g" (_eflags), "+m" ((_dst).val), "=&r" (_tmp)               \
        : "i" (EFLAGS_MASK) );                                          \
} while (0)
#elif defined(__i386__)
#define __emulate_2op_8byte(_op, _src, _dst, _eflags, qsx, qsy, qdx, qdy)
#define __emulate_1op_8byte(_op, _dst, _eflags)
#endif /* __i386__ */

/* Fetch next part of the instruction being emulated. */
#define insn_fetch_bytes(_size)                                         \
({ unsigned long _x = 0, _eip = state->eip;                             \
   state->eip += (_size); /* real hardware doesn't truncate */          \
   generate_exception_if((uint8_t)(state->eip -                         \
                                   ctxt->regs->eip) > MAX_INST_LEN,     \
                         EXC_GP, 0);                                    \
   rc = ops->insn_fetch(x86_seg_cs, _eip, &_x, (_size), ctxt);          \
   if ( rc ) goto done;                                                 \
   _x;                                                                  \
})
#define insn_fetch_type(_type) ((_type)insn_fetch_bytes(sizeof(_type)))

#define truncate_word(ea, byte_width)           \
({  unsigned long __ea = (ea);                  \
    unsigned int _width = (byte_width);         \
    ((_width == sizeof(unsigned long)) ? __ea : \
     (__ea & ((1UL << (_width << 3)) - 1)));    \
})
#define truncate_ea(ea) truncate_word((ea), ad_bytes)

#define mode_64bit() (ctxt->addr_size == 64)

#define fail_if(p)                                      \
do {                                                    \
    rc = (p) ? X86EMUL_UNHANDLEABLE : X86EMUL_OKAY;     \
    if ( rc ) goto done;                                \
} while (0)

#define generate_exception_if(p, e, ec)                                   \
({  if ( (p) ) {                                                          \
        fail_if(ops->inject_hw_exception == NULL);                        \
        rc = ops->inject_hw_exception(e, ec, ctxt) ? : X86EMUL_EXCEPTION; \
        goto done;                                                        \
    }                                                                     \
})

/*
 * Given byte has even parity (even number of 1s)? SDM Vol. 1 Sec. 3.4.3.1,
 * "Status Flags": EFLAGS.PF reflects parity of least-sig. byte of result only.
 */
static bool_t even_parity(uint8_t v)
{
#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm ( "test %1,%1" : "=@ccp" (v) : "q" (v) );
#else
    asm ( "test %1,%1; setp %0" : "=qm" (v) : "q" (v) );
#endif

    return v;
}

/* Update address held in a register, based on addressing mode. */
#define _register_address_increment(reg, inc, byte_width)               \
do {                                                                    \
    int _inc = (inc); /* signed type ensures sign extension to long */  \
    unsigned int _width = (byte_width);                                 \
    if ( _width == sizeof(unsigned long) )                              \
        (reg) += _inc;                                                  \
    else if ( mode_64bit() )                                            \
        (reg) = ((reg) + _inc) & ((1UL << (_width << 3)) - 1);          \
    else                                                                \
        (reg) = ((reg) & ~((1UL << (_width << 3)) - 1)) |               \
                (((reg) + _inc) & ((1UL << (_width << 3)) - 1));        \
} while (0)
#define register_address_increment(reg, inc) \
    _register_address_increment((reg), (inc), ad_bytes)

#define sp_pre_dec(dec) ({                                              \
    _register_address_increment(_regs.esp, -(dec), ctxt->sp_size/8);    \
    truncate_word(_regs.esp, ctxt->sp_size/8);                          \
})
#define sp_post_inc(inc) ({                                             \
    unsigned long __esp = truncate_word(_regs.esp, ctxt->sp_size/8);    \
    _register_address_increment(_regs.esp, (inc), ctxt->sp_size/8);     \
    __esp;                                                              \
})

#define jmp_rel(rel)                                                    \
do {                                                                    \
    unsigned long ip = _regs.eip + (int)(rel);                          \
    if ( op_bytes == 2 )                                                \
        ip = (uint16_t)ip;                                              \
    else if ( !mode_64bit() )                                           \
        ip = (uint32_t)ip;                                              \
    rc = ops->insn_fetch(x86_seg_cs, ip, NULL, 0, ctxt);                \
    if ( rc ) goto done;                                                \
    _regs.eip = ip;                                                     \
} while (0)

#define validate_far_branch(cs, ip) ({                                  \
    if ( sizeof(ip) <= 4 ) {                                            \
        ASSERT(in_longmode(ctxt, ops) <= 0);                            \
        generate_exception_if((ip) > (cs)->limit, EXC_GP, 0);           \
    } else                                                              \
        generate_exception_if(in_longmode(ctxt, ops) &&                 \
                              (cs)->attr.fields.l                       \
                              ? !is_canonical_address(ip)               \
                              : (ip) > (cs)->limit, EXC_GP, 0);         \
})

#define commit_far_branch(cs, ip) ({                                    \
    validate_far_branch(cs, ip);                                        \
    _regs.eip = (ip);                                                   \
    ops->write_segment(x86_seg_cs, cs, ctxt);                           \
})

struct fpu_insn_ctxt {
    uint8_t insn_bytes;
    int8_t exn_raised;
};

static void fpu_handle_exception(void *_fic, struct cpu_user_regs *regs)
{
    struct fpu_insn_ctxt *fic = _fic;
    ASSERT(regs->entry_vector < 0x20);
    fic->exn_raised = regs->entry_vector;
    regs->eip += fic->insn_bytes;
}

static int _get_fpu(
    enum x86_emulate_fpu_type type,
    struct fpu_insn_ctxt *fic,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc;

    fic->exn_raised = -1;

    fail_if(!ops->get_fpu);
    rc = ops->get_fpu(fpu_handle_exception, fic, type, ctxt);

    if ( rc == X86EMUL_OKAY )
    {
        unsigned long cr0;

        fail_if(!ops->read_cr);
        if ( type >= X86EMUL_FPU_xmm )
        {
            unsigned long cr4;

            rc = ops->read_cr(4, &cr4, ctxt);
            if ( rc != X86EMUL_OKAY )
                return rc;
            generate_exception_if(!(cr4 & ((type == X86EMUL_FPU_xmm)
                                           ? CR4_OSFXSR : CR4_OSXSAVE)),
                                  EXC_UD, -1);
        }

        rc = ops->read_cr(0, &cr0, ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
        if ( type >= X86EMUL_FPU_ymm )
        {
            /* Should be unreachable if VEX decoding is working correctly. */
            ASSERT((cr0 & CR0_PE) && !(ctxt->regs->eflags & EFLG_VM));
        }
        if ( cr0 & CR0_EM )
        {
            generate_exception_if(type == X86EMUL_FPU_fpu, EXC_NM, -1);
            generate_exception_if(type == X86EMUL_FPU_mmx, EXC_UD, -1);
            generate_exception_if(type == X86EMUL_FPU_xmm, EXC_UD, -1);
        }
        generate_exception_if((cr0 & CR0_TS) &&
                              (type != X86EMUL_FPU_wait || (cr0 & CR0_MP)),
                              EXC_NM, -1);
    }

 done:
    return rc;
}

#define get_fpu(_type, _fic)                                    \
do {                                                            \
    rc = _get_fpu(_type, _fic, ctxt, ops);                      \
    if ( rc ) goto done;                                        \
} while (0)
#define _put_fpu()                                              \
do {                                                            \
    if ( ops->put_fpu != NULL )                                 \
        (ops->put_fpu)(ctxt);                                   \
} while (0)
#define put_fpu(_fic)                                           \
do {                                                            \
    _put_fpu();                                                 \
    if( (_fic)->exn_raised == EXC_XM && ops->read_cr )          \
    {                                                           \
        unsigned long cr4;                                      \
        if ( (ops->read_cr(4, &cr4, ctxt) == X86EMUL_OKAY) &&   \
             !(cr4 & CR4_OSXMMEXCPT) )                          \
            (_fic)->exn_raised = EXC_UD;                        \
    }                                                           \
    generate_exception_if((_fic)->exn_raised >= 0,              \
                          (_fic)->exn_raised, -1);              \
} while (0)

#define emulate_fpu_insn(_op)                           \
do{ struct fpu_insn_ctxt fic;                           \
    get_fpu(X86EMUL_FPU_fpu, &fic);                     \
    asm volatile (                                      \
        "movb $2f-1f,%0 \n"                             \
        "1: " _op "     \n"                             \
        "2:             \n"                             \
        : "=m" (fic.insn_bytes) : : "memory" );         \
    put_fpu(&fic);                                      \
} while (0)

#define emulate_fpu_insn_memdst(_op, _arg)              \
do{ struct fpu_insn_ctxt fic;                           \
    get_fpu(X86EMUL_FPU_fpu, &fic);                     \
    asm volatile (                                      \
        "movb $2f-1f,%0 \n"                             \
        "1: " _op " %1  \n"                             \
        "2:             \n"                             \
        : "=m" (fic.insn_bytes), "=m" (_arg)            \
        : : "memory" );                                 \
    put_fpu(&fic);                                      \
} while (0)

#define emulate_fpu_insn_memsrc(_op, _arg)              \
do{ struct fpu_insn_ctxt fic;                           \
    get_fpu(X86EMUL_FPU_fpu, &fic);                     \
    asm volatile (                                      \
        "movb $2f-1f,%0 \n"                             \
        "1: " _op " %1  \n"                             \
        "2:             \n"                             \
        : "=m" (fic.insn_bytes)                         \
        : "m" (_arg) : "memory" );                      \
    put_fpu(&fic);                                      \
} while (0)

#define emulate_fpu_insn_stub(_bytes...)                                \
do {                                                                    \
    uint8_t *buf = get_stub(stub);                                      \
    unsigned int _nr = sizeof((uint8_t[]){ _bytes });                   \
    struct fpu_insn_ctxt fic = { .insn_bytes = _nr };                   \
    memcpy(buf, ((uint8_t[]){ _bytes, 0xc3 }), _nr + 1);                \
    get_fpu(X86EMUL_FPU_fpu, &fic);                                     \
    stub.func();                                                        \
    put_fpu(&fic);                                                      \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub_eflags(bytes...)                          \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    struct fpu_insn_ctxt fic_ = { .insn_bytes = nr_ };                  \
    unsigned long tmp_;                                                 \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    get_fpu(X86EMUL_FPU_fpu, &fic_);                                    \
    asm volatile ( _PRE_EFLAGS("[eflags]", "[mask]", "[tmp]")           \
                   "call *%[func];"                                     \
                   _POST_EFLAGS("[eflags]", "[mask]", "[tmp]")          \
                   : [eflags] "+g" (_regs.eflags),                      \
                     [tmp] "=&r" (tmp_)                                 \
                   : [func] "rm" (stub.func),                           \
                     [mask] "i" (EFLG_ZF|EFLG_PF|EFLG_CF) );            \
    put_fpu(&fic_);                                                     \
    put_stub(stub);                                                     \
} while (0)

static unsigned long _get_rep_prefix(
    const struct cpu_user_regs *int_regs,
    int ad_bytes)
{
    return (ad_bytes == 2) ? (uint16_t)int_regs->ecx :
           (ad_bytes == 4) ? (uint32_t)int_regs->ecx :
           int_regs->ecx;
}

#define get_rep_prefix() ({                                             \
    unsigned long max_reps = 1;                                         \
    if ( rep_prefix() )                                                 \
        max_reps = _get_rep_prefix(&_regs, ad_bytes);                   \
    if ( max_reps == 0 )                                                \
    {                                                                   \
        /* Skip the instruction if no repetitions are required. */      \
        dst.type = OP_NONE;                                             \
        goto writeback;                                                 \
    }                                                                   \
    max_reps;                                                           \
})

static void __put_rep_prefix(
    struct cpu_user_regs *int_regs,
    struct cpu_user_regs *ext_regs,
    int ad_bytes,
    unsigned long reps_completed)
{
    unsigned long ecx = ((ad_bytes == 2) ? (uint16_t)int_regs->ecx :
                         (ad_bytes == 4) ? (uint32_t)int_regs->ecx :
                         int_regs->ecx);

    /* Reduce counter appropriately, and repeat instruction if non-zero. */
    ecx -= reps_completed;
    if ( ecx != 0 )
        int_regs->eip = ext_regs->eip;

    if ( ad_bytes == 2 )
        *(uint16_t *)&int_regs->ecx = ecx;
    else if ( ad_bytes == 4 )
        int_regs->ecx = (uint32_t)ecx;
    else
        int_regs->ecx = ecx;
}

#define put_rep_prefix(reps_completed) ({                               \
    if ( rep_prefix() )                                                 \
        __put_rep_prefix(&_regs, ctxt->regs, ad_bytes, reps_completed); \
})

/* Clip maximum repetitions so that the index register at most just wraps. */
#define truncate_ea_and_reps(ea, reps, bytes_per_rep) ({                  \
    unsigned long todo__, ea__ = truncate_word(ea, ad_bytes);             \
    if ( !(ctxt->regs->eflags & EFLG_DF) )                                \
        todo__ = truncate_word(-(ea), ad_bytes) / (bytes_per_rep);        \
    else if ( truncate_word((ea) + (bytes_per_rep) - 1, ad_bytes) < ea__ )\
        todo__ = 1;                                                       \
    else                                                                  \
        todo__ = ea__ / (bytes_per_rep) + 1;                              \
    if ( !todo__ )                                                        \
        (reps) = 1;                                                       \
    else if ( todo__ < (reps) )                                           \
        (reps) = todo__;                                                  \
    ea__;                                                                 \
})

/* Compatibility function: read guest memory, zero-extend result to a ulong. */
static int read_ulong(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long *val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt,
        const struct x86_emulate_ops *ops)
{
    *val = 0;
    return ops->read(seg, offset, val, bytes, ctxt);
}

/*
 * Unsigned multiplication with double-word result.
 * IN:  Multiplicand=m[0], Multiplier=m[1]
 * OUT: Return CF/OF (overflow status); Result=m[1]:m[0]
 */
static bool_t mul_dbl(unsigned long m[2])
{
    bool_t rc;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm ( "mul %1" : "+a" (m[0]), "+d" (m[1]), "=@cco" (rc) );
#else
    asm ( "mul %1; seto %2"
          : "+a" (m[0]), "+d" (m[1]), "=qm" (rc) );
#endif

    return rc;
}

/*
 * Signed multiplication with double-word result.
 * IN:  Multiplicand=m[0], Multiplier=m[1]
 * OUT: Return CF/OF (overflow status); Result=m[1]:m[0]
 */
static bool_t imul_dbl(unsigned long m[2])
{
    bool_t rc;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm ( "imul %1" : "+a" (m[0]), "+d" (m[1]), "=@cco" (rc) );
#else
    asm ( "imul %1; seto %2"
          : "+a" (m[0]), "+d" (m[1]), "=qm" (rc) );
#endif

    return rc;
}

/*
 * Unsigned division of double-word dividend.
 * IN:  Dividend=u[1]:u[0], Divisor=v
 * OUT: Return 1: #DE
 *      Return 0: Quotient=u[0], Remainder=u[1]
 */
static bool_t div_dbl(unsigned long u[2], unsigned long v)
{
    if ( (v == 0) || (u[1] >= v) )
        return 1;
    asm ( "div"__OS" %2" : "+a" (u[0]), "+d" (u[1]) : "rm" (v) );
    return 0;
}

/*
 * Signed division of double-word dividend.
 * IN:  Dividend=u[1]:u[0], Divisor=v
 * OUT: Return 1: #DE
 *      Return 0: Quotient=u[0], Remainder=u[1]
 * NB. We don't use idiv directly as it's moderately hard to work out
 *     ahead of time whether it will #DE, which we cannot allow to happen.
 */
static bool_t idiv_dbl(unsigned long u[2], long v)
{
    bool_t negu = (long)u[1] < 0, negv = v < 0;

    /* u = abs(u) */
    if ( negu )
    {
        u[1] = ~u[1];
        if ( (u[0] = -u[0]) == 0 )
            u[1]++;
    }

    /* abs(u) / abs(v) */
    if ( div_dbl(u, negv ? -v : v) )
        return 1;

    /* Remainder has same sign as dividend. It cannot overflow. */
    if ( negu )
        u[1] = -u[1];

    /* Quotient is overflowed if sign bit is set. */
    if ( negu ^ negv )
    {
        if ( (long)u[0] >= 0 )
            u[0] = -u[0];
        else if ( (u[0] << 1) != 0 ) /* == 0x80...0 is okay */
            return 1;
    }
    else if ( (long)u[0] < 0 )
        return 1;

    return 0;
}

static bool_t
test_cc(
    unsigned int condition, unsigned int flags)
{
    int rc = 0;

    switch ( (condition & 15) >> 1 )
    {
    case 0: /* o */
        rc |= (flags & EFLG_OF);
        break;
    case 1: /* b/c/nae */
        rc |= (flags & EFLG_CF);
        break;
    case 2: /* z/e */
        rc |= (flags & EFLG_ZF);
        break;
    case 3: /* be/na */
        rc |= (flags & (EFLG_CF|EFLG_ZF));
        break;
    case 4: /* s */
        rc |= (flags & EFLG_SF);
        break;
    case 5: /* p/pe */
        rc |= (flags & EFLG_PF);
        break;
    case 7: /* le/ng */
        rc |= (flags & EFLG_ZF);
        /* fall through */
    case 6: /* l/nge */
        rc |= (!(flags & EFLG_SF) != !(flags & EFLG_OF));
        break;
    }

    /* Odd condition identifiers (lsb == 1) have inverted sense. */
    return (!!rc ^ (condition & 1));
}

static int
get_cpl(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    struct segment_register reg;

    if ( ctxt->regs->eflags & EFLG_VM )
        return 3;

    if ( (ops->read_segment == NULL) ||
         ops->read_segment(x86_seg_ss, &reg, ctxt) )
        return -1;

    return reg.attr.fields.dpl;
}

static int
_mode_iopl(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    int cpl = get_cpl(ctxt, ops);
    if ( cpl == -1 )
        return -1;
    return (cpl <= ((ctxt->regs->eflags >> 12) & 3));
}

#define mode_ring0() ({                         \
    int _cpl = get_cpl(ctxt, ops);              \
    fail_if(_cpl < 0);                          \
    (_cpl == 0);                                \
})
#define mode_iopl() ({                          \
    int _iopl = _mode_iopl(ctxt, ops);          \
    fail_if(_iopl < 0);                         \
    _iopl;                                      \
})

static int ioport_access_check(
    unsigned int first_port,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    unsigned long iobmp;
    struct segment_register tr;
    int rc = X86EMUL_OKAY;

    if ( !(ctxt->regs->eflags & EFLG_VM) && mode_iopl() )
        return X86EMUL_OKAY;

    fail_if(ops->read_segment == NULL);
    if ( (rc = ops->read_segment(x86_seg_tr, &tr, ctxt)) != 0 )
        return rc;

    /* Ensure that the TSS is valid and has an io-bitmap-offset field. */
    if ( !tr.attr.fields.p ||
         ((tr.attr.fields.type & 0xd) != 0x9) ||
         (tr.limit < 0x67) )
        goto raise_exception;

    if ( (rc = read_ulong(x86_seg_none, tr.base + 0x66,
                          &iobmp, 2, ctxt, ops)) )
        return rc;

    /* Ensure TSS includes two bytes including byte containing first port. */
    iobmp += first_port / 8;
    if ( tr.limit <= iobmp )
        goto raise_exception;

    if ( (rc = read_ulong(x86_seg_none, tr.base + iobmp,
                          &iobmp, 2, ctxt, ops)) )
        return rc;
    if ( (iobmp & (((1<<bytes)-1) << (first_port&7))) != 0 )
        goto raise_exception;

 done:
    return rc;

 raise_exception:
    fail_if(ops->inject_hw_exception == NULL);
    return ops->inject_hw_exception(EXC_GP, 0, ctxt) ? : X86EMUL_EXCEPTION;
}

static bool_t
in_realmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    unsigned long cr0;
    int rc;

    if ( ops->read_cr == NULL )
        return 0;

    rc = ops->read_cr(0, &cr0, ctxt);
    return (!rc && !(cr0 & CR0_PE));
}

static bool_t
in_protmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    return !(in_realmode(ctxt, ops) || (ctxt->regs->eflags & EFLG_VM));
}

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3

static bool_t vcpu_has(
    unsigned int eax,
    unsigned int reg,
    unsigned int bit,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    unsigned int ebx = 0, ecx = 0, edx = 0;
    int rc = X86EMUL_OKAY;

    fail_if(!ops->cpuid);
    rc = ops->cpuid(&eax, &ebx, &ecx, &edx, ctxt);
    if ( rc == X86EMUL_OKAY )
    {
        switch ( reg )
        {
        case EAX: reg = eax; break;
        case EBX: reg = ebx; break;
        case ECX: reg = ecx; break;
        case EDX: reg = edx; break;
        default: BUG();
        }
        if ( !(reg & (1U << bit)) )
            rc = ~X86EMUL_OKAY;
    }

 done:
    return rc == X86EMUL_OKAY;
}

#define vcpu_has_clflush() vcpu_has(       1, EDX, 19, ctxt, ops)
#define vcpu_has_lzcnt() vcpu_has(0x80000001, ECX,  5, ctxt, ops)
#define vcpu_has_misalignsse() vcpu_has(0x80000001, ECX, 7, ctxt, ops)
#define vcpu_has_bmi1()  vcpu_has(0x00000007, EBX,  3, ctxt, ops)
#define vcpu_has_hle()   vcpu_has(0x00000007, EBX,  4, ctxt, ops)
#define vcpu_has_rtm()   vcpu_has(0x00000007, EBX, 11, ctxt, ops)

#define vcpu_must_have(leaf, reg, bit) \
    generate_exception_if(!vcpu_has(leaf, reg, bit, ctxt, ops), EXC_UD, -1)
#define vcpu_must_have_fpu()  vcpu_must_have(0x00000001, EDX, 0)
#define vcpu_must_have_cmov() vcpu_must_have(0x00000001, EDX, 15)
#define vcpu_must_have_mmx()  vcpu_must_have(0x00000001, EDX, 23)
#define vcpu_must_have_sse()  vcpu_must_have(0x00000001, EDX, 25)
#define vcpu_must_have_sse2() vcpu_must_have(0x00000001, EDX, 26)
#define vcpu_must_have_sse3() vcpu_must_have(0x00000001, ECX,  0)
#define vcpu_must_have_cx16() vcpu_must_have(0x00000001, ECX, 13)
#define vcpu_must_have_sse4_2() vcpu_must_have(0x00000001, ECX, 20)
#define vcpu_must_have_movbe() vcpu_must_have(0x00000001, ECX, 22)
#define vcpu_must_have_avx()  vcpu_must_have(0x00000001, ECX, 28)

#ifdef __XEN__
/*
 * Note the difference between vcpu_must_have_<feature>() and
 * host_and_vcpu_must_have(<feature>): The latter needs to be used when
 * emulation code is using the same instruction class for carrying out
 * the actual operation.
 */
#define host_and_vcpu_must_have(feat) ({ \
    generate_exception_if(!cpu_has_##feat, EXC_UD, -1); \
    vcpu_must_have_##feat(); \
})
#else
#define host_and_vcpu_must_have(feat) vcpu_must_have_##feat()
#endif

static int
in_longmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    uint64_t efer;

    if ( !ops->read_msr ||
         unlikely(ops->read_msr(MSR_EFER, &efer, ctxt) != X86EMUL_OKAY) )
        return -1;

    return !!(efer & EFER_LMA);
}

static int
realmode_load_seg(
    enum x86_segment seg,
    uint16_t sel,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc = ops->read_segment(seg, sreg, ctxt);

    if ( !rc )
    {
        sreg->sel  = sel;
        sreg->base = (uint32_t)sel << 4;
    }

    return rc;
}

static int
protmode_load_seg(
    enum x86_segment seg,
    uint16_t sel, bool_t is_ret,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    struct segment_register desctab;
    struct { uint32_t a, b; } desc;
    uint8_t dpl, rpl;
    int cpl = get_cpl(ctxt, ops);
    uint32_t a_flag = 0x100;
    int rc, fault_type = EXC_GP;

    if ( cpl < 0 )
        return X86EMUL_UNHANDLEABLE;

    /* NULL selector? */
    if ( (sel & 0xfffc) == 0 )
    {
        switch ( seg )
        {
        case x86_seg_ss:
            if ( mode_64bit() && (cpl != 3) && (cpl == sel) )
        default:
                break;
            /* fall through */
        case x86_seg_cs:
        case x86_seg_tr:
            goto raise_exn;
        }
        memset(sreg, 0, sizeof(*sreg));
        sreg->sel = sel;
        return X86EMUL_OKAY;
    }

    /* System segment descriptors must reside in the GDT. */
    if ( !is_x86_user_segment(seg) && (sel & 4) )
        goto raise_exn;

    if ( (rc = ops->read_segment((sel & 4) ? x86_seg_ldtr : x86_seg_gdtr,
                                 &desctab, ctxt)) )
        return rc;

    /* Segment not valid for use (cooked meaning of .p)? */
    if ( !desctab.attr.fields.p )
        goto raise_exn;

    /* Check against descriptor table limit. */
    if ( ((sel & 0xfff8) + 7) > desctab.limit )
        goto raise_exn;

    if ( (rc = ops->read(x86_seg_none, desctab.base + (sel & 0xfff8),
                         &desc, sizeof(desc), ctxt)) )
        return rc;

    if ( !is_x86_user_segment(seg) )
    {
        /* System segments must have S flag == 0. */
        if ( desc.b & (1u << 12) )
            goto raise_exn;
        /* We do not support 64-bit descriptor types. */
        if ( in_longmode(ctxt, ops) )
            return X86EMUL_UNHANDLEABLE;
    }
    /* User segments must have S flag == 1. */
    else if ( !(desc.b & (1u << 12)) )
        goto raise_exn;

    dpl = (desc.b >> 13) & 3;
    rpl = sel & 3;

    switch ( seg )
    {
    case x86_seg_cs:
        /* Code segment? */
        if ( !(desc.b & (1u<<11)) )
            goto raise_exn;
        if ( is_ret
             ? /*
                * Really rpl < cpl, but our sole caller doesn't handle
                * privilege level changes.
                */
               rpl != cpl || (desc.b & (1 << 10) ? dpl > rpl : dpl != rpl)
             : desc.b & (1 << 10)
               /* Conforming segment: check DPL against CPL. */
               ? dpl > cpl
               /* Non-conforming segment: check RPL and DPL against CPL. */
               : rpl > cpl || dpl != cpl )
            goto raise_exn;
        /*
         * 64-bit code segments (L bit set) must have D bit clear.
         * Experimentally in long mode, the L and D bits are checked before
         * the Present bit.
         */
        if ( in_longmode(ctxt, ops) &&
             (desc.b & (1 << 21)) && (desc.b & (1 << 22)) )
            goto raise_exn;
        sel = (sel ^ rpl) | cpl;
        break;
    case x86_seg_ss:
        /* Writable data segment? */
        if ( (desc.b & (5u<<9)) != (1u<<9) )
            goto raise_exn;
        if ( (dpl != cpl) || (dpl != rpl) )
            goto raise_exn;
        break;
    case x86_seg_ldtr:
        /* LDT system segment? */
        if ( (desc.b & (15u<<8)) != (2u<<8) )
            goto raise_exn;
        a_flag = 0;
        break;
    case x86_seg_tr:
        /* Available TSS system segment? */
        if ( (desc.b & (15u<<8)) != (9u<<8) )
            goto raise_exn;
        a_flag = 0x200; /* busy flag */
        break;
    default:
        /* Readable code or data segment? */
        if ( (desc.b & (5u<<9)) == (4u<<9) )
            goto raise_exn;
        /* Non-conforming segment: check DPL against RPL and CPL. */
        if ( ((desc.b & (6u<<9)) != (6u<<9)) &&
             ((dpl < cpl) || (dpl < rpl)) )
            goto raise_exn;
        break;
    }

    /* Segment present in memory? */
    if ( !(desc.b & (1 << 15)) )
    {
        fault_type = seg != x86_seg_ss ? EXC_NP : EXC_SS;
        goto raise_exn;
    }

    /* Ensure Accessed flag is set. */
    if ( a_flag && !(desc.b & a_flag) )
    {
        uint32_t new_desc_b = desc.b | a_flag;

        if ( (rc = ops->cmpxchg(x86_seg_none, desctab.base + (sel & 0xfff8) + 4,
                                &desc.b, &new_desc_b, 4, ctxt)) != 0 )
            return rc;

        /* Force the Accessed flag in our local copy. */
        desc.b = new_desc_b;
    }

    sreg->base = (((desc.b <<  0) & 0xff000000u) |
                  ((desc.b << 16) & 0x00ff0000u) |
                  ((desc.a >> 16) & 0x0000ffffu));
    sreg->attr.bytes = (((desc.b >>  8) & 0x00ffu) |
                        ((desc.b >> 12) & 0x0f00u));
    sreg->limit = (desc.b & 0x000f0000u) | (desc.a & 0x0000ffffu);
    if ( sreg->attr.fields.g )
        sreg->limit = (sreg->limit << 12) | 0xfffu;
    sreg->sel = sel;
    return X86EMUL_OKAY;

 raise_exn:
    if ( ops->inject_hw_exception == NULL )
        return X86EMUL_UNHANDLEABLE;
    if ( (rc = ops->inject_hw_exception(fault_type, sel & 0xfffc, ctxt)) )
        return rc;
    return X86EMUL_EXCEPTION;
}

static int
load_seg(
    enum x86_segment seg,
    uint16_t sel, bool_t is_ret,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    struct segment_register reg;
    int rc;

    if ( (ops->read_segment == NULL) ||
         (ops->write_segment == NULL) )
        return X86EMUL_UNHANDLEABLE;

    if ( !sreg )
        sreg = &reg;

    if ( in_protmode(ctxt, ops) )
        rc = protmode_load_seg(seg, sel, is_ret, sreg, ctxt, ops);
    else
        rc = realmode_load_seg(seg, sel, sreg, ctxt, ops);

    if ( !rc && sreg == &reg )
        rc = ops->write_segment(seg, sreg, ctxt);

    return rc;
}

void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs *regs, int highbyte_regs)
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
    case 12: mark_regs_dirty(regs); p = &regs->r12; break;
    case 13: mark_regs_dirty(regs); p = &regs->r13; break;
    case 14: mark_regs_dirty(regs); p = &regs->r14; break;
    case 15: mark_regs_dirty(regs); p = &regs->r15; break;
#endif
    default: BUG(); p = NULL; break;
    }

    return p;
}

static bool is_aligned(enum x86_segment seg, unsigned long offs,
                       unsigned int size, struct x86_emulate_ctxt *ctxt,
                       const struct x86_emulate_ops *ops)
{
    struct segment_register reg;

    /* Expecting powers of two only. */
    ASSERT(!(size & (size - 1)));

    /* No alignment checking when we have no way to read segment data. */
    if ( !ops->read_segment )
        return true;

    if ( ops->read_segment(seg, &reg, ctxt) != X86EMUL_OKAY )
        return false;

    return !((reg.base + offs) & (size - 1));
}

static bool umip_active(struct x86_emulate_ctxt *ctxt,
                        const struct x86_emulate_ops *ops)
{
    unsigned long cr4;

    /* Intentionally not using mode_ring0() here to avoid its fail_if(). */
    return get_cpl(ctxt, ops) > 0 &&
           ops->read_cr && ops->read_cr(4, &cr4, ctxt) == X86EMUL_OKAY &&
           (cr4 & CR4_UMIP);
}

/* Inject a software interrupt/exception, emulating if needed. */
static int inject_swint(enum x86_swint_type type,
                        uint8_t vector, uint8_t insn_len,
                        struct x86_emulate_ctxt *ctxt,
                        const struct x86_emulate_ops *ops)
{
    int rc, error_code, fault_type = EXC_GP;

    fail_if(ops->inject_sw_interrupt == NULL);
    fail_if(ops->inject_hw_exception == NULL);

    /*
     * Without hardware support, injecting software interrupts/exceptions is
     * problematic.
     *
     * All software methods of generating exceptions (other than BOUND) yield
     * traps, so eip in the exception frame needs to point after the
     * instruction, not at it.
     *
     * However, if injecting it as a hardware exception causes a fault during
     * delivery, our adjustment of eip will cause the fault to be reported
     * after the faulting instruction, not pointing to it.
     *
     * Therefore, eip can only safely be wound forwards if we are certain that
     * injecting an equivalent hardware exception won't fault, which means
     * emulating everything the processor would do on a control transfer.
     *
     * However, emulation of complete control transfers is very complicated.
     * All we care about is that guest userspace cannot avoid the descriptor
     * DPL check by using the Xen emulator, and successfully invoke DPL=0
     * descriptors.
     *
     * Any OS which would further fault during injection is going to receive a
     * double fault anyway, and won't be in a position to care that the
     * faulting eip is incorrect.
     */

    if ( (ctxt->swint_emulate == x86_swint_emulate_all) ||
         ((ctxt->swint_emulate == x86_swint_emulate_icebp) &&
          (type == x86_swint_icebp)) )
    {
        if ( !in_realmode(ctxt, ops) )
        {
            unsigned int idte_size, idte_offset;
            struct segment_register idtr;
            uint32_t idte_ctl;
            int lm = in_longmode(ctxt, ops);

            if ( lm < 0 )
                return X86EMUL_UNHANDLEABLE;

            idte_size = lm ? 16 : 8;
            idte_offset = vector * idte_size;

            /* icebp sets the External Event bit despite being an instruction. */
            error_code = (vector << 3) | ECODE_IDT |
                (type == x86_swint_icebp ? ECODE_EXT : 0);

            /*
             * TODO - this does not cover the v8086 mode with CR4.VME case
             * correctly, but falls on the safe side from the point of view of
             * a 32bit OS.  Someone with many TUITs can see about reading the
             * TSS Software Interrupt Redirection bitmap.
             */
            if ( (ctxt->regs->eflags & EFLG_VM) &&
                 ((ctxt->regs->eflags & EFLG_IOPL) != EFLG_IOPL) )
                goto raise_exn;

            fail_if(ops->read_segment == NULL);
            fail_if(ops->read == NULL);
            if ( (rc = ops->read_segment(x86_seg_idtr, &idtr, ctxt)) )
                goto done;

            if ( (idte_offset + idte_size - 1) > idtr.limit )
                goto raise_exn;

            /*
             * Should strictly speaking read all 8/16 bytes of an entry,
             * but we currently only care about the dpl and present bits.
             */
            if ( (rc = ops->read(x86_seg_none, idtr.base + idte_offset + 4,
                                 &idte_ctl, sizeof(idte_ctl), ctxt)) )
                goto done;

            /* Is this entry present? */
            if ( !(idte_ctl & (1u << 15)) )
            {
                fault_type = EXC_NP;
                goto raise_exn;
            }

            /* icebp counts as a hardware event, and bypasses the dpl check. */
            if ( type != x86_swint_icebp )
            {
                struct segment_register ss;

                if ( (rc = ops->read_segment(x86_seg_ss, &ss, ctxt)) )
                    goto done;

                if ( ss.attr.fields.dpl > ((idte_ctl >> 13) & 3) )
                    goto raise_exn;
            }
        }

        ctxt->regs->eip += insn_len;
    }

    rc = ops->inject_sw_interrupt(type, vector, insn_len, ctxt);

 done:
    return rc;

 raise_exn:
    return ops->inject_hw_exception(fault_type, error_code, ctxt);
}

int x86emul_unhandleable_rw(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_UNHANDLEABLE;
}

struct x86_emulate_state {
    unsigned int op_bytes, ad_bytes;

    enum {
        ext_none = vex_none,
        ext_0f   = vex_0f,
        ext_0f38 = vex_0f38,
        ext_0f3a = vex_0f3a,
        /*
         * For XOP use values such that the respective instruction field
         * can be used without adjustment.
         */
        ext_8f08 = 8,
        ext_8f09,
        ext_8f0a,
    } ext;
    uint8_t modrm, modrm_mod, modrm_reg, modrm_rm;
    uint8_t rex_prefix;
    bool lock_prefix;
    opcode_desc_t desc;
    union vex vex;
    union evex evex;
    int override_seg;

    /*
     * Data operand effective address (usually computed from ModRM).
     * Default is a memory operand relative to segment DS.
     */
    struct operand ea;

    /* Immediate operand values, if any. Use otherwise unused fields. */
#define imm1 ea.val
#define imm2 ea.orig_val

    unsigned long eip;
    struct cpu_user_regs *regs;

#ifndef NDEBUG
    /*
     * Track caller of x86_decode_insn() to spot missing as well as
     * premature calls to x86_emulate_free_state().
     */
    void *caller;
#endif
};

/* Helper definitions. */
#define op_bytes (state->op_bytes)
#define ad_bytes (state->ad_bytes)
#define ext (state->ext)
#define modrm (state->modrm)
#define modrm_mod (state->modrm_mod)
#define modrm_reg (state->modrm_reg)
#define modrm_rm (state->modrm_rm)
#define rex_prefix (state->rex_prefix)
#define lock_prefix (state->lock_prefix)
#define vex (state->vex)
#define evex (state->evex)
#define override_seg (state->override_seg)
#define ea (state->ea)

static int
x86_decode_onebyte(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc = X86EMUL_OKAY;

    switch ( ctxt->opcode )
    {
    case 0x90: /* nop / pause */
        if ( repe_prefix() )
            ctxt->opcode |= X86EMUL_OPC_F3(0, 0);
        break;

    case 0x9a: /* call (far, absolute) */
    case 0xea: /* jmp (far, absolute) */
        generate_exception_if(mode_64bit(), EXC_UD, -1);

        imm1 = insn_fetch_bytes(op_bytes);
        imm2 = insn_fetch_type(uint16_t);
        break;

    case 0xa0: case 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2: case 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        /* Source EA is not encoded via ModRM. */
        ea.mem.off = insn_fetch_bytes(ad_bytes);
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        if ( op_bytes == 8 ) /* Fetch more bytes to obtain imm64. */
            imm1 = ((uint32_t)imm1 |
                    ((uint64_t)insn_fetch_type(uint32_t) << 32));
        break;

    case 0xc8: /* enter imm16,imm8 */
        imm2 = insn_fetch_type(uint8_t);
        break;
    }

 done:
    return rc;
}

static int
x86_decode_twobyte(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc = X86EMUL_OKAY;

    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case 0x78:
        switch ( vex.pfx )
        {
        case vex_66: /* extrq $imm8, $imm8, xmm */
        case vex_f2: /* insertq $imm8, $imm8, xmm, xmm */
            imm1 = insn_fetch_type(uint8_t);
            imm2 = insn_fetch_type(uint8_t);
            break;
        }
        /* fall through */
    case 0x10 ... 0x18:
    case 0x28 ... 0x2f:
    case 0x50 ... 0x77:
    case 0x79 ... 0x7f:
    case 0xae:
    case 0xc2:
    case 0xc4 ... 0xc7:
    case 0xd0 ... 0xfe:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;
        /* Intentionally not handling here despite being modified by F3:
    case 0xb8: jmpe / popcnt
    case 0xbc: bsf / tzcnt
    case 0xbd: bsr / lzcnt
         * They're being dealt with in the execution phase (if at all).
         */
    }

 done:
    return rc;
}

static int
x86_decode_0f38(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case 0x00 ... 0xef:
    case 0xf2 ... 0xff:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0xf0: case 0xf1: /* movbe / crc32 */
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;
    }

    return X86EMUL_OKAY;
}

static int
x86_decode(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    uint8_t b, d, sib, sib_index, sib_base;
    unsigned int def_op_bytes, def_ad_bytes, opcode;
    int rc = X86EMUL_OKAY;

    memset(state, 0, sizeof(*state));
    override_seg = -1;
    ea.type = OP_MEM;
    ea.mem.seg = x86_seg_ds;
    ea.reg = PTR_POISON;
    state->regs = ctxt->regs;
    state->eip = ctxt->regs->eip;

    ctxt->retire.byte = 0;

    op_bytes = def_op_bytes = ad_bytes = def_ad_bytes = ctxt->addr_size/8;
    if ( op_bytes == 8 )
    {
        op_bytes = def_op_bytes = 4;
#ifndef __x86_64__
        return X86EMUL_UNHANDLEABLE;
#endif
    }

    /* Prefix bytes. */
    for ( ; ; )
    {
        switch ( b = insn_fetch_type(uint8_t) )
        {
        case 0x66: /* operand-size override */
            op_bytes = def_op_bytes ^ 6;
            if ( !vex.pfx )
                vex.pfx = vex_66;
            break;
        case 0x67: /* address-size override */
            ad_bytes = def_ad_bytes ^ (mode_64bit() ? 12 : 6);
            break;
        case 0x2e: /* CS override */
            override_seg = x86_seg_cs;
            break;
        case 0x3e: /* DS override */
            override_seg = x86_seg_ds;
            break;
        case 0x26: /* ES override */
            override_seg = x86_seg_es;
            break;
        case 0x64: /* FS override */
            override_seg = x86_seg_fs;
            break;
        case 0x65: /* GS override */
            override_seg = x86_seg_gs;
            break;
        case 0x36: /* SS override */
            override_seg = x86_seg_ss;
            break;
        case 0xf0: /* LOCK */
            lock_prefix = 1;
            break;
        case 0xf2: /* REPNE/REPNZ */
            vex.pfx = vex_f2;
            break;
        case 0xf3: /* REP/REPE/REPZ */
            vex.pfx = vex_f3;
            break;
        case 0x40 ... 0x4f: /* REX */
            if ( !mode_64bit() )
                goto done_prefixes;
            rex_prefix = b;
            continue;
        default:
            goto done_prefixes;
        }

        /* Any legacy prefix after a REX prefix nullifies its effect. */
        rex_prefix = 0;
    }
 done_prefixes:

    if ( rex_prefix & REX_W )
        op_bytes = 8;

    /* Opcode byte(s). */
    d = opcode_table[b];
    if ( d == 0 && b == 0x0f )
    {
        /* Two-byte opcode. */
        b = insn_fetch_type(uint8_t);
        d = twobyte_table[b];
        switch ( b )
        {
        default:
            opcode = b | MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f;
            break;
        case 0x38:
            b = insn_fetch_type(uint8_t);
            opcode = b | MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f38;
            break;
        case 0x3a:
            b = insn_fetch_type(uint8_t);
            opcode = b | MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f3a;
            break;
        }
    }
    else
        opcode = b;

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        modrm = insn_fetch_type(uint8_t);
        modrm_mod = (modrm & 0xc0) >> 6;

        if ( !ext && ((b & ~1) == 0xc4 || (b == 0x8f && (modrm & 0x18)) ||
                      b == 0x62) )
            switch ( def_ad_bytes )
            {
            default:
                BUG(); /* Shouldn't be possible. */
            case 2:
                if ( in_realmode(ctxt, ops) || (state->regs->eflags & EFLG_VM) )
                    break;
                /* fall through */
            case 4:
                if ( modrm_mod != 3 )
                    break;
                /* fall through */
            case 8:
                /* VEX / XOP / EVEX */
                generate_exception_if(rex_prefix || vex.pfx, EXC_UD, -1);

                vex.raw[0] = modrm;
                if ( b == 0xc5 )
                {
                    opcode = X86EMUL_OPC_VEX_;
                    vex.raw[1] = modrm;
                    vex.opcx = vex_0f;
                    vex.x = 1;
                    vex.b = 1;
                    vex.w = 0;
                }
                else
                {
                    vex.raw[1] = insn_fetch_type(uint8_t);
                    if ( mode_64bit() )
                    {
                        if ( !vex.b )
                            rex_prefix |= REX_B;
                        if ( !vex.x )
                            rex_prefix |= REX_X;
                        if ( vex.w )
                        {
                            rex_prefix |= REX_W;
                            op_bytes = 8;
                        }
                    }
                    switch ( b )
                    {
                    case 0x62:
                        opcode = X86EMUL_OPC_EVEX_;
                        evex.raw[0] = vex.raw[0];
                        evex.raw[1] = vex.raw[1];
                        evex.raw[2] = insn_fetch_type(uint8_t);

                        vex.opcx = evex.opcx;
                        break;
                    case 0xc4:
                        opcode = X86EMUL_OPC_VEX_;
                        break;
                    default:
                        opcode = 0;
                        break;
                    }
                }
                if ( mode_64bit() && !vex.r )
                    rex_prefix |= REX_R;

                ext = vex.opcx;
                if ( b != 0x8f )
                {
                    b = insn_fetch_type(uint8_t);
                    switch ( ext )
                    {
                    case vex_0f:
                        opcode |= MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[b];
                        break;
                    case vex_0f38:
                        opcode |= MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x38];
                        break;
                    case vex_0f3a:
                        opcode |= MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x3a];
                        break;
                    default:
                        rc = X86EMUL_UNHANDLEABLE;
                        goto done;
                    }
                }
                else if ( ext < ext_8f08 +
                                sizeof(xop_table) / sizeof(*xop_table) )
                {
                    b = insn_fetch_type(uint8_t);
                    opcode |= MASK_INSR(0x8f08 + ext - ext_8f08,
                                        X86EMUL_OPC_EXT_MASK);
                    d = xop_table[ext - ext_8f08];
                }
                else
                {
                    rc = X86EMUL_UNHANDLEABLE;
                    goto done;
                }

                opcode |= b | MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);

                modrm = insn_fetch_type(uint8_t);
                modrm_mod = (modrm & 0xc0) >> 6;

                break;
            }

        modrm_reg = ((rex_prefix & 4) << 1) | ((modrm & 0x38) >> 3);
        modrm_rm  = modrm & 0x07;

        /* Early operand adjustments. */
        switch ( ext )
        {
        case ext_none:
            switch ( b )
            {
            case 0xf6 ... 0xf7: /* Grp3 */
                switch ( modrm_reg & 7 )
                {
                case 0 ... 1: /* test */
                    d |= DstMem | SrcImm;
                    break;
                case 2: /* not */
                case 3: /* neg */
                    d |= DstMem;
                    break;
                case 4: /* mul */
                case 5: /* imul */
                case 6: /* div */
                case 7: /* idiv */
                    /*
                     * DstEax isn't really precise for all cases; updates to
                     * rDX get handled in an open coded manner.
                     */
                    d |= DstEax | SrcMem;
                    break;
                }
                break;
            case 0xff: /* Grp5 */
                switch ( modrm_reg & 7 )
                {
                case 2: /* call (near) */
                case 4: /* jmp (near) */
                case 6: /* push */
                    if ( mode_64bit() && op_bytes == 4 )
                        op_bytes = 8;
                    /* fall through */
                case 3: /* call (far, absolute indirect) */
                case 5: /* jmp (far, absolute indirect) */
                    d = DstNone | SrcMem | ModRM | Mov;
                    break;
                }
                break;
            }
            break;

        case ext_0f:
            switch ( b )
            {
            case 0x00: /* Grp6 */
                switch ( modrm_reg & 6 )
                {
                case 0:
                    d |= DstMem | SrcImplicit | Mov;
                    break;
                case 2: case 4:
                    d |= SrcMem16;
                    break;
                }
                break;
            }
            break;

        case ext_0f38:
            switch ( opcode & X86EMUL_OPC_MASK )
            {
            case 0xf0: /* movbe / crc32 */
                d |= repne_prefix() ? ByteOp : Mov;
                break;
            case 0xf1: /* movbe / crc32 */
                if ( !repne_prefix() )
                    d = (d & ~(DstMask | SrcMask)) | DstMem | SrcReg | Mov;
                break;
            }
            break;

        case ext_0f3a:
        case ext_8f08:
        case ext_8f09:
        case ext_8f0a:
            break;

        default:
            ASSERT_UNREACHABLE();
        }

        if ( modrm_mod == 3 )
        {
            modrm_rm |= (rex_prefix & 1) << 3;
            ea.type = OP_REG;
        }
        else if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            switch ( modrm_rm )
            {
            case 0:
                ea.mem.off = state->regs->ebx + state->regs->esi;
                break;
            case 1:
                ea.mem.off = state->regs->ebx + state->regs->edi;
                break;
            case 2:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->ebp + state->regs->esi;
                break;
            case 3:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->ebp + state->regs->edi;
                break;
            case 4:
                ea.mem.off = state->regs->esi;
                break;
            case 5:
                ea.mem.off = state->regs->edi;
                break;
            case 6:
                if ( modrm_mod == 0 )
                    break;
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->ebp;
                break;
            case 7:
                ea.mem.off = state->regs->ebx;
                break;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( modrm_rm == 6 )
                    ea.mem.off = insn_fetch_type(int16_t);
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int16_t);
                break;
            }
            ea.mem.off = truncate_ea(ea.mem.off);
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            if ( modrm_rm == 4 )
            {
                sib = insn_fetch_type(uint8_t);
                sib_index = ((sib >> 3) & 7) | ((rex_prefix << 2) & 8);
                sib_base  = (sib & 7) | ((rex_prefix << 3) & 8);
                if ( sib_index != 4 )
                    ea.mem.off = *(long *)decode_register(sib_index,
                                                          state->regs, 0);
                ea.mem.off <<= (sib >> 6) & 3;
                if ( (modrm_mod == 0) && ((sib_base & 7) == 5) )
                    ea.mem.off += insn_fetch_type(int32_t);
                else if ( sib_base == 4 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += state->regs->esp;
                    if ( !ext && (b == 0x8f) )
                        /* POP <rm> computes its EA post increment. */
                        ea.mem.off += ((mode_64bit() && (op_bytes == 4))
                                       ? 8 : op_bytes);
                }
                else if ( sib_base == 5 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += state->regs->ebp;
                }
                else
                    ea.mem.off += *(long *)decode_register(sib_base,
                                                           state->regs, 0);
            }
            else
            {
                modrm_rm |= (rex_prefix & 1) << 3;
                ea.mem.off = *(long *)decode_register(modrm_rm,
                                                      state->regs, 0);
                if ( (modrm_rm == 5) && (modrm_mod != 0) )
                    ea.mem.seg = x86_seg_ss;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( (modrm_rm & 7) != 5 )
                    break;
                ea.mem.off = insn_fetch_type(int32_t);
                if ( !mode_64bit() )
                    break;
                /* Relative to RIP of next instruction. Argh! */
                ea.mem.off += state->eip;
                if ( (d & SrcMask) == SrcImm )
                    ea.mem.off += (d & ByteOp) ? 1 :
                        ((op_bytes == 8) ? 4 : op_bytes);
                else if ( (d & SrcMask) == SrcImmByte )
                    ea.mem.off += 1;
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int32_t);
                break;
            }
            ea.mem.off = truncate_ea(ea.mem.off);
        }
    }

    if ( override_seg != -1 && ea.type == OP_MEM )
        ea.mem.seg = override_seg;

    /* Fetch the immediate operand, if present. */
    switch ( d & SrcMask )
    {
        unsigned int bytes;

    case SrcImm:
        if ( !(d & ByteOp) )
            bytes = op_bytes != 8 ? op_bytes : 4;
        else
        {
    case SrcImmByte:
            bytes = 1;
        }
        /* NB. Immediates are sign-extended as necessary. */
        switch ( bytes )
        {
        case 1: imm1 = insn_fetch_type(int8_t);  break;
        case 2: imm1 = insn_fetch_type(int16_t); break;
        case 4: imm1 = insn_fetch_type(int32_t); break;
        }
        break;
    case SrcImm16:
        imm1 = insn_fetch_type(uint16_t);
        break;
    }

    ctxt->opcode = opcode;
    state->desc = d;

    switch ( ext )
    {
    case ext_none:
        rc = x86_decode_onebyte(state, ctxt, ops);
        break;

    case ext_0f:
        rc = x86_decode_twobyte(state, ctxt, ops);
        break;

    case ext_0f38:
        rc = x86_decode_0f38(state, ctxt, ops);
        break;

    case ext_0f3a:
        if ( !vex.opcx )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case ext_8f08:
    case ext_8f09:
    case ext_8f0a:
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

    /*
     * Undo the operand-size override effect of prefix 66 when it was
     * determined to have another meaning.
     */
    if ( op_bytes == 2 &&
         (ctxt->opcode & X86EMUL_OPC_PFX_MASK) == X86EMUL_OPC_66(0, 0) )
        op_bytes = 4;

 done:
    return rc;
}

/* No insn fetching past this point. */
#undef insn_fetch_bytes
#undef insn_fetch_type

int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    /* Shadow copy of register state. Committed on successful emulation. */
    struct cpu_user_regs _regs = *ctxt->regs;
    struct x86_emulate_state state;
    int rc;
    uint8_t b, d;
    bool tf = ctxt->regs->eflags & EFLG_TF;
    struct operand src = { .reg = PTR_POISON };
    struct operand dst = { .reg = PTR_POISON };
    enum x86_swint_type swint_type;
    struct x86_emulate_stub stub = {};
    DECLARE_ALIGNED(mmval_t, mmval);

    rc = x86_decode(&state, ctxt, ops);
    if ( rc != X86EMUL_OKAY )
        return rc;

    /* Sync rIP to post decode value. */
    _regs.eip = state.eip;

    b = ctxt->opcode;
    d = state.desc;
#define state (&state)

    if ( ea.type == OP_REG )
        ea.reg = decode_register(modrm_rm, &_regs,
                                 (d & ByteOp) && !rex_prefix);

    /* Decode and fetch the source operand: register, memory or immediate. */
    switch ( d & SrcMask )
    {
    case SrcNone: /* case SrcImplicit: */
        src.type = OP_NONE;
        break;
    case SrcReg:
        src.type = OP_REG;
        if ( d & ByteOp )
        {
            src.reg = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            src.val = *(uint8_t *)src.reg;
            src.bytes = 1;
        }
        else
        {
            src.reg = decode_register(modrm_reg, &_regs, 0);
            switch ( (src.bytes = op_bytes) )
            {
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        break;
    case SrcMem16:
        ea.bytes = 2;
        goto srcmem_common;
    case SrcMem:
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
    srcmem_common:
        src = ea;
        if ( src.type == OP_REG )
        {
            switch ( src.bytes )
            {
            case 1: src.val = *(uint8_t  *)src.reg; break;
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        else if ( (rc = read_ulong(src.mem.seg, src.mem.off,
                                   &src.val, src.bytes, ctxt, ops)) )
            goto done;
        break;
    case SrcImm:
        if ( !(d & ByteOp) )
            src.bytes = op_bytes != 8 ? op_bytes : 4;
        else
        {
    case SrcImmByte:
            src.bytes = 1;
        }
        src.type  = OP_IMM;
        src.val   = imm1;
        break;
    case SrcImm16:
        src.type  = OP_IMM;
        src.bytes = 2;
        src.val   = imm1;
        break;
    }

    /* Decode and fetch the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case DstNone: /* case DstImplicit: */
        /*
         * The only implicit-operands instructions allowed a LOCK prefix are
         * CMPXCHG{8,16}B, MOV CRn, MOV DRn.
         */
        generate_exception_if(
            lock_prefix &&
            (ext != ext_0f ||
             (((b < 0x20) || (b > 0x23)) && /* MOV CRn/DRn */
              (b != 0xc7))),                /* CMPXCHG{8,16}B */
            EXC_UD, -1);
        dst.type = OP_NONE;
        break;

    case DstReg:
        generate_exception_if(lock_prefix, EXC_UD, -1);
        dst.type = OP_REG;
        if ( d & ByteOp )
        {
            dst.reg = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            dst.val = *(uint8_t *)dst.reg;
            dst.bytes = 1;
        }
        else
        {
            dst.reg = decode_register(modrm_reg, &_regs, 0);
            switch ( (dst.bytes = op_bytes) )
            {
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        break;
    case DstBitBase:
        if ( ((d & SrcMask) == SrcImmByte) || (ea.type == OP_REG) )
        {
            src.val &= (op_bytes << 3) - 1;
        }
        else
        {
            /*
             * Instructions such as bt can reference an arbitrary offset from
             * their memory operand, but the instruction doing the actual
             * emulation needs the appropriate op_bytes read from memory.
             * Adjust both the source register and memory operand to make an
             * equivalent instruction.
             *
             * EA       += BitOffset DIV op_bytes*8
             * BitOffset = BitOffset MOD op_bytes*8
             * DIV truncates towards negative infinity.
             * MOD always produces a positive result.
             */
            if ( op_bytes == 2 )
                src.val = (int16_t)src.val;
            else if ( op_bytes == 4 )
                src.val = (int32_t)src.val;
            if ( (long)src.val < 0 )
                ea.mem.off -=
                    op_bytes + (((-src.val - 1) >> 3) & ~(op_bytes - 1L));
            else
                ea.mem.off += (src.val >> 3) & ~(op_bytes - 1L);
            src.val &= (op_bytes << 3) - 1;
        }
        /* Becomes a normal DstMem operation from here on. */
        d = (d & ~DstMask) | DstMem;
    case DstMem:
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst = ea;
        if ( dst.type == OP_REG )
        {
            generate_exception_if(lock_prefix, EXC_UD, -1);
            switch ( dst.bytes )
            {
            case 1: dst.val = *(uint8_t  *)dst.reg; break;
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        else if ( !(d & Mov) ) /* optimisation - avoid slow emulated read */
        {
            if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
                                  &dst.val, dst.bytes, ctxt, ops)) )
                goto done;
            dst.orig_val = dst.val;
        }
        else /* Lock prefix is allowed only on RMW instructions. */
            generate_exception_if(lock_prefix, EXC_UD, -1);
        break;
    }

    switch ( ctxt->opcode )
    {
        enum x86_segment seg;
        struct segment_register cs, sreg;

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
        generate_exception_if(lock_prefix, EXC_UD, -1);
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x06: /* push %%es */
        src.val = x86_seg_es;
    push_seg:
        generate_exception_if(mode_64bit() && !ext, EXC_UD, -1);
        fail_if(ops->read_segment == NULL);
        if ( (rc = ops->read_segment(src.val, &sreg, ctxt)) != 0 )
            goto done;
        src.val = sreg.sel;
        goto push;

    case 0x07: /* pop %%es */
        src.val = x86_seg_es;
    pop_seg:
        generate_exception_if(mode_64bit() && !ext, EXC_UD, -1);
        fail_if(ops->write_segment == NULL);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (op_bytes == 4) )
            op_bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &dst.val, op_bytes, ctxt, ops)) != 0 ||
             (rc = load_seg(src.val, dst.val, 0, NULL, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x0e: /* push %%cs */
        src.val = x86_seg_cs;
        goto push_seg;

    case 0x16: /* push %%ss */
        src.val = x86_seg_ss;
        goto push_seg;

    case 0x17: /* pop %%ss */
        src.val = x86_seg_ss;
        ctxt->retire.flags.mov_ss = 1;
        goto pop_seg;

    case 0x1e: /* push %%ds */
        src.val = x86_seg_ds;
        goto push_seg;

    case 0x1f: /* pop %%ds */
        src.val = x86_seg_ds;
        goto pop_seg;

    case 0x27: /* daa */
    case 0x2f: /* das */ {
        uint8_t al = _regs.eax;
        unsigned long eflags = _regs.eflags;

        generate_exception_if(mode_64bit(), EXC_UD, -1);
        _regs.eflags &= ~(EFLG_CF|EFLG_AF|EFLG_SF|EFLG_ZF|EFLG_PF);
        if ( ((al & 0x0f) > 9) || (eflags & EFLG_AF) )
        {
            _regs.eflags |= EFLG_AF;
            if ( b == 0x2f && (al < 6 || (eflags & EFLG_CF)) )
                _regs.eflags |= EFLG_CF;
            *(uint8_t *)&_regs.eax += (b == 0x27) ? 6 : -6;
        }
        if ( (al > 0x99) || (eflags & EFLG_CF) )
        {
            *(uint8_t *)&_regs.eax += (b == 0x27) ? 0x60 : -0x60;
            _regs.eflags |= EFLG_CF;
        }
        _regs.eflags |= ((uint8_t)_regs.eax == 0) ? EFLG_ZF : 0;
        _regs.eflags |= (( int8_t)_regs.eax <  0) ? EFLG_SF : 0;
        _regs.eflags |= even_parity(_regs.eax) ? EFLG_PF : 0;
        break;
    }

    case 0x37: /* aaa */
    case 0x3f: /* aas */
        generate_exception_if(mode_64bit(), EXC_UD, -1);
        _regs.eflags &= ~EFLG_CF;
        if ( ((uint8_t)_regs.eax > 9) || (_regs.eflags & EFLG_AF) )
        {
            ((uint8_t *)&_regs.eax)[0] += (b == 0x37) ? 6 : -6;
            ((uint8_t *)&_regs.eax)[1] += (b == 0x37) ? 1 : -1;
            _regs.eflags |= EFLG_CF | EFLG_AF;
        }
        ((uint8_t *)&_regs.eax)[0] &= 0x0f;
        break;

    case 0x40 ... 0x4f: /* inc/dec reg */
        dst.type  = OP_REG;
        dst.reg   = decode_register(b & 7, &_regs, 0);
        dst.bytes = op_bytes;
        dst.val   = *dst.reg;
        if ( b & 8 )
            emulate_1op("dec", dst, _regs.eflags);
        else
            emulate_1op("inc", dst, _regs.eflags);
        break;

    case 0x50 ... 0x57: /* push reg */
        src.val = *(unsigned long *)decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        goto push;

    case 0x58 ... 0x5f: /* pop reg */
        dst.type  = OP_REG;
        dst.reg   = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        dst.bytes = op_bytes;
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x60: /* pusha */ {
        int i;
        unsigned long regs[] = {
            _regs.eax, _regs.ecx, _regs.edx, _regs.ebx,
            _regs.esp, _regs.ebp, _regs.esi, _regs.edi };
        generate_exception_if(mode_64bit(), EXC_UD, -1);
        for ( i = 0; i < 8; i++ )
            if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                                  &regs[i], op_bytes, ctxt)) != 0 )
            goto done;
        break;
    }

    case 0x61: /* popa */ {
        int i;
        unsigned long dummy_esp, *regs[] = {
            (unsigned long *)&_regs.edi, (unsigned long *)&_regs.esi,
            (unsigned long *)&_regs.ebp, (unsigned long *)&dummy_esp,
            (unsigned long *)&_regs.ebx, (unsigned long *)&_regs.edx,
            (unsigned long *)&_regs.ecx, (unsigned long *)&_regs.eax };
        generate_exception_if(mode_64bit(), EXC_UD, -1);
        for ( i = 0; i < 8; i++ )
        {
            if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                                  &dst.val, op_bytes, ctxt, ops)) != 0 )
                goto done;
            if ( op_bytes == 2 )
                *(uint16_t *)regs[i] = (uint16_t)dst.val;
            else
                *regs[i] = dst.val; /* 64b: zero-ext done by read_ulong() */
        }
        break;
    }

    case 0x62: /* bound */ {
        unsigned long src_val2;
        int lb, ub, idx;
        generate_exception_if(mode_64bit() || (src.type != OP_MEM),
                              EXC_UD, -1);
        if ( (rc = read_ulong(src.mem.seg, src.mem.off + op_bytes,
                              &src_val2, op_bytes, ctxt, ops)) )
            goto done;
        ub  = (op_bytes == 2) ? (int16_t)src_val2 : (int32_t)src_val2;
        lb  = (op_bytes == 2) ? (int16_t)src.val  : (int32_t)src.val;
        idx = (op_bytes == 2) ? (int16_t)dst.val  : (int32_t)dst.val;
        generate_exception_if((idx < lb) || (idx > ub), EXC_BR, -1);
        dst.type = OP_NONE;
        break;
    }

    case 0x63: /* movsxd (x86/64) / arpl (x86/32) */
        if ( mode_64bit() )
        {
            /* movsxd */
            if ( ea.type == OP_REG )
                src.val = *ea.reg;
            else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                       &src.val, 4, ctxt, ops)) )
                goto done;
            dst.val = (int32_t)src.val;
        }
        else
        {
            /* arpl */
            unsigned int src_rpl = dst.val & 3;

            dst = ea;
            dst.bytes = 2;
            if ( dst.type == OP_REG )
                dst.val = *dst.reg;
            else if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
                                       &dst.val, 2, ctxt, ops)) )
                goto done;
            if ( src_rpl > (dst.val & 3) )
            {
                _regs.eflags |= EFLG_ZF;
                dst.val = (dst.val & ~3) | src_rpl;
            }
            else
            {
                _regs.eflags &= ~EFLG_ZF;
                dst.type = OP_NONE;
            }
            generate_exception_if(!in_protmode(ctxt, ops), EXC_UD, -1);
        }
        break;

    case 0x68: /* push imm{16,32,64} */
    case 0x6a: /* push imm8 */
    push:
        ASSERT(d & Mov); /* writeback needed */
        dst.type  = OP_MEM;
        dst.bytes = mode_64bit() && (op_bytes == 4) ? 8 : op_bytes;
        dst.val = src.val;
        dst.mem.seg = x86_seg_ss;
        dst.mem.off = sp_pre_dec(dst.bytes);
        break;

    case 0x69: /* imul imm16/32 */
    case 0x6b: /* imul imm8 */
        if ( ea.type == OP_REG )
            dst.val = *ea.reg;
        else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                   &dst.val, op_bytes, ctxt, ops)) )
            goto done;
        goto imul;

    case 0x6c ... 0x6d: /* ins %dx,%es:%edi */ {
        unsigned long nr_reps = get_rep_prefix();
        unsigned int port = (uint16_t)_regs.edx;
        dst.bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea_and_reps(_regs.edi, nr_reps, dst.bytes);
        if ( (rc = ioport_access_check(port, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        if ( (nr_reps > 1) && (ops->rep_ins != NULL) &&
             ((rc = ops->rep_ins(port, dst.mem.seg, dst.mem.off, dst.bytes,
                                 &nr_reps, ctxt)) != X86EMUL_UNHANDLEABLE) )
        {
            if ( rc != 0 )
                goto done;
        }
        else
        {
            fail_if(ops->read_io == NULL);
            if ( (rc = ops->read_io(port, dst.bytes, &dst.val, ctxt)) != 0 )
                goto done;
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        register_address_increment(
            _regs.edi,
            nr_reps * ((_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes));
        put_rep_prefix(nr_reps);
        break;
    }

    case 0x6e ... 0x6f: /* outs %esi,%dx */ {
        unsigned long nr_reps = get_rep_prefix();
        unsigned int port = (uint16_t)_regs.edx;
        dst.bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        ea.mem.off = truncate_ea_and_reps(_regs.esi, nr_reps, dst.bytes);
        if ( (rc = ioport_access_check(port, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        if ( (nr_reps > 1) && (ops->rep_outs != NULL) &&
             ((rc = ops->rep_outs(ea.mem.seg, ea.mem.off, port, dst.bytes,
                                  &nr_reps, ctxt)) != X86EMUL_UNHANDLEABLE) )
        {
            if ( rc != 0 )
                goto done;
        }
        else
        {
            if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.esi),
                                  &dst.val, dst.bytes, ctxt, ops)) != 0 )
                goto done;
            fail_if(ops->write_io == NULL);
            if ( (rc = ops->write_io(port, dst.bytes, dst.val, ctxt)) != 0 )
                goto done;
            nr_reps = 1;
        }
        register_address_increment(
            _regs.esi,
            nr_reps * ((_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes));
        put_rep_prefix(nr_reps);
        break;
    }

    case 0x70 ... 0x7f: /* jcc (short) */
        if ( test_cc(b, _regs.eflags) )
            jmp_rel((int32_t)src.val);
        break;

    case 0x82: /* Grp1 (x86/32 only) */
        generate_exception_if(mode_64bit(), EXC_UD, -1);
    case 0x80: case 0x81: case 0x83: /* Grp1 */
        switch ( modrm_reg & 7 )
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

    case 0xa8 ... 0xa9: /* test imm,%%eax */
    case 0x84 ... 0x85: test: /* test */
        emulate_2op_SrcV("test", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x86 ... 0x87: xchg: /* xchg */
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        /* Write back the memory destination with implicit LOCK prefix. */
        dst.val = src.val;
        lock_prefix = 1;
        break;

    case 0xc6: /* Grp11: mov / xabort */
    case 0xc7: /* Grp11: mov / xbegin */
        if ( modrm == 0xf8 && vcpu_has_rtm() )
        {
            /*
             * xbegin unconditionally aborts, xabort is unconditionally
             * a nop.
             */
            if ( b & 1 )
            {
                jmp_rel((int32_t)src.val);
                _regs.eax = 0;
            }
            dst.type = OP_NONE;
            break;
        }
        generate_exception_if((modrm_reg & 7) != 0, EXC_UD, -1);
    case 0x88 ... 0x8b: /* mov */
    case 0xa0 ... 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2 ... 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        dst.val = src.val;
        break;

    case 0x8c: /* mov Sreg,r/m */
        seg = modrm_reg & 7; /* REX.R is ignored. */
        generate_exception_if(!is_x86_user_segment(seg), EXC_UD, -1);
    store_selector:
        fail_if(ops->read_segment == NULL);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) != 0 )
            goto done;
        dst.val = sreg.sel;
        if ( dst.type == OP_MEM )
            dst.bytes = 2;
        break;

    case 0x8e: /* mov r/m,Sreg */
        seg = modrm_reg & 7; /* REX.R is ignored. */
        generate_exception_if(!is_x86_user_segment(seg) ||
                              seg == x86_seg_cs, EXC_UD, -1);
        if ( (rc = load_seg(seg, src.val, 0, NULL, ctxt, ops)) != 0 )
            goto done;
        if ( seg == x86_seg_ss )
            ctxt->retire.flags.mov_ss = 1;
        dst.type = OP_NONE;
        break;

    case 0x8d: /* lea */
        generate_exception_if(ea.type != OP_MEM, EXC_UD, -1);
        dst.val = ea.mem.off;
        break;

    case 0x8f: /* pop (sole member of Grp1a) */
        generate_exception_if((modrm_reg & 7) != 0, EXC_UD, -1);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x90: /* nop / xchg %%r8,%%rax */
    case X86EMUL_OPC_F3(0, 0x90): /* pause / xchg %%r8,%%rax */
        if ( !(rex_prefix & 1) )
            break; /* nop / pause */
        /* fall through */

    case 0x91 ... 0x97: /* xchg reg,%%rax */
        dst.type = OP_REG;
        dst.bytes = op_bytes;
        dst.reg  = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        dst.val  = *dst.reg;
        goto xchg;

    case 0x98: /* cbw/cwde/cdqe */
        switch ( op_bytes )
        {
        case 2: *(int16_t *)&_regs.eax = (int8_t)_regs.eax; break; /* cbw */
        case 4: _regs.eax = (uint32_t)(int16_t)_regs.eax; break; /* cwde */
        case 8: _regs.eax = (int32_t)_regs.eax; break; /* cdqe */
        }
        break;

    case 0x99: /* cwd/cdq/cqo */
        switch ( op_bytes )
        {
        case 2:
            *(int16_t *)&_regs.edx = ((int16_t)_regs.eax < 0) ? -1 : 0;
            break;
        case 4:
            _regs.edx = (uint32_t)(((int32_t)_regs.eax < 0) ? -1 : 0);
            break;
#ifdef __x86_64__ /* compile warning with some versions of 32-bit gcc */
        case 8:
            _regs.edx = ((int64_t)_regs.eax < 0) ? -1 : 0;
            break;
#endif
        }
        break;

    case 0x9a: /* call (far, absolute) */
        ASSERT(!mode_64bit());
    far_call:
        fail_if(ops->read_segment == NULL);

        if ( (rc = ops->read_segment(x86_seg_cs, &sreg, ctxt)) ||
             (rc = load_seg(x86_seg_cs, imm2, 0, &cs, ctxt, ops)) ||
             (validate_far_branch(&cs, imm1),
              src.val = sreg.sel,
              rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                              &src.val, op_bytes, ctxt)) ||
             (rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                              &_regs.eip, op_bytes, ctxt)) ||
             (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) )
            goto done;

        _regs.eip = imm1;
        break;

    case 0x9b:  /* wait/fwait */
    {
        struct fpu_insn_ctxt fic = { .insn_bytes = 1 };

        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_wait, &fic);
        asm volatile ( "fwait" ::: "memory" );
        put_fpu(&fic);
        break;
    }

    case 0x9c: /* pushf */
        src.val = _regs.eflags;
        goto push;

    case 0x9d: /* popf */ {
        uint32_t mask = EFLG_VIP | EFLG_VIF | EFLG_VM;
        if ( !mode_ring0() )
        {
            mask |= EFLG_IOPL;
            if ( !mode_iopl() )
                mask |= EFLG_IF;
        }
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (op_bytes == 4) )
            op_bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &dst.val, op_bytes, ctxt, ops)) != 0 )
            goto done;
        if ( op_bytes == 2 )
            dst.val = (uint16_t)dst.val | (_regs.eflags & 0xffff0000u);
        dst.val &= 0x257fd5;
        _regs.eflags &= mask;
        _regs.eflags |= (uint32_t)(dst.val & ~mask) | 0x02;
        break;
    }

    case 0x9e: /* sahf */
        *(uint8_t *)&_regs.eflags = (((uint8_t *)&_regs.eax)[1] & 0xd7) | 0x02;
        break;

    case 0x9f: /* lahf */
        ((uint8_t *)&_regs.eax)[1] = (_regs.eflags & 0xd7) | 0x02;
        break;

    case 0xa4 ... 0xa5: /* movs */ {
        unsigned long nr_reps = get_rep_prefix();
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea_and_reps(_regs.edi, nr_reps, dst.bytes);
        src.mem.off = truncate_ea_and_reps(_regs.esi, nr_reps, dst.bytes);
        if ( (nr_reps > 1) && (ops->rep_movs != NULL) &&
             ((rc = ops->rep_movs(ea.mem.seg, src.mem.off,
                                  dst.mem.seg, dst.mem.off, dst.bytes,
                                  &nr_reps, ctxt)) != X86EMUL_UNHANDLEABLE) )
        {
            if ( rc != 0 )
                goto done;
        }
        else
        {
            if ( (rc = read_ulong(ea.mem.seg, src.mem.off,
                                  &dst.val, dst.bytes, ctxt, ops)) != 0 )
                goto done;
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        register_address_increment(
            _regs.esi,
            nr_reps * ((_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes));
        register_address_increment(
            _regs.edi,
            nr_reps * ((_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes));
        put_rep_prefix(nr_reps);
        break;
    }

    case 0xa6 ... 0xa7: /* cmps */ {
        unsigned long next_eip = _regs.eip;
        get_rep_prefix();
        src.bytes = dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.esi),
                              &dst.val, dst.bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_es, truncate_ea(_regs.edi),
                              &src.val, src.bytes, ctxt, ops)) )
            goto done;
        register_address_increment(
            _regs.esi, (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes);
        register_address_increment(
            _regs.edi, (_regs.eflags & EFLG_DF) ? -src.bytes : src.bytes);
        put_rep_prefix(1);
        /* cmp: dst - src ==> src=*%%edi,dst=*%%esi ==> *%%esi - *%%edi */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        if ( (repe_prefix() && !(_regs.eflags & EFLG_ZF)) ||
             (repne_prefix() && (_regs.eflags & EFLG_ZF)) )
            _regs.eip = next_eip;
        break;
    }

    case 0xaa ... 0xab: /* stos */ {
        unsigned long nr_reps = get_rep_prefix();
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea(_regs.edi);
        if ( (nr_reps == 1) || !ops->rep_stos ||
             ((rc = ops->rep_stos(&_regs.eax,
                                  dst.mem.seg, dst.mem.off, dst.bytes,
                                  &nr_reps, ctxt)) == X86EMUL_UNHANDLEABLE) )
        {
            dst.val = _regs.eax;
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        else if ( rc != X86EMUL_OKAY )
            goto done;
        register_address_increment(
            _regs.edi,
            nr_reps * ((_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes));
        put_rep_prefix(nr_reps);
        break;
    }

    case 0xac ... 0xad: /* lods */ {
        /* unsigned long max_reps = */get_rep_prefix();
        dst.type  = OP_REG;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.reg   = (unsigned long *)&_regs.eax;
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.esi),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        register_address_increment(
            _regs.esi, (_regs.eflags & EFLG_DF) ? -dst.bytes : dst.bytes);
        put_rep_prefix(1);
        break;
    }

    case 0xae ... 0xaf: /* scas */ {
        unsigned long next_eip = _regs.eip;
        get_rep_prefix();
        src.bytes = dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.val = _regs.eax;
        if ( (rc = read_ulong(x86_seg_es, truncate_ea(_regs.edi),
                              &src.val, src.bytes, ctxt, ops)) != 0 )
            goto done;
        register_address_increment(
            _regs.edi, (_regs.eflags & EFLG_DF) ? -src.bytes : src.bytes);
        put_rep_prefix(1);
        /* cmp: dst - src ==> src=*%%edi,dst=%%eax ==> %%eax - *%%edi */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        if ( (repe_prefix() && !(_regs.eflags & EFLG_ZF)) ||
             (repne_prefix() && (_regs.eflags & EFLG_ZF)) )
            _regs.eip = next_eip;
        break;
    }

    case 0xb0 ... 0xb7: /* mov imm8,r8 */
        dst.reg = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, (rex_prefix == 0));
        dst.val = src.val;
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        dst.reg = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        dst.val = src.val;
        break;

    case 0xc0 ... 0xc1: grp2: /* Grp2 */
        switch ( modrm_reg & 7 )
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

    case 0xc2: /* ret imm16 (near) */
    case 0xc3: /* ret (near) */
        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + src.val),
                              &dst.val, op_bytes, ctxt, ops)) != 0 ||
             (rc = ops->insn_fetch(x86_seg_cs, dst.val, NULL, 0, ctxt)) )
            goto done;
        _regs.eip = dst.val;
        break;

    case 0xc4: /* les */ {
        unsigned long sel;
        dst.val = x86_seg_es;
    les: /* dst.val identifies the segment */
        generate_exception_if(mode_64bit() && !ext, EXC_UD, -1);
        generate_exception_if(src.type != OP_MEM, EXC_UD, -1);
        if ( (rc = read_ulong(src.mem.seg, src.mem.off + src.bytes,
                              &sel, 2, ctxt, ops)) != 0 )
            goto done;
        if ( (rc = load_seg(dst.val, sel, 0, NULL, ctxt, ops)) != 0 )
            goto done;
        dst.val = src.val;
        break;
    }

    case 0xc5: /* lds */
        dst.val = x86_seg_ds;
        goto les;

    case 0xc8: /* enter imm16,imm8 */ {
        uint8_t depth = imm2 & 31;
        int i;

        dst.type = OP_REG;
        dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
        dst.reg = (unsigned long *)&_regs.ebp;
        if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                              &_regs.ebp, dst.bytes, ctxt)) )
            goto done;
        dst.val = _regs.esp;

        if ( depth > 0 )
        {
            for ( i = 1; i < depth; i++ )
            {
                unsigned long ebp, temp_data;
                ebp = truncate_word(_regs.ebp - i*dst.bytes, ctxt->sp_size/8);
                if ( (rc = read_ulong(x86_seg_ss, ebp,
                                      &temp_data, dst.bytes, ctxt, ops)) ||
                     (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                                      &temp_data, dst.bytes, ctxt)) )
                    goto done;
            }
            if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                                  &dst.val, dst.bytes, ctxt)) )
                goto done;
        }

        sp_pre_dec(src.val);
        break;
    }

    case 0xc9: /* leave */
        /* First writeback, to %%esp. */
        dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
        switch ( dst.bytes )
        {
        case 2: *(uint16_t *)&_regs.esp = (uint16_t)_regs.ebp; break;
        case 4: _regs.esp = (uint32_t)_regs.ebp; break; /* 64b: zero-ext */
        case 8: _regs.esp = _regs.ebp; break;
        }

        /* Second writeback, to %%ebp. */
        dst.type = OP_REG;
        dst.reg = (unsigned long *)&_regs.ebp;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) )
            goto done;
        break;

    case 0xca: /* ret imm16 (far) */
    case 0xcb: /* ret (far) */
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &dst.val, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + src.val),
                              &src.val, op_bytes, ctxt, ops)) ||
             (rc = load_seg(x86_seg_cs, src.val, 1, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, dst.val)) )
            goto done;
        break;

    case 0xcc: /* int3 */
        src.val = EXC_BP;
        swint_type = x86_swint_int3;
        goto swint;

    case 0xcd: /* int imm8 */
        swint_type = x86_swint_int;
    swint:
        rc = inject_swint(swint_type, (uint8_t)src.val,
                          _regs.eip - ctxt->regs->eip,
                          ctxt, ops) ? : X86EMUL_EXCEPTION;
        goto done;

    case 0xce: /* into */
        generate_exception_if(mode_64bit(), EXC_UD, -1);
        if ( !(_regs.eflags & EFLG_OF) )
            break;
        src.val = EXC_OF;
        swint_type = x86_swint_into;
        goto swint;

    case 0xcf: /* iret */ {
        unsigned long sel, eip, eflags;
        uint32_t mask = EFLG_VIP | EFLG_VIF | EFLG_VM;

        fail_if(!in_realmode(ctxt, ops));
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &eip, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &sel, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &eflags, op_bytes, ctxt, ops)) )
            goto done;
        if ( op_bytes == 2 )
            eflags = (uint16_t)eflags | (_regs.eflags & 0xffff0000u);
        eflags &= 0x257fd5;
        _regs.eflags &= mask;
        _regs.eflags |= (eflags & ~mask) | 0x02;
        if ( (rc = load_seg(x86_seg_cs, sel, 1, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, (uint32_t)eip)) )
            goto done;
        break;
    }

    case 0xd0 ... 0xd1: /* Grp2 */
        src.val = 1;
        goto grp2;

    case 0xd2 ... 0xd3: /* Grp2 */
        src.val = _regs.ecx;
        goto grp2;

    case 0xd4: /* aam */
    case 0xd5: /* aad */ {
        unsigned int base = (uint8_t)src.val;

        generate_exception_if(mode_64bit(), EXC_UD, -1);
        if ( b & 0x01 )
        {
            uint16_t ax = _regs.eax;

            *(uint16_t *)&_regs.eax = (uint8_t)(ax + ((ax >> 8) * base));
        }
        else
        {
            uint8_t al = _regs.eax;

            generate_exception_if(!base, EXC_DE, -1);
            *(uint16_t *)&_regs.eax = ((al / base) << 8) | (al % base);
        }
        _regs.eflags &= ~(EFLG_SF|EFLG_ZF|EFLG_PF);
        _regs.eflags |= ((uint8_t)_regs.eax == 0) ? EFLG_ZF : 0;
        _regs.eflags |= (( int8_t)_regs.eax <  0) ? EFLG_SF : 0;
        _regs.eflags |= even_parity(_regs.eax) ? EFLG_PF : 0;
        break;
    }

    case 0xd6: /* salc */
        generate_exception_if(mode_64bit(), EXC_UD, -1);
        *(uint8_t *)&_regs.eax = (_regs.eflags & EFLG_CF) ? 0xff : 0x00;
        break;

    case 0xd7: /* xlat */ {
        unsigned long al = (uint8_t)_regs.eax;
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.ebx + al),
                              &al, 1, ctxt, ops)) != 0 )
            goto done;
        *(uint8_t *)&_regs.eax = al;
        break;
    }

    case 0xd8: /* FPU 0xd8 */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %stN,%stN */
        case 0xc8 ... 0xcf: /* fmul %stN,%stN */
        case 0xd0 ... 0xd7: /* fcom %stN,%stN */
        case 0xd8 ... 0xdf: /* fcomp %stN,%stN */
        case 0xe0 ... 0xe7: /* fsub %stN,%stN */
        case 0xe8 ... 0xef: /* fsubr %stN,%stN */
        case 0xf0 ... 0xf7: /* fdiv %stN,%stN */
        case 0xf8 ... 0xff: /* fdivr %stN,%stN */
            emulate_fpu_insn_stub(0xd8, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            ea.bytes = 4;
            src = ea;
            if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                 src.bytes, ctxt)) != 0 )
                goto done;
            switch ( modrm_reg & 7 )
            {
            case 0: /* fadd */
                emulate_fpu_insn_memsrc("fadds", src.val);
                break;
            case 1: /* fmul */
                emulate_fpu_insn_memsrc("fmuls", src.val);
                break;
            case 2: /* fcom */
                emulate_fpu_insn_memsrc("fcoms", src.val);
                break;
            case 3: /* fcomp */
                emulate_fpu_insn_memsrc("fcomps", src.val);
                break;
            case 4: /* fsub */
                emulate_fpu_insn_memsrc("fsubs", src.val);
                break;
            case 5: /* fsubr */
                emulate_fpu_insn_memsrc("fsubrs", src.val);
                break;
            case 6: /* fdiv */
                emulate_fpu_insn_memsrc("fdivs", src.val);
                break;
            case 7: /* fdivr */
                emulate_fpu_insn_memsrc("fdivrs", src.val);
                break;
            }
        }
        break;

    case 0xd9: /* FPU 0xd9 */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xfb: /* fsincos */
            fail_if(cpu_has_amd_erratum(573));
            /* fall through */
        case 0xc0 ... 0xc7: /* fld %stN */
        case 0xc8 ... 0xcf: /* fxch %stN */
        case 0xd0: /* fnop */
        case 0xe0: /* fchs */
        case 0xe1: /* fabs */
        case 0xe4: /* ftst */
        case 0xe5: /* fxam */
        case 0xe8: /* fld1 */
        case 0xe9: /* fldl2t */
        case 0xea: /* fldl2e */
        case 0xeb: /* fldpi */
        case 0xec: /* fldlg2 */
        case 0xed: /* fldln2 */
        case 0xee: /* fldz */
        case 0xf0: /* f2xm1 */
        case 0xf1: /* fyl2x */
        case 0xf2: /* fptan */
        case 0xf3: /* fpatan */
        case 0xf4: /* fxtract */
        case 0xf5: /* fprem1 */
        case 0xf6: /* fdecstp */
        case 0xf7: /* fincstp */
        case 0xf8: /* fprem */
        case 0xf9: /* fyl2xp1 */
        case 0xfa: /* fsqrt */
        case 0xfc: /* frndint */
        case 0xfd: /* fscale */
        case 0xfe: /* fsin */
        case 0xff: /* fcos */
            emulate_fpu_insn_stub(0xd9, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fld m32fp */
                ea.bytes = 4;
                src = ea;
                if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                     src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("flds", src.val);
                break;
            case 2: /* fstp m32fp */
                ea.bytes = 4;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fsts", dst.val);
                break;
            case 3: /* fstp m32fp */
                ea.bytes = 4;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fstps", dst.val);
                break;
                /* case 4: fldenv - TODO */
            case 5: /* fldcw m2byte */
                ea.bytes = 2;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                     src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("fldcw", src.val);
                break;
                /* case 6: fstenv - TODO */
            case 7: /* fnstcw m2byte */
                ea.bytes = 2;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fnstcw", dst.val);
                break;
            default:
                goto cannot_emulate;
            }
        }
        break;

    case 0xda: /* FPU 0xda */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovb %stN */
        case 0xc8 ... 0xcf: /* fcmove %stN */
        case 0xd0 ... 0xd7: /* fcmovbe %stN */
        case 0xd8 ... 0xdf: /* fcmovu %stN */
            vcpu_must_have_cmov();
            emulate_fpu_insn_stub_eflags(0xda, modrm);
            break;
        case 0xe9:          /* fucompp */
            emulate_fpu_insn_stub(0xda, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            ea.bytes = 4;
            src = ea;
            if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                 src.bytes, ctxt)) != 0 )
                goto done;
            switch ( modrm_reg & 7 )
            {
            case 0: /* fiadd m32i */
                emulate_fpu_insn_memsrc("fiaddl", src.val);
                break;
            case 1: /* fimul m32i */
                emulate_fpu_insn_memsrc("fimull", src.val);
                break;
            case 2: /* ficom m32i */
                emulate_fpu_insn_memsrc("ficoml", src.val);
                break;
            case 3: /* ficomp m32i */
                emulate_fpu_insn_memsrc("ficompl", src.val);
                break;
            case 4: /* fisub m32i */
                emulate_fpu_insn_memsrc("fisubl", src.val);
                break;
            case 5: /* fisubr m32i */
                emulate_fpu_insn_memsrc("fisubrl", src.val);
                break;
            case 6: /* fidiv m32i */
                emulate_fpu_insn_memsrc("fidivl", src.val);
                break;
            case 7: /* fidivr m32i */
                emulate_fpu_insn_memsrc("fidivrl", src.val);
                break;
            }
        }
        break;

    case 0xdb: /* FPU 0xdb */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovnb %stN */
        case 0xc8 ... 0xcf: /* fcmovne %stN */
        case 0xd0 ... 0xd7: /* fcmovnbe %stN */
        case 0xd8 ... 0xdf: /* fcmovnu %stN */
        case 0xe8 ... 0xef: /* fucomi %stN */
        case 0xf0 ... 0xf7: /* fcomi %stN */
            vcpu_must_have_cmov();
            emulate_fpu_insn_stub_eflags(0xdb, modrm);
            break;
        case 0xe2: /* fnclex */
            emulate_fpu_insn("fnclex");
            break;
        case 0xe3: /* fninit */
            emulate_fpu_insn("fninit");
            break;
        case 0xe4: /* fsetpm - 287 only, ignored by 387 */
            break;
        default:
            fail_if(modrm >= 0xc0);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fild m32i */
                ea.bytes = 4;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                     src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("fildl", src.val);
                break;
            case 1: /* fisttp m32i */
                host_and_vcpu_must_have(sse3);
                ea.bytes = 4;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fisttpl", dst.val);
                break;
            case 2: /* fist m32i */
                ea.bytes = 4;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fistl", dst.val);
                break;
            case 3: /* fistp m32i */
                ea.bytes = 4;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fistpl", dst.val);
                break;
            case 5: /* fld m80fp */
                ea.bytes = 10;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off,
                                     &src.val, src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("fldt", src.val);
                break;
            case 7: /* fstp m80fp */
                ea.bytes = 10;
                dst.type = OP_MEM;
                dst = ea;
                emulate_fpu_insn_memdst("fstpt", dst.val);
                break;
            default:
                goto cannot_emulate;
            }
        }
        break;

    case 0xdc: /* FPU 0xdc */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %stN */
        case 0xc8 ... 0xcf: /* fmul %stN */
        case 0xe0 ... 0xe7: /* fsubr %stN */
        case 0xe8 ... 0xef: /* fsub %stN */
        case 0xf0 ... 0xf7: /* fdivr %stN */
        case 0xf8 ... 0xff: /* fdiv %stN */
            emulate_fpu_insn_stub(0xdc, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            ea.bytes = 8;
            src = ea;
            if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                 src.bytes, ctxt)) != 0 )
                goto done;
            switch ( modrm_reg & 7 )
            {
            case 0: /* fadd m64fp */
                emulate_fpu_insn_memsrc("faddl", src.val);
                break;
            case 1: /* fmul m64fp */
                emulate_fpu_insn_memsrc("fmull", src.val);
                break;
            case 2: /* fcom m64fp */
                emulate_fpu_insn_memsrc("fcoml", src.val);
                break;
            case 3: /* fcomp m64fp */
                emulate_fpu_insn_memsrc("fcompl", src.val);
                break;
            case 4: /* fsub m64fp */
                emulate_fpu_insn_memsrc("fsubl", src.val);
                break;
            case 5: /* fsubr m64fp */
                emulate_fpu_insn_memsrc("fsubrl", src.val);
                break;
            case 6: /* fdiv m64fp */
                emulate_fpu_insn_memsrc("fdivl", src.val);
                break;
            case 7: /* fdivr m64fp */
                emulate_fpu_insn_memsrc("fdivrl", src.val);
                break;
            }
        }
        break;

    case 0xdd: /* FPU 0xdd */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* ffree %stN */
        case 0xd0 ... 0xd7: /* fst %stN */
        case 0xd8 ... 0xdf: /* fstp %stN */
        case 0xe0 ... 0xe7: /* fucom %stN */
        case 0xe8 ... 0xef: /* fucomp %stN */
            emulate_fpu_insn_stub(0xdd, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fld m64fp */;
                ea.bytes = 8;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                     src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("fldl", src.val);
                break;
            case 1: /* fisttp m64i */
                host_and_vcpu_must_have(sse3);
                ea.bytes = 8;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fisttpll", dst.val);
                break;
            case 2: /* fst m64fp */
                ea.bytes = 8;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fstl", dst.val);
                break;
            case 3: /* fstp m64fp */
                ea.bytes = 8;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fstpl", dst.val);
                break;
            case 7: /* fnstsw m2byte */
                ea.bytes = 2;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fnstsw", dst.val);
                break;
            default:
                goto cannot_emulate;
            }
        }
        break;

    case 0xde: /* FPU 0xde */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* faddp %stN */
        case 0xc8 ... 0xcf: /* fmulp %stN */
        case 0xd9: /* fcompp */
        case 0xe0 ... 0xe7: /* fsubrp %stN */
        case 0xe8 ... 0xef: /* fsubp %stN */
        case 0xf0 ... 0xf7: /* fdivrp %stN */
        case 0xf8 ... 0xff: /* fdivp %stN */
            emulate_fpu_insn_stub(0xde, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            ea.bytes = 2;
            src = ea;
            if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                 src.bytes, ctxt)) != 0 )
                goto done;
            switch ( modrm_reg & 7 )
            {
            case 0: /* fiadd m16i */
                emulate_fpu_insn_memsrc("fiadds", src.val);
                break;
            case 1: /* fimul m16i */
                emulate_fpu_insn_memsrc("fimuls", src.val);
                break;
            case 2: /* ficom m16i */
                emulate_fpu_insn_memsrc("ficoms", src.val);
                break;
            case 3: /* ficomp m16i */
                emulate_fpu_insn_memsrc("ficomps", src.val);
                break;
            case 4: /* fisub m16i */
                emulate_fpu_insn_memsrc("fisubs", src.val);
                break;
            case 5: /* fisubr m16i */
                emulate_fpu_insn_memsrc("fisubrs", src.val);
                break;
            case 6: /* fidiv m16i */
                emulate_fpu_insn_memsrc("fidivs", src.val);
                break;
            case 7: /* fidivr m16i */
                emulate_fpu_insn_memsrc("fidivrs", src.val);
                break;
            }
        }
        break;

    case 0xdf: /* FPU 0xdf */
        host_and_vcpu_must_have(fpu);
        switch ( modrm )
        {
        case 0xe0:
            /* fnstsw %ax */
            dst.bytes = 2;
            dst.type = OP_REG;
            dst.reg = (unsigned long *)&_regs.eax;
            emulate_fpu_insn_memdst("fnstsw", dst.val);
            break;
        case 0xe8 ... 0xef: /* fucomip %stN */
        case 0xf0 ... 0xf7: /* fcomip %stN */
            vcpu_must_have_cmov();
            emulate_fpu_insn_stub_eflags(0xdf, modrm);
            break;
        default:
            fail_if(modrm >= 0xc0);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fild m16i */
                ea.bytes = 2;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                     src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("filds", src.val);
                break;
            case 1: /* fisttp m16i */
                host_and_vcpu_must_have(sse3);
                ea.bytes = 2;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fisttps", dst.val);
                break;
            case 2: /* fist m16i */
                ea.bytes = 2;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fists", dst.val);
                break;
            case 3: /* fistp m16i */
                ea.bytes = 2;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fistps", dst.val);
                break;
            case 4: /* fbld m80dec */
                ea.bytes = 10;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off,
                                     &src.val, src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("fbld", src.val);
                break;
            case 5: /* fild m64i */
                ea.bytes = 8;
                src = ea;
                if ( (rc = ops->read(src.mem.seg, src.mem.off, &src.val,
                                     src.bytes, ctxt)) != 0 )
                    goto done;
                emulate_fpu_insn_memsrc("fildll", src.val);
                break;
            case 6: /* fbstp packed bcd */
                ea.bytes = 10;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fbstp", dst.val);
                break;
            case 7: /* fistp m64i */
                ea.bytes = 8;
                dst = ea;
                dst.type = OP_MEM;
                emulate_fpu_insn_memdst("fistpll", dst.val);
                break;
            }
        }
        break;

    case 0xe0 ... 0xe2: /* loop{,z,nz} */ {
        int do_jmp = !(_regs.eflags & EFLG_ZF); /* loopnz */

        if ( b == 0xe1 )
            do_jmp = !do_jmp; /* loopz */
        else if ( b == 0xe2 )
            do_jmp = 1; /* loop */
        switch ( ad_bytes )
        {
        case 2:
            do_jmp &= --(*(uint16_t *)&_regs.ecx) != 0;
            break;
        case 4:
            do_jmp &= --(*(uint32_t *)&_regs.ecx) != 0;
            _regs.ecx = (uint32_t)_regs.ecx; /* zero extend in x86/64 mode */
            break;
        default: /* case 8: */
            do_jmp &= --_regs.ecx != 0;
            break;
        }
        if ( do_jmp )
            jmp_rel((int32_t)src.val);
        break;
    }

    case 0xe3: /* jcxz/jecxz (short) */
        if ( (ad_bytes == 2) ? !(uint16_t)_regs.ecx :
             (ad_bytes == 4) ? !(uint32_t)_regs.ecx : !_regs.ecx )
            jmp_rel((int32_t)src.val);
        break;

    case 0xe4: /* in imm8,%al */
    case 0xe5: /* in imm8,%eax */
    case 0xe6: /* out %al,imm8 */
    case 0xe7: /* out %eax,imm8 */
    case 0xec: /* in %dx,%al */
    case 0xed: /* in %dx,%eax */
    case 0xee: /* out %al,%dx */
    case 0xef: /* out %eax,%dx */ {
        unsigned int port = ((b < 0xe8) ? (uint8_t)src.val
                                        : (uint16_t)_regs.edx);

        op_bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        if ( (rc = ioport_access_check(port, op_bytes, ctxt, ops)) != 0 )
            goto done;
        if ( b & 2 )
        {
            /* out */
            fail_if(ops->write_io == NULL);
            rc = ops->write_io(port, op_bytes, _regs.eax, ctxt);
        }
        else
        {
            /* in */
            dst.bytes = op_bytes;
            fail_if(ops->read_io == NULL);
            rc = ops->read_io(port, dst.bytes, &dst.val, ctxt);
        }
        if ( rc != 0 )
            goto done;
        break;
    }

    case 0xe8: /* call (near) */ {
        int32_t rel = src.val;

        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        src.val = _regs.eip;
        jmp_rel(rel);
        goto push;
    }

    case 0xe9: /* jmp (near) */
    case 0xeb: /* jmp (short) */
        jmp_rel((int32_t)src.val);
        break;

    case 0xea: /* jmp (far, absolute) */
        ASSERT(!mode_64bit());
    far_jmp:
        if ( (rc = load_seg(x86_seg_cs, imm2, 0, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, imm1)) )
            goto done;
        break;

    case 0xf1: /* int1 (icebp) */
        src.val = EXC_DB;
        swint_type = x86_swint_icebp;
        goto swint;

    case 0xf4: /* hlt */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        ctxt->retire.flags.hlt = 1;
        break;

    case 0xf5: /* cmc */
        _regs.eflags ^= EFLG_CF;
        break;

    case 0xf6 ... 0xf7: /* Grp3 */
        switch ( modrm_reg & 7 )
        {
            unsigned long u[2], v;

        case 0 ... 1: /* test */
            generate_exception_if(lock_prefix, EXC_UD, -1);
            goto test;
        case 2: /* not */
            dst.val = ~dst.val;
            break;
        case 3: /* neg */
            emulate_1op("neg", dst, _regs.eflags);
            break;
        case 4: /* mul */
            dst.reg = (unsigned long *)&_regs.eax;
            _regs.eflags &= ~(EFLG_OF|EFLG_CF);
            switch ( dst.bytes )
            {
            case 1:
                dst.val = (uint8_t)_regs.eax;
                dst.val *= src.val;
                if ( (uint8_t)dst.val != (uint16_t)dst.val )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                dst.bytes = 2;
                break;
            case 2:
                dst.val = (uint16_t)_regs.eax;
                dst.val *= src.val;
                if ( (uint16_t)dst.val != (uint32_t)dst.val )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                *(uint16_t *)&_regs.edx = dst.val >> 16;
                break;
#ifdef __x86_64__
            case 4:
                dst.val = _regs._eax;
                dst.val *= src.val;
                if ( (uint32_t)dst.val != dst.val )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                _regs.edx = (uint32_t)(dst.val >> 32);
                break;
#endif
            default:
                u[0] = src.val;
                u[1] = _regs.eax;
                if ( mul_dbl(u) )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                _regs.edx = u[1];
                dst.val  = u[0];
                break;
            }
            break;
        case 5: /* imul */
            dst.reg = (unsigned long *)&_regs.eax;
        imul:
            _regs.eflags &= ~(EFLG_OF|EFLG_CF);
            switch ( dst.bytes )
            {
            case 1:
                dst.val = (int8_t)src.val * (int8_t)_regs.eax;
                if ( (int8_t)dst.val != (int16_t)dst.val )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                ASSERT(b > 0x6b);
                dst.bytes = 2;
                break;
            case 2:
                dst.val = ((uint32_t)(int16_t)src.val *
                           (uint32_t)(int16_t)_regs.eax);
                if ( (int16_t)dst.val != (int32_t)dst.val )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                if ( b > 0x6b )
                    *(uint16_t *)&_regs.edx = dst.val >> 16;
                break;
#ifdef __x86_64__
            case 4:
                dst.val = ((uint64_t)(int32_t)src.val *
                           (uint64_t)(int32_t)_regs.eax);
                if ( (int32_t)dst.val != dst.val )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                if ( b > 0x6b )
                    _regs.edx = (uint32_t)(dst.val >> 32);
                break;
#endif
            default:
                u[0] = src.val;
                u[1] = _regs.eax;
                if ( imul_dbl(u) )
                    _regs.eflags |= EFLG_OF|EFLG_CF;
                if ( b > 0x6b )
                    _regs.edx = u[1];
                dst.val  = u[0];
                break;
            }
            break;
        case 6: /* div */
            dst.reg = (unsigned long *)&_regs.eax;
            switch ( src.bytes )
            {
            case 1:
                u[0] = (uint16_t)_regs.eax;
                u[1] = 0;
                v    = (uint8_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint8_t)u[0] != (uint16_t)u[0]),
                    EXC_DE, -1);
                dst.val = (uint8_t)u[0];
                ((uint8_t *)&_regs.eax)[1] = u[1];
                break;
            case 2:
                u[0] = ((uint32_t)_regs.edx << 16) | (uint16_t)_regs.eax;
                u[1] = 0;
                v    = (uint16_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint16_t)u[0] != (uint32_t)u[0]),
                    EXC_DE, -1);
                dst.val = (uint16_t)u[0];
                *(uint16_t *)&_regs.edx = u[1];
                break;
#ifdef __x86_64__
            case 4:
                u[0] = (_regs.edx << 32) | (uint32_t)_regs.eax;
                u[1] = 0;
                v    = (uint32_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint32_t)u[0] != u[0]),
                    EXC_DE, -1);
                dst.val   = (uint32_t)u[0];
                _regs.edx = (uint32_t)u[1];
                break;
#endif
            default:
                u[0] = _regs.eax;
                u[1] = _regs.edx;
                v    = src.val;
                generate_exception_if(div_dbl(u, v), EXC_DE, -1);
                dst.val   = u[0];
                _regs.edx = u[1];
                break;
            }
            break;
        case 7: /* idiv */
            dst.reg = (unsigned long *)&_regs.eax;
            switch ( src.bytes )
            {
            case 1:
                u[0] = (int16_t)_regs.eax;
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int8_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int8_t)u[0] != (int16_t)u[0]),
                    EXC_DE, -1);
                dst.val = (int8_t)u[0];
                ((int8_t *)&_regs.eax)[1] = u[1];
                break;
            case 2:
                u[0] = (int32_t)((_regs.edx << 16) | (uint16_t)_regs.eax);
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int16_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int16_t)u[0] != (int32_t)u[0]),
                    EXC_DE, -1);
                dst.val = (int16_t)u[0];
                *(int16_t *)&_regs.edx = u[1];
                break;
#ifdef __x86_64__
            case 4:
                u[0] = (_regs.edx << 32) | (uint32_t)_regs.eax;
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int32_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int32_t)u[0] != u[0]),
                    EXC_DE, -1);
                dst.val   = (int32_t)u[0];
                _regs.edx = (uint32_t)u[1];
                break;
#endif
            default:
                u[0] = _regs.eax;
                u[1] = _regs.edx;
                v    = src.val;
                generate_exception_if(idiv_dbl(u, v), EXC_DE, -1);
                dst.val   = u[0];
                _regs.edx = u[1];
                break;
            }
            break;
        }
        break;

    case 0xf8: /* clc */
        _regs.eflags &= ~EFLG_CF;
        break;

    case 0xf9: /* stc */
        _regs.eflags |= EFLG_CF;
        break;

    case 0xfa: /* cli */
        generate_exception_if(!mode_iopl(), EXC_GP, 0);
        _regs.eflags &= ~EFLG_IF;
        break;

    case 0xfb: /* sti */
        generate_exception_if(!mode_iopl(), EXC_GP, 0);
        if ( !(_regs.eflags & EFLG_IF) )
        {
            _regs.eflags |= EFLG_IF;
            ctxt->retire.flags.sti = 1;
        }
        break;

    case 0xfc: /* cld */
        _regs.eflags &= ~EFLG_DF;
        break;

    case 0xfd: /* std */
        _regs.eflags |= EFLG_DF;
        break;

    case 0xfe: /* Grp4 */
        generate_exception_if((modrm_reg & 7) >= 2, EXC_UD, -1);
    case 0xff: /* Grp5 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* inc */
            emulate_1op("inc", dst, _regs.eflags);
            break;
        case 1: /* dec */
            emulate_1op("dec", dst, _regs.eflags);
            break;
        case 2: /* call (near) */
            dst.val = _regs.eip;
            if ( (rc = ops->insn_fetch(x86_seg_cs, src.val, NULL, 0, ctxt)) )
                goto done;
            _regs.eip = src.val;
            src.val = dst.val;
            goto push;
        case 4: /* jmp (near) */
            if ( (rc = ops->insn_fetch(x86_seg_cs, src.val, NULL, 0, ctxt)) )
                goto done;
            _regs.eip = src.val;
            dst.type = OP_NONE;
            break;
        case 3: /* call (far, absolute indirect) */
        case 5: /* jmp (far, absolute indirect) */
            generate_exception_if(src.type != OP_MEM, EXC_UD, -1);

            if ( (rc = read_ulong(src.mem.seg, src.mem.off + op_bytes,
                                  &imm2, 2, ctxt, ops)) )
                goto done;
            imm1 = src.val;
            if ( !(modrm_reg & 4) )
                goto far_call;
            goto far_jmp;
        case 6: /* push */
            goto push;
        case 7:
            generate_exception_if(1, EXC_UD, -1);
        }
        break;

    case X86EMUL_OPC(0x0f, 0x00): /* Grp6 */
        seg = (modrm_reg & 1) ? x86_seg_tr : x86_seg_ldtr;
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD, -1);
        switch ( modrm_reg & 6 )
        {
        case 0: /* sldt / str */
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            goto store_selector;
        case 2: /* lldt / ltr */
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            if ( (rc = load_seg(seg, src.val, 0, NULL, ctxt, ops)) != 0 )
                goto done;
            break;
        default:
            generate_exception_if(true, EXC_UD, -1);
            break;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01): /* Grp7 */ {
        unsigned long base, limit, cr0, cr0w;

        switch( modrm )
        {
#ifdef __XEN__
        case 0xd1: /* xsetbv */
        {
            unsigned long cr4;

            generate_exception_if(vex.pfx, EXC_UD, -1);
            if ( !ops->read_cr || ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), EXC_UD, -1);
            generate_exception_if(!mode_ring0() ||
                                  handle_xsetbv(_regs._ecx,
                                                _regs._eax | (_regs.rdx << 32)),
                                  EXC_GP, 0);
            goto no_writeback;
        }
#endif

        case 0xd4: /* vmfunc */
            generate_exception_if(lock_prefix | rep_prefix() | (vex.pfx == vex_66),
                                  EXC_UD, -1);
            fail_if(!ops->vmfunc);
            if ( (rc = ops->vmfunc(ctxt) != X86EMUL_OKAY) )
                goto done;
            goto no_writeback;

        case 0xd5: /* xend */
            generate_exception_if(vex.pfx, EXC_UD, -1);
            generate_exception_if(!vcpu_has_rtm(), EXC_UD, -1);
            generate_exception_if(vcpu_has_rtm(), EXC_GP, 0);
            break;

        case 0xd6: /* xtest */
            generate_exception_if(vex.pfx, EXC_UD, -1);
            generate_exception_if(!vcpu_has_rtm() && !vcpu_has_hle(),
                                  EXC_UD, -1);
            /* Neither HLE nor RTM can be active when we get here. */
            _regs.eflags |= EFLG_ZF;
            goto no_writeback;

        case 0xdf: /* invlpga */
            generate_exception_if(!in_protmode(ctxt, ops), EXC_UD, -1);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(ops->invlpg == NULL);
            if ( (rc = ops->invlpg(x86_seg_none, truncate_ea(_regs.eax),
                                   ctxt)) )
                goto done;
            goto no_writeback;

        case 0xf9: /* rdtscp */
        {
            uint64_t tsc_aux;
            fail_if(ops->read_msr == NULL);
            if ( (rc = ops->read_msr(MSR_TSC_AUX, &tsc_aux, ctxt)) != 0 )
                goto done;
            _regs.ecx = (uint32_t)tsc_aux;
            goto rdtsc;
        }

        case 0xfc: /* clzero */
        {
            unsigned int eax = 1, ebx = 0, dummy = 0;
            unsigned long zero = 0;

            base = ad_bytes == 8 ? _regs.eax :
                   ad_bytes == 4 ? (uint32_t)_regs.eax : (uint16_t)_regs.eax;
            limit = 0;
            if ( vcpu_has_clflush() &&
                 ops->cpuid(&eax, &ebx, &dummy, &dummy, ctxt) == X86EMUL_OKAY )
                limit = ((ebx >> 8) & 0xff) * 8;
            generate_exception_if(limit < sizeof(long) ||
                                  (limit & (limit - 1)), EXC_UD, -1);
            base &= ~(limit - 1);
            if ( override_seg == -1 )
                override_seg = x86_seg_ds;
            if ( ops->rep_stos )
            {
                unsigned long nr_reps = limit / sizeof(zero);

                rc = ops->rep_stos(&zero, override_seg, base, sizeof(zero),
                                   &nr_reps, ctxt);
                if ( rc == X86EMUL_OKAY )
                {
                    base += nr_reps * sizeof(zero);
                    limit -= nr_reps * sizeof(zero);
                }
                else if ( rc != X86EMUL_UNHANDLEABLE )
                    goto done;
            }
            while ( limit )
            {
                rc = ops->write(override_seg, base, &zero, sizeof(zero), ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
                base += sizeof(zero);
                limit -= sizeof(zero);
            }
            goto no_writeback;
        }
        }

        seg = (modrm_reg & 1) ? x86_seg_idtr : x86_seg_gdtr;

        switch ( modrm_reg & 7 )
        {
        case 0: /* sgdt */
        case 1: /* sidt */
            generate_exception_if(ea.type != OP_MEM, EXC_UD, -1);
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            fail_if(ops->read_segment == NULL);
            if ( (rc = ops->read_segment(seg, &sreg, ctxt)) )
                goto done;
            if ( mode_64bit() )
                op_bytes = 8;
            else if ( op_bytes == 2 )
            {
                sreg.base &= 0xffffff;
                op_bytes = 4;
            }
            if ( (rc = ops->write(ea.mem.seg, ea.mem.off, &sreg.limit,
                                  2, ctxt)) != X86EMUL_OKAY ||
                 (rc = ops->write(ea.mem.seg, ea.mem.off + 2, &sreg.base,
                                  op_bytes, ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
        case 2: /* lgdt */
        case 3: /* lidt */
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            generate_exception_if(ea.type != OP_MEM, EXC_UD, -1);
            fail_if(ops->write_segment == NULL);
            memset(&sreg, 0, sizeof(sreg));
            if ( (rc = read_ulong(ea.mem.seg, ea.mem.off+0,
                                  &limit, 2, ctxt, ops)) ||
                 (rc = read_ulong(ea.mem.seg, ea.mem.off+2,
                                  &base, mode_64bit() ? 8 : 4, ctxt, ops)) )
                goto done;
            generate_exception_if(!is_canonical_address(base), EXC_GP, 0);
            sreg.base = base;
            sreg.limit = limit;
            if ( !mode_64bit() && op_bytes == 2 )
                sreg.base &= 0xffffff;
            if ( (rc = ops->write_segment(seg, &sreg, ctxt)) )
                goto done;
            break;
        case 4: /* smsw */
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            ea.bytes = (ea.type == OP_MEM) ? 2 : op_bytes;
            dst = ea;
            fail_if(ops->read_cr == NULL);
            if ( (rc = ops->read_cr(0, &dst.val, ctxt)) )
                goto done;
            d |= Mov; /* force writeback */
            break;
        case 6: /* lmsw */
            fail_if(ops->read_cr == NULL);
            fail_if(ops->write_cr == NULL);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            if ( (rc = ops->read_cr(0, &cr0, ctxt)) )
                goto done;
            if ( ea.type == OP_REG )
                cr0w = *ea.reg;
            else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                       &cr0w, 2, ctxt, ops)) )
                goto done;
            /* LMSW can: (1) set bits 0-3; (2) clear bits 1-3. */
            cr0 = (cr0 & ~0xe) | (cr0w & 0xf);
            if ( (rc = ops->write_cr(0, cr0, ctxt)) )
                goto done;
            break;
        case 7: /* invlpg */
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            generate_exception_if(ea.type != OP_MEM, EXC_UD, -1);
            fail_if(ops->invlpg == NULL);
            if ( (rc = ops->invlpg(ea.mem.seg, ea.mem.off, ctxt)) )
                goto done;
            break;
        default:
            goto cannot_emulate;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0x05): /* syscall */ {
        uint64_t msr_content;

        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD, -1);

        /* Inject #UD if syscall/sysret are disabled. */
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_EFER, &msr_content, ctxt)) != 0 )
            goto done;
        generate_exception_if((msr_content & EFER_SCE) == 0, EXC_UD, -1);

        if ( (rc = ops->read_msr(MSR_STAR, &msr_content, ctxt)) != 0 )
            goto done;

        cs.sel = (msr_content >> 32) & ~3; /* SELECTOR_RPL_MASK */
        sreg.sel = cs.sel + 8;

        cs.base = sreg.base = 0; /* flat segment */
        cs.limit = sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr.bytes = 0xc93; /* G+DB+P+S+Data */

#ifdef __x86_64__
        rc = in_longmode(ctxt, ops);
        if ( rc < 0 )
            goto cannot_emulate;
        if ( rc )
        {
            cs.attr.bytes = 0xa9b; /* L+DB+P+S+Code */

            _regs.rcx = _regs.rip;
            _regs.r11 = _regs.eflags & ~EFLG_RF;

            if ( (rc = ops->read_msr(mode_64bit() ? MSR_LSTAR : MSR_CSTAR,
                                     &msr_content, ctxt)) != 0 )
                goto done;
            _regs.rip = msr_content;

            if ( (rc = ops->read_msr(MSR_FMASK, &msr_content, ctxt)) != 0 )
                goto done;
            _regs.eflags &= ~(msr_content | EFLG_RF);
        }
        else
#endif
        {
            cs.attr.bytes = 0xc9b; /* G+DB+P+S+Code */

            _regs.ecx = (uint32_t)_regs.eip;
            _regs.eip = (uint32_t)msr_content;
            _regs.eflags &= ~(EFLG_VM | EFLG_IF | EFLG_RF);
        }

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) )
            goto done;

        /*
         * SYSCALL (unlike most instructions) evaluates its singlestep action
         * based on the resulting EFLG_TF, not the starting EFLG_TF.
         *
         * As the #DB is raised after the CPL change and before the OS can
         * switch stack, it is a large risk for privilege escalation.
         *
         * 64bit kernels should mask EFLG_TF in MSR_FMASK to avoid any
         * vulnerability.  Running the #DB handler on an IST stack is also a
         * mitigation.
         *
         * 32bit kernels have no ability to mask EFLG_TF at all.  Their only
         * mitigation is to use a task gate for handling #DB (or to not use
         * enable EFER.SCE to start with).
         */
        tf = _regs.eflags & EFLG_TF;

        break;
    }

    case X86EMUL_OPC(0x0f, 0x06): /* clts */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if((ops->read_cr == NULL) || (ops->write_cr == NULL));
        if ( (rc = ops->read_cr(0, &dst.val, ctxt)) ||
             (rc = ops->write_cr(0, dst.val&~8, ctxt)) )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x08): /* invd */
    case X86EMUL_OPC(0x0f, 0x09): /* wbinvd */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->wbinvd == NULL);
        if ( (rc = ops->wbinvd(ctxt)) != 0 )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x0b): /* ud2 */
    case X86EMUL_OPC(0x0f, 0xb9): /* ud1 */
    case X86EMUL_OPC(0x0f, 0xff): /* ud0 */
        generate_exception_if(1, EXC_UD, -1);

    case X86EMUL_OPC(0x0f, 0x0d): /* GrpP (prefetch) */
    case X86EMUL_OPC(0x0f, 0x18): /* Grp16 (prefetch/nop) */
    case X86EMUL_OPC(0x0f, 0x19) ... X86EMUL_OPC(0x0f, 0x1f): /* nop */
        break;

    case X86EMUL_OPC(0x0f, 0x2b):        /* movntps xmm,m128 */
    case X86EMUL_OPC_VEX(0x0f, 0x2b):    /* vmovntps xmm,m128 */
                                         /* vmovntps ymm,m256 */
    case X86EMUL_OPC_66(0x0f, 0x2b):     /* movntpd xmm,m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x2b): /* vmovntpd xmm,m128 */
                                         /* vmovntpd ymm,m256 */
        fail_if(ea.type != OP_MEM);
        /* fall through */
    case X86EMUL_OPC(0x0f, 0x28):        /* movaps xmm/m128,xmm */
    case X86EMUL_OPC_VEX(0x0f, 0x28):    /* vmovaps xmm/m128,xmm */
                                         /* vmovaps ymm/m256,ymm */
    case X86EMUL_OPC_66(0x0f, 0x28):     /* movapd xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x28): /* vmovapd xmm/m128,xmm */
                                         /* vmovapd ymm/m256,ymm */
    case X86EMUL_OPC(0x0f, 0x29):        /* movaps xmm,xmm/m128 */
    case X86EMUL_OPC_VEX(0x0f, 0x29):    /* vmovaps xmm,xmm/m128 */
                                         /* vmovaps ymm,ymm/m256 */
    case X86EMUL_OPC_66(0x0f, 0x29):     /* movapd xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x29): /* vmovapd xmm,xmm/m128 */
                                         /* vmovapd ymm,ymm/m256 */
    case X86EMUL_OPC(0x0f, 0x10):        /* movups xmm/m128,xmm */
    case X86EMUL_OPC_VEX(0x0f, 0x10):    /* vmovups xmm/m128,xmm */
                                         /* vmovups ymm/m256,ymm */
    case X86EMUL_OPC_66(0x0f, 0x10):     /* movupd xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x10): /* vmovupd xmm/m128,xmm */
                                         /* vmovupd ymm/m256,ymm */
    case X86EMUL_OPC_F3(0x0f, 0x10):     /* movss xmm/m32,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x10): /* vmovss xmm/m32,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x10):     /* movsd xmm/m64,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x10): /* vmovsd xmm/m64,xmm */
    case X86EMUL_OPC(0x0f, 0x11):        /* movups xmm,xmm/m128 */
    case X86EMUL_OPC_VEX(0x0f, 0x11):    /* vmovups xmm,xmm/m128 */
                                         /* vmovups ymm,ymm/m256 */
    case X86EMUL_OPC_66(0x0f, 0x11):     /* movupd xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x11): /* vmovupd xmm,xmm/m128 */
                                         /* vmovupd ymm,ymm/m256 */
    case X86EMUL_OPC_F3(0x0f, 0x11):     /* movss xmm,xmm/m32 */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x11): /* vmovss xmm,xmm/m32 */
    case X86EMUL_OPC_F2(0x0f, 0x11):     /* movsd xmm,xmm/m64 */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x11): /* vmovsd xmm,xmm/m64 */
    {
        uint8_t *buf = get_stub(stub);
        struct fpu_insn_ctxt fic = { .insn_bytes = 5 };

        buf[0] = 0x3e;
        buf[1] = 0x3e;
        buf[2] = 0x0f;
        buf[3] = b;
        buf[4] = modrm;
        buf[5] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                host_and_vcpu_must_have(sse2);
            else
                host_and_vcpu_must_have(sse);
            ea.bytes = 16;
            SET_SSE_PREFIX(buf[0], vex.pfx);
            get_fpu(X86EMUL_FPU_xmm, &fic);
        }
        else
        {
            fail_if((vex.reg != 0xf) &&
                    ((ea.type == OP_MEM) ||
                     !(vex.pfx & VEX_PREFIX_SCALAR_MASK)));
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm, &fic);
            ea.bytes = 16 << vex.l;
        }
        if ( vex.pfx & VEX_PREFIX_SCALAR_MASK )
            ea.bytes = vex.pfx & VEX_PREFIX_DOUBLE_MASK ? 8 : 4;
        if ( ea.type == OP_MEM )
        {
            uint32_t mxcsr = 0;

            if ( b < 0x28 )
                mxcsr = MXCSR_MM;
            else if ( vcpu_has_misalignsse() )
                asm ( "stmxcsr %0" : "=m" (mxcsr) );
            generate_exception_if(!(mxcsr & MXCSR_MM) &&
                                  !is_aligned(ea.mem.seg, ea.mem.off, ea.bytes,
                                              ctxt, ops),
                                  EXC_GP, 0);
            if ( !(b & 1) )
                rc = ops->read(ea.mem.seg, ea.mem.off+0, mmvalp,
                               ea.bytes, ctxt);
            /* convert memory operand to (%rAX) */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            buf[4] &= 0x38;
        }
        if ( !rc )
        {
           copy_REX_VEX(buf, rex_prefix, vex);
           asm volatile ( "call *%0" : : "r" (stub.func), "a" (mmvalp)
                                     : "memory" );
        }
        put_fpu(&fic);
        put_stub(stub);
        if ( !rc && (b & 1) && (ea.type == OP_MEM) )
            rc = ops->write(ea.mem.seg, ea.mem.off, mmvalp,
                            ea.bytes, ctxt);
        if ( rc )
            goto done;
        dst.type = OP_NONE;
        break;
    }

    case X86EMUL_OPC(0x0f, 0x20): /* mov cr,reg */
    case X86EMUL_OPC(0x0f, 0x21): /* mov dr,reg */
    case X86EMUL_OPC(0x0f, 0x22): /* mov reg,cr */
    case X86EMUL_OPC(0x0f, 0x23): /* mov reg,dr */
        generate_exception_if(ea.type != OP_REG, EXC_UD, -1);
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        modrm_reg |= lock_prefix << 3;
        if ( b & 2 )
        {
            /* Write to CR/DR. */
            src.val = *(unsigned long *)decode_register(modrm_rm, &_regs, 0);
            if ( !mode_64bit() )
                src.val = (uint32_t)src.val;
            rc = ((b & 1)
                  ? (ops->write_dr
                     ? ops->write_dr(modrm_reg, src.val, ctxt)
                     : X86EMUL_UNHANDLEABLE)
                  : (ops->write_cr
                     ? ops->write_cr(modrm_reg, src.val, ctxt)
                     : X86EMUL_UNHANDLEABLE));
        }
        else
        {
            /* Read from CR/DR. */
            dst.type  = OP_REG;
            dst.bytes = mode_64bit() ? 8 : 4;
            dst.reg   = decode_register(modrm_rm, &_regs, 0);
            rc = ((b & 1)
                  ? (ops->read_dr
                     ? ops->read_dr(modrm_reg, &dst.val, ctxt)
                     : X86EMUL_UNHANDLEABLE)
                  : (ops->read_cr
                     ? ops->read_cr(modrm_reg, &dst.val, ctxt)
                     : X86EMUL_UNHANDLEABLE));
        }
        if ( rc != 0 )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x30): /* wrmsr */ {
        uint64_t val = ((uint64_t)_regs.edx << 32) | (uint32_t)_regs.eax;
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->write_msr == NULL);
        if ( (rc = ops->write_msr((uint32_t)_regs.ecx, val, ctxt)) != 0 )
            goto done;
        break;
    }

    case X86EMUL_OPC(0x0f, 0x31): rdtsc: /* rdtsc */ {
        unsigned long cr4;
        uint64_t val;
        if ( !mode_ring0() )
        {
            fail_if(ops->read_cr == NULL);
            if ( (rc = ops->read_cr(4, &cr4, ctxt)) )
                goto done;
            generate_exception_if(cr4 & CR4_TSD, EXC_GP, 0);
        }
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_TSC, &val, ctxt)) != 0 )
            goto done;
        _regs.edx = (uint32_t)(val >> 32);
        _regs.eax = (uint32_t)(val >>  0);
        break;
    }

    case X86EMUL_OPC(0x0f, 0x32): /* rdmsr */ {
        uint64_t val;
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr((uint32_t)_regs.ecx, &val, ctxt)) != 0 )
            goto done;
        _regs.edx = (uint32_t)(val >> 32);
        _regs.eax = (uint32_t)(val >>  0);
        break;
    }

    case X86EMUL_OPC(0x0f, 0x40) ... X86EMUL_OPC(0x0f, 0x4f): /* cmovcc */
        vcpu_must_have_cmov();
        if ( test_cc(b, _regs.eflags) )
            dst.val = src.val;
        break;

    case X86EMUL_OPC(0x0f, 0x34): /* sysenter */ {
        uint64_t msr_content;
        int lm;

        generate_exception_if(mode_ring0(), EXC_GP, 0);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);

        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_SYSENTER_CS, &msr_content, ctxt)) != 0 )
            goto done;

        generate_exception_if(!(msr_content & 0xfffc), EXC_GP, 0);
        lm = in_longmode(ctxt, ops);
        if ( lm < 0 )
            goto cannot_emulate;

        _regs.eflags &= ~(EFLG_VM | EFLG_IF | EFLG_RF);

        fail_if(ops->read_segment == NULL);
        ops->read_segment(x86_seg_cs, &cs, ctxt);
        cs.sel = msr_content & ~3; /* SELECTOR_RPL_MASK */
        cs.base = 0;   /* flat segment */
        cs.limit = ~0u;  /* 4GB limit */
        cs.attr.bytes = lm ? 0xa9b  /* L+DB+P+S+Code */
                           : 0xc9b; /* G+DB+P+S+Code */

        sreg.sel = cs.sel + 8;
        sreg.base = 0;   /* flat segment */
        sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr.bytes = 0xc93; /* G+DB+P+S+Data */

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) != 0 ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) != 0 )
            goto done;

        if ( (rc = ops->read_msr(MSR_SYSENTER_EIP, &msr_content, ctxt)) != 0 )
            goto done;
        _regs.eip = lm ? msr_content : (uint32_t)msr_content;

        if ( (rc = ops->read_msr(MSR_SYSENTER_ESP, &msr_content, ctxt)) != 0 )
            goto done;
        _regs.esp = lm ? msr_content : (uint32_t)msr_content;

        break;
    }

    case X86EMUL_OPC(0x0f, 0x35): /* sysexit */ {
        uint64_t msr_content;
        bool_t user64 = !!(rex_prefix & REX_W);

        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);

        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_SYSENTER_CS, &msr_content, ctxt)) != 0 )
            goto done;

        generate_exception_if(!(msr_content & 0xfffc), EXC_GP, 0);
        generate_exception_if(user64 && (!is_canonical_address(_regs.edx) ||
                                         !is_canonical_address(_regs.ecx)),
                              EXC_GP, 0);

        cs.sel = (msr_content | 3) + /* SELECTOR_RPL_MASK */
                 (user64 ? 32 : 16);
        cs.base = 0;   /* flat segment */
        cs.limit = ~0u;  /* 4GB limit */
        cs.attr.bytes = user64 ? 0xafb  /* L+DB+P+DPL3+S+Code */
                               : 0xcfb; /* G+DB+P+DPL3+S+Code */

        sreg.sel = cs.sel + 8;
        sreg.base = 0;   /* flat segment */
        sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr.bytes = 0xcf3; /* G+DB+P+DPL3+S+Data */

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) != 0 ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) != 0 )
            goto done;

        _regs.eip = user64 ? _regs.edx : (uint32_t)_regs.edx;
        _regs.esp = user64 ? _regs.ecx : (uint32_t)_regs.ecx;
        break;
    }

    case X86EMUL_OPC(0x0f, 0xe7):        /* movntq mm,m64 */
    case X86EMUL_OPC_66(0x0f, 0xe7):     /* movntdq xmm,m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe7): /* vmovntdq xmm,m128 */
                                         /* vmovntdq ymm,m256 */
        fail_if(ea.type != OP_MEM);
        /* fall through */
    case X86EMUL_OPC(0x0f, 0x6f):        /* movq mm/m64,mm */
    case X86EMUL_OPC_66(0x0f, 0x6f):     /* movdqa xmm/m128,xmm */
    case X86EMUL_OPC_F3(0x0f, 0x6f):     /* movdqu xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6f): /* vmovdqa xmm/m128,xmm */
                                         /* vmovdqa ymm/m256,ymm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x6f): /* vmovdqu xmm/m128,xmm */
                                         /* vmovdqu ymm/m256,ymm */
    case X86EMUL_OPC(0x0f, 0x7e):        /* movd mm,r/m32 */
                                         /* movq mm,r/m64 */
    case X86EMUL_OPC_66(0x0f, 0x7e):     /* movd xmm,r/m32 */
                                         /* movq xmm,r/m64 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7e): /* vmovd xmm,r/m32 */
                                         /* vmovq xmm,r/m64 */
    case X86EMUL_OPC(0x0f, 0x7f):        /* movq mm,mm/m64 */
    case X86EMUL_OPC_66(0x0f, 0x7f):     /* movdqa xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7f): /* vmovdqa xmm,xmm/m128 */
                                         /* vmovdqa ymm,ymm/m256 */
    case X86EMUL_OPC_F3(0x0f, 0x7f):     /* movdqu xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x7f): /* vmovdqu xmm,xmm/m128 */
                                         /* vmovdqu ymm,ymm/m256 */
    case X86EMUL_OPC_66(0x0f, 0xd6):     /* movq xmm,xmm/m64 */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd6): /* vmovq xmm,xmm/m64 */
    {
        uint8_t *buf = get_stub(stub);
        struct fpu_insn_ctxt fic = { .insn_bytes = 5 };

        buf[0] = 0x3e;
        buf[1] = 0x3e;
        buf[2] = 0x0f;
        buf[3] = b;
        buf[4] = modrm;
        buf[5] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            switch ( vex.pfx )
            {
            case vex_66:
            case vex_f3:
                host_and_vcpu_must_have(sse2);
                /* Converting movdqu to movdqa here: Our buffer is aligned. */
                buf[0] = 0x66;
                get_fpu(X86EMUL_FPU_xmm, &fic);
                ea.bytes = 16;
                break;
            case vex_none:
                if ( b != 0xe7 )
                    host_and_vcpu_must_have(mmx);
                else
                    host_and_vcpu_must_have(sse);
                get_fpu(X86EMUL_FPU_mmx, &fic);
                ea.bytes = 8;
                break;
            default:
                goto cannot_emulate;
            }
        }
        else
        {
            fail_if(vex.reg != 0xf);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm, &fic);
            ea.bytes = 16 << vex.l;
        }
        switch ( b )
        {
        case 0x7e:
            generate_exception_if(vex.l, EXC_UD, -1);
            ea.bytes = op_bytes;
            break;
        case 0xd6:
            generate_exception_if(vex.l, EXC_UD, -1);
            ea.bytes = 8;
            break;
        }
        if ( ea.type == OP_MEM )
        {
            uint32_t mxcsr = 0;

            if ( ea.bytes < 16 || vex.pfx == vex_f3 )
                mxcsr = MXCSR_MM;
            else if ( vcpu_has_misalignsse() )
                asm ( "stmxcsr %0" : "=m" (mxcsr) );
            generate_exception_if(!(mxcsr & MXCSR_MM) &&
                                  !is_aligned(ea.mem.seg, ea.mem.off, ea.bytes,
                                              ctxt, ops),
                                  EXC_GP, 0);
            if ( b == 0x6f )
                rc = ops->read(ea.mem.seg, ea.mem.off+0, mmvalp,
                               ea.bytes, ctxt);
        }
        if ( ea.type == OP_MEM || b == 0x7e )
        {
            /* Convert memory operand or GPR destination to (%rAX) */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            buf[4] &= 0x38;
            if ( ea.type == OP_MEM )
                ea.reg = (void *)mmvalp;
            else /* Ensure zero-extension of a 32-bit result. */
                *ea.reg = 0;
        }
        if ( !rc )
        {
           copy_REX_VEX(buf, rex_prefix, vex);
           asm volatile ( "call *%0" : : "r" (stub.func), "a" (ea.reg)
                                     : "memory" );
        }
        put_fpu(&fic);
        put_stub(stub);
        if ( !rc && (b != 0x6f) && (ea.type == OP_MEM) )
            rc = ops->write(ea.mem.seg, ea.mem.off, mmvalp,
                            ea.bytes, ctxt);
        if ( rc )
            goto done;
        dst.type = OP_NONE;
        break;
    }

    case X86EMUL_OPC(0x0f, 0x80) ... X86EMUL_OPC(0x0f, 0x8f): /* jcc (near) */
        if ( test_cc(b, _regs.eflags) )
            jmp_rel((int32_t)src.val);
        break;

    case X86EMUL_OPC(0x0f, 0x90) ... X86EMUL_OPC(0x0f, 0x9f): /* setcc */
        dst.val = test_cc(b, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xa0): /* push %%fs */
        src.val = x86_seg_fs;
        goto push_seg;

    case X86EMUL_OPC(0x0f, 0xa1): /* pop %%fs */
        src.val = x86_seg_fs;
        goto pop_seg;

    case X86EMUL_OPC(0x0f, 0xa2): /* cpuid */ {
        unsigned int eax = _regs.eax, ebx = _regs.ebx;
        unsigned int ecx = _regs.ecx, edx = _regs.edx;
        fail_if(ops->cpuid == NULL);
        rc = ops->cpuid(&eax, &ebx, &ecx, &edx, ctxt);
        generate_exception_if(rc == X86EMUL_EXCEPTION,
                              EXC_GP, 0); /* CPUID Faulting? */
        if ( rc != X86EMUL_OKAY )
            goto done;
        _regs.eax = eax; _regs.ebx = ebx;
        _regs.ecx = ecx; _regs.edx = edx;
        break;
    }

    case X86EMUL_OPC(0x0f, 0xa3): bt: /* bt */
        emulate_2op_SrcV_nobyte("bt", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0xa4): /* shld imm8,r,r/m */
    case X86EMUL_OPC(0x0f, 0xa5): /* shld %%cl,r,r/m */
    case X86EMUL_OPC(0x0f, 0xac): /* shrd imm8,r,r/m */
    case X86EMUL_OPC(0x0f, 0xad): /* shrd %%cl,r,r/m */ {
        uint8_t shift, width = dst.bytes << 3;

        generate_exception_if(lock_prefix, EXC_UD, -1);
        if ( b & 1 )
            shift = _regs.ecx;
        else
        {
            shift = src.val;
            src.reg = decode_register(modrm_reg, &_regs, 0);
            src.val = truncate_word(*src.reg, dst.bytes);
        }
        if ( (shift &= width - 1) == 0 )
            break;
        dst.orig_val = truncate_word(dst.val, dst.bytes);
        dst.val = ((shift == width) ? src.val :
                   (b & 8) ?
                   /* shrd */
                   ((dst.orig_val >> shift) |
                    truncate_word(src.val << (width - shift), dst.bytes)) :
                   /* shld */
                   ((dst.orig_val << shift) |
                    ((src.val >> (width - shift)) & ((1ull << shift) - 1))));
        dst.val = truncate_word(dst.val, dst.bytes);
        _regs.eflags &= ~(EFLG_OF|EFLG_SF|EFLG_ZF|EFLG_PF|EFLG_CF);
        if ( (dst.val >> ((b & 8) ? (shift - 1) : (width - shift))) & 1 )
            _regs.eflags |= EFLG_CF;
        if ( ((dst.val ^ dst.orig_val) >> (width - 1)) & 1 )
            _regs.eflags |= EFLG_OF;
        _regs.eflags |= ((dst.val >> (width - 1)) & 1) ? EFLG_SF : 0;
        _regs.eflags |= (dst.val == 0) ? EFLG_ZF : 0;
        _regs.eflags |= even_parity(dst.val) ? EFLG_PF : 0;
        break;
    }

    case X86EMUL_OPC(0x0f, 0xa8): /* push %%gs */
        src.val = x86_seg_gs;
        goto push_seg;

    case X86EMUL_OPC(0x0f, 0xa9): /* pop %%gs */
        src.val = x86_seg_gs;
        goto pop_seg;

    case X86EMUL_OPC(0x0f, 0xab): bts: /* bts */
        emulate_2op_SrcV_nobyte("bts", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xae): case X86EMUL_OPC_66(0x0f, 0xae): /* Grp15 */
        switch ( modrm_reg & 7 )
        {
        case 7: /* clflush{,opt} */
            fail_if(modrm_mod == 3);
            fail_if(ops->wbinvd == NULL);
            if ( (rc = ops->wbinvd(ctxt)) != 0 )
                goto done;
            break;
        default:
            goto cannot_emulate;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xaf): /* imul */
        emulate_2op_SrcV_srcmem("imul", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xb0): case X86EMUL_OPC(0x0f, 0xb1): /* cmpxchg */
        /* Save real source value, then compare EAX against destination. */
        src.orig_val = src.val;
        src.val = _regs.eax;
        /* cmp: %%eax - dst ==> dst and src swapped for macro invocation */
        emulate_2op_SrcV("cmp", dst, src, _regs.eflags);
        if ( _regs.eflags & EFLG_ZF )
        {
            /* Success: write back to memory. */
            dst.val = src.orig_val;
        }
        else
        {
            /* Failure: write the value we saw to EAX. */
            dst.type = OP_REG;
            dst.reg  = (unsigned long *)&_regs.eax;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xb2): /* lss */
        dst.val = x86_seg_ss;
        goto les;

    case X86EMUL_OPC(0x0f, 0xb3): btr: /* btr */
        emulate_2op_SrcV_nobyte("btr", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xb4): /* lfs */
        dst.val = x86_seg_fs;
        goto les;

    case X86EMUL_OPC(0x0f, 0xb5): /* lgs */
        dst.val = x86_seg_gs;
        goto les;

    case X86EMUL_OPC(0x0f, 0xb6): /* movzx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_register(modrm_reg, &_regs, 0);
        dst.bytes = op_bytes;
        dst.val   = (uint8_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xb7): /* movzx rm16,r{16,32,64} */
        dst.val = (uint16_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xba): /* Grp8 */
        switch ( modrm_reg & 7 )
        {
        case 4: goto bt;
        case 5: goto bts;
        case 6: goto btr;
        case 7: goto btc;
        default: generate_exception_if(1, EXC_UD, -1);
        }
        break;

    case X86EMUL_OPC(0x0f, 0xbb): btc: /* btc */
        emulate_2op_SrcV_nobyte("btc", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xbc): /* bsf or tzcnt */ {
        bool_t zf;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
        asm ( "bsf %2,%0"
              : "=r" (dst.val), "=@ccz" (zf)
              : "rm" (src.val) );
#else
        asm ( "bsf %2,%0; setz %1"
              : "=r" (dst.val), "=qm" (zf)
              : "rm" (src.val) );
#endif
        _regs.eflags &= ~EFLG_ZF;
        if ( (vex.pfx == vex_f3) && vcpu_has_bmi1() )
        {
            _regs.eflags &= ~EFLG_CF;
            if ( zf )
            {
                _regs.eflags |= EFLG_CF;
                dst.val = op_bytes * 8;
            }
            else if ( !dst.val )
                _regs.eflags |= EFLG_ZF;
        }
        else if ( zf )
        {
            _regs.eflags |= EFLG_ZF;
            dst.type = OP_NONE;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xbd): /* bsr or lzcnt */ {
        bool_t zf;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
        asm ( "bsr %2,%0"
              : "=r" (dst.val), "=@ccz" (zf)
              : "rm" (src.val) );
#else
        asm ( "bsr %2,%0; setz %1"
              : "=r" (dst.val), "=qm" (zf)
              : "rm" (src.val) );
#endif
        _regs.eflags &= ~EFLG_ZF;
        if ( (vex.pfx == vex_f3) && vcpu_has_lzcnt() )
        {
            _regs.eflags &= ~EFLG_CF;
            if ( zf )
            {
                _regs.eflags |= EFLG_CF;
                dst.val = op_bytes * 8;
            }
            else
            {
                dst.val = op_bytes * 8 - 1 - dst.val;
                if ( !dst.val )
                    _regs.eflags |= EFLG_ZF;
            }
        }
        else if ( zf )
        {
            _regs.eflags |= EFLG_ZF;
            dst.type = OP_NONE;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xbe): /* movsx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_register(modrm_reg, &_regs, 0);
        dst.bytes = op_bytes;
        dst.val   = (int8_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xbf): /* movsx rm16,r{16,32,64} */
        dst.val = (int16_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xc0): case X86EMUL_OPC(0x0f, 0xc1): /* xadd */
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        goto add;

    case X86EMUL_OPC(0x0f, 0xc3): /* movnti */
        /* Ignore the non-temporal hint for now. */
        vcpu_must_have_sse2();
        generate_exception_if(dst.bytes <= 2, EXC_UD, -1);
        dst.val = src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xc7): /* Grp9 (cmpxchg8b/cmpxchg16b) */ {
        unsigned long old[2], exp[2], new[2];

        generate_exception_if((modrm_reg & 7) != 1, EXC_UD, -1);
        generate_exception_if(ea.type != OP_MEM, EXC_UD, -1);
        if ( op_bytes == 8 )
            host_and_vcpu_must_have(cx16);
        op_bytes *= 2;

        /* Get actual old value. */
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, old, op_bytes,
                             ctxt)) != 0 )
            goto done;

        /* Get expected and proposed values. */
        if ( op_bytes == 8 )
        {
            ((uint32_t *)exp)[0] = _regs.eax; ((uint32_t *)exp)[1] = _regs.edx;
            ((uint32_t *)new)[0] = _regs.ebx; ((uint32_t *)new)[1] = _regs.ecx;
        }
        else
        {
            exp[0] = _regs.eax; exp[1] = _regs.edx;
            new[0] = _regs.ebx; new[1] = _regs.ecx;
        }

        if ( memcmp(old, exp, op_bytes) )
        {
            /* Expected != actual: store actual to rDX:rAX and clear ZF. */
            _regs.eax = (op_bytes == 8) ? ((uint32_t *)old)[0] : old[0];
            _regs.edx = (op_bytes == 8) ? ((uint32_t *)old)[1] : old[1];
            _regs.eflags &= ~EFLG_ZF;
        }
        else
        {
            /* Expected == actual: attempt atomic cmpxchg and set ZF. */
            if ( (rc = ops->cmpxchg(ea.mem.seg, ea.mem.off, old,
                                    new, op_bytes, ctxt)) != 0 )
                goto done;
            _regs.eflags |= EFLG_ZF;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xc8) ... X86EMUL_OPC(0x0f, 0xcf): /* bswap */
        dst.type = OP_REG;
        dst.reg  = decode_register(
            (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        switch ( dst.bytes = op_bytes )
        {
        default: /* case 2: */
            /* Undefined behaviour. Writes zero on all tested CPUs. */
            dst.val = 0;
            break;
        case 4:
#ifdef __x86_64__
            asm ( "bswap %k0" : "=r" (dst.val) : "0" (*(uint32_t *)dst.reg) );
            break;
        case 8:
#endif
            asm ( "bswap %0" : "=r" (dst.val) : "0" (*dst.reg) );
            break;
        }
        break;

    case X86EMUL_OPC(0x0f38, 0xf0): /* movbe m,r */
    case X86EMUL_OPC(0x0f38, 0xf1): /* movbe r,m */
        vcpu_must_have_movbe();
        switch ( op_bytes )
        {
        case 2:
            asm ( "xchg %h0,%b0" : "=Q" (dst.val)
                                 : "0" (*(uint32_t *)&src.val) );
            break;
        case 4:
#ifdef __x86_64__
            asm ( "bswap %k0" : "=r" (dst.val)
                              : "0" (*(uint32_t *)&src.val) );
            break;
        case 8:
#endif
            asm ( "bswap %0" : "=r" (dst.val) : "0" (src.val) );
            break;
        default:
            ASSERT_UNREACHABLE();
        }
        break;
#ifdef HAVE_GAS_SSE4_2
    case X86EMUL_OPC_F2(0x0f38, 0xf0): /* crc32 r/m8, r{32,64} */
    case X86EMUL_OPC_F2(0x0f38, 0xf1): /* crc32 r/m{16,32,64}, r{32,64} */
        host_and_vcpu_must_have(sse4_2);
        dst.bytes = rex_prefix & REX_W ? 8 : 4;
        switch ( op_bytes )
        {
        case 1:
            asm ( "crc32b %1,%k0" : "+r" (dst.val)
                                  : "qm" (*(uint8_t *)&src.val) );
            break;
        case 2:
            asm ( "crc32w %1,%k0" : "+r" (dst.val)
                                  : "rm" (*(uint16_t *)&src.val) );
            break;
        case 4:
            asm ( "crc32l %1,%k0" : "+r" (dst.val)
                                  : "rm" (*(uint32_t *)&src.val) );
            break;
# ifdef __x86_64__
        case 8:
            asm ( "crc32q %1,%0" : "+r" (dst.val) : "rm" (src.val) );
            break;
# endif
        default:
            ASSERT_UNREACHABLE();
        }
        break;
#endif
    default:
        goto cannot_emulate;
    }

 writeback:
    switch ( dst.type )
    {
    case OP_REG:
        /* The 4-byte case *is* correct: in 64-bit mode we zero-extend. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)dst.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)dst.reg = (uint16_t)dst.val; break;
        case 4: *dst.reg = (uint32_t)dst.val; break; /* 64b: zero-ext */
        case 8: *dst.reg = dst.val; break;
        }
        break;
    case OP_MEM:
        if ( !(d & Mov) && (dst.orig_val == dst.val) &&
             !ctxt->force_writeback )
            /* nothing to do */;
        else if ( lock_prefix )
            rc = ops->cmpxchg(
                dst.mem.seg, dst.mem.off, &dst.orig_val,
                &dst.val, dst.bytes, ctxt);
        else
            rc = ops->write(
                dst.mem.seg, dst.mem.off, &dst.val, dst.bytes, ctxt);
        if ( rc != 0 )
            goto done;
    default:
        break;
    }

 no_writeback:
    /* Commit shadow register state. */
    _regs.eflags &= ~EFLG_RF;

    /* Zero the upper 32 bits of %rip if not in 64-bit mode. */
    if ( !mode_64bit() )
        _regs.eip = (uint32_t)_regs.eip;

    *ctxt->regs = _regs;

    /* Should a singlestep #DB be raised? */
    if ( tf && (rc == X86EMUL_OKAY) && ops->inject_hw_exception )
        rc = ops->inject_hw_exception(EXC_DB, -1, ctxt) ? : X86EMUL_EXCEPTION;

 done:
    _put_fpu();
    put_stub(stub);
    return rc;

 cannot_emulate:
    _put_fpu();
    put_stub(stub);
    return X86EMUL_UNHANDLEABLE;
#undef state
}

#undef op_bytes
#undef ad_bytes
#undef ext
#undef modrm
#undef modrm_mod
#undef modrm_reg
#undef modrm_rm
#undef rex_prefix
#undef lock_prefix
#undef vex
#undef override_seg
#undef ea

static void __init __maybe_unused build_assertions(void)
{
    /* Check the values against SReg3 encoding in opcode/ModRM bytes. */
    BUILD_BUG_ON(x86_seg_es != 0);
    BUILD_BUG_ON(x86_seg_cs != 1);
    BUILD_BUG_ON(x86_seg_ss != 2);
    BUILD_BUG_ON(x86_seg_ds != 3);
    BUILD_BUG_ON(x86_seg_fs != 4);
    BUILD_BUG_ON(x86_seg_gs != 5);
}

#ifdef __XEN__

#include <xen/err.h>

struct x86_emulate_state *
x86_decode_insn(
    struct x86_emulate_ctxt *ctxt,
    int (*insn_fetch)(
        enum x86_segment seg, unsigned long offset,
        void *p_data, unsigned int bytes,
        struct x86_emulate_ctxt *ctxt))
{
    static DEFINE_PER_CPU(struct x86_emulate_state, state);
    struct x86_emulate_state *state = &this_cpu(state);
    const struct x86_emulate_ops ops = {
        .insn_fetch = insn_fetch,
        .read       = x86emul_unhandleable_rw,
        .write      = PTR_POISON,
        .cmpxchg    = PTR_POISON,
    };
    int rc = x86_decode(state, ctxt, &ops);

    if ( unlikely(rc != X86EMUL_OKAY) )
        return ERR_PTR(-rc);

#ifndef NDEBUG
    /*
     * While we avoid memory allocation (by use of per-CPU data) above,
     * nevertheless make sure callers properly release the state structure
     * for forward compatibility.
     */
    if ( state->caller )
    {
        printk(XENLOG_ERR "Unreleased emulation state acquired by %ps\n",
               state->caller);
        dump_execution_state();
    }
    state->caller = __builtin_return_address(0);
#endif

    return state;
}

static inline void check_state(const struct x86_emulate_state *state)
{
#ifndef NDEBUG
    ASSERT(state->caller);
#endif
}

#ifndef NDEBUG
void x86_emulate_free_state(struct x86_emulate_state *state)
{
    check_state(state);
    state->caller = NULL;
}
#endif

int
x86_insn_modrm(const struct x86_emulate_state *state,
               unsigned int *rm, unsigned int *reg)
{
    check_state(state);

    if ( !(state->desc & ModRM) )
        return -EINVAL;

    if ( rm )
        *rm = state->modrm_rm;
    if ( reg )
        *reg = state->modrm_reg;

    return state->modrm_mod;
}

unsigned int
x86_insn_length(const struct x86_emulate_state *state,
                const struct x86_emulate_ctxt *ctxt)
{
    check_state(state);

    return state->eip - ctxt->regs->eip;
}

#endif
