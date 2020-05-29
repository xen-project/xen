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
/* vSIB addressing mode (0f38 extension opcodes only), aliasing ModRM. */
#define vSIB        (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)
/* VEX/EVEX (SIMD only): 2nd source operand unused (must be all ones) */
#define TwoOp       Mov
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
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
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
    ByteOp|DstImplicit|SrcEax|Mov, DstImplicit|SrcEax|Mov,
    ByteOp|DstEax|SrcImplicit|Mov, DstEax|SrcImplicit|Mov,
    ByteOp|DstImplicit|SrcEax, DstImplicit|SrcEax,
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
    ImplicitOps|ModRM, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM, ImplicitOps|ModRM|Mov,
    DstImplicit|SrcMem16|ModRM, ImplicitOps|ModRM|Mov,
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

static const struct twobyte_table {
    opcode_desc_t desc;
    simd_opsize_t size:4;
    disp8scale_t d8s:4;
} twobyte_table[256] = {
    [0x00] = { ModRM },
    [0x01] = { ImplicitOps|ModRM },
    [0x02] = { DstReg|SrcMem16|ModRM },
    [0x03] = { DstReg|SrcMem16|ModRM },
    [0x05] = { ImplicitOps },
    [0x06] = { ImplicitOps },
    [0x07] = { ImplicitOps },
    [0x08] = { ImplicitOps },
    [0x09] = { ImplicitOps },
    [0x0b] = { ImplicitOps },
    [0x0d] = { ImplicitOps|ModRM },
    [0x0e] = { ImplicitOps },
    [0x0f] = { ModRM|SrcImmByte },
    [0x10] = { DstImplicit|SrcMem|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x11] = { DstMem|SrcImplicit|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x12] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, 3 },
    [0x13] = { DstMem|SrcImplicit|ModRM|Mov, simd_other, 3 },
    [0x14 ... 0x15] = { DstImplicit|SrcMem|ModRM, simd_packed_fp, d8s_vl },
    [0x16] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, 3 },
    [0x17] = { DstMem|SrcImplicit|ModRM|Mov, simd_other, 3 },
    [0x18 ... 0x1f] = { ImplicitOps|ModRM },
    [0x20 ... 0x21] = { DstMem|SrcImplicit|ModRM },
    [0x22 ... 0x23] = { DstImplicit|SrcMem|ModRM },
    [0x28] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x29] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x2a] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, d8s_dq64 },
    [0x2b] = { DstMem|SrcImplicit|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x2c ... 0x2d] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x2e ... 0x2f] = { ImplicitOps|ModRM|TwoOp, simd_none, d8s_dq },
    [0x30 ... 0x35] = { ImplicitOps },
    [0x37] = { ImplicitOps },
    [0x38] = { DstReg|SrcMem|ModRM },
    [0x3a] = { DstReg|SrcImmByte|ModRM },
    [0x40 ... 0x4f] = { DstReg|SrcMem|ModRM|Mov },
    [0x50] = { DstReg|SrcImplicit|ModRM|Mov },
    [0x51] = { DstImplicit|SrcMem|ModRM|TwoOp, simd_any_fp, d8s_vl },
    [0x52 ... 0x53] = { DstImplicit|SrcMem|ModRM|TwoOp, simd_single_fp },
    [0x54 ... 0x57] = { DstImplicit|SrcMem|ModRM, simd_packed_fp, d8s_vl },
    [0x58 ... 0x59] = { DstImplicit|SrcMem|ModRM, simd_any_fp, d8s_vl },
    [0x5a] = { DstImplicit|SrcMem|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x5b] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x5c ... 0x5f] = { DstImplicit|SrcMem|ModRM, simd_any_fp, d8s_vl },
    [0x60 ... 0x62] = { DstImplicit|SrcMem|ModRM, simd_other, d8s_vl },
    [0x63 ... 0x67] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0x68 ... 0x6a] = { DstImplicit|SrcMem|ModRM, simd_other, d8s_vl },
    [0x6b ... 0x6d] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0x6e] = { DstImplicit|SrcMem|ModRM|Mov, simd_none, d8s_dq64 },
    [0x6f] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_int, d8s_vl },
    [0x70] = { SrcImmByte|ModRM|TwoOp, simd_other, d8s_vl },
    [0x71 ... 0x73] = { DstImplicit|SrcImmByte|ModRM, simd_none, d8s_vl },
    [0x74 ... 0x76] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0x77] = { DstImplicit|SrcNone },
    [0x78 ... 0x79] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, d8s_vl },
    [0x7a] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x7b] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, d8s_dq64 },
    [0x7c ... 0x7d] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0x7e] = { DstMem|SrcImplicit|ModRM|Mov, simd_none, d8s_dq64 },
    [0x7f] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_int, d8s_vl },
    [0x80 ... 0x8f] = { DstImplicit|SrcImm },
    [0x90 ... 0x9f] = { ByteOp|DstMem|SrcNone|ModRM|Mov },
    [0xa0 ... 0xa1] = { ImplicitOps|Mov },
    [0xa2] = { ImplicitOps },
    [0xa3] = { DstBitBase|SrcReg|ModRM },
    [0xa4] = { DstMem|SrcImmByte|ModRM },
    [0xa5] = { DstMem|SrcReg|ModRM },
    [0xa6 ... 0xa7] = { ModRM },
    [0xa8 ... 0xa9] = { ImplicitOps|Mov },
    [0xaa] = { ImplicitOps },
    [0xab] = { DstBitBase|SrcReg|ModRM },
    [0xac] = { DstMem|SrcImmByte|ModRM },
    [0xad] = { DstMem|SrcReg|ModRM },
    [0xae] = { ImplicitOps|ModRM },
    [0xaf] = { DstReg|SrcMem|ModRM },
    [0xb0] = { ByteOp|DstMem|SrcReg|ModRM },
    [0xb1] = { DstMem|SrcReg|ModRM },
    [0xb2] = { DstReg|SrcMem|ModRM|Mov },
    [0xb3] = { DstBitBase|SrcReg|ModRM },
    [0xb4 ... 0xb5] = { DstReg|SrcMem|ModRM|Mov },
    [0xb6] = { ByteOp|DstReg|SrcMem|ModRM|Mov },
    [0xb7] = { DstReg|SrcMem16|ModRM|Mov },
    [0xb8] = { DstReg|SrcMem|ModRM },
    [0xb9] = { ModRM },
    [0xba] = { DstBitBase|SrcImmByte|ModRM },
    [0xbb] = { DstBitBase|SrcReg|ModRM },
    [0xbc ... 0xbd] = { DstReg|SrcMem|ModRM },
    [0xbe] = { ByteOp|DstReg|SrcMem|ModRM|Mov },
    [0xbf] = { DstReg|SrcMem16|ModRM|Mov },
    [0xc0] = { ByteOp|DstMem|SrcReg|ModRM },
    [0xc1] = { DstMem|SrcReg|ModRM },
    [0xc2] = { DstImplicit|SrcImmByte|ModRM, simd_any_fp, d8s_vl },
    [0xc3] = { DstMem|SrcReg|ModRM|Mov },
    [0xc4] = { DstReg|SrcImmByte|ModRM, simd_packed_int, 1 },
    [0xc5] = { DstReg|SrcImmByte|ModRM|Mov },
    [0xc6] = { DstImplicit|SrcImmByte|ModRM, simd_packed_fp, d8s_vl },
    [0xc7] = { ImplicitOps|ModRM },
    [0xc8 ... 0xcf] = { ImplicitOps },
    [0xd0] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0xd1 ... 0xd3] = { DstImplicit|SrcMem|ModRM, simd_128, 4 },
    [0xd4 ... 0xd5] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xd6] = { DstMem|SrcImplicit|ModRM|Mov, simd_other, 3 },
    [0xd7] = { DstReg|SrcImplicit|ModRM|Mov },
    [0xd8 ... 0xdf] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xe0] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xe1 ... 0xe2] = { DstImplicit|SrcMem|ModRM, simd_128, 4 },
    [0xe3 ... 0xe5] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xe6] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0xe7] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_int, d8s_vl },
    [0xe8 ... 0xef] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xf0] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0xf1 ... 0xf3] = { DstImplicit|SrcMem|ModRM, simd_128, 4 },
    [0xf4 ... 0xf6] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xf7] = { DstMem|SrcMem|ModRM|Mov, simd_packed_int },
    [0xf8 ... 0xfe] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xff] = { ModRM }
};

/*
 * The next two tables are indexed by high opcode extension byte (the one
 * that's encoded like an immediate) nibble, with each table element then
 * bit-indexed by low opcode extension byte nibble.
 */
static const uint16_t _3dnow_table[16] = {
    [0x0] = (1 << 0xd) /* pi2fd */,
    [0x1] = (1 << 0xd) /* pf2id */,
    [0x9] = (1 << 0x0) /* pfcmpge */ |
            (1 << 0x4) /* pfmin */ |
            (1 << 0x6) /* pfrcp */ |
            (1 << 0x7) /* pfrsqrt */ |
            (1 << 0xa) /* pfsub */ |
            (1 << 0xe) /* pfadd */,
    [0xa] = (1 << 0x0) /* pfcmpgt */ |
            (1 << 0x4) /* pfmax */ |
            (1 << 0x6) /* pfrcpit1 */ |
            (1 << 0x7) /* pfrsqit1 */ |
            (1 << 0xa) /* pfsubr */ |
            (1 << 0xe) /* pfacc */,
    [0xb] = (1 << 0x0) /* pfcmpeq */ |
            (1 << 0x4) /* pfmul */ |
            (1 << 0x6) /* pfrcpit2 */ |
            (1 << 0x7) /* pmulhrw */ |
            (1 << 0xf) /* pavgusb */,
};

static const uint16_t _3dnow_ext_table[16] = {
    [0x0] = (1 << 0xc) /* pi2fw */,
    [0x1] = (1 << 0xc) /* pf2iw */,
    [0x8] = (1 << 0xa) /* pfnacc */ |
            (1 << 0xe) /* pfpnacc */,
    [0xb] = (1 << 0xb) /* pswapd */,
};

/*
 * "two_op" and "four_op" below refer to the number of register operands
 * (one of which possibly also allowing to be a memory one). The named
 * operand counts do not include any immediate operands.
 */
static const struct ext0f38_table {
    uint8_t simd_size:5;
    uint8_t to_mem:1;
    uint8_t two_op:1;
    uint8_t vsib:1;
    disp8scale_t d8s:4;
} ext0f38_table[256] = {
    [0x00] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x01 ... 0x03] = { .simd_size = simd_packed_int },
    [0x04] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x05 ... 0x0a] = { .simd_size = simd_packed_int },
    [0x0b] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x0c ... 0x0d] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x0e ... 0x0f] = { .simd_size = simd_packed_fp },
    [0x10 ... 0x12] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x13] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x14 ... 0x16] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x17] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x18] = { .simd_size = simd_scalar_opc, .two_op = 1, .d8s = 2 },
    [0x19] = { .simd_size = simd_scalar_opc, .two_op = 1, .d8s = 3 },
    [0x1a] = { .simd_size = simd_128, .two_op = 1, .d8s = 4 },
    [0x1b] = { .simd_size = simd_256, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x1c ... 0x1f] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x20] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x21] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x22] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_8 },
    [0x23] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x24] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x25] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x26 ... 0x29] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x2a] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x2b] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x2c] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x2d] = { .simd_size = simd_packed_fp, .d8s = d8s_dq },
    [0x2e ... 0x2f] = { .simd_size = simd_packed_fp, .to_mem = 1 },
    [0x30] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x31] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x32] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_8 },
    [0x33] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x34] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x35] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x36 ... 0x3f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x40] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x41] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x42] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x43] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x44] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x45 ... 0x47] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x4c] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x4d] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x4e] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x4f] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x50 ... 0x53] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x54 ... 0x55] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x58] = { .simd_size = simd_other, .two_op = 1, .d8s = 2 },
    [0x59] = { .simd_size = simd_other, .two_op = 1, .d8s = 3 },
    [0x5a] = { .simd_size = simd_128, .two_op = 1, .d8s = 4 },
    [0x5b] = { .simd_size = simd_256, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x62] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_bw },
    [0x63] = { .simd_size = simd_packed_int, .to_mem = 1, .two_op = 1, .d8s = d8s_bw },
    [0x64 ... 0x66] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x70 ... 0x73] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x75 ... 0x76] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x77] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x78] = { .simd_size = simd_other, .two_op = 1 },
    [0x79] = { .simd_size = simd_other, .two_op = 1, .d8s = 1 },
    [0x7a ... 0x7c] = { .simd_size = simd_none, .two_op = 1 },
    [0x7d ... 0x7e] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x7f] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x82] = { .simd_size = simd_other },
    [0x83] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x88] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_dq },
    [0x89] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_dq },
    [0x8a] = { .simd_size = simd_packed_fp, .to_mem = 1, .two_op = 1, .d8s = d8s_dq },
    [0x8b] = { .simd_size = simd_packed_int, .to_mem = 1, .two_op = 1, .d8s = d8s_dq },
    [0x8c] = { .simd_size = simd_packed_int },
    [0x8d] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x8e] = { .simd_size = simd_packed_int, .to_mem = 1 },
    [0x8f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x90 ... 0x93] = { .simd_size = simd_other, .vsib = 1, .d8s = d8s_dq },
    [0x96 ... 0x98] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x99] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x9a] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x9b] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x9c] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x9d] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x9e] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x9f] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xa0 ... 0xa3] = { .simd_size = simd_other, .vsib = 1, .d8s = d8s_dq },
    [0xa6 ... 0xa8] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xa9] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xaa] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xab] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xac] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xad] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xae] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xaf] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xb4 ... 0xb5] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xb6 ... 0xb8] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xb9] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xba] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xbb] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xbc] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xbd] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xbe] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xbf] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xc4] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0xc6 ... 0xc7] = { .simd_size = simd_other, .vsib = 1, .d8s = d8s_dq },
    [0xc8] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0xc9] = { .simd_size = simd_other },
    [0xca] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0xcb] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xcc] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0xcd] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xcf] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xdb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xdc ... 0xdf] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xf0] = { .two_op = 1 },
    [0xf1] = { .to_mem = 1, .two_op = 1 },
    [0xf2 ... 0xf3] = {},
    [0xf5 ... 0xf7] = {},
    [0xf8] = { .simd_size = simd_other },
    [0xf9] = { .to_mem = 1, .two_op = 1 /* Mov */ },
};

/* Shift values between src and dst sizes of pmov{s,z}x{b,w,d}{w,d,q}. */
static const uint8_t pmov_convert_delta[] = { 1, 2, 3, 1, 2, 1 };

static const struct ext0f3a_table {
    uint8_t simd_size:5;
    uint8_t to_mem:1;
    uint8_t two_op:1;
    uint8_t four_op:1;
    disp8scale_t d8s:4;
} ext0f3a_table[256] = {
    [0x00] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x01] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x02] = { .simd_size = simd_packed_int },
    [0x03] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x04 ... 0x05] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x06] = { .simd_size = simd_packed_fp },
    [0x08 ... 0x09] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x0a ... 0x0b] = { .simd_size = simd_scalar_opc, .d8s = d8s_dq },
    [0x0c ... 0x0d] = { .simd_size = simd_packed_fp },
    [0x0e] = { .simd_size = simd_packed_int },
    [0x0f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x14] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = 0 },
    [0x15] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = 1 },
    [0x16] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = d8s_dq64 },
    [0x17] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = 2 },
    [0x18] = { .simd_size = simd_128, .d8s = 4 },
    [0x19] = { .simd_size = simd_128, .to_mem = 1, .two_op = 1, .d8s = 4 },
    [0x1a] = { .simd_size = simd_256, .d8s = d8s_vl_by_2 },
    [0x1b] = { .simd_size = simd_256, .to_mem = 1, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x1d] = { .simd_size = simd_other, .to_mem = 1, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x1e ... 0x1f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x20] = { .simd_size = simd_none, .d8s = 0 },
    [0x21] = { .simd_size = simd_other, .d8s = 2 },
    [0x22] = { .simd_size = simd_none, .d8s = d8s_dq64 },
    [0x23] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x25] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x26] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x27] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x30 ... 0x33] = { .simd_size = simd_other, .two_op = 1 },
    [0x38] = { .simd_size = simd_128, .d8s = 4 },
    [0x3a] = { .simd_size = simd_256, .d8s = d8s_vl_by_2 },
    [0x39] = { .simd_size = simd_128, .to_mem = 1, .two_op = 1, .d8s = 4 },
    [0x3b] = { .simd_size = simd_256, .to_mem = 1, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x3e ... 0x3f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x40 ... 0x41] = { .simd_size = simd_packed_fp },
    [0x42 ... 0x43] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x44] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x46] = { .simd_size = simd_packed_int },
    [0x48 ... 0x49] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x4a ... 0x4b] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x4c] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x50] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x51] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x54] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x55] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x56] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x57] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x5c ... 0x5f] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x60 ... 0x63] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x66] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x67] = { .simd_size = simd_scalar_vexw, .two_op = 1, .d8s = d8s_dq },
    [0x68 ... 0x69] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x6a ... 0x6b] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0x6c ... 0x6d] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x6e ... 0x6f] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0x70 ... 0x73] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x78 ... 0x79] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x7a ... 0x7b] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0x7c ... 0x7d] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x7e ... 0x7f] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0xcc] = { .simd_size = simd_other },
    [0xce ... 0xcf] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xdf] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xf0] = {},
};

static const opcode_desc_t xop_table[] = {
    DstReg|SrcImmByte|ModRM,
    DstReg|SrcMem|ModRM,
    DstReg|SrcImm|ModRM,
};

static const struct ext8f08_table {
    uint8_t simd_size:5;
    uint8_t two_op:1;
    uint8_t four_op:1;
} ext8f08_table[256] = {
    [0xa2] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x85 ... 0x87] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x8e ... 0x8f] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x95 ... 0x97] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x9e ... 0x9f] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xa3] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xa6] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xb6] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xc0 ... 0xc3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xcc ... 0xcf] = { .simd_size = simd_packed_int },
    [0xec ... 0xef] = { .simd_size = simd_packed_int },
};

static const struct ext8f09_table {
    uint8_t simd_size:5;
    uint8_t two_op:1;
} ext8f09_table[256] = {
    [0x01 ... 0x02] = { .two_op = 1 },
    [0x80 ... 0x81] = { .simd_size = simd_packed_fp, .two_op = 1 },
    [0x82 ... 0x83] = { .simd_size = simd_scalar_opc, .two_op = 1 },
    [0x90 ... 0x9b] = { .simd_size = simd_packed_int },
    [0xc1 ... 0xc3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xc6 ... 0xc7] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xcb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xd1 ... 0xd3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xd6 ... 0xd7] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xdb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xe1 ... 0xe3] = { .simd_size = simd_packed_int, .two_op = 1 },
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

#ifdef __x86_64__
# define PFX2 REX_PREFIX
#else
# define PFX2 0x3e
#endif
#define PFX_BYTES 3
#define init_prefixes(stub) ({ \
    uint8_t *buf_ = get_stub(stub); \
    buf_[0] = 0x3e; \
    buf_[1] = PFX2; \
    buf_[2] = 0x0f; \
    buf_ + 3; \
})

#define copy_VEX(ptr, vex) ({ \
    if ( !mode_64bit() ) \
        (vex).reg |= 8; \
    (ptr)[0 - PFX_BYTES] = ext < ext_8f08 ? 0xc4 : 0x8f; \
    (ptr)[1 - PFX_BYTES] = (vex).raw[0]; \
    (ptr)[2 - PFX_BYTES] = (vex).raw[1]; \
    container_of((ptr) + 1 - PFX_BYTES, typeof(vex), raw[0]); \
})

#define copy_REX_VEX(ptr, rex, vex) do { \
    if ( (vex).opcx != vex_none ) \
        copy_VEX(ptr, vex); \
    else \
    { \
        if ( (vex).pfx ) \
            (ptr)[0 - PFX_BYTES] = sse_prefix[(vex).pfx - 1]; \
        /* \
         * "rex" is always zero for other than 64-bit mode, so OR-ing it \
         * into any prefix (and not just REX_PREFIX) is safe on 32-bit \
         * (test harness) builds. \
         */ \
        (ptr)[1 - PFX_BYTES] |= rex; \
    } \
} while (0)

union evex {
    uint8_t raw[3];
    struct {             /* SDM names */
        uint8_t opcx:2;  /* mm */
        uint8_t mbz:2;
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

#define EVEX_PFX_BYTES 4
#define init_evex(stub) ({ \
    uint8_t *buf_ = get_stub(stub); \
    buf_[0] = 0x62; \
    buf_ + EVEX_PFX_BYTES; \
})

#define copy_EVEX(ptr, evex) ({ \
    if ( !mode_64bit() ) \
        (evex).reg |= 8; \
    (ptr)[1 - EVEX_PFX_BYTES] = (evex).raw[0]; \
    (ptr)[2 - EVEX_PFX_BYTES] = (evex).raw[1]; \
    (ptr)[3 - EVEX_PFX_BYTES] = (evex).raw[2]; \
    container_of((ptr) + 1 - EVEX_PFX_BYTES, typeof(evex), raw[0]); \
})

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
    enum {
        rmw_NONE,
        rmw_adc,
        rmw_add,
        rmw_and,
        rmw_btc,
        rmw_btr,
        rmw_bts,
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
    struct cpu_user_regs *regs;

#ifndef NDEBUG
    /*
     * Track caller of x86_decode_insn() to spot missing as well as
     * premature calls to x86_emulate_free_state().
     */
    void *caller;
#endif
};

#ifdef __x86_64__
#define PTR_POISON ((void *)0x8086000000008086UL) /* non-canonical */
#else
#define PTR_POISON NULL /* 32-bit builds are for user-space, so NULL is OK. */
#endif

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

/*
 * While proper alignment gets specified above, this doesn't get honored by
 * the compiler for automatic variables. Use this helper to instantiate a
 * suitably aligned variable, producing a pointer to access it.
 */
#define DECLARE_ALIGNED(type, var)                                        \
    long __##var[(sizeof(type) + __alignof(type)) / __alignof(long) - 1]; \
    type *const var##p =                                                  \
        (void *)(((long)__##var + __alignof(type) - __alignof(__##var))   \
                 & -__alignof(type))

#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define ASM_FLAG_OUT(yes, no) yes
#else
# define ASM_FLAG_OUT(yes, no) no
#endif

/* Floating point status word definitions. */
#define FSW_ES    (1U << 7)

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
#define EXC_DF  8
#define EXC_TS 10
#define EXC_NP 11
#define EXC_SS 12
#define EXC_GP 13
#define EXC_PF 14
#define EXC_MF 16
#define EXC_AC 17
#define EXC_XM 19

#define EXC_HAS_EC                                                      \
    ((1u << EXC_DF) | (1u << EXC_TS) | (1u << EXC_NP) |                 \
     (1u << EXC_SS) | (1u << EXC_GP) | (1u << EXC_PF) | (1u << EXC_AC))

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
#define EFLAGS_MASK (X86_EFLAGS_OF | X86_EFLAGS_SF | X86_EFLAGS_ZF | \
                     X86_EFLAGS_AF | X86_EFLAGS_PF | X86_EFLAGS_CF)

/*
 * These EFLAGS bits are modifiable (by POPF and IRET), possibly subject
 * to further CPL and IOPL constraints.
 */
#define EFLAGS_MODIFIABLE (X86_EFLAGS_ID | X86_EFLAGS_AC | X86_EFLAGS_RF | \
                           X86_EFLAGS_NT | X86_EFLAGS_IOPL | X86_EFLAGS_DF | \
                           X86_EFLAGS_IF | X86_EFLAGS_TF | EFLAGS_MASK)

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

/* Raw emulation: instruction has two explicit operands. */
#define __emulate_2op_nobyte(_op, src, dst, sz, eflags, wsx,wsy,wdx,wdy,   \
                             lsx,lsy,ldx,ldy, qsx,qsy,qdx,qdy, extra...)   \
do{ unsigned long _tmp;                                                    \
    switch ( sz )                                                          \
    {                                                                      \
    case 2:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"w %"wsx"3,%"wdx"1; "                                       \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (eflags), "+" wdy (*(dst)), "=&r" (_tmp)                \
            : wsy (src), "i" (EFLAGS_MASK), ## extra );                    \
        break;                                                             \
    case 4:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"l %"lsx"3,%"ldx"1; "                                       \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (eflags), "+" ldy (*(dst)), "=&r" (_tmp)                \
            : lsy (src), "i" (EFLAGS_MASK), ## extra );                    \
        break;                                                             \
    case 8:                                                                \
        __emulate_2op_8byte(_op, src, dst, eflags, qsx, qsy, qdx, qdy,     \
                            ## extra);                                     \
        break;                                                             \
    }                                                                      \
} while (0)
#define __emulate_2op(_op, src, dst, sz, eflags, _bx, by, wx, wy,          \
                      lx, ly, qx, qy, extra...)                            \
do{ unsigned long _tmp;                                                    \
    switch ( sz )                                                          \
    {                                                                      \
    case 1:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"b %"_bx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : by (src), "i" (EFLAGS_MASK), ##extra );                      \
        break;                                                             \
    default:                                                               \
        __emulate_2op_nobyte(_op, src, dst, sz, eflags, wx, wy, "", "m",   \
                             lx, ly, "", "m", qx, qy, "", "m", ##extra);   \
        break;                                                             \
    }                                                                      \
} while (0)
/* Source operand is byte-sized and may be restricted to just %cl. */
#define _emulate_2op_SrcB(op, src, dst, sz, eflags)                        \
    __emulate_2op(op, src, dst, sz, eflags,                                \
                  "b", "c", "b", "c", "b", "c", "b", "c")
#define emulate_2op_SrcB(op, src, dst, eflags)                             \
    _emulate_2op_SrcB(op, (src).val, &(dst).val, (dst).bytes, eflags)
/* Source operand is byte, word, long or quad sized. */
#define _emulate_2op_SrcV(op, src, dst, sz, eflags, extra...)              \
    __emulate_2op(op, src, dst, sz, eflags,                                \
                  "b", "q", "w", "r", _LO32, "r", "", "r", ##extra)
#define emulate_2op_SrcV(_op, _src, _dst, _eflags)                         \
    _emulate_2op_SrcV(_op, (_src).val, &(_dst).val, (_dst).bytes, _eflags)
/* Source operand is word, long or quad sized. */
#define _emulate_2op_SrcV_nobyte(op, src, dst, sz, eflags, extra...)       \
    __emulate_2op_nobyte(op, src, dst, sz, eflags, "w", "r", "", "m",      \
                         _LO32, "r", "", "m", "", "r", "", "m", ##extra)
#define emulate_2op_SrcV_nobyte(_op, _src, _dst, _eflags)                  \
    _emulate_2op_SrcV_nobyte(_op, (_src).val, &(_dst).val, (_dst).bytes,   \
                             _eflags)
/* Operands are word, long or quad sized and source may be in memory. */
#define emulate_2op_SrcV_srcmem(_op, _src, _dst, _eflags)                  \
    __emulate_2op_nobyte(_op, (_src).val, &(_dst).val, (_dst).bytes,       \
                         _eflags, "", "m", "w", "r",                       \
                         "", "m", _LO32, "r", "", "m", "", "r")

/* Instruction has only one explicit operand (no source operand). */
#define _emulate_1op(_op, dst, sz, eflags, extra...)                       \
do{ unsigned long _tmp;                                                    \
    switch ( sz )                                                          \
    {                                                                      \
    case 1:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"b %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : "i" (EFLAGS_MASK), ##extra );                                \
        break;                                                             \
    case 2:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"w %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : "i" (EFLAGS_MASK), ##extra );                                \
        break;                                                             \
    case 4:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"l %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : "i" (EFLAGS_MASK), ##extra );                                \
        break;                                                             \
    case 8:                                                                \
        __emulate_1op_8byte(_op, dst, eflags, ##extra);                    \
        break;                                                             \
    }                                                                      \
} while (0)
#define emulate_1op(op, dst, eflags)                                       \
    _emulate_1op(op, &(dst).val, (dst).bytes, eflags)

/* Emulate an instruction with quadword operands (x86/64 only). */
#if defined(__x86_64__)
#define __emulate_2op_8byte(_op, src, dst, eflags,                      \
                            qsx, qsy, qdx, qdy, extra...)               \
do{ asm volatile (                                                      \
        _PRE_EFLAGS("0","4","2")                                        \
        _op"q %"qsx"3,%"qdx"1; "                                        \
        _POST_EFLAGS("0","4","2")                                       \
        : "+g" (eflags), "+" qdy (*(dst)), "=&r" (_tmp)                 \
        : qsy (src), "i" (EFLAGS_MASK), ##extra );                      \
} while (0)
#define __emulate_1op_8byte(_op, dst, eflags, extra...)                 \
do{ asm volatile (                                                      \
        _PRE_EFLAGS("0","3","2")                                        \
        _op"q %1; "                                                     \
        _POST_EFLAGS("0","3","2")                                       \
        : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                    \
        : "i" (EFLAGS_MASK), ##extra );                                 \
} while (0)
#elif defined(__i386__)
#define __emulate_2op_8byte(op, src, dst, eflags, qsx, qsy, qdx, qdy, extra...)
#define __emulate_1op_8byte(op, dst, eflags, extra...)
#endif /* __i386__ */

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
    return (e < 32 && ((1u << e) & EXC_HAS_EC)) ? ec : X86_EVENT_NO_EC;
}

#define generate_exception_if(p, e, ec...)                                \
({  if ( (p) ) {                                                          \
        x86_emul_hw_exception(e, mkec(e, ##ec, 0), ctxt);                 \
        rc = X86EMUL_EXCEPTION;                                           \
        goto done;                                                        \
    }                                                                     \
})

#define generate_exception(e, ec...) generate_exception_if(true, e, ##ec)

#ifdef __XEN__
# define invoke_stub(pre, post, constraints...) do {                    \
    stub_exn.info = (union stub_exception_token) { .raw = ~0 };         \
    stub_exn.line = __LINE__; /* Utility outweighs livepatching cost */ \
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
#else
# define invoke_stub(pre, post, constraints...)                         \
    asm volatile ( pre "\n\tcall *%[stub]\n\t" post                     \
                   : constraints, [stub] "rm" (stub.func),              \
                     "m" (*(typeof(stub.buf) *)stub.addr) )
#endif

#define emulate_stub(dst, src...) do {                                  \
    unsigned long tmp;                                                  \
    invoke_stub(_PRE_EFLAGS("[efl]", "[msk]", "[tmp]"),                 \
                _POST_EFLAGS("[efl]", "[msk]", "[tmp]"),                \
                dst, [tmp] "=&r" (tmp), [efl] "+g" (_regs.eflags)       \
                : [msk] "i" (EFLAGS_MASK), ## src);                     \
} while (0)

/* Fetch next part of the instruction being emulated. */
#define insn_fetch_bytes(_size)                                         \
({ unsigned long _x = 0, _ip = state->ip;                               \
   state->ip += (_size); /* real hardware doesn't truncate */           \
   generate_exception_if((uint8_t)(state->ip -                          \
                                   ctxt->regs->r(ip)) > MAX_INST_LEN,   \
                         EXC_GP, 0);                                    \
   rc = ops->insn_fetch(x86_seg_cs, _ip, &_x, (_size), ctxt);           \
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

#ifdef __x86_64__
# define mode_64bit() (ctxt->addr_size == 64)
#else
# define mode_64bit() false
#endif

/*
 * Given byte has even parity (even number of 1s)? SDM Vol. 1 Sec. 3.4.3.1,
 * "Status Flags": EFLAGS.PF reflects parity of least-sig. byte of result only.
 */
static bool even_parity(uint8_t v)
{
    asm ( "test %1,%1" ASM_FLAG_OUT(, "; setp %0")
          : ASM_FLAG_OUT("=@ccp", "=qm") (v) : "q" (v) );

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
#define register_address_adjust(reg, adj)                               \
    _register_address_increment(reg,                                    \
                                _regs.eflags & X86_EFLAGS_DF ?          \
                                -(adj) : (adj),                         \
                                ad_bytes)

#define sp_pre_dec(dec) ({                                              \
    _register_address_increment(_regs.r(sp), -(dec), ctxt->sp_size/8);  \
    truncate_word(_regs.r(sp), ctxt->sp_size/8);                        \
})
#define sp_post_inc(inc) ({                                             \
    unsigned long sp = truncate_word(_regs.r(sp), ctxt->sp_size/8);     \
    _register_address_increment(_regs.r(sp), (inc), ctxt->sp_size/8);   \
    sp;                                                                 \
})

#define jmp_rel(rel)                                                    \
do {                                                                    \
    unsigned long ip = _regs.r(ip) + (int)(rel);                        \
    if ( op_bytes == 2 && (amd_like(ctxt) || !mode_64bit()) )           \
        ip = (uint16_t)ip;                                              \
    else if ( !mode_64bit() )                                           \
        ip = (uint32_t)ip;                                              \
    rc = ops->insn_fetch(x86_seg_cs, ip, NULL, 0, ctxt);                \
    if ( rc ) goto done;                                                \
    _regs.r(ip) = ip;                                                   \
    singlestep = _regs.eflags & X86_EFLAGS_TF;                          \
} while (0)

#define validate_far_branch(cs, ip) ({                                  \
    if ( sizeof(ip) <= 4 ) {                                            \
        ASSERT(!ctxt->lma);                                             \
        generate_exception_if((ip) > (cs)->limit, EXC_GP, 0);           \
    } else                                                              \
        generate_exception_if(ctxt->lma && (cs)->l                      \
                              ? !is_canonical_address(ip)               \
                              : (ip) > (cs)->limit, EXC_GP, 0);         \
})

#define commit_far_branch(cs, newip) ({                                 \
    validate_far_branch(cs, newip);                                     \
    _regs.r(ip) = (newip);                                              \
    singlestep = _regs.eflags & X86_EFLAGS_TF;                          \
    ops->write_segment(x86_seg_cs, cs, ctxt);                           \
})

static int _get_fpu(
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    uint64_t xcr0;
    int rc;

    fail_if(!ops->get_fpu);
    ASSERT(type != X86EMUL_FPU_none);

    if ( type < X86EMUL_FPU_ymm || !ops->read_xcr ||
         ops->read_xcr(0, &xcr0, ctxt) != X86EMUL_OKAY )
    {
        ASSERT(!ctxt->event_pending);
        xcr0 = 0;
    }

    switch ( type )
    {
    case X86EMUL_FPU_zmm:
        if ( !(xcr0 & X86_XCR0_ZMM) || !(xcr0 & X86_XCR0_HI_ZMM) ||
             !(xcr0 & X86_XCR0_OPMASK) )
            return X86EMUL_UNHANDLEABLE;
        /* fall through */
    case X86EMUL_FPU_ymm:
        if ( !(xcr0 & X86_XCR0_SSE) || !(xcr0 & X86_XCR0_YMM) )
            return X86EMUL_UNHANDLEABLE;
        break;

    case X86EMUL_FPU_opmask:
        if ( !(xcr0 & X86_XCR0_SSE) || !(xcr0 & X86_XCR0_OPMASK) )
            return X86EMUL_UNHANDLEABLE;
        break;

    default:
        break;
    }

    rc = ops->get_fpu(type, ctxt);

    if ( rc == X86EMUL_OKAY )
    {
        unsigned long cr0;

        fail_if(type == X86EMUL_FPU_fpu && !ops->put_fpu);

        fail_if(!ops->read_cr);
        if ( type >= X86EMUL_FPU_xmm )
        {
            unsigned long cr4;

            rc = ops->read_cr(4, &cr4, ctxt);
            if ( rc != X86EMUL_OKAY )
                return rc;
            generate_exception_if(!(cr4 & ((type == X86EMUL_FPU_xmm)
                                           ? X86_CR4_OSFXSR : X86_CR4_OSXSAVE)),
                                  EXC_UD);
        }

        rc = ops->read_cr(0, &cr0, ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
        if ( type >= X86EMUL_FPU_ymm )
        {
            /* Should be unreachable if VEX decoding is working correctly. */
            ASSERT((cr0 & X86_CR0_PE) && !(ctxt->regs->eflags & X86_EFLAGS_VM));
        }
        if ( cr0 & X86_CR0_EM )
        {
            generate_exception_if(type == X86EMUL_FPU_fpu, EXC_NM);
            generate_exception_if(type == X86EMUL_FPU_mmx, EXC_UD);
            generate_exception_if(type == X86EMUL_FPU_xmm, EXC_UD);
        }
        generate_exception_if((cr0 & X86_CR0_TS) &&
                              (type != X86EMUL_FPU_wait || (cr0 & X86_CR0_MP)),
                              EXC_NM);
    }

 done:
    return rc;
}

#define get_fpu(type)                                           \
do {                                                            \
    rc = _get_fpu(fpu_type = (type), ctxt, ops);                \
    if ( rc ) goto done;                                        \
} while (0)

static void put_fpu(
    enum x86_emulate_fpu_type type,
    bool failed_late,
    const struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    if ( unlikely(failed_late) && type == X86EMUL_FPU_fpu )
        ops->put_fpu(ctxt, X86EMUL_FPU_fpu, NULL);
    else if ( unlikely(type == X86EMUL_FPU_fpu) && !state->fpu_ctrl )
    {
        struct x86_emul_fpu_aux aux = {
            .ip = ctxt->regs->r(ip),
            .cs = ctxt->regs->cs,
            .op = ((ctxt->opcode & 7) << 8) | state->modrm,
        };
        struct segment_register sreg;

        if ( ops->read_segment &&
             ops->read_segment(x86_seg_cs, &sreg, ctxt) == X86EMUL_OKAY )
            aux.cs = sreg.sel;
        if ( state->ea.type == OP_MEM )
        {
            aux.dp = state->ea.mem.off;
            if ( ops->read_segment &&
                 ops->read_segment(state->ea.mem.seg, &sreg,
                                   ctxt) == X86EMUL_OKAY )
                aux.ds = sreg.sel;
            else
                switch ( state->ea.mem.seg )
                {
                case x86_seg_cs: aux.ds = ctxt->regs->cs; break;
                case x86_seg_ds: aux.ds = ctxt->regs->ds; break;
                case x86_seg_es: aux.ds = ctxt->regs->es; break;
                case x86_seg_fs: aux.ds = ctxt->regs->fs; break;
                case x86_seg_gs: aux.ds = ctxt->regs->gs; break;
                case x86_seg_ss: aux.ds = ctxt->regs->ss; break;
                default:         ASSERT_UNREACHABLE();    break;
                }
            aux.dval = true;
        }
        ops->put_fpu(ctxt, X86EMUL_FPU_none, &aux);
    }
    else if ( type != X86EMUL_FPU_none && ops->put_fpu )
        ops->put_fpu(ctxt, X86EMUL_FPU_none, NULL);
}

static inline bool fpu_check_write(void)
{
    uint16_t fsw;

    asm ( "fnstsw %0" : "=am" (fsw) );

    return !(fsw & FSW_ES);
}

#define emulate_fpu_insn_memdst(opc, ext, arg)                          \
do {                                                                    \
    /* ModRM: mod=0, reg=ext, rm=0, i.e. a (%rax) operand */            \
    insn_bytes = 2;                                                     \
    memcpy(get_stub(stub),                                              \
           ((uint8_t[]){ opc, ((ext) & 7) << 3, 0xc3 }), 3);            \
    invoke_stub("", "", "+m" (arg) : "a" (&(arg)));                     \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_memsrc(opc, ext, arg)                          \
do {                                                                    \
    /* ModRM: mod=0, reg=ext, rm=0, i.e. a (%rax) operand */            \
    memcpy(get_stub(stub),                                              \
           ((uint8_t[]){ opc, ((ext) & 7) << 3, 0xc3 }), 3);            \
    invoke_stub("", "", "=m" (dummy) : "m" (arg), "a" (&(arg)));        \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub(bytes...)                                 \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    invoke_stub("", "", "=m" (dummy) : "i" (0));                        \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub_eflags(bytes...)                          \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    unsigned long tmp_;                                                 \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    invoke_stub(_PRE_EFLAGS("[eflags]", "[mask]", "[tmp]"),             \
                _POST_EFLAGS("[eflags]", "[mask]", "[tmp]"),            \
                [eflags] "+g" (_regs.eflags), [tmp] "=&r" (tmp_)        \
                : [mask] "i" (X86_EFLAGS_ZF|X86_EFLAGS_PF|X86_EFLAGS_CF)); \
    put_stub(stub);                                                     \
} while (0)

static inline unsigned long get_loop_count(
    const struct cpu_user_regs *regs,
    int ad_bytes)
{
    return (ad_bytes > 4) ? regs->r(cx)
                          : (ad_bytes < 4) ? regs->cx : regs->ecx;
}

static inline void put_loop_count(
    struct cpu_user_regs *regs,
    int ad_bytes,
    unsigned long count)
{
    if ( ad_bytes == 2 )
        regs->cx = count;
    else
        regs->r(cx) = ad_bytes == 4 ? (uint32_t)count : count;
}

#define get_rep_prefix(using_si, using_di) ({                           \
    unsigned long max_reps = 1;                                         \
    if ( rep_prefix() )                                                 \
        max_reps = get_loop_count(&_regs, ad_bytes);                    \
    if ( max_reps == 0 )                                                \
    {                                                                   \
        /*                                                              \
         * Skip the instruction if no repetitions are required, but     \
         * zero extend involved registers first when using 32-bit       \
         * addressing in 64-bit mode.                                   \
         */                                                             \
        if ( mode_64bit() && ad_bytes == 4 )                            \
        {                                                               \
            _regs.r(cx) = 0;                                            \
            if ( using_si ) _regs.r(si) = _regs.esi;                    \
            if ( using_di ) _regs.r(di) = _regs.edi;                    \
        }                                                               \
        goto complete_insn;                                             \
    }                                                                   \
    if ( max_reps > 1 && (_regs.eflags & X86_EFLAGS_TF) &&              \
         !is_branch_step(ctxt, ops) )                                   \
        max_reps = 1;                                                   \
    max_reps;                                                           \
})

static void __put_rep_prefix(
    struct cpu_user_regs *int_regs,
    struct cpu_user_regs *ext_regs,
    int ad_bytes,
    unsigned long reps_completed)
{
    unsigned long ecx = get_loop_count(int_regs, ad_bytes);

    /* Reduce counter appropriately, and repeat instruction if non-zero. */
    ecx -= reps_completed;
    if ( ecx != 0 )
        int_regs->r(ip) = ext_regs->r(ip);

    put_loop_count(int_regs, ad_bytes, ecx);
}

#define put_rep_prefix(reps_completed) ({                               \
    if ( rep_prefix() )                                                 \
    {                                                                   \
        __put_rep_prefix(&_regs, ctxt->regs, ad_bytes, reps_completed); \
        if ( unlikely(rc == X86EMUL_EXCEPTION) )                        \
            goto complete_insn;                                         \
    }                                                                   \
})

/* Clip maximum repetitions so that the index register at most just wraps. */
#define truncate_ea_and_reps(ea, reps, bytes_per_rep) ({                  \
    unsigned long todo__, ea__ = truncate_ea(ea);                         \
    if ( !(_regs.eflags & X86_EFLAGS_DF) )                                \
        todo__ = truncate_ea(-ea__) / (bytes_per_rep);                    \
    else if ( truncate_ea(ea__ + (bytes_per_rep) - 1) < ea__ )            \
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
static bool mul_dbl(unsigned long m[2])
{
    bool rc;

    asm ( "mul %1" ASM_FLAG_OUT(, "; seto %2")
          : "+a" (m[0]), "+d" (m[1]), ASM_FLAG_OUT("=@cco", "=qm") (rc) );

    return rc;
}

/*
 * Signed multiplication with double-word result.
 * IN:  Multiplicand=m[0], Multiplier=m[1]
 * OUT: Return CF/OF (overflow status); Result=m[1]:m[0]
 */
static bool imul_dbl(unsigned long m[2])
{
    bool rc;

    asm ( "imul %1" ASM_FLAG_OUT(, "; seto %2")
          : "+a" (m[0]), "+d" (m[1]), ASM_FLAG_OUT("=@cco", "=qm") (rc) );

    return rc;
}

/*
 * Unsigned division of double-word dividend.
 * IN:  Dividend=u[1]:u[0], Divisor=v
 * OUT: Return 1: #DE
 *      Return 0: Quotient=u[0], Remainder=u[1]
 */
static bool div_dbl(unsigned long u[2], unsigned long v)
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
static bool idiv_dbl(unsigned long u[2], long v)
{
    bool negu = (long)u[1] < 0, negv = v < 0;

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

static bool
test_cc(
    unsigned int condition, unsigned int flags)
{
    int rc = 0;

    switch ( (condition & 15) >> 1 )
    {
    case 0: /* o */
        rc |= (flags & X86_EFLAGS_OF);
        break;
    case 1: /* b/c/nae */
        rc |= (flags & X86_EFLAGS_CF);
        break;
    case 2: /* z/e */
        rc |= (flags & X86_EFLAGS_ZF);
        break;
    case 3: /* be/na */
        rc |= (flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF));
        break;
    case 4: /* s */
        rc |= (flags & X86_EFLAGS_SF);
        break;
    case 5: /* p/pe */
        rc |= (flags & X86_EFLAGS_PF);
        break;
    case 7: /* le/ng */
        rc |= (flags & X86_EFLAGS_ZF);
        /* fall through */
    case 6: /* l/nge */
        rc |= (!(flags & X86_EFLAGS_SF) != !(flags & X86_EFLAGS_OF));
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

    if ( ctxt->regs->eflags & X86_EFLAGS_VM )
        return 3;

    if ( (ops->read_segment == NULL) ||
         ops->read_segment(x86_seg_ss, &reg, ctxt) )
        return -1;

    return reg.dpl;
}

static int
_mode_iopl(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    int cpl = get_cpl(ctxt, ops);
    if ( cpl == -1 )
        return -1;
    return cpl <= MASK_EXTR(ctxt->regs->eflags, X86_EFLAGS_IOPL);
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
#define mode_vif() ({                                        \
    cr4 = 0;                                                 \
    if ( ops->read_cr && get_cpl(ctxt, ops) == 3 )           \
    {                                                        \
        rc = ops->read_cr(4, &cr4, ctxt);                    \
        if ( rc != X86EMUL_OKAY ) goto done;                 \
    }                                                        \
    !!(cr4 & (_regs.eflags & X86_EFLAGS_VM ? X86_CR4_VME : X86_CR4_PVI)); \
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

    if ( !(ctxt->regs->eflags & X86_EFLAGS_VM) && mode_iopl() )
        return X86EMUL_OKAY;

    fail_if(ops->read_segment == NULL);
    /*
     * X86EMUL_DONE coming back here may be used to defer the port
     * permission check to the respective ioport hook.
     */
    if ( (rc = ops->read_segment(x86_seg_tr, &tr, ctxt)) != 0 )
        return rc == X86EMUL_DONE ? X86EMUL_OKAY : rc;

    /* Ensure the TSS has an io-bitmap-offset field. */
    generate_exception_if(tr.type != 0xb, EXC_GP, 0);

    switch ( rc = read_ulong(x86_seg_tr, 0x66, &iobmp, 2, ctxt, ops) )
    {
    case X86EMUL_OKAY:
        break;

    case X86EMUL_EXCEPTION:
        generate_exception_if(!ctxt->event_pending, EXC_GP, 0);
        /* fallthrough */

    default:
        return rc;
    }

    /* Read two bytes including byte containing first port. */
    switch ( rc = read_ulong(x86_seg_tr, iobmp + first_port / 8,
                             &iobmp, 2, ctxt, ops) )
    {
    case X86EMUL_OKAY:
        break;

    case X86EMUL_EXCEPTION:
        generate_exception_if(!ctxt->event_pending, EXC_GP, 0);
        /* fallthrough */

    default:
        return rc;
    }

    generate_exception_if(iobmp & (((1 << bytes) - 1) << (first_port & 7)),
                          EXC_GP, 0);

 done:
    return rc;
}

static bool
in_realmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    unsigned long cr0;
    int rc;

    if ( ops->read_cr == NULL )
        return 0;

    rc = ops->read_cr(0, &cr0, ctxt);
    return (!rc && !(cr0 & X86_CR0_PE));
}

static bool
in_protmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    return !(in_realmode(ctxt, ops) || (ctxt->regs->eflags & X86_EFLAGS_VM));
}

static bool
_amd_like(const struct cpuid_policy *cp)
{
    return cp->x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON);
}

static bool
amd_like(const struct x86_emulate_ctxt *ctxt)
{
    return _amd_like(ctxt->cpuid);
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
#define vcpu_has_avx512pf()    (ctxt->cpuid->feat.avx512pf)
#define vcpu_has_avx512er()    (ctxt->cpuid->feat.avx512er)
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
#define vcpu_has_tsxldtrk()    (ctxt->cpuid->feat.tsxldtrk)
#define vcpu_has_rdpid()       (ctxt->cpuid->feat.rdpid)
#define vcpu_has_movdiri()     (ctxt->cpuid->feat.movdiri)
#define vcpu_has_movdir64b()   (ctxt->cpuid->feat.movdir64b)
#define vcpu_has_enqcmd()      (ctxt->cpuid->feat.enqcmd)
#define vcpu_has_avx512_4vnniw() (ctxt->cpuid->feat.avx512_4vnniw)
#define vcpu_has_avx512_4fmaps() (ctxt->cpuid->feat.avx512_4fmaps)
#define vcpu_has_serialize()   (ctxt->cpuid->feat.serialize)
#define vcpu_has_avx512_bf16() (ctxt->cpuid->feat.avx512_bf16)

#define vcpu_must_have(feat) \
    generate_exception_if(!vcpu_has_##feat(), EXC_UD)

#ifdef __XEN__
/*
 * Note the difference between vcpu_must_have(<feature>) and
 * host_and_vcpu_must_have(<feature>): The latter needs to be used when
 * emulation code is using the same instruction class for carrying out
 * the actual operation.
 */
#define host_and_vcpu_must_have(feat) ({ \
    generate_exception_if(!cpu_has_##feat, EXC_UD); \
    vcpu_must_have(feat); \
})
#else
/*
 * For the test harness both are fine to be used interchangeably, i.e.
 * features known to always be available (e.g. SSE/SSE2) to (64-bit) Xen
 * may be checked for by just vcpu_must_have().
 */
#define host_and_vcpu_must_have(feat) vcpu_must_have(feat)
#endif

/* Initialise output state in x86_emulate_ctxt */
static void init_context(struct x86_emulate_ctxt *ctxt)
{
    ctxt->retire.raw = 0;
    x86_emul_reset_event(ctxt);
}

static int
realmode_load_seg(
    enum x86_segment seg,
    uint16_t sel,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc;

    if ( !ops->read_segment )
        return X86EMUL_UNHANDLEABLE;

    if ( (rc = ops->read_segment(seg, sreg, ctxt)) == X86EMUL_OKAY )
    {
        sreg->sel  = sel;
        sreg->base = (uint32_t)sel << 4;
    }

    return rc;
}

/*
 * Passing in x86_seg_none means
 * - suppress any exceptions other than #PF,
 * - don't commit any state.
 */
static int
protmode_load_seg(
    enum x86_segment seg,
    uint16_t sel, bool is_ret,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    const struct cpuid_policy *cp = ctxt->cpuid;
    enum x86_segment sel_seg = (sel & 4) ? x86_seg_ldtr : x86_seg_gdtr;
    struct { uint32_t a, b; } desc, desc_hi = {};
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
        if ( !_amd_like(cp) || !ops->read_segment ||
             ops->read_segment(seg, sreg, ctxt) != X86EMUL_OKAY )
            memset(sreg, 0, sizeof(*sreg));
        else
            sreg->attr = 0;
        sreg->sel = sel;

        /* Since CPL == SS.DPL, we need to put back DPL. */
        if ( seg == x86_seg_ss )
            sreg->dpl = sel;

        return X86EMUL_OKAY;
    }

    /* System segment descriptors must reside in the GDT. */
    if ( is_x86_system_segment(seg) && (sel & 4) )
        goto raise_exn;

    switch ( rc = ops->read(sel_seg, sel & 0xfff8, &desc, sizeof(desc), ctxt) )
    {
    case X86EMUL_OKAY:
        break;

    case X86EMUL_EXCEPTION:
        if ( !ctxt->event_pending )
            goto raise_exn;
        /* fallthrough */

    default:
        return rc;
    }

    /* System segments must have S flag == 0. */
    if ( is_x86_system_segment(seg) && (desc.b & (1u << 12)) )
        goto raise_exn;
    /* User segments must have S flag == 1. */
    if ( is_x86_user_segment(seg) && !(desc.b & (1u << 12)) )
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
        if ( ctxt->lma && (desc.b & (1 << 21)) && (desc.b & (1 << 22)) )
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
    case x86_seg_none:
        /* Non-conforming segment: check DPL against RPL and CPL. */
        if ( ((desc.b & (0x1c << 8)) != (0x1c << 8)) &&
             ((dpl < cpl) || (dpl < rpl)) )
            return X86EMUL_EXCEPTION;
        a_flag = 0;
        break;
    }

    /* Segment present in memory? */
    if ( !(desc.b & (1 << 15)) && seg != x86_seg_none )
    {
        fault_type = seg != x86_seg_ss ? EXC_NP : EXC_SS;
        goto raise_exn;
    }

    if ( !is_x86_user_segment(seg) )
    {
        /*
         * Whether to use an 8- or 16-byte descriptor in long mode depends
         * on sub-mode, descriptor type, and vendor:
         * - non-system descriptors are always 8-byte ones,
         * - system descriptors are always 16-byte ones in 64-bit mode,
         * - (call) gates are always 16-byte ones,
         * - other system descriptors in compatibility mode have
         *   - only their low 8-byte bytes read on Intel,
         *   - all 16 bytes read with the high 8 bytes ignored on AMD.
         */
        bool wide = desc.b & 0x1000
                    ? false : (desc.b & 0xf00) != 0xc00 && !_amd_like(cp)
                               ? mode_64bit() : ctxt->lma;

        if ( wide )
        {
            switch ( rc = ops->read(sel_seg, (sel & 0xfff8) + 8,
                                    &desc_hi, sizeof(desc_hi), ctxt) )
            {
            case X86EMUL_OKAY:
                break;

            case X86EMUL_EXCEPTION:
                if ( !ctxt->event_pending )
                    goto raise_exn;
                /* fall through */
            default:
                return rc;
            }
            if ( !mode_64bit() && _amd_like(cp) && (desc.b & 0xf00) != 0xc00 )
                desc_hi.b = desc_hi.a = 0;
            if ( (desc_hi.b & 0x00001f00) ||
                 (seg != x86_seg_none &&
                  !is_canonical_address((uint64_t)desc_hi.a << 32)) )
                goto raise_exn;
        }
    }

    /* Ensure Accessed flag is set. */
    if ( a_flag && !(desc.b & a_flag) )
    {
        uint32_t new_desc_b = desc.b | a_flag;

        fail_if(!ops->cmpxchg);
        switch ( (rc = ops->cmpxchg(sel_seg, (sel & 0xfff8) + 4, &desc.b,
                                    &new_desc_b, sizeof(desc.b), true, ctxt)) )
        {
        case X86EMUL_OKAY:
            break;

        case X86EMUL_EXCEPTION:
            if ( !ctxt->event_pending )
                goto raise_exn;
            /* fallthrough */

        default:
            return rc;

        case X86EMUL_CMPXCHG_FAILED:
            return X86EMUL_RETRY;
        }

        /* Force the Accessed flag in our local copy. */
        desc.b = new_desc_b;
    }

    sreg->base = (((uint64_t)desc_hi.a << 32) |
                  ((desc.b <<  0) & 0xff000000u) |
                  ((desc.b << 16) & 0x00ff0000u) |
                  ((desc.a >> 16) & 0x0000ffffu));
    sreg->attr = (((desc.b >>  8) & 0x00ffu) |
                  ((desc.b >> 12) & 0x0f00u));
    sreg->limit = (desc.b & 0x000f0000u) | (desc.a & 0x0000ffffu);
    if ( sreg->g )
        sreg->limit = (sreg->limit << 12) | 0xfffu;
    sreg->sel = sel;
    return X86EMUL_OKAY;

 raise_exn:
    generate_exception_if(seg != x86_seg_none, fault_type, sel & 0xfffc);
    rc = X86EMUL_EXCEPTION;
 done:
    return rc;
}

static int
load_seg(
    enum x86_segment seg,
    uint16_t sel, bool is_ret,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    struct segment_register reg;
    int rc;

    if ( !ops->write_segment )
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

/* Map GPRs by ModRM encoding to their offset within struct cpu_user_regs. */
const uint8_t cpu_user_regs_gpr_offsets[] = {
    offsetof(struct cpu_user_regs, r(ax)),
    offsetof(struct cpu_user_regs, r(cx)),
    offsetof(struct cpu_user_regs, r(dx)),
    offsetof(struct cpu_user_regs, r(bx)),
    offsetof(struct cpu_user_regs, r(sp)),
    offsetof(struct cpu_user_regs, r(bp)),
    offsetof(struct cpu_user_regs, r(si)),
    offsetof(struct cpu_user_regs, r(di)),
#ifdef __x86_64__
    offsetof(struct cpu_user_regs, r8),
    offsetof(struct cpu_user_regs, r9),
    offsetof(struct cpu_user_regs, r10),
    offsetof(struct cpu_user_regs, r11),
    offsetof(struct cpu_user_regs, r12),
    offsetof(struct cpu_user_regs, r13),
    offsetof(struct cpu_user_regs, r14),
    offsetof(struct cpu_user_regs, r15),
#endif
};

static void *_decode_gpr(
    struct cpu_user_regs *regs, unsigned int modrm_reg, bool legacy)
{
    static const uint8_t byte_reg_offsets[] = {
        offsetof(struct cpu_user_regs, al),
        offsetof(struct cpu_user_regs, cl),
        offsetof(struct cpu_user_regs, dl),
        offsetof(struct cpu_user_regs, bl),
        offsetof(struct cpu_user_regs, ah),
        offsetof(struct cpu_user_regs, ch),
        offsetof(struct cpu_user_regs, dh),
        offsetof(struct cpu_user_regs, bh),
    };

    if ( !legacy )
        return decode_gpr(regs, modrm_reg);

    /* Check that the array is a power of two. */
    BUILD_BUG_ON(ARRAY_SIZE(byte_reg_offsets) &
                 (ARRAY_SIZE(byte_reg_offsets) - 1));

    ASSERT(modrm_reg < ARRAY_SIZE(byte_reg_offsets));

    /* Note that this also acts as array_access_nospec() stand-in. */
    modrm_reg &= ARRAY_SIZE(byte_reg_offsets) - 1;

    return (void *)regs + byte_reg_offsets[modrm_reg];
}

static unsigned long *decode_vex_gpr(
    unsigned int vex_reg, struct cpu_user_regs *regs,
    const struct x86_emulate_ctxt *ctxt)
{
    return decode_gpr(regs, ~vex_reg & (mode_64bit() ? 0xf : 7));
}

static unsigned int decode_disp8scale(enum disp8scale scale,
                                      const struct x86_emulate_state *state)
{
    switch ( scale )
    {
    case d8s_bw:
        return state->evex.w;

    default:
        if ( scale < d8s_vl )
            return scale;
        if ( state->evex.brs )
        {
    case d8s_dq:
            return 2 + state->evex.w;
        }
        break;

    case d8s_dq64:
        return 2 + (state->op_bytes == 8);
    }

    switch ( state->simd_size )
    {
    case simd_any_fp:
    case simd_single_fp:
        if ( !(state->evex.pfx & VEX_PREFIX_SCALAR_MASK) )
            break;
        /* fall through */
    case simd_scalar_opc:
    case simd_scalar_vexw:
        return 2 + state->evex.w;

    case simd_128:
        /* These should have an explicit size specified. */
        ASSERT_UNREACHABLE();
        return 4;

    default:
        break;
    }

    return 4 + state->evex.lr - (scale - d8s_vl);
}

#define avx512_vlen_check(lig) do { \
    switch ( evex.lr ) \
    { \
    default: \
        generate_exception(EXC_UD); \
    case 2: \
        break; \
    case 0: case 1: \
        if ( !(lig) ) \
            host_and_vcpu_must_have(avx512vl); \
        break; \
    } \
} while ( false )

static bool is_aligned(enum x86_segment seg, unsigned long offs,
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

static bool is_branch_step(struct x86_emulate_ctxt *ctxt,
                           const struct x86_emulate_ops *ops)
{
    uint64_t debugctl;

    return ops->read_msr &&
           ops->read_msr(MSR_IA32_DEBUGCTLMSR, &debugctl, ctxt) == X86EMUL_OKAY &&
           (debugctl & IA32_DEBUGCTLMSR_BTF);
}

static bool umip_active(struct x86_emulate_ctxt *ctxt,
                        const struct x86_emulate_ops *ops)
{
    unsigned long cr4;

    /* Intentionally not using mode_ring0() here to avoid its fail_if(). */
    return get_cpl(ctxt, ops) > 0 &&
           ops->read_cr && ops->read_cr(4, &cr4, ctxt) == X86EMUL_OKAY &&
           (cr4 & X86_CR4_UMIP);
}

static void adjust_bnd(struct x86_emulate_ctxt *ctxt,
                       const struct x86_emulate_ops *ops, enum vex_pfx pfx)
{
    uint64_t xcr0, bndcfg;
    int rc;

    if ( pfx == vex_f2 || !cpu_has_mpx || !vcpu_has_mpx() )
        return;

    if ( !ops->read_xcr || ops->read_xcr(0, &xcr0, ctxt) != X86EMUL_OKAY ||
         !(xcr0 & X86_XCR0_BNDREGS) || !(xcr0 & X86_XCR0_BNDCSR) )
        return;

    if ( !mode_ring0() )
        bndcfg = read_bndcfgu();
    else if ( !ops->read_msr ||
              ops->read_msr(MSR_IA32_BNDCFGS, &bndcfg, ctxt) != X86EMUL_OKAY )
        return;
    if ( (bndcfg & IA32_BNDCFGS_ENABLE) && !(bndcfg & IA32_BNDCFGS_PRESERVE) )
    {
        /*
         * Using BNDMK or any other MPX instruction here is pointless, as
         * we run with MPX disabled ourselves, and hence they're all no-ops.
         * Therefore we have two ways to clear BNDn: Enable MPX temporarily
         * (in which case executing any suitable non-prefixed branch
         * instruction would do), or use XRSTOR.
         */
        xstate_set_init(X86_XCR0_BNDREGS);
    }
 done:;
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
#define evex_encoded() (evex.mbs)
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
    case 0x06: /* push %%es */
    case 0x07: /* pop %%es */
    case 0x0e: /* push %%cs */
    case 0x16: /* push %%ss */
    case 0x17: /* pop %%ss */
    case 0x1e: /* push %%ds */
    case 0x1f: /* pop %%ds */
    case 0x27: /* daa */
    case 0x2f: /* das */
    case 0x37: /* aaa */
    case 0x3f: /* aas */
    case 0x60: /* pusha */
    case 0x61: /* popa */
    case 0x62: /* bound */
    case 0xc4: /* les */
    case 0xc5: /* lds */
    case 0xce: /* into */
    case 0xd4: /* aam */
    case 0xd5: /* aad */
    case 0xd6: /* salc */
        state->not_64bit = true;
        break;

    case 0x82: /* Grp1 (x86/32 only) */
        state->not_64bit = true;
        /* fall through */
    case 0x80: case 0x81: case 0x83: /* Grp1 */
        if ( (modrm_reg & 7) == 7 ) /* cmp */
            state->desc = (state->desc & ByteOp) | DstNone | SrcMem;
        break;

    case 0x90: /* nop / pause */
        if ( repe_prefix() )
            ctxt->opcode |= X86EMUL_OPC_F3(0, 0);
        break;

    case 0x9a: /* call (far, absolute) */
    case 0xea: /* jmp (far, absolute) */
        generate_exception_if(mode_64bit(), EXC_UD);

        imm1 = insn_fetch_bytes(op_bytes);
        imm2 = insn_fetch_type(uint16_t);
        break;

    case 0xa0: case 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2: case 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        /* Source EA is not encoded via ModRM. */
        ea.type = OP_MEM;
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

    case 0xf6: case 0xf7: /* Grp3 */
        if ( !(modrm_reg & 6) ) /* test */
            state->desc = (state->desc & ByteOp) | DstNone | SrcMem;
        break;

    case 0xff: /* Grp5 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* call (near) */
        case 4: /* jmp (near) */
            if ( mode_64bit() && (op_bytes == 4 || !amd_like(ctxt)) )
                op_bytes = 8;
            state->desc = DstNone | SrcMem | Mov;
            break;

        case 3: /* call (far, absolute indirect) */
        case 5: /* jmp (far, absolute indirect) */
            /* REX.W ignored on a vendor-dependent basis. */
            if ( op_bytes == 8 && amd_like(ctxt) )
                op_bytes = 4;
            state->desc = DstNone | SrcMem | Mov;
            break;

        case 6: /* push */
            if ( mode_64bit() && op_bytes == 4 )
                op_bytes = 8;
            state->desc = DstNone | SrcMem | Mov;
            break;
        }
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
    case 0x00: /* Grp6 */
        switch ( modrm_reg & 6 )
        {
        case 0:
            state->desc |= DstMem | SrcImplicit | Mov;
            break;
        case 2: case 4:
            state->desc |= SrcMem16;
            break;
        }
        break;

    case 0x78:
        state->desc = ImplicitOps;
        state->simd_size = simd_none;
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
    case 0x7a ... 0x7d:
    case 0x7f:
    case 0xc2 ... 0xc3:
    case 0xc5 ... 0xc6:
    case 0xd0 ... 0xef:
    case 0xf1 ... 0xfe:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0x20: case 0x22: /* mov to/from cr */
        if ( lock_prefix && vcpu_has_cr8_legacy() )
        {
            modrm_reg += 8;
            lock_prefix = false;
        }
        /* fall through */
    case 0x21: case 0x23: /* mov to/from dr */
        ASSERT(ea.type == OP_REG); /* Early operand adjustment ensures this. */
        generate_exception_if(lock_prefix, EXC_UD);
        op_bytes = mode_64bit() ? 8 : 4;
        break;

    case 0x79:
        state->desc = DstReg | SrcMem;
        state->simd_size = simd_packed_int;
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0x7e:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        if ( vex.pfx == vex_f3 ) /* movq xmm/m64,xmm */
        {
    case X86EMUL_OPC_VEX_F3(0, 0x7e): /* vmovq xmm/m64,xmm */
    case X86EMUL_OPC_EVEX_F3(0, 0x7e): /* vmovq xmm/m64,xmm */
            state->desc = DstImplicit | SrcMem | TwoOp;
            state->simd_size = simd_other;
            /* Avoid the state->desc clobbering of TwoOp below. */
            return X86EMUL_OKAY;
        }
        break;

    case X86EMUL_OPC_VEX(0, 0x90):    /* kmov{w,q} */
    case X86EMUL_OPC_VEX_66(0, 0x90): /* kmov{b,d} */
        state->desc = DstReg | SrcMem | Mov;
        state->simd_size = simd_other;
        break;

    case X86EMUL_OPC_VEX(0, 0x91):    /* kmov{w,q} */
    case X86EMUL_OPC_VEX_66(0, 0x91): /* kmov{b,d} */
        state->desc = DstMem | SrcReg | Mov;
        state->simd_size = simd_other;
        break;

    case 0xae:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        /* fall through */
    case X86EMUL_OPC_VEX(0, 0xae):
        switch ( modrm_reg & 7 )
        {
        case 2: /* {,v}ldmxcsr */
            state->desc = DstImplicit | SrcMem | Mov;
            op_bytes = 4;
            break;

        case 3: /* {,v}stmxcsr */
            state->desc = DstMem | SrcImplicit | Mov;
            op_bytes = 4;
            break;
        }
        break;

    case 0xb2: /* lss */
    case 0xb4: /* lfs */
    case 0xb5: /* lgs */
        /* REX.W ignored on a vendor-dependent basis. */
        if ( op_bytes == 8 && amd_like(ctxt) )
            op_bytes = 4;
        break;

    case 0xb8: /* jmpe / popcnt */
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

        /* Intentionally not handling here despite being modified by F3:
    case 0xbc: bsf / tzcnt
    case 0xbd: bsr / lzcnt
         * They're being dealt with in the execution phase (if at all).
         */

    case 0xc4: /* pinsrw */
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0, 0xc4): /* vpinsrw */
    case X86EMUL_OPC_EVEX_66(0, 0xc4): /* vpinsrw */
        state->desc = DstReg | SrcMem16;
        break;

    case 0xf0:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        if ( vex.pfx == vex_f2 ) /* lddqu mem,xmm */
        {
        /* fall through */
    case X86EMUL_OPC_VEX_F2(0, 0xf0): /* vlddqu mem,{x,y}mm */
            state->desc = DstImplicit | SrcMem | TwoOp;
            state->simd_size = simd_other;
            /* Avoid the state->desc clobbering of TwoOp below. */
            return X86EMUL_OKAY;
        }
        break;
    }

    /*
     * Scalar forms of most VEX-/EVEX-encoded TwoOp instructions have
     * three operands.  Those which do really have two operands
     * should have exited earlier.
     */
    if ( state->simd_size && vex.opcx &&
         (vex.pfx & VEX_PREFIX_SCALAR_MASK) )
        state->desc &= ~TwoOp;

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
    case 0xf2 ... 0xf5:
    case 0xf7 ... 0xf8:
    case 0xfa ... 0xff:
        op_bytes = 0;
        /* fall through */
    case 0xf6: /* adcx / adox */
    case 0xf9: /* movdiri */
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case X86EMUL_OPC_EVEX_66(0, 0x2d): /* vscalefs{s,d} */
        state->simd_size = simd_scalar_vexw;
        break;

    case X86EMUL_OPC_EVEX_66(0, 0x7a): /* vpbroadcastb */
    case X86EMUL_OPC_EVEX_66(0, 0x7b): /* vpbroadcastw */
    case X86EMUL_OPC_EVEX_66(0, 0x7c): /* vpbroadcast{d,q} */
        break;

    case 0xf0: /* movbe / crc32 */
        state->desc |= repne_prefix() ? ByteOp : Mov;
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0xf1: /* movbe / crc32 */
        if ( repne_prefix() )
            state->desc = DstReg | SrcMem;
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case X86EMUL_OPC_VEX(0, 0xf2):    /* andn */
    case X86EMUL_OPC_VEX(0, 0xf3):    /* Grp 17 */
    case X86EMUL_OPC_VEX(0, 0xf5):    /* bzhi */
    case X86EMUL_OPC_VEX_F3(0, 0xf5): /* pext */
    case X86EMUL_OPC_VEX_F2(0, 0xf5): /* pdep */
    case X86EMUL_OPC_VEX_F2(0, 0xf6): /* mulx */
    case X86EMUL_OPC_VEX(0, 0xf7):    /* bextr */
    case X86EMUL_OPC_VEX_66(0, 0xf7): /* shlx */
    case X86EMUL_OPC_VEX_F3(0, 0xf7): /* sarx */
    case X86EMUL_OPC_VEX_F2(0, 0xf7): /* shrx */
        break;

    default:
        op_bytes = 0;
        break;
    }

    return X86EMUL_OKAY;
}

static int
x86_decode_0f3a(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    if ( !vex.opcx )
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);

    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case X86EMUL_OPC_66(0, 0x14)
     ... X86EMUL_OPC_66(0, 0x17):     /* pextr*, extractps */
    case X86EMUL_OPC_VEX_66(0, 0x14)
     ... X86EMUL_OPC_VEX_66(0, 0x17): /* vpextr*, vextractps */
    case X86EMUL_OPC_EVEX_66(0, 0x14)
     ... X86EMUL_OPC_EVEX_66(0, 0x17): /* vpextr*, vextractps */
    case X86EMUL_OPC_VEX_F2(0, 0xf0): /* rorx */
        break;

    case X86EMUL_OPC_66(0, 0x20):     /* pinsrb */
    case X86EMUL_OPC_VEX_66(0, 0x20): /* vpinsrb */
    case X86EMUL_OPC_EVEX_66(0, 0x20): /* vpinsrb */
        state->desc = DstImplicit | SrcMem;
        if ( modrm_mod != 3 )
            state->desc |= ByteOp;
        break;

    case X86EMUL_OPC_66(0, 0x22):     /* pinsr{d,q} */
    case X86EMUL_OPC_VEX_66(0, 0x22): /* vpinsr{d,q} */
    case X86EMUL_OPC_EVEX_66(0, 0x22): /* vpinsr{d,q} */
        state->desc = DstImplicit | SrcMem;
        break;

    default:
        op_bytes = 0;
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
    uint8_t b, d;
    unsigned int def_op_bytes, def_ad_bytes, opcode;
    enum x86_segment override_seg = x86_seg_none;
    bool pc_rel = false;
    int rc = X86EMUL_OKAY;

    ASSERT(ops->insn_fetch);

    memset(state, 0, sizeof(*state));
    ea.type = OP_NONE;
    ea.mem.seg = x86_seg_ds;
    ea.reg = PTR_POISON;
    state->regs = ctxt->regs;
    state->ip = ctxt->regs->r(ip);

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
        case 0x2e: /* CS override / ignored in 64-bit mode */
            if ( !mode_64bit() )
                override_seg = x86_seg_cs;
            break;
        case 0x3e: /* DS override / ignored in 64-bit mode */
            if ( !mode_64bit() )
                override_seg = x86_seg_ds;
            break;
        case 0x26: /* ES override / ignored in 64-bit mode */
            if ( !mode_64bit() )
                override_seg = x86_seg_es;
            break;
        case 0x64: /* FS override */
            override_seg = x86_seg_fs;
            break;
        case 0x65: /* GS override */
            override_seg = x86_seg_gs;
            break;
        case 0x36: /* SS override / ignored in 64-bit mode */
            if ( !mode_64bit() )
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
        d = twobyte_table[b].desc;
        switch ( b )
        {
        default:
            opcode = b | MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f;
            state->simd_size = twobyte_table[b].size;
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
                if ( state->regs->eflags & X86_EFLAGS_VM )
                    break;
                /* fall through */
            case 4:
                if ( modrm_mod != 3 || in_realmode(ctxt, ops) )
                    break;
                /* fall through */
            case 8:
                /* VEX / XOP / EVEX */
                generate_exception_if(rex_prefix || vex.pfx, EXC_UD);
                /*
                 * With operand size override disallowed (see above), op_bytes
                 * should not have changed from its default.
                 */
                ASSERT(op_bytes == def_op_bytes);

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
                    else
                    {
                        /* Operand size fixed at 4 (no override via W bit). */
                        op_bytes = 4;
                        vex.b = 1;
                    }
                    switch ( b )
                    {
                    case 0x62:
                        opcode = X86EMUL_OPC_EVEX_;
                        evex.raw[0] = vex.raw[0];
                        evex.raw[1] = vex.raw[1];
                        evex.raw[2] = insn_fetch_type(uint8_t);

                        generate_exception_if(!evex.mbs || evex.mbz, EXC_UD);
                        generate_exception_if(!evex.opmsk && evex.z, EXC_UD);

                        if ( !mode_64bit() )
                            evex.R = 1;

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
                if ( !vex.r )
                    rex_prefix |= REX_R;

                ext = vex.opcx;
                if ( b != 0x8f )
                {
                    b = insn_fetch_type(uint8_t);
                    switch ( ext )
                    {
                    case vex_0f:
                        opcode |= MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[b].desc;
                        state->simd_size = twobyte_table[b].size;
                        break;
                    case vex_0f38:
                        opcode |= MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x38].desc;
                        break;
                    case vex_0f3a:
                        opcode |= MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x3a].desc;
                        break;
                    default:
                        rc = X86EMUL_UNRECOGNIZED;
                        goto done;
                    }
                }
                else if ( ext < ext_8f08 + ARRAY_SIZE(xop_table) )
                {
                    b = insn_fetch_type(uint8_t);
                    opcode |= MASK_INSR(0x8f08 + ext - ext_8f08,
                                        X86EMUL_OPC_EXT_MASK);
                    d = array_access_nospec(xop_table, ext - ext_8f08);
                }
                else
                {
                    rc = X86EMUL_UNRECOGNIZED;
                    goto done;
                }

                opcode |= b | MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);

                if ( !evex_encoded() )
                    evex.lr = vex.l;

                if ( !(d & ModRM) )
                    break;

                modrm = insn_fetch_type(uint8_t);
                modrm_mod = (modrm & 0xc0) >> 6;

                break;
            }
    }

    if ( d & ModRM )
    {
        unsigned int disp8scale = 0;

        d &= ~ModRM;
#undef ModRM /* Only its aliases are valid to use from here on. */
        modrm_reg = ((rex_prefix & 4) << 1) | ((modrm & 0x38) >> 3) |
                    ((evex_encoded() && !evex.R) << 4);
        modrm_rm  = modrm & 0x07;

        /*
         * Early operand adjustments. Only ones affecting further processing
         * prior to the x86_decode_*() calls really belong here. That would
         * normally be only addition/removal of SrcImm/SrcImm16, so their
         * fetching can be taken care of by the common code below.
         */
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
            }
            break;

        case ext_0f:
            if ( evex_encoded() )
                disp8scale = decode_disp8scale(twobyte_table[b].d8s, state);

            switch ( b )
            {
            case 0x12: /* vmovsldup / vmovddup */
                if ( evex.pfx == vex_f2 )
                    disp8scale = evex.lr ? 4 + evex.lr : 3;
                /* fall through */
            case 0x16: /* vmovshdup */
                if ( evex.pfx == vex_f3 )
                    disp8scale = 4 + evex.lr;
                break;

            case 0x20: /* mov cr,reg */
            case 0x21: /* mov dr,reg */
            case 0x22: /* mov reg,cr */
            case 0x23: /* mov reg,dr */
                /*
                 * Mov to/from cr/dr ignore the encoding of Mod, and behave as
                 * if they were encoded as reg/reg instructions.  No futher
                 * disp/SIB bytes are fetched.
                 */
                modrm_mod = 3;
                break;

            case 0x78:
            case 0x79:
                if ( !evex.pfx )
                    break;
                /* vcvt{,t}ps2uqq need special casing */
                if ( evex.pfx == vex_66 )
                {
                    if ( !evex.w && !evex.brs )
                        --disp8scale;
                    break;
                }
                /* vcvt{,t}s{s,d}2usi need special casing: fall through */
            case 0x2c: /* vcvtts{s,d}2si need special casing */
            case 0x2d: /* vcvts{s,d}2si need special casing */
                if ( evex_encoded() )
                    disp8scale = 2 + (evex.pfx & VEX_PREFIX_DOUBLE_MASK);
                break;

            case 0x5a: /* vcvtps2pd needs special casing */
                if ( disp8scale && !evex.pfx && !evex.brs )
                    --disp8scale;
                break;

            case 0x7a: /* vcvttps2qq and vcvtudq2pd need special casing */
                if ( disp8scale && evex.pfx != vex_f2 && !evex.w && !evex.brs )
                    --disp8scale;
                break;

            case 0x7b: /* vcvtp{s,d}2qq need special casing */
                if ( disp8scale && evex.pfx == vex_66 )
                    disp8scale = (evex.brs ? 2 : 3 + evex.lr) + evex.w;
                break;

            case 0x7e: /* vmovq xmm/m64,xmm needs special casing */
                if ( disp8scale == 2 && evex.pfx == vex_f3 )
                    disp8scale = 3;
                break;

            case 0xe6: /* vcvtdq2pd needs special casing */
                if ( disp8scale && evex.pfx == vex_f3 && !evex.w && !evex.brs )
                    --disp8scale;
                break;
            }
            break;

        case ext_0f38:
            d = ext0f38_table[b].to_mem ? DstMem | SrcReg
                                        : DstReg | SrcMem;
            if ( ext0f38_table[b].two_op )
                d |= TwoOp;
            if ( ext0f38_table[b].vsib )
                d |= vSIB;
            state->simd_size = ext0f38_table[b].simd_size;
            if ( evex_encoded() )
            {
                /*
                 * VPMOVUS* are identical to VPMOVS* Disp8-scaling-wise, but
                 * their attributes don't match those of the vex_66 encoded
                 * insns with the same base opcodes. Rather than adding new
                 * columns to the table, handle this here for now.
                 */
                if ( evex.pfx != vex_f3 || (b & 0xf8) != 0x10 )
                    disp8scale = decode_disp8scale(ext0f38_table[b].d8s, state);
                else
                {
                    disp8scale = decode_disp8scale(ext0f38_table[b ^ 0x30].d8s,
                                                   state);
                    state->simd_size = simd_other;
                }

                switch ( b )
                {
                /* vp4dpwssd{,s} need special casing */
                case 0x52: case 0x53:
                /* v4f{,n}madd{p,s}s need special casing */
                case 0x9a: case 0x9b: case 0xaa: case 0xab:
                    if ( evex.pfx == vex_f2 )
                    {
                        disp8scale = 4;
                        state->simd_size = simd_128;
                    }
                    break;
                }
            }
            break;

        case ext_0f3a:
            /*
             * Cannot update d here yet, as the immediate operand still
             * needs fetching.
             */
            state->simd_size = ext0f3a_table[b].simd_size;
            if ( evex_encoded() )
                disp8scale = decode_disp8scale(ext0f3a_table[b].d8s, state);
            break;

        case ext_8f09:
            if ( ext8f09_table[b].two_op )
                d |= TwoOp;
            state->simd_size = ext8f09_table[b].simd_size;
            break;

        case ext_8f08:
        case ext_8f0a:
            /*
             * Cannot update d here yet, as the immediate operand still
             * needs fetching.
             */
            break;

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNIMPLEMENTED;
        }

        if ( modrm_mod == 3 )
        {
            generate_exception_if(d & vSIB, EXC_UD);
            modrm_rm |= ((rex_prefix & 1) << 3) |
                        (evex_encoded() && !evex.x) << 4;
            ea.type = OP_REG;
        }
        else if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            generate_exception_if(d & vSIB, EXC_UD);
            ea.type = OP_MEM;
            switch ( modrm_rm )
            {
            case 0:
                ea.mem.off = state->regs->bx + state->regs->si;
                break;
            case 1:
                ea.mem.off = state->regs->bx + state->regs->di;
                break;
            case 2:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->bp + state->regs->si;
                break;
            case 3:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->bp + state->regs->di;
                break;
            case 4:
                ea.mem.off = state->regs->si;
                break;
            case 5:
                ea.mem.off = state->regs->di;
                break;
            case 6:
                if ( modrm_mod == 0 )
                    break;
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->bp;
                break;
            case 7:
                ea.mem.off = state->regs->bx;
                break;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( modrm_rm == 6 )
                    ea.mem.off = insn_fetch_type(int16_t);
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t) << disp8scale;
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int16_t);
                break;
            }
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            ea.type = OP_MEM;
            if ( modrm_rm == 4 )
            {
                uint8_t sib = insn_fetch_type(uint8_t);
                uint8_t sib_base = (sib & 7) | ((rex_prefix << 3) & 8);

                state->sib_index = ((sib >> 3) & 7) | ((rex_prefix << 2) & 8);
                state->sib_scale = (sib >> 6) & 3;
                if ( unlikely(d & vSIB) )
                    state->sib_index |= (mode_64bit() && evex_encoded() &&
                                         !evex.RX) << 4;
                else if ( state->sib_index != 4 )
                {
                    ea.mem.off = *decode_gpr(state->regs, state->sib_index);
                    ea.mem.off <<= state->sib_scale;
                }
                if ( (modrm_mod == 0) && ((sib_base & 7) == 5) )
                    ea.mem.off += insn_fetch_type(int32_t);
                else if ( sib_base == 4 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += state->regs->r(sp);
                    if ( !ext && (b == 0x8f) )
                        /* POP <rm> computes its EA post increment. */
                        ea.mem.off += ((mode_64bit() && (op_bytes == 4))
                                       ? 8 : op_bytes);
                }
                else if ( sib_base == 5 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += state->regs->r(bp);
                }
                else
                    ea.mem.off += *decode_gpr(state->regs, sib_base);
            }
            else
            {
                generate_exception_if(d & vSIB, EXC_UD);
                modrm_rm |= (rex_prefix & 1) << 3;
                ea.mem.off = *decode_gpr(state->regs, modrm_rm);
                if ( (modrm_rm == 5) && (modrm_mod != 0) )
                    ea.mem.seg = x86_seg_ss;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( (modrm_rm & 7) != 5 )
                    break;
                ea.mem.off = insn_fetch_type(int32_t);
                pc_rel = mode_64bit();
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t) << disp8scale;
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int32_t);
                break;
            }
        }
    }
    else
    {
        modrm_mod = 0xff;
        modrm_reg = modrm_rm = modrm = 0;
    }

    if ( override_seg != x86_seg_none )
        ea.mem.seg = override_seg;

    /* Fetch the immediate operand, if present. */
    switch ( d & SrcMask )
    {
        unsigned int bytes;

    case SrcImm:
        if ( !(d & ByteOp) )
        {
            if ( mode_64bit() && !amd_like(ctxt) &&
                 ((ext == ext_none && (b | 1) == 0xe9) /* call / jmp */ ||
                  (ext == ext_0f && (b | 0xf) == 0x8f) /* jcc */ ) )
                op_bytes = 4;
            bytes = op_bytes != 8 ? op_bytes : 4;
        }
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
        d = ext0f3a_table[b].to_mem ? DstMem | SrcReg : DstReg | SrcMem;
        if ( ext0f3a_table[b].two_op )
            d |= TwoOp;
        else if ( ext0f3a_table[b].four_op && !mode_64bit() && vex.opcx )
            imm1 &= 0x7f;
        state->desc = d;
        rc = x86_decode_0f3a(state, ctxt, ops);
        break;

    case ext_8f08:
        d = DstReg | SrcMem;
        if ( ext8f08_table[b].two_op )
            d |= TwoOp;
        else if ( ext8f08_table[b].four_op && !mode_64bit() )
            imm1 &= 0x7f;
        state->desc = d;
        state->simd_size = ext8f08_table[b].simd_size;
        break;

    case ext_8f09:
    case ext_8f0a:
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNIMPLEMENTED;
    }

    if ( ea.type == OP_MEM )
    {
        if ( pc_rel )
            ea.mem.off += state->ip;

        ea.mem.off = truncate_ea(ea.mem.off);
    }

    /*
     * Simple op_bytes calculations. More complicated cases produce 0
     * and are further handled during execute.
     */
    switch ( state->simd_size )
    {
    case simd_none:
        /*
         * When prefix 66 has a meaning different from operand-size override,
         * operand size defaults to 4 and can't be overridden to 2.
         */
        if ( op_bytes == 2 &&
             (ctxt->opcode & X86EMUL_OPC_PFX_MASK) == X86EMUL_OPC_66(0, 0) )
            op_bytes = 4;
        break;

#ifndef X86EMUL_NO_SIMD
    case simd_packed_int:
        switch ( vex.pfx )
        {
        case vex_none:
            if ( !vex.opcx )
            {
                op_bytes = 8;
                break;
            }
            /* fall through */
        case vex_66:
            op_bytes = 16 << evex.lr;
            break;
        default:
            op_bytes = 0;
            break;
        }
        break;

    case simd_single_fp:
        if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
        {
            op_bytes = 0;
            break;
    case simd_packed_fp:
            if ( vex.pfx & VEX_PREFIX_SCALAR_MASK )
            {
                op_bytes = 0;
                break;
            }
        }
        /* fall through */
    case simd_any_fp:
        switch ( vex.pfx )
        {
        default:
            op_bytes = 16 << evex.lr;
            break;
        case vex_f3:
            generate_exception_if(evex_encoded() && evex.w, EXC_UD);
            op_bytes = 4;
            break;
        case vex_f2:
            generate_exception_if(evex_encoded() && !evex.w, EXC_UD);
            op_bytes = 8;
            break;
        }
        break;

    case simd_scalar_opc:
        op_bytes = 4 << (ctxt->opcode & 1);
        break;

    case simd_scalar_vexw:
        op_bytes = 4 << vex.w;
        break;

    case simd_128:
        /* The special cases here are MMX shift insns. */
        op_bytes = vex.opcx || vex.pfx ? 16 : 8;
        break;

    case simd_256:
        op_bytes = 32;
        break;
#endif /* !X86EMUL_NO_SIMD */

    default:
        op_bytes = 0;
        break;
    }

 done:
    return rc;
}

/* No insn fetching past this point. */
#undef insn_fetch_bytes
#undef insn_fetch_type

/* Undo DEBUG wrapper. */
#undef x86_emulate

int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    /* Shadow copy of register state. Committed on successful emulation. */
    struct cpu_user_regs _regs = *ctxt->regs;
    struct x86_emulate_state state;
    int rc;
    uint8_t b, d, *opc = NULL;
    unsigned int first_byte = 0, elem_bytes, insn_bytes = 0;
    uint64_t op_mask = ~0ULL;
    bool singlestep = (_regs.eflags & X86_EFLAGS_TF) &&
	    !is_branch_step(ctxt, ops);
    bool sfence = false, fault_suppression = false;
    struct operand src = { .reg = PTR_POISON };
    struct operand dst = { .reg = PTR_POISON };
    unsigned long cr4;
    enum x86_emulate_fpu_type fpu_type = X86EMUL_FPU_none;
    struct x86_emulate_stub stub = {};
    DECLARE_ALIGNED(mmval_t, mmval);
#ifdef __XEN__
    struct {
        union stub_exception_token info;
        unsigned int line;
    } stub_exn;
#endif

    ASSERT(ops->read);

    init_context(ctxt);

    generate_exception_if((mode_vif() &&
                           (_regs.eflags & X86_EFLAGS_VIF) &&
                           (_regs.eflags & X86_EFLAGS_VIP)),
                          EXC_GP, 0);

    rc = x86_decode(&state, ctxt, ops);
    if ( rc != X86EMUL_OKAY )
        return rc;

    /* Sync rIP to post decode value. */
    _regs.r(ip) = state.ip;

    if ( ops->validate )
    {
#ifndef NDEBUG
        state.caller = __builtin_return_address(0);
#endif
        rc = ops->validate(&state, ctxt);
#ifndef NDEBUG
        state.caller = NULL;
#endif
        if ( rc == X86EMUL_DONE )
            goto complete_insn;
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    b = ctxt->opcode;
    d = state.desc;
#define state (&state)
    elem_bytes = 4 << evex.w;

    generate_exception_if(state->not_64bit && mode_64bit(), EXC_UD);

    if ( ea.type == OP_REG )
        ea.reg = _decode_gpr(&_regs, modrm_rm, (d & ByteOp) && !rex_prefix && !vex.opcx);

    memset(mmvalp, 0xaa /* arbitrary */, sizeof(*mmvalp));

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
            src.reg = _decode_gpr(&_regs, modrm_reg, !rex_prefix && !vex.opcx);
            src.val = *(uint8_t *)src.reg;
            src.bytes = 1;
        }
        else
        {
            src.reg = decode_gpr(&_regs, modrm_reg);
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
        if ( state->simd_size )
            break;
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

#ifndef X86EMUL_NO_SIMD
    /* With a memory operand, fetch the mask register in use (if any). */
    if ( ea.type == OP_MEM && evex.opmsk &&
         _get_fpu(fpu_type = X86EMUL_FPU_opmask, ctxt, ops) == X86EMUL_OKAY )
    {
        uint8_t *stb = get_stub(stub);

        /* KMOV{W,Q} %k<n>, (%rax) */
        stb[0] = 0xc4;
        stb[1] = 0xe1;
        stb[2] = cpu_has_avx512bw ? 0xf8 : 0x78;
        stb[3] = 0x91;
        stb[4] = evex.opmsk << 3;
        insn_bytes = 5;
        stb[5] = 0xc3;

        invoke_stub("", "", "+m" (op_mask) : "a" (&op_mask));

        insn_bytes = 0;
        put_stub(stub);

        fault_suppression = true;
    }

    if ( fpu_type == X86EMUL_FPU_opmask )
    {
        /* Squash (side) effects of the _get_fpu() above. */
        x86_emul_reset_event(ctxt);
        put_fpu(X86EMUL_FPU_opmask, false, state, ctxt, ops);
        fpu_type = X86EMUL_FPU_none;
    }
#endif /* !X86EMUL_NO_SIMD */

    /* Decode (but don't fetch) the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case DstNone: /* case DstImplicit: */
        /*
         * The only implicit-operands instructions allowed a LOCK prefix are
         * CMPXCHG{8,16}B (MOV CRn is being handled elsewhere).
         */
        generate_exception_if(lock_prefix &&
                              (vex.opcx || ext != ext_0f || b != 0xc7 ||
                               (modrm_reg & 7) != 1 || ea.type != OP_MEM),
                              EXC_UD);
        dst.type = OP_NONE;
        break;

    case DstReg:
        generate_exception_if(lock_prefix, EXC_UD);
        dst.type = OP_REG;
        if ( d & ByteOp )
        {
            dst.reg = _decode_gpr(&_regs, modrm_reg, !rex_prefix && !vex.opcx);
            dst.val = *(uint8_t *)dst.reg;
            dst.bytes = 1;
        }
        else
        {
            dst.reg = decode_gpr(&_regs, modrm_reg);
            switch ( (dst.bytes = op_bytes) )
            {
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        break;
    case DstBitBase:
        if ( ea.type == OP_MEM )
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
            ea.mem.off = truncate_ea(ea.mem.off);
        }

        /* Bit index always truncated to within range. */
        src.val &= (op_bytes << 3) - 1;

        d = (d & ~DstMask) | DstMem;
        /* Becomes a normal DstMem operation from here on. */
    case DstMem:
        generate_exception_if(ea.type == OP_MEM && evex.z, EXC_UD);
        if ( state->simd_size )
        {
            generate_exception_if(lock_prefix, EXC_UD);
            break;
        }
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst = ea;
        if ( dst.type == OP_REG )
        {
            generate_exception_if(lock_prefix, EXC_UD);
            switch ( dst.bytes )
            {
            case 1: dst.val = *(uint8_t  *)dst.reg; break;
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        else if ( d & Mov ) /* optimisation - avoid slow emulated read */
        {
            /* Lock prefix is allowed only on RMW instructions. */
            generate_exception_if(lock_prefix, EXC_UD);
            fail_if(!ops->write);
        }
        else if ( !ops->rmw )
        {
            fail_if(lock_prefix ? !ops->cmpxchg : !ops->write);
            if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
                                  &dst.val, dst.bytes, ctxt, ops)) )
                goto done;
            dst.orig_val = dst.val;
        }
        break;
    }

    switch ( ctxt->opcode )
    {
        enum x86_segment seg;
        struct segment_register cs, sreg;
        struct cpuid_leaf cpuid_leaf;
        uint64_t msr_val;
        unsigned int i, n;
        unsigned long dummy;

    case 0x00: case 0x01: add: /* add reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_add;
        else
        {
    case 0x02 ... 0x05: /* add */
            emulate_2op_SrcV("add", src, dst, _regs.eflags);
        }
        break;

    case 0x08: case 0x09: or: /* or reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_or;
        else
        {
    case 0x0a ... 0x0d: /* or */
            emulate_2op_SrcV("or", src, dst, _regs.eflags);
        }
        break;

    case 0x10: case 0x11: adc: /* adc reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_adc;
        else
        {
    case 0x12 ... 0x15: /* adc */
            emulate_2op_SrcV("adc", src, dst, _regs.eflags);
        }
        break;

    case 0x18: case 0x19: sbb: /* sbb reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_sbb;
        else
        {
    case 0x1a ... 0x1d: /* sbb */
            emulate_2op_SrcV("sbb", src, dst, _regs.eflags);
        }
        break;

    case 0x20: case 0x21: and: /* and reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_and;
        else
        {
    case 0x22 ... 0x25: /* and */
            emulate_2op_SrcV("and", src, dst, _regs.eflags);
        }
        break;

    case 0x28: case 0x29: sub: /* sub reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_sub;
        else
        {
    case 0x2a ... 0x2d: /* sub */
            emulate_2op_SrcV("sub", src, dst, _regs.eflags);
        }
        break;

    case 0x30: case 0x31: xor: /* xor reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_xor;
        else
        {
    case 0x32 ... 0x35: /* xor */
            emulate_2op_SrcV("xor", src, dst, _regs.eflags);
        }
        break;

    case 0x38: case 0x39: cmp: /* cmp reg,mem */
        emulate_2op_SrcV("cmp", dst, src, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x3a ... 0x3d: /* cmp */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x06: /* push %%es */
    case 0x0e: /* push %%cs */
    case 0x16: /* push %%ss */
    case 0x1e: /* push %%ds */
    case X86EMUL_OPC(0x0f, 0xa0): /* push %%fs */
    case X86EMUL_OPC(0x0f, 0xa8): /* push %%gs */
        fail_if(ops->read_segment == NULL);
        if ( (rc = ops->read_segment((b >> 3) & 7, &sreg,
                                     ctxt)) != X86EMUL_OKAY )
            goto done;
        src.val = sreg.sel;
        goto push;

    case 0x07: /* pop %%es */
    case 0x17: /* pop %%ss */
    case 0x1f: /* pop %%ds */
    case X86EMUL_OPC(0x0f, 0xa1): /* pop %%fs */
    case X86EMUL_OPC(0x0f, 0xa9): /* pop %%gs */
        fail_if(ops->write_segment == NULL);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (op_bytes == 4) )
            op_bytes = 8;
        seg = (b >> 3) & 7;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes), &dst.val,
                              op_bytes, ctxt, ops)) != X86EMUL_OKAY ||
             (rc = load_seg(seg, dst.val, 0, NULL, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        if ( seg == x86_seg_ss )
            ctxt->retire.mov_ss = true;
        break;

    case 0x27: /* daa */
    case 0x2f: /* das */ {
        uint8_t al = _regs.al;
        unsigned int eflags = _regs.eflags;

        _regs.eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_AF | X86_EFLAGS_SF |
                          X86_EFLAGS_ZF | X86_EFLAGS_PF);
        if ( ((al & 0x0f) > 9) || (eflags & X86_EFLAGS_AF) )
        {
            _regs.eflags |= X86_EFLAGS_AF;
            if ( b == 0x2f && (al < 6 || (eflags & X86_EFLAGS_CF)) )
                _regs.eflags |= X86_EFLAGS_CF;
            _regs.al += (b == 0x27) ? 6 : -6;
        }
        if ( (al > 0x99) || (eflags & X86_EFLAGS_CF) )
        {
            _regs.al += (b == 0x27) ? 0x60 : -0x60;
            _regs.eflags |= X86_EFLAGS_CF;
        }
        _regs.eflags |= !_regs.al ? X86_EFLAGS_ZF : 0;
        _regs.eflags |= ((int8_t)_regs.al < 0) ? X86_EFLAGS_SF : 0;
        _regs.eflags |= even_parity(_regs.al) ? X86_EFLAGS_PF : 0;
        break;
    }

    case 0x37: /* aaa */
    case 0x3f: /* aas */
        _regs.eflags &= ~X86_EFLAGS_CF;
        if ( (_regs.al > 9) || (_regs.eflags & X86_EFLAGS_AF) )
        {
            _regs.al += (b == 0x37) ? 6 : -6;
            _regs.ah += (b == 0x37) ? 1 : -1;
            _regs.eflags |= X86_EFLAGS_CF | X86_EFLAGS_AF;
        }
        _regs.al &= 0x0f;
        break;

    case 0x40 ... 0x4f: /* inc/dec reg */
        dst.type  = OP_REG;
        dst.reg   = decode_gpr(&_regs, b & 7);
        dst.bytes = op_bytes;
        dst.val   = *dst.reg;
        if ( b & 8 )
            emulate_1op("dec", dst, _regs.eflags);
        else
            emulate_1op("inc", dst, _regs.eflags);
        break;

    case 0x50 ... 0x57: /* push reg */
        src.val = *decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        goto push;

    case 0x58 ... 0x5f: /* pop reg */
        dst.type  = OP_REG;
        dst.reg   = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        dst.bytes = op_bytes;
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x60: /* pusha */
        fail_if(!ops->write);
        ea.val = _regs.esp;
        for ( i = 0; i < 8; i++ )
        {
            void *reg = decode_gpr(&_regs, i);

            if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                                  reg != &_regs.esp ? reg : &ea.val,
                                  op_bytes, ctxt)) != 0 )
                goto done;
        }
        break;

    case 0x61: /* popa */
        for ( i = 0; i < 8; i++ )
        {
            void *reg = decode_gpr(&_regs, 7 - i);

            if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                                  &dst.val, op_bytes, ctxt, ops)) != 0 )
                goto done;
            if ( reg == &_regs.r(sp) )
                continue;
            if ( op_bytes == 2 )
                *(uint16_t *)reg = dst.val;
            else
                *(unsigned long *)reg = dst.val;
        }
        break;

    case 0x62: /* bound */ {
        int lb, ub, idx;

        generate_exception_if(src.type != OP_MEM, EXC_UD);
        if ( (rc = read_ulong(src.mem.seg, truncate_ea(src.mem.off + op_bytes),
                              &ea.val, op_bytes, ctxt, ops)) )
            goto done;
        ub  = (op_bytes == 2) ? (int16_t)ea.val   : (int32_t)ea.val;
        lb  = (op_bytes == 2) ? (int16_t)src.val  : (int32_t)src.val;
        idx = (op_bytes == 2) ? (int16_t)dst.val  : (int32_t)dst.val;
        generate_exception_if((idx < lb) || (idx > ub), EXC_BR);
        dst.type = OP_NONE;
        break;
    }

    case 0x63: /* movsxd (x86/64) / arpl (x86/32) */
        if ( mode_64bit() )
        {
            /* movsxd */
            if ( ea.type == OP_REG )
                src.val = *ea.reg;
            else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val,
                                       (op_bytes == 2 && !amd_like(ctxt)
                                        ? 2 : 4),
                                       ctxt, ops)) )
                goto done;
            dst.val = (int32_t)src.val;
        }
        else
        {
            /* arpl */
            unsigned int src_rpl = dst.val & 3;

            generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);

            dst = ea;
            dst.bytes = 2;
            if ( dst.type == OP_REG )
                dst.val = *dst.reg;
            else if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
                                       &dst.val, 2, ctxt, ops)) )
                goto done;
            if ( src_rpl > (dst.val & 3) )
            {
                _regs.eflags |= X86_EFLAGS_ZF;
                dst.val = (dst.val & ~3) | src_rpl;
            }
            else
            {
                _regs.eflags &= ~X86_EFLAGS_ZF;
                dst.type = OP_NONE;
            }
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
        unsigned long nr_reps = get_rep_prefix(false, true);
        unsigned int port = _regs.dx;

        dst.bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea_and_reps(_regs.r(di), nr_reps, dst.bytes);
        if ( (rc = ioport_access_check(port, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        /* Try the presumably most efficient approach first. */
        if ( !ops->rep_ins )
            nr_reps = 1;
        rc = X86EMUL_UNHANDLEABLE;
        if ( nr_reps == 1 && ops->read_io && ops->write )
        {
            rc = ops->read_io(port, dst.bytes, &dst.val, ctxt);
            if ( rc != X86EMUL_UNHANDLEABLE )
                nr_reps = 0;
        }
        if ( (nr_reps > 1 || rc == X86EMUL_UNHANDLEABLE) && ops->rep_ins )
            rc = ops->rep_ins(port, dst.mem.seg, dst.mem.off, dst.bytes,
                              &nr_reps, ctxt);
        if ( nr_reps >= 1 && rc == X86EMUL_UNHANDLEABLE )
        {
            fail_if(!ops->read_io || !ops->write);
            if ( (rc = ops->read_io(port, dst.bytes, &dst.val, ctxt)) != 0 )
                goto done;
            nr_reps = 0;
        }
        if ( !nr_reps && rc == X86EMUL_OKAY )
        {
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        register_address_adjust(_regs.r(di), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0x6e ... 0x6f: /* outs %esi,%dx */ {
        unsigned long nr_reps = get_rep_prefix(true, false);
        unsigned int port = _regs.dx;

        dst.bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        ea.mem.off = truncate_ea_and_reps(_regs.r(si), nr_reps, dst.bytes);
        if ( (rc = ioport_access_check(port, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        /* Try the presumably most efficient approach first. */
        if ( !ops->rep_outs )
            nr_reps = 1;
        rc = X86EMUL_UNHANDLEABLE;
        if ( nr_reps == 1 && ops->write_io )
        {
            rc = read_ulong(ea.mem.seg, ea.mem.off, &dst.val, dst.bytes,
                            ctxt, ops);
            if ( rc != X86EMUL_UNHANDLEABLE )
                nr_reps = 0;
        }
        if ( (nr_reps > 1 || rc == X86EMUL_UNHANDLEABLE) && ops->rep_outs )
            rc = ops->rep_outs(ea.mem.seg, ea.mem.off, port, dst.bytes,
                               &nr_reps, ctxt);
        if ( nr_reps >= 1 && rc == X86EMUL_UNHANDLEABLE )
        {
            if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &dst.val,
                                  dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
                goto done;
            fail_if(ops->write_io == NULL);
            nr_reps = 0;
        }
        if ( !nr_reps && rc == X86EMUL_OKAY )
        {
            if ( (rc = ops->write_io(port, dst.bytes, dst.val, ctxt)) != 0 )
                goto done;
            nr_reps = 1;
        }
        register_address_adjust(_regs.r(si), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0x70 ... 0x7f: /* jcc (short) */
        if ( test_cc(b, _regs.eflags) )
            jmp_rel((int32_t)src.val);
        adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case 0x80: case 0x81: case 0x82: case 0x83: /* Grp1 */
        switch ( modrm_reg & 7 )
        {
        case 0: goto add;
        case 1: goto or;
        case 2: goto adc;
        case 3: goto sbb;
        case 4: goto and;
        case 5: goto sub;
        case 6: goto xor;
        case 7:
            dst.val = imm1;
            goto cmp;
        }
        break;

    case 0xa8 ... 0xa9: /* test imm,%%eax */
    case 0x84 ... 0x85: test: /* test */
        emulate_2op_SrcV("test", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x86 ... 0x87: xchg: /* xchg */
        /*
         * The lock prefix is implied for this insn (and setting it for the
         * register operands case here is benign to subsequent code).
         */
        lock_prefix = 1;
        if ( ops->rmw && dst.type == OP_MEM )
        {
            state->rmw = rmw_xchg;
            break;
        }
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        /* Arrange for write back of the memory destination. */
        dst.val = src.val;
        break;

    case 0xc6: /* Grp11: mov / xabort */
    case 0xc7: /* Grp11: mov / xbegin */
        if ( modrm == 0xf8 && vcpu_has_rtm() )
        {
            /*
             * xbegin unconditionally aborts, xabort is unconditionally
             * a nop. It also does not truncate the destination address to
             * 16 bits when 16-bit operand size is in effect.
             */
            if ( b & 1 )
            {
                op_bytes = 4;
                jmp_rel((int32_t)src.val);
                _regs.r(ax) = 0;
            }
            dst.type = OP_NONE;
            break;
        }
        generate_exception_if((modrm_reg & 7) != 0, EXC_UD);
    case 0x88 ... 0x8b: /* mov */
    case 0xa0 ... 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2 ... 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        dst.val = src.val;
        break;

    case 0x8c: /* mov Sreg,r/m */
        seg = modrm_reg & 7; /* REX.R is ignored. */
        generate_exception_if(!is_x86_user_segment(seg), EXC_UD);
    store_selector:
        fail_if(ops->read_segment == NULL);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) != 0 )
            goto done;
        dst.val = sreg.sel;
        if ( dst.type == OP_MEM )
            dst.bytes = 2;
        break;

    case 0x8d: /* lea */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        dst.val = ea.mem.off;
        break;

    case 0x8e: /* mov r/m,Sreg */
        seg = modrm_reg & 7; /* REX.R is ignored. */
        generate_exception_if(!is_x86_user_segment(seg) ||
                              seg == x86_seg_cs, EXC_UD);
        if ( (rc = load_seg(seg, src.val, 0, NULL, ctxt, ops)) != 0 )
            goto done;
        if ( seg == x86_seg_ss )
            ctxt->retire.mov_ss = true;
        dst.type = OP_NONE;
        break;

    case 0x8f: /* pop (sole member of Grp1a) */
        generate_exception_if((modrm_reg & 7) != 0, EXC_UD);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x90: /* nop / xchg %%r8,%%rax */
    case X86EMUL_OPC_F3(0, 0x90): /* pause / xchg %%r8,%%rax */
        if ( !(rex_prefix & REX_B) )
            break; /* nop / pause */
        /* fall through */

    case 0x91 ... 0x97: /* xchg reg,%%rax */
        dst.type = OP_REG;
        dst.bytes = op_bytes;
        dst.reg  = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        dst.val  = *dst.reg;
        goto xchg;

    case 0x98: /* cbw/cwde/cdqe */
        switch ( op_bytes )
        {
        case 2: _regs.ax = (int8_t)_regs.al; break; /* cbw */
        case 4: _regs.r(ax) = (uint32_t)(int16_t)_regs.ax; break; /* cwde */
        case 8: _regs.r(ax) = (int32_t)_regs.eax; break; /* cdqe */
        }
        break;

    case 0x99: /* cwd/cdq/cqo */
        switch ( op_bytes )
        {
        case 2: _regs.dx = -((int16_t)_regs.ax < 0); break;
        case 4: _regs.r(dx) = (uint32_t)-((int32_t)_regs.eax < 0); break;
#ifdef __x86_64__
        case 8: _regs.rdx = -((int64_t)_regs.rax < 0); break;
#endif
        }
        break;

    case 0x9a: /* call (far, absolute) */
        ASSERT(!mode_64bit());
    far_call:
        fail_if(!ops->read_segment || !ops->write);

        if ( (rc = ops->read_segment(x86_seg_cs, &sreg, ctxt)) ||
             (rc = load_seg(x86_seg_cs, imm2, 0, &cs, ctxt, ops)) ||
             (validate_far_branch(&cs, imm1),
              src.val = sreg.sel,
              rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                              &src.val, op_bytes, ctxt)) ||
             (rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                              &_regs.r(ip), op_bytes, ctxt)) ||
             (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) )
            goto done;

        _regs.r(ip) = imm1;
        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

#ifndef X86EMUL_NO_FPU
    case 0x9b:  /* wait/fwait */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_wait);
        emulate_fpu_insn_stub(b);
        break;
#endif

    case 0x9c: /* pushf */
        if ( (_regs.eflags & X86_EFLAGS_VM) &&
             MASK_EXTR(_regs.eflags, X86_EFLAGS_IOPL) != 3 )
        {
            cr4 = 0;
            if ( op_bytes == 2 && ops->read_cr )
            {
                rc = ops->read_cr(4, &cr4, ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
            }
            generate_exception_if(!(cr4 & X86_CR4_VME), EXC_GP, 0);
            src.val = (_regs.flags & ~X86_EFLAGS_IF) | X86_EFLAGS_IOPL;
            if ( _regs.eflags & X86_EFLAGS_VIF )
                src.val |= X86_EFLAGS_IF;
        }
        else
            src.val = _regs.r(flags) & ~(X86_EFLAGS_VM | X86_EFLAGS_RF);
        goto push;

    case 0x9d: /* popf */ {
        /*
         * Bits which may not be modified by this instruction. RF is handled
         * uniformly during instruction retirement.
         */
        uint32_t mask = X86_EFLAGS_VIP | X86_EFLAGS_VIF | X86_EFLAGS_VM;

        cr4 = 0;
        if ( !mode_ring0() )
        {
            if ( _regs.eflags & X86_EFLAGS_VM )
            {
                if ( op_bytes == 2 && ops->read_cr )
                {
                    rc = ops->read_cr(4, &cr4, ctxt);
                    if ( rc != X86EMUL_OKAY )
                        goto done;
                }
                /* All IOPL != 3 POPFs fail, except in vm86 mode. */
                generate_exception_if(!(cr4 & X86_CR4_VME) &&
                                      MASK_EXTR(_regs.eflags, X86_EFLAGS_IOPL) != 3,
                                      EXC_GP, 0);
            }
            /*
             * IOPL cannot be modified outside of CPL 0.  IF cannot be
             * modified if IOPL < CPL.
             */
            mask |= X86_EFLAGS_IOPL;
            if ( !mode_iopl() )
                mask |= X86_EFLAGS_IF;
        }
        /* 64-bit mode: POPF defaults to a 64-bit operand. */
        if ( mode_64bit() && (op_bytes == 4) )
            op_bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &dst.val, op_bytes, ctxt, ops)) != 0 )
            goto done;
        if ( op_bytes == 2 )
        {
            /* 16-bit POPF preserves the upper 16 bits of EFLAGS. */
            dst.val = (uint16_t)dst.val | (_regs.eflags & 0xffff0000u);
            /* VME processing only applies at IOPL != 3. */
            if ( (cr4 & X86_CR4_VME) &&
                 MASK_EXTR(_regs.eflags, X86_EFLAGS_IOPL) != 3 )
            {
                generate_exception_if(dst.val & X86_EFLAGS_TF, EXC_GP, 0);
                if ( dst.val & X86_EFLAGS_IF )
                {
                    generate_exception_if(_regs.eflags & X86_EFLAGS_VIP,
                                          EXC_GP, 0);
                    dst.val |= X86_EFLAGS_VIF;
                }
                else
                    dst.val &= ~X86_EFLAGS_VIF;
                mask &= ~X86_EFLAGS_VIF;
            }
        }
        dst.val &= EFLAGS_MODIFIABLE;
        _regs.eflags &= mask;
        _regs.eflags |= (dst.val & ~mask) | X86_EFLAGS_MBS;
        break;
    }

    case 0x9e: /* sahf */
        if ( mode_64bit() )
            vcpu_must_have(lahf_lm);
        *(uint8_t *)&_regs.eflags = (_regs.ah & EFLAGS_MASK) | X86_EFLAGS_MBS;
        break;

    case 0x9f: /* lahf */
        if ( mode_64bit() )
            vcpu_must_have(lahf_lm);
        _regs.ah = (_regs.eflags & EFLAGS_MASK) | X86_EFLAGS_MBS;
        break;

    case 0xa4 ... 0xa5: /* movs */ {
        unsigned long nr_reps = get_rep_prefix(true, true);

        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea_and_reps(_regs.r(di), nr_reps, dst.bytes);
        src.mem.off = truncate_ea_and_reps(_regs.r(si), nr_reps, dst.bytes);
        if ( (nr_reps == 1) || !ops->rep_movs ||
             ((rc = ops->rep_movs(ea.mem.seg, src.mem.off,
                                  dst.mem.seg, dst.mem.off, dst.bytes,
                                  &nr_reps, ctxt)) == X86EMUL_UNHANDLEABLE) )
        {
            if ( (rc = read_ulong(ea.mem.seg, src.mem.off,
                                  &dst.val, dst.bytes, ctxt, ops)) != 0 )
                goto done;
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        register_address_adjust(_regs.r(si), nr_reps * dst.bytes);
        register_address_adjust(_regs.r(di), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0xa6 ... 0xa7: /* cmps */ {
        unsigned long next_eip = _regs.r(ip);

        get_rep_prefix(true, true);
        src.bytes = dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.r(si)),
                              &dst.val, dst.bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_es, truncate_ea(_regs.r(di)),
                              &src.val, src.bytes, ctxt, ops)) )
            goto done;
        register_address_adjust(_regs.r(si), dst.bytes);
        register_address_adjust(_regs.r(di), src.bytes);
        put_rep_prefix(1);
        /* cmp: dst - src ==> src=*%%edi,dst=*%%esi ==> *%%esi - *%%edi */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        if ( (repe_prefix() && !(_regs.eflags & X86_EFLAGS_ZF)) ||
             (repne_prefix() && (_regs.eflags & X86_EFLAGS_ZF)) )
            _regs.r(ip) = next_eip;
        break;
    }

    case 0xaa ... 0xab: /* stos */ {
        unsigned long nr_reps = get_rep_prefix(false, true);

        dst.bytes = src.bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea(_regs.r(di));
        if ( (nr_reps == 1) || !ops->rep_stos ||
             ((rc = ops->rep_stos(&src.val,
                                  dst.mem.seg, dst.mem.off, dst.bytes,
                                  &nr_reps, ctxt)) == X86EMUL_UNHANDLEABLE) )
        {
            dst.val = src.val;
            dst.type = OP_MEM;
            nr_reps = 1;
            rc = X86EMUL_OKAY;
        }
        register_address_adjust(_regs.r(di), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0xac ... 0xad: /* lods */
        get_rep_prefix(true, false);
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.r(si)),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        register_address_adjust(_regs.r(si), dst.bytes);
        put_rep_prefix(1);
        break;

    case 0xae ... 0xaf: /* scas */ {
        unsigned long next_eip = _regs.r(ip);

        get_rep_prefix(false, true);
        if ( (rc = read_ulong(x86_seg_es, truncate_ea(_regs.r(di)),
                              &dst.val, src.bytes, ctxt, ops)) != 0 )
            goto done;
        register_address_adjust(_regs.r(di), src.bytes);
        put_rep_prefix(1);
        /* cmp: %%eax - *%%edi ==> src=%%eax,dst=*%%edi ==> src - dst */
        dst.bytes = src.bytes;
        emulate_2op_SrcV("cmp", dst, src, _regs.eflags);
        if ( (repe_prefix() && !(_regs.eflags & X86_EFLAGS_ZF)) ||
             (repne_prefix() && (_regs.eflags & X86_EFLAGS_ZF)) )
            _regs.r(ip) = next_eip;
        break;
    }

    case 0xb0 ... 0xb7: /* mov imm8,r8 */
        dst.reg = _decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3),
                              !rex_prefix);
        dst.val = src.val;
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        dst.reg = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        dst.val = src.val;
        break;

    case 0xc0 ... 0xc1: grp2: /* Grp2 */
        generate_exception_if(lock_prefix, EXC_UD);

        switch ( modrm_reg & 7 )
        {
#define GRP2(name, ext) \
        case ext: \
            if ( ops->rmw && dst.type == OP_MEM ) \
                state->rmw = rmw_##name; \
            else \
                emulate_2op_SrcB(#name, src, dst, _regs.eflags); \
            break

        GRP2(rol, 0);
        GRP2(ror, 1);
        GRP2(rcl, 2);
        GRP2(rcr, 3);
        case 6: /* sal/shl alias */
        GRP2(shl, 4);
        GRP2(shr, 5);
        GRP2(sar, 7);
#undef GRP2
        }
        break;

    case 0xc2: /* ret imm16 (near) */
    case 0xc3: /* ret (near) */
        op_bytes = (op_bytes == 4 || !amd_like(ctxt)) && mode_64bit()
                   ? 8 : op_bytes;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + src.val),
                              &dst.val, op_bytes, ctxt, ops)) != 0 ||
             (rc = ops->insn_fetch(x86_seg_cs, dst.val, NULL, 0, ctxt)) )
            goto done;
        _regs.r(ip) = dst.val;
        adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case 0xc4: /* les */
    case 0xc5: /* lds */
        seg = (b & 1) * 3; /* es = 0, ds = 3 */
    les:
        generate_exception_if(src.type != OP_MEM, EXC_UD);
        if ( (rc = read_ulong(src.mem.seg, truncate_ea(src.mem.off + src.bytes),
                              &dst.val, 2, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        ASSERT(is_x86_user_segment(seg));
        if ( (rc = load_seg(seg, dst.val, 0, NULL, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        dst.val = src.val;
        break;

    case 0xc8: /* enter imm16,imm8 */
        dst.type = OP_REG;
        dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
        dst.reg = (unsigned long *)&_regs.r(bp);
        fail_if(!ops->write);
        if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                              &_regs.r(bp), dst.bytes, ctxt)) )
            goto done;
        dst.val = _regs.r(sp);

        n = imm2 & 31;
        if ( n )
        {
            for ( i = 1; i < n; i++ )
            {
                unsigned long ebp, temp_data;
                ebp = truncate_word(_regs.r(bp) - i*dst.bytes, ctxt->sp_size/8);
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

    case 0xc9: /* leave */
        /* First writeback, to %%esp. */
        dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
        if ( dst.bytes == 2 )
            _regs.sp = _regs.bp;
        else
            _regs.r(sp) = dst.bytes == 4 ? _regs.ebp : _regs.r(bp);

        /* Second writeback, to %%ebp. */
        dst.type = OP_REG;
        dst.reg = (unsigned long *)&_regs.r(bp);
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

    case 0xce: /* into */
        if ( !(_regs.eflags & X86_EFLAGS_OF) )
            break;
        /* Fallthrough */
    case 0xcc: /* int3 */
    case 0xcd: /* int imm8 */
    case 0xf1: /* int1 (icebp) */
        ASSERT(!ctxt->event_pending);
        switch ( ctxt->opcode )
        {
        case 0xcc: /* int3 */
            ctxt->event.vector = EXC_BP;
            ctxt->event.type = X86_EVENTTYPE_SW_EXCEPTION;
            break;
        case 0xcd: /* int imm8 */
            ctxt->event.vector = imm1;
            ctxt->event.type = X86_EVENTTYPE_SW_INTERRUPT;
            break;
        case 0xce: /* into */
            ctxt->event.vector = EXC_OF;
            ctxt->event.type = X86_EVENTTYPE_SW_EXCEPTION;
            break;
        case 0xf1: /* icebp */
            ctxt->event.vector = EXC_DB;
            ctxt->event.type = X86_EVENTTYPE_PRI_SW_EXCEPTION;
            break;
        }
        ctxt->event.error_code = X86_EVENT_NO_EC;
        ctxt->event.insn_len = _regs.r(ip) - ctxt->regs->r(ip);
        ctxt->event_pending = true;
        rc = X86EMUL_EXCEPTION;
        goto done;

    case 0xcf: /* iret */ {
        unsigned long sel, eip, eflags;
        uint32_t mask = X86_EFLAGS_VIP | X86_EFLAGS_VIF | X86_EFLAGS_VM;

        fail_if(!in_realmode(ctxt, ops));
        ctxt->retire.unblock_nmi = true;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &eip, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &sel, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &eflags, op_bytes, ctxt, ops)) )
            goto done;
        if ( op_bytes == 2 )
            eflags = (uint16_t)eflags | (_regs.eflags & 0xffff0000u);
        eflags &= EFLAGS_MODIFIABLE;
        _regs.eflags &= mask;
        _regs.eflags |= (eflags & ~mask) | X86_EFLAGS_MBS;
        if ( (rc = load_seg(x86_seg_cs, sel, 1, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, (uint32_t)eip)) )
            goto done;
        break;
    }

    case 0xd0 ... 0xd1: /* Grp2 */
        src.val = 1;
        goto grp2;

    case 0xd2 ... 0xd3: /* Grp2 */
        src.val = _regs.cl;
        goto grp2;

    case 0xd4: /* aam */
    case 0xd5: /* aad */
        n = (uint8_t)src.val;
        if ( b & 0x01 )
            _regs.ax = (uint8_t)(_regs.al + (_regs.ah * n));
        else
        {
            generate_exception_if(!n, EXC_DE);
            _regs.al = _regs.al % n;
            _regs.ah = _regs.al / n;
        }
        _regs.eflags &= ~(X86_EFLAGS_SF | X86_EFLAGS_ZF | X86_EFLAGS_PF);
        _regs.eflags |= !_regs.al ? X86_EFLAGS_ZF : 0;
        _regs.eflags |= ((int8_t)_regs.al < 0) ? X86_EFLAGS_SF : 0;
        _regs.eflags |= even_parity(_regs.al) ? X86_EFLAGS_PF : 0;
        break;

    case 0xd6: /* salc */
        _regs.al = (_regs.eflags & X86_EFLAGS_CF) ? 0xff : 0x00;
        break;

    case 0xd7: /* xlat */ {
        unsigned long al;

        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.r(bx) + _regs.al),
                              &al, 1, ctxt, ops)) != 0 )
            goto done;
        _regs.al = al;
        break;
    }

#ifndef X86EMUL_NO_FPU
    case 0xd8: /* FPU 0xd8 */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %stN,%st */
        case 0xc8 ... 0xcf: /* fmul %stN,%st */
        case 0xd0 ... 0xd7: /* fcom %stN,%st */
        case 0xd8 ... 0xdf: /* fcomp %stN,%st */
        case 0xe0 ... 0xe7: /* fsub %stN,%st */
        case 0xe8 ... 0xef: /* fsubr %stN,%st */
        case 0xf0 ... 0xf7: /* fdiv %stN,%st */
        case 0xf8 ... 0xff: /* fdivr %stN,%st */
            emulate_fpu_insn_stub(0xd8, modrm);
            break;
        default:
        fpu_memsrc32:
            ASSERT(ea.type == OP_MEM);
            if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                 4, ctxt)) != X86EMUL_OKAY )
                goto done;
            emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
            break;
        }
        break;

    case 0xd9: /* FPU 0xd9 */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xfb: /* fsincos */
            fail_if(cpu_has_amd_erratum(573));
            /* fall through */
        case 0xc0 ... 0xc7: /* fld %stN */
        case 0xc8 ... 0xcf: /* fxch %stN */
        case 0xd0: /* fnop */
        case 0xd8 ... 0xdf: /* fstp %stN (alternative encoding) */
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
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fld m32fp */
                goto fpu_memsrc32;
            case 2: /* fst m32fp */
            case 3: /* fstp m32fp */
            fpu_memdst32:
                dst = ea;
                dst.bytes = 4;
                emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
                break;
            case 4: /* fldenv */
                /* Raise #MF now if there are pending unmasked exceptions. */
                emulate_fpu_insn_stub(0xd9, 0xd0 /* fnop */);
                /* fall through */
            case 6: /* fnstenv */
                fail_if(!ops->blk);
                state->blk = modrm_reg & 2 ? blk_fst : blk_fld;
                /*
                 * REX is meaningless for these insns by this point - (ab)use
                 * the field to communicate real vs protected mode to ->blk().
                 */
                /*state->*/rex_prefix = in_protmode(ctxt, ops);
                if ( (rc = ops->blk(ea.mem.seg, ea.mem.off, NULL,
                                    op_bytes > 2 ? sizeof(struct x87_env32)
                                                 : sizeof(struct x87_env16),
                                    &_regs.eflags,
                                    state, ctxt)) != X86EMUL_OKAY )
                    goto done;
                state->fpu_ctrl = true;
                break;
            case 5: /* fldcw m2byte */
                state->fpu_ctrl = true;
            fpu_memsrc16:
                if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                     2, ctxt)) != X86EMUL_OKAY )
                    goto done;
                emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
                break;
            case 7: /* fnstcw m2byte */
                state->fpu_ctrl = true;
            fpu_memdst16:
                dst = ea;
                dst.bytes = 2;
                emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
                break;
            default:
                generate_exception(EXC_UD);
            }
            /*
             * Control instructions can't raise FPU exceptions, so we need
             * to consider suppressing writes only for non-control ones.
             */
            if ( dst.type == OP_MEM && !state->fpu_ctrl && !fpu_check_write() )
                dst.type = OP_NONE;
        }
        break;

    case 0xda: /* FPU 0xda */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovb %stN */
        case 0xc8 ... 0xcf: /* fcmove %stN */
        case 0xd0 ... 0xd7: /* fcmovbe %stN */
        case 0xd8 ... 0xdf: /* fcmovu %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xda, modrm);
            break;
        case 0xe9:          /* fucompp */
            emulate_fpu_insn_stub(0xda, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            goto fpu_memsrc32;
        }
        break;

    case 0xdb: /* FPU 0xdb */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovnb %stN */
        case 0xc8 ... 0xcf: /* fcmovne %stN */
        case 0xd0 ... 0xd7: /* fcmovnbe %stN */
        case 0xd8 ... 0xdf: /* fcmovnu %stN */
        case 0xe8 ... 0xef: /* fucomi %stN */
        case 0xf0 ... 0xf7: /* fcomi %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xdb, modrm);
            break;
        case 0xe0: /* fneni - 8087 only, ignored by 287 */
        case 0xe1: /* fndisi - 8087 only, ignored by 287 */
        case 0xe2: /* fnclex */
        case 0xe3: /* fninit */
        case 0xe4: /* fnsetpm - 287 only, ignored by 387 */
        /* case 0xe5: frstpm - 287 only, #UD on 387 */
            state->fpu_ctrl = true;
            emulate_fpu_insn_stub(0xdb, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fild m32i */
                goto fpu_memsrc32;
            case 1: /* fisttp m32i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fist m32i */
            case 3: /* fistp m32i */
                goto fpu_memdst32;
            case 5: /* fld m80fp */
            fpu_memsrc80:
                if ( (rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp,
                                     10, ctxt)) != X86EMUL_OKAY )
                    goto done;
                emulate_fpu_insn_memsrc(b, modrm_reg & 7, *mmvalp);
                break;
            case 7: /* fstp m80fp */
            fpu_memdst80:
                fail_if(!ops->write);
                emulate_fpu_insn_memdst(b, modrm_reg & 7, *mmvalp);
                if ( fpu_check_write() &&
                     (rc = ops->write(ea.mem.seg, ea.mem.off, mmvalp,
                                      10, ctxt)) != X86EMUL_OKAY )
                    goto done;
                break;
            default:
                generate_exception(EXC_UD);
            }
        }
        break;

    case 0xdc: /* FPU 0xdc */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %st,%stN */
        case 0xc8 ... 0xcf: /* fmul %st,%stN */
        case 0xd0 ... 0xd7: /* fcom %stN,%st (alternative encoding) */
        case 0xd8 ... 0xdf: /* fcomp %stN,%st (alternative encoding) */
        case 0xe0 ... 0xe7: /* fsubr %st,%stN */
        case 0xe8 ... 0xef: /* fsub %st,%stN */
        case 0xf0 ... 0xf7: /* fdivr %st,%stN */
        case 0xf8 ... 0xff: /* fdiv %st,%stN */
            emulate_fpu_insn_stub(0xdc, modrm);
            break;
        default:
        fpu_memsrc64:
            ASSERT(ea.type == OP_MEM);
            if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                 8, ctxt)) != X86EMUL_OKAY )
                goto done;
            emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
            break;
        }
        break;

    case 0xdd: /* FPU 0xdd */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* ffree %stN */
        case 0xc8 ... 0xcf: /* fxch %stN (alternative encoding) */
        case 0xd0 ... 0xd7: /* fst %stN */
        case 0xd8 ... 0xdf: /* fstp %stN */
        case 0xe0 ... 0xe7: /* fucom %stN */
        case 0xe8 ... 0xef: /* fucomp %stN */
            emulate_fpu_insn_stub(0xdd, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fld m64fp */;
                goto fpu_memsrc64;
            case 1: /* fisttp m64i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fst m64fp */
            case 3: /* fstp m64fp */
            fpu_memdst64:
                dst = ea;
                dst.bytes = 8;
                emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
                break;
            case 4: /* frstor */
                /* Raise #MF now if there are pending unmasked exceptions. */
                emulate_fpu_insn_stub(0xd9, 0xd0 /* fnop */);
                /* fall through */
            case 6: /* fnsave */
                fail_if(!ops->blk);
                state->blk = modrm_reg & 2 ? blk_fst : blk_fld;
                /*
                 * REX is meaningless for these insns by this point - (ab)use
                 * the field to communicate real vs protected mode to ->blk().
                 */
                /*state->*/rex_prefix = in_protmode(ctxt, ops);
                if ( (rc = ops->blk(ea.mem.seg, ea.mem.off, NULL,
                                    op_bytes > 2 ? sizeof(struct x87_env32) + 80
                                                 : sizeof(struct x87_env16) + 80,
                                    &_regs.eflags,
                                    state, ctxt)) != X86EMUL_OKAY )
                    goto done;
                state->fpu_ctrl = true;
                break;
            case 7: /* fnstsw m2byte */
                state->fpu_ctrl = true;
                goto fpu_memdst16;
            default:
                generate_exception(EXC_UD);
            }
            /*
             * Control instructions can't raise FPU exceptions, so we need
             * to consider suppressing writes only for non-control ones.
             */
            if ( dst.type == OP_MEM && !state->fpu_ctrl && !fpu_check_write() )
                dst.type = OP_NONE;
        }
        break;

    case 0xde: /* FPU 0xde */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* faddp %stN */
        case 0xc8 ... 0xcf: /* fmulp %stN */
        case 0xd0 ... 0xd7: /* fcomp %stN (alternative encoding) */
        case 0xd9: /* fcompp */
        case 0xe0 ... 0xe7: /* fsubrp %stN */
        case 0xe8 ... 0xef: /* fsubp %stN */
        case 0xf0 ... 0xf7: /* fdivrp %stN */
        case 0xf8 ... 0xff: /* fdivp %stN */
            emulate_fpu_insn_stub(0xde, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
            break;
        }
        break;

    case 0xdf: /* FPU 0xdf */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xe0:
            /* fnstsw %ax */
            state->fpu_ctrl = true;
            dst.bytes = 2;
            dst.type = OP_REG;
            dst.reg = (void *)&_regs.ax;
            emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
            break;
        case 0xe8 ... 0xef: /* fucomip %stN */
        case 0xf0 ... 0xf7: /* fcomip %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xdf, modrm);
            break;
        case 0xc0 ... 0xc7: /* ffreep %stN */
        case 0xc8 ... 0xcf: /* fxch %stN (alternative encoding) */
        case 0xd0 ... 0xd7: /* fstp %stN (alternative encoding) */
        case 0xd8 ... 0xdf: /* fstp %stN (alternative encoding) */
            emulate_fpu_insn_stub(0xdf, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fild m16i */
                goto fpu_memsrc16;
            case 1: /* fisttp m16i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fist m16i */
            case 3: /* fistp m16i */
                goto fpu_memdst16;
            case 4: /* fbld m80dec */
                goto fpu_memsrc80;
            case 5: /* fild m64i */
                dst.type = OP_NONE;
                goto fpu_memsrc64;
            case 6: /* fbstp packed bcd */
                goto fpu_memdst80;
            case 7: /* fistp m64i */
                goto fpu_memdst64;
            }
        }
        break;
#endif /* !X86EMUL_NO_FPU */

    case 0xe0 ... 0xe2: /* loop{,z,nz} */ {
        unsigned long count = get_loop_count(&_regs, ad_bytes);
        int do_jmp = !(_regs.eflags & X86_EFLAGS_ZF); /* loopnz */

        if ( b == 0xe1 )
            do_jmp = !do_jmp; /* loopz */
        else if ( b == 0xe2 )
            do_jmp = 1; /* loop */
        if ( count != 1 && do_jmp )
            jmp_rel((int32_t)src.val);
        put_loop_count(&_regs, ad_bytes, count - 1);
        break;
    }

    case 0xe3: /* jcxz/jecxz (short) */
        if ( !get_loop_count(&_regs, ad_bytes) )
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
        unsigned int port = ((b < 0xe8) ? (uint8_t)src.val : _regs.dx);

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
        {
            if ( rc == X86EMUL_DONE )
                goto complete_insn;
            goto done;
        }
        break;
    }

    case 0xe8: /* call (near) */ {
        int32_t rel = src.val;

        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        src.val = _regs.r(ip);
        jmp_rel(rel);
        adjust_bnd(ctxt, ops, vex.pfx);
        goto push;
    }

    case 0xe9: /* jmp (near) */
    case 0xeb: /* jmp (short) */
        jmp_rel((int32_t)src.val);
        if ( !(b & 2) )
            adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case 0xea: /* jmp (far, absolute) */
        ASSERT(!mode_64bit());
    far_jmp:
        if ( (rc = load_seg(x86_seg_cs, imm2, 0, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, imm1)) )
            goto done;
        break;

    case 0xf4: /* hlt */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        ctxt->retire.hlt = true;
        break;

    case 0xf5: /* cmc */
        _regs.eflags ^= X86_EFLAGS_CF;
        break;

    case 0xf6 ... 0xf7: /* Grp3 */
        if ( (d & DstMask) == DstEax )
            dst.reg = (unsigned long *)&_regs.r(ax);
        switch ( modrm_reg & 7 )
        {
            unsigned long u[2], v;

        case 0 ... 1: /* test */
            dst.val = imm1;
            dst.bytes = src.bytes;
            goto test;
        case 2: /* not */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_not;
            else
                dst.val = ~dst.val;
            break;
        case 3: /* neg */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_neg;
            else
                emulate_1op("neg", dst, _regs.eflags);
            break;
        case 4: /* mul */
            _regs.eflags &= ~(X86_EFLAGS_OF | X86_EFLAGS_CF);
            switch ( dst.bytes )
            {
            case 1:
                dst.val = _regs.al;
                dst.val *= src.val;
                if ( (uint8_t)dst.val != (uint16_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                dst.bytes = 2;
                break;
            case 2:
                dst.val = _regs.ax;
                dst.val *= src.val;
                if ( (uint16_t)dst.val != (uint32_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                _regs.dx = dst.val >> 16;
                break;
#ifdef __x86_64__
            case 4:
                dst.val = _regs.eax;
                dst.val *= src.val;
                if ( (uint32_t)dst.val != dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                _regs.rdx = dst.val >> 32;
                break;
#endif
            default:
                u[0] = src.val;
                u[1] = _regs.r(ax);
                if ( mul_dbl(u) )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                _regs.r(dx) = u[1];
                dst.val = u[0];
                break;
            }
            break;
        case 5: /* imul */
            dst.val = _regs.r(ax);
        imul:
            _regs.eflags &= ~(X86_EFLAGS_OF | X86_EFLAGS_CF);
            switch ( dst.bytes )
            {
            case 1:
                dst.val = (int8_t)src.val * (int8_t)dst.val;
                if ( (int8_t)dst.val != (int16_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                ASSERT(b > 0x6b);
                dst.bytes = 2;
                break;
            case 2:
                dst.val = ((uint32_t)(int16_t)src.val *
                           (uint32_t)(int16_t)dst.val);
                if ( (int16_t)dst.val != (int32_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                if ( b > 0x6b )
                    _regs.dx = dst.val >> 16;
                break;
#ifdef __x86_64__
            case 4:
                dst.val = ((uint64_t)(int32_t)src.val *
                           (uint64_t)(int32_t)dst.val);
                if ( (int32_t)dst.val != dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                if ( b > 0x6b )
                    _regs.rdx = dst.val >> 32;
                break;
#endif
            default:
                u[0] = src.val;
                u[1] = dst.val;
                if ( imul_dbl(u) )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                if ( b > 0x6b )
                    _regs.r(dx) = u[1];
                dst.val = u[0];
                break;
            }
            break;
        case 6: /* div */
            switch ( src.bytes )
            {
            case 1:
                u[0] = _regs.ax;
                u[1] = 0;
                v    = (uint8_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint8_t)u[0] != (uint16_t)u[0]),
                    EXC_DE);
                dst.val = (uint8_t)u[0];
                _regs.ah = u[1];
                break;
            case 2:
                u[0] = (_regs.edx << 16) | _regs.ax;
                u[1] = 0;
                v    = (uint16_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint16_t)u[0] != (uint32_t)u[0]),
                    EXC_DE);
                dst.val = (uint16_t)u[0];
                _regs.dx = u[1];
                break;
#ifdef __x86_64__
            case 4:
                u[0] = (_regs.rdx << 32) | _regs.eax;
                u[1] = 0;
                v    = (uint32_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint32_t)u[0] != u[0]),
                    EXC_DE);
                dst.val   = (uint32_t)u[0];
                _regs.rdx = (uint32_t)u[1];
                break;
#endif
            default:
                u[0] = _regs.r(ax);
                u[1] = _regs.r(dx);
                v    = src.val;
                generate_exception_if(div_dbl(u, v), EXC_DE);
                dst.val     = u[0];
                _regs.r(dx) = u[1];
                break;
            }
            break;
        case 7: /* idiv */
            switch ( src.bytes )
            {
            case 1:
                u[0] = (int16_t)_regs.ax;
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int8_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int8_t)u[0] != (int16_t)u[0]),
                    EXC_DE);
                dst.val = (int8_t)u[0];
                _regs.ah = u[1];
                break;
            case 2:
                u[0] = (int32_t)((_regs.edx << 16) | _regs.ax);
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int16_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int16_t)u[0] != (int32_t)u[0]),
                    EXC_DE);
                dst.val = (int16_t)u[0];
                _regs.dx = u[1];
                break;
#ifdef __x86_64__
            case 4:
                u[0] = (_regs.rdx << 32) | _regs.eax;
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int32_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int32_t)u[0] != u[0]),
                    EXC_DE);
                dst.val   = (int32_t)u[0];
                _regs.rdx = (uint32_t)u[1];
                break;
#endif
            default:
                u[0] = _regs.r(ax);
                u[1] = _regs.r(dx);
                v    = src.val;
                generate_exception_if(idiv_dbl(u, v), EXC_DE);
                dst.val     = u[0];
                _regs.r(dx) = u[1];
                break;
            }
            break;
        }
        break;

    case 0xf8: /* clc */
        _regs.eflags &= ~X86_EFLAGS_CF;
        break;

    case 0xf9: /* stc */
        _regs.eflags |= X86_EFLAGS_CF;
        break;

    case 0xfa: /* cli */
        if ( mode_iopl() )
            _regs.eflags &= ~X86_EFLAGS_IF;
        else
        {
            generate_exception_if(!mode_vif(), EXC_GP, 0);
            _regs.eflags &= ~X86_EFLAGS_VIF;
        }
        break;

    case 0xfb: /* sti */
        if ( mode_iopl() )
        {
            if ( !(_regs.eflags & X86_EFLAGS_IF) )
                ctxt->retire.sti = true;
            _regs.eflags |= X86_EFLAGS_IF;
        }
        else
        {
            generate_exception_if((_regs.eflags & X86_EFLAGS_VIP) ||
				  !mode_vif(),
                                  EXC_GP, 0);
            if ( !(_regs.eflags & X86_EFLAGS_VIF) )
                ctxt->retire.sti = true;
            _regs.eflags |= X86_EFLAGS_VIF;
        }
        break;

    case 0xfc: /* cld */
        _regs.eflags &= ~X86_EFLAGS_DF;
        break;

    case 0xfd: /* std */
        _regs.eflags |= X86_EFLAGS_DF;
        break;

    case 0xfe: /* Grp4 */
        generate_exception_if((modrm_reg & 7) >= 2, EXC_UD);
        /* Fallthrough. */
    case 0xff: /* Grp5 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* inc */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_inc;
            else
                emulate_1op("inc", dst, _regs.eflags);
            break;
        case 1: /* dec */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_dec;
            else
                emulate_1op("dec", dst, _regs.eflags);
            break;
        case 2: /* call (near) */
            dst.val = _regs.r(ip);
            if ( (rc = ops->insn_fetch(x86_seg_cs, src.val, NULL, 0, ctxt)) )
                goto done;
            _regs.r(ip) = src.val;
            src.val = dst.val;
            adjust_bnd(ctxt, ops, vex.pfx);
            goto push;
        case 4: /* jmp (near) */
            if ( (rc = ops->insn_fetch(x86_seg_cs, src.val, NULL, 0, ctxt)) )
                goto done;
            _regs.r(ip) = src.val;
            dst.type = OP_NONE;
            adjust_bnd(ctxt, ops, vex.pfx);
            break;
        case 3: /* call (far, absolute indirect) */
        case 5: /* jmp (far, absolute indirect) */
            generate_exception_if(src.type != OP_MEM, EXC_UD);

            if ( (rc = read_ulong(src.mem.seg,
                                  truncate_ea(src.mem.off + op_bytes),
                                  &imm2, 2, ctxt, ops)) )
                goto done;
            imm1 = src.val;
            if ( !(modrm_reg & 4) )
                goto far_call;
            goto far_jmp;
        case 6: /* push */
            goto push;
        case 7:
            generate_exception(EXC_UD);
        }
        break;

    case X86EMUL_OPC(0x0f, 0x00): /* Grp6 */
        seg = (modrm_reg & 1) ? x86_seg_tr : x86_seg_ldtr;
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
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
        case 4: /* verr / verw */
            _regs.eflags &= ~X86_EFLAGS_ZF;
            switch ( rc = protmode_load_seg(x86_seg_none, src.val, false,
                                            &sreg, ctxt, ops) )
            {
            case X86EMUL_OKAY:
                if ( sreg.s &&
                     ((modrm_reg & 1) ? ((sreg.type & 0xa) == 0x2)
                                      : ((sreg.type & 0xa) != 0x8)) )
                    _regs.eflags |= X86_EFLAGS_ZF;
                break;
            case X86EMUL_EXCEPTION:
                if ( ctxt->event_pending )
                {
                    ASSERT(ctxt->event.vector == EXC_PF);
            default:
                    goto done;
                }
                /* Instead of the exception, ZF remains cleared. */
                rc = X86EMUL_OKAY;
                break;
            }
            break;
        default:
            generate_exception_if(true, EXC_UD);
            break;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01): /* Grp7 */
    {
        unsigned long base, limit, cr0, cr0w;

        seg = (modrm_reg & 1) ? x86_seg_idtr : x86_seg_gdtr;

        switch( modrm )
        {
        case 0xca: /* clac */
        case 0xcb: /* stac */
            vcpu_must_have(smap);
            generate_exception_if(vex.pfx || !mode_ring0(), EXC_UD);

            _regs.eflags &= ~X86_EFLAGS_AC;
            if ( modrm == 0xcb )
                _regs.eflags |= X86_EFLAGS_AC;
            break;

        case 0xd0: /* xgetbv */
            generate_exception_if(vex.pfx, EXC_UD);
            if ( !ops->read_cr || !ops->read_xcr ||
                 ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), EXC_UD);
            rc = ops->read_xcr(_regs.ecx, &msr_val, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
            _regs.r(ax) = (uint32_t)msr_val;
            _regs.r(dx) = msr_val >> 32;
            break;

        case 0xd1: /* xsetbv */
            generate_exception_if(vex.pfx, EXC_UD);
            if ( !ops->read_cr || !ops->write_xcr ||
                 ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), EXC_UD);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            rc = ops->write_xcr(_regs.ecx,
                                _regs.eax | ((uint64_t)_regs.edx << 32), ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
            break;

        case 0xd4: /* vmfunc */
            generate_exception_if(vex.pfx, EXC_UD);
            fail_if(!ops->vmfunc);
            if ( (rc = ops->vmfunc(ctxt)) != X86EMUL_OKAY )
                goto done;
            break;

        case 0xd5: /* xend */
            generate_exception_if(vex.pfx, EXC_UD);
            generate_exception_if(!vcpu_has_rtm(), EXC_UD);
            generate_exception_if(vcpu_has_rtm(), EXC_GP, 0);
            break;

        case 0xd6: /* xtest */
            generate_exception_if(vex.pfx, EXC_UD);
            generate_exception_if(!vcpu_has_rtm() && !vcpu_has_hle(),
                                  EXC_UD);
            /* Neither HLE nor RTM can be active when we get here. */
            _regs.eflags |= X86_EFLAGS_ZF;
            break;

        case 0xdf: /* invlpga */
            fail_if(!ops->read_msr);
            if ( (rc = ops->read_msr(MSR_EFER,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            /* Finding SVME set implies vcpu_has_svm(). */
            generate_exception_if(!(msr_val & EFER_SVME) ||
                                  !in_protmode(ctxt, ops), EXC_UD);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(!ops->tlb_op);
            if ( (rc = ops->tlb_op(x86emul_invlpga, truncate_ea(_regs.r(ax)),
                                   _regs.ecx, ctxt)) != X86EMUL_OKAY )
                goto done;
            break;

        case 0xe8:
            switch ( vex.pfx )
            {
            case vex_none: /* serialize */
                host_and_vcpu_must_have(serialize);
                asm volatile ( ".byte 0x0f, 0x01, 0xe8" );
                break;
            case vex_f2: /* xsusldtrk */
                vcpu_must_have(tsxldtrk);
                /*
                 * We're never in a transactional region when coming here
                 * - nothing else to do.
                 */
                break;
            default:
                goto unimplemented_insn;
            }
            break;

        case 0xe9:
            switch ( vex.pfx )
            {
            case vex_f2: /* xresldtrk */
                vcpu_must_have(tsxldtrk);
                /*
                 * We're never in a transactional region when coming here
                 * - nothing else to do.
                 */
                break;
            default:
                goto unimplemented_insn;
            }
            break;

        case 0xf8: /* swapgs */
            generate_exception_if(!mode_64bit(), EXC_UD);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(!ops->read_segment || !ops->read_msr ||
                    !ops->write_segment || !ops->write_msr);
            if ( (rc = ops->read_segment(x86_seg_gs, &sreg,
                                         ctxt)) != X86EMUL_OKAY ||
                 (rc = ops->read_msr(MSR_SHADOW_GS_BASE, &msr_val,
                                     ctxt)) != X86EMUL_OKAY ||
                 (rc = ops->write_msr(MSR_SHADOW_GS_BASE, sreg.base,
                                      ctxt)) != X86EMUL_OKAY )
                goto done;
            sreg.base = msr_val;
            if ( (rc = ops->write_segment(x86_seg_gs, &sreg,
                                          ctxt)) != X86EMUL_OKAY )
            {
                /* Best effort unwind (i.e. no error checking). */
                ops->write_msr(MSR_SHADOW_GS_BASE, msr_val, ctxt);
                goto done;
            }
            break;

        case 0xf9: /* rdtscp */
            fail_if(ops->read_msr == NULL);
            if ( (rc = ops->read_msr(MSR_TSC_AUX,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            _regs.r(cx) = (uint32_t)msr_val;
            goto rdtsc;

        case 0xfc: /* clzero */
        {
            unsigned long zero = 0;

            vcpu_must_have(clzero);

            base = ad_bytes == 8 ? _regs.r(ax) :
                   ad_bytes == 4 ? _regs.eax : _regs.ax;
            limit = ctxt->cpuid->basic.clflush_size * 8;
            generate_exception_if(limit < sizeof(long) ||
                                  (limit & (limit - 1)), EXC_UD);
            base &= ~(limit - 1);
            if ( ops->rep_stos )
            {
                unsigned long nr_reps = limit / sizeof(zero);

                rc = ops->rep_stos(&zero, ea.mem.seg, base, sizeof(zero),
                                   &nr_reps, ctxt);
                if ( rc == X86EMUL_OKAY )
                {
                    base += nr_reps * sizeof(zero);
                    limit -= nr_reps * sizeof(zero);
                }
                else if ( rc != X86EMUL_UNHANDLEABLE )
                    goto done;
            }
            fail_if(limit && !ops->write);
            while ( limit )
            {
                rc = ops->write(ea.mem.seg, base, &zero, sizeof(zero), ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
                base += sizeof(zero);
                limit -= sizeof(zero);
            }
            break;
        }

#define _GRP7(mod, reg) \
            (((mod) << 6) | ((reg) << 3)) ... (((mod) << 6) | ((reg) << 3) | 7)
#define GRP7_MEM(reg) _GRP7(0, reg): case _GRP7(1, reg): case _GRP7(2, reg)
#define GRP7_ALL(reg) GRP7_MEM(reg): case _GRP7(3, reg)

        case GRP7_MEM(0): /* sgdt */
        case GRP7_MEM(1): /* sidt */
            ASSERT(ea.type == OP_MEM);
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            fail_if(!ops->read_segment || !ops->write);
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
                 (rc = ops->write(ea.mem.seg, truncate_ea(ea.mem.off + 2),
                                  &sreg.base, op_bytes, ctxt)) != X86EMUL_OKAY )
                goto done;
            break;

        case GRP7_MEM(2): /* lgdt */
        case GRP7_MEM(3): /* lidt */
            ASSERT(ea.type == OP_MEM);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(ops->write_segment == NULL);
            memset(&sreg, 0, sizeof(sreg));
            if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                  &limit, 2, ctxt, ops)) ||
                 (rc = read_ulong(ea.mem.seg, truncate_ea(ea.mem.off + 2),
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

        case GRP7_ALL(4): /* smsw */
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            if ( ea.type == OP_MEM )
            {
                fail_if(!ops->write);
                d |= Mov; /* force writeback */
                ea.bytes = 2;
            }
            else
                ea.bytes = op_bytes;
            dst = ea;
            fail_if(ops->read_cr == NULL);
            if ( (rc = ops->read_cr(0, &dst.val, ctxt)) )
                goto done;
            break;

        case GRP7_ALL(6): /* lmsw */
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

        case GRP7_MEM(7): /* invlpg */
            ASSERT(ea.type == OP_MEM);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(!ops->tlb_op);
            if ( (rc = ops->tlb_op(x86emul_invlpg, ea.mem.off, ea.mem.seg,
                                   ctxt)) != X86EMUL_OKAY )
                goto done;
            break;

#undef GRP7_ALL
#undef GRP7_MEM
#undef _GRP7

        default:
            goto unimplemented_insn;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0x02): /* lar */
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
        _regs.eflags &= ~X86_EFLAGS_ZF;
        switch ( rc = protmode_load_seg(x86_seg_none, src.val, false, &sreg,
                                        ctxt, ops) )
        {
        case X86EMUL_OKAY:
            if ( !sreg.s )
            {
                switch ( sreg.type )
                {
                case 0x01: /* available 16-bit TSS */
                case 0x03: /* busy 16-bit TSS */
                case 0x04: /* 16-bit call gate */
                case 0x05: /* 16/32-bit task gate */
                    if ( ctxt->lma )
                        break;
                    /* fall through */
                case 0x02: /* LDT */
                case 0x09: /* available 32/64-bit TSS */
                case 0x0b: /* busy 32/64-bit TSS */
                case 0x0c: /* 32/64-bit call gate */
                    _regs.eflags |= X86_EFLAGS_ZF;
                    break;
                }
            }
            else
                _regs.eflags |= X86_EFLAGS_ZF;
            break;
        case X86EMUL_EXCEPTION:
            if ( ctxt->event_pending )
            {
                ASSERT(ctxt->event.vector == EXC_PF);
        default:
                goto done;
            }
            /* Instead of the exception, ZF remains cleared. */
            rc = X86EMUL_OKAY;
            break;
        }
        if ( _regs.eflags & X86_EFLAGS_ZF )
            dst.val = ((sreg.attr & 0xff) << 8) |
                      ((sreg.limit >> (sreg.g ? 12 : 0)) & 0xf0000) |
                      ((sreg.attr & 0xf00) << 12);
        else
            dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0x03): /* lsl */
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
        _regs.eflags &= ~X86_EFLAGS_ZF;
        switch ( rc = protmode_load_seg(x86_seg_none, src.val, false, &sreg,
                                        ctxt, ops) )
        {
        case X86EMUL_OKAY:
            if ( !sreg.s )
            {
                switch ( sreg.type )
                {
                case 0x01: /* available 16-bit TSS */
                case 0x03: /* busy 16-bit TSS */
                    if ( ctxt->lma )
                        break;
                    /* fall through */
                case 0x02: /* LDT */
                case 0x09: /* available 32/64-bit TSS */
                case 0x0b: /* busy 32/64-bit TSS */
                    _regs.eflags |= X86_EFLAGS_ZF;
                    break;
                }
            }
            else
                _regs.eflags |= X86_EFLAGS_ZF;
            break;
        case X86EMUL_EXCEPTION:
            if ( ctxt->event_pending )
            {
                ASSERT(ctxt->event.vector == EXC_PF);
        default:
                goto done;
            }
            /* Instead of the exception, ZF remains cleared. */
            rc = X86EMUL_OKAY;
            break;
        }
        if ( _regs.eflags & X86_EFLAGS_ZF )
            dst.val = sreg.limit;
        else
            dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0x05): /* syscall */
        /*
         * Inject #UD if syscall/sysret are disabled. EFER.SCE can't be set
         * with the respective CPUID bit clear, so no need for an explicit
         * check of that one.
         */
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_EFER, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        generate_exception_if((msr_val & EFER_SCE) == 0, EXC_UD);
        generate_exception_if(!amd_like(ctxt) && !mode_64bit(), EXC_UD);

        if ( (rc = ops->read_msr(MSR_STAR, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        cs.sel = (msr_val >> 32) & ~3; /* SELECTOR_RPL_MASK */
        sreg.sel = cs.sel + 8;

        cs.base = sreg.base = 0; /* flat segment */
        cs.limit = sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr = 0xc93; /* G+DB+P+S+Data */

#ifdef __x86_64__
        if ( ctxt->lma )
        {
            cs.attr = 0xa9b; /* L+DB+P+S+Code */

            _regs.rcx = _regs.rip;
            _regs.r11 = _regs.eflags & ~X86_EFLAGS_RF;

            if ( (rc = ops->read_msr(mode_64bit() ? MSR_LSTAR : MSR_CSTAR,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            _regs.rip = msr_val;

            if ( (rc = ops->read_msr(MSR_SYSCALL_MASK,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            _regs.eflags &= ~(msr_val | X86_EFLAGS_RF);
        }
        else
#endif
        {
            cs.attr = 0xc9b; /* G+DB+P+S+Code */

            _regs.r(cx) = _regs.eip;
            _regs.eip = msr_val;
            _regs.eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IF | X86_EFLAGS_RF);
        }

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) )
            goto done;

        /*
         * SYSCALL (unlike most instructions) evaluates its singlestep action
         * based on the resulting EFLAGS.TF, not the starting EFLAGS.TF.
         *
         * As the #DB is raised after the CPL change and before the OS can
         * switch stack, it is a large risk for privilege escalation.
         *
         * 64bit kernels should mask EFLAGS.TF in MSR_SYSCALL_MASK to avoid any
         * vulnerability.  Running the #DB handler on an IST stack is also a
         * mitigation.
         *
         * 32bit kernels have no ability to mask EFLAGS.TF at all.
         * Their only mitigation is to use a task gate for handling
         * #DB (or to not use enable EFER.SCE to start with).
         */
        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x06): /* clts */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if((ops->read_cr == NULL) || (ops->write_cr == NULL));
        if ( (rc = ops->read_cr(0, &dst.val, ctxt)) != X86EMUL_OKAY ||
             (rc = ops->write_cr(0, dst.val & ~X86_CR0_TS, ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x07): /* sysret */
        /*
         * Inject #UD if syscall/sysret are disabled. EFER.SCE can't be set
         * with the respective CPUID bit clear, so no need for an explicit
         * check of that one.
         */
        fail_if(!ops->read_msr);
        if ( (rc = ops->read_msr(MSR_EFER, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        generate_exception_if(!(msr_val & EFER_SCE), EXC_UD);
        generate_exception_if(!amd_like(ctxt) && !mode_64bit(), EXC_UD);
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);
#ifdef __x86_64__
        /*
         * Doing this for just Intel (rather than e.g. !amd_like()) as this is
         * in fact risking to make guest OSes vulnerable to the equivalent of
         * XSA-7 (CVE-2012-0217).
         */
        generate_exception_if(ctxt->cpuid->x86_vendor == X86_VENDOR_INTEL &&
                              op_bytes == 8 && !is_canonical_address(_regs.rcx),
                              EXC_GP, 0);
#endif

        if ( (rc = ops->read_msr(MSR_STAR, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        sreg.sel = ((msr_val >> 48) + 8) | 3; /* SELECTOR_RPL_MASK */
        cs.sel = op_bytes == 8 ? sreg.sel + 8 : sreg.sel - 8;

        cs.base = sreg.base = 0; /* flat segment */
        cs.limit = sreg.limit = ~0u; /* 4GB limit */
        cs.attr = 0xcfb; /* G+DB+P+DPL3+S+Code */
        sreg.attr = 0xcf3; /* G+DB+P+DPL3+S+Data */

        /* Only the selector part of SS gets updated by AMD and alike. */
        if ( amd_like(ctxt) )
        {
            fail_if(!ops->read_segment);
            if ( (rc = ops->read_segment(x86_seg_ss, &sreg,
                                         ctxt)) != X86EMUL_OKAY )
                goto done;

            /* There's explicitly no RPL adjustment here. */
            sreg.sel = (msr_val >> 48) + 8;
            /* But DPL needs adjustment, for the new CPL to be correct. */
            sreg.dpl = 3;
        }

#ifdef __x86_64__
        if ( mode_64bit() )
        {
            if ( op_bytes == 8 )
            {
                cs.attr = 0xafb; /* L+DB+P+DPL3+S+Code */
                _regs.rip = _regs.rcx;
            }
            else
                _regs.rip = _regs.ecx;

            _regs.eflags = _regs.r11 & ~(X86_EFLAGS_RF | X86_EFLAGS_VM);
        }
        else
#endif
        {
            _regs.r(ip) = _regs.ecx;
            _regs.eflags |= X86_EFLAGS_IF;
        }

        fail_if(!ops->write_segment);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) != X86EMUL_OKAY ||
             (rc = ops->write_segment(x86_seg_ss, &sreg,
                                      ctxt)) != X86EMUL_OKAY )
            goto done;

        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x08): /* invd */
    case X86EMUL_OPC(0x0f, 0x09): /* wbinvd / wbnoinvd */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(!ops->cache_op);
        if ( (rc = ops->cache_op(b == 0x09 ? !repe_prefix() ||
                                             !vcpu_has_wbnoinvd()
                                             ? x86emul_wbinvd
                                             : x86emul_wbnoinvd
                                           : x86emul_invd,
                                 x86_seg_none, 0,
                                 ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x0b): /* ud2 */
    case X86EMUL_OPC(0x0f, 0xb9): /* ud1 */
    case X86EMUL_OPC(0x0f, 0xff): /* ud0 */
        generate_exception(EXC_UD);

    case X86EMUL_OPC(0x0f, 0x0d): /* GrpP (prefetch) */
    case X86EMUL_OPC(0x0f, 0x18): /* Grp16 (prefetch/nop) */
    case X86EMUL_OPC(0x0f, 0x19) ... X86EMUL_OPC(0x0f, 0x1f): /* nop */
        break;

#ifndef X86EMUL_NO_MMX

    case X86EMUL_OPC(0x0f, 0x0e): /* femms */
        host_and_vcpu_must_have(3dnow);
        asm volatile ( "femms" );
        break;

    case X86EMUL_OPC(0x0f, 0x0f): /* 3DNow! */
        if ( _3dnow_table[(imm1 >> 4) & 0xf] & (1 << (imm1 & 0xf)) )
            host_and_vcpu_must_have(3dnow);
        else if ( _3dnow_ext_table[(imm1 >> 4) & 0xf] & (1 << (imm1 & 0xf)) )
            host_and_vcpu_must_have(3dnow_ext);
        else
            generate_exception(EXC_UD);

        get_fpu(X86EMUL_FPU_mmx);

        d = DstReg | SrcMem;
        op_bytes = 8;
        state->simd_size = simd_other;
        goto simd_0f_imm8;

#endif /* !X86EMUL_NO_MMX */

#if !defined(X86EMUL_NO_SIMD) && !defined(X86EMUL_NO_MMX)
# define CASE_SIMD_PACKED_INT(pfx, opc)      \
    case X86EMUL_OPC(pfx, opc):              \
    case X86EMUL_OPC_66(pfx, opc)
#elif !defined(X86EMUL_NO_SIMD)
# define CASE_SIMD_PACKED_INT(pfx, opc)      \
    case X86EMUL_OPC_66(pfx, opc)
#elif !defined(X86EMUL_NO_MMX)
# define CASE_SIMD_PACKED_INT(pfx, opc)      \
    case X86EMUL_OPC(pfx, opc)
#else
# define CASE_SIMD_PACKED_INT(pfx, opc) C##pfx##_##opc
#endif

#ifndef X86EMUL_NO_SIMD

# define CASE_SIMD_PACKED_INT_VEX(pfx, opc)  \
    CASE_SIMD_PACKED_INT(pfx, opc):          \
    case X86EMUL_OPC_VEX_66(pfx, opc)

# define CASE_SIMD_ALL_FP(kind, pfx, opc)    \
    CASE_SIMD_PACKED_FP(kind, pfx, opc):     \
    CASE_SIMD_SCALAR_FP(kind, pfx, opc)
# define CASE_SIMD_PACKED_FP(kind, pfx, opc) \
    case X86EMUL_OPC##kind(pfx, opc):        \
    case X86EMUL_OPC##kind##_66(pfx, opc)
# define CASE_SIMD_SCALAR_FP(kind, pfx, opc) \
    case X86EMUL_OPC##kind##_F3(pfx, opc):   \
    case X86EMUL_OPC##kind##_F2(pfx, opc)
# define CASE_SIMD_SINGLE_FP(kind, pfx, opc) \
    case X86EMUL_OPC##kind(pfx, opc):        \
    case X86EMUL_OPC##kind##_F3(pfx, opc)

# define CASE_SIMD_ALL_FP_VEX(pfx, opc)      \
    CASE_SIMD_ALL_FP(, pfx, opc):            \
    CASE_SIMD_ALL_FP(_VEX, pfx, opc)
# define CASE_SIMD_PACKED_FP_VEX(pfx, opc)   \
    CASE_SIMD_PACKED_FP(, pfx, opc):         \
    CASE_SIMD_PACKED_FP(_VEX, pfx, opc)
# define CASE_SIMD_SCALAR_FP_VEX(pfx, opc)   \
    CASE_SIMD_SCALAR_FP(, pfx, opc):         \
    CASE_SIMD_SCALAR_FP(_VEX, pfx, opc)
# define CASE_SIMD_SINGLE_FP_VEX(pfx, opc)   \
    CASE_SIMD_SINGLE_FP(, pfx, opc):         \
    CASE_SIMD_SINGLE_FP(_VEX, pfx, opc)

#else

# define CASE_SIMD_PACKED_INT_VEX(pfx, opc)  \
    CASE_SIMD_PACKED_INT(pfx, opc)

# define CASE_SIMD_ALL_FP(kind, pfx, opc)    C##kind##pfx##_##opc
# define CASE_SIMD_PACKED_FP(kind, pfx, opc) Cp##kind##pfx##_##opc
# define CASE_SIMD_SCALAR_FP(kind, pfx, opc) Cs##kind##pfx##_##opc
# define CASE_SIMD_SINGLE_FP(kind, pfx, opc) C##kind##pfx##_##opc

# define CASE_SIMD_ALL_FP_VEX(pfx, opc)    CASE_SIMD_ALL_FP(, pfx, opc)
# define CASE_SIMD_PACKED_FP_VEX(pfx, opc) CASE_SIMD_PACKED_FP(, pfx, opc)
# define CASE_SIMD_SCALAR_FP_VEX(pfx, opc) CASE_SIMD_SCALAR_FP(, pfx, opc)
# define CASE_SIMD_SINGLE_FP_VEX(pfx, opc) CASE_SIMD_SINGLE_FP(, pfx, opc)

#endif

    CASE_SIMD_SCALAR_FP(, 0x0f, 0x2b):     /* movnts{s,d} xmm,mem */
        host_and_vcpu_must_have(sse4a);
        /* fall through */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x2b):   /* movntp{s,d} xmm,m128 */
                                           /* vmovntp{s,d} {x,y}mm,mem */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        sfence = true;
        /* fall through */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x10):      /* mov{up,s}{s,d} xmm/mem,xmm */
                                           /* vmovup{s,d} {x,y}mm/mem,{x,y}mm */
                                           /* vmovs{s,d} mem,xmm */
                                           /* vmovs{s,d} xmm,xmm,xmm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x11):      /* mov{up,s}{s,d} xmm,xmm/mem */
                                           /* vmovup{s,d} {x,y}mm,{x,y}mm/mem */
                                           /* vmovs{s,d} xmm,mem */
                                           /* vmovs{s,d} xmm,xmm,xmm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x14):   /* unpcklp{s,d} xmm/m128,xmm */
                                           /* vunpcklp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x15):   /* unpckhp{s,d} xmm/m128,xmm */
                                           /* vunpckhp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x28):   /* movap{s,d} xmm/m128,xmm */
                                           /* vmovap{s,d} {x,y}mm/mem,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x29):   /* movap{s,d} xmm,xmm/m128 */
                                           /* vmovap{s,d} {x,y}mm,{x,y}mm/mem */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x51):      /* sqrt{p,s}{s,d} xmm/mem,xmm */
                                           /* vsqrtp{s,d} {x,y}mm/mem,{x,y}mm */
                                           /* vsqrts{s,d} xmm/m32,xmm,xmm */
    CASE_SIMD_SINGLE_FP_VEX(0x0f, 0x52):   /* rsqrt{p,s}s xmm/mem,xmm */
                                           /* vrsqrtps {x,y}mm/mem,{x,y}mm */
                                           /* vrsqrtss xmm/m32,xmm,xmm */
    CASE_SIMD_SINGLE_FP_VEX(0x0f, 0x53):   /* rcp{p,s}s xmm/mem,xmm */
                                           /* vrcpps {x,y}mm/mem,{x,y}mm */
                                           /* vrcpss xmm/m32,xmm,xmm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x54):   /* andp{s,d} xmm/m128,xmm */
                                           /* vandp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x55):   /* andnp{s,d} xmm/m128,xmm */
                                           /* vandnp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x56):   /* orp{s,d} xmm/m128,xmm */
                                           /* vorp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x57):   /* xorp{s,d} xmm/m128,xmm */
                                           /* vxorp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x58):      /* add{p,s}{s,d} xmm/mem,xmm */
                                           /* vadd{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x59):      /* mul{p,s}{s,d} xmm/mem,xmm */
                                           /* vmul{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x5c):      /* sub{p,s}{s,d} xmm/mem,xmm */
                                           /* vsub{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x5d):      /* min{p,s}{s,d} xmm/mem,xmm */
                                           /* vmin{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x5e):      /* div{p,s}{s,d} xmm/mem,xmm */
                                           /* vdiv{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP_VEX(0x0f, 0x5f):      /* max{p,s}{s,d} xmm/mem,xmm */
                                           /* vmax{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_fp:
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
            {
    simd_0f_sse2:
                vcpu_must_have(sse2);
            }
            else
                vcpu_must_have(sse);
    simd_0f_xmm:
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            /* vmovs{s,d} to/from memory have only two operands. */
            if ( (b & ~1) == 0x10 && ea.type == OP_MEM )
                d |= TwoOp;
    simd_0f_avx:
            host_and_vcpu_must_have(avx);
    simd_0f_ymm:
            get_fpu(X86EMUL_FPU_ymm);
        }
    simd_0f_common:
        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* convert memory operand to (%rAX) */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 2;
        break;

    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x2b): /* vmovntp{s,d} [xyz]mm,mem */
        generate_exception_if(ea.type != OP_MEM || evex.opmsk, EXC_UD);
        sfence = true;
        /* fall through */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x10): /* vmovup{s,d} [xyz]mm/mem,[xyz]mm{k} */
    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x10): /* vmovs{s,d} mem,xmm{k} */
                                            /* vmovs{s,d} xmm,xmm,xmm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x11): /* vmovup{s,d} [xyz]mm,[xyz]mm/mem{k} */
    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x11): /* vmovs{s,d} xmm,mem{k} */
                                            /* vmovs{s,d} xmm,xmm,xmm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x28): /* vmovap{s,d} [xyz]mm/mem,[xyz]mm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x29): /* vmovap{s,d} [xyz]mm,[xyz]mm/mem{k} */
        /* vmovs{s,d} to/from memory have only two operands. */
        if ( (b & ~1) == 0x10 && ea.type == OP_MEM )
            d |= TwoOp;
        generate_exception_if(evex.brs, EXC_UD);
        /* fall through */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x51):    /* vsqrtp{s,d} [xyz]mm/mem,[xyz]mm{k} */
                                            /* vsqrts{s,d} xmm/m32,xmm,xmm{k} */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x58):    /* vadd{p,s}{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x59):    /* vmul{p,s}{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x5c):    /* vsub{p,s}{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x5d):    /* vmin{p,s}{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x5e):    /* vdiv{p,s}{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x5f):    /* vmax{p,s}{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    avx512f_all_fp:
        generate_exception_if((evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK) ||
                               (ea.type != OP_REG && evex.brs &&
                                (evex.pfx & VEX_PREFIX_SCALAR_MASK))),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( ea.type != OP_REG || !evex.brs )
            avx512_vlen_check(evex.pfx & VEX_PREFIX_SCALAR_MASK);
    simd_zmm:
        get_fpu(X86EMUL_FPU_zmm);
        opc = init_evex(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* convert memory operand to (%rAX) */
            evex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = EVEX_PFX_BYTES + 2;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_66(0x0f, 0x12):       /* movlpd m64,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x12):   /* vmovlpd m64,xmm,xmm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x13):   /* movlp{s,d} xmm,m64 */
                                           /* vmovlp{s,d} xmm,m64 */
    case X86EMUL_OPC_66(0x0f, 0x16):       /* movhpd m64,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x16):   /* vmovhpd m64,xmm,xmm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x17):   /* movhp{s,d} xmm,m64 */
                                           /* vmovhp{s,d} xmm,m64 */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* fall through */
    case X86EMUL_OPC(0x0f, 0x12):          /* movlps m64,xmm */
                                           /* movhlps xmm,xmm */
    case X86EMUL_OPC_VEX(0x0f, 0x12):      /* vmovlps m64,xmm,xmm */
                                           /* vmovhlps xmm,xmm,xmm */
    case X86EMUL_OPC(0x0f, 0x16):          /* movhps m64,xmm */
                                           /* movlhps xmm,xmm */
    case X86EMUL_OPC_VEX(0x0f, 0x16):      /* vmovhps m64,xmm,xmm */
                                           /* vmovlhps xmm,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        if ( (d & DstMask) != DstMem )
            d &= ~TwoOp;
        op_bytes = 8;
        goto simd_0f_fp;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x12):   /* vmovlpd m64,xmm,xmm */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x13): /* vmovlp{s,d} xmm,m64 */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x16):   /* vmovhpd m64,xmm,xmm */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x17): /* vmovhp{s,d} xmm,m64 */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX(0x0f, 0x12):      /* vmovlps m64,xmm,xmm */
                                            /* vmovhlps xmm,xmm,xmm */
    case X86EMUL_OPC_EVEX(0x0f, 0x16):      /* vmovhps m64,xmm,xmm */
                                            /* vmovlhps xmm,xmm,xmm */
        generate_exception_if((evex.lr || evex.opmsk || evex.brs ||
                               evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK)),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( (d & DstMask) != DstMem )
            d &= ~TwoOp;
        op_bytes = 8;
        goto simd_zmm;

    case X86EMUL_OPC_F3(0x0f, 0x12):       /* movsldup xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x12):   /* vmovsldup {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F2(0x0f, 0x12):       /* movddup xmm/m64,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x12):   /* vmovddup {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x16):       /* movshdup xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x16):   /* vmovshdup {x,y}mm/mem,{x,y}mm */
        d |= TwoOp;
        op_bytes = !(vex.pfx & VEX_PREFIX_DOUBLE_MASK) || vex.l
                   ? 16 << vex.l : 8;
    simd_0f_sse3_avx:
        if ( vex.opcx != vex_none )
            goto simd_0f_avx;
        host_and_vcpu_must_have(sse3);
        goto simd_0f_xmm;

    case X86EMUL_OPC_EVEX_F3(0x0f, 0x12):   /* vmovsldup [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f, 0x12):   /* vmovddup [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0x16):   /* vmovshdup [xyz]mm/mem,[xyz]mm{k} */
        generate_exception_if((evex.brs ||
                               evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK)),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        avx512_vlen_check(false);
        d |= TwoOp;
        op_bytes = !(evex.pfx & VEX_PREFIX_DOUBLE_MASK) || evex.lr
                   ? 16 << evex.lr : 8;
        fault_suppression = false;
        goto simd_zmm;

    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x14): /* vunpcklp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x15): /* vunpckhp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK),
                              EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x76): /* vpermi2{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x77): /* vpermi2p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x7e): /* vpermt2{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x7f): /* vpermt2p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        fault_suppression = false;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xdb): /* vpand{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xdf): /* vpandn{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xeb): /* vpor{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xef): /* vpxor{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x14): /* vprorv{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x15): /* vprolv{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x39): /* vpmins{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x3b): /* vpminu{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x3d): /* vpmaxs{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x3f): /* vpmaxu{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x45): /* vpsrlv{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x46): /* vpsrav{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x47): /* vpsllv{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x4c): /* vrcp14p{s,d} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x4e): /* vrsqrt14p{s,d} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x64): /* vpblendm{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x65): /* vblendmp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    avx512f_no_sae:
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(ea.type != OP_MEM && evex.brs, EXC_UD);
        avx512_vlen_check(false);
        goto simd_zmm;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC(0x0f, 0x20): /* mov cr,reg */
    case X86EMUL_OPC(0x0f, 0x21): /* mov dr,reg */
    case X86EMUL_OPC(0x0f, 0x22): /* mov reg,cr */
    case X86EMUL_OPC(0x0f, 0x23): /* mov reg,dr */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        if ( b & 2 )
        {
            /* Write to CR/DR. */
            typeof(ops->write_cr) write = (b & 1) ? ops->write_dr
                                                  : ops->write_cr;

            fail_if(!write);
            rc = write(modrm_reg, src.val, ctxt);
        }
        else
        {
            /* Read from CR/DR. */
            typeof(ops->read_cr) read = (b & 1) ? ops->read_dr : ops->read_cr;

            fail_if(!read);
            rc = read(modrm_reg, &dst.val, ctxt);
        }
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;

#if !defined(X86EMUL_NO_MMX) && !defined(X86EMUL_NO_SIMD)

    case X86EMUL_OPC_66(0x0f, 0x2a):       /* cvtpi2pd mm/m64,xmm */
        if ( ea.type == OP_REG )
        {
    case X86EMUL_OPC(0x0f, 0x2a):          /* cvtpi2ps mm/m64,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x2c):     /* cvttp{s,d}2pi xmm/mem,mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x2d):     /* cvtp{s,d}2pi xmm/mem,mm */
            host_and_vcpu_must_have(mmx);
        }
        op_bytes = (b & 4) && (vex.pfx & VEX_PREFIX_DOUBLE_MASK) ? 16 : 8;
        goto simd_0f_fp;

#endif /* !X86EMUL_NO_MMX && !X86EMUL_NO_SIMD */

    CASE_SIMD_SCALAR_FP_VEX(0x0f, 0x2a):   /* {,v}cvtsi2s{s,d} r/m,xmm */
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                vcpu_must_have(sse2);
            else
                vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        if ( ea.type == OP_MEM )
        {
            rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val,
                            rex_prefix & REX_W ? 8 : 4, ctxt, ops);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        else
            src.val = rex_prefix & REX_W ? *ea.reg : (uint32_t)*ea.reg;

        state->simd_size = simd_none;
        goto simd_0f_rm;

    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x2a): /* vcvtsi2s{s,d} r/m,xmm,xmm */
    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x7b): /* vcvtusi2s{s,d} r/m,xmm,xmm */
        generate_exception_if(evex.opmsk || (ea.type != OP_REG && evex.brs),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( !evex.brs )
            avx512_vlen_check(true);
        get_fpu(X86EMUL_FPU_zmm);

        if ( ea.type == OP_MEM )
        {
            rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val,
                            rex_prefix & REX_W ? 8 : 4, ctxt, ops);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        else
            src.val = *ea.reg;

        opc = init_evex(stub);
        opc[0] = b;
        /* Convert memory/GPR source to %rAX. */
        evex.b = 1;
        if ( !mode_64bit() )
            evex.w = 0;
        /*
         * SDM version 067 claims that exception type E10NF implies #UD when
         * EVEX.L'L is non-zero for 32-bit VCVT{,U}SI2SD. Experimentally this
         * cannot be confirmed, but be on the safe side for the stub.
         */
        if ( !evex.w && evex.pfx == vex_f2 )
            evex.lr = 0;
        opc[1] = (modrm & 0x38) | 0xc0;
        insn_bytes = EVEX_PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_EVEX(opc, evex);
        invoke_stub("", "", "=g" (dummy) : "a" (src.val));

        put_stub(stub);
        state->simd_size = simd_none;
        break;

    CASE_SIMD_SCALAR_FP_VEX(0x0f, 0x2c):   /* {,v}cvtts{s,d}2si xmm/mem,reg */
    CASE_SIMD_SCALAR_FP_VEX(0x0f, 0x2d):   /* {,v}cvts{s,d}2si xmm/mem,reg */
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                vcpu_must_have(sse2);
            else
                vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);

            /* Work around erratum BT230. */
            vex.l = 0;
        }

        opc = init_prefixes(stub);
    cvts_2si:
        opc[0] = b;
        /* Convert GPR destination to %rAX and memory operand to (%rCX). */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        evex.r = 1;
        if ( ea.type == OP_MEM )
        {
            rex_prefix &= ~REX_B;
            vex.b = 1;
            evex.b = 1;
            opc[1] = 0x01;

            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp,
                           vex.pfx & VEX_PREFIX_DOUBLE_MASK ? 8 : 4, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        else
            opc[1] = modrm & 0xc7;
        if ( !mode_64bit() )
        {
            vex.w = 0;
            evex.w = 0;
        }
        if ( evex_encoded() )
        {
            insn_bytes = EVEX_PFX_BYTES + 2;
            copy_EVEX(opc, evex);
        }
        else
        {
            insn_bytes = PFX_BYTES + 2;
            copy_REX_VEX(opc, rex_prefix, vex);
        }
        opc[2] = 0xc3;

        ea.reg = decode_gpr(&_regs, modrm_reg);
        invoke_stub("", "", "=a" (*ea.reg) : "c" (mmvalp), "m" (*mmvalp));

        put_stub(stub);
        state->simd_size = simd_none;
        break;

    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x2c): /* vcvtts{s,d}2si xmm/mem,reg */
    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x2d): /* vcvts{s,d}2si xmm/mem,reg */
    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x78): /* vcvtts{s,d}2usi xmm/mem,reg */
    CASE_SIMD_SCALAR_FP(_EVEX, 0x0f, 0x79): /* vcvts{s,d}2usi xmm/mem,reg */
        generate_exception_if((evex.reg != 0xf || !evex.RX || evex.opmsk ||
                               (ea.type != OP_REG && evex.brs)),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( !evex.brs )
            avx512_vlen_check(true);
        get_fpu(X86EMUL_FPU_zmm);
        opc = init_evex(stub);
        goto cvts_2si;

    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x2e):   /* {,v}ucomis{s,d} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x2f):   /* {,v}comis{s,d} xmm/mem,xmm */
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx )
                vcpu_must_have(sse2);
            else
                vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        op_bytes = 4 << vex.pfx;
    vcomi:
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, op_bytes, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;

            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            evex.b = 1;
            opc[1] &= 0x38;
        }
        if ( evex_encoded() )
        {
            insn_bytes = EVEX_PFX_BYTES + 2;
            copy_EVEX(opc, evex);
        }
        else
        {
            insn_bytes = PFX_BYTES + 2;
            copy_REX_VEX(opc, rex_prefix, vex);
        }
        opc[2] = 0xc3;

        invoke_stub(_PRE_EFLAGS("[eflags]", "[mask]", "[tmp]"),
                    _POST_EFLAGS("[eflags]", "[mask]", "[tmp]"),
                    [eflags] "+g" (_regs.eflags),
                    [tmp] "=&r" (dummy), "+m" (*mmvalp)
                    : "a" (mmvalp), [mask] "i" (EFLAGS_MASK));

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x2e): /* vucomis{s,d} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x2f): /* vcomis{s,d} xmm/mem,xmm */
        generate_exception_if((evex.reg != 0xf || !evex.RX || evex.opmsk ||
                               (ea.type != OP_REG && evex.brs) ||
                               evex.w != evex.pfx),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( !evex.brs )
            avx512_vlen_check(true);
        get_fpu(X86EMUL_FPU_zmm);

        opc = init_evex(stub);
        op_bytes = 4 << evex.w;
        goto vcomi;

    case X86EMUL_OPC(0x0f, 0x30): /* wrmsr */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->write_msr == NULL);
        if ( (rc = ops->write_msr(_regs.ecx,
                                  ((uint64_t)_regs.r(dx) << 32) | _regs.eax,
                                  ctxt)) != 0 )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x31): rdtsc: /* rdtsc */
        if ( !mode_ring0() )
        {
            fail_if(ops->read_cr == NULL);
            if ( (rc = ops->read_cr(4, &cr4, ctxt)) )
                goto done;
            generate_exception_if(cr4 & X86_CR4_TSD, EXC_GP, 0);
        }
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_IA32_TSC,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(dx) = msr_val >> 32;
        _regs.r(ax) = (uint32_t)msr_val;
        break;

    case X86EMUL_OPC(0x0f, 0x32): /* rdmsr */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(_regs.ecx, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(dx) = msr_val >> 32;
        _regs.r(ax) = (uint32_t)msr_val;
        break;

    case X86EMUL_OPC(0x0f, 0x34): /* sysenter */
        vcpu_must_have(sep);
        generate_exception_if(amd_like(ctxt) && ctxt->lma, EXC_UD);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);

        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_CS,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        generate_exception_if(!(msr_val & 0xfffc), EXC_GP, 0);

        _regs.eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IF | X86_EFLAGS_RF);

        cs.sel = msr_val & ~3; /* SELECTOR_RPL_MASK */
        cs.base = 0;   /* flat segment */
        cs.limit = ~0u;  /* 4GB limit */
        cs.attr = ctxt->lma ? 0xa9b  /* G+L+P+S+Code */
                            : 0xc9b; /* G+DB+P+S+Code */

        sreg.sel = cs.sel + 8;
        sreg.base = 0;   /* flat segment */
        sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr = 0xc93; /* G+DB+P+S+Data */

        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_EIP,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(ip) = ctxt->lma ? msr_val : (uint32_t)msr_val;

        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_ESP,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(sp) = ctxt->lma ? msr_val : (uint32_t)msr_val;

        fail_if(!ops->write_segment);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs,
                                      ctxt)) != X86EMUL_OKAY ||
             (rc = ops->write_segment(x86_seg_ss, &sreg,
                                      ctxt)) != X86EMUL_OKAY )
            goto done;

        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x35): /* sysexit */
        vcpu_must_have(sep);
        generate_exception_if(amd_like(ctxt) && ctxt->lma, EXC_UD);
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);

        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_CS,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        generate_exception_if(!(msr_val & 0xfffc), EXC_GP, 0);
        generate_exception_if(op_bytes == 8 &&
                              (!is_canonical_address(_regs.r(dx)) ||
                               !is_canonical_address(_regs.r(cx))),
                              EXC_GP, 0);

        cs.sel = (msr_val | 3) + /* SELECTOR_RPL_MASK */
                 (op_bytes == 8 ? 32 : 16);
        cs.base = 0;   /* flat segment */
        cs.limit = ~0u;  /* 4GB limit */
        cs.attr = op_bytes == 8 ? 0xafb  /* L+DB+P+DPL3+S+Code */
                                : 0xcfb; /* G+DB+P+DPL3+S+Code */

        sreg.sel = cs.sel + 8;
        sreg.base = 0;   /* flat segment */
        sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr = 0xcf3; /* G+DB+P+DPL3+S+Data */

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) != 0 ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) != 0 )
            goto done;

        _regs.r(ip) = op_bytes == 8 ? _regs.r(dx) : _regs.edx;
        _regs.r(sp) = op_bytes == 8 ? _regs.r(cx) : _regs.ecx;

        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x40) ... X86EMUL_OPC(0x0f, 0x4f): /* cmovcc */
        vcpu_must_have(cmov);
        if ( test_cc(b, _regs.eflags) )
            dst.val = src.val;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_VEX(0x0f, 0x4a):    /* kadd{w,q} k,k,k */
        if ( !vex.w )
            host_and_vcpu_must_have(avx512dq);
        /* fall through */
    case X86EMUL_OPC_VEX(0x0f, 0x41):    /* kand{w,q} k,k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x41): /* kand{b,d} k,k,k */
    case X86EMUL_OPC_VEX(0x0f, 0x42):    /* kandn{w,q} k,k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x42): /* kandn{b,d} k,k,k */
    case X86EMUL_OPC_VEX(0x0f, 0x45):    /* kor{w,q} k,k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x45): /* kor{b,d} k,k,k */
    case X86EMUL_OPC_VEX(0x0f, 0x46):    /* kxnor{w,q} k,k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x46): /* kxnor{b,d} k,k,k */
    case X86EMUL_OPC_VEX(0x0f, 0x47):    /* kxor{w,q} k,k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x47): /* kxor{b,d} k,k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x4a): /* kadd{b,d} k,k,k */
        generate_exception_if(!vex.l, EXC_UD);
    opmask_basic:
        if ( vex.w )
            host_and_vcpu_must_have(avx512bw);
        else if ( vex.pfx )
            host_and_vcpu_must_have(avx512dq);
    opmask_common:
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(!vex.r || (mode_64bit() && !(vex.reg & 8)) ||
                              ea.type != OP_REG, EXC_UD);

        vex.reg |= 8;
        d &= ~TwoOp;

        get_fpu(X86EMUL_FPU_opmask);

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        insn_bytes = PFX_BYTES + 2;

        state->simd_size = simd_other;
        op_bytes = 1; /* Any non-zero value will do. */
        break;

    case X86EMUL_OPC_VEX(0x0f, 0x44):    /* knot{w,q} k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x44): /* knot{b,d} k,k */
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
        goto opmask_basic;

    case X86EMUL_OPC_VEX(0x0f, 0x4b):    /* kunpck{w,d}{d,q} k,k,k */
        generate_exception_if(!vex.l, EXC_UD);
        host_and_vcpu_must_have(avx512bw);
        goto opmask_common;

    case X86EMUL_OPC_VEX_66(0x0f, 0x4b): /* kunpckbw k,k,k */
        generate_exception_if(!vex.l || vex.w, EXC_UD);
        goto opmask_common;

#endif /* X86EMUL_NO_SIMD */

    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x50):   /* movmskp{s,d} xmm,reg */
                                           /* vmovmskp{s,d} {x,y}mm,reg */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd7):  /* pmovmskb {,x}mm,reg */
                                           /* vpmovmskb {x,y}mm,reg */
        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR destination to %rAX. */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        insn_bytes = PFX_BYTES + 2;
    simd_0f_to_gpr:
        opc[insn_bytes - PFX_BYTES] = 0xc3;

        generate_exception_if(ea.type != OP_REG, EXC_UD);

        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                vcpu_must_have(sse2);
            else
            {
                if ( b != 0x50 )
                {
                    host_and_vcpu_must_have(mmx);
                    vcpu_must_have(mmxext);
                }
                else
                    vcpu_must_have(sse);
            }
            if ( b == 0x50 || (vex.pfx & VEX_PREFIX_DOUBLE_MASK) )
                get_fpu(X86EMUL_FPU_xmm);
            else
                get_fpu(X86EMUL_FPU_mmx);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            if ( b == 0x50 || !vex.l )
                host_and_vcpu_must_have(avx);
            else
                host_and_vcpu_must_have(avx2);
            get_fpu(X86EMUL_FPU_ymm);
        }

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "=a" (dst.val) : [dummy] "i" (0));

        put_stub(stub);

        ASSERT(!state->simd_size);
        dst.bytes = 4;
        break;

    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x54): /* vandp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x55): /* vandnp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x56): /* vorp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0x57): /* vxorp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if((evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK) ||
                               (ea.type != OP_MEM && evex.brs)),
                              EXC_UD);
        host_and_vcpu_must_have(avx512dq);
        avx512_vlen_check(false);
        goto simd_zmm;

    CASE_SIMD_ALL_FP_VEX(0x0f, 0x5a):      /* cvt{p,s}{s,d}2{p,s}{s,d} xmm/mem,xmm */
                                           /* vcvtp{s,d}2p{s,d} {x,y}mm/mem,{x,y}mm */
                                           /* vcvts{s,d}2s{s,d} xmm/mem,xmm,xmm */
        op_bytes = 4 << (((vex.pfx & VEX_PREFIX_SCALAR_MASK) ? 0 : 1 + vex.l) +
                         !!(vex.pfx & VEX_PREFIX_DOUBLE_MASK));
    simd_0f_cvt:
        if ( vex.opcx == vex_none )
            goto simd_0f_sse2;
        goto simd_0f_avx;

    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0x5a):   /* vcvtp{s,d}2p{s,d} [xyz]mm/mem,[xyz]mm{k} */
                                           /* vcvts{s,d}2s{s,d} xmm/mem,xmm,xmm{k} */
        op_bytes = 4 << (((evex.pfx & VEX_PREFIX_SCALAR_MASK) ? 0 : 1 + evex.lr) +
                         evex.w);
        goto avx512f_all_fp;

#ifndef X86EMUL_NO_SIMD

    CASE_SIMD_PACKED_FP_VEX(0x0f, 0x5b):   /* cvt{ps,dq}2{dq,ps} xmm/mem,xmm */
                                           /* vcvt{ps,dq}2{dq,ps} {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x5b):       /* cvttps2dq xmm/mem,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x5b):   /* vcvttps2dq {x,y}mm/mem,{x,y}mm */
        d |= TwoOp;
        op_bytes = 16 << vex.l;
        goto simd_0f_cvt;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x5b): /* vcvtps2dq [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0x5b): /* vcvttps2dq [xyz]mm/mem,[xyz]mm{k} */
        generate_exception_if(evex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX(0x0f, 0x5b):    /* vcvtdq2ps [xyz]mm/mem,[xyz]mm{k} */
                                          /* vcvtqq2ps [xyz]mm/mem,{x,y}mm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f, 0x7a): /* vcvtudq2ps [xyz]mm/mem,[xyz]mm{k} */
                                          /* vcvtuqq2ps [xyz]mm/mem,{x,y}mm{k} */
        if ( evex.w )
            host_and_vcpu_must_have(avx512dq);
        else
        {
    case X86EMUL_OPC_EVEX(0x0f, 0x78):    /* vcvttp{s,d}2udq [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX(0x0f, 0x79):    /* vcvtp{s,d}2udq [xyz]mm/mem,[xyz]mm{k} */
            host_and_vcpu_must_have(avx512f);
        }
        if ( ea.type != OP_REG || !evex.brs )
            avx512_vlen_check(false);
        d |= TwoOp;
        op_bytes = 16 << evex.lr;
        goto simd_zmm;

#endif /* !X86EMUL_NO_SIMD */

    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x60): /* punpcklbw {,x}mm/mem,{,x}mm */
                                          /* vpunpcklbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x61): /* punpcklwd {,x}mm/mem,{,x}mm */
                                          /* vpunpcklwd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x62): /* punpckldq {,x}mm/mem,{,x}mm */
                                          /* vpunpckldq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x68): /* punpckhbw {,x}mm/mem,{,x}mm */
                                          /* vpunpckhbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x69): /* punpckhwd {,x}mm/mem,{,x}mm */
                                          /* vpunpckhwd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x6a): /* punpckhdq {,x}mm/mem,{,x}mm */
                                          /* vpunpckhdq {x,y}mm/mem,{x,y}mm,{x,y}mm */
        op_bytes = vex.pfx ? 16 << vex.l : b & 8 ? 8 : 4;
        /* fall through */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x63): /* packssbw {,x}mm/mem,{,x}mm */
                                          /* vpackssbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x64): /* pcmpgtb {,x}mm/mem,{,x}mm */
                                          /* vpcmpgtb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x65): /* pcmpgtw {,x}mm/mem,{,x}mm */
                                          /* vpcmpgtw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x66): /* pcmpgtd {,x}mm/mem,{,x}mm */
                                          /* vpcmpgtd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x67): /* packusbw {,x}mm/mem,{,x}mm */
                                          /* vpackusbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x6b): /* packsswd {,x}mm/mem,{,x}mm */
                                          /* vpacksswd {x,y}mm/mem,{x,y}mm,{x,y}mm */
#ifndef X86EMUL_NO_SIMD
    case X86EMUL_OPC_66(0x0f, 0x6c):     /* punpcklqdq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6c): /* vpunpcklqdq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x6d):     /* punpckhqdq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6d): /* vpunpckhqdq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x74): /* pcmpeqb {,x}mm/mem,{,x}mm */
                                          /* vpcmpeqb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x75): /* pcmpeqw {,x}mm/mem,{,x}mm */
                                          /* vpcmpeqw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x76): /* pcmpeqd {,x}mm/mem,{,x}mm */
                                          /* vpcmpeqd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd1): /* psrlw {,x}mm/mem,{,x}mm */
                                          /* vpsrlw xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd2): /* psrld {,x}mm/mem,{,x}mm */
                                          /* vpsrld xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd3): /* psrlq {,x}mm/mem,{,x}mm */
                                          /* vpsrlq xmm/m128,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xd4):     /* paddq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd4): /* vpaddq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd5): /* pmullw {,x}mm/mem,{,x}mm */
                                          /* vpmullw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd8): /* psubusb {,x}mm/mem,{,x}mm */
                                          /* vpsubusb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xd9): /* psubusw {,x}mm/mem,{,x}mm */
                                          /* vpsubusw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xda):     /* pminub xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xda): /* vpminub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xdb): /* pand {,x}mm/mem,{,x}mm */
                                          /* vpand {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xdc): /* paddusb {,x}mm/mem,{,x}mm */
                                          /* vpaddusb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xdd): /* paddusw {,x}mm/mem,{,x}mm */
                                          /* vpaddusw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xde):     /* pmaxub xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xde): /* vpmaxub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xdf): /* pandn {,x}mm/mem,{,x}mm */
                                          /* vpandn {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xe0):     /* pavgb xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe0): /* vpavgb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xe1): /* psraw {,x}mm/mem,{,x}mm */
                                          /* vpsraw xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xe2): /* psrad {,x}mm/mem,{,x}mm */
                                          /* vpsrad xmm/m128,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xe3):     /* pavgw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe3): /* vpavgw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xe4):     /* pmulhuw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe4): /* vpmulhuw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xe5): /* pmulhw {,x}mm/mem,{,x}mm */
                                          /* vpmulhw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xe8): /* psubsb {,x}mm/mem,{,x}mm */
                                          /* vpsubsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xe9): /* psubsw {,x}mm/mem,{,x}mm */
                                          /* vpsubsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xea):     /* pminsw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xea): /* vpminsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xeb): /* por {,x}mm/mem,{,x}mm */
                                          /* vpor {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xec): /* paddsb {,x}mm/mem,{,x}mm */
                                          /* vpaddsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xed): /* paddsw {,x}mm/mem,{,x}mm */
                                          /* vpaddsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xee):     /* pmaxsw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xee): /* vpmaxsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xef): /* pxor {,x}mm/mem,{,x}mm */
                                          /* vpxor {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf1): /* psllw {,x}mm/mem,{,x}mm */
                                          /* vpsllw xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf2): /* pslld {,x}mm/mem,{,x}mm */
                                          /* vpslld xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf3): /* psllq {,x}mm/mem,{,x}mm */
                                          /* vpsllq xmm/m128,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xf4):     /* pmuludq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf4): /* vpmuludq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf5): /* pmaddwd {,x}mm/mem,{,x}mm */
                                          /* vpmaddwd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xf6):     /* psadbw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf6): /* vpsadbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf8): /* psubb {,x}mm/mem,{,x}mm */
                                          /* vpsubb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf9): /* psubw {,x}mm/mem,{,x}mm */
                                          /* vpsubw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xfa): /* psubd {,x}mm/mem,{,x}mm */
                                          /* vpsubd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xfb):     /* psubq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xfb): /* vpsubq {x,y}mm/mem,{x,y}mm,{x,y}mm */
#endif /* !X86EMUL_NO_SIMD */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xfc): /* paddb {,x}mm/mem,{,x}mm */
                                          /* vpaddb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xfd): /* paddw {,x}mm/mem,{,x}mm */
                                          /* vpaddw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xfe): /* paddd {,x}mm/mem,{,x}mm */
                                          /* vpaddd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_int:
#ifndef X86EMUL_NO_SIMD
        if ( vex.opcx != vex_none )
        {
    case X86EMUL_OPC_VEX_66(0x0f38, 0x00): /* vpshufb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x01): /* vphaddw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x02): /* vphaddd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x03): /* vphaddsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x04): /* vpmaddubsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x05): /* vphsubw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x06): /* vphsubd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x07): /* vphsubsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x08): /* vpsignb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x09): /* vpsignw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0a): /* vpsignd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0b): /* vpmulhrsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1c): /* vpabsb {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1d): /* vpabsw {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1e): /* vpabsd {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x28): /* vpmuldq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x29): /* vpcmpeqq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2b): /* vpackusdw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x37): /* vpcmpgtq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x38): /* vpminsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x39): /* vpminsd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3a): /* vpminub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3b): /* vpminud {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3c): /* vpmaxsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3d): /* vpmaxsd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3e): /* vpmaxub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3f): /* vpmaxud {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x40): /* vpmulld {x,y}mm/mem,{x,y}mm,{x,y}mm */
            if ( !vex.l )
                goto simd_0f_avx;
            /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x45): /* vpsrlv{d,q} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x47): /* vpsllv{d,q} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_avx2:
            host_and_vcpu_must_have(avx2);
            goto simd_0f_ymm;
        }
        if ( vex.pfx )
            goto simd_0f_sse2;
#endif /* !X86EMUL_NO_SIMD */
    simd_0f_mmx:
        host_and_vcpu_must_have(mmx);
        get_fpu(X86EMUL_FPU_mmx);
        goto simd_0f_common;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0xf6): /* vpsadbw [xyz]mm/mem,[xyz]mm,[xyz]mm */
        generate_exception_if(evex.opmsk, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x60): /* vpunpcklbw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x61): /* vpunpcklwd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x68): /* vpunpckhbw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x69): /* vpunpckhwd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        op_bytes = 16 << evex.lr;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x63): /* vpacksswb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x67): /* vpackuswb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd1): /* vpsrlw xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe1): /* vpsraw xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf1): /* vpsllw xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf5): /* vpmaddwd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x00): /* vpshufb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x04): /* vpmaddubsw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        fault_suppression = false;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd5): /* vpmullw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd8): /* vpsubusb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd9): /* vpsubusw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xdc): /* vpaddusb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xdd): /* vpaddusw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe0): /* vpavgb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe3): /* vpavgw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe5): /* vpmulhw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe8): /* vpsubsb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe9): /* vpsubsw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xec): /* vpaddsb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xed): /* vpaddsw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf8): /* vpsubb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf9): /* vpsubw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xfc): /* vpaddb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xfd): /* vpaddw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x0b): /* vpmulhrsw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x1c): /* vpabsb [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x1d): /* vpabsw [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x66): /* vpblendm{b,w} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.brs, EXC_UD);
        elem_bytes = 1 << (b & 1);
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x62): /* vpunpckldq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x6a): /* vpunpckhdq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(evex.w, EXC_UD);
        fault_suppression = false;
        op_bytes = 16 << evex.lr;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x26): /* vptestnm{b,w} [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x27): /* vptestnm{d,q} [xyz]mm/mem,[xyz]mm,k{k} */
        op_bytes = 16 << evex.lr;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f,   0x64): /* vpcmpeqb [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f,   0x65): /* vpcmpeqw [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f,   0x66): /* vpcmpeqd [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f,   0x74): /* vpcmpgtb [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f,   0x75): /* vpcmpgtw [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f,   0x76): /* vpcmpgtd [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x26): /* vptestm{b,w} [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x27): /* vptestm{d,q} [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x29): /* vpcmpeqq [xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x37): /* vpcmpgtq [xyz]mm/mem,[xyz]mm,k{k} */
        generate_exception_if(!evex.r || !evex.R || evex.z, EXC_UD);
        if ( b & (ext == ext_0f38 ? 1 : 2) )
        {
            generate_exception_if(b != 0x27 && evex.w != (b & 1), EXC_UD);
            goto avx512f_no_sae;
        }
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.brs, EXC_UD);
        elem_bytes = 1 << (ext == ext_0f ? b & 1 : evex.w);
        avx512_vlen_check(false);
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x6b): /* vpackssdw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x2b): /* vpackusdw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(evex.w || evex.brs, EXC_UD);
        fault_suppression = false;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x6c): /* vpunpcklqdq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x6d): /* vpunpckhqdq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        fault_suppression = false;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd4): /* vpaddq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf4): /* vpmuludq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x28): /* vpmuldq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(!evex.w, EXC_UD);
        goto avx512f_no_sae;

#endif /* X86EMUL_NO_SIMD */

    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x6e): /* mov{d,q} r/m,{,x}mm */
                                          /* vmov{d,q} r/m,xmm */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x7e): /* mov{d,q} {,x}mm,r/m */
                                          /* vmov{d,q} xmm,r/m */
        if ( vex.opcx != vex_none )
        {
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }

    simd_0f_rm:
        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert memory/GPR operand to (%rAX). */
        rex_prefix &= ~REX_B;
        vex.b = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0x38;
        insn_bytes = PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "+m" (src.val) : "a" (&src.val));
        dst.val = src.val;

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0x6e): /* vmov{d,q} r/m,xmm */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x7e): /* vmov{d,q} xmm,r/m */
        generate_exception_if((evex.lr || evex.opmsk || evex.brs ||
                               evex.reg != 0xf || !evex.RX),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        get_fpu(X86EMUL_FPU_zmm);

        opc = init_evex(stub);
        opc[0] = b;
        /* Convert memory/GPR operand to (%rAX). */
        evex.b = 1;
        if ( !mode_64bit() )
            evex.w = 0;
        opc[1] = modrm & 0x38;
        insn_bytes = EVEX_PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_EVEX(opc, evex);
        invoke_stub("", "", "+m" (src.val) : "a" (&src.val));
        dst.val = src.val;

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

    case X86EMUL_OPC_66(0x0f, 0xe7):     /* movntdq xmm,m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe7): /* vmovntdq {x,y}mm,mem */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        sfence = true;
        /* fall through */
    case X86EMUL_OPC_66(0x0f, 0x6f):     /* movdqa xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6f): /* vmovdqa {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x6f):     /* movdqu xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x6f): /* vmovdqu {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x7f):     /* movdqa xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7f): /* vmovdqa {x,y}mm,{x,y}mm/mem */
    case X86EMUL_OPC_F3(0x0f, 0x7f):     /* movdqu xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x7f): /* vmovdqu {x,y}mm,{x,y}mm/mem */
    movdqa:
        d |= TwoOp;
        op_bytes = 16 << vex.l;
        if ( vex.opcx != vex_none )
            goto simd_0f_avx;
        goto simd_0f_sse2;

    case X86EMUL_OPC_EVEX_66(0x0f, 0xe7): /* vmovntdq [xyz]mm,mem */
        generate_exception_if(ea.type != OP_MEM || evex.opmsk || evex.w,
                              EXC_UD);
        sfence = true;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x6f): /* vmovdqa{32,64} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0x6f): /* vmovdqu{32,64} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x7f): /* vmovdqa{32,64} [xyz]mm,[xyz]mm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0x7f): /* vmovdqu{32,64} [xyz]mm,[xyz]mm/mem{k} */
    vmovdqa:
        generate_exception_if(evex.brs, EXC_UD);
        d |= TwoOp;
        op_bytes = 16 << evex.lr;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_F2(0x0f, 0x6f): /* vmovdqu{8,16} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f, 0x7f): /* vmovdqu{8,16} [xyz]mm,[xyz]mm/mem{k} */
        host_and_vcpu_must_have(avx512bw);
        elem_bytes = 1 << evex.w;
        goto vmovdqa;

    case X86EMUL_OPC_VEX_66(0x0f, 0xd6): /* vmovq xmm,xmm/m64 */
        generate_exception_if(vex.l, EXC_UD);
        d |= TwoOp;
        /* fall through */
    case X86EMUL_OPC_66(0x0f, 0xd6):     /* movq xmm,xmm/m64 */
#endif /* !X86EMUL_NO_SIMD */
#ifndef X86EMUL_NO_MMX
    case X86EMUL_OPC(0x0f, 0x6f):        /* movq mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0x7f):        /* movq mm,mm/m64 */
#endif
        op_bytes = 8;
        goto simd_0f_int;

#ifndef X86EMUL_NO_SIMD
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0x70):/* pshuf{w,d} $imm8,{,x}mm/mem,{,x}mm */
                                         /* vpshufd $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x70):     /* pshufhw $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x70): /* vpshufhw $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F2(0x0f, 0x70):     /* pshuflw $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x70): /* vpshuflw $imm8,{x,y}mm/mem,{x,y}mm */
        d = (d & ~SrcMask) | SrcMem | TwoOp;
        op_bytes = vex.pfx ? 16 << vex.l : 8;
#endif
    simd_0f_int_imm8:
        if ( vex.opcx != vex_none )
        {
#ifndef X86EMUL_NO_SIMD
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0e): /* vpblendw $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0f): /* vpalignr $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x42): /* vmpsadbw $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
#endif
            if ( vex.l )
            {
    simd_0f_imm8_avx2:
                host_and_vcpu_must_have(avx2);
            }
            else
            {
#ifndef X86EMUL_NO_SIMD
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x08): /* vroundps $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x09): /* vroundpd $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0a): /* vroundss $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0b): /* vroundsd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0c): /* vblendps $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0d): /* vblendpd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x40): /* vdpps $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
#endif
    simd_0f_imm8_avx:
                host_and_vcpu_must_have(avx);
            }
    simd_0f_imm8_ymm:
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
    simd_0f_imm8_sse2:
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            vcpu_must_have(mmxext);
            get_fpu(X86EMUL_FPU_mmx);
        }
    simd_0f_imm8:
        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0x70): /* vpshufd $imm8,[xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0x70): /* vpshufhw $imm8,[xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f, 0x70): /* vpshuflw $imm8,[xyz]mm/mem,[xyz]mm{k} */
        if ( evex.pfx == vex_66 )
            generate_exception_if(evex.w, EXC_UD);
        else
        {
            host_and_vcpu_must_have(avx512bw);
            generate_exception_if(evex.brs, EXC_UD);
        }
        d = (d & ~SrcMask) | SrcMem | TwoOp;
        op_bytes = 16 << evex.lr;
        fault_suppression = false;
        goto avx512f_imm8_no_sae;

    CASE_SIMD_PACKED_INT(0x0f, 0x71):    /* Grp12 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x71):
    CASE_SIMD_PACKED_INT(0x0f, 0x72):    /* Grp13 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x72):
        switch ( modrm_reg & 7 )
        {
        case 2: /* psrl{w,d} $imm8,{,x}mm */
                /* vpsrl{w,d} $imm8,{x,y}mm,{x,y}mm */
        case 4: /* psra{w,d} $imm8,{,x}mm */
                /* vpsra{w,d} $imm8,{x,y}mm,{x,y}mm */
        case 6: /* psll{w,d} $imm8,{,x}mm */
                /* vpsll{w,d} $imm8,{x,y}mm,{x,y}mm */
            break;
        default:
            goto unrecognized_insn;
        }
    simd_0f_shift_imm:
        generate_exception_if(ea.type != OP_REG, EXC_UD);

        if ( vex.opcx != vex_none )
        {
            if ( vex.l )
                host_and_vcpu_must_have(avx2);
            else
                host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;

#endif /* X86EMUL_NO_SIMD */

    simd_0f_reg_only:
        opc[insn_bytes - PFX_BYTES] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", [dummy_out] "=g" (dummy) : [dummy_in] "i" (0) );

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0x71): /* Grp12 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* vpsrlw $imm8,[xyz]mm/mem,[xyz]mm{k} */
        case 4: /* vpsraw $imm8,[xyz]mm/mem,[xyz]mm{k} */
        case 6: /* vpsllw $imm8,[xyz]mm/mem,[xyz]mm{k} */
        avx512bw_shift_imm:
            fault_suppression = false;
            op_bytes = 16 << evex.lr;
            state->simd_size = simd_packed_int;
            goto avx512bw_imm;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x72): /* Grp13 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* vpsrld $imm8,[xyz]mm/mem,[xyz]mm{k} */
        case 6: /* vpslld $imm8,[xyz]mm/mem,[xyz]mm{k} */
            generate_exception_if(evex.w, EXC_UD);
            /* fall through */
        case 0: /* vpror{d,q} $imm8,[xyz]mm/mem,[xyz]mm{k} */
        case 1: /* vprol{d,q} $imm8,[xyz]mm/mem,[xyz]mm{k} */
        case 4: /* vpsra{d,q} $imm8,[xyz]mm/mem,[xyz]mm{k} */
        avx512f_shift_imm:
            op_bytes = 16 << evex.lr;
            state->simd_size = simd_packed_int;
            goto avx512f_imm8_no_sae;
        }
        goto unrecognized_insn;

#endif /* !X86EMUL_NO_SIMD */
#ifndef X86EMUL_NO_MMX

    case X86EMUL_OPC(0x0f, 0x73):        /* Grp14 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* psrlq $imm8,mm */
        case 6: /* psllq $imm8,mm */
            goto simd_0f_shift_imm;
        }
        goto unrecognized_insn;

#endif /* !X86EMUL_NO_MMX */
#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_66(0x0f, 0x73):
    case X86EMUL_OPC_VEX_66(0x0f, 0x73):
        switch ( modrm_reg & 7 )
        {
        case 2: /* psrlq $imm8,xmm */
                /* vpsrlq $imm8,{x,y}mm,{x,y}mm */
        case 3: /* psrldq $imm8,xmm */
                /* vpsrldq $imm8,{x,y}mm,{x,y}mm */
        case 6: /* psllq $imm8,xmm */
                /* vpsllq $imm8,{x,y}mm,{x,y}mm */
        case 7: /* pslldq $imm8,xmm */
                /* vpslldq $imm8,{x,y}mm,{x,y}mm */
            goto simd_0f_shift_imm;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC_EVEX_66(0x0f, 0x73): /* Grp14 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* vpsrlq $imm8,[xyz]mm/mem,[xyz]mm{k} */
        case 6: /* vpsllq $imm8,[xyz]mm/mem,[xyz]mm{k} */
            generate_exception_if(!evex.w, EXC_UD);
            goto avx512f_shift_imm;
        case 3: /* vpsrldq $imm8,[xyz]mm/mem,[xyz]mm */
        case 7: /* vpslldq $imm8,[xyz]mm/mem,[xyz]mm */
            generate_exception_if(evex.opmsk, EXC_UD);
            goto avx512bw_shift_imm;
        }
        goto unrecognized_insn;

#endif /* !X86EMUL_NO_SIMD */

#ifndef X86EMUL_NO_MMX
    case X86EMUL_OPC(0x0f, 0x77):        /* emms */
#endif
#ifndef X86EMUL_NO_SIMD
    case X86EMUL_OPC_VEX(0x0f, 0x77):    /* vzero{all,upper} */
        if ( vex.opcx != vex_none )
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);

#ifdef __x86_64__
            if ( !mode_64bit() )
            {
                /*
                 * Can't use the actual instructions here, as we must not
                 * touch YMM8...YMM15.
                 */
                if ( vex.l )
                {
                    /* vpxor %xmmN, %xmmN, %xmmN */
                    asm volatile ( ".byte 0xc5,0xf9,0xef,0xc0" );
                    asm volatile ( ".byte 0xc5,0xf1,0xef,0xc9" );
                    asm volatile ( ".byte 0xc5,0xe9,0xef,0xd2" );
                    asm volatile ( ".byte 0xc5,0xe1,0xef,0xdb" );
                    asm volatile ( ".byte 0xc5,0xd9,0xef,0xe4" );
                    asm volatile ( ".byte 0xc5,0xd1,0xef,0xed" );
                    asm volatile ( ".byte 0xc5,0xc9,0xef,0xf6" );
                    asm volatile ( ".byte 0xc5,0xc1,0xef,0xff" );
                }
                else
                {
                    /* vpor %xmmN, %xmmN, %xmmN */
                    asm volatile ( ".byte 0xc5,0xf9,0xeb,0xc0" );
                    asm volatile ( ".byte 0xc5,0xf1,0xeb,0xc9" );
                    asm volatile ( ".byte 0xc5,0xe9,0xeb,0xd2" );
                    asm volatile ( ".byte 0xc5,0xe1,0xeb,0xdb" );
                    asm volatile ( ".byte 0xc5,0xd9,0xeb,0xe4" );
                    asm volatile ( ".byte 0xc5,0xd1,0xeb,0xed" );
                    asm volatile ( ".byte 0xc5,0xc9,0xeb,0xf6" );
                    asm volatile ( ".byte 0xc5,0xc1,0xeb,0xff" );
                }

                ASSERT(!state->simd_size);
                break;
            }
#endif
        }
        else
#endif /* !X86EMUL_NO_SIMD */
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }

        /* Work around erratum BT36. */
        vex.w = 0;

        opc = init_prefixes(stub);
        opc[0] = b;
        insn_bytes = PFX_BYTES + 1;
        goto simd_0f_reg_only;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_66(0x0f, 0x78):     /* Grp17 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* extrq $imm8,$imm8,xmm */
            break;
        default:
            goto unrecognized_insn;
        }
        /* fall through */
    case X86EMUL_OPC_F2(0x0f, 0x78):     /* insertq $imm8,$imm8,xmm,xmm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);

        host_and_vcpu_must_have(sse4a);
        get_fpu(X86EMUL_FPU_xmm);

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        opc[2] = imm1;
        opc[3] = imm2;
        insn_bytes = PFX_BYTES + 4;
        goto simd_0f_reg_only;

    case X86EMUL_OPC_66(0x0f, 0x79):     /* extrq xmm,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x79):     /* insertq xmm,xmm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        host_and_vcpu_must_have(sse4a);
        op_bytes = 8;
        goto simd_0f_xmm;

    case X86EMUL_OPC_EVEX_66(0x0f, 0xe6):   /* vcvttpd2dq [xyz]mm/mem,{x,y}mm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f, 0xe6):   /* vcvtpd2dq [xyz]mm/mem,{x,y}mm{k} */
        generate_exception_if(!evex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0x7a):   /* vcvtudq2pd {x,y}mm/mem,[xyz]mm{k} */
                                            /* vcvtuqq2pd [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f, 0xe6):   /* vcvtdq2pd {x,y}mm/mem,[xyz]mm{k} */
                                            /* vcvtqq2pd [xyz]mm/mem,[xyz]mm{k} */
        if ( evex.pfx != vex_f3 )
            host_and_vcpu_must_have(avx512f);
        else if ( evex.w )
        {
    case X86EMUL_OPC_EVEX_66(0x0f, 0x78):   /* vcvttps2uqq {x,y}mm/mem,[xyz]mm{k} */
                                            /* vcvttpd2uqq [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x79):   /* vcvtps2uqq {x,y}mm/mem,[xyz]mm{k} */
                                            /* vcvtpd2uqq [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x7a):   /* vcvttps2qq {x,y}mm/mem,[xyz]mm{k} */
                                            /* vcvttpd2qq [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0x7b):   /* vcvtps2qq {x,y}mm/mem,[xyz]mm{k} */
                                            /* vcvtpd2qq [xyz]mm/mem,[xyz]mm{k} */
            host_and_vcpu_must_have(avx512dq);
        }
        else
        {
            host_and_vcpu_must_have(avx512f);
            generate_exception_if(ea.type != OP_MEM && evex.brs, EXC_UD);
        }
        if ( ea.type != OP_REG || !evex.brs )
            avx512_vlen_check(false);
        d |= TwoOp;
        op_bytes = 8 << (evex.w + evex.lr);
        goto simd_zmm;

    case X86EMUL_OPC_F2(0x0f, 0xf0):     /* lddqu m128,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0xf0): /* vlddqu mem,{x,y}mm */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_66(0x0f, 0x7c):     /* haddpd xmm/m128,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x7c):     /* haddps xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7c): /* vhaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x7c): /* vhaddps {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x7d):     /* hsubpd xmm/m128,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x7d):     /* hsubps xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7d): /* vhsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x7d): /* vhsubps {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xd0):     /* addsubpd xmm/m128,xmm */
    case X86EMUL_OPC_F2(0x0f, 0xd0):     /* addsubps xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd0): /* vaddsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0xd0): /* vaddsubps {x,y}mm/mem,{x,y}mm,{x,y}mm */
        op_bytes = 16 << vex.l;
        goto simd_0f_sse3_avx;

    case X86EMUL_OPC_F3(0x0f, 0x7e):     /* movq xmm/m64,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x7e): /* vmovq xmm/m64,xmm */
        generate_exception_if(vex.l, EXC_UD);
        op_bytes = 8;
        goto simd_0f_int;

    case X86EMUL_OPC_EVEX_F3(0x0f, 0x7e): /* vmovq xmm/m64,xmm */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd6): /* vmovq xmm,xmm/m64 */
        generate_exception_if(evex.lr || !evex.w || evex.opmsk || evex.brs,
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        d |= TwoOp;
        op_bytes = 8;
        goto simd_zmm;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC(0x0f, 0x80) ... X86EMUL_OPC(0x0f, 0x8f): /* jcc (near) */
        if ( test_cc(b, _regs.eflags) )
            jmp_rel((int32_t)src.val);
        adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case X86EMUL_OPC(0x0f, 0x90) ... X86EMUL_OPC(0x0f, 0x9f): /* setcc */
        dst.val = test_cc(b, _regs.eflags);
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_VEX(0x0f, 0x91):    /* kmov{w,q} k,mem */
    case X86EMUL_OPC_VEX_66(0x0f, 0x91): /* kmov{b,d} k,mem */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX(0x0f, 0x90):    /* kmov{w,q} k/mem,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x90): /* kmov{b,d} k/mem,k */
        generate_exception_if(vex.l || !vex.r, EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( vex.w )
        {
            host_and_vcpu_must_have(avx512bw);
            op_bytes = 4 << !vex.pfx;
        }
        else if ( vex.pfx )
        {
            host_and_vcpu_must_have(avx512dq);
            op_bytes = 1;
        }
        else
            op_bytes = 2;

        get_fpu(X86EMUL_FPU_opmask);

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* convert memory operand to (%rAX) */
            vex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 2;
        break;

    case X86EMUL_OPC_VEX(0x0f, 0x92):    /* kmovw r32,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x92): /* kmovb r32,k */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x92): /* kmov{d,q} reg,k */
        generate_exception_if(vex.l || !vex.r || vex.reg != 0xf ||
                              ea.type != OP_REG, EXC_UD);

        host_and_vcpu_must_have(avx512f);
        if ( vex.pfx == vex_f2 )
            host_and_vcpu_must_have(avx512bw);
        else
        {
            generate_exception_if(vex.w, EXC_UD);
            if ( vex.pfx )
                host_and_vcpu_must_have(avx512dq);
        }

        get_fpu(X86EMUL_FPU_opmask);

        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR source to %rAX. */
        vex.b = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xf8;
        opc[2] = 0xc3;

        copy_VEX(opc, vex);
        ea.reg = decode_gpr(&_regs, modrm_rm);
        invoke_stub("", "", "=m" (dummy) : "a" (*ea.reg));

        put_stub(stub);

        ASSERT(!state->simd_size);
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC_VEX(0x0f, 0x93):    /* kmovw k,r32 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x93): /* kmovb k,r32 */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x93): /* kmov{d,q} k,reg */
        generate_exception_if(vex.l || vex.reg != 0xf || ea.type != OP_REG,
                              EXC_UD);
        dst = ea;
        dst.reg = decode_gpr(&_regs, modrm_reg);

        host_and_vcpu_must_have(avx512f);
        if ( vex.pfx == vex_f2 )
        {
            host_and_vcpu_must_have(avx512bw);
            dst.bytes = 4 << (mode_64bit() && vex.w);
        }
        else
        {
            generate_exception_if(vex.w, EXC_UD);
            dst.bytes = 4;
            if ( vex.pfx )
                host_and_vcpu_must_have(avx512dq);
        }

        get_fpu(X86EMUL_FPU_opmask);

        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR destination to %rAX. */
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        opc[2] = 0xc3;

        copy_VEX(opc, vex);
        invoke_stub("", "", "=a" (dst.val) : [dummy] "i" (0));

        put_stub(stub);

        ASSERT(!state->simd_size);
        break;

    case X86EMUL_OPC_VEX(0x0f, 0x99):    /* ktest{w,q} k,k */
        if ( !vex.w )
            host_and_vcpu_must_have(avx512dq);
        /* fall through */
    case X86EMUL_OPC_VEX(0x0f, 0x98):    /* kortest{w,q} k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x98): /* kortest{b,d} k,k */
    case X86EMUL_OPC_VEX_66(0x0f, 0x99): /* ktest{b,d} k,k */
        generate_exception_if(vex.l || !vex.r || vex.reg != 0xf ||
                              ea.type != OP_REG, EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( vex.w )
            host_and_vcpu_must_have(avx512bw);
        else if ( vex.pfx )
            host_and_vcpu_must_have(avx512dq);

        get_fpu(X86EMUL_FPU_opmask);

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        opc[2] = 0xc3;

        copy_VEX(opc, vex);
        invoke_stub(_PRE_EFLAGS("[eflags]", "[mask]", "[tmp]"),
                    _POST_EFLAGS("[eflags]", "[mask]", "[tmp]"),
                    [eflags] "+g" (_regs.eflags),
                    "=a" (dst.val), [tmp] "=&r" (dummy)
                    : [mask] "i" (EFLAGS_MASK));

        put_stub(stub);

        ASSERT(!state->simd_size);
        dst.type = OP_NONE;
        break;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC(0x0f, 0xa2): /* cpuid */
        msr_val = 0;
        fail_if(ops->cpuid == NULL);

        /* Speculatively read MSR_INTEL_MISC_FEATURES_ENABLES. */
        if ( ops->read_msr && !mode_ring0() &&
             (rc = ops->read_msr(MSR_INTEL_MISC_FEATURES_ENABLES,
                                 &msr_val, ctxt)) == X86EMUL_EXCEPTION )
        {
            /* Not implemented.  Squash the exception and proceed normally. */
            x86_emul_reset_event(ctxt);
            rc = X86EMUL_OKAY;
        }
        if ( rc != X86EMUL_OKAY )
            goto done;

        generate_exception_if((msr_val & MSR_MISC_FEATURES_CPUID_FAULTING),
                              EXC_GP, 0); /* Faulting active? (Inc. CPL test) */

        rc = ops->cpuid(_regs.eax, _regs.ecx, &cpuid_leaf, ctxt);
        if ( rc != X86EMUL_OKAY )
            goto done;
        _regs.r(ax) = cpuid_leaf.a;
        _regs.r(bx) = cpuid_leaf.b;
        _regs.r(cx) = cpuid_leaf.c;
        _regs.r(dx) = cpuid_leaf.d;
        break;

    case X86EMUL_OPC(0x0f, 0xa3): bt: /* bt */
        generate_exception_if(lock_prefix, EXC_UD);

        if ( ops->rmw && dst.type == OP_MEM &&
             (rc = read_ulong(dst.mem.seg, dst.mem.off, &dst.val,
                              dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
            goto done;

        emulate_2op_SrcV_nobyte("bt", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0xa4): /* shld imm8,r,r/m */
    case X86EMUL_OPC(0x0f, 0xa5): /* shld %%cl,r,r/m */
    case X86EMUL_OPC(0x0f, 0xac): /* shrd imm8,r,r/m */
    case X86EMUL_OPC(0x0f, 0xad): /* shrd %%cl,r,r/m */ {
        uint8_t shift, width = dst.bytes << 3;

        generate_exception_if(lock_prefix, EXC_UD);

        if ( b & 1 )
            shift = _regs.cl;
        else
        {
            shift = src.val;
            src.reg = decode_gpr(&_regs, modrm_reg);
            src.val = truncate_word(*src.reg, dst.bytes);
        }

        if ( ops->rmw && dst.type == OP_MEM )
        {
            ea.orig_val = shift;
            state->rmw = b & 8 ? rmw_shrd : rmw_shld;
            break;
        }

        if ( (shift &= width - 1) == 0 )
            break;
        dst.orig_val = dst.val;
        dst.val = (b & 8) ?
                  /* shrd */
                  ((dst.orig_val >> shift) |
                   truncate_word(src.val << (width - shift), dst.bytes)) :
                  /* shld */
                  (truncate_word(dst.orig_val << shift, dst.bytes) |
                   (src.val >> (width - shift)));
        _regs.eflags &= ~(X86_EFLAGS_OF | X86_EFLAGS_SF | X86_EFLAGS_ZF |
                          X86_EFLAGS_PF | X86_EFLAGS_CF);
        if ( (dst.orig_val >> ((b & 8) ? (shift - 1) : (width - shift))) & 1 )
            _regs.eflags |= X86_EFLAGS_CF;
        if ( ((dst.val ^ dst.orig_val) >> (width - 1)) & 1 )
            _regs.eflags |= X86_EFLAGS_OF;
        _regs.eflags |= ((dst.val >> (width - 1)) & 1) ? X86_EFLAGS_SF : 0;
        _regs.eflags |= (dst.val == 0) ? X86_EFLAGS_ZF : 0;
        _regs.eflags |= even_parity(dst.val) ? X86_EFLAGS_PF : 0;
        break;
    }

    case X86EMUL_OPC(0x0f, 0xab): bts: /* bts */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_bts;
        else
            emulate_2op_SrcV_nobyte("bts", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xae): case X86EMUL_OPC_66(0x0f, 0xae): /* Grp15 */
        switch ( modrm_reg & 7 )
        {
#if !defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
    !defined(X86EMUL_NO_SIMD)
        case 0: /* fxsave */
        case 1: /* fxrstor */
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(fxsr);
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            generate_exception_if(!is_aligned(ea.mem.seg, ea.mem.off, 16,
                                              ctxt, ops),
                                  EXC_GP, 0);
            fail_if(!ops->blk);
            op_bytes =
#ifdef __x86_64__
                !mode_64bit() ? offsetof(struct x86_fxsr, xmm[8]) :
#endif
                sizeof(struct x86_fxsr);
            if ( amd_like(ctxt) )
            {
                /* Assume "normal" operation in case of missing hooks. */
                if ( !ops->read_cr ||
                     ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                    cr4 = X86_CR4_OSFXSR;
                if ( !ops->read_msr ||
                     ops->read_msr(MSR_EFER, &msr_val, ctxt) != X86EMUL_OKAY )
                    msr_val = 0;
                if ( !(cr4 & X86_CR4_OSFXSR) ||
                     (mode_64bit() && mode_ring0() && (msr_val & EFER_FFXSE)) )
                    op_bytes = offsetof(struct x86_fxsr, xmm[0]);
            }
            /*
             * This could also be X86EMUL_FPU_mmx, but it shouldn't be
             * X86EMUL_FPU_xmm, as we don't want CR4.OSFXSR checked.
             */
            get_fpu(X86EMUL_FPU_fpu);
            state->fpu_ctrl = true;
            state->blk = modrm_reg & 1 ? blk_fxrstor : blk_fxsave;
            if ( (rc = ops->blk(ea.mem.seg, ea.mem.off, NULL,
                                sizeof(struct x86_fxsr), &_regs.eflags,
                                state, ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
#endif /* X86EMUL_NO_{FPU,MMX,SIMD} */

#ifndef X86EMUL_NO_SIMD
        case 2: /* ldmxcsr */
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(sse);
        ldmxcsr:
            generate_exception_if(src.type != OP_MEM, EXC_UD);
            get_fpu(vex.opcx ? X86EMUL_FPU_ymm : X86EMUL_FPU_xmm);
            generate_exception_if(src.val & ~mxcsr_mask, EXC_GP, 0);
            asm volatile ( "ldmxcsr %0" :: "m" (src.val) );
            break;

        case 3: /* stmxcsr */
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(sse);
        stmxcsr:
            generate_exception_if(dst.type != OP_MEM, EXC_UD);
            get_fpu(vex.opcx ? X86EMUL_FPU_ymm : X86EMUL_FPU_xmm);
            asm volatile ( "stmxcsr %0" : "=m" (dst.val) );
            break;
#endif /* X86EMUL_NO_SIMD */

        case 5: /* lfence */
            fail_if(modrm_mod != 3);
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(sse2);
            asm volatile ( "lfence" ::: "memory" );
            break;
        case 6:
            if ( modrm_mod == 3 ) /* mfence */
            {
                generate_exception_if(vex.pfx, EXC_UD);
                vcpu_must_have(sse2);
                asm volatile ( "mfence" ::: "memory" );
                break;
            }
            /* else clwb */
            fail_if(!vex.pfx);
            vcpu_must_have(clwb);
            fail_if(!ops->cache_op);
            if ( (rc = ops->cache_op(x86emul_clwb, ea.mem.seg, ea.mem.off,
                                     ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
        case 7:
            if ( modrm_mod == 3 ) /* sfence */
            {
                generate_exception_if(vex.pfx, EXC_UD);
                vcpu_must_have(mmxext);
                asm volatile ( "sfence" ::: "memory" );
                break;
            }
            /* else clflush{,opt} */
            if ( !vex.pfx )
                vcpu_must_have(clflush);
            else
                vcpu_must_have(clflushopt);
            fail_if(!ops->cache_op);
            if ( (rc = ops->cache_op(vex.pfx ? x86emul_clflushopt
                                             : x86emul_clflush,
                                     ea.mem.seg, ea.mem.off,
                                     ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
        default:
            goto unimplemented_insn;
        }
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_VEX(0x0f, 0xae): /* Grp15 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* vldmxcsr */
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            vcpu_must_have(avx);
            goto ldmxcsr;
        case 3: /* vstmxcsr */
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            vcpu_must_have(avx);
            goto stmxcsr;
        }
        goto unrecognized_insn;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC_F3(0x0f, 0xae): /* Grp15 */
        fail_if(modrm_mod != 3);
        generate_exception_if((modrm_reg & 4) || !mode_64bit(), EXC_UD);
        fail_if(!ops->read_cr);
        if ( (rc = ops->read_cr(4, &cr4, ctxt)) != X86EMUL_OKAY )
            goto done;
        generate_exception_if(!(cr4 & X86_CR4_FSGSBASE), EXC_UD);
        seg = modrm_reg & 1 ? x86_seg_gs : x86_seg_fs;
        fail_if(!ops->read_segment);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) != X86EMUL_OKAY )
            goto done;
        dst.reg = decode_gpr(&_regs, modrm_rm);
        if ( !(modrm_reg & 2) )
        {
            /* rd{f,g}sbase */
            dst.type = OP_REG;
            dst.bytes = (op_bytes == 8) ? 8 : 4;
            dst.val = sreg.base;
        }
        else
        {
            /* wr{f,g}sbase */
            if ( op_bytes == 8 )
            {
                sreg.base = *dst.reg;
                generate_exception_if(!is_canonical_address(sreg.base),
                                      EXC_GP, 0);
            }
            else
                sreg.base = (uint32_t)*dst.reg;
            fail_if(!ops->write_segment);
            if ( (rc = ops->write_segment(seg, &sreg, ctxt)) != X86EMUL_OKAY )
                goto done;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xaf): /* imul */
        emulate_2op_SrcV_srcmem("imul", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xb0): case X86EMUL_OPC(0x0f, 0xb1): /* cmpxchg */
        fail_if(!ops->cmpxchg);

        if ( ops->rmw && dst.type == OP_MEM &&
             (rc = read_ulong(dst.mem.seg, dst.mem.off, &dst.val,
                              dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
            goto done;

        _regs.eflags &= ~EFLAGS_MASK;
        if ( !((dst.val ^ _regs.r(ax)) &
               (~0UL >> (8 * (sizeof(long) - dst.bytes)))) )
        {
            /* Success: write back to memory. */
            if ( dst.type == OP_MEM )
            {
                dst.val = _regs.r(ax);
                switch ( rc = ops->cmpxchg(dst.mem.seg, dst.mem.off, &dst.val,
                                           &src.val, dst.bytes, lock_prefix,
                                           ctxt) )
                {
                case X86EMUL_OKAY:
                    dst.type = OP_NONE;
                    _regs.eflags |= X86_EFLAGS_ZF | X86_EFLAGS_PF;
                    break;
                case X86EMUL_CMPXCHG_FAILED:
                    rc = X86EMUL_OKAY;
                    break;
                default:
                    goto done;
                }
            }
            else
            {
                dst.val = src.val;
                _regs.eflags |= X86_EFLAGS_ZF | X86_EFLAGS_PF;
            }
        }
        if ( !(_regs.eflags & X86_EFLAGS_ZF) )
        {
            /* Failure: write the value we saw to EAX. */
            dst.type = OP_REG;
            dst.reg  = (unsigned long *)&_regs.r(ax);
            /* cmp: %%eax - dst ==> dst and src swapped for macro invocation */
            src.val = _regs.r(ax);
            emulate_2op_SrcV("cmp", dst, src, _regs.eflags);
            ASSERT(!(_regs.eflags & X86_EFLAGS_ZF));
        }
        break;

    case X86EMUL_OPC(0x0f, 0xb2): /* lss */
    case X86EMUL_OPC(0x0f, 0xb4): /* lfs */
    case X86EMUL_OPC(0x0f, 0xb5): /* lgs */
        seg = b & 7;
        goto les;

    case X86EMUL_OPC(0x0f, 0xb3): btr: /* btr */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_btr;
        else
            emulate_2op_SrcV_nobyte("btr", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xb6): /* movzx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_gpr(&_regs, modrm_reg);
        dst.bytes = op_bytes;
        dst.val   = (uint8_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xb7): /* movzx rm16,r{16,32,64} */
        dst.val = (uint16_t)src.val;
        break;

    case X86EMUL_OPC_F3(0x0f, 0xb8): /* popcnt r/m,r */
        host_and_vcpu_must_have(popcnt);
        asm ( "popcnt %1,%0" : "=r" (dst.val) : "rm" (src.val) );
        _regs.eflags &= ~EFLAGS_MASK;
        if ( !dst.val )
            _regs.eflags |= X86_EFLAGS_ZF;
        break;

    case X86EMUL_OPC(0x0f, 0xba): /* Grp8 */
        switch ( modrm_reg & 7 )
        {
        case 4: goto bt;
        case 5: goto bts;
        case 6: goto btr;
        case 7: goto btc;
        default: generate_exception(EXC_UD);
        }
        break;

    case X86EMUL_OPC(0x0f, 0xbb): btc: /* btc */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_btc;
        else
            emulate_2op_SrcV_nobyte("btc", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xbc): /* bsf or tzcnt */
    {
        bool zf;

        asm ( "bsf %2,%0" ASM_FLAG_OUT(, "; setz %1")
              : "=r" (dst.val), ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : "rm" (src.val) );
        _regs.eflags &= ~X86_EFLAGS_ZF;
        if ( (vex.pfx == vex_f3) && vcpu_has_bmi1() )
        {
            _regs.eflags &= ~X86_EFLAGS_CF;
            if ( zf )
            {
                _regs.eflags |= X86_EFLAGS_CF;
                dst.val = op_bytes * 8;
            }
            else if ( !dst.val )
                _regs.eflags |= X86_EFLAGS_ZF;
        }
        else if ( zf )
        {
            _regs.eflags |= X86_EFLAGS_ZF;
            dst.type = OP_NONE;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xbd): /* bsr or lzcnt */
    {
        bool zf;

        asm ( "bsr %2,%0" ASM_FLAG_OUT(, "; setz %1")
              : "=r" (dst.val), ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : "rm" (src.val) );
        _regs.eflags &= ~X86_EFLAGS_ZF;
        if ( (vex.pfx == vex_f3) && vcpu_has_lzcnt() )
        {
            _regs.eflags &= ~X86_EFLAGS_CF;
            if ( zf )
            {
                _regs.eflags |= X86_EFLAGS_CF;
                dst.val = op_bytes * 8;
            }
            else
            {
                dst.val = op_bytes * 8 - 1 - dst.val;
                if ( !dst.val )
                    _regs.eflags |= X86_EFLAGS_ZF;
            }
        }
        else if ( zf )
        {
            _regs.eflags |= X86_EFLAGS_ZF;
            dst.type = OP_NONE;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xbe): /* movsx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_gpr(&_regs, modrm_reg);
        dst.bytes = op_bytes;
        dst.val   = (int8_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xbf): /* movsx rm16,r{16,32,64} */
        dst.val = (int16_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xc0): case X86EMUL_OPC(0x0f, 0xc1): /* xadd */
        if ( ops->rmw && dst.type == OP_MEM )
        {
            state->rmw = rmw_xadd;
            break;
        }
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        goto add;

    CASE_SIMD_ALL_FP_VEX(0x0f, 0xc2):      /* cmp{p,s}{s,d} $imm8,xmm/mem,xmm */
                                           /* vcmp{p,s}{s,d} $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP_VEX(0x0f, 0xc6):   /* shufp{s,d} $imm8,xmm/mem,xmm */
                                           /* vshufp{s,d} $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        d = (d & ~SrcMask) | SrcMem;
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                goto simd_0f_imm8_sse2;
            vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
            goto simd_0f_imm8;
        }
        goto simd_0f_imm8_avx;

#ifndef X86EMUL_NO_SIMD

    CASE_SIMD_ALL_FP(_EVEX, 0x0f, 0xc2): /* vcmp{p,s}{s,d} $imm8,[xyz]mm/mem,[xyz]mm,k{k} */
        generate_exception_if((evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK) ||
                               (ea.type != OP_REG && evex.brs &&
                                (evex.pfx & VEX_PREFIX_SCALAR_MASK)) ||
                               !evex.r || !evex.R || evex.z),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( ea.type != OP_REG || !evex.brs )
            avx512_vlen_check(evex.pfx & VEX_PREFIX_SCALAR_MASK);
    simd_imm8_zmm:
        if ( (d & SrcMask) == SrcImmByte )
            d = (d & ~SrcMask) | SrcMem;
        get_fpu(X86EMUL_FPU_zmm);
        opc = init_evex(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* convert memory operand to (%rAX) */
            evex.b = 1;
            opc[1] &= 0x38;
        }
        opc[2] = imm1;
        insn_bytes = EVEX_PFX_BYTES + 3;
        break;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC(0x0f, 0xc3): /* movnti */
        /* Ignore the non-temporal hint for now. */
        vcpu_must_have(sse2);
        dst.val = src.val;
        sfence = true;
        break;

    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xc4):  /* pinsrw $imm8,r32/m16,{,x}mm */
                                           /* vpinsrw $imm8,r32/m16,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        memcpy(mmvalp, &src.val, 2);
        ea.type = OP_MEM;
        goto simd_0f_int_imm8;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0xc4):   /* vpinsrw $imm8,r32/m16,xmm,xmm */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x20): /* vpinsrb $imm8,r32/m8,xmm,xmm */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x22): /* vpinsr{d,q} $imm8,r/m,xmm,xmm */
        generate_exception_if(evex.lr || evex.opmsk || evex.brs, EXC_UD);
        if ( b & 2 )
            host_and_vcpu_must_have(avx512dq);
        else
            host_and_vcpu_must_have(avx512bw);
        if ( !mode_64bit() )
            evex.w = 0;
        memcpy(mmvalp, &src.val, op_bytes);
        ea.type = OP_MEM;
        op_bytes = src.bytes;
        d = SrcMem16; /* Fake for the common SIMD code below. */
        state->simd_size = simd_other;
        goto avx512f_imm8_no_sae;

#endif /* !X86EMUL_NO_SIMD */

    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xc5):  /* pextrw $imm8,{,x}mm,reg */
                                           /* vpextrw $imm8,xmm,reg */
        generate_exception_if(vex.l, EXC_UD);
        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR destination to %rAX. */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        goto simd_0f_to_gpr;

#ifndef X86EMUL_NO_SIMD

    CASE_SIMD_PACKED_FP(_EVEX, 0x0f, 0xc6): /* vshufp{s,d} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(evex.w != (evex.pfx & VEX_PREFIX_DOUBLE_MASK),
                              EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x03): /* valign{d,q} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        fault_suppression = false;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x25): /* vpternlog{d,q} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    avx512f_imm8_no_sae:
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(ea.type != OP_MEM && evex.brs, EXC_UD);
        avx512_vlen_check(false);
        goto simd_imm8_zmm;

#endif /* X86EMUL_NO_SIMD */

    case X86EMUL_OPC(0x0f, 0xc7): /* Grp9 */
    {
        union {
            uint32_t u32[2];
            uint64_t u64[2];
        } *old, *aux;

        if ( ea.type == OP_REG )
        {
            bool __maybe_unused carry;

            switch ( modrm_reg & 7 )
            {
            default:
                goto unrecognized_insn;

            case 6: /* rdrand */
#ifdef HAVE_AS_RDRAND
                generate_exception_if(rep_prefix(), EXC_UD);
                host_and_vcpu_must_have(rdrand);
                dst = ea;
                switch ( op_bytes )
                {
                case 2:
                    asm ( "rdrand %w0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                default:
# ifdef __x86_64__
                    asm ( "rdrand %k0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                case 8:
# endif
                    asm ( "rdrand %0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                }
                _regs.eflags &= ~EFLAGS_MASK;
                if ( carry )
                    _regs.eflags |= X86_EFLAGS_CF;
                break;
#else
                goto unimplemented_insn;
#endif

            case 7: /* rdseed / rdpid */
                if ( repe_prefix() ) /* rdpid */
                {
                    generate_exception_if(ea.type != OP_REG, EXC_UD);
                    vcpu_must_have(rdpid);
                    fail_if(!ops->read_msr);
                    if ( (rc = ops->read_msr(MSR_TSC_AUX, &msr_val,
                                             ctxt)) != X86EMUL_OKAY )
                        goto done;
                    dst = ea;
                    dst.val = msr_val;
                    dst.bytes = 4;
                    break;
                }
#ifdef HAVE_AS_RDSEED
                generate_exception_if(rep_prefix(), EXC_UD);
                host_and_vcpu_must_have(rdseed);
                dst = ea;
                switch ( op_bytes )
                {
                case 2:
                    asm ( "rdseed %w0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                default:
# ifdef __x86_64__
                    asm ( "rdseed %k0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                case 8:
# endif
                    asm ( "rdseed %0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                }
                _regs.eflags &= ~EFLAGS_MASK;
                if ( carry )
                    _regs.eflags |= X86_EFLAGS_CF;
                break;
#endif
            }
            break;
        }

        /* cmpxchg8b/cmpxchg16b */
        generate_exception_if((modrm_reg & 7) != 1, EXC_UD);
        fail_if(!ops->cmpxchg);
        if ( rex_prefix & REX_W )
        {
            host_and_vcpu_must_have(cx16);
            generate_exception_if(!is_aligned(ea.mem.seg, ea.mem.off, 16,
                                              ctxt, ops),
                                  EXC_GP, 0);
            op_bytes = 16;
        }
        else
        {
            vcpu_must_have(cx8);
            op_bytes = 8;
        }

        old = container_of(&mmvalp->ymm[0], typeof(*old), u64[0]);
        aux = container_of(&mmvalp->ymm[2], typeof(*aux), u64[0]);

        /* Get actual old value. */
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, old, op_bytes,
                             ctxt)) != X86EMUL_OKAY )
            goto done;

        /* Get expected value. */
        if ( !(rex_prefix & REX_W) )
        {
            aux->u32[0] = _regs.eax;
            aux->u32[1] = _regs.edx;
        }
        else
        {
            aux->u64[0] = _regs.r(ax);
            aux->u64[1] = _regs.r(dx);
        }

        if ( memcmp(old, aux, op_bytes) )
        {
        cmpxchgNb_failed:
            /* Expected != actual: store actual to rDX:rAX and clear ZF. */
            _regs.r(ax) = !(rex_prefix & REX_W) ? old->u32[0] : old->u64[0];
            _regs.r(dx) = !(rex_prefix & REX_W) ? old->u32[1] : old->u64[1];
            _regs.eflags &= ~X86_EFLAGS_ZF;
        }
        else
        {
            /*
             * Expected == actual: Get proposed value, attempt atomic cmpxchg
             * and set ZF if successful.
             */
            if ( !(rex_prefix & REX_W) )
            {
                aux->u32[0] = _regs.ebx;
                aux->u32[1] = _regs.ecx;
            }
            else
            {
                aux->u64[0] = _regs.r(bx);
                aux->u64[1] = _regs.r(cx);
            }

            switch ( rc = ops->cmpxchg(ea.mem.seg, ea.mem.off, old, aux,
                                       op_bytes, lock_prefix, ctxt) )
            {
            case X86EMUL_OKAY:
                _regs.eflags |= X86_EFLAGS_ZF;
                break;

            case X86EMUL_CMPXCHG_FAILED:
                rc = X86EMUL_OKAY;
                goto cmpxchgNb_failed;

            default:
                goto done;
            }
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xc8) ... X86EMUL_OPC(0x0f, 0xcf): /* bswap */
        dst.type = OP_REG;
        dst.reg  = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
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

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0xd2): /* vpsrld xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xd3): /* vpsrlq xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe2): /* vpsra{d,q} xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf2): /* vpslld xmm/m128,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xf3): /* vpsllq xmm/m128,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(evex.brs, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x0c): /* vpermilps [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x0d): /* vpermilpd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        fault_suppression = false;
        if ( b == 0xe2 )
            goto avx512f_no_sae;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xfa): /* vpsubd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xfb): /* vpsubq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xfe): /* vpaddd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x1e): /* vpabsd [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x1f): /* vpabsq [xyz]mm/mem,[xyz]mm{k} */
        generate_exception_if(evex.w != (b & 1), EXC_UD);
        goto avx512f_no_sae;

#endif /* !X86EMUL_NO_SIMD */
#ifndef X86EMUL_NO_MMX

    case X86EMUL_OPC(0x0f, 0xd4):        /* paddq mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xf4):        /* pmuludq mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xfb):        /* psubq mm/m64,mm */
        vcpu_must_have(sse2);
        goto simd_0f_mmx;

#endif /* !X86EMUL_NO_MMX */
#if !defined(X86EMUL_NO_MMX) && !defined(X86EMUL_NO_SIMD)

    case X86EMUL_OPC_F3(0x0f, 0xd6):     /* movq2dq mm,xmm */
    case X86EMUL_OPC_F2(0x0f, 0xd6):     /* movdq2q xmm,mm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        op_bytes = 8;
        host_and_vcpu_must_have(mmx);
        goto simd_0f_int;

#endif /* !X86EMUL_NO_MMX && !X86EMUL_NO_SIMD */
#ifndef X86EMUL_NO_MMX

    case X86EMUL_OPC(0x0f, 0xe7):        /* movntq mm,m64 */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        sfence = true;
        /* fall through */
    case X86EMUL_OPC(0x0f, 0xda):        /* pminub mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xde):        /* pmaxub mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xea):        /* pminsw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xee):        /* pmaxsw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xe0):        /* pavgb mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xe3):        /* pavgw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xe4):        /* pmulhuw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xf6):        /* psadbw mm/m64,mm */
        vcpu_must_have(mmxext);
        goto simd_0f_mmx;

#endif /* !X86EMUL_NO_MMX */
#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f, 0xda): /* vpminub [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xde): /* vpmaxub [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xe4): /* vpmulhuw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xea): /* vpminsw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f, 0xee): /* vpmaxsw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.brs, EXC_UD);
        elem_bytes = b & 0x10 ? 1 : 2;
        goto avx512f_no_sae;

    case X86EMUL_OPC_66(0x0f, 0xe6):       /* cvttpd2dq xmm/mem,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe6):   /* vcvttpd2dq {x,y}mm/mem,xmm */
    case X86EMUL_OPC_F3(0x0f, 0xe6):       /* cvtdq2pd xmm/mem,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0xe6):   /* vcvtdq2pd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_F2(0x0f, 0xe6):       /* cvtpd2dq xmm/mem,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0xe6):   /* vcvtpd2dq {x,y}mm/mem,xmm */
        d |= TwoOp;
        op_bytes = 8 << (!!(vex.pfx & VEX_PREFIX_DOUBLE_MASK) + vex.l);
        goto simd_0f_cvt;

#endif /* !X86EMUL_NO_SIMD */

    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf7): /* {,v}maskmov{q,dqu} {,x}mm,{,x}mm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        if ( vex.opcx != vex_none )
        {
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            d |= TwoOp;
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            vcpu_must_have(mmxext);
            get_fpu(X86EMUL_FPU_mmx);
        }

        /*
         * While we can't reasonably provide fully correct behavior here
         * (in particular avoiding the memory read in anticipation of all
         * bytes in the range eventually being written), we can (and should)
         * still suppress the memory access if all mask bits are clear. Read
         * the mask bits via {,v}pmovmskb for that purpose.
         */
        opc = init_prefixes(stub);
        opc[0] = 0xd7; /* {,v}pmovmskb */
        /* (Ab)use "sfence" for latching the original REX.R / VEX.R. */
        sfence = rex_prefix & REX_R;
        /* Convert GPR destination to %rAX. */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        opc[2] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "=a" (ea.val) : [dummy] "i" (0));

        put_stub(stub);
        if ( !ea.val )
            goto complete_insn;

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        insn_bytes = PFX_BYTES + 2;
        /* Restore high bit of XMM destination. */
        if ( sfence )
        {
            rex_prefix |= REX_R;
            vex.r = 0;
        }

        ea.type = OP_MEM;
        ea.mem.off = truncate_ea(_regs.r(di));
        sfence = true;
        break;

    CASE_SIMD_PACKED_INT(0x0f38, 0x00): /* pshufb {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x01): /* phaddw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x02): /* phaddd {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x03): /* phaddsw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x04): /* pmaddubsw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x05): /* phsubw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x06): /* phsubd {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x07): /* phsubsw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x08): /* psignb {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x09): /* psignw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x0a): /* psignd {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x0b): /* pmulhrsw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x1c): /* pabsb {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x1d): /* pabsw {,x}mm/mem,{,x}mm */
    CASE_SIMD_PACKED_INT(0x0f38, 0x1e): /* pabsd {,x}mm/mem,{,x}mm */
        host_and_vcpu_must_have(ssse3);
        if ( vex.pfx )
        {
    simd_0f38_common:
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }
        opc = init_prefixes(stub);
        opc[0] = 0x38;
        opc[1] = b;
        opc[2] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[2] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 3;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_VEX_66(0x0f38, 0x19): /* vbroadcastsd xmm/m64,ymm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1a): /* vbroadcastf128 m128,ymm */
        generate_exception_if(!vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x18): /* vbroadcastss xmm/m32,{x,y}mm */
        if ( ea.type != OP_MEM )
        {
            generate_exception_if(b & 2, EXC_UD);
            host_and_vcpu_must_have(avx2);
        }
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0c): /* vpermilps {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0d): /* vpermilpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_avx;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x0e): /* vtestps {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0f): /* vtestpd {x,y}mm/mem,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_66(0x0f38, 0x17):     /* ptest xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x17): /* vptest {x,y}mm/mem,{x,y}mm */
        if ( vex.opcx == vex_none )
        {
            host_and_vcpu_must_have(sse4_1);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        if ( vex.opcx == vex_none )
            opc++[0] = 0x38;
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 16 << vex.l, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;

            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 2;
        opc[2] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            /* Cover for extra prefix byte. */
            --opc;
            ++insn_bytes;
        }

        copy_REX_VEX(opc, rex_prefix, vex);
        emulate_stub("+m" (*mmvalp), "a" (mmvalp));

        put_stub(stub);
        state->simd_size = simd_none;
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC_66(0x0f38, 0x20): /* pmovsxbw xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x21): /* pmovsxbd xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x22): /* pmovsxbq xmm/m16,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x23): /* pmovsxwd xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x24): /* pmovsxwq xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x25): /* pmovsxdq xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x30): /* pmovzxbw xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x31): /* pmovzxbd xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x32): /* pmovzxbq xmm/m16,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x33): /* pmovzxwd xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x34): /* pmovzxwq xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x35): /* pmovzxdq xmm/m64,xmm */
        op_bytes = 16 >> pmov_convert_delta[b & 7];
        /* fall through */
    case X86EMUL_OPC_66(0x0f38, 0x10): /* pblendvb XMM0,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x14): /* blendvps XMM0,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x15): /* blendvpd XMM0,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x28): /* pmuldq xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x29): /* pcmpeqq xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x2b): /* packusdw xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x38): /* pminsb xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x39): /* pminsd xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3a): /* pminub xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3b): /* pminud xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3c): /* pmaxsb xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3d): /* pmaxsd xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3e): /* pmaxub xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3f): /* pmaxud xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x40): /* pmulld xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x41): /* phminposuw xmm/m128,xmm */
        host_and_vcpu_must_have(sse4_1);
        goto simd_0f38_common;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x10): /* vpsrlvw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x11): /* vpsravw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x12): /* vpsllvw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(!evex.w || evex.brs, EXC_UD);
        elem_bytes = 2;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x10): /* vpmovuswb [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x20): /* vpmovsxbw {x,y}mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x20): /* vpmovswb [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x30): /* vpmovzxbw {x,y}mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x30): /* vpmovwb [xyz]mm,{x,y}mm/mem{k} */
        host_and_vcpu_must_have(avx512bw);
        if ( evex.pfx != vex_f3 )
        {
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x21): /* vpmovsxbd xmm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x22): /* vpmovsxbq xmm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x23): /* vpmovsxwd {x,y}mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x24): /* vpmovsxwq xmm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x25): /* vpmovsxdq {x,y}mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x31): /* vpmovzxbd xmm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x32): /* vpmovzxbq xmm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x33): /* vpmovzxwd {x,y}mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x34): /* vpmovzxwq xmm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x35): /* vpmovzxdq {x,y}mm/mem,[xyz]mm{k} */
            generate_exception_if(evex.w && (b & 7) == 5, EXC_UD);
        }
        else
        {
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x11): /* vpmovusdb [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x12): /* vpmovusqb [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x13): /* vpmovusdw [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x14): /* vpmovusqw [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x15): /* vpmovusqd [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x21): /* vpmovsdb [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x22): /* vpmovsqb [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x23): /* vpmovsdw [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x24): /* vpmovsqw [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x25): /* vpmovsqd [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x31): /* vpmovdb [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x32): /* vpmovqb [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x33): /* vpmovdw [xyz]mm,{x,y}mm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x34): /* vpmovqw [xyz]mm,xmm/mem{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x35): /* vpmovqd [xyz]mm,{x,y}mm/mem{k} */
            generate_exception_if(evex.w || (ea.type != OP_REG && evex.z), EXC_UD);
            d = DstMem | SrcReg | TwoOp;
        }
        generate_exception_if(evex.brs, EXC_UD);
        op_bytes = 32 >> (pmov_convert_delta[b & 7] + 1 - evex.lr);
        elem_bytes = (b & 7) < 3 ? 1 : (b & 7) != 5 ? 2 : 4;
        goto avx512f_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x13): /* vcvtph2ps xmm/mem,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        host_and_vcpu_must_have(f16c);
        op_bytes = 8 << vex.l;
        goto simd_0f_ymm;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x13): /* vcvtph2ps {x,y}mm/mem,[xyz]mm{k} */
        generate_exception_if(evex.w || (ea.type != OP_REG && evex.brs), EXC_UD);
        host_and_vcpu_must_have(avx512f);
        if ( !evex.brs )
            avx512_vlen_check(false);
        op_bytes = 8 << evex.lr;
        elem_bytes = 2;
        goto simd_zmm;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x16): /* vpermps ymm/m256,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x36): /* vpermd ymm/m256,ymm,ymm */
        generate_exception_if(!vex.l || vex.w, EXC_UD);
        goto simd_0f_avx2;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x16): /* vpermp{s,d} {y,z}mm/mem,{y,z}mm,{y,z}mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x36): /* vperm{d,q} {y,z}mm/mem,{y,z}mm,{y,z}mm{k} */
        generate_exception_if(!evex.lr, EXC_UD);
        fault_suppression = false;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x18): /* vbroadcastss xmm/m32,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x58): /* vpbroadcastd xmm/m32,[xyz]mm{k} */
        op_bytes = elem_bytes;
        generate_exception_if(evex.w || evex.brs, EXC_UD);
    avx512_broadcast:
        /*
         * For the respective code below the main switch() to work we need to
         * fold op_mask here: A source element gets read whenever any of its
         * respective destination elements' mask bits is set.
         */
        if ( fault_suppression )
        {
            n = 1 << ((b & 3) - evex.w);
            EXPECT(elem_bytes > 0);
            ASSERT(op_bytes == n * elem_bytes);
            for ( i = n; i < (16 << evex.lr) / elem_bytes; i += n )
                op_mask |= (op_mask >> i) & ((1 << n) - 1);
        }
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x1b): /* vbroadcastf32x8 m256,zmm{k} */
                                            /* vbroadcastf64x4 m256,zmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x5b): /* vbroadcasti32x8 m256,zmm{k} */
                                            /* vbroadcasti64x4 m256,zmm{k} */
        generate_exception_if(ea.type != OP_MEM || evex.lr != 2, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x19): /* vbroadcastsd xmm/m64,{y,z}mm{k} */
                                            /* vbroadcastf32x2 xmm/m64,{y,z}mm{k} */
        generate_exception_if(!evex.lr, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x59): /* vpbroadcastq xmm/m64,[xyz]mm{k} */
                                            /* vbroadcasti32x2 xmm/m64,[xyz]mm{k} */
        if ( b == 0x59 )
            op_bytes = 8;
        generate_exception_if(evex.brs, EXC_UD);
        if ( !evex.w )
            host_and_vcpu_must_have(avx512dq);
        goto avx512_broadcast;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x1a): /* vbroadcastf32x4 m128,{y,z}mm{k} */
                                            /* vbroadcastf64x2 m128,{y,z}mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x5a): /* vbroadcasti32x4 m128,{y,z}mm{k} */
                                            /* vbroadcasti64x2 m128,{y,z}mm{k} */
        generate_exception_if(ea.type != OP_MEM || !evex.lr || evex.brs,
                              EXC_UD);
        if ( evex.w )
            host_and_vcpu_must_have(avx512dq);
        goto avx512_broadcast;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x20): /* vpmovsxbw xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x21): /* vpmovsxbd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x22): /* vpmovsxbq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x23): /* vpmovsxwd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x24): /* vpmovsxwq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x25): /* vpmovsxdq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x30): /* vpmovzxbw xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x31): /* vpmovzxbd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x32): /* vpmovzxbq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x33): /* vpmovzxwd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x34): /* vpmovzxwq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x35): /* vpmovzxdq xmm/mem,{x,y}mm */
        op_bytes = 16 >> (pmov_convert_delta[b & 7] - vex.l);
        goto simd_0f_int;

    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x29): /* vpmov{b,w}2m [xyz]mm,k */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x39): /* vpmov{d,q}2m [xyz]mm,k */
        generate_exception_if(!evex.r || !evex.R, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x28): /* vpmovm2{b,w} k,[xyz]mm */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x38): /* vpmovm2{d,q} k,[xyz]mm */
        if ( b & 0x10 )
            host_and_vcpu_must_have(avx512dq);
        else
            host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.opmsk || ea.type != OP_REG, EXC_UD);
        d |= TwoOp;
        op_bytes = 16 << evex.lr;
        goto avx512f_no_sae;

    case X86EMUL_OPC_66(0x0f38, 0x2a):     /* movntdqa m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2a): /* vmovntdqa mem,{x,y}mm */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* Ignore the non-temporal hint for now, using movdqa instead. */
        asm volatile ( "mfence" ::: "memory" );
        b = 0x6f;
        if ( vex.opcx == vex_none )
            vcpu_must_have(sse4_1);
        else
        {
            vex.opcx = vex_0f;
            if ( vex.l )
                vcpu_must_have(avx2);
        }
        goto movdqa;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x2a): /* vmovntdqa mem,[xyz]mm */
        generate_exception_if(ea.type != OP_MEM || evex.opmsk || evex.w,
                              EXC_UD);
        /* Ignore the non-temporal hint for now, using vmovdqa32 instead. */
        asm volatile ( "mfence" ::: "memory" );
        b = 0x6f;
        evex.opcx = vex_0f;
        goto vmovdqa;

    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x2a): /* vpbroadcastmb2q k,[xyz]mm */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x3a): /* vpbroadcastmw2d k,[xyz]mm */
        generate_exception_if((ea.type != OP_REG || evex.opmsk ||
                               evex.w == ((b >> 4) & 1)),
                              EXC_UD);
        d |= TwoOp;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xc4): /* vpconflict{d,q} [xyz]mm/mem,[xyz]mm{k} */
        fault_suppression = false;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x44): /* vplzcnt{d,q} [xyz]mm/mem,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512cd);
        goto avx512f_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x2c): /* vmaskmovps mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2d): /* vmaskmovpd mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2e): /* vmaskmovps {x,y}mm,{x,y}mm,mem */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2f): /* vmaskmovpd {x,y}mm,{x,y}mm,mem */
    {
        typeof(vex) *pvex;

        generate_exception_if(ea.type != OP_MEM || vex.w, EXC_UD);
        host_and_vcpu_must_have(avx);
        elem_bytes = 4 << (b & 1);
    vmaskmov:
        get_fpu(X86EMUL_FPU_ymm);

        /*
         * While we can't reasonably provide fully correct behavior here
         * (in particular, for writes, avoiding the memory read in anticipation
         * of all elements in the range eventually being written), we can (and
         * should) still limit the memory access to the smallest possible range
         * (suppressing it altogether if all mask bits are clear), to provide
         * correct faulting behavior. Read the mask bits via vmovmskp{s,d}
         * for that purpose.
         */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        if ( elem_bytes == 4 )
            pvex->pfx = vex_none;
        opc[0] = 0x50; /* vmovmskp{s,d} */
        /* Use %rax as GPR destination and VEX.vvvv as source. */
        pvex->r = 1;
        pvex->b = !mode_64bit() || (vex.reg >> 3);
        opc[1] = 0xc0 | (~vex.reg & 7);
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "=a" (ea.val) : [dummy] "i" (0));
        put_stub(stub);

        evex.opmsk = 1; /* fake */
        op_mask = ea.val;
        fault_suppression = true;

        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert memory operand to (%rAX). */
        rex_prefix &= ~REX_B;
        vex.b = 1;
        opc[1] = modrm & 0x38;
        insn_bytes = PFX_BYTES + 2;

        break;
    }

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x2c): /* vscalefp{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x42): /* vgetexpp{s,d} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x96): /* vfmaddsub132p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x97): /* vfmsubadd132p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x98): /* vfmadd132p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x9a): /* vfmsub132p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x9c): /* vfnmadd132p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x9e): /* vfnmsub132p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa6): /* vfmaddsub213p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa7): /* vfmsubadd213p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa8): /* vfmadd213p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xaa): /* vfmsub213p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xac): /* vfnmadd213p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xae): /* vfnmsub213p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xb6): /* vfmaddsub231p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xb7): /* vfmsubadd231p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xb8): /* vfmadd231p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xba): /* vfmsub231p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xbc): /* vfnmadd231p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xbe): /* vfnmsub231p{s,d} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512f);
        if ( ea.type != OP_REG || !evex.brs )
            avx512_vlen_check(false);
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x2d): /* vscalefs{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x43): /* vgetexps{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x99): /* vfmadd132s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x9b): /* vfmsub132s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x9d): /* vfnmadd132s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x9f): /* vfnmsub132s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa9): /* vfmadd213s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xab): /* vfmsub213s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xad): /* vfnmadd213s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xaf): /* vfnmsub213s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xb9): /* vfmadd231s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xbb): /* vfmsub231s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xbd): /* vfnmadd231s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xbf): /* vfnmsub231s{s,d} xmm/mem,xmm,xmm{k} */
        host_and_vcpu_must_have(avx512f);
    simd_zmm_scalar_sae:
        generate_exception_if(ea.type != OP_REG && evex.brs, EXC_UD);
        if ( !evex.brs )
            avx512_vlen_check(true);
        goto simd_zmm;

    case X86EMUL_OPC_66(0x0f38, 0x37): /* pcmpgtq xmm/m128,xmm */
        host_and_vcpu_must_have(sse4_2);
        goto simd_0f38_common;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x38): /* vpminsb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x3a): /* vpminuw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x3c): /* vpmaxsb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x3e): /* vpmaxuw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.brs, EXC_UD);
        elem_bytes = b & 2 ?: 1;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x40): /* vpmull{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        if ( evex.w )
            host_and_vcpu_must_have(avx512dq);
        goto avx512f_no_sae;

    case X86EMUL_OPC_66(0x0f38, 0xdb):     /* aesimc xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdb): /* vaesimc xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xdc):     /* aesenc xmm/m128,xmm,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xdd):     /* aesenclast xmm/m128,xmm,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xde):     /* aesdec xmm/m128,xmm,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xdf):     /* aesdeclast xmm/m128,xmm,xmm */
        host_and_vcpu_must_have(aesni);
        if ( vex.opcx == vex_none )
            goto simd_0f38_common;
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x41): /* vphminposuw xmm/m128,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_avx;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x50): /* vpdpbusd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x51): /* vpdpbusds [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x52): /* vpdpwssd [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x53): /* vpdpwssds [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_vnni);
        generate_exception_if(evex.w, EXC_UD);
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_F2(0x0f38, 0x72): /* vcvtne2ps2bf16 [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x72): /* vcvtneps2bf16 [xyz]mm/mem,{x,y}mm{k} */
        if ( evex.pfx == vex_f2 )
            fault_suppression = false;
        else
            d |= TwoOp;
        /* fall through */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x52): /* vdpbf16ps [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_bf16);
        generate_exception_if(evex.w, EXC_UD);
        op_bytes = 16 << evex.lr;
        goto avx512f_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x58): /* vpbroadcastd xmm/m32,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x59): /* vpbroadcastq xmm/m64,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x78): /* vpbroadcastb xmm/m8,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x79): /* vpbroadcastw xmm/m16,{x,y}mm */
        op_bytes = 1 << ((!(b & 0x20) * 2) + (b & 1));
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x46): /* vpsravd {x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_avx2;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x4d): /* vrcp14s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x4f): /* vrsqrt14s{s,d} xmm/mem,xmm,xmm{k} */
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(evex.brs, EXC_UD);
        avx512_vlen_check(true);
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_F2(0x0f38, 0x52): /* vp4dpwssd m128,zmm+3,zmm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f38, 0x53): /* vp4dpwssds m128,zmm+3,zmm{k} */
        host_and_vcpu_must_have(avx512_4vnniw);
        generate_exception_if((ea.type != OP_MEM || evex.w || evex.brs ||
                               evex.lr != 2),
                              EXC_UD);
        op_mask = op_mask & 0xffff ? 0xf : 0;
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x8f): /* vpshufbitqmb [xyz]mm/mem,[xyz]mm,k{k} */
        generate_exception_if(evex.w || !evex.r || !evex.R || evex.z, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x54): /* vpopcnt{b,w} [xyz]mm/mem,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_bitalg);
        generate_exception_if(evex.brs, EXC_UD);
        elem_bytes = 1 << evex.w;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x55): /* vpopcnt{d,q} [xyz]mm/mem,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_vpopcntdq);
        goto avx512f_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x5a): /* vbroadcasti128 m128,ymm */
        generate_exception_if(ea.type != OP_MEM || !vex.l || vex.w, EXC_UD);
        goto simd_0f_avx2;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x62): /* vpexpand{b,w} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x63): /* vpcompress{b,w} [xyz]mm,[xyz]mm/mem{k} */
        host_and_vcpu_must_have(avx512_vbmi2);
        elem_bytes = 1 << evex.w;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x88): /* vexpandp{s,d} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x89): /* vpexpand{d,q} [xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x8a): /* vcompressp{s,d} [xyz]mm,[xyz]mm/mem{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x8b): /* vpcompress{d,q} [xyz]mm,[xyz]mm/mem{k} */
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(evex.brs, EXC_UD);
        avx512_vlen_check(false);
        /*
         * For the respective code below the main switch() to work we need to
         * compact op_mask here: Memory accesses are non-sparse even if the
         * mask register has sparsely set bits.
         */
        if ( likely(fault_suppression) )
        {
            n = 1 << ((b & 8 ? 2 : 4) + evex.lr - evex.w);
            EXPECT(elem_bytes > 0);
            ASSERT(op_bytes == n * elem_bytes);
            op_mask &= ~0ULL >> (64 - n);
            n = hweight64(op_mask);
            op_bytes = n * elem_bytes;
            if ( n )
                op_mask = ~0ULL >> (64 - n);
        }
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x70): /* vpshldvw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x72): /* vpshrdvw [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(!evex.w, EXC_UD);
        elem_bytes = 2;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x71): /* vpshldv{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x73): /* vpshrdv{d,q} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_vbmi2);
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x75): /* vpermi2{b,w} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x7d): /* vpermt2{b,w} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x8d): /* vperm{b,w} [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        if ( !evex.w )
            host_and_vcpu_must_have(avx512_vbmi);
        else
            host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.brs, EXC_UD);
        fault_suppression = false;
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x78): /* vpbroadcastb xmm/m8,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x79): /* vpbroadcastw xmm/m16,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.w || evex.brs, EXC_UD);
        op_bytes = elem_bytes = 1 << (b & 1);
        /* See the comment at the avx512_broadcast label. */
        op_mask |= !(b & 1 ? !(uint32_t)op_mask : !op_mask);
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x7a): /* vpbroadcastb r32,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x7b): /* vpbroadcastw r32,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x7c): /* vpbroadcast{d,q} reg,[xyz]mm{k} */
        generate_exception_if((ea.type != OP_REG || evex.brs ||
                               evex.reg != 0xf || !evex.RX),
                              EXC_UD);
        host_and_vcpu_must_have(avx512f);
        avx512_vlen_check(false);
        get_fpu(X86EMUL_FPU_zmm);

        opc = init_evex(stub);
        opc[0] = b;
        /* Convert GPR source to %rAX. */
        evex.b = 1;
        if ( !mode_64bit() )
            evex.w = 0;
        opc[1] = modrm & 0xf8;
        insn_bytes = EVEX_PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_EVEX(opc, evex);
        invoke_stub("", "", "=g" (dummy) : "a" (src.val));

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC_66(0x0f38, 0x82): /* invpcid reg,m128 */
        vcpu_must_have(invpcid);
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        generate_exception_if(!mode_ring0(), EXC_GP, 0);

        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 16,
                             ctxt)) != X86EMUL_OKAY )
            goto done;

        generate_exception_if(mmvalp->xmm[0] & ~0xfff, EXC_GP, 0);
        dst.val = mode_64bit() ? *dst.reg : (uint32_t)*dst.reg;

        switch ( dst.val )
        {
        case X86_INVPCID_INDIV_ADDR:
             generate_exception_if(!is_canonical_address(mmvalp->xmm[1]),
                                   EXC_GP, 0);
             /* fall through */
        case X86_INVPCID_SINGLE_CTXT:
             if ( !mode_64bit() || !ops->read_cr )
                 cr4 = 0;
             else if ( (rc = ops->read_cr(4, &cr4, ctxt)) != X86EMUL_OKAY )
                 goto done;
             generate_exception_if(!(cr4 & X86_CR4_PCIDE) && mmvalp->xmm[0],
                                   EXC_GP, 0);
             break;
        case X86_INVPCID_ALL_INCL_GLOBAL:
        case X86_INVPCID_ALL_NON_GLOBAL:
             break;
        default:
             generate_exception(EXC_GP, 0);
        }

        fail_if(!ops->tlb_op);
        if ( (rc = ops->tlb_op(x86emul_invpcid, truncate_ea(mmvalp->xmm[1]),
                               x86emul_invpcid_aux(mmvalp->xmm[0], dst.val),
                               ctxt)) != X86EMUL_OKAY )
            goto done;

        state->simd_size = simd_none;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x83): /* vpmultishiftqb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(!evex.w, EXC_UD);
        host_and_vcpu_must_have(avx512_vbmi);
        fault_suppression = false;
        goto avx512f_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x8c): /* vpmaskmov{d,q} mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x8e): /* vpmaskmov{d,q} {x,y}mm,{x,y}mm,mem */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        host_and_vcpu_must_have(avx2);
        elem_bytes = 4 << vex.w;
        goto vmaskmov;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x90): /* vpgatherd{d,q} {x,y}mm,mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x91): /* vpgatherq{d,q} {x,y}mm,mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x92): /* vgatherdp{s,d} {x,y}mm,mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x93): /* vgatherqp{s,d} {x,y}mm,mem,{x,y}mm */
    {
        unsigned int mask_reg = ~vex.reg & (mode_64bit() ? 0xf : 7);
        typeof(vex) *pvex;
        union {
            int32_t dw[8];
            int64_t qw[4];
        } index, mask;
        bool done = false;

        ASSERT(ea.type == OP_MEM);
        generate_exception_if(modrm_reg == state->sib_index ||
                              modrm_reg == mask_reg ||
                              state->sib_index == mask_reg, EXC_UD);
        generate_exception_if(!cpu_has_avx, EXC_UD);
        vcpu_must_have(avx2);
        get_fpu(X86EMUL_FPU_ymm);

        /* Read destination, index, and mask registers. */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        opc[0] = 0x7f; /* vmovdqa */
        /* Use (%rax) as destination and modrm_reg as source. */
        pvex->r = !mode_64bit() || !(modrm_reg & 8);
        pvex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "=m" (*mmvalp) : "a" (mmvalp));

        pvex->pfx = vex_f3; /* vmovdqu */
        /* Switch to sib_index as source. */
        pvex->r = !mode_64bit() || !(state->sib_index & 8);
        opc[1] = (state->sib_index & 7) << 3;

        invoke_stub("", "", "=m" (index) : "a" (&index));

        /* Switch to mask_reg as source. */
        pvex->r = !mode_64bit() || !(mask_reg & 8);
        opc[1] = (mask_reg & 7) << 3;

        invoke_stub("", "", "=m" (mask) : "a" (&mask));
        put_stub(stub);

        /* Clear untouched parts of the destination and mask values. */
        n = 1 << (2 + vex.l - ((b & 1) | vex.w));
        op_bytes = 4 << vex.w;
        memset((void *)mmvalp + n * op_bytes, 0, 32 - n * op_bytes);
        memset((void *)&mask + n * op_bytes, 0, 32 - n * op_bytes);

        for ( i = 0; i < n && rc == X86EMUL_OKAY; ++i )
        {
            if ( (vex.w ? mask.qw[i] : mask.dw[i]) < 0 )
            {
                signed long idx = b & 1 ? index.qw[i] : index.dw[i];

                rc = ops->read(ea.mem.seg,
                               truncate_ea(ea.mem.off +
                                           (idx << state->sib_scale)),
                               (void *)mmvalp + i * op_bytes, op_bytes, ctxt);
                if ( rc != X86EMUL_OKAY )
                {
                    /*
                     * If we've made any progress and the access did not fault,
                     * force a retry instead. This is for example necessary to
                     * cope with the limited capacity of HVM's MMIO cache.
                     */
                    if ( rc != X86EMUL_EXCEPTION && done )
                        rc = X86EMUL_RETRY;
                    break;
                }

#ifdef __XEN__
                if ( i + 1 < n && local_events_need_delivery() )
                    rc = X86EMUL_RETRY;
#endif

                done = true;
            }

            if ( vex.w )
                mask.qw[i] = 0;
            else
                mask.dw[i] = 0;
        }

        /* Write destination and mask registers. */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        opc[0] = 0x6f; /* vmovdqa */
        /* Use modrm_reg as destination and (%rax) as source. */
        pvex->r = !mode_64bit() || !(modrm_reg & 8);
        pvex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "+m" (*mmvalp) : "a" (mmvalp));

        pvex->pfx = vex_f3; /* vmovdqu */
        /* Switch to mask_reg as destination. */
        pvex->r = !mode_64bit() || !(mask_reg & 8);
        opc[1] = (mask_reg & 7) << 3;

        invoke_stub("", "", "+m" (mask) : "a" (&mask));
        put_stub(stub);

        if ( rc != X86EMUL_OKAY )
            goto done;

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC_EVEX_66(0x0f38, 0x90): /* vpgatherd{d,q} mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x91): /* vpgatherq{d,q} mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x92): /* vgatherdp{s,d} mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0x93): /* vgatherqp{s,d} mem,[xyz]mm{k} */
    {
        typeof(evex) *pevex;
        union {
            int32_t dw[16];
            int64_t qw[8];
        } index;
        bool done = false;

        ASSERT(ea.type == OP_MEM);
        generate_exception_if((!evex.opmsk || evex.brs || evex.z ||
                               evex.reg != 0xf ||
                               modrm_reg == state->sib_index),
                              EXC_UD);
        avx512_vlen_check(false);
        host_and_vcpu_must_have(avx512f);
        get_fpu(X86EMUL_FPU_zmm);

        /* Read destination and index registers. */
        opc = init_evex(stub);
        pevex = copy_EVEX(opc, evex);
        pevex->opcx = vex_0f;
        opc[0] = 0x7f; /* vmovdqa{32,64} */
        /*
         * The register writeback below has to retain masked-off elements, but
         * needs to clear upper portions in the index-wider-than-data cases.
         * Therefore read (and write below) the full register. The alternative
         * would have been to fiddle with the mask register used.
         */
        pevex->opmsk = 0;
        /* Use (%rax) as destination and modrm_reg as source. */
        pevex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pevex->RX = 1;
        opc[2] = 0xc3;

        invoke_stub("", "", "=m" (*mmvalp) : "a" (mmvalp));

        pevex->pfx = vex_f3; /* vmovdqu{32,64} */
        pevex->w = b & 1;
        /* Switch to sib_index as source. */
        pevex->r = !mode_64bit() || !(state->sib_index & 0x08);
        pevex->R = !mode_64bit() || !(state->sib_index & 0x10);
        opc[1] = (state->sib_index & 7) << 3;

        invoke_stub("", "", "=m" (index) : "a" (&index));
        put_stub(stub);

        /* Clear untouched parts of the destination and mask values. */
        n = 1 << (2 + evex.lr - ((b & 1) | evex.w));
        op_bytes = 4 << evex.w;
        memset((void *)mmvalp + n * op_bytes, 0, 64 - n * op_bytes);
        op_mask &= (1 << n) - 1;

        for ( i = 0; op_mask; ++i )
        {
            long idx = b & 1 ? index.qw[i] : index.dw[i];

            if ( !(op_mask & (1 << i)) )
                continue;

            rc = ops->read(ea.mem.seg,
                           truncate_ea(ea.mem.off + (idx << state->sib_scale)),
                           (void *)mmvalp + i * op_bytes, op_bytes, ctxt);
            if ( rc != X86EMUL_OKAY )
            {
                /*
                 * If we've made some progress and the access did not fault,
                 * force a retry instead. This is for example necessary to
                 * cope with the limited capacity of HVM's MMIO cache.
                 */
                if ( rc != X86EMUL_EXCEPTION && done )
                    rc = X86EMUL_RETRY;
                break;
            }

            op_mask &= ~(1 << i);
            done = true;

#ifdef __XEN__
            if ( op_mask && local_events_need_delivery() )
            {
                rc = X86EMUL_RETRY;
                break;
            }
#endif
        }

        /* Write destination and mask registers. */
        opc = init_evex(stub);
        pevex = copy_EVEX(opc, evex);
        pevex->opcx = vex_0f;
        opc[0] = 0x6f; /* vmovdqa{32,64} */
        pevex->opmsk = 0;
        /* Use modrm_reg as destination and (%rax) as source. */
        pevex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pevex->RX = 1;
        opc[2] = 0xc3;

        invoke_stub("", "", "+m" (*mmvalp) : "a" (mmvalp));

        /*
         * kmovw: This is VEX-encoded, so we can't use pevex. Avoid copy_VEX() etc
         * as well, since we can easily use the 2-byte VEX form here.
         */
        opc -= EVEX_PFX_BYTES;
        opc[0] = 0xc5;
        opc[1] = 0xf8;
        opc[2] = 0x90;
        /* Use (%rax) as source. */
        opc[3] = evex.opmsk << 3;
        opc[4] = 0xc3;

        invoke_stub("", "", "+m" (op_mask) : "a" (&op_mask));
        put_stub(stub);

        if ( rc != X86EMUL_OKAY )
            goto done;

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC_VEX_66(0x0f38, 0x96): /* vfmaddsub132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x97): /* vfmsubadd132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x98): /* vfmadd132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x99): /* vfmadd132s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9a): /* vfmsub132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9b): /* vfmsub132s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9c): /* vfnmadd132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9d): /* vfnmadd132s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9e): /* vfnmsub132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9f): /* vfnmsub132s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa6): /* vfmaddsub213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa7): /* vfmsubadd213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa8): /* vfmadd213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa9): /* vfmadd213s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xaa): /* vfmsub213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xab): /* vfmsub213s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xac): /* vfnmadd213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xad): /* vfnmadd213s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xae): /* vfnmsub213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xaf): /* vfnmsub213s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb6): /* vfmaddsub231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb7): /* vfmsubadd231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb8): /* vfmadd231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb9): /* vfmadd231s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xba): /* vfmsub231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbb): /* vfmsub231s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbc): /* vfnmadd231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbd): /* vfnmadd231s{s,d} xmm/mem,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbe): /* vfnmsub231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbf): /* vfnmsub231s{s,d} xmm/mem,xmm,xmm */
        host_and_vcpu_must_have(fma);
        goto simd_0f_ymm;

    case X86EMUL_OPC_EVEX_F2(0x0f38, 0x9a): /* v4fmaddps m128,zmm+3,zmm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f38, 0xaa): /* v4fnmaddps m128,zmm+3,zmm{k} */
        host_and_vcpu_must_have(avx512_4fmaps);
        generate_exception_if((ea.type != OP_MEM || evex.w || evex.brs ||
                               evex.lr != 2),
                              EXC_UD);
        op_mask = op_mask & 0xffff ? 0xf : 0;
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_F2(0x0f38, 0x9b): /* v4fmaddss m128,xmm+3,xmm{k} */
    case X86EMUL_OPC_EVEX_F2(0x0f38, 0xab): /* v4fnmaddss m128,xmm+3,xmm{k} */
        host_and_vcpu_must_have(avx512_4fmaps);
        generate_exception_if((ea.type != OP_MEM || evex.w || evex.brs ||
                               evex.lr == 3),
                              EXC_UD);
        op_mask = op_mask & 1 ? 0xf : 0;
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa0): /* vpscatterd{d,q} [xyz]mm,mem{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa1): /* vpscatterq{d,q} [xyz]mm,mem{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa2): /* vscatterdp{s,d} [xyz]mm,mem{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xa3): /* vscatterqp{s,d} [xyz]mm,mem{k} */
    {
        typeof(evex) *pevex;
        union {
            int32_t dw[16];
            int64_t qw[8];
        } index;
        bool done = false;

        ASSERT(ea.type == OP_MEM);
        fail_if(!ops->write);
        generate_exception_if((!evex.opmsk || evex.brs || evex.z ||
                               evex.reg != 0xf ||
                               modrm_reg == state->sib_index),
                              EXC_UD);
        avx512_vlen_check(false);
        host_and_vcpu_must_have(avx512f);
        get_fpu(X86EMUL_FPU_zmm);

        /* Read source and index registers. */
        opc = init_evex(stub);
        pevex = copy_EVEX(opc, evex);
        pevex->opcx = vex_0f;
        opc[0] = 0x7f; /* vmovdqa{32,64} */
        /* Use (%rax) as destination and modrm_reg as source. */
        pevex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pevex->RX = 1;
        opc[2] = 0xc3;

        invoke_stub("", "", "=m" (*mmvalp) : "a" (mmvalp));

        pevex->pfx = vex_f3; /* vmovdqu{32,64} */
        pevex->w = b & 1;
        /* Switch to sib_index as source. */
        pevex->r = !mode_64bit() || !(state->sib_index & 0x08);
        pevex->R = !mode_64bit() || !(state->sib_index & 0x10);
        opc[1] = (state->sib_index & 7) << 3;

        invoke_stub("", "", "=m" (index) : "a" (&index));
        put_stub(stub);

        /* Clear untouched parts of the mask value. */
        n = 1 << (2 + evex.lr - ((b & 1) | evex.w));
        op_bytes = 4 << evex.w;
        op_mask &= (1 << n) - 1;

        for ( i = 0; op_mask; ++i )
        {
            long idx = b & 1 ? index.qw[i] : index.dw[i];

            if ( !(op_mask & (1 << i)) )
                continue;

            rc = ops->write(ea.mem.seg,
                            truncate_ea(ea.mem.off + (idx << state->sib_scale)),
                            (void *)mmvalp + i * op_bytes, op_bytes, ctxt);
            if ( rc != X86EMUL_OKAY )
            {
                /* See comment in gather emulation. */
                if ( rc != X86EMUL_EXCEPTION && done )
                    rc = X86EMUL_RETRY;
                break;
            }

            op_mask &= ~(1 << i);
            done = true;

#ifdef __XEN__
            if ( op_mask && local_events_need_delivery() )
            {
                rc = X86EMUL_RETRY;
                break;
            }
#endif
        }

        /* Write mask register. See comment in gather emulation. */
        opc = get_stub(stub);
        opc[0] = 0xc5;
        opc[1] = 0xf8;
        opc[2] = 0x90;
        /* Use (%rax) as source. */
        opc[3] = evex.opmsk << 3;
        opc[4] = 0xc3;

        invoke_stub("", "", "+m" (op_mask) : "a" (&op_mask));
        put_stub(stub);

        if ( rc != X86EMUL_OKAY )
            goto done;

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xb4): /* vpmadd52luq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xb5): /* vpmadd52huq [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_ifma);
        generate_exception_if(!evex.w, EXC_UD);
        goto avx512f_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xc6):
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xc7):
    {
#ifndef __XEN__
        typeof(evex) *pevex;
        union {
            int32_t dw[16];
            int64_t qw[8];
        } index;
#endif

        ASSERT(ea.type == OP_MEM);
        generate_exception_if((!cpu_has_avx512f || !evex.opmsk || evex.brs ||
                               evex.z || evex.reg != 0xf || evex.lr != 2),
                              EXC_UD);

        switch ( modrm_reg & 7 )
        {
        case 1: /* vgatherpf0{d,q}p{s,d} mem{k} */
        case 2: /* vgatherpf1{d,q}p{s,d} mem{k} */
        case 5: /* vscatterpf0{d,q}p{s,d} mem{k} */
        case 6: /* vscatterpf1{d,q}p{s,d} mem{k} */
            vcpu_must_have(avx512pf);
            break;
        default:
            generate_exception(EXC_UD);
        }

        get_fpu(X86EMUL_FPU_zmm);

#ifndef __XEN__
        /*
         * For the test harness perform zero byte memory accesses, such that
         * in particular correct Disp8 scaling can be verified.
         */
        fail_if((modrm_reg & 4) && !ops->write);

        /* Read index register. */
        opc = init_evex(stub);
        pevex = copy_EVEX(opc, evex);
        pevex->opcx = vex_0f;
        /* vmovdqu{32,64} */
        opc[0] = 0x7f;
        pevex->pfx = vex_f3;
        pevex->w = b & 1;
        /* Use (%rax) as destination and sib_index as source. */
        pevex->b = 1;
        opc[1] = (state->sib_index & 7) << 3;
        pevex->r = !mode_64bit() || !(state->sib_index & 0x08);
        pevex->R = !mode_64bit() || !(state->sib_index & 0x10);
        pevex->RX = 1;
        opc[2] = 0xc3;

        invoke_stub("", "", "=m" (index) : "a" (&index));
        put_stub(stub);

        /* Clear untouched parts of the mask value. */
        n = 1 << (4 - ((b & 1) | evex.w));
        op_mask &= (1 << n) - 1;

        for ( i = 0; rc == X86EMUL_OKAY && op_mask; ++i )
        {
            long idx = b & 1 ? index.qw[i] : index.dw[i];

            if ( !(op_mask & (1 << i)) )
                continue;

            rc = (modrm_reg & 4
                  ? ops->write
                  : ops->read)(ea.mem.seg,
                               truncate_ea(ea.mem.off +
                                           (idx << state->sib_scale)),
                               NULL, 0, ctxt);
            if ( rc == X86EMUL_EXCEPTION )
            {
                /* Squash memory access related exceptions. */
                x86_emul_reset_event(ctxt);
                rc = X86EMUL_OKAY;
            }

            op_mask &= ~(1 << i);
        }

        if ( rc != X86EMUL_OKAY )
            goto done;
#endif

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC(0x0f38, 0xc8):     /* sha1nexte xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xc9):     /* sha1msg1 xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xca):     /* sha1msg2 xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xcb):     /* sha256rnds2 XMM0,xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xcc):     /* sha256msg1 xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xcd):     /* sha256msg2 xmm/m128,xmm */
        host_and_vcpu_must_have(sha);
        op_bytes = 16;
        goto simd_0f38_common;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xc8): /* vexp2p{s,d} zmm/mem,zmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xca): /* vrcp28p{s,d} zmm/mem,zmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xcc): /* vrsqrt28p{s,d} zmm/mem,zmm{k} */
        host_and_vcpu_must_have(avx512er);
        generate_exception_if((ea.type != OP_REG || !evex.brs) && evex.lr != 2,
                              EXC_UD);
        goto simd_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xcb): /* vrcp28s{s,d} xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xcd): /* vrsqrt28s{s,d} xmm/mem,xmm,xmm{k} */
        host_and_vcpu_must_have(avx512er);
        goto simd_zmm_scalar_sae;

    case X86EMUL_OPC_66(0x0f38, 0xcf):      /* gf2p8mulb xmm/m128,xmm */
        host_and_vcpu_must_have(gfni);
        goto simd_0f38_common;

    case X86EMUL_OPC_VEX_66(0x0f38, 0xcf):  /* vgf2p8mulb {x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(gfni);
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_avx;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xcf): /* vgf2p8mulb [xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(gfni);
        generate_exception_if(evex.w || evex.brs, EXC_UD);
        elem_bytes = 1;
        goto avx512f_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f38, 0xdc):  /* vaesenc {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdd):  /* vaesenclast {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xde):  /* vaesdec {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdf):  /* vaesdeclast {x,y}mm/mem,{x,y}mm,{x,y}mm */
        if ( !vex.l )
            host_and_vcpu_must_have(aesni);
        else
            host_and_vcpu_must_have(vaes);
        goto simd_0f_avx;

    case X86EMUL_OPC_EVEX_66(0x0f38, 0xdc): /* vaesenc [xyz]mm/mem,[xyz]mm,[xyz]mm */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xdd): /* vaesenclast [xyz]mm/mem,[xyz]mm,[xyz]mm */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xde): /* vaesdec [xyz]mm/mem,[xyz]mm,[xyz]mm */
    case X86EMUL_OPC_EVEX_66(0x0f38, 0xdf): /* vaesdeclast [xyz]mm/mem,[xyz]mm,[xyz]mm */
        host_and_vcpu_must_have(vaes);
        generate_exception_if(evex.brs || evex.opmsk, EXC_UD);
        goto avx512f_no_sae;

#endif /* !X86EMUL_NO_SIMD */

    case X86EMUL_OPC(0x0f38, 0xf0): /* movbe m,r */
    case X86EMUL_OPC(0x0f38, 0xf1): /* movbe r,m */
        vcpu_must_have(movbe);
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
#ifdef HAVE_AS_SSE4_2
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

    case X86EMUL_OPC_VEX(0x0f38, 0xf2):    /* andn r/m,r,r */
    case X86EMUL_OPC_VEX(0x0f38, 0xf5):    /* bzhi r,r/m,r */
    case X86EMUL_OPC_VEX_F3(0x0f38, 0xf5): /* pext r/m,r,r */
    case X86EMUL_OPC_VEX_F2(0x0f38, 0xf5): /* pdep r/m,r,r */
    case X86EMUL_OPC_VEX(0x0f38, 0xf7):    /* bextr r,r/m,r */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xf7): /* shlx r,r/m,r */
    case X86EMUL_OPC_VEX_F3(0x0f38, 0xf7): /* sarx r,r/m,r */
    case X86EMUL_OPC_VEX_F2(0x0f38, 0xf7): /* shrx r,r/m,r */
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pvex = container_of(buf + 1, typeof(vex), raw[0]);

        if ( b == 0xf5 || vex.pfx )
            host_and_vcpu_must_have(bmi2);
        else
            host_and_vcpu_must_have(bmi1);
        generate_exception_if(vex.l, EXC_UD);

        buf[0] = 0xc4;
        *pvex = vex;
        pvex->b = 1;
        pvex->r = 1;
        pvex->reg = 0xf; /* rAX */
        buf[3] = b;
        buf[4] = 0x09; /* reg=rCX r/m=(%rCX) */
        buf[5] = 0xc3;

        src.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        emulate_stub([dst] "=&c" (dst.val), "[dst]" (&src.val), "a" (*src.reg));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_VEX(0x0f38, 0xf3): /* Grp 17 */
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pvex = container_of(buf + 1, typeof(vex), raw[0]);

        switch ( modrm_reg & 7 )
        {
        case 1: /* blsr r,r/m */
        case 2: /* blsmsk r,r/m */
        case 3: /* blsi r,r/m */
            host_and_vcpu_must_have(bmi1);
            break;
        default:
            goto unrecognized_insn;
        }

        generate_exception_if(vex.l, EXC_UD);

        buf[0] = 0xc4;
        *pvex = vex;
        pvex->b = 1;
        pvex->r = 1;
        pvex->reg = 0xf; /* rAX */
        buf[3] = b;
        buf[4] = (modrm & 0x38) | 0x01; /* r/m=(%rCX) */
        buf[5] = 0xc3;

        dst.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        emulate_stub("=&a" (dst.val), "c" (&src.val));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_66(0x0f38, 0xf6): /* adcx r/m,r */
    case X86EMUL_OPC_F3(0x0f38, 0xf6): /* adox r/m,r */
    {
        unsigned int mask = rep_prefix() ? X86_EFLAGS_OF : X86_EFLAGS_CF;
        unsigned int aux = _regs.eflags & mask ? ~0 : 0;
        bool carry;

        vcpu_must_have(adx);
#ifdef __x86_64__
        if ( op_bytes == 8 )
            asm ( "add %[aux],%[aux]\n\t"
                  "adc %[src],%[dst]\n\t"
                  ASM_FLAG_OUT(, "setc %[carry]")
                  : [dst] "+r" (dst.val),
                    [carry] ASM_FLAG_OUT("=@ccc", "=qm") (carry),
                    [aux] "+r" (aux)
                  : [src] "rm" (src.val) );
        else
#endif
            asm ( "add %[aux],%[aux]\n\t"
                  "adc %k[src],%k[dst]\n\t"
                  ASM_FLAG_OUT(, "setc %[carry]")
                  : [dst] "+r" (dst.val),
                    [carry] ASM_FLAG_OUT("=@ccc", "=qm") (carry),
                    [aux] "+r" (aux)
                  : [src] "rm" (src.val) );
        if ( carry )
            _regs.eflags |= mask;
        else
            _regs.eflags &= ~mask;
        break;
    }

    case X86EMUL_OPC_VEX_F2(0x0f38, 0xf6): /* mulx r/m,r,r */
        vcpu_must_have(bmi2);
        generate_exception_if(vex.l, EXC_UD);
        ea.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        if ( mode_64bit() && vex.w )
            asm ( "mulq %3" : "=a" (*ea.reg), "=d" (dst.val)
                            : "0" (src.val), "rm" (_regs.r(dx)) );
        else
            asm ( "mull %3" : "=a" (*ea.reg), "=d" (dst.val)
                            : "0" ((uint32_t)src.val), "rm" (_regs.edx) );
        break;

    case X86EMUL_OPC_66(0x0f38, 0xf8): /* movdir64b r,m512 */
        host_and_vcpu_must_have(movdir64b);
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        src.val = truncate_ea(*dst.reg);
        generate_exception_if(!is_aligned(x86_seg_es, src.val, 64, ctxt, ops),
                              EXC_GP, 0);
        fail_if(!ops->blk);
        state->blk = blk_movdir;
        BUILD_BUG_ON(sizeof(*mmvalp) < 64);
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 64,
                             ctxt)) != X86EMUL_OKAY ||
             (rc = ops->blk(x86_seg_es, src.val, mmvalp, 64, &_regs.eflags,
                            state, ctxt)) != X86EMUL_OKAY )
            goto done;
        state->simd_size = simd_none;
        break;

    case X86EMUL_OPC_F2(0x0f38, 0xf8): /* enqcmd r,m512 */
    case X86EMUL_OPC_F3(0x0f38, 0xf8): /* enqcmds r,m512 */
        host_and_vcpu_must_have(enqcmd);
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        generate_exception_if(vex.pfx != vex_f2 && !mode_ring0(), EXC_GP, 0);
        src.val = truncate_ea(*dst.reg);
        generate_exception_if(!is_aligned(x86_seg_es, src.val, 64, ctxt, ops),
                              EXC_GP, 0);
        fail_if(!ops->blk);
        BUILD_BUG_ON(sizeof(*mmvalp) < 64);
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 64,
                             ctxt)) != X86EMUL_OKAY )
            goto done;
        if ( vex.pfx == vex_f2 ) /* enqcmd */
        {
            fail_if(!ops->read_msr);
            if ( (rc = ops->read_msr(MSR_PASID, &msr_val,
                                     ctxt)) != X86EMUL_OKAY )
                goto done;
            generate_exception_if(!(msr_val & PASID_VALID), EXC_GP, 0);
            mmvalp->data32[0] = MASK_EXTR(msr_val, PASID_PASID_MASK);
        }
        mmvalp->data32[0] &= ~0x7ff00000;
        state->blk = blk_enqcmd;
        if ( (rc = ops->blk(x86_seg_es, src.val, mmvalp, 64, &_regs.eflags,
                            state, ctxt)) != X86EMUL_OKAY )
            goto done;
        state->simd_size = simd_none;
        break;

    case X86EMUL_OPC(0x0f38, 0xf9): /* movdiri mem,r */
        host_and_vcpu_must_have(movdiri);
        generate_exception_if(dst.type != OP_MEM, EXC_UD);
        fail_if(!ops->blk);
        state->blk = blk_movdir;
        if ( (rc = ops->blk(dst.mem.seg, dst.mem.off, &src.val, op_bytes,
                            &_regs.eflags, state, ctxt)) != X86EMUL_OKAY )
            goto done;
        dst.type = OP_NONE;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x00): /* vpermq $imm8,ymm/m256,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x01): /* vpermpd $imm8,ymm/m256,ymm */
        generate_exception_if(!vex.l || !vex.w, EXC_UD);
        goto simd_0f_imm8_avx2;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x00): /* vpermq $imm8,{y,z}mm/mem,{y,z}mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x01): /* vpermpd $imm8,{y,z}mm/mem,{y,z}mm{k} */
        generate_exception_if(!evex.lr || !evex.w, EXC_UD);
        fault_suppression = false;
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x38): /* vinserti128 $imm8,xmm/m128,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x39): /* vextracti128 $imm8,ymm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x46): /* vperm2i128 $imm8,ymm/m256,ymm,ymm */
        generate_exception_if(!vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x02): /* vpblendd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_imm8_avx2;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x06): /* vperm2f128 $imm8,ymm/m256,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x18): /* vinsertf128 $imm8,xmm/m128,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x19): /* vextractf128 $imm8,ymm,xmm/m128 */
        generate_exception_if(!vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x04): /* vpermilps $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x05): /* vpermilpd $imm8,{x,y}mm/mem,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x04): /* vpermilps $imm8,[xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x05): /* vpermilpd $imm8,[xyz]mm/mem,[xyz]mm{k} */
        generate_exception_if(evex.w != (b & 1), EXC_UD);
        fault_suppression = false;
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC_66(0x0f3a, 0x08): /* roundps $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x09): /* roundpd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0a): /* roundss $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0b): /* roundsd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0c): /* blendps $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0d): /* blendpd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0e): /* pblendw $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x40): /* dpps $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x41): /* dppd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x42): /* mpsadbw $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(sse4_1);
        goto simd_0f3a_common;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x0a): /* vrndscaless $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x0b): /* vrndscalesd $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(ea.type != OP_REG && evex.brs, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x08): /* vrndscaleps $imm8,[xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x09): /* vrndscalepd $imm8,[xyz]mm/mem,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(evex.w != (b & 1), EXC_UD);
        avx512_vlen_check(b & 2);
        goto simd_imm8_zmm;

#endif /* X86EMUL_NO_SIMD */

    CASE_SIMD_PACKED_INT(0x0f3a, 0x0f): /* palignr $imm8,{,x}mm/mem,{,x}mm */
        host_and_vcpu_must_have(ssse3);
        if ( vex.pfx )
        {
    simd_0f3a_common:
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }
        opc = init_prefixes(stub);
        opc[0] = 0x3a;
        opc[1] = b;
        opc[2] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[2] &= 0x38;
        }
        opc[3] = imm1;
        insn_bytes = PFX_BYTES + 4;
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x42): /* vdbpsadbw $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(evex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x0f): /* vpalignr $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        fault_suppression = false;
        goto avx512bw_imm;

    case X86EMUL_OPC_66(0x0f3a, 0x14): /* pextrb $imm8,xmm,r/m */
    case X86EMUL_OPC_66(0x0f3a, 0x15): /* pextrw $imm8,xmm,r/m */
    case X86EMUL_OPC_66(0x0f3a, 0x16): /* pextr{d,q} $imm8,xmm,r/m */
    case X86EMUL_OPC_66(0x0f3a, 0x17): /* extractps $imm8,xmm,r/m */
        host_and_vcpu_must_have(sse4_1);
        get_fpu(X86EMUL_FPU_xmm);

        opc = init_prefixes(stub);
        opc++[0] = 0x3a;
    pextr:
        opc[0] = b;
        /* Convert memory/GPR operand to (%rAX). */
        rex_prefix &= ~REX_B;
        evex.b = vex.b = 1;
        if ( !mode_64bit() )
            evex.w = vex.w = 0;
        opc[1] = modrm & 0x38;
        opc[2] = imm1;
        opc[3] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            /* Cover for extra prefix byte. */
            --opc;
        }

        if ( evex_encoded() )
            copy_EVEX(opc, evex);
        else
            copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "=m" (dst.val) : "a" (&dst.val));
        put_stub(stub);

        ASSERT(!state->simd_size);
        dst.bytes = dst.type == OP_REG || b == 0x17 ? 4 : 1 << (b & 3);
        if ( b == 0x16 && (rex_prefix & REX_W) )
            dst.bytes = 8;
        break;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x14): /* vpextrb $imm8,xmm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x15): /* vpextrw $imm8,xmm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x16): /* vpextr{d,q} $imm8,xmm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x17): /* vextractps $imm8,xmm,r/m */
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
        host_and_vcpu_must_have(avx);
        get_fpu(X86EMUL_FPU_ymm);

        /* Work around erratum BT41. */
        if ( !mode_64bit() )
            vex.w = 0;

        opc = init_prefixes(stub);
        goto pextr;

    case X86EMUL_OPC_EVEX_66(0x0f, 0xc5):   /* vpextrw $imm8,xmm,reg */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        /* Convert to alternative encoding: We want to use a memory operand. */
        evex.opcx = ext_0f3a;
        b = 0x15;
        modrm <<= 3;
        evex.r = evex.b;
        evex.R = evex.x;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x14): /* vpextrb $imm8,xmm,r/m */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x15): /* vpextrw $imm8,xmm,r/m */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x16): /* vpextr{d,q} $imm8,xmm,r/m */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x17): /* vextractps $imm8,xmm,r/m */
        generate_exception_if((evex.lr || evex.reg != 0xf || !evex.RX ||
                               evex.opmsk || evex.brs),
                              EXC_UD);
        if ( !(b & 2) )
            host_and_vcpu_must_have(avx512bw);
        else if ( !(b & 1) )
            host_and_vcpu_must_have(avx512dq);
        else
            host_and_vcpu_must_have(avx512f);
        get_fpu(X86EMUL_FPU_zmm);
        opc = init_evex(stub);
        goto pextr;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x18): /* vinsertf32x4 $imm8,xmm/m128,{y,z}mm{k} */
                                            /* vinsertf64x2 $imm8,xmm/m128,{y,z}mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x19): /* vextractf32x4 $imm8,{y,z}mm,xmm/m128{k} */
                                            /* vextractf64x2 $imm8,{y,z}mm,xmm/m128{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x38): /* vinserti32x4 $imm8,xmm/m128,{y,z}mm{k} */
                                            /* vinserti64x2 $imm8,xmm/m128,{y,z}mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x39): /* vextracti32x4 $imm8,{y,z}mm,xmm/m128{k} */
                                            /* vextracti64x2 $imm8,{y,z}mm,xmm/m128{k} */
        if ( evex.w )
            host_and_vcpu_must_have(avx512dq);
        generate_exception_if(evex.brs, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x23): /* vshuff32x4 $imm8,{y,z}mm/mem,{y,z}mm,{y,z}mm{k} */
                                            /* vshuff64x2 $imm8,{y,z}mm/mem,{y,z}mm,{y,z}mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x43): /* vshufi32x4 $imm8,{y,z}mm/mem,{y,z}mm,{y,z}mm{k} */
                                            /* vshufi64x2 $imm8,{y,z}mm/mem,{y,z}mm,{y,z}mm{k} */
        generate_exception_if(!evex.lr, EXC_UD);
        fault_suppression = false;
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x1a): /* vinsertf32x4 $imm8,ymm/m256,zmm{k} */
                                            /* vinsertf64x2 $imm8,ymm/m256,zmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x1b): /* vextractf32x8 $imm8,zmm,ymm/m256{k} */
                                            /* vextractf64x4 $imm8,zmm,ymm/m256{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x3a): /* vinserti32x4 $imm8,ymm/m256,zmm{k} */
                                            /* vinserti64x2 $imm8,ymm/m256,zmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x3b): /* vextracti32x8 $imm8,zmm,ymm/m256{k} */
                                            /* vextracti64x4 $imm8,zmm,ymm/m256{k} */
        if ( !evex.w )
            host_and_vcpu_must_have(avx512dq);
        generate_exception_if(evex.lr != 2 || evex.brs, EXC_UD);
        fault_suppression = false;
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x1d): /* vcvtps2ph $imm8,{x,y}mm,xmm/mem */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x1d): /* vcvtps2ph $imm8,[xyz]mm,{x,y}mm/mem{k} */
    {
        uint32_t mxcsr;

        fail_if(!ops->write);
        if ( evex_encoded() )
        {
            generate_exception_if((evex.w || evex.reg != 0xf || !evex.RX ||
                                   (ea.type != OP_REG && (evex.z || evex.brs))),
                                  EXC_UD);
            host_and_vcpu_must_have(avx512f);
            avx512_vlen_check(false);
            opc = init_evex(stub);
        }
        else
        {
            generate_exception_if(vex.w || vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(f16c);
            opc = init_prefixes(stub);
        }

        op_bytes = 8 << evex.lr;

        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            vex.b = 1;
            evex.b = 1;
            opc[1] &= 0x38;
        }
        opc[2] = imm1;
        if ( evex_encoded() )
        {
            unsigned int full = 0;

            insn_bytes = EVEX_PFX_BYTES + 3;
            copy_EVEX(opc, evex);

            if ( ea.type == OP_MEM && evex.opmsk )
            {
                full = 0xffff >> (16 - op_bytes / 2);
                op_mask &= full;
                if ( !op_mask )
                    goto complete_insn;

                first_byte = __builtin_ctz(op_mask);
                op_mask >>= first_byte;
                full >>= first_byte;
                first_byte <<= 1;
                op_bytes = (32 - __builtin_clz(op_mask)) << 1;

                /*
                 * We may need to read (parts of) the memory operand for the
                 * purpose of merging in order to avoid splitting the write
                 * below into multiple ones.
                 */
                if ( op_mask != full &&
                     (rc = ops->read(ea.mem.seg,
                                     truncate_ea(ea.mem.off + first_byte),
                                     (void *)mmvalp + first_byte, op_bytes,
                                     ctxt)) != X86EMUL_OKAY )
                    goto done;
            }
        }
        else
        {
            insn_bytes = PFX_BYTES + 3;
            copy_VEX(opc, vex);
        }
        opc[3] = 0xc3;

        /* Latch MXCSR - we may need to restore it below. */
        invoke_stub("stmxcsr %[mxcsr]", "",
                    "=m" (*mmvalp), [mxcsr] "=m" (mxcsr) : "a" (mmvalp));

        put_stub(stub);

        if ( ea.type == OP_MEM )
        {
            rc = ops->write(ea.mem.seg, truncate_ea(ea.mem.off + first_byte),
                            (void *)mmvalp + first_byte, op_bytes, ctxt);
            if ( rc != X86EMUL_OKAY )
            {
                asm volatile ( "ldmxcsr %0" :: "m" (mxcsr) );
                goto done;
            }
        }

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x1e): /* vpcmpu{d,q} $imm8,[xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x1f): /* vpcmp{d,q} $imm8,[xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x3e): /* vpcmpu{b,w} $imm8,[xyz]mm/mem,[xyz]mm,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x3f): /* vpcmp{b,w} $imm8,[xyz]mm/mem,[xyz]mm,k{k} */
        generate_exception_if(!evex.r || !evex.R || evex.z, EXC_UD);
        if ( !(b & 0x20) )
            goto avx512f_imm8_no_sae;
    avx512bw_imm:
        host_and_vcpu_must_have(avx512bw);
        generate_exception_if(evex.brs, EXC_UD);
        elem_bytes = 1 << evex.w;
        avx512_vlen_check(false);
        goto simd_imm8_zmm;

    case X86EMUL_OPC_66(0x0f3a, 0x20): /* pinsrb $imm8,r32/m8,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x22): /* pinsr{d,q} $imm8,r/m,xmm */
        host_and_vcpu_must_have(sse4_1);
        get_fpu(X86EMUL_FPU_xmm);
        memcpy(mmvalp, &src.val, op_bytes);
        ea.type = OP_MEM;
        op_bytes = src.bytes;
        d = SrcMem16; /* Fake for the common SIMD code below. */
        state->simd_size = simd_other;
        goto simd_0f3a_common;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x20): /* vpinsrb $imm8,r32/m8,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x22): /* vpinsr{d,q} $imm8,r/m,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        if ( !mode_64bit() )
            vex.w = 0;
        memcpy(mmvalp, &src.val, op_bytes);
        ea.type = OP_MEM;
        op_bytes = src.bytes;
        d = SrcMem16; /* Fake for the common SIMD code below. */
        state->simd_size = simd_other;
        goto simd_0f_int_imm8;

    case X86EMUL_OPC_66(0x0f3a, 0x21): /* insertps $imm8,xmm/m32,xmm */
        host_and_vcpu_must_have(sse4_1);
        op_bytes = 4;
        goto simd_0f3a_common;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x21): /* vinsertps $imm8,xmm/m32,xmm,xmm */
        op_bytes = 4;
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x41): /* vdppd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x21): /* vinsertps $imm8,xmm/m32,xmm,xmm */
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(evex.lr || evex.w || evex.opmsk || evex.brs,
                              EXC_UD);
        op_bytes = 4;
        goto simd_imm8_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x50): /* vrangep{s,d} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x56): /* vreducep{s,d} $imm8,[xyz]mm/mem,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512dq);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x26): /* vgetmantp{s,d} $imm8,[xyz]mm/mem,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x54): /* vfixupimmp{s,d} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512f);
        if ( ea.type != OP_REG || !evex.brs )
            avx512_vlen_check(false);
        goto simd_imm8_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x51): /* vranges{s,d} $imm8,xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x57): /* vreduces{s,d} $imm8,xmm/mem,xmm,xmm{k} */
        host_and_vcpu_must_have(avx512dq);
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x27): /* vgetmants{s,d} $imm8,xmm/mem,xmm,xmm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x55): /* vfixupimms{s,d} $imm8,xmm/mem,xmm,xmm{k} */
        host_and_vcpu_must_have(avx512f);
        generate_exception_if(ea.type != OP_REG && evex.brs, EXC_UD);
        if ( !evex.brs )
            avx512_vlen_check(true);
        goto simd_imm8_zmm;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x30): /* kshiftr{b,w} $imm8,k,k */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x32): /* kshiftl{b,w} $imm8,k,k */
        if ( !vex.w )
            host_and_vcpu_must_have(avx512dq);
    opmask_shift_imm:
        generate_exception_if(vex.l || !vex.r || vex.reg != 0xf ||
                              ea.type != OP_REG, EXC_UD);
        host_and_vcpu_must_have(avx512f);
        get_fpu(X86EMUL_FPU_opmask);
        op_bytes = 1; /* Any non-zero value will do. */
        goto simd_0f_imm8;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x31): /* kshiftr{d,q} $imm8,k,k */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x33): /* kshiftl{d,q} $imm8,k,k */
        host_and_vcpu_must_have(avx512bw);
        goto opmask_shift_imm;

    case X86EMUL_OPC_66(0x0f3a, 0x44):     /* pclmulqdq $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x44): /* vpclmulqdq $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(pclmulqdq);
        if ( vex.opcx == vex_none )
            goto simd_0f3a_common;
        if ( vex.l )
            host_and_vcpu_must_have(vpclmulqdq);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x44): /* vpclmulqdq $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm */
        host_and_vcpu_must_have(vpclmulqdq);
        generate_exception_if(evex.brs || evex.opmsk, EXC_UD);
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x48): /* vpermil2ps $imm,{x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
                                           /* vpermil2ps $imm,{x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x49): /* vpermil2pd $imm,{x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
                                           /* vpermil2pd $imm,{x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(xop);
        goto simd_0f_imm8_ymm;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x4a): /* vblendvps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x4b): /* vblendvpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x4c): /* vpblendvb {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_int_imm8;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5c): /* vfmaddsubps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddsubps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5d): /* vfmaddsubpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5e): /* vfmsubaddps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubaddps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5f): /* vfmsubaddpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x68): /* vfmaddps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x69): /* vfmaddpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6a): /* vfmaddss xmm,xmm/m32,xmm,xmm */
                                           /* vfmaddss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6b): /* vfmaddsd xmm,xmm/m64,xmm,xmm */
                                           /* vfmaddsd xmm/m64,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6c): /* vfmsubps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6d): /* vfmsubpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6e): /* vfmsubss xmm,xmm/m32,xmm,xmm */
                                           /* vfmsubss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6f): /* vfmsubsd xmm,xmm/m64,xmm,xmm */
                                           /* vfmsubsd xmm/m64,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x78): /* vfnmaddps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmaddps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x79): /* vfnmaddpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7a): /* vfnmaddss xmm,xmm/m32,xmm,xmm */
                                           /* vfnmaddss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7b): /* vfnmaddsd xmm,xmm/m64,xmm,xmm */
                                           /* vfnmaddsd xmm/m64,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7c): /* vfnmsubps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmsubps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7d): /* vfnmsubpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7e): /* vfnmsubss xmm,xmm/m32,xmm,xmm */
                                           /* vfnmsubss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7f): /* vfnmsubsd xmm,xmm/m64,xmm,xmm */
                                           /* vfnmsubsd xmm/m64,xmm,xmm,xmm */
        host_and_vcpu_must_have(fma4);
        goto simd_0f_imm8_ymm;

    case X86EMUL_OPC_66(0x0f3a, 0x60):     /* pcmpestrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x60): /* vpcmpestrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x61):     /* pcmpestri $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x61): /* vpcmpestri $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x62):     /* pcmpistrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x62): /* vpcmpistrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x63):     /* pcmpistri $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x63): /* vpcmpistri $imm8,xmm/m128,xmm */
        if ( vex.opcx == vex_none )
        {
            host_and_vcpu_must_have(sse4_2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        if ( vex.opcx == vex_none )
            opc++[0] = 0x3a;
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rDI). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x3f;
            opc[1] |= 0x07;

            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 16, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        opc[3] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            /* Cover for extra prefix byte. */
            --opc;
            ++insn_bytes;
        }

        copy_REX_VEX(opc, rex_prefix, vex);
#ifdef __x86_64__
        if ( rex_prefix & REX_W )
            emulate_stub("=c" (dst.val), "m" (*mmvalp), "D" (mmvalp),
                         "a" (_regs.rax), "d" (_regs.rdx));
        else
#endif
            emulate_stub("=c" (dst.val), "m" (*mmvalp), "D" (mmvalp),
                         "a" (_regs.eax), "d" (_regs.edx));

        state->simd_size = simd_none;
        if ( b & 1 )
            _regs.r(cx) = (uint32_t)dst.val;
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x66): /* vfpclassp{s,d} $imm8,[xyz]mm/mem,k{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x67): /* vfpclasss{s,d} $imm8,[xyz]mm/mem,k{k} */
        host_and_vcpu_must_have(avx512dq);
        generate_exception_if(!evex.r || !evex.R || evex.z, EXC_UD);
        if ( !(b & 1) )
            goto avx512f_imm8_no_sae;
        generate_exception_if(evex.brs, EXC_UD);
        avx512_vlen_check(true);
        goto simd_imm8_zmm;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x70): /* vpshldw $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x72): /* vpshrdw $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        generate_exception_if(!evex.w, EXC_UD);
        elem_bytes = 2;
        /* fall through */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x71): /* vpshld{d,q} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0x73): /* vpshrd{d,q} $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(avx512_vbmi2);
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC(0x0f3a, 0xcc):     /* sha1rnds4 $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(sha);
        op_bytes = 16;
        goto simd_0f3a_common;

    case X86EMUL_OPC_66(0x0f3a, 0xce):      /* gf2p8affineqb $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0xcf):      /* gf2p8affineinvqb $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(gfni);
        goto simd_0f3a_common;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0xce):  /* vgf2p8affineqb $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0xcf):  /* vgf2p8affineinvqb $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(gfni);
        generate_exception_if(!vex.w, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_EVEX_66(0x0f3a, 0xce): /* vgf2p8affineqb $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
    case X86EMUL_OPC_EVEX_66(0x0f3a, 0xcf): /* vgf2p8affineinvqb $imm8,[xyz]mm/mem,[xyz]mm,[xyz]mm{k} */
        host_and_vcpu_must_have(gfni);
        generate_exception_if(!evex.w, EXC_UD);
        fault_suppression = false;
        goto avx512f_imm8_no_sae;

    case X86EMUL_OPC_66(0x0f3a, 0xdf):     /* aeskeygenassist $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0xdf): /* vaeskeygenassist $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(aesni);
        if ( vex.opcx == vex_none )
            goto simd_0f3a_common;
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_imm8_avx;

#endif /* X86EMUL_NO_SIMD */

    case X86EMUL_OPC_VEX_F2(0x0f3a, 0xf0): /* rorx imm,r/m,r */
        vcpu_must_have(bmi2);
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
        if ( ea.type == OP_REG )
            src.val = *ea.reg;
        else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val, op_bytes,
                                   ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        if ( mode_64bit() && vex.w )
            asm ( "rorq %b1,%0" : "=g" (dst.val) : "c" (imm1), "0" (src.val) );
        else
            asm ( "rorl %b1,%k0" : "=g" (dst.val) : "c" (imm1), "0" (src.val) );
        break;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_XOP(08, 0x85): /* vpmacssww xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x86): /* vpmacsswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x87): /* vpmacssdql xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x8e): /* vpmacssdd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x8f): /* vpmacssdqh xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x95): /* vpmacsww xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x96): /* vpmacswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x97): /* vpmacsdql xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x9e): /* vpmacsdd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x9f): /* vpmacsdqh xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xa6): /* vpmadcsswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xb6): /* vpmadcswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xc0): /* vprotb $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xc1): /* vprotw $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xc2): /* vprotd $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xc3): /* vprotq $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xcc): /* vpcomb $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xcd): /* vpcomw $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xce): /* vpcomd $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xcf): /* vpcomq $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xec): /* vpcomub $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xed): /* vpcomuw $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xee): /* vpcomud $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xef): /* vpcomuq $imm,xmm/m128,xmm,xmm */
        generate_exception_if(vex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(08, 0xa3): /* vpperm xmm/m128,xmm,xmm,xmm */
                                    /* vpperm xmm,xmm/m128,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(08, 0xa2): /* vpcmov {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
                                    /* vpcmov {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(xop);
        goto simd_0f_imm8_ymm;

#endif /* X86EMUL_NO_SIMD */

    case X86EMUL_OPC_XOP(09, 0x01): /* XOP Grp1 */
        switch ( modrm_reg & 7 )
        {
        case 1: /* blcfill r/m,r */
        case 2: /* blsfill r/m,r */
        case 3: /* blcs r/m,r */
        case 4: /* tzmsk r/m,r */
        case 5: /* blcic r/m,r */
        case 6: /* blsic r/m,r */
        case 7: /* t1mskc r/m,r */
            host_and_vcpu_must_have(tbm);
            break;
        default:
            goto unrecognized_insn;
        }

    xop_09_rm_rv:
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pxop = container_of(buf + 1, typeof(vex), raw[0]);

        generate_exception_if(vex.l, EXC_UD);

        buf[0] = 0x8f;
        *pxop = vex;
        pxop->b = 1;
        pxop->r = 1;
        pxop->reg = 0xf; /* rAX */
        buf[3] = b;
        buf[4] = (modrm & 0x38) | 0x01; /* r/m=(%rCX) */
        buf[5] = 0xc3;

        dst.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        emulate_stub([dst] "=&a" (dst.val), "c" (&src.val));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_XOP(09, 0x02): /* XOP Grp2 */
        switch ( modrm_reg & 7 )
        {
        case 1: /* blcmsk r/m,r */
        case 6: /* blci r/m,r */
            host_and_vcpu_must_have(tbm);
            goto xop_09_rm_rv;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC_XOP(09, 0x12): /* XOP Grp3 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* llwpcb r */
        case 1: /* slwpcb r */
            /* LWP is unsupported, so produce #UD unconditionally. */
            generate_exception(EXC_UD);
        }
        goto unrecognized_insn;

#ifndef X86EMUL_NO_SIMD

    case X86EMUL_OPC_XOP(09, 0x82): /* vfrczss xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x83): /* vfrczsd xmm/m128,xmm */
        generate_exception_if(vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(09, 0x80): /* vfrczps {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_XOP(09, 0x81): /* vfrczpd {x,y}mm/mem,{x,y}mm */
        host_and_vcpu_must_have(xop);
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_ymm;

    case X86EMUL_OPC_XOP(09, 0xc1): /* vphaddbw xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc2): /* vphaddbd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc3): /* vphaddbq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc6): /* vphaddwd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc7): /* vphaddwq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xcb): /* vphadddq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd1): /* vphaddubw xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd2): /* vphaddubd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd3): /* vphaddubq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd6): /* vphadduwd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd7): /* vphadduwq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xdb): /* vphaddudq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xe2): /* vphsubwd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xe3): /* vphsubdq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xe1): /* vphsubbw xmm/m128,xmm */
        generate_exception_if(vex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(09, 0x90): /* vprotb xmm/m128,xmm,xmm */
                                    /* vprotb xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x91): /* vprotw xmm/m128,xmm,xmm */
                                    /* vprotw xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x92): /* vprotd xmm/m128,xmm,xmm */
                                    /* vprotd xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x93): /* vprotq xmm/m128,xmm,xmm */
                                    /* vprotq xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x94): /* vpshlb xmm/m128,xmm,xmm */
                                    /* vpshlb xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x95): /* vpshlw xmm/m128,xmm,xmm */
                                    /* vpshlw xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x96): /* vpshld xmm/m128,xmm,xmm */
                                    /* vpshld xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x97): /* vpshlq xmm/m128,xmm,xmm */
                                    /* vpshlq xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x98): /* vpshab xmm/m128,xmm,xmm */
                                    /* vpshab xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x99): /* vpshaw xmm/m128,xmm,xmm */
                                    /* vpshaw xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x9a): /* vpshad xmm/m128,xmm,xmm */
                                    /* vpshad xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x9b): /* vpshaq xmm/m128,xmm,xmm */
                                    /* vpshaq xmm,xmm/m128,xmm */
        generate_exception_if(vex.l, EXC_UD);
        host_and_vcpu_must_have(xop);
        goto simd_0f_ymm;

#endif /* X86EMUL_NO_SIMD */

    case X86EMUL_OPC_XOP(0a, 0x10): /* bextr imm,r/m,r */
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pxop = container_of(buf + 1, typeof(vex), raw[0]);

        host_and_vcpu_must_have(tbm);
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);

        if ( ea.type == OP_REG )
            src.val = *ea.reg;
        else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val, op_bytes,
                                   ctxt, ops)) != X86EMUL_OKAY )
            goto done;

        buf[0] = 0x8f;
        *pxop = vex;
        pxop->b = 1;
        pxop->r = 1;
        buf[3] = b;
        buf[4] = 0x09; /* reg=rCX r/m=(%rCX) */
        *(uint32_t *)(buf + 5) = imm1;
        buf[9] = 0xc3;

        emulate_stub([dst] "=&c" (dst.val), "[dst]" (&src.val));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_XOP(0a, 0x12): /* XOP Grp4 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* lwpins $imm32,r/m,r */
        case 1: /* lwpval $imm32,r/m,r */
            /* LWP is unsupported, so produce #UD unconditionally. */
            generate_exception(EXC_UD);
        }
        goto unrecognized_insn;

    default:
    unimplemented_insn:
        rc = X86EMUL_UNIMPLEMENTED;
        goto done;
    unrecognized_insn:
        rc = X86EMUL_UNRECOGNIZED;
        goto done;
    }

    if ( state->rmw )
    {
        ea.val = src.val;
        op_bytes = dst.bytes;
        rc = ops->rmw(dst.mem.seg, dst.mem.off, dst.bytes, &_regs.eflags,
                      state, ctxt);
        if ( rc != X86EMUL_OKAY )
            goto done;

        /* Some operations require a register to be written. */
        switch ( state->rmw )
        {
        case rmw_xchg:
        case rmw_xadd:
            switch ( dst.bytes )
            {
            case 1: *(uint8_t  *)src.reg = (uint8_t)ea.val; break;
            case 2: *(uint16_t *)src.reg = (uint16_t)ea.val; break;
            case 4: *src.reg = (uint32_t)ea.val; break; /* 64b reg: zero-extend */
            case 8: *src.reg = ea.val; break;
            }
            break;

        default:
            break;
        }

        dst.type = OP_NONE;
    }
    else if ( state->simd_size )
    {
        generate_exception_if(!op_bytes, EXC_UD);
        generate_exception_if((vex.opcx && (d & TwoOp) &&
                               (vex.reg != 0xf || (evex_encoded() && !evex.RX))),
                              EXC_UD);

        if ( !opc )
            BUG();
        if ( evex_encoded() )
        {
            opc[insn_bytes - EVEX_PFX_BYTES] = 0xc3;
            copy_EVEX(opc, evex);
        }
        else
        {
            opc[insn_bytes - PFX_BYTES] = 0xc3;
            copy_REX_VEX(opc, rex_prefix, vex);
        }

        if ( ea.type == OP_MEM )
        {
            uint32_t mxcsr = 0;
            uint64_t full = 0;

            if ( op_bytes < 16 ||
                 (vex.opcx
                  ? /* vmov{{a,nt}p{s,d},{,nt}dqa,ntdq} are exceptions. */
                    ext == ext_0f
                    ? ((b | 1) != 0x29 && b != 0x2b &&
                       ((b | 0x10) != 0x7f || vex.pfx != vex_66) &&
                       b != 0xe7)
                    : (ext != ext_0f38 || b != 0x2a)
                  : /* movup{s,d}, {,mask}movdqu, and lddqu are exceptions. */
                    ext == ext_0f &&
                    ((b | 1) == 0x11 ||
                     ((b | 0x10) == 0x7f && vex.pfx == vex_f3) ||
                     b == 0xf7 || b == 0xf0)) )
                mxcsr = MXCSR_MM;
            else if ( vcpu_has_misalignsse() )
                asm ( "stmxcsr %0" : "=m" (mxcsr) );
            generate_exception_if(!(mxcsr & MXCSR_MM) &&
                                  !is_aligned(ea.mem.seg, ea.mem.off, op_bytes,
                                              ctxt, ops),
                                  EXC_GP, 0);

            EXPECT(elem_bytes > 0);
            if ( evex.brs )
            {
                ASSERT((d & DstMask) != DstMem);
                op_bytes = elem_bytes;
            }
            if ( evex.opmsk )
            {
                ASSERT(!(op_bytes % elem_bytes));
                full = ~0ULL >> (64 - op_bytes / elem_bytes);
                op_mask &= full;
            }
            if ( fault_suppression )
            {
                if ( !op_mask )
                    goto simd_no_mem;
                if ( !evex.brs )
                {
                    first_byte = __builtin_ctzll(op_mask);
                    op_mask >>= first_byte;
                    full >>= first_byte;
                    first_byte *= elem_bytes;
                    op_bytes = (64 - __builtin_clzll(op_mask)) * elem_bytes;
                }
            }
            /*
             * Independent of fault suppression we may need to read (parts of)
             * the memory operand for the purpose of merging without splitting
             * the write below into multiple ones. Note that the EVEX.Z check
             * here isn't strictly needed, due to there not currently being
             * any instructions allowing zeroing-merging on memory writes (and
             * we raise #UD during DstMem processing far above in this case),
             * yet conceptually the read is then unnecessary.
             */
            if ( evex.opmsk && !evex.z && (d & DstMask) == DstMem &&
                 op_mask != full )
                d = (d & ~SrcMask) | SrcMem;

            switch ( d & SrcMask )
            {
            case SrcMem:
                rc = ops->read(ea.mem.seg, truncate_ea(ea.mem.off + first_byte),
                               (void *)mmvalp + first_byte, op_bytes,
                               ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
                /* fall through */
            case SrcMem16:
                dst.type = OP_NONE;
                break;
            default:
                EXPECT((d & DstMask) == DstMem);
                break;
            }
            if ( (d & DstMask) == DstMem )
            {
                fail_if(!ops->write); /* Check before running the stub. */
                if ( (d & SrcMask) == SrcMem )
                    d |= Mov; /* Force memory write to occur below. */

                switch ( ctxt->opcode )
                {
                case X86EMUL_OPC_VEX_66(0x0f38, 0x2e): /* vmaskmovps */
                case X86EMUL_OPC_VEX_66(0x0f38, 0x2f): /* vmaskmovpd */
                case X86EMUL_OPC_VEX_66(0x0f38, 0x8e): /* vpmaskmov{d,q} */
                    /* These have merge semantics; force write to occur. */
                    d |= Mov;
                    break;
                default:
                    ASSERT(d & Mov);
                    break;
                }

                dst.type = OP_MEM;
                dst.bytes = op_bytes;
                dst.mem = ea.mem;
            }
        }
        else
        {
        simd_no_mem:
            dst.type = OP_NONE;
        }

        /* {,v}maskmov{q,dqu}, as an exception, uses rDI. */
        if ( likely((ctxt->opcode & ~(X86EMUL_OPC_PFX_MASK |
                                      X86EMUL_OPC_ENCODING_MASK)) !=
                    X86EMUL_OPC(0x0f, 0xf7)) )
            invoke_stub("", "", "+m" (*mmvalp) : "a" (mmvalp));
        else
            invoke_stub("", "", "+m" (*mmvalp) : "D" (mmvalp));

        put_stub(stub);
    }

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
        {
            fail_if(!ops->cmpxchg);
            rc = ops->cmpxchg(
                dst.mem.seg, dst.mem.off, &dst.orig_val,
                &dst.val, dst.bytes, true, ctxt);
            if ( rc == X86EMUL_CMPXCHG_FAILED )
                rc = X86EMUL_RETRY;
        }
        else
        {
            fail_if(!ops->write);
            rc = ops->write(dst.mem.seg, truncate_ea(dst.mem.off + first_byte),
                            !state->simd_size ? &dst.val
                                              : (void *)mmvalp + first_byte,
                            dst.bytes, ctxt);
            if ( sfence )
                asm volatile ( "sfence" ::: "memory" );
        }
        if ( rc != 0 )
            goto done;
    default:
        break;
    }

 complete_insn: /* Commit shadow register state. */
    put_fpu(fpu_type, false, state, ctxt, ops);
    fpu_type = X86EMUL_FPU_none;

    /* Zero the upper 32 bits of %rip if not in 64-bit mode. */
    if ( !mode_64bit() )
        _regs.r(ip) = _regs.eip;

    /* Should a singlestep #DB be raised? */
    if ( rc == X86EMUL_OKAY && singlestep && !ctxt->retire.mov_ss )
    {
        ctxt->retire.singlestep = true;
        ctxt->retire.sti = false;
    }

    if ( rc != X86EMUL_DONE )
        *ctxt->regs = _regs;
    else
    {
        ctxt->regs->r(ip) = _regs.r(ip);
        rc = X86EMUL_OKAY;
    }

    ctxt->regs->eflags &= ~X86_EFLAGS_RF;

 done:
    put_fpu(fpu_type, insn_bytes > 0 && dst.type == OP_MEM, state, ctxt, ops);
    put_stub(stub);
    return rc;
#undef state

#ifdef __XEN__
 emulation_stub_failure:
    generate_exception_if(stub_exn.info.fields.trapnr == EXC_MF, EXC_MF);
    if ( stub_exn.info.fields.trapnr == EXC_XM )
    {
        unsigned long cr4;

        if ( !ops->read_cr || ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
            cr4 = X86_CR4_OSXMMEXCPT;
        generate_exception(cr4 & X86_CR4_OSXMMEXCPT ? EXC_XM : EXC_UD);
    }
    gprintk(XENLOG_WARNING,
            "exception %u (ec=%04x) in emulation stub (line %u)\n",
            stub_exn.info.fields.trapnr, stub_exn.info.fields.ec,
            stub_exn.line);
    gprintk(XENLOG_INFO, "  stub: %"__stringify(MAX_INST_LEN)"ph\n",
            stub.func);
    generate_exception_if(stub_exn.info.fields.trapnr == EXC_UD, EXC_UD);
    domain_crash(current->domain);
#endif

 unhandleable:
    rc = X86EMUL_UNHANDLEABLE;
    goto done;
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
#undef ea

int x86_emul_rmw(
    void *ptr,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned long *dst = ptr;

    ASSERT(bytes == state->op_bytes);

/*
 * We cannot use Jcc below, as this code executes with the guest status flags
 * loaded into the EFLAGS register. Hence our only choice is J{E,R}CXZ.
 */
#ifdef __x86_64__
# define JCXZ "jrcxz"
#else
# define JCXZ "jecxz"
#endif

#define COND_LOCK(op) \
    JCXZ " .L" #op "%=\n\t" \
    "lock\n" \
    ".L" #op "%=:\n\t" \
    #op

    switch ( state->rmw )
    {
#define UNOP(op) \
    case rmw_##op: \
        _emulate_1op(COND_LOCK(op), dst, bytes, *eflags, \
                     "c" ((long)state->lock_prefix) ); \
        break
#define BINOP(op, sfx) \
    case rmw_##op: \
        _emulate_2op_SrcV##sfx(COND_LOCK(op), \
                               state->ea.val, dst, bytes, *eflags, \
                               "c" ((long)state->lock_prefix) ); \
        break
#define SHIFT(op) \
    case rmw_##op: \
        ASSERT(!state->lock_prefix); \
        _emulate_2op_SrcB(#op, state->ea.val, dst, bytes, *eflags); \
        break

    BINOP(adc, );
    BINOP(add, );
    BINOP(and, );
    BINOP(btc, _nobyte);
    BINOP(bts, _nobyte);
    BINOP(btr, _nobyte);
     UNOP(dec);
     UNOP(inc);
     UNOP(neg);
    BINOP(or, );
    SHIFT(rcl);
    SHIFT(rcr);
    SHIFT(rol);
    SHIFT(ror);
    SHIFT(sar);
    BINOP(sbb, );
    SHIFT(shl);
    SHIFT(shr);
    BINOP(sub, );
    BINOP(xor, );

#undef UNOP
#undef BINOP
#undef SHIFT

    case rmw_not:
        switch ( state->op_bytes )
        {
        case 1:
            asm ( COND_LOCK(notb) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
        case 2:
            asm ( COND_LOCK(notw) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
        case 4:
            asm ( COND_LOCK(notl) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
#ifdef __x86_64__
        case 8:
            asm ( COND_LOCK(notq) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
#endif
        }
        break;

    case rmw_shld:
        ASSERT(!state->lock_prefix);
        _emulate_2op_SrcV_nobyte("shld",
                                 state->ea.val, dst, bytes, *eflags,
                                 "c" (state->ea.orig_val) );
        break;

    case rmw_shrd:
        ASSERT(!state->lock_prefix);
        _emulate_2op_SrcV_nobyte("shrd",
                                 state->ea.val, dst, bytes, *eflags,
                                 "c" (state->ea.orig_val) );
        break;

    case rmw_xadd:
        switch ( state->op_bytes )
        {
            unsigned long dummy;

#define XADD(sz, cst, mod) \
        case sz: \
            asm ( _PRE_EFLAGS("[efl]", "[msk]", "[tmp]") \
                  COND_LOCK(xadd) " %"#mod"[reg], %[mem]; " \
                  _POST_EFLAGS("[efl]", "[msk]", "[tmp]") \
                  : [reg] "+" #cst (state->ea.val), \
                    [mem] "+m" (*dst), \
                    [efl] "+g" (*eflags), \
                    [tmp] "=&r" (dummy) \
                  : "c" ((long)state->lock_prefix), \
                    [msk] "i" (EFLAGS_MASK) ); \
            break
        XADD(1, q, b);
        XADD(2, r, w);
        XADD(4, r, k);
#ifdef __x86_64__
        XADD(8, r, );
#endif
#undef XADD
        }
        break;

    case rmw_xchg:
        switch ( state->op_bytes )
        {
        case 1:
            asm ( "xchg %b0, %b1" : "+q" (state->ea.val), "+m" (*dst) );
            break;
        case 2:
            asm ( "xchg %w0, %w1" : "+r" (state->ea.val), "+m" (*dst) );
            break;
        case 4:
#ifdef __x86_64__
            asm ( "xchg %k0, %k1" : "+r" (state->ea.val), "+m" (*dst) );
            break;
        case 8:
#endif
            asm ( "xchg %0, %1" : "+r" (state->ea.val), "+m" (*dst) );
            break;
        }
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

#undef COND_LOCK
#undef JCXZ

    return X86EMUL_OKAY;
}

int x86_emul_blk(
    void *ptr,
    void *data,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    int rc = X86EMUL_OKAY;

    switch ( state->blk )
    {
        bool zf;
#ifndef X86EMUL_NO_FPU
        struct {
            struct x87_env32 env;
            struct {
               uint8_t bytes[10];
            } freg[8];
        } fpstate;
#endif

        /*
         * Throughout this switch(), memory clobbers are used to compensate
         * that other operands may not properly express the (full) memory
         * ranges covered.
         */
    case blk_enqcmd:
        ASSERT(bytes == 64);
        if ( ((unsigned long)ptr & 0x3f) )
        {
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }
        *eflags &= ~EFLAGS_MASK;
#ifdef HAVE_AS_ENQCMD
        asm ( "enqcmds (%[src]), %[dst]" ASM_FLAG_OUT(, "; setz %[zf]")
              : [zf] ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : [src] "r" (data), [dst] "r" (ptr) : "memory" );
#else
        /* enqcmds (%rsi), %rdi */
        asm ( ".byte 0xf3, 0x0f, 0x38, 0xf8, 0x3e"
              ASM_FLAG_OUT(, "; setz %[zf]")
              : [zf] ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : "S" (data), "D" (ptr) : "memory" );
#endif
        if ( zf )
            *eflags |= X86_EFLAGS_ZF;
        break;

#ifndef X86EMUL_NO_FPU

    case blk_fld:
        ASSERT(!data);

        /* state->rex_prefix carries CR0.PE && !EFLAGS.VM setting */
        switch ( bytes )
        {
        case sizeof(fpstate.env): /* 32-bit FLDENV */
        case sizeof(fpstate):     /* 32-bit FRSTOR */
            memcpy(&fpstate.env, ptr, sizeof(fpstate.env));
            if ( !state->rex_prefix )
            {
                /* Convert 32-bit real/vm86 to 32-bit prot format. */
                unsigned int fip = fpstate.env.mode.real.fip_lo +
                                   (fpstate.env.mode.real.fip_hi << 16);
                unsigned int fdp = fpstate.env.mode.real.fdp_lo +
                                   (fpstate.env.mode.real.fdp_hi << 16);
                unsigned int fop = fpstate.env.mode.real.fop;

                fpstate.env.mode.prot.fip = fip & 0xf;
                fpstate.env.mode.prot.fcs = fip >> 4;
                fpstate.env.mode.prot.fop = fop;
                fpstate.env.mode.prot.fdp = fdp & 0xf;
                fpstate.env.mode.prot.fds = fdp >> 4;
            }

            if ( bytes == sizeof(fpstate.env) )
                ptr = NULL;
            else
                ptr += sizeof(fpstate.env);
            break;

        case sizeof(struct x87_env16):                        /* 16-bit FLDENV */
        case sizeof(struct x87_env16) + sizeof(fpstate.freg): /* 16-bit FRSTOR */
        {
            const struct x87_env16 *env = ptr;

            fpstate.env.fcw = env->fcw;
            fpstate.env.fsw = env->fsw;
            fpstate.env.ftw = env->ftw;

            if ( state->rex_prefix )
            {
                /* Convert 16-bit prot to 32-bit prot format. */
                fpstate.env.mode.prot.fip = env->mode.prot.fip;
                fpstate.env.mode.prot.fcs = env->mode.prot.fcs;
                fpstate.env.mode.prot.fdp = env->mode.prot.fdp;
                fpstate.env.mode.prot.fds = env->mode.prot.fds;
                fpstate.env.mode.prot.fop = 0; /* unknown */
            }
            else
            {
                /* Convert 16-bit real/vm86 to 32-bit prot format. */
                unsigned int fip = env->mode.real.fip_lo +
                                   (env->mode.real.fip_hi << 16);
                unsigned int fdp = env->mode.real.fdp_lo +
                                   (env->mode.real.fdp_hi << 16);
                unsigned int fop = env->mode.real.fop;

                fpstate.env.mode.prot.fip = fip & 0xf;
                fpstate.env.mode.prot.fcs = fip >> 4;
                fpstate.env.mode.prot.fop = fop;
                fpstate.env.mode.prot.fdp = fdp & 0xf;
                fpstate.env.mode.prot.fds = fdp >> 4;
            }

            if ( bytes == sizeof(*env) )
                ptr = NULL;
            else
                ptr += sizeof(*env);
            break;
        }

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }

        if ( ptr )
        {
            memcpy(fpstate.freg, ptr, sizeof(fpstate.freg));
            asm volatile ( "frstor %0" :: "m" (fpstate) );
        }
        else
            asm volatile ( "fldenv %0" :: "m" (fpstate.env) );
        break;

    case blk_fst:
        ASSERT(!data);

        /* Don't chance consuming uninitialized data. */
        memset(&fpstate, 0, sizeof(fpstate));
        if ( bytes > sizeof(fpstate.env) )
            asm ( "fnsave %0" : "+m" (fpstate) );
        else
            asm ( "fnstenv %0" : "+m" (fpstate.env) );

        /* state->rex_prefix carries CR0.PE && !EFLAGS.VM setting */
        switch ( bytes )
        {
        case sizeof(fpstate.env): /* 32-bit FNSTENV */
        case sizeof(fpstate):     /* 32-bit FNSAVE */
            if ( !state->rex_prefix )
            {
                /* Convert 32-bit prot to 32-bit real/vm86 format. */
                unsigned int fip = fpstate.env.mode.prot.fip +
                                   (fpstate.env.mode.prot.fcs << 4);
                unsigned int fdp = fpstate.env.mode.prot.fdp +
                                   (fpstate.env.mode.prot.fds << 4);
                unsigned int fop = fpstate.env.mode.prot.fop;

                memset(&fpstate.env.mode, 0, sizeof(fpstate.env.mode));
                fpstate.env.mode.real.fip_lo = fip;
                fpstate.env.mode.real.fip_hi = fip >> 16;
                fpstate.env.mode.real.fop = fop;
                fpstate.env.mode.real.fdp_lo = fdp;
                fpstate.env.mode.real.fdp_hi = fdp >> 16;
            }
            memcpy(ptr, &fpstate.env, sizeof(fpstate.env));
            if ( bytes == sizeof(fpstate.env) )
                ptr = NULL;
            else
                ptr += sizeof(fpstate.env);
            break;

        case sizeof(struct x87_env16):                        /* 16-bit FNSTENV */
        case sizeof(struct x87_env16) + sizeof(fpstate.freg): /* 16-bit FNSAVE */
            if ( state->rex_prefix )
            {
                /* Convert 32-bit prot to 16-bit prot format. */
                struct x87_env16 *env = ptr;

                env->fcw = fpstate.env.fcw;
                env->fsw = fpstate.env.fsw;
                env->ftw = fpstate.env.ftw;
                env->mode.prot.fip = fpstate.env.mode.prot.fip;
                env->mode.prot.fcs = fpstate.env.mode.prot.fcs;
                env->mode.prot.fdp = fpstate.env.mode.prot.fdp;
                env->mode.prot.fds = fpstate.env.mode.prot.fds;
            }
            else
            {
                /* Convert 32-bit prot to 16-bit real/vm86 format. */
                unsigned int fip = fpstate.env.mode.prot.fip +
                                   (fpstate.env.mode.prot.fcs << 4);
                unsigned int fdp = fpstate.env.mode.prot.fdp +
                                   (fpstate.env.mode.prot.fds << 4);
                struct x87_env16 env = {
                    .fcw = fpstate.env.fcw,
                    .fsw = fpstate.env.fsw,
                    .ftw = fpstate.env.ftw,
                    .mode.real.fip_lo = fip,
                    .mode.real.fip_hi = fip >> 16,
                    .mode.real.fop = fpstate.env.mode.prot.fop,
                    .mode.real.fdp_lo = fdp,
                    .mode.real.fdp_hi = fdp >> 16
                };

                memcpy(ptr, &env, sizeof(env));
            }
            if ( bytes == sizeof(struct x87_env16) )
                ptr = NULL;
            else
                ptr += sizeof(struct x87_env16);
            break;

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }

        if ( ptr )
            memcpy(ptr, fpstate.freg, sizeof(fpstate.freg));
        break;

#endif /* X86EMUL_NO_FPU */

#if !defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
    !defined(X86EMUL_NO_SIMD)

    case blk_fxrstor:
    {
        struct x86_fxsr *fxsr = FXSAVE_AREA;

        ASSERT(!data);
        ASSERT(bytes == sizeof(*fxsr));
        ASSERT(state->op_bytes <= bytes);

        if ( state->op_bytes < sizeof(*fxsr) )
        {
            if ( state->rex_prefix & REX_W )
            {
                /*
                 * The only way to force fxsaveq on a wide range of gas
                 * versions. On older versions the rex64 prefix works only if
                 * we force an addressing mode that doesn't require extended
                 * registers.
                 */
                asm volatile ( ".byte 0x48; fxsave (%1)"
                               : "=m" (*fxsr) : "R" (fxsr) );
            }
            else
                asm volatile ( "fxsave %0" : "=m" (*fxsr) );
        }

        /*
         * Don't chance the reserved or available ranges to contain any
         * data FXRSTOR may actually consume in some way: Copy only the
         * defined portion, and zero the rest.
         */
        memcpy(fxsr, ptr, min(state->op_bytes,
                              (unsigned int)offsetof(struct x86_fxsr, rsvd)));
        memset(fxsr->rsvd, 0, sizeof(*fxsr) - offsetof(struct x86_fxsr, rsvd));

        generate_exception_if(fxsr->mxcsr & ~mxcsr_mask, EXC_GP, 0);

        if ( state->rex_prefix & REX_W )
        {
            /* See above for why operand/constraints are this way. */
            asm volatile ( ".byte 0x48; fxrstor (%1)"
                           :: "m" (*fxsr), "R" (fxsr) );
        }
        else
            asm volatile ( "fxrstor %0" :: "m" (*fxsr) );
        break;
    }

    case blk_fxsave:
    {
        struct x86_fxsr *fxsr = FXSAVE_AREA;

        ASSERT(!data);
        ASSERT(bytes == sizeof(*fxsr));
        ASSERT(state->op_bytes <= bytes);

        if ( state->op_bytes < sizeof(*fxsr) )
            /* Don't chance consuming uninitialized data. */
            memset(fxsr, 0, state->op_bytes);
        else
            fxsr = ptr;

        if ( state->rex_prefix & REX_W )
        {
            /* See above for why operand/constraints are this way. */
            asm volatile ( ".byte 0x48; fxsave (%1)"
                           : "=m" (*fxsr) : "R" (fxsr) );
        }
        else
            asm volatile ( "fxsave %0" : "=m" (*fxsr) );

        if ( fxsr != ptr ) /* i.e. state->op_bytes < sizeof(*fxsr) */
            memcpy(ptr, fxsr, state->op_bytes);
        break;
    }

#endif /* X86EMUL_NO_{FPU,MMX,SIMD} */

    case blk_movdir:
        switch ( bytes )
        {
#ifdef __x86_64__
        case sizeof(uint32_t):
# ifdef HAVE_AS_MOVDIR
            asm ( "movdiri %0, (%1)"
                  :: "r" (*(uint32_t *)data), "r" (ptr) : "memory" );
# else
            /* movdiri %esi, (%rdi) */
            asm ( ".byte 0x0f, 0x38, 0xf9, 0x37"
                  :: "S" (*(uint32_t *)data), "D" (ptr) : "memory" );
# endif
            break;
#endif

        case sizeof(unsigned long):
#ifdef HAVE_AS_MOVDIR
            asm ( "movdiri %0, (%1)"
                  :: "r" (*(unsigned long *)data), "r" (ptr) : "memory" );
#else
            /* movdiri %rsi, (%rdi) */
            asm ( ".byte 0x48, 0x0f, 0x38, 0xf9, 0x37"
                  :: "S" (*(unsigned long *)data), "D" (ptr) : "memory" );
#endif
            break;

        case 64:
            if ( ((unsigned long)ptr & 0x3f) )
            {
                ASSERT_UNREACHABLE();
                return X86EMUL_UNHANDLEABLE;
            }
#ifdef HAVE_AS_MOVDIR
            asm ( "movdir64b (%0), %1" :: "r" (data), "r" (ptr) : "memory" );
#else
            /* movdir64b (%rsi), %rdi */
            asm ( ".byte 0x66, 0x0f, 0x38, 0xf8, 0x3e"
                  :: "S" (data), "D" (ptr) : "memory" );
#endif
            break;

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

 done:
    return rc;
}

static void __init __maybe_unused build_assertions(void)
{
    /* Check the values against SReg3 encoding in opcode/ModRM bytes. */
    BUILD_BUG_ON(x86_seg_es != 0);
    BUILD_BUG_ON(x86_seg_cs != 1);
    BUILD_BUG_ON(x86_seg_ss != 2);
    BUILD_BUG_ON(x86_seg_ds != 3);
    BUILD_BUG_ON(x86_seg_fs != 4);
    BUILD_BUG_ON(x86_seg_gs != 5);

    /*
     * Check X86_EVENTTYPE_* against VMCB EVENTINJ and VMCS INTR_INFO type
     * fields.
     */
    BUILD_BUG_ON(X86_EVENTTYPE_EXT_INTR != 0);
    BUILD_BUG_ON(X86_EVENTTYPE_NMI != 2);
    BUILD_BUG_ON(X86_EVENTTYPE_HW_EXCEPTION != 3);
    BUILD_BUG_ON(X86_EVENTTYPE_SW_INTERRUPT != 4);
    BUILD_BUG_ON(X86_EVENTTYPE_PRI_SW_EXCEPTION != 5);
    BUILD_BUG_ON(X86_EVENTTYPE_SW_EXCEPTION != 6);
}

#ifndef NDEBUG
/*
 * In debug builds, wrap x86_emulate() with some assertions about its expected
 * behaviour.
 */
int x86_emulate_wrapper(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    unsigned long orig_ip = ctxt->regs->r(ip);
    int rc;

    if ( mode_64bit() )
        ASSERT(ctxt->lma);

    rc = x86_emulate(ctxt, ops);

    /*
     * Most retire flags should only be set for successful instruction
     * emulation.
     */
    if ( rc != X86EMUL_OKAY )
    {
        typeof(ctxt->retire) retire = ctxt->retire;

        retire.unblock_nmi = false;
        ASSERT(!retire.raw);
    }

    /* All cases returning X86EMUL_EXCEPTION should have fault semantics. */
    if ( rc == X86EMUL_EXCEPTION )
        ASSERT(ctxt->regs->r(ip) == orig_ip);

    /*
     * An event being pending should exactly match returning
     * X86EMUL_EXCEPTION.  (If this trips, the chances are a codepath has
     * called hvm_inject_hw_exception() rather than using
     * x86_emul_hw_exception().)
     */
    ASSERT(ctxt->event_pending == (rc == X86EMUL_EXCEPTION));

    return rc;
}
#endif

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
    };
    int rc;

    init_context(ctxt);

    rc = x86_decode(state, ctxt, &ops);
    if ( unlikely(rc != X86EMUL_OKAY) )
        return ERR_PTR(-rc);

#if defined(__XEN__) && !defined(NDEBUG)
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
#if defined(__XEN__) && !defined(NDEBUG)
    ASSERT(state->caller);
#endif
}

#if defined(__XEN__) && !defined(NDEBUG)
void x86_emulate_free_state(struct x86_emulate_state *state)
{
    check_state(state);
    state->caller = NULL;
}
#endif

unsigned int
x86_insn_opsize(const struct x86_emulate_state *state)
{
    check_state(state);

    return state->op_bytes << 3;
}

int
x86_insn_modrm(const struct x86_emulate_state *state,
               unsigned int *rm, unsigned int *reg)
{
    check_state(state);

    if ( unlikely(state->modrm_mod > 3) )
    {
        if ( rm )
            *rm = ~0U;
        if ( reg )
            *reg = ~0U;
        return -EINVAL;
    }

    if ( rm )
        *rm = state->modrm_rm;
    if ( reg )
        *reg = state->modrm_reg;

    return state->modrm_mod;
}

unsigned long
x86_insn_operand_ea(const struct x86_emulate_state *state,
                    enum x86_segment *seg)
{
    *seg = state->ea.type == OP_MEM ? state->ea.mem.seg : x86_seg_none;

    check_state(state);

    return state->ea.mem.off;
}

/*
 * This function means to return 'true' for all supported insns with explicit
 * accesses to memory.  This means also insns which don't have an explicit
 * memory operand (like POP), but it does not mean e.g. segment selector
 * loads, where the descriptor table access is considered an implicit one.
 */
bool
x86_insn_is_mem_access(const struct x86_emulate_state *state,
                       const struct x86_emulate_ctxt *ctxt)
{
    if ( mode_64bit() && state->not_64bit )
        return false;

    if ( state->ea.type == OP_MEM )
    {
        switch ( ctxt->opcode )
        {
        case 0x8d: /* LEA */
        case X86EMUL_OPC(0x0f, 0x0d): /* PREFETCH */
        case X86EMUL_OPC(0x0f, 0x18)
         ... X86EMUL_OPC(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC_66(0x0f, 0x18)
         ... X86EMUL_OPC_66(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC_F3(0x0f, 0x18)
         ... X86EMUL_OPC_F3(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC_F2(0x0f, 0x18)
         ... X86EMUL_OPC_F2(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC(0x0f, 0xb9): /* UD1 */
        case X86EMUL_OPC(0x0f, 0xff): /* UD0 */
            return false;

        case X86EMUL_OPC(0x0f, 0x01):
            return (state->modrm_reg & 7) != 7; /* INVLPG */

        case X86EMUL_OPC(0x0f, 0xae):
            return (state->modrm_reg & 7) != 7; /* CLFLUSH */

        case X86EMUL_OPC_66(0x0f, 0xae):
            return (state->modrm_reg & 7) < 6; /* CLWB, CLFLUSHOPT */
        }

        return true;
    }

    switch ( ctxt->opcode )
    {
    case 0x06 ... 0x07: /* PUSH / POP %es */
    case 0x0e:          /* PUSH %cs */
    case 0x16 ... 0x17: /* PUSH / POP %ss */
    case 0x1e ... 0x1f: /* PUSH / POP %ds */
    case 0x50 ... 0x5f: /* PUSH / POP reg */
    case 0x60 ... 0x61: /* PUSHA / POPA */
    case 0x68: case 0x6a: /* PUSH imm */
    case 0x6c ... 0x6f: /* INS / OUTS */
    case 0x8f:          /* POP r/m */
    case 0x9a:          /* CALL (far, direct) */
    case 0x9c ... 0x9d: /* PUSHF / POPF */
    case 0xa4 ... 0xa7: /* MOVS / CMPS */
    case 0xaa ... 0xaf: /* STOS / LODS / SCAS */
    case 0xc2 ... 0xc3: /* RET (near) */
    case 0xc8 ... 0xc9: /* ENTER / LEAVE */
    case 0xca ... 0xcb: /* RET (far) */
    case 0xd7:          /* XLAT */
    case 0xe8:          /* CALL (near, direct) */
    case X86EMUL_OPC(0x0f, 0xa0):         /* PUSH %fs */
    case X86EMUL_OPC(0x0f, 0xa1):         /* POP %fs */
    case X86EMUL_OPC(0x0f, 0xa8):         /* PUSH %gs */
    case X86EMUL_OPC(0x0f, 0xa9):         /* POP %gs */
    CASE_SIMD_PACKED_INT_VEX(0x0f, 0xf7): /* MASKMOV{Q,DQU} */
                                          /* VMASKMOVDQU */
        return true;

    case 0xff:
        switch ( state->modrm_reg & 7 )
        {
        case 2: /* CALL (near, indirect) */
        case 6: /* PUSH r/m */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01):
        /* Cover CLZERO. */
        return (state->modrm_rm & 7) == 4 && (state->modrm_reg & 7) == 7;
    }

    return false;
}

/*
 * This function means to return 'true' for all supported insns with explicit
 * writes to memory.  This means also insns which don't have an explicit
 * memory operand (like PUSH), but it does not mean e.g. segment selector
 * loads, where the (possible) descriptor table write is considered an
 * implicit access.
 */
bool
x86_insn_is_mem_write(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt)
{
    if ( mode_64bit() && state->not_64bit )
        return false;

    switch ( state->desc & DstMask )
    {
    case DstMem:
        /* The SrcMem check is to cover {,V}MASKMOV{Q,DQU}. */
        return state->modrm_mod != 3 || (state->desc & SrcMask) == SrcMem;

    case DstBitBase:
    case DstImplicit:
        break;

    default:
        switch ( ctxt->opcode )
        {
        case 0x63:                         /* ARPL */
            return !mode_64bit();

        case X86EMUL_OPC_66(0x0f38, 0xf8): /* MOVDIR64B */
        case X86EMUL_OPC_F2(0x0f38, 0xf8): /* ENQCMD */
        case X86EMUL_OPC_F3(0x0f38, 0xf8): /* ENQCMDS */
            return true;
        }

        return false;
    }

    if ( state->modrm_mod == 3 )
    {
        switch ( ctxt->opcode )
        {
        case 0xff: /* Grp5 */
            break;

        case X86EMUL_OPC(0x0f, 0x01): /* CLZERO is the odd one. */
            return (state->modrm_rm & 7) == 4 && (state->modrm_reg & 7) == 7;

        default:
            return false;
        }
    }

    switch ( ctxt->opcode )
    {
    case 0x06:                           /* PUSH %es */
    case 0x0e:                           /* PUSH %cs */
    case 0x16:                           /* PUSH %ss */
    case 0x1e:                           /* PUSH %ds */
    case 0x50 ... 0x57:                  /* PUSH reg */
    case 0x60:                           /* PUSHA */
    case 0x68: case 0x6a:                /* PUSH imm */
    case 0x6c: case 0x6d:                /* INS */
    case 0x9a:                           /* CALL (far, direct) */
    case 0x9c:                           /* PUSHF */
    case 0xa4: case 0xa5:                /* MOVS */
    case 0xaa: case 0xab:                /* STOS */
    case 0xc8:                           /* ENTER */
    case 0xe8:                           /* CALL (near, direct) */
    case X86EMUL_OPC(0x0f, 0xa0):        /* PUSH %fs */
    case X86EMUL_OPC(0x0f, 0xa8):        /* PUSH %gs */
    case X86EMUL_OPC(0x0f, 0xab):        /* BTS */
    case X86EMUL_OPC(0x0f, 0xb3):        /* BTR */
    case X86EMUL_OPC(0x0f, 0xbb):        /* BTC */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x10) ...
         X86EMUL_OPC_EVEX_F3(0x0f38, 0x15): /* VPMOVUS* */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x20) ...
         X86EMUL_OPC_EVEX_F3(0x0f38, 0x25): /* VPMOVS* */
    case X86EMUL_OPC_EVEX_F3(0x0f38, 0x30) ...
         X86EMUL_OPC_EVEX_F3(0x0f38, 0x35): /* VPMOV{D,Q,W}* */
        return true;

    case 0xd9:
        switch ( state->modrm_reg & 7 )
        {
        case 2: /* FST m32fp */
        case 3: /* FSTP m32fp */
        case 6: /* FNSTENV */
        case 7: /* FNSTCW */
            return true;
        }
        break;

    case 0xdb:
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* FISTTP m32i */
        case 2: /* FIST m32i */
        case 3: /* FISTP m32i */
        case 7: /* FSTP m80fp */
            return true;
        }
        break;

    case 0xdd:
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* FISTTP m64i */
        case 2: /* FST m64fp */
        case 3: /* FSTP m64fp */
        case 6: /* FNSAVE */
        case 7: /* FNSTSW */
            return true;
        }
        break;

    case 0xdf:
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* FISTTP m16i */
        case 2: /* FIST m16i */
        case 3: /* FISTP m16i */
        case 6: /* FBSTP */
        case 7: /* FISTP m64i */
            return true;
        }
        break;

    case 0xff:
        switch ( state->modrm_reg & 7 )
        {
        case 2: /* CALL (near, indirect) */
        case 3: /* CALL (far, indirect) */
        case 6: /* PUSH r/m */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01):
        switch ( state->modrm_reg & 7 )
        {
        case 0: /* SGDT */
        case 1: /* SIDT */
        case 4: /* SMSW */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xae):
        switch ( state->modrm_reg & 7 )
        {
        case 0: /* FXSAVE */
        /* case 3: STMXCSR - handled above */
        case 4: /* XSAVE */
        case 6: /* XSAVEOPT */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xba):
        return (state->modrm_reg & 7) > 4; /* BTS / BTR / BTC */

    case X86EMUL_OPC(0x0f, 0xc7):
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* CMPXCHG{8,16}B */
        case 4: /* XSAVEC */
        case 5: /* XSAVES */
            return true;
        }
        break;
    }

    return false;
}

bool
x86_insn_is_portio(const struct x86_emulate_state *state,
                   const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
    case 0x6c ... 0x6f: /* INS / OUTS */
    case 0xe4 ... 0xe7: /* IN / OUT imm8 */
    case 0xec ... 0xef: /* IN / OUT %dx */
        return true;
    }

    return false;
}

bool
x86_insn_is_cr_access(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
        unsigned int ext;

    case X86EMUL_OPC(0x0f, 0x01):
        if ( x86_insn_modrm(state, NULL, &ext) >= 0
             && (ext & 5) == 4 ) /* SMSW / LMSW */
            return true;
        break;

    case X86EMUL_OPC(0x0f, 0x06): /* CLTS */
    case X86EMUL_OPC(0x0f, 0x20): /* MOV from CRn */
    case X86EMUL_OPC(0x0f, 0x22): /* MOV to CRn */
        return true;
    }

    return false;
}

unsigned long
x86_insn_immediate(const struct x86_emulate_state *state, unsigned int nr)
{
    check_state(state);

    switch ( nr )
    {
    case 0:
        return state->imm1;
    case 1:
        return state->imm2;
    }

    return 0;
}

unsigned int
x86_insn_length(const struct x86_emulate_state *state,
                const struct x86_emulate_ctxt *ctxt)
{
    check_state(state);

    return state->ip - ctxt->regs->r(ip);
}
